// main dynamically serve static sites from artifactory
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/log"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/proxy"
	"github.com/spf13/viper"
)

const (
	lclHost       = "ARTIFACTORY_HOST"
	lclUser       = "ARTIFACTORY_USER"
	lclPass       = "ARTIFACTORY_PASS"
	lclPath       = "ROOT_PATH"
	lclConfig     = "app_config"
	lclArtService = "art_service"
	lclClient     = "client"
)

var errAPI = errors.New("API Error")
var errNotFound = fmt.Errorf("%w: %v", errAPI, "404 Not Found")

func main() {
	viper.SetEnvPrefix("DOCS")
	viper.MustBindEnv(lclHost)
	viper.MustBindEnv(lclUser)
	viper.MustBindEnv(lclPass)
	viper.MustBindEnv(lclPath)

	config := newAppConfig()

	if err := config.validate(); err != nil {
		panic(err)
	}

	siteManager := newSiteManager(&artifactoryFetcher{
		host: config.host,
		reqModFunc: func(req *http.Request) {
			req.SetBasicAuth(config.user, config.pass)
		},
		hashTable:   make(map[string]string),
		client:      config.clnt,
		siteRootDir: "/usr/local/share/docs-sites",
		repoPath:    "batcave-misc/knight-light-docs",
	})

	siteManager.siteRootDir = "/usr/local/share/docs-sites"

	app := fiber.New()
	app.Use(logger.New(logger.Config{Output: os.Stdout}))

	app.Use(func(c *fiber.Ctx) error {
		log.Tracew("request", "method", string(c.Request().Header.Method()), "request_uri", c.Request().URI())
		c.Locals(lclConfig, config)
		return c.Next()
	})

	app.Get("/ping", func(c *fiber.Ctx) error {
		return c.SendString("pong")
	})

	app.Get("/health", func(c *fiber.Ctx) error {
		return c.SendStatus(http.StatusOK)
	})

	app.Get("/:siteID/*", func(c *fiber.Ctx) error {
		siteID := c.Params("siteID")
		return siteManager.Request(c, siteID)
	})

	doneChan := make(chan func())
	sigChan := make(chan os.Signal, 1)

	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := app.Listen(":8080"); err != nil {
			doneChan <- func() {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
	}()

	select {
	case exitFunc := <-doneChan:
		exitFunc()
	case sig := <-sigChan:
		log.Info("Recieved termination signal: %s. Shutting down... timeout 5 seconds\n", sig)
		log.Infow("request shutdown...", "target", "site manager")
	}

	shutdownCompleteChan := make(chan struct{})
	go func() {
		if err := siteManager.ShutdownAll(); err != nil {
			panic(err)
		}
		log.Infow("done.", "target", "site apps")
		log.Infow("request shutdown...", "target", "root")
		if err := app.ShutdownWithTimeout(time.Second * 5); err != nil {
			panic(err)
		}
		log.Infow("done.", "target", "root")
		log.Info("Graceful shutdown complete.")
		shutdownCompleteChan <- struct{}{}
	}()

	select {
	case <-shutdownCompleteChan:
		os.Exit(0)
	case <-time.After(time.Second * 5):
		fmt.Fprintln(os.Stderr, "GRACEFUL EXIT FAILED")
		os.Exit(1)
	}

}

type appConfig struct {
	host string
	user string
	pass string
	path string
	clnt *http.Client
}

func newAppConfig() *appConfig {
	return &appConfig{
		host: viper.GetString(lclHost),
		user: viper.GetString(lclUser),
		pass: viper.GetString(lclPass),
		path: viper.GetString(lclPath),
		clnt: http.DefaultClient,
	}
}

func (c *appConfig) validate() error {
	var err error
	for _, e := range []string{lclHost, lclUser, lclPass, lclPath} {
		if viper.GetString(e) == "" {
			err = errors.Join(err, fmt.Errorf("environment variable not set: DOCS_%s", e))
		}
	}
	return err
}

type lastModfiedResponse struct {
	URI          string `json:"uri"`
	LastModified string `json:"lastModified"`
}

type fileInfoResponse struct {
	URI         string `json:"Uri"`
	DownloadURI string `json:"downloadUri"`
}

// Site contains the metadata for the dynamic static site
type Site struct {
	staticDirPath string
	siteID        string
	port          int
	// First singal starts graceful shutdown, when signal is returned, shutdown has completed
	shutdownChan chan struct{}
}

func (s *Site) proxyAddr() string {
	return fmt.Sprintf("http://localhost:%d", s.port)
}

func (s *Site) listenAddr() string {
	return fmt.Sprintf(":%d", s.port)
}

func (s *Site) shutdown() <-chan struct{} {
	s.shutdownChan <- struct{}{}
	return s.shutdownChan
}

type siteFetcher interface {
	Fetch(siteID string) (staticDirname string, err error)
	LastModified(siteID string) (lastModfiedResponse, error)
}

type siteManager struct {
	portMu      sync.Mutex
	initSiteMu  sync.Mutex
	ports       []int
	sites       []*Site
	siteFetcher siteFetcher
	siteRootDir string
}

func newSiteManager(fetcher siteFetcher) *siteManager {
	return &siteManager{
		siteFetcher: fetcher,
		sites:       make([]*Site, 0),
		ports:       make([]int, 0),
	}
}

func (m *siteManager) ShutdownAll() error {
	for _, site := range m.sites {
		<-site.shutdown()
	}
	return nil
}

func (m *siteManager) initSite(siteID string) error {

	newSite := &Site{
		// ADD static "WAIT" file
		staticDirPath: path.Join(m.siteRootDir, siteID),
		siteID:        siteID,
		port:          m.newPort(),
		shutdownChan:  make(chan struct{}),
	}
	m.sites = append(m.sites, newSite)

	if _, err := m.siteFetcher.LastModified(siteID); err != nil {
		return fmt.Errorf("%w: will not initialize a site server that cannot fetch content", err)
	}
	// start the micro app for the site
	go func() {
		app := fiber.New()
		app.Static("/", newSite.staticDirPath)
		app.Use(func(c *fiber.Ctx) error {
			uri := c.Context().RequestURI()
			log.Tracew("request to micro app", "site_id", siteID, "proxy_addr", newSite.proxyAddr(), "req_uri", string(uri),
				"static_dir", newSite.staticDirPath)
			return c.Next()
		})

		go func() {
			if err := app.Listen(newSite.listenAddr()); err != nil {
				log.Error(err)
			}
		}()

		<-newSite.shutdownChan
		if err := app.ShutdownWithTimeout(time.Second * 2); err != nil {
			log.Error(err)
		}
		newSite.shutdownChan <- struct{}{}
	}()
	return nil
}

func (m *siteManager) Request(c *fiber.Ctx, siteID string) error {
	if strings.Contains(siteID, ".") {
		return c.SendStatus(http.StatusNotFound)
	}

	m.initSiteMu.Lock()
	exists := false
	for _, site := range m.sites {
		if site.siteID == siteID {
			exists = true
			break
		}
	}

	if !exists {
		if err := m.initSite(siteID); err != nil {
			m.initSiteMu.Unlock()
			return err
		}
	}
	m.initSiteMu.Unlock()

	dir, err := m.siteFetcher.Fetch(siteID)
	if err != nil {
		log.Errorw("site fetch error", "err", err, "site_id", siteID)
		return c.SendStatus(http.StatusInternalServerError)
	}

	var currentSite *Site
	for i := range m.sites {
		if m.sites[i].siteID == siteID {
			currentSite = m.sites[i]
		}
	}

	if currentSite == nil {
		log.Errorw("current site is nil", "siteID", siteID, "static_dir", dir)
		return c.SendStatus(http.StatusInternalServerError)
	}
	currentSite.staticDirPath = dir

	u, _ := url.JoinPath(currentSite.proxyAddr(), c.Params("*"))
	log.Tracew("proxy forward ---> " + u)
	return proxy.Forward(u)(c)
}

func (m *siteManager) newPort() int {
	m.portMu.Lock()
	defer m.portMu.Unlock()
	newPort := 8090 + len(m.ports)
	m.ports = append(m.ports, newPort)
	return newPort
}

type artifactoryFetcher struct {
	host        string
	reqModFunc  func(*http.Request)
	client      *http.Client
	siteRootDir string
	repoPath    string
	mu          sync.Mutex
	hashTable   map[string]string
}

func (f *artifactoryFetcher) Fetch(siteID string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	resObj, err := f.LastModified(siteID)
	if err != nil {
		return "", err
	}
	modHash := hash(resObj.LastModified)
	sitePath := path.Join(f.siteRootDir, siteID)

	log.Tracew("", "fetcher", "artifactory", "last_modified", resObj.LastModified,
		"last_modified_hash", modHash, "siteID", siteID, "site_root_dir", f.siteRootDir,
		"site_path", sitePath)

	if f.hashTable[siteID] != modHash {
		err = f.downloadLatest(resObj, sitePath)
	}
	if err != nil {
		log.Errorw("fail to stat site path and/or download latest", "site_path", sitePath, "err", err)
		return "", err
	}
	f.hashTable[siteID] = modHash
	return sitePath, nil
}

func (f *artifactoryFetcher) downloadLatest(resObj lastModfiedResponse, sitePath string) error {
	if err := os.RemoveAll(sitePath); err != nil {
		log.Errorw("cannot clear content", "site_path", sitePath, "err", err)
		return err
	}
	if err := os.MkdirAll(sitePath, 0777); err != nil {
		return err
	}
	req, _ := http.NewRequest(http.MethodGet, resObj.URI, nil)
	f.reqModFunc(req)
	res, err := f.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %s", errAPI, res.Status)
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s", errAPI, res.Status)
	}

	fileInfoObj := fileInfoResponse{}
	if err := json.NewDecoder(res.Body).Decode(&fileInfoObj); err != nil {
		return err
	}
	// Download the tarball
	req, _ = http.NewRequest(http.MethodGet, fileInfoObj.DownloadURI, nil)
	f.reqModFunc(req)
	res, err = f.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %s", errAPI, res.Status)
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s", errAPI, res.Status)
	}

	defer res.Body.Close()
	if err := extractTo(sitePath, res.Body); err != nil {
		log.Errorw("extracting", "err", err.Error(), "site_path", sitePath)
		return err
	}
	return nil
}

func (f *artifactoryFetcher) LastModified(siteID string) (lastModfiedResponse, error) {
	var resObj lastModfiedResponse

	rawURL, _ := url.JoinPath(f.host, "artifactory", "api", "storage", f.repoPath, siteID)
	url, _ := url.Parse(rawURL)
	query := url.Query()
	query.Set("lastModified", "")
	url.RawQuery = query.Encode()

	log.Tracew("", "fetcher", "artifactory", "url", url, "siteID", siteID)
	req, _ := http.NewRequest(http.MethodGet, url.String(), nil)
	f.reqModFunc(req)
	res, err := f.client.Do(req)
	if err != nil {
		return resObj, fmt.Errorf("%w: %v", errAPI, err)
	}
	if res.StatusCode != http.StatusOK {
		return resObj, fmt.Errorf("%w: %s", errAPI, res.Status)
	}

	if err := json.NewDecoder(res.Body).Decode(&resObj); err != nil {
		return resObj, fmt.Errorf("%w: %s", errAPI, err)
	}
	return resObj, nil
}

func hash(s string) string {
	hasher := sha1.New()
	strings.NewReader(s).WriteTo(hasher)
	return hex.EncodeToString(hasher.Sum(nil))
}

// extractTo expects .tar.gz from reader
func extractTo(dir string, r io.Reader) error {
	buf := new(bytes.Buffer)

	gzipReader, err := gzip.NewReader(r)
	if err != nil {
		log.Errorw("initializing gzip reader", "err", err, "dest_dir", dir)
		return err
	}
	if _, err := buf.ReadFrom(gzipReader); err != nil {
		log.Errorw("reading into gzipReader", "err", err, "dest_dir", dir)
		return err
	}

	defer gzipReader.Close()

	tarReader := tar.NewReader(buf)

	for {
		hdr, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Errorw("parsing tarball", "err", err, "dest_dir", dir)
			return err
		}
		filename := path.Join(dir, hdr.Name)
		// Skip the root dir
		if filename == dir {
			continue
		}

		if hdr.FileInfo().IsDir() {
			log.Tracew("creating directory...", "dest", filename, "hdr_name", hdr.Name)
			if err := os.MkdirAll(filename, 0755); err != nil {
				return err
			}
			continue
		}
		f, err := os.Create(filename)
		defer f.Close()

		if err != nil {
			return err
		}
		log.Tracew("writing file...", "dest", filename, "hdr_name", hdr.Name)
		if _, err := f.ReadFrom(tarReader); err != nil {
			return err
		}
	}

	return nil
}

// type ArtifactoryService struct {
// 	host string
// 	// reqModFunc can be used to add authentication if necessary
// 	reqModFunc func(*http.Request)
// 	client     *http.Client
// }
//
// func (s *ArtifactoryService) lastModified(itemPath string) (lastModfiedResponse, error) {
// 	// log.Tracew("request", "name", c.Params("name"), "method", string(c.Request().Header.Method()), "request_uri", c.Request().URI())
//
// 	url, _ := url.JoinPath(s.host, "artifactory", "api", "storage", itemPath)
// 	log.Tracew("", "service", "artifactory", "url", url, "itemPath", itemPath)
// 	mod := lastModfiedResponse{}
// 	res, err := s.get(url)
// 	if err != nil {
// 		return mod, err
// 	}
// 	err = json.NewDecoder(res.Body).Decode(&mod)
// 	log.Debugw(fmt.Sprintf("%+v", mod), "service", "artifactory", "url", url, "decode_error", err)
// 	return mod, err
// }
//
// func (s *ArtifactoryService) get(url string) (*http.Response, error) {
// 	req, _ := http.NewRequest(http.MethodGet, url, nil)
// 	s.reqModFunc(req)
// 	res, err := s.client.Do(req)
// 	if err != nil {
// 		log.Errorw(err.Error(), "url", url, "service", "apiAgent")
// 		return nil, err
// 	}
//
// 	if res.StatusCode == http.StatusNotFound {
// 		return nil, errNotFound
// 	}
//
// 	if res.StatusCode != http.StatusOK {
// 		return nil, fmt.Errorf("status: %s", res.Status)
// 	}
// 	return res, nil
// }
//
// func (s *ArtifactoryService) WriteGenericItem(itemPath string, w io.Writer) error {
// 	url, _ := url.JoinPath(s.host, itemPath)
// 	log.Tracew("", "service", "artifactory", "url", url, "itemPath", itemPath)
// 	res, err := s.get(url)
// 	if err != nil {
// 		return err
// 	}
// 	_, err = io.Copy(w, res.Body)
// 	return err
// }
//
// func (s *ArtifactoryService) WriteGenericLastModifiedItem(itemPath string, w io.Writer) error {
// 	log.Tracew("", "service", "artifactory", "itemPath", itemPath)
// 	mod, err := s.lastModified(itemPath)
// 	if err != nil {
// 		log.Errorw(err.Error(), "service", "artifactory", "itemPath", itemPath)
// 		return err
// 	}
// 	res, err := s.get(mod.URI)
// 	if err != nil {
// 		return err
// 	}
// 	_, err = io.Copy(w, res.Body)
// 	return err
// }
