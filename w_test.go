package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

var mockTGZFile = ".sandbox/kld-hugo-20230822T184130Z.tgz"

func TestExtract(t *testing.T) {
	f, err := os.Open(mockTGZFile)
	if err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	if err := extractTo(dest, f); err != nil {
		t.Fatal(err)
	}

	fmt.Printf("Filename: %s\n", f.Name())
}

func TestArtifactoryFetcher(t *testing.T) {
	svr := mockServer(t)
	rootDir := t.TempDir()
	fetcher := &artifactoryFetcher{
		host:        svr.URL,
		client:      svr.Client(),
		reqModFunc:  func(r *http.Request) {},
		siteRootDir: rootDir,
		repoPath:    "repo",
	}
	outDir, err := fetcher.Fetch("site-a")
	if err != nil {
		t.Fatal(err)
	}
	err = filepath.Walk(outDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		t.Logf("Size: %8d Path: %s,", info.Size(), path)
		return nil
	})

	if err != nil {
		t.Fatal(err)
	}
}

func mockServer(t *testing.T) *httptest.Server {
	downloadServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("[download server]", r.RequestURI)
		if r.RequestURI == "/site-a/abc-123/download" {
			if _, err := io.Copy(w, MustOpen(mockTGZFile, t)); err != nil {
				t.Fatal(err)
			}
		}
	}))

	fileInfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("[file info server]", r.RequestURI)
		if r.RequestURI == "/site-a/abc-123" {
			json.NewEncoder(w).Encode(&fileInfoResponse{
				DownloadURI: downloadServer.URL + "/site-a/abc-123/download",
			})
		}
	}))
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("[last modified server] ", r.RequestURI)
		t.Log("[last modified server] ", r.URL)
		if r.RequestURI == "/artifactory/api/storage/repo/site-a?lastModified=" {
			json.NewEncoder(w).Encode(&lastModfiedResponse{
				URI:          fileInfoServer.URL + "/site-a/abc-123",
				LastModified: "abc-123",
			})
		}
	}))
}

func MustOpen(filename string, t *testing.T) *os.File {
	f, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
