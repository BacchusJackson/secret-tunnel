FROM artifactory.cloud.cms.gov/docker/golang:1.21-alpine as build

WORKDIR /app

COPY go.mod ./

RUN apk add git && \
    go mod download

COPY . ./

RUN go build -o /app/bin/batcave-docs ./...


FROM artifactory.cloud.cms.gov/docker/golang:1.21-alpine

WORKDIR /app

COPY --from=build /app/bin/batcave-docs .

EXPOSE 8080

CMD [ "/app/batcave-docs" ]
