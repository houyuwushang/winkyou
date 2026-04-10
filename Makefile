GO ?= go
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>NUL)
BUILD_TIME ?= $(shell powershell -NoProfile -Command "[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')")
LDFLAGS := -X 'winkyou/pkg/version.Version=$(VERSION)' -X 'winkyou/pkg/version.Commit=$(COMMIT)' -X 'winkyou/pkg/version.BuildTime=$(BUILD_TIME)'

.PHONY: tidy fmt test build

tidy:
	$(GO) mod tidy

fmt:
	$(GO) fmt ./...

test:
	$(GO) test ./...

build:
	$(GO) build -ldflags "$(LDFLAGS)" -o bin/wink ./cmd/wink

