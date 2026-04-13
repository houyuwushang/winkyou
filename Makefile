GO ?= go
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null)
BUILD_TIME ?= $(shell if command -v powershell >/dev/null 2>&1; then powershell -NoProfile -Command "[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')"; else date -u +%Y-%m-%dT%H:%M:%SZ; fi)
LDFLAGS := -X 'winkyou/pkg/version.Version=$(VERSION)' -X 'winkyou/pkg/version.Commit=$(COMMIT)' -X 'winkyou/pkg/version.BuildTime=$(BUILD_TIME)'

.PHONY: tidy fmt test test-unit test-integration test-e2e test-e2e-privileged build build-all build-wink build-wink-coordinator build-wink-relay

tidy:
	$(GO) mod tidy

fmt:
	$(GO) fmt ./...

test:
	$(GO) test ./...

test-unit:
	$(GO) test $$( $(GO) list ./... | grep -v '^winkyou/test/' )

test-integration:
	WINKYOU_NETIF_ALLOW_MEMORY=1 WINKYOU_TUNNEL_ALLOW_MEMORY=1 $(GO) test ./test/integration/... -count=1

test-e2e:
	WINKYOU_NETIF_ALLOW_MEMORY=1 WINKYOU_TUNNEL_ALLOW_MEMORY=1 $(GO) test ./test/e2e/... -count=1

test-e2e-privileged:
	WINKYOU_E2E_PRIVILEGED=1 $(GO) test -tags=privileged_e2e ./test/e2e/... -count=1

build: build-wink

build-wink:
	$(GO) build -ldflags "$(LDFLAGS)" -o bin/wink ./cmd/wink

build-wink-coordinator:
	$(GO) build -ldflags "$(LDFLAGS)" -o bin/wink-coordinator ./cmd/wink-coordinator

build-wink-relay:
	$(GO) build -ldflags "$(LDFLAGS)" -o bin/wink-relay ./cmd/wink-relay

build-all: build-wink build-wink-coordinator build-wink-relay
