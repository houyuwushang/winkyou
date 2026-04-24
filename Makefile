GO ?= go
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null)
BUILD_TIME ?= $(shell if command -v powershell >/dev/null 2>&1; then powershell -NoProfile -Command "[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')"; else date -u +%Y-%m-%dT%H:%M:%SZ; fi)
LDFLAGS := -X 'winkyou/pkg/version.Version=$(VERSION)' -X 'winkyou/pkg/version.Commit=$(COMMIT)' -X 'winkyou/pkg/version.BuildTime=$(BUILD_TIME)'

.PHONY: tidy fmt test test-unit test-integration test-e2e test-e2e-privileged test-e2e-relay test-e2e-relay-privileged test-phase2d build build-all build-wink build-wink-coordinator build-wink-relay build-windows-client build-linux-client build-linux-coordinator build-linux-relay build-deploy-preview ensure-bin

ensure-bin:
	@mkdir -p bin

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

test-e2e-relay:
	WINKYOU_FORCE_RELAY=1 WINKYOU_NETIF_ALLOW_MEMORY=1 WINKYOU_TUNNEL_ALLOW_MEMORY=1 $(GO) test ./pkg/client ./test/e2e/... -count=1 -run TestRelay

test-e2e-relay-privileged:
	WINKYOU_E2E_PRIVILEGED=1 WINKYOU_FORCE_RELAY=1 $(GO) test -tags=privileged_e2e ./test/e2e/... -count=1 -run TestRelay

test-phase2d:
	$(GO) test ./pkg/solver/strategy/legacyice -count=10
	$(GO) test ./pkg/session -count=10
	WINKYOU_FORCE_RELAY=1 WINKYOU_NETIF_ALLOW_MEMORY=1 WINKYOU_TUNNEL_ALLOW_MEMORY=1 $(GO) test ./pkg/client -run TestRelayWGGoTwoEnginesExchangeIPv4Packets -count=3 -v
	$(GO) test ./... -count=1

build: build-wink

build-wink: ensure-bin
	$(GO) build -ldflags "$(LDFLAGS)" -o bin/wink ./cmd/wink

build-wink-coordinator: ensure-bin
	$(GO) build -ldflags "$(LDFLAGS)" -o bin/wink-coordinator ./cmd/wink-coordinator

build-wink-relay: ensure-bin
	$(GO) build -ldflags "$(LDFLAGS)" -o bin/wink-relay ./cmd/wink-relay

build-all: build-wink build-wink-coordinator build-wink-relay

build-windows-client: ensure-bin
	GOOS=windows GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o bin/wink.exe ./cmd/wink

build-linux-client: ensure-bin
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o bin/wink ./cmd/wink

build-linux-coordinator: ensure-bin
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o bin/wink-coordinator ./cmd/wink-coordinator

build-linux-relay: ensure-bin
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o bin/wink-relay ./cmd/wink-relay

build-deploy-preview: build-windows-client build-linux-client build-linux-coordinator build-linux-relay
