package netif

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
)

var errUnsupportedBackend = errors.New("netif: backend unsupported on this platform")

func newByBackend(cfg Config) (NetworkInterface, error) {
	backend, err := normalizeBackend(cfg.Backend)
	if err != nil {
		return nil, err
	}

	switch backend {
	case "tun":
		return createTUNInterface(cfg)
	case "memory":
		if !allowMemoryBackendForTest() {
			return nil, fmt.Errorf("netif: memory backend is test-only")
		}
		return newMemoryInterface(Config{Backend: "userspace", MTU: cfg.MTU}), nil
	case "userspace":
		return nil, fmt.Errorf("netif: userspace backend not implemented: %w", ErrNotImplemented)
	case "proxy":
		return nil, fmt.Errorf("netif: proxy backend not implemented: %w", ErrNotImplemented)
	case "auto":
		return newAuto(cfg)
	default:
		return nil, fmt.Errorf("netif: unknown backend: %s", backend)
	}
}

func normalizeBackend(backend string) (string, error) {
	switch backend {
	case "", "auto", "tun", "userspace", "proxy", "memory":
		if backend == "" {
			return "auto", nil
		}
		return backend, nil
	default:
		return "", fmt.Errorf("netif: unknown backend: %s", backend)
	}
}

func newAuto(cfg Config) (NetworkInterface, error) {
	if allowMemoryBackendForTest() {
		return newMemoryInterface(Config{Backend: "userspace", MTU: cfg.MTU}), nil
	}

	candidates := []string{"userspace", "proxy"}
	if supportsTUN(runtime.GOOS) {
		candidates = append([]string{"tun"}, candidates...)
	}

	var errs []string
	for _, backend := range candidates {
		next := cfg
		next.Backend = backend
		ni, err := newByBackend(next)
		if err == nil {
			return ni, nil
		}
		errs = append(errs, fmt.Sprintf("%s: %v", backend, err))
	}

	return nil, fmt.Errorf("netif: auto backend selection failed: %s", strings.Join(errs, "; "))
}

func supportsTUN(goos string) bool {
	switch goos {
	case "linux", "darwin", "windows":
		return true
	default:
		return false
	}
}

func allowMemoryBackendForTest() bool {
	if os.Getenv("WINKYOU_NETIF_ALLOW_MEMORY") == "1" {
		return true
	}
	return strings.HasSuffix(os.Args[0], ".test")
}
