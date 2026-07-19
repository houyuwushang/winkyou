package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	winkclient "winkyou/pkg/client"
	"winkyou/pkg/processidentity"

	"github.com/spf13/cobra"
)

const defaultDownTimeout = 10 * time.Second

func newDownCmd(opts *Options) *cobra.Command {
	var force bool
	var timeout time.Duration

	cmd := &cobra.Command{
		Use:   "down",
		Short: "Disconnect and stop",
		RunE: func(cmd *cobra.Command, args []string) error {
			if timeout <= 0 {
				return fmt.Errorf("--timeout must be greater than zero")
			}

			stateKey := runtimeStateKey(opts)
			state, err := winkclient.LoadRuntimeState(stateKey)
			if err != nil {
				if errors.Is(err, winkclient.ErrRuntimeStateNotFound) {
					cmd.Println("wink down: no active runtime state")
					return nil
				}
				return err
			}

			if isManagedRuntimeState(state) {
				if strings.TrimSpace(state.ControlEndpoint) == "" {
					return fmt.Errorf("wink down: refusing managed shutdown: runtime state has no control endpoint")
				}
				if err := validateManagedRuntimeOwner(state); err != nil {
					return fmt.Errorf("wink down: refusing managed shutdown: %w", err)
				}
				ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
				defer cancel()
				if err := requestGracefulRuntimeStop(ctx, state); err != nil {
					if force {
						return fmt.Errorf("wink down: graceful stop failed: %w (--force never bypasses authenticated shutdown for managed runtimes)", err)
					}
					return fmt.Errorf("wink down: graceful stop failed: %w", err)
				}
				if err := waitRuntimeStateRemoved(ctx, stateKey, state.InstanceID); err != nil {
					if force {
						return fmt.Errorf("wink down: %w (--force never kills a managed runtime by PID)", err)
					}
					return err
				}
				cmd.Printf("wink down: gracefully stopped pid=%d\n", state.PID)
				return nil
			}

			// Legacy runtimes predate the authenticated loopback shutdown endpoint.
			// Make their PID-only compatibility path explicit; a plain wink down
			// must never kill an unverifiable process instance.
			if !force {
				return fmt.Errorf("wink down: legacy runtime has no authenticated shutdown endpoint; verify pid %d and retry with --force", state.PID)
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()
			if err := forceStopLegacyRuntime(ctx, state.PID); err != nil {
				return fmt.Errorf("wink down: legacy force-stop failed; runtime state was kept: %w", err)
			}
			if err := winkclient.RemoveRuntimeState(stateKey); err != nil {
				return err
			}

			cmd.Printf("wink down: force-stopped pid=%d\n", state.PID)
			return nil
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "allow legacy PID-based stop; never bypass managed authenticated shutdown")
	cmd.Flags().DurationVar(&timeout, "timeout", defaultDownTimeout, "maximum time to wait for graceful shutdown")
	return cmd
}

func isManagedRuntimeState(state *winkclient.RuntimeState) bool {
	if state == nil {
		return false
	}
	return strings.TrimSpace(state.InstanceID) != "" ||
		strings.TrimSpace(state.ProcessStartID) != "" ||
		strings.TrimSpace(state.ControlEndpoint) != "" ||
		strings.TrimSpace(state.ShutdownToken) != ""
}

func validateManagedRuntimeOwner(state *winkclient.RuntimeState) error {
	if state == nil {
		return fmt.Errorf("runtime state is nil")
	}
	if strings.TrimSpace(state.InstanceID) == "" {
		return fmt.Errorf("runtime state has no instance id")
	}
	if state.PID <= 0 {
		return fmt.Errorf("runtime state has invalid pid %d", state.PID)
	}
	processStartID := strings.TrimSpace(state.ProcessStartID)
	if processStartID == "" {
		return fmt.Errorf("runtime state has no process start identity")
	}
	matches, err := processidentity.Matches(state.PID, processStartID)
	if err != nil {
		return fmt.Errorf("verify pid %d identity: %w", state.PID, err)
	}
	if !matches {
		return fmt.Errorf("pid %d is no longer the recorded process instance", state.PID)
	}
	return nil
}

func requestGracefulRuntimeStop(ctx context.Context, state *winkclient.RuntimeState) error {
	if state == nil {
		return fmt.Errorf("runtime state is nil")
	}
	token := strings.TrimSpace(state.ShutdownToken)
	if token == "" {
		return fmt.Errorf("runtime state has no shutdown token")
	}

	endpoint, err := loopbackControlURL(state.ControlEndpoint)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/v1/shutdown", nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Wink-Shutdown-Token", token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("control endpoint returned %s", resp.Status)
	}
	return nil
}

func loopbackControlURL(endpoint string) (string, error) {
	raw := strings.TrimSpace(endpoint)
	if raw == "" {
		return "", fmt.Errorf("runtime state has no control endpoint")
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid control endpoint: %w", err)
	}
	if parsed.Scheme != "http" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("control endpoint must be a plain loopback http address")
	}
	host := parsed.Hostname()
	if !strings.EqualFold(host, "localhost") {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return "", fmt.Errorf("refusing non-loopback control endpoint %q", endpoint)
		}
	}
	if parsed.Port() == "" {
		return "", fmt.Errorf("control endpoint must include a port")
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func waitRuntimeStateRemoved(ctx context.Context, stateKey, instanceID string) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		state, err := winkclient.LoadRuntimeState(stateKey)
		if errors.Is(err, winkclient.ErrRuntimeStateNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if state.InstanceID != instanceID {
			return fmt.Errorf("runtime state was replaced by instance %q while waiting for instance %q to stop", state.InstanceID, instanceID)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for runtime cleanup: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func forceStopLegacyRuntime(ctx context.Context, pid int) error {
	if pid <= 0 {
		return fmt.Errorf("invalid pid %d", pid)
	}
	if pid == os.Getpid() {
		return fmt.Errorf("refusing to terminate the current wink command process")
	}
	processStartID, alive, err := processidentity.Inspect(pid)
	if err != nil {
		return fmt.Errorf("inspect pid %d before termination: %w", pid, err)
	}
	if !alive {
		return nil
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := process.Kill(); err != nil {
		return err
	}

	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		matches, err := processidentity.Matches(pid, processStartID)
		if err != nil {
			return fmt.Errorf("confirm pid %d termination: %w", pid, err)
		}
		if !matches {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out confirming pid %d termination: %w", pid, ctx.Err())
		case <-ticker.C:
		}
	}
}
