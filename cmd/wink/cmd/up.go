package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	winkclient "winkyou/pkg/client"

	"winkyou/pkg/logger"
	"winkyou/pkg/processidentity"
)

func newUpCmd(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "up",
		Short: "Start and connect to the network",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, log, err := loadRuntime(opts)
			if err != nil {
				return err
			}
			defer log.Sync()

			stateKey := runtimeStateKey(opts)
			runtimeLock, err := winkclient.AcquireRuntimeStateLock(stateKey)
			if err != nil {
				if errors.Is(err, winkclient.ErrRuntimeStateLocked) {
					return fmt.Errorf("wink is already starting or running for state %s", winkclient.RuntimeStatePath(stateKey))
				}
				return err
			}
			defer func() {
				if err := runtimeLock.Close(); err != nil {
					log.Warn("failed to release runtime lifecycle lock", logger.Error(err))
				}
			}()

			if err := prepareRuntimeStateForStart(stateKey); err != nil {
				return err
			}

			engine, err := winkclient.NewEngine(cfg, log, stateKey)
			if err != nil {
				return err
			}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			if err := engine.Start(ctx); err != nil {
				return err
			}

			status := engine.Status()
			log.Info(
				"wink engine started",
				logger.String("node", status.NodeName),
				logger.String("node_id", status.NodeID),
				logger.String("virtual_ip", status.VirtualIP.String()),
				logger.String("backend", status.Backend),
				logger.String("nat_type", status.NATType),
			)
			cmd.Printf(
				"wink up: node=%s id=%s ip=%s backend=%s nat=%s state_file=%s\n",
				status.NodeName,
				status.NodeID,
				status.VirtualIP.String(),
				status.Backend,
				status.NATType,
				runtimeStatePath(opts),
			)

			if doneEngine, ok := engine.(winkclient.DoneEngine); ok {
				if done := doneEngine.Done(); done != nil {
					select {
					case <-ctx.Done():
					case <-done:
					}
				} else {
					<-ctx.Done()
				}
			} else {
				<-ctx.Done()
			}
			return engine.Stop()
		},
	}
}

func prepareRuntimeStateForStart(stateKey string) error {
	state, err := winkclient.LoadRuntimeState(stateKey)
	if errors.Is(err, winkclient.ErrRuntimeStateNotFound) {
		return nil
	}
	if err != nil {
		return err
	}

	if processStartID := strings.TrimSpace(state.ProcessStartID); processStartID != "" {
		matches, matchErr := processidentity.Matches(state.PID, processStartID)
		if matchErr != nil {
			return fmt.Errorf("verify existing wink process identity: %w", matchErr)
		}
		if matches {
			return fmt.Errorf("wink is already running (pid %d, instance %s)", state.PID, state.InstanceID)
		}
		if strings.TrimSpace(state.InstanceID) == "" {
			return fmt.Errorf("stale managed runtime state has no instance id; refusing automatic removal")
		}
		return winkclient.RemoveRuntimeStateIfInstance(stateKey, state.InstanceID)
	}

	if strings.TrimSpace(state.ControlEndpoint) != "" || strings.TrimSpace(state.InstanceID) != "" {
		return fmt.Errorf("managed runtime state has no process start identity; refusing automatic removal")
	}
	if state.IsFresh(20 * time.Second) {
		return fmt.Errorf("wink is already running (pid %d)", state.PID)
	}
	return winkclient.RemoveRuntimeState(stateKey)
}
