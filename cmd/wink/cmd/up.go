package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	winkclient "winkyou/pkg/client"

	"winkyou/pkg/logger"
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

			if state, stateErr := winkclient.LoadRuntimeState(opts.ConfigPath); stateErr == nil {
				if state.IsFresh(20 * time.Second) {
					return fmt.Errorf("wink is already running (pid %d)", state.PID)
				}
				if err := winkclient.RemoveRuntimeState(opts.ConfigPath); err != nil {
					return err
				}
			} else if !errors.Is(stateErr, winkclient.ErrRuntimeStateNotFound) {
				return stateErr
			}

			engine, err := winkclient.NewEngine(cfg, log, opts.ConfigPath)
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
				"wink up: node=%s id=%s ip=%s backend=%s nat=%s state=%s\n",
				status.NodeName,
				status.NodeID,
				status.VirtualIP.String(),
				status.Backend,
				status.NATType,
				runtimeStatePath(opts),
			)

			<-ctx.Done()
			return engine.Stop()
		},
	}
}
