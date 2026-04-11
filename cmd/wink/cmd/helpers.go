package cmd

import (
	"fmt"

	winkclient "winkyou/pkg/client"
	"winkyou/pkg/config"
	"winkyou/pkg/logger"
)

func loadConfig(opts *Options) (*config.Config, error) {
	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}

	return cfg, nil
}

func loadRuntime(opts *Options) (*config.Config, logger.Logger, error) {
	cfg, err := loadConfig(opts)
	if err != nil {
		return nil, nil, err
	}

	if opts.Verbose {
		cfg.Log.Level = "debug"
	}

	log, err := logger.New(&cfg.Log)
	if err != nil {
		return nil, nil, fmt.Errorf("create logger: %w", err)
	}

	return cfg, log, nil
}

func runtimeStatePath(opts *Options) string {
	return winkclient.RuntimeStatePath(opts.ConfigPath)
}
