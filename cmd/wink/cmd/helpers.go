package cmd

import (
	"fmt"

	"winkyou/pkg/config"
	"winkyou/pkg/logger"
)

func loadRuntime(opts *Options) (*config.Config, logger.Logger, error) {
	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load config: %w", err)
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

