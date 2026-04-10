package logger

import "winkyou/pkg/config"

type Options struct {
	Level  string
	Format string
	Output string
	File   string
}

func DefaultOptions() Options {
	return Options{
		Level:  "info",
		Format: "text",
		Output: "stderr",
	}
}

func FromConfig(cfg *config.LogConfig) Options {
	if cfg == nil {
		return DefaultOptions()
	}

	return Options{
		Level:  cfg.Level,
		Format: cfg.Format,
		Output: cfg.Output,
		File:   cfg.File,
	}
}

