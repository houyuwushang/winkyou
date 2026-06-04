package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

const defaultLogTailLines = 100

func newLogsCmd(opts *Options) *cobra.Command {
	var logPath string
	tailLines := defaultLogTailLines

	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Show client log file output",
		RunE: func(cmd *cobra.Command, args []string) error {
			if tailLines < 0 {
				return fmt.Errorf("--tail must be greater than or equal to zero")
			}

			path, enabled, err := resolveLogFilePath(opts, logPath)
			if err != nil {
				return err
			}
			if !enabled {
				cmd.Println("File logging is disabled for this config.")
				cmd.Println("Set log.output: file and log.file: <path> in the client config to use wink logs.")
				return nil
			}

			return printLogFile(cmd, path, tailLines)
		},
	}

	cmd.Flags().StringVar(&logPath, "path", "", "read logs from this file instead of config log.file")
	cmd.Flags().IntVar(&tailLines, "tail", defaultLogTailLines, "number of trailing log lines to show")
	return cmd
}

func resolveLogFilePath(opts *Options, override string) (string, bool, error) {
	if path := strings.TrimSpace(override); path != "" {
		return path, true, nil
	}

	cfg, err := loadConfig(opts)
	if err != nil {
		return "", false, err
	}
	if !strings.EqualFold(strings.TrimSpace(cfg.Log.Output), "file") || strings.TrimSpace(cfg.Log.File) == "" {
		return "", false, nil
	}
	return cfg.Log.File, true, nil
}

func printLogFile(cmd *cobra.Command, path string, tailLines int) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read log file %s: %w", path, err)
	}

	lines := splitLogLines(string(raw))
	start := 0
	if tailLines > 0 && len(lines) > tailLines {
		start = len(lines) - tailLines
	}
	if tailLines == 0 {
		start = len(lines)
	}

	cmd.Printf("Log File: %s\n", path)
	for _, line := range lines[start:] {
		cmd.Println(line)
	}
	return nil
}

func splitLogLines(raw string) []string {
	normalized := strings.ReplaceAll(raw, "\r\n", "\n")
	normalized = strings.TrimRight(normalized, "\n")
	if normalized == "" {
		return nil
	}
	return strings.Split(normalized, "\n")
}
