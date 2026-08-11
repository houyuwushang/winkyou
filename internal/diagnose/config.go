package diagnose

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"winkyou/pkg/config"
)

func inspectConfiguration(path string) ConfigStatus {
	explicit := strings.TrimSpace(path) != ""
	resolved := path
	if !explicit {
		path = ""
		resolved = config.DefaultPath()
	}
	status := ConfigStatus{ExplicitPath: explicit}
	info, statErr := os.Stat(resolved)
	switch {
	case statErr == nil:
		status.FilePresent = true
		if info.IsDir() {
			status.State = ConfigInvalid
			status.Source = configSource(explicit, true)
			status.Detail = "configuration path is a directory"
			return status
		}
	case errors.Is(statErr, os.ErrNotExist) && explicit:
		status.State = ConfigMissing
		status.Source = "custom_file"
		status.Detail = "explicit configuration file was not found"
		return status
	case errors.Is(statErr, os.ErrNotExist):
		status.Source = "defaults_and_environment"
	case statErr != nil:
		status.State = ConfigUnavailable
		status.Source = configSource(explicit, false)
		status.Detail = sanitizeConfigError(statErr.Error(), resolved)
		return status
	}

	if _, err := config.Load(path); err != nil {
		status.State = ConfigInvalid
		if status.Source == "" {
			status.Source = configSource(explicit, status.FilePresent)
		}
		status.Detail = "configuration could not be loaded or validated; field values are omitted from this passive report"
		return status
	}
	status.State = ConfigReady
	if status.Source == "" {
		status.Source = configSource(explicit, status.FilePresent)
	}
	if status.FilePresent {
		status.Detail = "configuration file loaded and validated; values are omitted from this report"
	} else {
		status.Detail = "built-in defaults and local environment validated; no default file was found"
	}
	return status
}

func configSource(explicit, present bool) string {
	if explicit {
		return "custom_file"
	}
	if present {
		return "default_file"
	}
	return "defaults_and_environment"
}

func sanitizeConfigError(detail, path string) string {
	for _, candidate := range []string{path, filepath.Clean(path)} {
		if strings.TrimSpace(candidate) != "" && candidate != "." {
			detail = strings.ReplaceAll(detail, candidate, "<config>")
		}
	}
	return boundedText(detail, 512)
}

func boundedText(value string, maxBytes int) string {
	if !utf8.ValidString(value) {
		value = strings.ToValidUTF8(value, "?")
	}
	value = strings.Map(func(current rune) rune {
		if unicode.IsControl(current) {
			return ' '
		}
		return current
	}, value)
	value = strings.Join(strings.Fields(value), " ")
	if maxBytes <= 0 {
		return ""
	}
	for len(value) > maxBytes {
		_, size := utf8.DecodeLastRuneInString(value)
		value = value[:len(value)-size]
	}
	return value
}
