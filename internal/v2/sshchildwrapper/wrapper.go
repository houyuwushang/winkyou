package sshchildwrapper

import (
	"bytes"
	"errors"
	"strings"
)

const (
	FixedWrapperPath   = "/usr/libexec/winkyou/gate-c-child-wrapper"
	FixedBinaryPath    = "/usr/libexec/winkyou/wink"
	FixedClientCommand = "wink solver direct child --stdio"
	FixedUmask         = 0o077
)

var (
	ErrWrapperInvalid     = errors.New("sshchildwrapper: fixed wrapper domain is invalid")
	ErrWrapperUnsupported = errors.New("sshchildwrapper: platform is unsupported")
)

type Execution struct {
	Executable  string
	Arguments   []string
	Environment []string
	Umask       uint32
}

// Plan validates SSH_ORIGINAL_COMMAND byte-for-byte and returns the only
// allowed child execution. It never invokes a shell or searches PATH.
func Plan(originalCommand string) (Execution, error) {
	if originalCommand != FixedClientCommand {
		return Execution{}, ErrWrapperInvalid
	}
	return Execution{
		Executable:  FixedBinaryPath,
		Arguments:   []string{"solver", "direct", "child", "--stdio"},
		Environment: []string{"LANG=C", "LC_ALL=C"},
		Umask:       FixedUmask,
	}, nil
}

// AuthorizedKeyOptions returns the fixed option prefix for the dedicated Gate
// C key. The public key material is intentionally supplied only by deployment.
func AuthorizedKeyOptions() string {
	return `restrict,command="` + FixedWrapperPath + `"`
}

// ValidateSSHDResolvedConfig checks the stable, relevant subset of a private
// deployment's sanitized sshd -T -C output. It accepts no config path and
// performs no process or network operation.
func ValidateSSHDResolvedConfig(payload []byte) error {
	if len(payload) == 0 || len(payload) > 64*1024 || bytes.IndexByte(payload, 0) >= 0 {
		return ErrWrapperInvalid
	}
	wanted := map[string]string{"permituserenvironment": "no"}
	seen := make(map[string]string, len(wanted))
	for _, line := range strings.Split(strings.ReplaceAll(string(payload), "\r\n", "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		key := strings.ToLower(fields[0])
		if _, required := wanted[key]; required {
			if _, duplicate := seen[key]; duplicate {
				return ErrWrapperInvalid
			}
			seen[key] = strings.ToLower(fields[1])
		}
	}
	for key, value := range wanted {
		if seen[key] != value {
			return ErrWrapperInvalid
		}
	}
	return nil
}

func ValidateFixedInstallation() error { return validateFixedInstallation() }
