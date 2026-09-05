package sshchildwrapper

import (
	"bytes"
	"strings"
)

// ValidateRootSSHDResolvedConfig validates the additional Gate C1b scheme-B
// execution domain. It does not replace or relax the C1a validator, execute
// sshd, or accept a configuration path. Callers must separately verify the
// exact owner-only key entry returned by AuthorizedKeyOptions.
func ValidateRootSSHDResolvedConfig(payload []byte) error {
	if ValidateSSHDResolvedConfig(payload) != nil || bytes.IndexByte(payload, 0) >= 0 {
		return ErrWrapperInvalid
	}
	wanted := map[string]string{
		"permitrootlogin":              "forced-commands-only",
		"authenticationmethods":        "publickey",
		"pubkeyauthentication":         "yes",
		"passwordauthentication":       "no",
		"kbdinteractiveauthentication": "no",
		"permituserenvironment":        "no",
		"disableforwarding":            "yes",
		"permittty":                    "no",
		"permituserrc":                 "no",
	}
	seen := make(map[string]bool, len(wanted))
	for _, line := range strings.Split(strings.ReplaceAll(string(payload), "\r\n", "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		key := strings.ToLower(fields[0])
		value, required := wanted[key]
		if !required {
			continue
		}
		if seen[key] || len(fields) != 2 || strings.ToLower(fields[1]) != value {
			return ErrWrapperInvalid
		}
		seen[key] = true
	}
	if len(seen) != len(wanted) {
		return ErrWrapperInvalid
	}
	return nil
}
