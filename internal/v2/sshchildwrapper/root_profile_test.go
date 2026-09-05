package sshchildwrapper

import (
	"errors"
	"strings"
	"testing"
)

const rootSSHDResolvedFixture = `permitrootlogin forced-commands-only
authenticationmethods publickey
pubkeyauthentication yes
passwordauthentication no
kbdinteractiveauthentication no
permituserenvironment no
disableforwarding yes
permittty no
permituserrc no
`

func TestRootSSHDProfileRequiresDedicatedForcedCommandOnly(t *testing.T) {
	for _, fixture := range []string{rootSSHDResolvedFixture, strings.ReplaceAll(rootSSHDResolvedFixture, "\n", "\r\n")} {
		if err := ValidateRootSSHDResolvedConfig([]byte(fixture)); err != nil {
			t.Fatal("frozen root execution profile rejected")
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(rootSSHDResolvedFixture), "\n") {
		fields := strings.Fields(line)
		for _, mutation := range []struct{ name, value string }{
			{"missing", strings.Replace(rootSSHDResolvedFixture, line+"\n", "", 1)},
			{"duplicate", rootSSHDResolvedFixture + line + "\n"},
			{"wrong", strings.Replace(rootSSHDResolvedFixture, line, fields[0]+" invalid", 1)},
			{"extra_value", strings.Replace(rootSSHDResolvedFixture, line, line+" extra", 1)},
		} {
			t.Run(fields[0]+"/"+mutation.name, func(t *testing.T) {
				if !errors.Is(ValidateRootSSHDResolvedConfig([]byte(mutation.value)), ErrWrapperInvalid) {
					t.Fatal("unsafe root execution profile accepted")
				}
			})
		}
	}
	for _, rootPolicy := range []string{"yes", "prohibit-password", "without-password", "no"} {
		fixture := strings.Replace(rootSSHDResolvedFixture, "forced-commands-only", rootPolicy, 1)
		if !errors.Is(ValidateRootSSHDResolvedConfig([]byte(fixture)), ErrWrapperInvalid) {
			t.Fatal("non-exact root policy accepted")
		}
	}
	for _, fixture := range [][]byte{nil, []byte(rootSSHDResolvedFixture + "\x00"), []byte(strings.Repeat("x", 64*1024+1))} {
		if !errors.Is(ValidateRootSSHDResolvedConfig(fixture), ErrWrapperInvalid) {
			t.Fatal("malformed root profile accepted")
		}
	}
}
