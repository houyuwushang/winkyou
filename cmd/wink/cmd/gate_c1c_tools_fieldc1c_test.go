//go:build fieldc1c

package cmd

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"winkyou/internal/v2/fieldc1c"
)

// Synthetic resolved configuration: no address, key, path or host identity.
const fieldSSHDResolvedGolden = `permitrootlogin forced-commands-only
authenticationmethods publickey
pubkeyauthentication yes
passwordauthentication no
kbdinteractiveauthentication no
permituserenvironment no
disableforwarding yes
permittty no
permituserrc no
maxsessions 1
maxstartups 1:1:1
logingracetime 3
forcecommand none
`

func TestFieldToolsSSHDCommandGolden(t *testing.T) {
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetIn(strings.NewReader(fieldSSHDResolvedGolden))
	root.SetArgs([]string{"gate-c1c", "verify-sshd"})
	if err := root.Execute(); err != nil || out.String() != "{\"ok\":true}\n" {
		t.Fatalf("read-only command absent or golden mismatch: class=%T bytes=%d", err, out.Len())
	}
}

type fieldPanicReader struct{}

func (fieldPanicReader) Read([]byte) (int, error) { panic("invalid arguments performed I/O") }

func TestFieldToolsRejectGlobalFlagPresenceBeforeInput(t *testing.T) {
	for _, flag := range []string{"--config=", "--state=", "--verbose=false"} {
		for _, method := range []string{"verify-sshd", "ledger", "derive"} {
			t.Run(method+flag, func(t *testing.T) {
				root := newRootCmd()
				var out bytes.Buffer
				root.SetOut(&out)
				root.SetErr(&out)
				root.SetIn(fieldPanicReader{})
				root.SetArgs([]string{"gate-c1c", method, flag})
				if err := root.Execute(); !errors.Is(err, fieldc1c.ErrInvalid) {
					t.Fatal("flag presence did not fail with stable invalid class")
				}
			})
		}
	}
}
