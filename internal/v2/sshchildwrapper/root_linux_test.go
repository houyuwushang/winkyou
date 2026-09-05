//go:build linux

package sshchildwrapper

import (
	"errors"
	"reflect"
	"testing"
)

func TestRootExecutionChecksIdentityAndInstallationBeforePlan(t *testing.T) {
	for _, test := range []struct {
		name, command string
		uid, euid     int
		installation  error
		wantChecks    int
		wantOK        bool
	}{
		{"root", FixedClientCommand, 0, 0, nil, 1, true},
		{"unprivileged", FixedClientCommand, 1000, 1000, nil, 0, false},
		{"setuid", FixedClientCommand, 1000, 0, nil, 0, false},
		{"dropped", FixedClientCommand, 0, 1000, nil, 0, false},
		{"command", FixedClientCommand + " --extra", 0, 0, nil, 0, false},
		{"installation", FixedClientCommand, 0, 0, ErrWrapperInvalid, 1, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			checks := 0
			got, err := prepareRootExecution(test.command, test.uid, test.euid, func() error {
				checks++
				return test.installation
			})
			if checks != test.wantChecks || (err == nil) != test.wantOK {
				t.Fatal("root identity or installation boundary changed")
			}
			if test.wantOK {
				want, _ := Plan(FixedClientCommand)
				if !reflect.DeepEqual(got, want) {
					t.Fatal("root execution changed C1a argv/environment/umask")
				}
			} else if !errors.Is(err, ErrWrapperInvalid) || !reflect.DeepEqual(got, Execution{}) {
				t.Fatal("invalid root execution returned a usable plan")
			}
		})
	}
	if _, err := prepareRootExecution(FixedClientCommand, 0, 0, nil); !errors.Is(err, ErrWrapperInvalid) {
		t.Fatal("missing installation verifier accepted")
	}
}
