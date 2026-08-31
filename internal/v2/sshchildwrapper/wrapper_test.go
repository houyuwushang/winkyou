package sshchildwrapper

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestPlanFreezesAbsoluteBinaryArgvEnvironmentAndUmask(t *testing.T) {
	plan, err := Plan(FixedClientCommand)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Executable != FixedBinaryPath || !reflect.DeepEqual(plan.Arguments, []string{"solver", "direct", "child", "--stdio"}) ||
		!reflect.DeepEqual(plan.Environment, []string{"LANG=C", "LC_ALL=C"}) || plan.Umask != 0o077 {
		t.Fatal("fixed wrapper execution plan changed")
	}
	if !strings.HasPrefix(plan.Executable, "/") || strings.Contains(strings.Join(plan.Arguments, " "), "sh -c") {
		t.Fatal("execution plan is not an absolute direct exec")
	}
	for _, forbidden := range []string{"PATH=", "SSH_ORIGINAL_COMMAND", "SSH_AUTH_SOCK", "SSH_ASKPASS"} {
		if strings.Contains(strings.Join(plan.Environment, "\n"), forbidden) {
			t.Fatalf("execution environment contains %s", forbidden)
		}
	}
}

func TestPlanRejectsEveryNonExactOriginalCommand(t *testing.T) {
	for _, value := range []string{"", "wink solver direct child", FixedClientCommand + " ", "sh -c '" + FixedClientCommand + "'", "wink solver direct child --stdio --extra"} {
		if _, err := Plan(value); !errors.Is(err, ErrWrapperInvalid) {
			t.Fatalf("Plan(%q) error=%v", value, err)
		}
	}
}

func TestAuthorizedKeyOptionsHasRestrictAndOneAbsoluteCommand(t *testing.T) {
	options := AuthorizedKeyOptions()
	if options != `restrict,command="/usr/libexec/winkyou/gate-c-child-wrapper"` || strings.Contains(options, "environment=") {
		t.Fatalf("authorized key options=%q", options)
	}
}

func TestSSHDResolvedConfigRequiresPermitUserEnvironmentNo(t *testing.T) {
	if err := ValidateSSHDResolvedConfig([]byte("permituserenvironment no\npasswordauthentication no\n")); err != nil {
		t.Fatal(err)
	}
	for _, payload := range [][]byte{
		[]byte("permituserenvironment yes\n"), nil,
		[]byte("passwordauthentication no\n"),
		[]byte("permituserenvironment no\npermituserenvironment no\n"),
	} {
		if err := ValidateSSHDResolvedConfig(payload); !errors.Is(err, ErrWrapperInvalid) {
			t.Fatalf("ValidateSSHDResolvedConfig(%q) error=%v", payload, err)
		}
	}
}
