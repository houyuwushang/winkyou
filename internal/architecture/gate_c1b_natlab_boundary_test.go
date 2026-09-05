package architecture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const gateC1bNATLabAdapter = "internal/v2/gatecorchestrator/natlab_proof_linux.go"

var gateC1bNATLabFiles = []string{
	gateC1bNATLabAdapter,
	"cmd/wink/cmd/gate_c1b_natlab_proof_linux.go",
	"pkg/tunnel/gate_c1b_natlab_linux.go",
}

func approvedGateC1bNATLabAdapter(root, relative string) bool {
	if relative != gateC1bNATLabAdapter {
		return false
	}
	return hasExactGateC1bNATLabTag(root, relative)
}

func hasExactGateC1bNATLabTag(root, relative string) bool {
	payload, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
	return err == nil && strings.HasPrefix(strings.ReplaceAll(string(payload), "\r\n", "\n"), "//go:build linux && natlab && c1bproof\n")
}

func TestGateC1bNATLabSeamsAreAbsentFromOrdinaryBuilds(t *testing.T) {
	root := repositoryRoot(t)
	for _, relative := range gateC1bNATLabFiles {
		if !hasExactGateC1bNATLabTag(root, relative) {
			t.Fatalf("%s lacks exact linux+natlab+c1bproof boundary", relative)
		}
	}
	if !gateC1bNATLabTunnelSealed(root) {
		t.Fatal("isolated WireGuard constructor enabled a native bind or widened its interface")
	}
	payload, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(gateC1bNATLabAdapter)))
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, forbidden := range []string{"configuration.Machine =", "configuration.Ledger =", "configuration.ExpectedPeerAddress =",
		"configuration.ProbeFactory =", "configuration.Harness =", "AllowedTargetScopeUnicast", "NewUDPFactory", "AcquirePreparedNamespace"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("isolated adapter overrides forbidden authority %s", forbidden)
		}
	}
	for _, required := range []string{"probeio.NewGateB2NATLabFactory(proof.Namespace, proof.Side, endpoints)",
		"probeio.NewGateB3NATLabFactory(proof.Namespace, proof.Side, endpoints)", "authority.Endpoint() != endpoint"} {
		if strings.Count(text, required) != 1 {
			t.Fatalf("isolated adapter lost exact namespace/target binding %s", required)
		}
	}
}

func gateC1bNATLabTunnelSealed(root string) bool {
	path := "pkg/tunnel/gate_c1b_natlab_linux.go"
	if !hasExactGateC1bNATLabTag(root, path) {
		return false
	}
	payload, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		return false
	}
	for _, required := range []string{"instance.memoryOnly = true", "cfg.ListenPort != 0", `cfg.Interface.Type() != "tun"`, `cfg.Interface.Name() != "wink-c1b-proof"`} {
		if strings.Count(string(payload), required) != 1 {
			return false
		}
	}
	return true
}

func TestGateC1bNATLabTunnelRejectsTagAndNativeBindMutations(t *testing.T) {
	repository := repositoryRoot(t)
	path := "pkg/tunnel/gate_c1b_natlab_linux.go"
	payload, err := os.ReadFile(filepath.Join(repository, filepath.FromSlash(path)))
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range [][2]string{
		{"linux && natlab && c1bproof", "linux"}, {"instance.memoryOnly = true", "instance.memoryOnly = false"},
		{"cfg.ListenPort != 0", "false"}, {`cfg.Interface.Type() != "tun"`, "false"}, {`cfg.Interface.Name() != "wink-c1b-proof"`, "false"},
	} {
		root := t.TempDir()
		writeArchitectureMutation(t, root, path, strings.ReplaceAll(string(payload), change[0], change[1]))
		if gateC1bNATLabTunnelSealed(root) {
			t.Fatal("isolated tunnel capability mutation was accepted")
		}
	}
}

func TestGateC1bNATLabTagAndConsumerMutationsAreRejected(t *testing.T) {
	root := t.TempDir()
	for _, tag := range []string{"", "//go:build linux\n", "//go:build natlab\n", "//go:build linux && natlab\n"} {
		writeArchitectureMutation(t, root, gateC1bNATLabAdapter, tag+"package gatecorchestrator\n")
		if approvedGateC1bNATLabAdapter(root, gateC1bNATLabAdapter) {
			t.Fatal("incomplete test constraint granted a production capability")
		}
	}
	writeArchitectureMutation(t, root, gateC1bNATLabAdapter, "//go:build linux && natlab && c1bproof\n\npackage gatecorchestrator\n")
	if !approvedGateC1bNATLabAdapter(root, gateC1bNATLabAdapter) || approvedGateC1bNATLabAdapter(root, "pkg/runtime/bypass.go") {
		t.Fatal("exact natlab consumer boundary changed")
	}
	writeArchitectureMutation(t, root, "pkg/runtime/bypass.go", `package runtime
func bypass() { _ = RunNATLabInitiator; _ = RunNATLabResponder; _ = ExecuteGateCNATLabProof; _ = PrepareRootExecution; _ = newSSHAuthority; _ = NewGateCNATLabWireGuard }
`)
	violations, err := gateC1bAuthorityUseViolations(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"RunNATLabInitiator", "RunNATLabResponder", "ExecuteGateCNATLabProof", "PrepareRootExecution", "newSSHAuthority", "NewGateCNATLabWireGuard"} {
		if !containsLineFragment(violations, "unapproved Gate C1b authority "+name) {
			t.Fatalf("production escape %s was not detected", name)
		}
	}
}
