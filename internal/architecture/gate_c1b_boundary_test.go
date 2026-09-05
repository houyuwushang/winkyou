package architecture

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestGateC1bBoundaryIsExactAndCapabilityNarrow(t *testing.T) {
	root := repositoryRoot(t)
	if violations := gateC1bProofTagViolations(root); len(violations) != 0 {
		t.Fatalf("Gate C1b test seam became ordinary authority: %v", violations)
	}
	repository, err := scanRepository(root)
	if err != nil {
		t.Fatal(err)
	}
	if violations := gateC1bDependencyViolations(repository); len(violations) != 0 {
		t.Fatalf("Gate C1b dependency boundary drifted:\n  %s", strings.Join(violations, "\n  "))
	}
	if violations, err := gateC1bCapabilityViolations(root); err != nil {
		t.Fatal(err)
	} else if len(violations) != 0 {
		t.Fatalf("Gate C1b gained raw network/process/SSH authority:\n  %s", strings.Join(violations, "\n  "))
	}
	if violations, err := gateC1bShapeViolations(root); err != nil {
		t.Fatal(err)
	} else if len(violations) != 0 {
		t.Fatalf("Gate C1b fixed product shape drifted:\n  %s", strings.Join(violations, "\n  "))
	}
	if violations, err := gateC1bAuthorityUseViolations(root); err != nil {
		t.Fatal(err)
	} else if len(violations) != 0 {
		t.Fatalf("Gate C1b authority escaped its exact owner:\n  %s", strings.Join(violations, "\n  "))
	}
	for imported, restriction := range map[string]struct {
		watched map[string]string
		allowed map[string]struct{}
	}{
		modulePath + "/internal/v2/gatecchildstream": {
			watched: map[string]string{"New": "constructs the responder bounded stream outside the orchestrator"},
			allowed: map[string]struct{}{"internal/v2/gatecorchestrator/orchestrator.go": {}},
		},
		modulePath + "/internal/v2/sshassembly": {
			watched: map[string]string{"OpenClient": "opens the fixed SSH child outside the orchestrator"},
			allowed: map[string]struct{}{"internal/v2/gatecorchestrator/orchestrator.go": {}},
		},
		modulePath + "/internal/v2/directconnect/gateb": {
			watched: map[string]string{"RunForProduct": "runs the Gate B product handoff outside the orchestrator"},
			allowed: map[string]struct{}{"internal/v2/gatecorchestrator/orchestrator.go": {}},
		},
	} {
		violations, err := importedSelectorUseViolations(root, imported, restriction.watched, restriction.allowed)
		if err != nil {
			t.Fatal(err)
		}
		if len(violations) != 0 {
			t.Fatalf("restricted use of %s escaped:\n  %s", imported, strings.Join(violations, "\n  "))
		}
	}
}

func TestGateC1bDependencyGateDetectsProductLegacyAndLayeringMutations(t *testing.T) {
	orch := modulePath + "/internal/v2/gatecorchestrator"
	child := modulePath + "/internal/v2/gatecchildstream"
	gateB := modulePath + "/internal/v2/directconnect/gateb"
	artifact := modulePath + "/internal/v2/gatecattempt"
	for _, mutation := range []struct{ importer, imported, fragment string }{
		{modulePath + "/internal/solverstdio", orch, "imports Gate C1b orchestrator"},
		{modulePath + "/pkg/runtime", child, "imports Gate C1b child stream"},
		{orch, modulePath + "/pkg/runtime", "imports forbidden Gate C1b dependency"},
		{gateB, artifact, "Gate B imports Gate C product artifact"},
		{modulePath + "/pkg/tunnel", modulePath + "/internal/v2/sshassembly", "imports Gate C layering violation"},
	} {
		repository := scanResult{packages: map[string]*packageInfo{
			mutation.importer: {imports: map[string]struct{}{mutation.imported: {}}},
		}}
		violations := gateC1bDependencyViolations(repository)
		if !containsLineFragment(violations, mutation.fragment) {
			t.Errorf("%s -> %s mutation not detected: %v", mutation.importer, mutation.imported, violations)
		}
	}
}

func TestGateC1bCapabilityGateDetectsDialExecPasswordAndHostBypass(t *testing.T) {
	root := t.TempDir()
	writeArchitectureMutation(t, root, "internal/v2/gatecchildstream/bypass.go", `package gatecchildstream
import (
  "net"
  "os/exec"
)
var _ net.Conn
var _ = exec.Command
`)
	writeArchitectureMutation(t, root, "internal/v2/gatecorchestrator/bypass.go", `package gatecorchestrator
import (
  "net"
  "golang.org/x/crypto/ssh"
)
var _ = net.Dial
var _ ssh.Client
const bypass = "PasswordAuthentication=yes StrictHostKeyChecking=no ProxyCommand=run"
`)
	violations, err := gateC1bCapabilityViolations(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"gatecchildstream/bypass.go imports net", "gatecchildstream/bypass.go imports os/exec",
		"gatecorchestrator/bypass.go imports golang.org/x/crypto/ssh", "reference:net.Dial",
		"PasswordAuthentication=yes", "StrictHostKeyChecking=no", "ProxyCommand=",
	} {
		if !containsLineFragment(violations, fragment) {
			t.Errorf("capability mutation %q was not detected: %v", fragment, violations)
		}
	}
}

func TestGateC1bShapeGateDetectsRawFactoryHostTUNContextAndRetryMutations(t *testing.T) {
	root := t.TempDir()
	writeArchitectureMutation(t, root, "internal/v2/gatecorchestrator/bypass.go", `package gatecorchestrator
import (
  "context"
  "winkyou/internal/probeio"
  "winkyou/internal/v2/directconnect/gateb"
  "winkyou/internal/v2/sshassembly"
  "winkyou/pkg/netif"
  "winkyou/pkg/tunnel"
)
func bypass() {
  _ = context.Background()
  _, _ = probeio.NewUDPFactory(probeio.UDPFactoryConfig{})
  _, _ = netif.New(netif.Config{})
  _, _ = tunnel.New(tunnel.Config{})
  _, _, _ = gateb.RunForProduct(context.Background(), gateb.Config{})
  _, _, _ = gateb.RunForProduct(context.Background(), gateb.Config{})
  _, _ = sshassembly.OpenClient(context.Background(), sshassembly.Config{})
  _, _ = sshassembly.OpenClient(context.Background(), sshassembly.Config{})
  _ = probeio.GateB2TestConsumer
  _ = SourcePayload{}
  _ = Fallback
  _ = TakePSK
  _ = ProbeSocket{}
  _ = PromoteToLease
  _ = UnplannedPort
}
`)
	violations, err := gateC1bShapeViolations(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"probeio.NewUDPFactory count=1 want=0", "netif.New count=1 want=0", "tunnel.New count=1 want=0",
		"context.Background count=5 want=0", "gateb.RunForProduct count=2 want=1", "sshassembly.OpenClient count=2 want=1",
		"uses forbidden GateB2TestConsumer", "uses forbidden SourcePayload", "uses forbidden Fallback", "uses forbidden TakePSK",
		"uses forbidden ProbeSocket", "uses forbidden PromoteToLease", "uses forbidden UnplannedPort",
	} {
		if !containsLineFragment(violations, fragment) {
			t.Errorf("shape mutation %q was not detected: %v", fragment, violations)
		}
	}
}

func TestGateC1bRestrictedUseGateDetectsRawStreamAndProductRunnerEscape(t *testing.T) {
	root := t.TempDir()
	writeArchitectureMutation(t, root, "pkg/runtime/bypass.go", `package runtime
import (
  "context"
  child "winkyou/internal/v2/gatecchildstream"
  gateb "winkyou/internal/v2/directconnect/gateb"
)
func bypass() {
  _, _ = child.New(nil, nil, time.Time{})
  _, _, _ = gateb.RunForProduct(context.Background(), gateb.Config{})
}
`)
	checks := []struct {
		imported string
		watched  map[string]string
		fragment string
	}{
		{modulePath + "/internal/v2/gatecchildstream", map[string]string{"New": "constructs raw child stream"}, "constructs raw child stream"},
		{modulePath + "/internal/v2/directconnect/gateb", map[string]string{"RunForProduct": "runs product handoff"}, "runs product handoff"},
	}
	for _, check := range checks {
		violations, err := importedSelectorUseViolations(root, check.imported, check.watched, map[string]struct{}{})
		if err != nil {
			t.Fatal(err)
		}
		if !containsLineFragment(violations, check.fragment) {
			t.Errorf("restricted-use mutation %q was not detected: %v", check.fragment, violations)
		}
	}
}

func TestGateC1bAuthorityGateDetectsProductConsumerAndConstructorEscape(t *testing.T) {
	root := t.TempDir()
	writeArchitectureMutation(t, root, "pkg/runtime/bypass.go", `package runtime
func bypass() {
  _ = WireGuardDirectSessionConsumer
  _ = PromoteToWireGuardSessionLease
  _ = AdoptWireGuardSession
  _ = NewGateCMemoryInterface
  _ = NewMemoryWireGuard
  _ = RunForProduct
  _ = RunResponderStdio
  _ = NewProductProtocol
  _ = TakeConsumerReadiness
  _ = ConsumerReady
  _ = RunMemoryInitiator
  _ = RunMemoryResponder
  _ = OpenMemoryProofClient
  _ = ClaimMemoryProof
  _ = ExecuteGateCMemoryProof
}
`)
	violations, err := gateC1bAuthorityUseViolations(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"WireGuardDirectSessionConsumer", "PromoteToWireGuardSessionLease", "AdoptWireGuardSession",
		"NewGateCMemoryInterface", "NewMemoryWireGuard", "RunForProduct", "RunResponderStdio",
		"NewProductProtocol", "TakeConsumerReadiness", "ConsumerReady",
		"RunMemoryInitiator", "RunMemoryResponder", "OpenMemoryProofClient", "ClaimMemoryProof", "ExecuteGateCMemoryProof",
	} {
		if !containsLineFragment(violations, "unapproved Gate C1b authority "+name) {
			t.Errorf("authority mutation %s was not detected: %v", name, violations)
		}
	}
}

func TestGateC1bNetifCapabilityGraphExceptionIsExact(t *testing.T) {
	orch := modulePath + "/internal/v2/gatecorchestrator"
	if !approvedCapabilityDependencyEndpoint(orch, modulePath+"/pkg/netif") {
		t.Fatal("exact memory-interface package endpoint was not recognized")
	}
	for _, candidate := range [][2]string{
		{orch, modulePath + "/pkg/nat"},
		{modulePath + "/pkg/runtime", modulePath + "/pkg/netif"},
		{orch + "/bypass", modulePath + "/pkg/netif"},
	} {
		if approvedCapabilityDependencyEndpoint(candidate[0], candidate[1]) {
			t.Fatalf("capability graph exception widened to %q -> %q", candidate[0], candidate[1])
		}
	}
}

var gateC1bProofFiles = []string{
	"internal/v2/gatecorchestrator/memory_proof_c1bproof.go",
	"internal/v2/sshassembly/memory_c1bproof.go",
	"internal/v2/gatecstage/memory_c1bproof.go",
	"cmd/wink/cmd/gate_c1b_memory_proof.go",
}

func gateC1bProofTagViolations(root string) []string {
	var violations []string
	for _, relative := range gateC1bProofFiles {
		payload, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil || !strings.HasPrefix(strings.ReplaceAll(string(payload), "\r\n", "\n"), "//go:build c1bproof\n") {
			violations = append(violations, relative+" lacks exact c1bproof constraint")
		}
	}
	return violations
}

func TestGateC1bMemorySeamTagRemovalIsDetected(t *testing.T) {
	root := t.TempDir()
	for _, relative := range gateC1bProofFiles {
		writeArchitectureMutation(t, root, relative, "//go:build c1bproof\n\npackage mutation\n")
	}
	if got := gateC1bProofTagViolations(root); len(got) != 0 {
		t.Fatal(got)
	}
	for _, relative := range gateC1bProofFiles {
		writeArchitectureMutation(t, root, relative, "package mutation\n")
		if got := gateC1bProofTagViolations(root); !containsLineFragment(got, relative+" lacks exact c1bproof constraint") {
			t.Fatalf("untagged seam escaped: %v", got)
		}
		writeArchitectureMutation(t, root, relative, "//go:build c1bproof\n\npackage mutation\n")
	}
}

func TestGateC1bMemorySeamCannotReplaceAttemptOwner(t *testing.T) {
	root := t.TempDir()
	relative := "internal/v2/gatecorchestrator/memory_proof_c1bproof.go"
	base := "//go:build c1bproof\n\npackage mutation\nfunc f() { configuration.ProbeFactory = factory; configuration.Harness = hooks; _ = options.Machine == nil; _ = options.Ledger == nil; BODY }\n"
	for _, field := range []string{"Machine", "Ledger"} {
		writeArchitectureMutation(t, root, relative, strings.ReplaceAll(base, "BODY", "configuration."+field+" = replacement"))
		violations, err := gateC1bShapeViolations(root)
		if err != nil || !containsLineFragment(violations, "mutates forbidden "+field) {
			t.Fatalf("attempt owner replacement escaped (%s): %v, %v", field, violations, err)
		}
	}
	writeArchitectureMutation(t, root, relative, strings.ReplaceAll(base, "BODY", ""))
	violations, err := gateC1bShapeViolations(root)
	if err != nil || containsLineFragment(violations, "mutates forbidden Machine") || containsLineFragment(violations, "mutates forbidden Ledger") {
		t.Fatalf("read-only owner validation was mistaken for replacement: %v, %v", violations, err)
	}
}

func gateC1bDependencyViolations(repository scanResult) []string {
	orch := modulePath + "/internal/v2/gatecorchestrator"
	child := modulePath + "/internal/v2/gatecchildstream"
	command := modulePath + "/cmd/wink/cmd"
	gateB := modulePath + "/internal/v2/directconnect/gateb"
	gateCArtifact := modulePath + "/internal/v2/gatecattempt"
	allowedOrchestratorImports := map[string]struct{}{
		modulePath + "/internal/governor": {}, modulePath + "/internal/probeio": {},
		modulePath + "/internal/v2/directattempt": {}, gateB: {}, gateCArtifact: {}, child: {},
		modulePath + "/internal/v2/gatecrequest": {}, modulePath + "/internal/v2/gatecstage": {},
		modulePath + "/internal/v2/hardnatbudget": {}, modulePath + "/internal/v2/hardnatobserve": {},
		modulePath + "/internal/v2/hardnatplan": {}, modulePath + "/internal/v2/oobcarrier": {},
		modulePath + "/internal/v2/pairgen": {}, modulePath + "/internal/v2/sshassembly": {},
		modulePath + "/pkg/config": {}, modulePath + "/pkg/netif": {}, modulePath + "/pkg/tunnel": {},
	}
	layeringRestricted := map[string]struct{}{
		gateCArtifact: {}, modulePath + "/internal/v2/gatecrequest": {}, modulePath + "/internal/v2/gatecstage": {},
		modulePath + "/internal/v2/sshassembly": {}, modulePath + "/internal/v2/hardnatplan": {},
		modulePath + "/internal/v2/hardnatbudget": {}, modulePath + "/internal/v2/hardnatattempt": {},
		modulePath + "/internal/v2/hardnatcontrol": {}, modulePath + "/internal/v2/hardnatobserve": {},
	}
	var violations []string
	for importer, information := range repository.packages {
		for imported := range information.imports {
			switch {
			case (imported == orch || strings.HasPrefix(imported, orch+"/")) && importer != command:
				violations = append(violations, importer+" imports Gate C1b orchestrator "+imported)
			case (imported == child || strings.HasPrefix(imported, child+"/")) && importer != orch:
				violations = append(violations, importer+" imports Gate C1b child stream "+imported)
			case importer == orch && !containsImportOrChild(allowedOrchestratorImports, imported):
				violations = append(violations, importer+" imports forbidden Gate C1b dependency "+imported)
			case importer == child && imported != modulePath+"/internal/v2/oobcarrier":
				violations = append(violations, importer+" imports forbidden child-stream dependency "+imported)
			case importer == gateB && (imported == gateCArtifact || strings.HasPrefix(imported, gateCArtifact+"/")):
				violations = append(violations, importer+" Gate B imports Gate C product artifact "+imported)
			case (importer == modulePath+"/pkg/session" || importer == modulePath+"/pkg/tunnel") && containsImportOrChild(layeringRestricted, imported):
				violations = append(violations, importer+" imports Gate C layering violation "+imported)
			}
		}
	}
	return uniqueSortedStrings(violations)
}

func gateC1bCapabilityViolations(root string) ([]string, error) {
	repository, err := scanRepository(root)
	if err != nil {
		return nil, err
	}
	packages := map[string]struct{}{
		modulePath + "/internal/v2/gatecorchestrator": {},
		modulePath + "/internal/v2/gatecchildstream":  {},
	}
	var violations []string
	for _, finding := range repository.findings {
		if _, watched := packages[finding.pkg]; watched {
			violations = append(violations, fmt.Sprintf("%s owns %s in %s", finding.pkg, finding.capability, finding.file))
		}
	}
	forbiddenImports := []string{"os/exec", "syscall", "golang.org/x/sys/", "golang.org/x/crypto/ssh", "tailscale.com/", "github.com/pion/", "github.com/quic-go/"}
	forbiddenText := []string{
		"PasswordAuthentication=yes", "StrictHostKeyChecking=no", "ProxyCommand=", "ProxyJump=",
		"ControlMaster=", "keyboard-interactive", "sshpass", "sh -c", "cmd.exe", "powershell.exe",
	}
	err = walkGateC1bProduction(root, func(filename, relative, packageDirectory string, parsed *ast.File, payload []byte) error {
		for _, specification := range parsed.Imports {
			imported, err := strconv.Unquote(specification.Path.Value)
			if err != nil {
				return err
			}
			forbidden := specification.Name != nil && specification.Name.Name == "."
			if packageDirectory == "internal/v2/gatecchildstream" && (imported == "net" || strings.HasPrefix(imported, "net/")) {
				forbidden = true
			}
			for _, prefix := range forbiddenImports {
				if imported == prefix || strings.HasPrefix(imported, prefix) {
					forbidden = true
				}
			}
			if forbidden {
				violations = append(violations, relative+" imports "+imported)
			}
		}
		text := string(payload)
		for _, forbidden := range forbiddenText {
			if strings.Contains(text, forbidden) {
				violations = append(violations, relative+" contains forbidden "+forbidden)
			}
		}
		return nil
	})
	return uniqueSortedStrings(violations), err
}

func gateC1bShapeViolations(root string) ([]string, error) {
	type expectedUse struct {
		directory, imported, name string
		want                      int
	}
	expected := []expectedUse{
		{"internal/v2/gatecorchestrator", modulePath + "/internal/v2/sshassembly", "OpenClient", 1},
		{"internal/v2/gatecorchestrator", modulePath + "/internal/v2/gatecchildstream", "New", 1},
		{"internal/v2/gatecorchestrator", modulePath + "/internal/v2/directconnect/gateb", "RunForProduct", 1},
		{"internal/v2/gatecorchestrator", modulePath + "/pkg/netif", "NewGateCMemoryInterface", 1},
		{"internal/v2/gatecorchestrator", modulePath + "/pkg/netif", "New", 0},
		{"internal/v2/gatecorchestrator", modulePath + "/pkg/tunnel", "NewMemoryWireGuard", 1},
		{"internal/v2/gatecorchestrator", modulePath + "/pkg/tunnel", "New", 0},
		{"internal/v2/gatecorchestrator", modulePath + "/internal/probeio", "NewUDPFactory", 0},
		{"internal/v2/gatecorchestrator", modulePath + "/internal/v2/sshassembly", "NewNATLabAuthority", 1},
		{"internal/v2/gatecorchestrator", "context", "WithoutCancel", 1},
		{"internal/v2/gatecorchestrator", "context", "Background", 0},
		{"cmd/wink/cmd", modulePath + "/internal/v2/gatecorchestrator", "RunInitiator", 1},
		{"cmd/wink/cmd", modulePath + "/internal/v2/gatecorchestrator", "RunResponderStdio", 1},
	}
	var violations []string
	for _, item := range expected {
		count, err := importedSelectorCountInDirectory(root, item.directory, item.imported, item.name)
		if err != nil {
			return nil, err
		}
		if count != item.want {
			violations = append(violations, fmt.Sprintf("%s %s.%s count=%d want=%d", item.directory, filepath.Base(item.imported), item.name, count, item.want))
		}
	}

	forbiddenIdentifiers := map[string]struct{}{
		"AllowedTargetScopeUnicast": {}, "GateATestConsumer": {}, "GateB2TestConsumer": {}, "GateB3TestConsumer": {},
		"SourcePayload": {}, "Fallback": {}, "ProxyCommand": {}, "ProxyJump": {}, "Password": {}, "Ping": {},
		"TakePSK": {}, "ProbeSocket": {}, "Promote": {}, "PromoteToLease": {}, "OpenProbeSocket": {},
		"RemoteCandidateAddress": {}, "SecondAddress": {}, "UnplannedPort": {}, "Listen": {}, "ListenPacket": {},
	}
	err := walkGateC1bProduction(root, func(_ string, relative, packageDirectory string, parsed *ast.File, _ []byte) error {
		if packageDirectory != "internal/v2/gatecorchestrator" && packageDirectory != "cmd/wink/cmd" {
			return nil
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if ok {
				if _, forbidden := forbiddenIdentifiers[identifier.Name]; forbidden {
					violations = append(violations, relative+" uses forbidden "+identifier.Name)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		return nil, err
	}

	orchestratorPayload, err := os.ReadFile(filepath.Join(root, "internal", "v2", "gatecorchestrator", "orchestrator.go"))
	if err == nil {
		text := string(orchestratorPayload)
		for fragment, want := range map[string]int{
			"ExpectedPeerAddress: input.request.ExpectedPeerPublicAddress": 1,
			"deps.configureGateB(&gateConfig)":                             1,
			"if deps.configureGateB == nil":                                1,
			"configureGateB":                                               2,
		} {
			if count := strings.Count(text, fragment); count != want {
				violations = append(violations, fmt.Sprintf("orchestrator.go %q count=%d want=%d", fragment, count, want))
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	proofPath := filepath.Join(root, "internal", "v2", "gatecorchestrator", "memory_proof_c1bproof.go")
	if payload, err := os.ReadFile(proofPath); err == nil {
		normalized := strings.ReplaceAll(string(payload), "\r\n", "\n")
		if !strings.HasPrefix(normalized, "//go:build c1bproof\n") {
			violations = append(violations, "memory_proof_c1bproof.go lacks exact c1bproof build constraint")
		}
		for fragment, want := range map[string]int{"configuration.ProbeFactory =": 1, "configuration.Harness =": 1} {
			if count := strings.Count(normalized, fragment); count != want {
				violations = append(violations, fmt.Sprintf("memory_proof_c1bproof.go %q count=%d want=%d", fragment, count, want))
			}
		}
		for _, forbidden := range []string{"ExpectedPeerAddress", "NATLabFactory", "HardNATLabFactory"} {
			if strings.Contains(normalized, forbidden) {
				violations = append(violations, "memory_proof_c1bproof.go mutates forbidden "+forbidden)
			}
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), proofPath, payload, 0)
		if err != nil {
			return nil, err
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			assignment, ok := node.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for _, left := range assignment.Lhs {
				if selector, ok := left.(*ast.SelectorExpr); ok && (selector.Sel.Name == "Machine" || selector.Sel.Name == "Ledger") {
					violations = append(violations, "memory_proof_c1bproof.go mutates forbidden "+selector.Sel.Name)
				}
			}
			return true
		})
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	gatePath := filepath.Join(root, "internal", "probeio", "wireguard_session_gate.go")
	if payload, err := os.ReadFile(gatePath); err == nil {
		text := string(payload)
		for _, required := range []string{"WireGuardChallengeTimeout = 3 * time.Second", "WireGuardChallengePackets = 3"} {
			if !strings.Contains(text, required) {
				violations = append(violations, "wireguard_session_gate.go lacks fixed "+required)
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	tunnelUses, err := importedSelectorFunctions(filepath.Join(root, "pkg", "tunnel", "tunnel_wggo.go"), "context", "Background")
	if err == nil {
		if len(tunnelUses) != 2 || tunnelUses["(*peerTransportBind).Send"] != 1 || tunnelUses["(*peerTransportBind).readTransportLoop"] != 1 {
			violations = append(violations, fmt.Sprintf("tunnel_wggo.go context.Background owners=%v want exact Send/readTransportLoop", tunnelUses))
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return uniqueSortedStrings(violations), nil
}

func gateC1bAuthorityUseViolations(root string) ([]string, error) {
	allowed := map[string]map[string]struct{}{
		"RunNATLabInitiator":      {"internal/v2/gatecorchestrator/natlab_proof_linux.go": {}, "cmd/wink/cmd/gate_c1b_natlab_proof_linux.go": {}},
		"RunNATLabResponder":      {"internal/v2/gatecorchestrator/natlab_proof_linux.go": {}, "cmd/wink/cmd/gate_c1b_natlab_proof_linux.go": {}},
		"ExecuteGateCNATLabProof": {"cmd/wink/cmd/gate_c1b_natlab_proof_linux.go": {}},
		"newSSHAuthority": {
			"internal/v2/gatecorchestrator/types.go": {}, "internal/v2/gatecorchestrator/entry.go": {},
			"internal/v2/gatecorchestrator/orchestrator.go": {}, "internal/v2/gatecorchestrator/natlab_proof_linux.go": {},
		},
		"PrepareRootExecution":    {"internal/v2/sshchildwrapper/root_linux.go": {}, "internal/v2/sshchildwrapper/root_unsupported.go": {}},
		"RunMemoryInitiator":      {"internal/v2/gatecorchestrator/memory_proof_c1bproof.go": {}, "cmd/wink/cmd/gate_c1b_memory_proof.go": {}},
		"RunMemoryResponder":      {"internal/v2/gatecorchestrator/memory_proof_c1bproof.go": {}, "cmd/wink/cmd/gate_c1b_memory_proof.go": {}},
		"OpenMemoryProofClient":   {"internal/v2/gatecorchestrator/memory_proof_c1bproof.go": {}, "internal/v2/sshassembly/memory_c1bproof.go": {}},
		"ClaimMemoryProof":        {"internal/v2/gatecorchestrator/memory_proof_c1bproof.go": {}, "internal/v2/gatecstage/memory_c1bproof.go": {}},
		"StageMemoryProof":        {"internal/v2/gatecstage/memory_c1bproof.go": {}},
		"ExecuteGateCMemoryProof": {"cmd/wink/cmd/gate_c1b_memory_proof.go": {}},
		"NewProductProtocol": {
			"internal/v2/hardnatcontrol/consumer_ready.go": {}, "internal/v2/directconnect/gateb/connect.go": {},
		},
		"TakeConsumerReadiness": {
			"internal/v2/hardnatcontrol/consumer_ready.go": {}, "internal/v2/directconnect/gateb/product_handoff.go": {},
		},
		"ConsumerReadinessCodec": {"internal/probeio/wireguard_consumer_ready.go": {}},
		"ConsumerReady": {
			"internal/probeio/wireguard_consumer_ready.go": {}, "internal/probeio/wireguard_session_gate.go": {},
			"internal/v2/directconnect/gateb/product_handoff.go": {}, "internal/v2/gatecorchestrator/orchestrator.go": {},
		},
		"WireGuardDirectSessionConsumer": {
			"internal/probeio/probeio.go": {}, "internal/probeio/transport_lease.go": {},
			"internal/probeio/wireguard_session_gate.go": {}, "internal/v2/directconnect/gateb/connect.go": {},
		},
		"PromoteToWireGuardSessionLease": {
			"internal/probeio/probeio.go": {}, "internal/v2/directconnect/gateb/connect.go": {},
		},
		"AdoptWireGuardSession": {
			"internal/probeio/wireguard_session_gate.go": {}, "internal/v2/directconnect/gateb/connect.go": {},
		},
		"NewGateCMemoryInterface": {
			"pkg/netif/interface.go": {}, "internal/v2/gatecorchestrator/orchestrator.go": {},
		},
		"NewMemoryWireGuard": {
			"pkg/tunnel/tunnel.go": {}, "internal/v2/gatecorchestrator/orchestrator.go": {},
		},
		"RunForProduct": {
			"internal/v2/directconnect/gateb/types.go": {}, "internal/v2/gatecorchestrator/orchestrator.go": {},
		},
		"RunInitiator": {
			"internal/v2/gatecorchestrator/entry.go": {}, "cmd/wink/cmd/solver.go": {},
		},
		"RunResponderStdio": {
			"internal/v2/gatecorchestrator/entry.go": {}, "cmd/wink/cmd/solver.go": {},
		},
		"configureGateB": {
			"internal/v2/gatecorchestrator/types.go": {}, "internal/v2/gatecorchestrator/orchestrator.go": {},
			"internal/v2/gatecorchestrator/memory_proof_c1bproof.go": {}, "internal/v2/gatecorchestrator/natlab_proof_linux.go": {},
		},
		"TakePSK": {
			"internal/v2/hardnatattempt/artifact.go": {}, "internal/v2/oobattempt/artifact.go": {},
			"internal/v2/directattempt/artifact.go": {}, "internal/v2/gatecattempt/artifact.go": {},
			"internal/v2/directsim/simulator.go": {}, "internal/v2/directconnect/protocol.go": {},
			"internal/v2/directconnect/gatea/connect.go": {}, "internal/v2/directconnect/gateb/connect.go": {},
			"internal/v2/directconnect/gateb/types.go": {},
		},
	}
	var violations []string
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if filename != root && (strings.HasPrefix(entry.Name(), ".") || entry.Name() == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		relative, err := filepath.Rel(root, filename)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		parsed, err := parser.ParseFile(fset, filename, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			owners, watched := allowed[identifierName(identifier, ok)]
			if watched {
				if _, approved := owners[relative]; !approved {
					position := fset.Position(identifier.Pos())
					violations = append(violations, fmt.Sprintf("%s:%d uses unapproved Gate C1b authority %s", relative, position.Line, identifier.Name))
				}
			}
			return true
		})
		return nil
	})
	return uniqueSortedStrings(violations), err
}

func walkGateC1bProduction(root string, visit func(filename, relative, packageDirectory string, parsed *ast.File, payload []byte) error) error {
	watched := map[string]struct{}{"internal/v2/gatecorchestrator": {}, "internal/v2/gatecchildstream": {}, "cmd/wink/cmd": {}}
	return filepath.WalkDir(root, func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if filename != root && (strings.HasPrefix(entry.Name(), ".") || entry.Name() == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		relative, err := filepath.Rel(root, filename)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		directory := filepath.ToSlash(filepath.Dir(relative))
		if _, ok := watched[directory]; !ok {
			return nil
		}
		if directory == "cmd/wink/cmd" && relative != "cmd/wink/cmd/solver.go" {
			return nil
		}
		payload, err := os.ReadFile(filename)
		if err != nil {
			return err
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), filename, payload, 0)
		if err != nil {
			return err
		}
		return visit(filename, relative, directory, parsed, payload)
	})
}

func importedSelectorCountInDirectory(root, relativeDirectory, importedPath, selectorName string) (int, error) {
	directory := filepath.Join(root, filepath.FromSlash(relativeDirectory))
	count := 0
	err := filepath.WalkDir(directory, func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if os.IsNotExist(walkErr) {
				return nil
			}
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		current, err := importedSelectorCount(filename, importedPath, selectorName)
		if err != nil {
			return err
		}
		count += current
		return nil
	})
	return count, err
}

func importedSelectorFunctions(filename, importedPath, selectorName string) (map[string]int, error) {
	parsed, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
	if err != nil {
		return nil, err
	}
	aliases := map[string]struct{}{}
	for _, specification := range parsed.Imports {
		imported, err := strconv.Unquote(specification.Path.Value)
		if err != nil {
			return nil, err
		}
		if imported == importedPath {
			name := filepath.Base(importedPath)
			if specification.Name != nil {
				name = specification.Name.Name
			}
			aliases[name] = struct{}{}
		}
	}
	uses := map[string]int{}
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		owner := function.Name.Name
		if function.Recv != nil && len(function.Recv.List) == 1 {
			owner = "(" + astTypeName(function.Recv.List[0].Type) + ")." + owner
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != selectorName {
				return true
			}
			identifier, ok := selector.X.(*ast.Ident)
			if ok {
				if _, imported := aliases[identifier.Name]; imported {
					uses[owner]++
				}
			}
			return true
		})
	}
	return uses, nil
}

func astTypeName(expression ast.Expr) string {
	switch value := expression.(type) {
	case *ast.StarExpr:
		return "*" + astTypeName(value.X)
	case *ast.Ident:
		return value.Name
	default:
		return "?"
	}
}

func identifierName(identifier *ast.Ident, ok bool) string {
	if !ok || identifier == nil {
		return ""
	}
	return identifier.Name
}

func uniqueSortedStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func writeArchitectureMutation(t *testing.T, root, relative, source string) {
	t.Helper()
	filename := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
}
