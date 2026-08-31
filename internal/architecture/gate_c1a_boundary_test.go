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

func TestGateC1aBoundaryIsSealedAndProductDisconnected(t *testing.T) {
	root := repositoryRoot(t)
	result, err := scanRepository(root)
	if err != nil {
		t.Fatal(err)
	}
	if violations := gateC1aDependencyViolations(result); len(violations) != 0 {
		t.Fatalf("Gate C1a escaped its exact package boundary:\n  %s", strings.Join(violations, "\n  "))
	}
	if violations, err := gateC1aCapabilityViolations(root); err != nil {
		t.Fatal(err)
	} else if len(violations) != 0 {
		t.Fatalf("Gate C1a gained an unreviewed capability:\n  %s", strings.Join(violations, "\n  "))
	}
	if violations, err := gateC1aShapeViolations(root); err != nil {
		t.Fatal(err)
	} else if len(violations) != 0 {
		t.Fatalf("Gate C1a fixed call shape drifted:\n  %s", strings.Join(violations, "\n  "))
	}
}

func TestGateC1aDependencyGateDetectsProductAndRawStreamImporters(t *testing.T) {
	assembly := modulePath + "/internal/v2/sshassembly"
	wrapper := modulePath + "/internal/v2/sshchildwrapper"
	stage := modulePath + "/internal/v2/gatecstage"
	request := modulePath + "/internal/v2/gatecrequest"
	tests := []struct{ importer, imported, fragment string }{
		{modulePath + "/internal/solverstdio", assembly, "imports C1a SSH assembly"},
		{modulePath + "/pkg/runtime", assembly, "imports C1a SSH assembly"},
		{modulePath + "/pkg/meshruntime", wrapper, "imports C1a child wrapper"},
		{modulePath + "/cmd/wink-signal", stage, "imports C1a responder staging"},
		{modulePath + "/pkg/session", request, "imports C1a local request"},
	}
	for _, test := range tests {
		result := scanResult{packages: map[string]*packageInfo{
			test.importer: {imports: map[string]struct{}{test.imported: {}}},
		}}
		violations := gateC1aDependencyViolations(result)
		if len(violations) != 1 || !strings.Contains(violations[0], test.fragment) {
			t.Errorf("%s -> %s violations=%v", test.importer, test.imported, violations)
		}
	}
}

func TestGateC1aCapabilityGateDetectsRawNetworkExecAndGateBMutation(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "internal", "v2", "sshassembly")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	source := []byte(`package sshassembly
import (
  "net"
  "os/exec"
  "winkyou/internal/probeio"
  "winkyou/internal/v2/directconnect/gateb"
  "winkyou/pkg/netif"
)
var _ net.Conn
var _ = exec.Command
var _ probeio.Factory
var _ gateb.Config
var _ netif.Interface
`)
	if err := os.WriteFile(filepath.Join(directory, "bypass.go"), source, 0o600); err != nil {
		t.Fatal(err)
	}
	violations, err := gateC1aCapabilityViolations(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"imports net", "imports os/exec outside the fixed process adapter", "imports winkyou/internal/probeio", "imports winkyou/internal/v2/directconnect/gateb", "imports winkyou/pkg/netif"} {
		if !containsLineFragment(violations, fragment) {
			t.Errorf("mutation %q was not detected: %v", fragment, violations)
		}
	}
}

func TestGateC1aShapeGateDetectsSecondSpawnAuthorityAndProfileBypass(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "internal", "v2", "sshassembly")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"process.go": `package sshassembly
import "os/exec"
func spawn(spec processSpec) { _ = exec.Command(spec.executable); _ = exec.Command("cmd.exe") }
`,
		"assembly.go": `package sshassembly
func run(lease interface{ ClaimExclusive(string) error }) { _ = lease.ClaimExclusive("one"); _ = lease.ClaimExclusive("two") }
`,
		"authority.go": `package sshassembly
type SSHEndpointAuthority interface{ sshEndpointAuthority() }
func NewBypassAuthority() SSHEndpointAuthority { return nil }
`,
		"profile.go": `package sshassembly
const bad = "PasswordAuthentication=yes StrictHostKeyChecking=no ProxyCommand=run ControlMaster=yes"
`,
		"escape.go": `package sshassembly
func bypass() { _ = processSpec{} }
`,
		"authority_natlab_linux.go": `//go:build linux
package sshassembly
func NewNATLabAuthority() SSHEndpointAuthority { return nil }
`,
	}
	for name, source := range files {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	violations, err := gateC1aShapeViolations(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"exec.Command count=2 want=1", "ClaimExclusive count=2 want=1", "unreviewed exported SSH authority constructor NewBypassAuthority",
		"lacks exact linux+natlab build constraint", "constructs processSpec outside assembly.go",
		"contains forbidden PasswordAuthentication=yes", "contains forbidden StrictHostKeyChecking=no",
	} {
		if !containsLineFragment(violations, fragment) {
			t.Errorf("shape mutation %q was not detected: %v", fragment, violations)
		}
	}
}

func gateC1aDependencyViolations(result scanResult) []string {
	gateCAttempt := modulePath + "/internal/v2/gatecattempt"
	gateCRequest := modulePath + "/internal/v2/gatecrequest"
	gateCStage := modulePath + "/internal/v2/gatecstage"
	assembly := modulePath + "/internal/v2/sshassembly"
	wrapper := modulePath + "/internal/v2/sshchildwrapper"
	pairgen := modulePath + "/internal/v2/pairgen"
	command := modulePath + "/cmd/wink/cmd"
	allowed := map[string]map[string]struct{}{
		gateCAttempt: {pairgen: {}, gateCRequest: {}, gateCStage: {}, command: {}},
		gateCRequest: {gateCStage: {}, assembly: {}},
		gateCStage:   {command: {}},
		assembly:     {},
		wrapper:      {},
	}
	labels := map[string]string{
		gateCAttempt: "C1a product artifact", gateCRequest: "C1a local request", gateCStage: "C1a responder staging",
		assembly: "C1a SSH assembly", wrapper: "C1a child wrapper",
	}
	var violations []string
	for importer, info := range result.packages {
		for imported := range info.imports {
			for restricted, importers := range allowed {
				if imported != restricted && !strings.HasPrefix(imported, restricted+"/") {
					continue
				}
				if importer == restricted || strings.HasPrefix(importer, restricted+"/") {
					continue
				}
				if _, ok := importers[importer]; !ok {
					violations = append(violations, importer+" imports "+labels[restricted]+" "+imported)
				}
			}
		}
	}
	sort.Strings(violations)
	return violations
}

func gateC1aCapabilityViolations(root string) ([]string, error) {
	packages := map[string]struct{}{
		"internal/v2/gatecattempt": {}, "internal/v2/gatecrequest": {}, "internal/v2/gatecstage": {},
		"internal/v2/sshassembly": {}, "internal/v2/sshchildwrapper": {},
	}
	forbiddenModulePrefixes := []string{
		modulePath + "/internal/probeio", modulePath + "/internal/v2/directconnect/gateb",
		modulePath + "/pkg/netif", modulePath + "/pkg/tunnel", modulePath + "/pkg/meshruntime",
		"tailscale.com/", "github.com/pion/", "github.com/quic-go/",
	}
	var violations []string
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
		packageDirectory := filepath.ToSlash(filepath.Dir(relative))
		if _, watched := packages[packageDirectory]; !watched {
			return nil
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), filename, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, specification := range parsed.Imports {
			imported, err := strconv.Unquote(specification.Path.Value)
			if err != nil {
				return err
			}
			forbidden := imported == "net" || (strings.HasPrefix(imported, "net/") && imported != "net/netip")
			if imported == "unsafe" && relative != "internal/v2/sshassembly/process_windows.go" {
				forbidden = true
			}
			if imported == "syscall" && relative != "internal/v2/sshchildwrapper/validate_linux.go" &&
				relative != "internal/v2/sshassembly/process_linux.go" && relative != "internal/v2/sshassembly/process_windows.go" {
				forbidden = true
			}
			if imported == "os/exec" && relative != "internal/v2/sshassembly/process.go" &&
				relative != "internal/v2/sshassembly/process_linux.go" && relative != "internal/v2/sshassembly/process_windows.go" &&
				relative != "internal/v2/sshassembly/process_unsupported.go" {
				violations = append(violations, relative+" imports os/exec outside the fixed process adapter")
				continue
			}
			for _, prefix := range forbiddenModulePrefixes {
				if imported == prefix || strings.HasPrefix(imported, prefix) {
					forbidden = true
				}
			}
			if forbidden {
				violations = append(violations, relative+" imports "+imported)
			}
		}
		return nil
	})
	sort.Strings(violations)
	return violations, err
}

func gateC1aShapeViolations(root string) ([]string, error) {
	directory := filepath.Join(root, "internal", "v2", "sshassembly")
	var violations []string
	natlab := filepath.Join(directory, "authority_natlab_linux.go")
	if payload, err := os.ReadFile(natlab); err == nil {
		normalized := strings.ReplaceAll(string(payload), "\r\n", "\n")
		if !strings.HasPrefix(normalized, "//go:build linux && natlab\n") {
			violations = append(violations, "internal/v2/sshassembly/authority_natlab_linux.go lacks exact linux+natlab build constraint")
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	execCount, claimCount, drainCount := 0, 0, 0
	fset := token.NewFileSet()
	err := filepath.WalkDir(directory, func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		relative, err := filepath.Rel(root, filename)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		payload, err := os.ReadFile(filename)
		if err != nil {
			return err
		}
		text := string(payload)
		for _, forbidden := range []string{"PasswordAuthentication=yes", "StrictHostKeyChecking=no", "ControlMaster=yes", "cmd.exe", "powershell.exe", "sh -c"} {
			if strings.Contains(text, forbidden) {
				violations = append(violations, relative+" contains forbidden "+forbidden)
			}
		}
		parsed, err := parser.ParseFile(fset, filename, payload, 0)
		if err != nil {
			return err
		}
		execAliases := make(map[string]struct{})
		for _, imported := range parsed.Imports {
			path, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				return err
			}
			if path != "os/exec" {
				continue
			}
			name := "exec"
			if imported.Name != nil {
				name = imported.Name.Name
			}
			execAliases[name] = struct{}{}
		}
		for _, declaration := range parsed.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Recv != nil || !function.Name.IsExported() || function.Type.Results == nil {
				continue
			}
			returnsAuthority := false
			ast.Inspect(function.Type.Results, func(node ast.Node) bool {
				identifier, ok := node.(*ast.Ident)
				if ok && identifier.Name == "SSHEndpointAuthority" {
					returnsAuthority = true
				}
				return true
			})
			if returnsAuthority && function.Name.Name != "NewLoopbackAuthority" && function.Name.Name != "NewNATLabAuthority" {
				violations = append(violations, relative+" defines unreviewed exported SSH authority constructor "+function.Name.Name)
			}
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.CallExpr:
				selector, ok := value.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if qualifier, ok := selector.X.(*ast.Ident); ok {
					if _, isExec := execAliases[qualifier.Name]; isExec {
						if relative == "internal/v2/sshassembly/process.go" && selector.Sel.Name == "Command" {
							execCount++
						} else {
							violations = append(violations, relative+" calls unreviewed os/exec "+selector.Sel.Name)
						}
						return true
					}
				}
				switch selector.Sel.Name {
				case "ClaimExclusive":
					claimCount++
				case "RegisterDrain":
					drainCount++
				}
			case *ast.CompositeLit:
				identifier, ok := value.Type.(*ast.Ident)
				if ok && identifier.Name == "processSpec" && relative != "internal/v2/sshassembly/assembly.go" {
					violations = append(violations, relative+" constructs processSpec outside assembly.go")
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	if execCount != 1 {
		violations = append(violations, fmt.Sprintf("internal/v2/sshassembly exec.Command count=%d want=1", execCount))
	}
	if claimCount != 1 {
		violations = append(violations, fmt.Sprintf("internal/v2/sshassembly ClaimExclusive count=%d want=1", claimCount))
	}
	if drainCount != 1 {
		violations = append(violations, fmt.Sprintf("internal/v2/sshassembly RegisterDrain count=%d want=1", drainCount))
	}
	profilePath := filepath.Join(directory, "profile.go")
	if payload, err := os.ReadFile(profilePath); err == nil {
		text := string(payload)
		for _, required := range []string{"-F", "IdentityAgent=none", "GlobalKnownHostsFile=none", "SessionType=default", FixedRemoteCommandForGate()} {
			if !strings.Contains(text, required) {
				violations = append(violations, "internal/v2/sshassembly/profile.go lacks fixed "+required)
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	containmentRequirements := map[string][]string{
		"process_linux.go":   {"runtime.LockOSThread", "Pdeathsig: syscall.SIGKILL"},
		"process_windows.go": {"CREATE_SUSPENDED", "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE", "AssignProcessToJobObject", "ResumeThread"},
	}
	for name, required := range containmentRequirements {
		path := filepath.Join(directory, name)
		payload, err := os.ReadFile(path)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, err
			}
			violations = append(violations, "internal/v2/sshassembly/"+name+" lacks parent-death containment")
			continue
		}
		text := string(payload)
		for _, fragment := range required {
			if !strings.Contains(text, fragment) {
				violations = append(violations, "internal/v2/sshassembly/"+name+" lacks fixed "+fragment)
			}
		}
	}
	sort.Strings(violations)
	return violations, nil
}

func FixedRemoteCommandForGate() string { return "wink solver direct child --stdio" }
