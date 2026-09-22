package architecture

import (
	"context"
	"crypto/sha256"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

var fieldC1cImportFiles = map[string]bool{
	"internal/probeio/field_factory_fieldc1c.go":               true,
	"internal/v2/directconnect/gateb/deployment_fieldc1c.go":   true,
	"internal/v2/sshassembly/authority_fieldc1c.go":            true,
	"internal/v2/gatecorchestrator/field_entry_linux.go":       true,
	"internal/v2/gatecorchestrator/field_entry_unsupported.go": true,
	"pkg/netif/field_authority_fieldc1c.go":                    true,
	"cmd/wink/cmd/gate_c1c_fieldc1c.go":                        true,
	"internal/c1crouter/nat_linux.go":                          true,
	"internal/c1crouter/journal_linux.go":                      true,
	"internal/c1crouter/topology_linux.go":                     true,
	"internal/c1crouter/guardian_linux.go":                     true,
	"internal/c1crouter/runtime_linux.go":                      true,
	"internal/c1crouter/command_linux.go":                      true,
}

// The field adapter may reject a non-nil test factory; it cannot construct,
// assign, return, or otherwise consume that factory's namespace authority.
func approvedFieldC1cNATLabExclusion(root, relative string, file *ast.File, identifier *ast.Ident) bool {
	if relative != "internal/v2/directconnect/gateb/deployment_fieldc1c.go" {
		return false
	}
	data, err := os.ReadFile(filepath.Join(root, relative))
	if err != nil || !strings.HasPrefix(strings.ReplaceAll(string(data), "\r\n", "\n"), "//go:build fieldc1c\n") {
		return false
	}
	allowed := false
	for _, declaration := range file.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "validate" || fn.Recv == nil || len(fn.Recv.List) != 1 {
			continue
		}
		receiver, ok := fn.Recv.List[0].Type.(*ast.Ident)
		if !ok || receiver.Name != "deploymentAuthority" {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			expr, ok := node.(*ast.BinaryExpr)
			if !ok || expr.Op != token.NEQ {
				return true
			}
			left, ok := expr.X.(*ast.SelectorExpr)
			if !ok || left.Sel != identifier {
				return true
			}
			owner, ownerOK := left.X.(*ast.Ident)
			right, rightOK := expr.Y.(*ast.Ident)
			if ownerOK && owner.Name == "config" && rightOK && right.Name == "nil" {
				allowed = true
			}
			return true
		})
	}
	return allowed
}

func TestFieldC1cNATLabExclusionDoesNotGrantConsumption(t *testing.T) {
	relative := "internal/v2/directconnect/gateb/deployment_fieldc1c.go"
	for _, tc := range []struct {
		body     string
		rejected bool
	}{
		{"if config.HardNATLabFactory != nil { return invalid }; return nil", false},
		{"if config.HardNATLabFactory == nil { return invalid }; return nil", true},
		{"return config.HardNATLabFactory", true},
		{"config.HardNATLabFactory = other; return nil", true},
		{"if config.HardNATLabFactory != other { return invalid }; return nil", true},
	} {
		root := t.TempDir()
		writeArchitectureMutation(t, root, relative, "//go:build fieldc1c\n\npackage gateb\nfunc (a deploymentAuthority) validate(config Config) error {"+tc.body+"}\n")
		violations, err := gateB3AuthorityViolations(root)
		if err != nil || (len(violations) != 0) != tc.rejected {
			t.Fatalf("natlab exclusion mutation: %v %v", violations, err)
		}
	}
}

func TestFieldC1cCapabilitiesStaySealed(t *testing.T) {
	violations, err := fieldC1cViolations(repositoryRoot(t))
	if err != nil || len(violations) > 0 {
		t.Fatalf("field capability gate: %v %v", err, violations)
	}
}

func fieldC1cViolations(root string) ([]string, error) {
	var violations []string
	err := filepath.WalkDir(root, func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if strings.HasPrefix(entry.Name(), ".") && filename != root {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(filename, ".go") || strings.HasSuffix(filename, "_test.go") {
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
		source := strings.ReplaceAll(string(payload), "\r\n", "\n")
		file, err := parser.ParseFile(token.NewFileSet(), filename, source, 0)
		if err != nil {
			return err
		}
		fieldFile := strings.Contains(relative, "fieldc1c") || strings.HasPrefix(filepath.Base(relative), "field_")
		if fieldFile && !strings.HasPrefix(source, "//go:build fieldc1c\n") && !strings.HasPrefix(source, "//go:build linux && fieldc1c\n") && !strings.HasPrefix(source, "//go:build !linux && fieldc1c\n") {
			violations = append(violations, relative+" missing exact field constraint")
		}
		for _, imported := range file.Imports {
			value, _ := strconv.Unquote(imported.Path.Value)
			if value == modulePath+"/internal/v2/fieldc1c" && !fieldC1cImportFiles[relative] {
				violations = append(violations, relative+" unapproved field import")
			}
			if strings.HasPrefix(relative, "internal/probeio/") && (value == modulePath+"/internal/v2/hardnatplan" || value == modulePath+"/internal/v2/hardnatbudget") && relative != "internal/probeio/field_factory_fieldc1c.go" {
				violations = append(violations, relative+" untagged field plan dependency")
			}
			if strings.HasPrefix(relative, "cmd/wink/") && value == modulePath+"/internal/v2/sshchildwrapper" && relative != "cmd/wink/deployment_fieldc1c_linux.go" {
				violations = append(violations, relative+" unapproved wrapper import")
			}
			if strings.HasPrefix(relative, "internal/v2/fieldc1c/") && (value == "net" || value == "os/exec" || value == "syscall" && filepath.Base(relative) != "path_linux.go") {
				violations = append(violations, relative+" raw authorization capability")
			}
		}
		allowedUses := map[string]map[string]bool{
			"NewFieldAuthority":          {"internal/v2/sshassembly/authority_fieldc1c.go": true, "internal/v2/gatecorchestrator/field_entry_linux.go": true},
			"NewFieldUDPFactory":         {"internal/probeio/field_factory_fieldc1c.go": true, "internal/v2/gatecorchestrator/field_entry_linux.go": true},
			"ConfigureFieldAttempt":      {"internal/v2/directconnect/gateb/deployment_fieldc1c.go": true, "internal/v2/gatecorchestrator/field_entry_linux.go": true},
			"NewFieldInterfaceAuthority": {"pkg/netif/field_authority_fieldc1c.go": true, "internal/v2/gatecorchestrator/field_entry_linux.go": true},
			"NewFieldInterface":          {"pkg/netif/field_tun_linux.go": true, "internal/v2/gatecorchestrator/field_entry_linux.go": true},
			"NewFieldWireGuard":          {"pkg/tunnel/fieldc1c_linux.go": true, "internal/v2/gatecorchestrator/field_entry_linux.go": true},
			"ExecFieldRoot":              {"internal/v2/sshchildwrapper/exec_fieldc1c_linux.go": true, "cmd/wink/deployment_fieldc1c_linux.go": true},
			"AuthorizePlan":              {"internal/probeio/field_factory_fieldc1c.go": true, "internal/v2/directconnect/gateb/deployment_fieldc1c.go": true},
		}
		ast.Inspect(file, func(node ast.Node) bool {
			if literal, ok := node.(*ast.CompositeLit); ok && len(literal.Elts) != 0 && strings.HasPrefix(relative, "internal/v2/fieldc1c/") {
				if name, ok := literal.Type.(*ast.Ident); ok && name.Name == "Instance" {
					owner := ""
					for _, declaration := range file.Decls {
						if fn, ok := declaration.(*ast.FuncDecl); ok && fn.Pos() <= literal.Pos() && literal.End() <= fn.End() {
							owner = fn.Name.Name
						}
					}
					if relative != "internal/v2/fieldc1c/instance.go" || owner != "Load" {
						violations = append(violations, relative+" issues instance outside Load")
					}
				}
			}
			id, ok := node.(*ast.Ident)
			if !ok {
				return true
			}
			if allowed, watched := allowedUses[id.Name]; watched && !allowed[relative] {
				violations = append(violations, relative+" unapproved "+id.Name)
			}
			return true
		})
		if relative == "pkg/netif/field_netlink_linux.go" {
			// AF_INET in netlink address payloads is allowed, never in Socket.
			if !strings.Contains(source, "unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)") || strings.Count(source, "unix.Socket(") != 1 {
				violations = append(violations, "field kernel fd escaped exact local family")
			}
		}
		if fieldFile {
			rawCalls := 0
			ast.Inspect(file, func(node ast.Node) bool {
				if selector, ok := node.(*ast.SelectorExpr); ok {
					switch selector.Sel.Name {
					case "Syscall", "Syscall6", "RawSyscall", "RawSyscall6":
						rawCalls++
					}
				}
				return true
			})
			if rawCalls != 0 && (relative != "pkg/netif/field_tun_linux.go" || rawCalls != 1 ||
				!strings.Contains(source, "unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(request)))")) {
				violations = append(violations, relative+" raw syscall escaped exact TUN ioctl")
			}
		}
		return nil
	})
	sort.Strings(violations)
	return violations, err
}

func TestFieldC1cMutationRejectsTagAndConsumerEscapes(t *testing.T) {
	mutants := map[string]string{
		"internal/v2/fieldc1c/bypass.go":        "//go:build fieldc1c\n\npackage fieldc1c\nfunc Bypass(){_=Instance{value: nil}}\n",
		"pkg/client/plan.go":                    "package client\nfunc f(){factory.AuthorizePlan(plan)}\n",
		"pkg/runtime/escape.go":                 "package runtime\nimport \"winkyou/internal/v2/fieldc1c\"\nvar _ = fieldc1c.Load\n",
		"internal/probeio/escape.go":            "package probeio\nimport \"winkyou/internal/v2/hardnatplan\"\nvar _ hardnatplan.Plan\n",
		"cmd/wink/deployment_fieldc1c_linux.go": "package main\nfunc f(){ _=ExecFieldRoot }\n",
		"pkg/netif/field_netlink_linux.go":      "//go:build linux && fieldc1c\n\npackage netif\nfunc openFieldKernelControl(){ unix.Socket(unix.AF_INET, unix.SOCK_RAW, 0) }\n",
		"pkg/netif/field_tun_linux.go":          "//go:build linux && fieldc1c\n\npackage netif\nfunc bypass(){ unix.Syscall(unix.SYS_SOCKET, 0, 0, 0) }\n",
		"pkg/client/escape.go":                  "package client\nfunc f(){_=NewFieldAuthority;_=NewFieldUDPFactory;_=ConfigureFieldAttempt;_=NewFieldInterface;_=NewFieldWireGuard}\n",
	}
	for relative, source := range mutants {
		t.Run(relative, func(t *testing.T) {
			root := t.TempDir()
			writeArchitectureMutation(t, root, relative, source)
			violations, err := fieldC1cViolations(root)
			if err != nil || len(violations) == 0 {
				t.Fatalf("mutation escaped: %v %v", violations, err)
			}
		})
	}
}

var fieldC1cSymbolPatterns = []string{
	`winkyou/internal/v2/fieldc1c\.Load`,
	`winkyou/internal/v2/sshassembly\.NewFieldAuthority`,
	`winkyou/internal/probeio\.NewFieldUDPFactory`,
	`winkyou/pkg/netif\.NewFieldInterface`,
	`winkyou/pkg/tunnel\.NewFieldWireGuard`,
	`winkyou/internal/v2/gatecorchestrator\.RunFieldInitiator`,
	`winkyou/internal/v2/sshchildwrapper\.ExecFieldRoot`,
}

func TestFieldC1cBinarySymbolIsolation(t *testing.T) {
	for _, tags := range []string{"", "c1bproof", "natlab", "fieldc1c"} {
		t.Run("tags="+tags, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			output := filepath.Join(t.TempDir(), "wink.elf")
			args := []string{"build", "-gcflags=all=-l", "-o", output}
			if tags != "" {
				args = append(args, "-tags="+tags)
			}
			args = append(args, "./cmd/wink")
			build := exec.CommandContext(ctx, "go", args...)
			build.Dir = repositoryRoot(t)
			for _, entry := range os.Environ() {
				if !strings.HasPrefix(entry, "GOOS=") && !strings.HasPrefix(entry, "CGO_ENABLED=") {
					build.Env = append(build.Env, entry)
				}
			}
			build.Env = append(build.Env, "GOOS=linux", "CGO_ENABLED=0")
			started := time.Now()
			if data, err := build.CombinedOutput(); err != nil {
				fieldSymbolFailure(t, ctx, "build", started, data)
			}
			nm := exec.CommandContext(ctx, "go", "tool", "nm", output)
			started = time.Now()
			data, err := nm.CombinedOutput()
			if err != nil {
				fieldSymbolFailure(t, ctx, "nm", started, data)
			}
			for _, pattern := range fieldC1cSymbolPatterns {
				found := regexp.MustCompile(pattern).Match(data)
				if found != (tags == "fieldc1c") {
					t.Fatalf("symbol contract %s presence=%t", pattern, found)
				}
			}
		})
	}
}

func fieldSymbolFailure(t *testing.T, ctx context.Context, phase string, started time.Time, data []byte) {
	t.Helper()
	class := "tool_failed"
	if ctx.Err() != nil {
		class = "deadline"
	}
	// Tool diagnostics may contain local paths. Publish only a stable class,
	// elapsed time and evidence digest, never the command/output text.
	digest := sha256.Sum256(data)
	t.Fatalf("symbol witness phase=%s class=%s wall_ms=%d diagnostic_bytes=%d diagnostic_sha256=%x", phase, class, time.Since(started).Milliseconds(), len(data), digest)
}
