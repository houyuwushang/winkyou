package architecture

import (
	"context"
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
			if _, err := build.CombinedOutput(); err != nil {
				t.Fatal("symbol witness build failed")
			}
			nm := exec.CommandContext(ctx, "go", "tool", "nm", output)
			data, err := nm.CombinedOutput()
			if err != nil {
				t.Fatal("symbol witness unavailable")
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
