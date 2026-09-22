package architecture

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const sshAuthorityDirectory = "internal/v2/sshassembly/"

func TestSSHAuthorityTokenBoundary(t *testing.T) {
	sources := sshAuthoritySources(t)
	if violations := sshAuthorityTokenViolations(sources); len(violations) != 0 {
		t.Fatalf("SSH authority seal changed:\n%s", strings.Join(violations, "\n"))
	}
}

func TestSSHAuthorityTokenMutations(t *testing.T) {
	original := sshAuthoritySources(t)
	tests := []struct{ name, file, before, after, violation string }{
		{"interface", "authority.go", "type SSHEndpointAuthority struct {\n\tendpoint netip.AddrPort\n\tscope    endpointScope\n}", "type SSHEndpointAuthority interface { Endpoint() netip.AddrPort }", "opaque private struct"},
		{"exported_field", "authority.go", "endpoint netip.AddrPort\n\tscope", "EndpointValue netip.AddrPort\n\tscope", "opaque private struct"},
		{"mutable_receiver", "authority.go", "func (authority SSHEndpointAuthority) Endpoint", "func (authority *SSHEndpointAuthority) Endpoint", "pointer receiver"},
		{"setter", "authority.go", "func canonicalEndpoint", "func (authority SSHEndpointAuthority) SetEndpoint() {}\nfunc canonicalEndpoint", "unreviewed authority method"},
		{"unchecked_scope", "authority.go", "authority.scope.validateEndpoint(endpoint) != nil", "false", "validated snapshot guard"},
		{"unchecked_canonical", "authority.go", "endpoint != authority.endpoint", "false", "validated snapshot guard"},
		{"bind_dynamic_address", "profile.go", "endpoint: endpoint, user:", "endpoint: authority.Endpoint(), user:", "unchecked Endpoint extraction"},
		{"argv_dynamic_address", "profile.go", "endpoint.Addr().String()", "config.authority.Endpoint().Addr().String()", "unchecked Endpoint extraction"},
		{"spawn_no_recheck", "assembly.go", "endpoint, err = config.Client.authority.validatedEndpoint()", "endpoint, err = config.Client.endpoint, nil", "openClient snapshot count"},
		{"extra_issuer", "authority.go", "func canonicalEndpoint", "func extra() SSHEndpointAuthority { return SSHEndpointAuthority{endpoint: netip.AddrPort{}, scope: loopbackScope{}} }\nfunc canonicalEndpoint", "outside exact issuer"},
		{"global_issuer", "authority.go", "func canonicalEndpoint", "var extra = SSHEndpointAuthority{endpoint: netip.AddrPort{}, scope: loopbackScope{}}\nfunc canonicalEndpoint", "outside exact issuer"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sources := make(map[string]string, len(original))
			for path, source := range original {
				sources[path] = source
			}
			path := sshAuthorityDirectory + test.file
			if strings.Count(sources[path], test.before) != 1 {
				t.Fatal("mutation no longer selects exactly one source site")
			}
			sources[path] = strings.Replace(sources[path], test.before, test.after, 1)
			if violations := sshAuthorityTokenViolations(sources); !containsLineFragment(violations, test.violation) {
				t.Fatalf("mutation not rejected: %v", violations)
			}
		})
	}
	for _, alias := range []string{"sshassembly", "renamed"} {
		t.Run("external_embedding_"+alias, func(t *testing.T) {
			sources := map[string]string{
				"internal/v2/gatecorchestrator/bypass.go": fmt.Sprintf(`package gatecorchestrator
import %s "winkyou/internal/v2/sshassembly"
type wrapper struct { %s.SSHEndpointAuthority }
`, alias, alias),
			}
			if violations := sshAuthorityTokenViolations(sources); !containsLineFragment(violations, "embeds SSH authority") {
				t.Fatalf("external wrapper not rejected: %v", violations)
			}
		})
	}
}

func sshAuthoritySources(t *testing.T) map[string]string {
	t.Helper()
	root := repositoryRoot(t)
	sources := make(map[string]string)
	for _, directory := range []string{sshAuthorityDirectory, "internal/v2/gatecorchestrator/"} {
		entries, err := os.ReadDir(filepath.Join(root, directory))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			path := directory + entry.Name()
			payload, err := os.ReadFile(filepath.Join(root, path))
			if err != nil {
				t.Fatal(err)
			}
			sources[path] = strings.ReplaceAll(string(payload), "\r\n", "\n")
		}
	}
	return sources
}

func sshAuthorityTokenViolations(sources map[string]string) []string {
	var violations []string
	fset := token.NewFileSet()
	for path, source := range sources {
		file, err := parser.ParseFile(fset, path, source, 0)
		if err != nil {
			violations = append(violations, path+" parse error")
			continue
		}
		assembly := strings.HasPrefix(path, sshAuthorityDirectory)
		aliases := map[string]bool{}
		for _, spec := range file.Imports {
			imported, _ := strconv.Unquote(spec.Path.Value)
			if imported == modulePath+"/internal/v2/sshassembly" {
				name := "sshassembly"
				if spec.Name != nil {
					name = spec.Name.Name
				}
				aliases[name] = true
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			if value, ok := node.(*ast.CompositeLit); ok && assembly && len(value.Elts) != 0 {
				if identifier, ok := value.Type.(*ast.Ident); ok && identifier.Name == "SSHEndpointAuthority" {
					owner := ""
					for _, declaration := range file.Decls {
						if fn, ok := declaration.(*ast.FuncDecl); ok && fn.Pos() <= value.Pos() && value.End() <= fn.End() {
							owner = fn.Name.Name
						}
					}
					ordinary := path == sshAuthorityDirectory+"authority.go" && owner == "NewLoopbackAuthority"
					natlab := path == sshAuthorityDirectory+"authority_natlab_linux.go" && owner == "NewNATLabAuthority"
					field := path == sshAuthorityDirectory+"authority_fieldc1c.go" && owner == "NewFieldAuthority" &&
						strings.HasPrefix(source, "//go:build fieldc1c\n")
					if !ordinary && !natlab && !field {
						violations = append(violations, path+" constructs authority outside exact issuer")
					}
				}
			}
			if value, ok := node.(*ast.StructType); ok && !assembly {
				for _, field := range value.Fields.List {
					selector, ok := field.Type.(*ast.SelectorExpr)
					if !ok || len(field.Names) != 0 || selector.Sel.Name != "SSHEndpointAuthority" {
						continue
					}
					if owner, ok := selector.X.(*ast.Ident); ok && aliases[owner.Name] {
						violations = append(violations, path+" embeds SSH authority in a production wrapper")
					}
				}
			}
			if spec, ok := node.(*ast.TypeSpec); ok && assembly && spec.Name.Name == "SSHEndpointAuthority" {
				shape := sshAuthorityNode(fset, spec.Type)
				if spec.Assign.IsValid() || shape != "struct {\n\tendpoint netip.AddrPort\n\tscope    endpointScope\n}" {
					violations = append(violations, path+" authority is not the exact opaque private struct")
				}
			}
			return true
		})
		if !assembly {
			continue
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if fn.Recv != nil {
				receiver := sshAuthorityNode(fset, fn.Recv.List[0].Type)
				if receiver == "*SSHEndpointAuthority" {
					violations = append(violations, path+" authority has a mutable pointer receiver")
				}
				if strings.TrimPrefix(receiver, "*") == "SSHEndpointAuthority" &&
					fn.Name.Name != "Endpoint" && fn.Name.Name != "IsZero" && fn.Name.Name != "validatedEndpoint" {
					violations = append(violations, path+" unreviewed authority method "+fn.Name.Name)
				}
			}
			count := 0
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				if call, ok := node.(*ast.CallExpr); ok {
					if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
						switch selector.Sel.Name {
						case "Endpoint":
							violations = append(violations, path+" unchecked Endpoint extraction in "+fn.Name.Name)
						case "validatedEndpoint":
							count++
						}
					}
				}
				return true
			})
			want, checked := map[string]int{"BindClientConfig": 1, "buildArguments": 1, "openClient": 2}[fn.Name.Name]
			if checked && count != want {
				violations = append(violations, fmt.Sprintf("%s %s snapshot count=%d want=%d", path, fn.Name.Name, count, want))
			}
			if fn.Name.Name == "validatedEndpoint" {
				body := sshAuthorityNode(fset, fn.Body)
				for _, guard := range []string{"endpoint := canonicalEndpoint(authority.endpoint)", "!endpoint.IsValid()", "endpoint != authority.endpoint", "authority.scope == nil", "authority.scope.validateEndpoint(endpoint) != nil", "return endpoint, nil"} {
					if !strings.Contains(body, guard) {
						violations = append(violations, path+" lacks validated snapshot guard "+guard)
					}
				}
			}
		}
	}
	sort.Strings(violations)
	return violations
}

func sshAuthorityNode(fset *token.FileSet, node ast.Node) string {
	var output bytes.Buffer
	_ = format.Node(&output, fset, node)
	return output.String()
}
