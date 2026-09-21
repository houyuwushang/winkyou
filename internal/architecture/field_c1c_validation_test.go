package architecture

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Runtime negative vectors exercise actual validation. These independent
// source mutations additionally ensure that deleting one bearing guard does
// not silently turn that vector suite into a different authorization contract.
var fieldValidationGuards = map[string][]string{
	"internal/v2/fieldc1c/validate.go": {
		"len(raw) != 88", "if !present", "isNull || !filled(reflect.ValueOf(doc).Field(index))",
		"doc.AuthoritySchemaRevision != Schema", "doc.ExactSHA != build.sha", "doc.ExactSHA != build.revision", "build.modified",
		"binaryHash != build.binaryHash", "now.Before(before)", "!now.Before(after)", "!now.Before(expires)",
		"doc.Operator == doc.IndependentReviewer", "doc.Devices[0].Role != \"initiator\"", "device.OS != \"linux\"",
		"doc.DependencyAndConfigurationSHA256 != dependencyDigest(build, doc.Devices)",
	},
	"internal/v2/fieldc1c/instance.go": {
		"type Instance struct{ value *validated }", "runtime.GOOS != \"linux\"", "safeParents(filepath.Dir(path)) != nil",
		"validate(payload, role, time.Now().UTC(), build)", "path != expected", "scope != wantScope",
		"debug.ReadBuildInfo()", "os.Executable()", "sha256.New()", "io.Copy(hash, file)",
		"now.Before(instance.value.notBefore)", "!now.Before(instance.value.notAfter)",
		"netip.ParseAddr(value)", "netip.ParseAddrPort(value)", "!address.IsGlobalUnicast()",
		"decoder.DisallowUnknownFields()", "visitJSON(decoder, 0)",
	},
	"internal/probeio/field_factory_fieldc1c.go": {
		"netip.AddrPortFrom(netip.IPv4Unspecified(), 0)", "ctx.Value(deploymentLeaseKey{}) != factory.lease",
		"request.ID != factory.binding.ID", "!hardnatbudget.Exact(", "factory.opened >= factory.maximum",
		"factory.opened != factory.maximum", "factory.planSet", "!plan.Executable",
		"netip.AddrPortFrom(factory.peer, candidate.TargetPort)", "targets[fieldTarget{slot, target}]",
		"!datagram.owner.targetAllowed(datagram.slot, target)",
	},
	"internal/v2/sshassembly/authority_fieldc1c.go": {
		"type fieldScope struct", "scope: fieldScope{instance: instance}", "instance.SSHEndpoint()",
		"expected != endpoint", "expectedPin != pin", "expectedIdentity != identity",
	},
	"internal/v2/sshchildwrapper/exec_fieldc1c_linux.go": {
		"PrepareRootExecution(originalCommand)",
		"syscall.Exec(plan.Executable, append([]string{plan.Executable}, plan.Arguments...), plan.Environment)",
	},
	"pkg/netif/field_authority_fieldc1c.go": {
		"type FieldInterfaceAuthority struct{ state *fieldInterfaceState }", "permit.Name != name", "permit.MTU != mtu",
		"permit.LocalAddress != local.String()", "permit.PeerAddress != peer.String()", "len(routes) != 1", "routes[0] != netip.PrefixFrom(peer, 32)",
	},
	"pkg/tunnel/fieldc1c_linux.go": {"cfg.Interface.(*netif.FieldInterface)", "!owned.ValidTransport()", "cfg.ListenPort != 0", "instance.memoryOnly = true"},
}

func fieldValidationSources(t *testing.T) map[string]string {
	t.Helper()
	sources := make(map[string]string)
	for file := range fieldValidationGuards {
		data, err := os.ReadFile(filepath.Join(repositoryRoot(t), file))
		if err != nil {
			t.Fatal(err)
		}
		sources[file] = strings.ReplaceAll(string(data), "\r\n", "\n")
	}
	return sources
}

func fieldValidationViolations(sources map[string]string) []string {
	var violations []string
	for file, guards := range fieldValidationGuards {
		for _, guard := range guards {
			if !strings.Contains(sources[file], guard) {
				violations = append(violations, file+" lacks frozen validation guard")
			}
		}
	}
	return violations
}

func TestFieldC1cValidationGuardsAndDeletionMutants(t *testing.T) {
	sources := fieldValidationSources(t)
	if bad := fieldValidationViolations(sources); len(bad) != 0 {
		t.Fatalf("field validation contract changed: %v", bad)
	}
	for file, guards := range fieldValidationGuards {
		for _, guard := range guards {
			t.Run(filepath.Base(file)+"/"+guard, func(t *testing.T) {
				old := sources[file]
				sources[file] = strings.ReplaceAll(old, guard, "/* removed-bearing-check */")
				defer func() { sources[file] = old }()
				if len(fieldValidationViolations(sources)) == 0 {
					t.Fatal("validation deletion escaped")
				}
			})
		}
	}
}

func TestFieldC1cOpaqueInstanceCannotGainExternalIssuer(t *testing.T) {
	sources := fieldValidationSources(t)
	original := sources["internal/v2/fieldc1c/instance.go"]
	for _, replacement := range []string{
		"type Instance interface{ Check() error }", "type Instance struct{ Value *validated }",
		"type Instance struct{ *validated }",
	} {
		sources["internal/v2/fieldc1c/instance.go"] = strings.Replace(original, "type Instance struct{ value *validated }", replacement, 1)
		if len(fieldValidationViolations(sources)) == 0 {
			t.Fatal("external authority forgery escaped")
		}
	}
	// A private representation alone is not enough if an added exported
	// function can issue it without Load's build, path and machine witnesses.
	check := func(source string) int {
		parsed, err := parser.ParseFile(token.NewFileSet(), "instance.go", source, 0)
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				literal, ok := node.(*ast.CompositeLit)
				if !ok || len(literal.Elts) == 0 {
					return true
				}
				name, ok := literal.Type.(*ast.Ident)
				if ok && name.Name == "Instance" && fn.Name.Name != "Load" {
					count++
				}
				return true
			})
		}
		return count
	}
	if check(original) != 0 || check(original+"\nfunc Bypass(v *validated) Instance {return Instance{value:v}}\n") != 1 {
		t.Fatal("opaque instance issuer mutation not caught")
	}
}
