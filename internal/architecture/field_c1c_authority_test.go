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

// The field issuer extends the concrete token, never a public interface or
// caller-supplied address. Ordinary/NATLab issuers remain distinct.
func TestFieldC1cSSHAuthorityShape(t *testing.T) {
	path := filepath.Join(repositoryRoot(t), "internal/v2/sshassembly/authority_fieldc1c.go")
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("field-only SSH authority issuer is absent")
	}
	source := strings.ReplaceAll(string(payload), "\r\n", "\n")
	if !strings.HasPrefix(source, "//go:build fieldc1c\n") {
		t.Fatal("field issuer must have the exact independent fieldc1c build gate")
	}
	file, err := parser.ParseFile(token.NewFileSet(), "authority_fieldc1c.go", source, 0)
	if err != nil {
		t.Fatal("field issuer syntax rejected")
	}
	var scope, issuer, validator int
	ast.Inspect(file, func(node ast.Node) bool {
		if spec, ok := node.(*ast.TypeSpec); ok && spec.Name.Name == "fieldScope" {
			scope++
			structure, ok := spec.Type.(*ast.StructType)
			if !ok || spec.Assign.IsValid() {
				t.Fatal("fieldScope must be a private concrete scope")
			}
			for _, field := range structure.Fields.List {
				if len(field.Names) != 1 || ast.IsExported(field.Names[0].Name) {
					t.Fatal("fieldScope must not embed or export authority fields")
				}
			}
		}
		if fn, ok := node.(*ast.FuncDecl); ok {
			if fn.Name.Name == "NewFieldAuthority" && fn.Recv == nil {
				issuer++
				if fn.Type.Params.NumFields() != 1 || fn.Type.Results.NumFields() != 2 {
					t.Fatal("field issuer accepts exactly one validated instance")
				}
			}
			if fn.Name.Name == "validateEndpoint" && fn.Recv != nil {
				if name, ok := fn.Recv.List[0].Type.(*ast.Ident); ok && name.Name == "fieldScope" {
					validator++
				}
			}
		}
		return true
	})
	if scope != 1 || issuer != 1 || validator != 1 {
		t.Fatalf("field scope/issuer/validator counts = %d/%d/%d", scope, issuer, validator)
	}
}
