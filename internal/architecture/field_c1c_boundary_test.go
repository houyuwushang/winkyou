package architecture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"go/ast"
	"go/format"
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

// B1 grants exactly these files, never a generic Windows field capability.
var fieldWindowsFiles = map[string]bool{
	"pkg/netif/field_tun_windows.go":      true,
	"pkg/netif/field_ipcfg_windows.go":    true,
	"pkg/netif/field_iphlpapi_windows.go": true,
}

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
		if fieldWindowsFiles[relative] {
			if !strings.HasPrefix(source, "//go:build windows && fieldc1c\n") {
				violations = append(violations, relative+" missing exact Windows field constraint")
			}
			violations = append(violations, fieldWindowsFileViolations(relative, file)...)
		} else if fieldFile && !strings.HasPrefix(source, "//go:build fieldc1c\n") && !strings.HasPrefix(source, "//go:build linux && fieldc1c\n") && !strings.HasPrefix(source, "//go:build !linux && fieldc1c\n") {
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
			"NewFieldInterface":          {"pkg/netif/field_tun_linux.go": true, "pkg/netif/field_tun_windows.go": true, "internal/v2/gatecorchestrator/field_entry_linux.go": true},
			"NewFieldWireGuard":          {"pkg/tunnel/fieldc1c_linux.go": true, "internal/v2/gatecorchestrator/field_entry_linux.go": true},
			"ExecFieldRoot":              {"internal/v2/sshchildwrapper/exec_fieldc1c_linux.go": true, "cmd/wink/deployment_fieldc1c_linux.go": true},
			"AuthorizePlan":              {"internal/probeio/field_factory_fieldc1c.go": true, "internal/v2/directconnect/gateb/deployment_fieldc1c.go": true},
			"WintunIdentity":             {"internal/v2/fieldc1c/identity_fieldc1c.go": true, "pkg/netif/field_authority_fieldc1c.go": true},
			"fieldWindowsPermit":         {"pkg/netif/field_tun_windows.go": true},
			"newFieldWindowsInterface":   {"pkg/netif/field_tun_windows.go": true},
			"fieldNativeWintun":          {"pkg/netif/field_tun_windows.go": true},
			"fieldIPHelper":              {"pkg/netif/field_tun_windows.go": true, "pkg/netif/field_iphlpapi_windows.go": true},
			"configureFieldIP":           {"pkg/netif/field_tun_windows.go": true, "pkg/netif/field_ipcfg_windows.go": true},
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

// The fifteen local IP Helper procedures are a closed set. Enumeration and
// FreeMibTable are read-only witness plumbing, not a Flush or table setter.
var fieldWindowsIPProcs = map[string]string{
	"fieldProcIfTable": "GetIfTable2Ex", "fieldProcIfEntry": "GetIfEntry2",
	"fieldProcLUIDGUID": "ConvertInterfaceLuidToGuid", "fieldProcGUIDLUID": "ConvertInterfaceGuidToLuid",
	"fieldProcAddressTable": "GetUnicastIpAddressTable", "fieldProcRouteTable": "GetIpForwardTable2",
	"fieldProcFreeTable": "FreeMibTable", "fieldProcGetInterface": "GetIpInterfaceEntry",
	"fieldProcSetInterface": "SetIpInterfaceEntry", "fieldProcGetAddress": "GetUnicastIpAddressEntry",
	"fieldProcCreateAddress": "CreateUnicastIpAddressEntry", "fieldProcDeleteAddress": "DeleteUnicastIpAddressEntry",
	"fieldProcGetRoute": "GetIpForwardEntry2", "fieldProcCreateRoute": "CreateIpForwardEntry2", "fieldProcDeleteRoute": "DeleteIpForwardEntry2",
}

func fieldWindowsFileViolations(relative string, file *ast.File) []string {
	var bad []string
	reject := func(reason string) { bad = append(bad, relative+" "+reason) }
	aliases := map[string]string{}
	procCounts := map[string]int{}
	for _, spec := range file.Imports {
		path, _ := strconv.Unquote(spec.Path.Value)
		alias := filepath.Base(path)
		if spec.Name != nil {
			alias = spec.Name.Name
		}
		aliases[alias] = path
		if alias == "." || path == "os/exec" || strings.Contains(path, "winipcfg") {
			reject("unapproved import")
		}
	}
	owner := func(pos token.Pos) string {
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Pos() <= pos && pos < fn.End() {
				return fn.Name.Name
			}
		}
		return ""
	}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			if fn.Name.Name == "init" {
				reject("eager OS capability")
			}
			if fn.Recv == nil && fn.Name.IsExported() && fn.Name.Name != "NewFieldInterface" && fn.Name.Name != "PreflightFieldInterface" {
				reject("exported capability constructor")
			}
		}
		if group, ok := decl.(*ast.GenDecl); ok {
			for _, spec := range group.Specs {
				if row, ok := spec.(*ast.TypeSpec); ok && row.Name.Name == "FieldInterface" {
					fields, ok := row.Type.(*ast.StructType)
					if !ok {
						reject("interface ownership type escaped")
						continue
					}
					for _, field := range fields.Fields.List {
						if len(field.Names) == 0 {
							reject("public embedded raw device")
						}
						for _, name := range field.Names {
							if name.IsExported() {
								reject("public raw interface member")
							}
						}
					}
				}
				if value, ok := spec.(*ast.ValueSpec); ok && relative == "pkg/netif/field_iphlpapi_windows.go" {
					for index, name := range value.Names {
						if !strings.HasPrefix(name.Name, "fieldProc") {
							continue
						}
						want, exists := fieldWindowsIPProcs[name.Name]
						if !exists || index >= len(value.Values) {
							reject("unapproved DLL procedure")
							continue
						}
						call, ok := value.Values[index].(*ast.CallExpr)
						if !ok || len(call.Args) != 1 {
							reject("unapproved DLL procedure")
							continue
						}
						literal, ok := call.Args[0].(*ast.BasicLit)
						if !ok || literal.Value != strconv.Quote(want) {
							reject("unapproved DLL procedure")
						}
					}
				}
			}
		}
	}
	ast.Inspect(file, func(node ast.Node) bool {
		if literal, ok := node.(*ast.CompositeLit); ok && len(literal.Elts) > 0 {
			if name, ok := literal.Type.(*ast.Ident); ok && (name.Name == "fieldWindowsPermit" || name.Name == "fieldWindowsBinding") && owner(literal.Pos()) != "fieldPermit" {
				reject("forged private permit")
			}
		}
		if fn, ok := node.(*ast.FuncDecl); ok && fn.Recv != nil {
			var recv bytes.Buffer
			_ = format.Node(&recv, token.NewFileSet(), fn.Recv.List[0].Type)
			if recv.String() == "*FieldInterface" {
				allowed := map[string]bool{"Name": true, "Type": true, "MTU": true, "SetIP": true, "AddRoute": true, "RemoveRoute": true, "ValidTransport": true, "Read": true, "Write": true, "InjectPacket": true, "ReceivePacket": true, "Close": true, "Witness": true}
				if fn.Name.IsExported() && !allowed[fn.Name.Name] {
					reject("raw device accessor")
				}
				if fn.Name.Name == "SetIP" || fn.Name.Name == "AddRoute" || fn.Name.Name == "RemoveRoute" {
					var body bytes.Buffer
					_ = format.Node(&body, token.NewFileSet(), fn.Body)
					if strings.Join(strings.Fields(body.String()), " ") != "{ return ErrFieldInterface }" {
						reject("arbitrary configuration setter")
					}
				}
			}
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		name := selector.Sel.Name
		if strings.HasPrefix(name, "Flush") || strings.HasPrefix(name, "SetDNS") || strings.HasPrefix(name, "SetRoutes") || name == "OpenAdapter" || name == "DeleteDriver" {
			reject("forbidden bulk, DNS or takeover capability")
		}
		base, ok := selector.X.(*ast.Ident)
		if !ok {
			return true
		}
		path := aliases[base.Name]
		if (path == "net" && (strings.HasPrefix(name, "Dial") || strings.HasPrefix(name, "Listen"))) || path == "os/exec" {
			reject("network or child capability")
		}
		if name == "NewProc" && (relative != "pkg/netif/field_iphlpapi_windows.go" || base.Name != "fieldIPDLL") {
			reject("unapproved procedure factory")
		}
		if name == "NewProc" {
			value := ""
			if len(call.Args) == 1 {
				if literal, ok := call.Args[0].(*ast.BasicLit); ok {
					value, _ = strconv.Unquote(literal.Value)
				}
			}
			approved := false
			for _, expected := range fieldWindowsIPProcs {
				if value == expected {
					approved = true
				}
			}
			if !approved {
				reject("unapproved procedure name")
			}
			procCounts[value]++
		}
		if name == "Call" {
			if _, ok := fieldWindowsIPProcs[base.Name]; relative != "pkg/netif/field_iphlpapi_windows.go" || !ok {
				reject("unapproved local syscall")
			}
			functions := map[string]string{"fieldProcIfTable": "snapshot", "fieldProcAddressTable": "snapshot", "fieldProcRouteTable": "snapshot", "fieldProcFreeTable": "snapshot", "fieldProcIfEntry": "identity", "fieldProcLUIDGUID": "identity", "fieldProcGUIDLUID": "identity", "fieldProcGetInterface": "getInterface", "fieldProcSetInterface": "setInterface", "fieldProcGetAddress": "getAddress", "fieldProcCreateAddress": "createAddress", "fieldProcDeleteAddress": "deleteAddress", "fieldProcGetRoute": "getRoute", "fieldProcCreateRoute": "createRoute", "fieldProcDeleteRoute": "deleteRoute"}
			if functions[base.Name] != owner(call.Pos()) {
				reject("syscall escaped owned operation")
			}
		}
		if path == "golang.zx2c4.com/wireguard/tun" && (relative != "pkg/netif/field_tun_windows.go" || name != "CreateTUNWithRequestedGUID" || owner(call.Pos()) != "create") {
			reject("unapproved Wintun factory")
		}
		if path == "golang.org/x/sys/windows" && name == "NewLazySystemDLL" {
			if relative != "pkg/netif/field_iphlpapi_windows.go" || len(call.Args) != 1 {
				reject("unapproved system DLL")
			} else if value, ok := call.Args[0].(*ast.BasicLit); !ok || value.Value != `"iphlpapi.dll"` {
				reject("unapproved system DLL")
			}
		}
		if path == "golang.org/x/sys/windows" {
			functions := map[string]string{"GetAce": "fieldInstallationACL", "UTF16PtrFromString": "fieldSealDLL|fieldWintunUnloaded", "CreateFile": "fieldSealDLL", "GetFileInformationByHandle": "fieldSealDLL", "GetSecurityInfo": "fieldSealDLL", "GetModuleHandleEx": "fieldWintunUnloaded", "GetCurrentProcessToken": "preflight|create", "FreeLibrary": "Close|create", "LoadLibraryEx": "create", "GetModuleFileName": "create", "UTF16ToString": "create|snapshot|identity", "NewLazySystemDLL": ""}
			want, found := functions[name]
			if !found || !strings.Contains("|"+want+"|", "|"+owner(call.Pos())+"|") {
				reject("unapproved Windows API call")
			}
		}
		return true
	})
	if relative == "pkg/netif/field_iphlpapi_windows.go" {
		for _, expected := range fieldWindowsIPProcs {
			if procCounts[expected] != 1 {
				reject("procedure declaration count changed")
			}
		}
	}
	return bad
}

// Bearing guards supplement executable fake-negative tests. Parse without
// comments first: a comment containing an old check is not implementation.
var fieldWindowsGuards = map[string][]string{
	"pkg/netif/field_authority_fieldc1c.go": {"runtime.GOOS == \"windows\"", "instance.WintunIdentity()", "derivedName != name", "binding.Role != \"initiator\"", "device.OS != \"windows\""},
	"pkg/netif/field_tun_windows.go": {
		"!authority.valid()", "authority.state.used.Load()", "!permit.valid()", "permit.used.Load()", "!permit.used.CompareAndSwap(false, true)",
		"fieldRejectConflicts(permit.binding, before)", "id.guid != permit.binding.guid", "id.name != permit.binding.name",
		"configureFieldIP(ctx, api, permit.binding, id)", "f.txn.rollback(ctx)", "f.device.Close()", "f.api.snapshot()",
		"!w.InterfaceChecked", "!w.InterfaceAbsent", "!w.AddressesAbsent", "!w.RoutesAbsent", "!w.UnrelatedUnchanged",
		"2*time.Second", "fieldDriverOwner.TryLock()", "!fieldWintunUnloaded()", "windows.OPEN_EXISTING", "windows.FILE_FLAG_OPEN_REPARSE_POINT",
		"info.NumberOfLinks != 1", "fieldInstallationACL(sd, index <= 0)", "hex.EncodeToString(hash.Sum(nil)) != fieldDLLHash(runtime.GOARCH)",
		"log.SetOutput(record)", "windows.LoadLibraryEx(seal.path, 0, windows.LOAD_LIBRARY_SEARCH_SYSTEM32)",
		"wgtun.CreateTUNWithRequestedGUID(binding.name, &binding.guid, int(binding.mtu))",
	},
	"pkg/netif/field_ipcfg_windows.go": {
		"strings.EqualFold(adapter.name, binding.name) || adapter.guid == binding.guid", "address == binding.local || address == binding.peer",
		"prefix.Bits() != 0", "txn.applied = txn.before", "txn.applied.DadTransmits = 0", "txn.applied.MTU = binding.mtu",
		"fieldSameInterface(readInterface, txn.applied)", "fieldSameAddress(readAddress, txn.address)", "fieldSameRoute(readRoute, txn.route)", "fieldIdentityMatches(api, identity)",
		"fieldSameRoute(row, transaction.route)", "fieldSameAddress(row, transaction.address)", "fieldSameInterface(row, transaction.applied)",
		"api.deleteRoute(row)", "api.deleteAddress(row)", "api.setInterface(restore)", "errors.Is(err, windows.ERROR_NOT_FOUND)",
	},
}

func fieldWindowsGuardViolations(relative, source string) []string {
	var bad []string
	file, err := parser.ParseFile(token.NewFileSet(), relative, source, 0)
	if err != nil {
		return []string{relative + " invalid source"}
	}
	var rendered bytes.Buffer
	_ = format.Node(&rendered, token.NewFileSet(), file)
	text := rendered.String()
	for _, guard := range fieldWindowsGuards[relative] {
		if !strings.Contains(text, guard) {
			bad = append(bad, relative+" lacks Windows bearing guard")
		}
	}
	return bad
}

func TestFieldWindowsB1BearingGuardsAndMutations(t *testing.T) {
	for relative, guards := range fieldWindowsGuards {
		payload, err := os.ReadFile(filepath.Join(repositoryRoot(t), relative))
		if err != nil {
			t.Fatal("source missing")
		}
		source := strings.ReplaceAll(string(payload), "\r\n", "\n")
		if bad := fieldWindowsGuardViolations(relative, source); len(bad) != 0 {
			t.Fatal(bad)
		}
		for _, guard := range guards {
			t.Run(filepath.Base(relative)+"/"+guard, func(t *testing.T) {
				mutant := strings.ReplaceAll(source, guard, "/* removed bearing guard */ false")
				if len(fieldWindowsGuardViolations(relative, mutant)) == 0 {
					t.Fatal("bearing deletion escaped")
				}
			})
		}
	}
}

func TestFieldWindowsB1CapabilityMutations(t *testing.T) {
	for name, source := range map[string]string{
		"tag":           "//go:build fieldc1c\n\npackage netif\n",
		"raw_handle":    "//go:build windows && fieldc1c\n\npackage netif\ntype FieldInterface struct{Raw any}",
		"export_getter": "//go:build windows && fieldc1c\n\npackage netif\nfunc(f *FieldInterface)Raw()any{return f.device}",
		"setter":        "//go:build windows && fieldc1c\n\npackage netif\nfunc(f *FieldInterface)SetIP()error{return nil}",
		"fake_issuer":   "//go:build windows && fieldc1c\n\npackage netif\nfunc forge(){_ = fieldWindowsPermit{valid:yes}}",
		"dns":           "//go:build windows && fieldc1c\n\npackage netif\nfunc f(){x.SetDNS(nil)}",
		"flush":         "//go:build windows && fieldc1c\n\npackage netif\nfunc f(){x.FlushRoutes()}",
		"takeover":      "//go:build windows && fieldc1c\n\npackage netif\nfunc f(){x.OpenAdapter(\"other\")}",
		"child":         "//go:build windows && fieldc1c\n\npackage netif\nimport e \"os/exec\"\nfunc f(){e.Command(\"tool\")}",
		"proc":          "//go:build windows && fieldc1c\n\npackage netif\nfunc f(){dll.NewProc(\"SetDNS\")}",
		"eager":         "//go:build windows && fieldc1c\n\npackage netif\nfunc init(){}",
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeArchitectureMutation(t, root, "pkg/netif/field_tun_windows.go", source)
			bad, err := fieldC1cViolations(root)
			if err != nil || len(bad) == 0 {
				t.Fatal("capability mutation escaped")
			}
		})
	}
	for _, relative := range []string{"pkg/netif/bypass.go", "pkg/client/field_windows.go", "internal/v2/gatecorchestrator/field_entry_windows.go"} {
		t.Run(relative, func(t *testing.T) {
			root := t.TempDir()
			writeArchitectureMutation(t, root, relative, "//go:build fieldc1c\n\npackage bypass\nfunc f(){_ = newFieldWindowsInterface;_ = NewFieldInterface}")
			bad, err := fieldC1cViolations(root)
			if err != nil || len(bad) == 0 {
				t.Fatal("unapproved consumer escaped")
			}
		})
	}
}

func TestFieldWindowsB1OrdinaryBinaryHasNoCapability(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	output := filepath.Join(t.TempDir(), "wink.exe")
	build := exec.CommandContext(ctx, "go", "build", "-buildvcs=true", "-gcflags=all=-l", "-o", output, "./cmd/wink")
	build.Dir = repositoryRoot(t)
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "GOOS=") && !strings.HasPrefix(entry, "CGO_ENABLED=") {
			build.Env = append(build.Env, entry)
		}
	}
	build.Env = append(build.Env, "GOOS=windows", "CGO_ENABLED=0")
	started := time.Now()
	if data, err := build.CombinedOutput(); err != nil {
		fieldSymbolFailure(t, ctx, "windows_build", started, data)
	}
	nm := exec.CommandContext(ctx, "go", "tool", "nm", output)
	started = time.Now()
	data, err := nm.CombinedOutput()
	if err != nil {
		fieldSymbolFailure(t, ctx, "windows_nm", started, data)
	}
	for _, pattern := range []string{`winkyou/pkg/netif\.(?:NewFieldInterface|fieldIP|fieldNative|fieldSealDLL|fieldPermit)`, `winkyou/internal/v2/fieldc1c\..*WintunIdentity`} {
		if regexp.MustCompile(pattern).Match(data) {
			t.Fatal("ordinary Windows binary linked field capability")
		}
	}
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
