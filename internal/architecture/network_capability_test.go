package architecture

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "winkyou"

var thirdPartyCapabilityPrefixes = []string{
	"github.com/pion/",
	"github.com/quic-go/",
}

var directCapabilityCalls = map[string]map[string]struct{}{
	"net": names(
		"Dial",
		"DialIP",
		"DialTCP",
		"DialTimeout",
		"DialUDP",
		"FileConn",
		"FileListener",
		"FilePacketConn",
		"Listen",
		"ListenIP",
		"ListenMulticastUDP",
		"ListenPacket",
		"ListenTCP",
		"ListenUDP",
	),
	"syscall": names("Socket"),
	"golang.org/x/sys/unix": names(
		"Socket",
		"Socketpair",
	),
	"golang.org/x/sys/windows": names(
		"Socket",
		"WSASocket",
	),
}

// These methods cover values such as net.Dialer and net.ListenConfig when the
// receiver's static type is not available from syntax alone. Freezing the
// small number of existing same-named calls is safer than accepting an alias-
// based escape from the inventory.
var receiverCapabilityMethods = names(
	"Dial",
	"DialContext",
	"Listen",
	"ListenPacket",
	"LookupNetIP",
)

type finding struct {
	file       string
	function   string
	capability string
	pkg        string
}

type packageInfo struct {
	imports map[string]struct{}
}

type scanResult struct {
	findings []finding
	packages map[string]*packageInfo
}

type governedCapabilityApproval struct {
	file       string
	function   string
	capability string
	pkg        string
	owner      string
}

// These are the only raw capabilities approved inside governed v2 packages.
// probeio returns only Datagram and the disconnected N2c carrier retains its
// one stream internally. Any filename, function, capability, package, owner,
// or count drift must fail review rather than silently widening an exception.
var governedCapabilityApprovals = []governedCapabilityApproval{
	{
		file:       "internal/probeio/udp_factory.go",
		function:   "openGovernedUDP",
		capability: "reference:net.ListenUDP",
		pkg:        modulePath + "/internal/probeio",
		owner:      "governor",
	},
	{
		file:       "internal/v2/rendezvouscarrier/dialer.go",
		function:   "openGovernedRendezvous",
		capability: "call:method.DialContext",
		pkg:        modulePath + "/internal/v2/rendezvouscarrier",
		owner:      "governor",
	},
	{
		file:       "internal/v2/rendezvouscarrier/resolver.go",
		function:   "lookupGovernedRendezvousHost",
		capability: "call:method.LookupNetIP",
		pkg:        modulePath + "/internal/v2/rendezvouscarrier",
		owner:      "governor",
	},
	{
		file:       "internal/v2/rendezvousserver/listener.go",
		function:   "listenOneShot",
		capability: "reference:net.Listen",
		pkg:        modulePath + "/internal/v2/rendezvousserver",
		owner:      "one-shot-rendezvous",
	},
}

func TestProductionNetworkCapabilityInventory(t *testing.T) {
	root := repositoryRoot(t)
	result, err := scanRepository(root)
	if err != nil {
		t.Fatalf("scan production Go sources: %v", err)
	}

	actual := aggregateFindings(result.findings)
	inventoryPath := filepath.Join(root, "internal", "architecture", "testdata", "network_capabilities.txt")
	expected, err := readInventory(inventoryPath)
	if err != nil {
		t.Fatalf("read network capability inventory: %v", err)
	}
	if unexpected, stale := inventoryDifference(actual, expected); len(unexpected) > 0 || len(stale) > 0 {
		t.Fatalf(
			"production network capability inventory changed\n\nnew or changed entries:\n%s\n\nstale entries:\n%s\n\ncomplete current inventory:\n%s",
			formatLines(unexpected),
			formatLines(stale),
			formatLines(actual),
		)
	}

	if violations := governedCapabilityViolations(result); len(violations) > 0 {
		t.Fatalf("governed v2 package bypasses probeio:\n%s", formatLines(violations))
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve architecture test source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}

func scanRepository(root string) (scanResult, error) {
	result := scanResult{packages: make(map[string]*packageInfo)}
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if filename != root && strings.HasPrefix(entry.Name(), ".") {
				return filepath.SkipDir
			}
			switch entry.Name() {
			case "node_modules", "vendor":
				if filename != root {
					return filepath.SkipDir
				}
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
		directory := path.Dir(relative)
		if directory == "." {
			directory = ""
		}
		pkgPath := modulePath
		if directory != "" {
			pkgPath += "/" + directory
		}

		parsed, err := parser.ParseFile(fset, filename, nil, 0)
		if err != nil {
			return fmt.Errorf("parse %s: %w", relative, err)
		}
		imports, importedPaths, err := sourceImports(parsed)
		if err != nil {
			return fmt.Errorf("imports in %s: %w", relative, err)
		}
		info := result.packages[pkgPath]
		if info == nil {
			info = &packageInfo{imports: make(map[string]struct{})}
			result.packages[pkgPath] = info
		}
		for _, imported := range importedPaths {
			if strings.HasPrefix(imported, modulePath+"/") {
				info.imports[imported] = struct{}{}
			}
			if isThirdPartyCapability(imported) {
				result.findings = append(result.findings, finding{
					file:       relative,
					function:   "<imports>",
					capability: "import:" + imported,
					pkg:        pkgPath,
				})
			}
		}
		for _, imported := range dotCapabilityImports(parsed) {
			if isDirectCapabilityPackage(imported) {
				result.findings = append(result.findings, finding{
					file:       relative,
					function:   "<imports>",
					capability: "dot-import:" + imported,
					pkg:        pkgPath,
				})
			}
		}

		visitor := &capabilityVisitor{
			imports:  imports,
			file:     relative,
			function: "<init>",
			pkg:      pkgPath,
			findings: &result.findings,
		}
		ast.Walk(visitor, parsed)
		return nil
	})
	if err != nil {
		return scanResult{}, err
	}
	return result, nil
}

func sourceImports(file *ast.File) (map[string]string, []string, error) {
	aliases := make(map[string]string)
	paths := make([]string, 0, len(file.Imports))
	for _, spec := range file.Imports {
		imported, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return nil, nil, err
		}
		paths = append(paths, imported)
		alias := path.Base(imported)
		if spec.Name != nil {
			alias = spec.Name.Name
		}
		aliases[alias] = imported
	}
	return aliases, paths, nil
}

type capabilityVisitor struct {
	imports  map[string]string
	file     string
	function string
	pkg      string
	findings *[]finding
}

func (visitor *capabilityVisitor) Visit(node ast.Node) ast.Visitor {
	switch current := node.(type) {
	case *ast.FuncDecl:
		child := *visitor
		child.function = functionName(current)
		return &child
	case *ast.FuncLit:
		child := *visitor
		child.function = visitor.function + ".func"
		return &child
	case *ast.CallExpr:
		capability := callCapability(current, visitor.imports)
		if capability != "" {
			*visitor.findings = append(*visitor.findings, finding{
				file:       visitor.file,
				function:   visitor.function,
				capability: capability,
				pkg:        visitor.pkg,
			})
		}
	case *ast.SelectorExpr:
		capability := selectorCapability(current, visitor.imports)
		if capability != "" {
			*visitor.findings = append(*visitor.findings, finding{
				file:       visitor.file,
				function:   visitor.function,
				capability: capability,
				pkg:        visitor.pkg,
			})
		}
	}
	return visitor
}

func functionName(function *ast.FuncDecl) string {
	if function.Recv == nil || len(function.Recv.List) == 0 {
		return function.Name.Name
	}
	return types.ExprString(function.Recv.List[0].Type) + "." + function.Name.Name
}

func callCapability(call *ast.CallExpr, imports map[string]string) string {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	if selectorCapability(selector, imports) != "" {
		// Direct function and statically known receiver references are
		// recorded when the selector itself is visited.
		return ""
	}
	if _, found := receiverCapabilityMethods[selector.Sel.Name]; found {
		return "call:method." + selector.Sel.Name
	}
	return ""
}

func selectorCapability(selector *ast.SelectorExpr, imports map[string]string) string {
	if identifier, ok := selector.X.(*ast.Ident); ok {
		imported := imports[identifier.Name]
		if functions := directCapabilityCalls[imported]; functions != nil {
			if _, found := functions[selector.Sel.Name]; found {
				return "reference:" + imported + "." + selector.Sel.Name
			}
		}
	}
	if isKnownNetworkReceiver(selector.X, imports) {
		if _, found := receiverCapabilityMethods[selector.Sel.Name]; found {
			return "reference:method." + selector.Sel.Name
		}
	}
	return ""
}

func isKnownNetworkReceiver(expression ast.Expr, imports map[string]string) bool {
	switch current := expression.(type) {
	case *ast.ParenExpr:
		return isKnownNetworkReceiver(current.X, imports)
	case *ast.StarExpr:
		return isKnownNetworkReceiver(current.X, imports)
	case *ast.UnaryExpr:
		return isKnownNetworkReceiver(current.X, imports)
	case *ast.CompositeLit:
		return isKnownNetworkReceiver(current.Type, imports)
	case *ast.SelectorExpr:
		identifier, ok := current.X.(*ast.Ident)
		if !ok || imports[identifier.Name] != "net" {
			return false
		}
		switch current.Sel.Name {
		case "Dialer", "ListenConfig":
			return true
		default:
			return false
		}
	}
	return false
}

func dotCapabilityImports(file *ast.File) []string {
	var result []string
	for _, spec := range file.Imports {
		if spec.Name == nil || spec.Name.Name != "." {
			continue
		}
		imported, err := strconv.Unquote(spec.Path.Value)
		if err == nil {
			result = append(result, imported)
		}
	}
	return result
}

func aggregateFindings(findings []finding) []string {
	counts := make(map[string]int)
	for _, current := range findings {
		key := strings.Join([]string{current.file, current.function, current.capability}, " | ")
		counts[key]++
	}
	result := make([]string, 0, len(counts))
	for key, count := range counts {
		result = append(result, fmt.Sprintf("%s | count=%d", key, count))
	}
	sort.Strings(result)
	return result
}

func readInventory(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var result []string
	scanner := bufio.NewScanner(file)
	line := 0
	for scanner.Scan() {
		line++
		value := strings.TrimSpace(scanner.Text())
		if value == "" || strings.HasPrefix(value, "#") {
			continue
		}
		if len(result) > 0 && value <= result[len(result)-1] {
			return nil, fmt.Errorf("line %d is duplicate or not sorted", line)
		}
		result = append(result, value)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func inventoryDifference(actual, expected []string) (unexpected, stale []string) {
	actualSet := make(map[string]struct{}, len(actual))
	expectedSet := make(map[string]struct{}, len(expected))
	for _, item := range actual {
		actualSet[item] = struct{}{}
	}
	for _, item := range expected {
		expectedSet[item] = struct{}{}
	}
	for _, item := range actual {
		if _, found := expectedSet[item]; !found {
			unexpected = append(unexpected, item)
		}
	}
	for _, item := range expected {
		if _, found := actualSet[item]; !found {
			stale = append(stale, item)
		}
	}
	return unexpected, stale
}

func governedCapabilityViolations(result scanResult) []string {
	capabilityPackages := make(map[string]struct{})
	var violations []string
	for _, current := range result.findings {
		if approvedGovernedCapability(current) {
			continue
		}
		capabilityPackages[current.pkg] = struct{}{}
		if isGovernedPackage(current.pkg) {
			violations = append(violations, fmt.Sprintf(
				"%s directly owns %s in %s (%s)",
				current.pkg,
				current.capability,
				current.file,
				current.function,
			))
		}
	}
	for pkg := range result.packages {
		if !isGovernedPackage(pkg) {
			continue
		}
		if dependencyPath := capabilityDependencyPath(pkg, result.packages, capabilityPackages); len(dependencyPath) > 0 {
			violations = append(violations, strings.Join(dependencyPath, " -> "))
		}
	}
	sort.Strings(violations)
	return violations
}

func approvedGovernedCapability(current finding) bool {
	for _, approval := range governedCapabilityApprovals {
		if (approval.owner == "governor" || approval.owner == "one-shot-rendezvous") &&
			current.file == approval.file &&
			current.function == approval.function &&
			current.capability == approval.capability &&
			current.pkg == approval.pkg {
			return true
		}
	}
	return false
}

func capabilityDependencyPath(start string, packages map[string]*packageInfo, capabilityPackages map[string]struct{}) []string {
	type pathItem struct {
		pkg  string
		path []string
	}
	queue := []pathItem{{pkg: start, path: []string{start}}}
	visited := map[string]struct{}{start: {}}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		info := packages[current.pkg]
		if info == nil {
			continue
		}
		imports := make([]string, 0, len(info.imports))
		for imported := range info.imports {
			imports = append(imports, imported)
		}
		sort.Strings(imports)
		for _, imported := range imports {
			if _, seen := visited[imported]; seen {
				continue
			}
			nextPath := append(append([]string(nil), current.path...), imported)
			if _, capable := capabilityPackages[imported]; capable && !approvedCapabilityDependencyEndpoint(start, imported) {
				return append(nextPath, "[raw network capability]")
			}
			visited[imported] = struct{}{}
			queue = append(queue, pathItem{pkg: imported, path: nextPath})
		}
	}
	return nil
}

// Gate C1b passes only the exact in-process MemoryTestInterface to the sealed
// NewMemoryWireGuard constructor. pkg/netif also contains platform TUN files,
// so the package-level graph needs this one endpoint exception; the Gate C1b
// shape gate separately rejects every OS-interface constructor or new import.
func approvedCapabilityDependencyEndpoint(start, endpoint string) bool {
	return start == modulePath+"/internal/v2/gatecorchestrator" && endpoint == modulePath+"/pkg/netif"
}

func isGovernedPackage(pkg string) bool {
	return pkg == modulePath+"/internal/probeio" ||
		strings.HasPrefix(pkg, modulePath+"/internal/probeio/") ||
		pkg == modulePath+"/internal/stunobserve" ||
		strings.HasPrefix(pkg, modulePath+"/internal/stunobserve/") ||
		pkg == modulePath+"/internal/natsim" ||
		strings.HasPrefix(pkg, modulePath+"/internal/natsim/") ||
		pkg == modulePath+"/internal/governor" ||
		strings.HasPrefix(pkg, modulePath+"/internal/governor/") ||
		pkg == modulePath+"/internal/diagnose" ||
		strings.HasPrefix(pkg, modulePath+"/internal/diagnose/") ||
		pkg == modulePath+"/internal/v2" ||
		strings.HasPrefix(pkg, modulePath+"/internal/v2/") ||
		pkg == modulePath+"/pkg/v2" ||
		strings.HasPrefix(pkg, modulePath+"/pkg/v2/")
}

func isThirdPartyCapability(imported string) bool {
	for _, prefix := range thirdPartyCapabilityPrefixes {
		if strings.HasPrefix(imported, prefix) {
			return true
		}
	}
	return false
}

func isDirectCapabilityPackage(imported string) bool {
	if directCapabilityCalls[imported] != nil || isThirdPartyCapability(imported) {
		return true
	}
	return false
}

func formatLines(lines []string) string {
	if len(lines) == 0 {
		return "  (none)"
	}
	return "  " + strings.Join(lines, "\n  ")
}

func names(values ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}
