package architecture

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func c1cProofFunction(source, name string) *ast.FuncDecl {
	file, err := parser.ParseFile(token.NewFileSet(), "proof.go", source, 0)
	if err != nil {
		return nil
	}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == name {
			return fn
		}
	}
	return nil
}

func c1cProofCallName(call *ast.CallExpr) string {
	switch f := call.Fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		if owner, ok := f.X.(*ast.Ident); ok {
			return owner.Name + "." + f.Sel.Name
		}
	}
	return ""
}

func c1cProofCalls(fn *ast.FuncDecl) []string {
	if fn == nil {
		return nil
	}
	var calls []string
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			calls = append(calls, c1cProofCallName(call))
		}
		return true
	})
	return calls
}

func c1cProofRootValid(source, name string, runs int) bool {
	fn := c1cProofFunction(source, name)
	if fn == nil {
		return false
	}
	valid, guards, observed := true, 0, 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch c1cProofCallName(call) {
		case "requireC1cProofEnvironment":
			guards++
		case "requireGateB3Environment", "requireGateB3HostConntrackGuard":
			valid = false
		case "t.Run":
			observed++
			if len(call.Args) != 2 {
				valid = false
				break
			}
			wrapper, ok := call.Args[1].(*ast.CallExpr)
			if !ok || c1cProofCallName(wrapper) != "guard" || len(wrapper.Args) != 1 {
				valid = false
			}
		}
		return true
	})
	return valid && guards == 1 && observed == runs
}

func c1cProofCollectorValid(source string) bool {
	if !strings.HasPrefix(source, "//go:build linux && natlab && c1bproof && fieldc1c\n") {
		return false
	}
	entry := c1cProofCalls(c1cProofFunction(source, "requireC1cProofEnvironment"))
	var order []string
	for _, call := range entry {
		if strings.HasPrefix(call, "require") {
			order = append(order, call)
		}
	}
	if !reflect.DeepEqual(order, []string{"requireC1cMaintainerHostProof", "requireGateB3Environment", "requireGateB3Environment", "requireGateB3HostConntrackGuard"}) {
		return false
	}
	collector := c1cProofFunction(source, "requireC1cMaintainerHostProof")
	if collector == nil {
		return false
	}
	counts := map[string]int{}
	for _, call := range c1cProofCalls(collector) {
		counts[call]++
		if strings.Contains(call, "Write") || strings.Contains(call, "Mount") || strings.HasPrefix(call, "exec.") {
			return false
		}
	}
	if counts["readGateB3ConntrackMax"] != 2 || counts["t.Cleanup"] != 2 || counts["c1cHostProofMode"] != 1 {
		return false
	}
	unchanged := false
	ast.Inspect(collector.Body, func(n ast.Node) bool {
		if b, ok := n.(*ast.BinaryExpr); ok && b.Op == token.NEQ {
			left, lok := b.X.(*ast.Ident)
			right, rok := b.Y.(*ast.Ident)
			if lok && rok && left.Name == "current" && right.Name == "original" {
				unchanged = true
			}
		}
		return true
	})
	return unchanged
}

func TestC1cMaintainerProofBoundary(t *testing.T) {
	root := repositoryRoot(t)
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(root, "test/natlab", name))
		if err != nil {
			t.Fatal("proof source unavailable")
		}
		return strings.ReplaceAll(string(b), "\r\n", "\n")
	}
	collector := read("c1c_maintainer_proof_linux_test.go")
	if !c1cProofCollectorValid(collector) {
		t.Fatal("maintainer proof preflight or ceiling contract changed")
	}
	for _, tc := range []struct {
		file, function string
		runs           int
	}{
		{"field_c1c_netns_linux_test.go", "TestLinuxFieldC1cExactBuildProof", 1},
		{"c1c_router_netns_linux_test.go", "TestLinuxC1cRouterFullInstances", 4},
	} {
		source := read(tc.file)
		if !c1cProofRootValid(source, tc.function, tc.runs) {
			t.Fatal("proof root lost subtest ceiling witness")
		}
		if c1cProofRootValid(strings.Replace(source, "guard := requireC1cProofEnvironment(t)", "requireGateB3Environment(t)", 1), tc.function, tc.runs) {
			t.Fatal("unguarded root mutation accepted")
		}
		if c1cProofRootValid(strings.Replace(source, "guard(", "unguarded(", 1), tc.function, tc.runs) {
			t.Fatal("unwrapped subtest mutation accepted")
		}
	}
	for _, mutation := range [][2]string{
		{"guard := requireC1cMaintainerHostProof(t)", "requireGateB3Environment(t); guard := requireC1cMaintainerHostProof(t)"},
		{"t.Cleanup(func() { check(t) })", "check(t)"},
		{"current != original", "current == original"},
		{"original, err := readGateB3ConntrackMax(\"\")", "original, err := readGateB3ConntrackMax(\"\"); os.WriteFile(\"synthetic\", nil, 0600)"},
	} {
		if c1cProofCollectorValid(strings.Replace(collector, mutation[0], mutation[1], 1)) {
			t.Fatal("unsafe proof collector mutation accepted")
		}
	}
	files, err := filepath.Glob(filepath.Join(root, "test/natlab", "*.go"))
	if err != nil {
		t.Fatal("proof source enumeration failed")
	}
	for _, name := range files {
		base := filepath.Base(name)
		if base == "c1c_maintainer_proof_linux_test.go" || base == "c1c_maintainer_proof_test.go" || base == "field_c1c_netns_linux_test.go" || base == "c1c_router_netns_linux_test.go" {
			continue
		}
		source := read(base)
		if strings.Contains(source, "requireC1cProofEnvironment") || strings.Contains(source, "requireC1cMaintainerHostProof") || strings.Contains(source, "WINKYOU_C1C_MAINTAINER_HOST_PROOF") {
			t.Fatal("maintainer mode escaped its two proof roots")
		}
	}
}

var c1cSnapshotCommand = regexp.MustCompile(`(?m)^    \("([a-z_]+)", (\[.*\]), (?:True|False)\),$`)

func c1cSnapshotValid(source string) bool {
	want := map[string][]string{
		"namespaces":      {"/usr/sbin/ip", "netns", "list"},
		"links":           {"/usr/sbin/ip", "-j", "link", "show"},
		"addresses":       {"/usr/sbin/ip", "-j", "addr", "show"},
		"routes":          {"/usr/sbin/ip", "-j", "route", "show"},
		"rules":           {"/usr/sbin/ip", "-j", "rule", "show"},
		"nft":             {"/usr/sbin/nft", "-j", "list", "ruleset"},
		"conntrack_max":   {"/usr/sbin/sysctl", "-n", "net.netfilter.nf_conntrack_max"},
		"conntrack_count": {"/usr/sbin/sysctl", "-n", "net.netfilter.nf_conntrack_count"},
		"ip_forward":      {"/usr/sbin/sysctl", "-n", "net.ipv4.ip_forward"},
		"modules":         {"/usr/sbin/lsmod"},
		"registry":        {"/usr/bin/find", "/var/run/netns", "-mindepth", "1", "-maxdepth", "1", "-printf", "%f\\n"},
		"ss_udp":          {"/usr/bin/ss", "-H", "-nup"},
		"ss_tcp":          {"/usr/bin/ss", "-H", "-ntp"},
	}
	for _, m := range c1cSnapshotCommand.FindAllStringSubmatch(source, -1) {
		var args []string
		if json.Unmarshal([]byte(m[2]), &args) != nil || !reflect.DeepEqual(want[m[1]], args) {
			return false
		}
		delete(want, m[1])
	}
	if len(want) != 0 {
		return false
	}
	for _, literal := range []string{
		`if [ "$#" -ne 0 ]; then`, "exec /usr/bin/python3 -I -B - <<'PY'",
		`NSENTER = "/usr/bin/nsenter"`, `PREFIX = [NSENTER, "--net=/proc/1/ns/net", "--mount=/proc/1/ns/mnt", "--"]`,
		`PREFIX + command, stdin=subprocess.DEVNULL`, `stderr=subprocess.DEVNULL, check=True, timeout=10`,
		`bucket = "volatile" if name in ("ss_udp", "ss_tcp") else "nonvolatile"`,
		`info.st_uid != 0 or info.st_mode & 0o022`, `"class": "snapshot_read_failed"`,
	} {
		if !strings.Contains(source, literal) {
			return false
		}
	}
	for _, forbidden := range []string{"shell=True", "os.system", "os.environ", "sys.argv", "--evidence", "subprocess.Popen", "open(", "eval(", "exec("} {
		if strings.Contains(source, forbidden) {
			return false
		}
	}
	return strings.Count(source, "subprocess.run(") == 1
}

func TestC1cReviewSnapshotContractAndPrivacy(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repositoryRoot(t), "scripts/c1c-review-snapshot.sh"))
	if err != nil {
		t.Fatal("review snapshot unavailable")
	}
	source := strings.ReplaceAll(string(b), "\r\n", "\n")
	if !c1cSnapshotValid(source) {
		t.Fatal("snapshot read-only command contract changed")
	}
	for _, line := range strings.Split(source, "\n") {
		if len(sourcePrivacyLine(line)) != 0 {
			t.Fatal("snapshot source privacy rejected; values withheld")
		}
		for _, pattern := range []*regexp.Regexp{docIPv4, docIPv6} {
			for _, candidate := range pattern.FindAllString(line, -1) {
				if _, err := netip.ParseAddr(strings.TrimRight(candidate, ".")); err == nil {
					t.Fatal("snapshot must not contain any address literal; value withheld")
				}
			}
		}
	}
	for _, mutation := range [][2]string{
		{`"/usr/sbin/sysctl", "-n"`, `"/usr/sbin/sysctl", "-w"`},
		{`"--net=/proc/1/ns/net", `, ""},
		{`"--mount=/proc/1/ns/mnt", `, ""},
		{`if [ "$#" -ne 0 ]; then`, `if false; then`},
		{`("ss_udp", "ss_tcp") else "nonvolatile"`, `("ss_udp", "ss_tcp", "conntrack_count") else "nonvolatile"`},
		{`check=True, timeout=10`, `check=False, timeout=10`},
	} {
		if c1cSnapshotValid(strings.Replace(source, mutation[0], mutation[1], 1)) {
			t.Fatal("unsafe snapshot mutation accepted")
		}
	}
}

func TestC1cReviewSnapshotCeilingExceptionIsReadOnly(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repositoryRoot(t), "scripts/c1c-review-snapshot.sh"))
	if err != nil {
		t.Fatal("snapshot unavailable")
	}
	source := strings.ReplaceAll(string(b), "\r\n", "\n")
	for _, tc := range []struct {
		name, path, source string
		allowed            bool
	}{
		{"exact_read_only", "scripts/c1c-review-snapshot.sh", source, true},
		{"write", "scripts/c1c-review-snapshot.sh", strings.Replace(source, `"/usr/sbin/sysctl", "-n"`, `"/usr/sbin/sysctl", "-w"`, 1), false},
		{"renamed", "scripts/renamed-snapshot.sh", source, false},
		{"lost_init", "scripts/c1c-review-snapshot.sh", strings.Replace(source, `"--net=/proc/1/ns/net", `, "", 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeArchitectureMutation(t, root, tc.path, tc.source)
			violations, err := gateB3ConntrackAuthorityViolations(root)
			if err != nil || (len(violations) == 0) != tc.allowed {
				t.Fatal("snapshot ceiling exception escaped read-only boundary")
			}
		})
	}
}
