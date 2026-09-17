package architecture

import (
	"fmt"
	"io/fs"
	"net/netip"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
	"unicode"
	"unicode/utf8"
)

type docPrivacyFinding struct {
	File, Class string
	Line        int
}

var (
	docIPv4              = regexp.MustCompile(`[0-9]{1,3}(?:\.[0-9]{1,3}){3}`)
	docPartialV4         = regexp.MustCompile(`(?i)[0-9]{1,3}(?:\.(?:[0-9]{1,3}|x|\*)){3}`)
	docIPv6              = regexp.MustCompile(`[0-9A-Fa-f:.]+(?:%[A-Za-z0-9_.-]+)?`)
	docDrive             = regexp.MustCompile(`(?i)(?:^|[^\pL\pN])([a-z]:[\\/])`)
	docHome              = regexp.MustCompile(`(?i)\\+Users\\+|(?:^|[^\pL\pN_])/(?:home|Users)/`)
	docKey               = regexp.MustCompile(`ssh-(?:ed25519|rsa)|SHA256:[A-Za-z0-9+/=]{20,}`)
	docMAC               = regexp.MustCompile(`(?i)\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b`)
	docInlineCode        = regexp.MustCompile("`([^`]+)`")
	docURLs              = regexp.MustCompile(`\]\((https?://[^\s<>\)]+)\)`)
	docLanguageOperators = []*regexp.Regexp{
		regexp.MustCompile(`\$\{[A-Za-z_][A-Za-z0-9_]*\[@\]\}`),
		regexp.MustCompile(`\$@(?:$|["'\s])`),
		regexp.MustCompile(`\$\{?[A-Za-z_][A-Za-z0-9_]*\}?@\$\{?[A-Za-z_][A-Za-z0-9_]*\}?`),
		regexp.MustCompile(`\{[^{}@]+\}@\{[^{}@]+\}`),
		regexp.MustCompile(`0x[0-9A-Fa-f]+@[0-9]+(?:>>[0-9]+)?[=&]`),
	}
	docSplat     = regexp.MustCompile(`^@[A-Za-z_][A-Za-z0-9_]*(?:\s|$)`)
	docSplatCall = regexp.MustCompile(`(?:^|[;|])\s*(?:&\s+\$[A-Za-z_][A-Za-z0-9_]*|[A-Za-z]+-[A-Za-z]+)\s+$`)
	docAtTokens  = regexp.MustCompile("(?:" +
		"main@[a-f0-9]{7,40}|github\\.com/flynn/noise" + "@v1\\.1\\.0|" +
		"actions/(?:checkout|setup-go|upload-artifact)@v[0-9]+|" +
		"wink-stund@(?:3478|3479)?\\.service|" +
		"attempt_expired@ready|hard_nat_candidate_exhausted@candidates|" +
		"hard_nat_evidence_insufficient@fresh_evidence|oob_stream_closed@plan_committed|" +
		"punch_timeout@punch|verification_failed@verify" +
		")")
)

func docWordBoundary(line string, start, end int) bool {
	if start > 0 {
		r, _ := utf8.DecodeLastRuneInString(line[:start])
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '.' {
			return false
		}
	}
	if end < len(line) {
		r, size := utf8.DecodeRuneInString(line[end:])
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			return false
		}
		if r == '.' && end+size < len(line) {
			next, _ := utf8.DecodeRuneInString(line[end+size:])
			if unicode.IsLetter(next) || unicode.IsDigit(next) || next == '_' || next == '.' {
				return false
			}
		}
	}
	return true
}

func docAllowedAddress(addr netip.Addr, suffix string) bool {
	if addr.Zone() != "" {
		return false
	}
	addr = addr.Unmap()
	// Maintainer-classified public resolver/example (IPV4_12), retained unchanged.
	if addr.String() == "1.2.3.4" {
		return true
	}
	if addr.IsLoopback() || addr.IsUnspecified() {
		return true
	}
	for _, prefix := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"} {
		if netip.MustParsePrefix(prefix).Contains(addr) {
			return true
		}
	}
	if addr.String() == "10.0.0.1" || addr.String() == "10.0.0.2" {
		return true
	}
	// Exact prefix tokens only: this does NOT authorize addresses inside them.
	// The additional product default is maintainer-approved as one exact CIDR
	// token; no address inside that network is authorized by this exception.
	for host, bits := range map[string]string{"10.0.0.0": "/24", "100.64.0.0": "/10", "198.18.0.0": "/15", "128." + "0.0.0": "/1", "10.42.0.0": "/24"} {
		if addr.String() == host && strings.HasPrefix(suffix, bits) {
			if len(suffix) == len(bits) {
				return true
			}
			next, _ := utf8.DecodeRuneInString(suffix[len(bits):])
			return unicode.IsSpace(next) || strings.ContainsRune("`\"'),;]}>|。；、，", next)
		}
	}
	return false
}

func docAllowedAt(line string, offset int) bool {
	// Language operators are not identities. Match only the operator span;
	// a destination elsewhere on the same line must still be rejected.
	for _, rule := range docLanguageOperators {
		for _, span := range rule.FindAllStringIndex(line, -1) {
			if span[0] <= offset && offset < span[1] {
				return true
			}
		}
	}
	if offset > 0 && line[offset-1] == ']' && offset+1 < len(line) && strings.ContainsRune("({", rune(line[offset+1])) {
		return true
	}
	if strings.TrimSpace(line) == "@dataclass" {
		return true
	}
	// PowerShell splatting is a standalone variable, never a dotted destination.
	if docSplatCall.MatchString(line[:offset]) && docSplat.MatchString(line[offset:]) {
		return true
	}
	for _, span := range docAtTokens.FindAllStringIndex(line, -1) {
		if span[0] <= offset && offset < span[1] && docWordBoundary(line, span[0], span[1]) {
			return true
		}
	}
	// A public reference path/version is not URL user-info. Only these existing
	// reference hosts have an at-sign; arbitrary links do not bypass the gate.
	for _, span := range docURLs.FindAllStringSubmatchIndex(line, -1) {
		if span[2] <= offset && offset < span[3] {
			u, err := url.Parse(line[span[2]:span[3]])
			if err == nil && u.User == nil && !strings.Contains(u.RawQuery+u.Fragment, "@") &&
				(u.Host == "pkg.go.dev" || u.Host == "medium.com") {
				return true
			}
		}
	}
	if offset > 0 && offset+1 < len(line) && line[offset-1] == '`' && line[offset+1] == '`' {
		return true // the standalone u32 operator, not an identity token
	}
	if offset > 0 && strings.ContainsRune("'\"", rune(line[offset-1])) && strings.TrimSpace(line[:offset-1]) == "" &&
		(strings.TrimSpace(line[offset+1:]) == "" || strings.HasPrefix(strings.TrimSpace(line[offset+1:]), "|")) {
		return true // closing PowerShell here-string delimiter
	}
	if offset+1 < len(line) && strings.ContainsRune("({'\"", rune(line[offset+1])) &&
		(offset == 0 || strings.ContainsRune(" \t=(", rune(line[offset-1]))) {
		if line[offset+1] == '\'' || line[offset+1] == '"' {
			return strings.TrimSpace(line[offset+2:]) == ""
		}
		return true
	}
	if strings.Contains(line, "\"@-\"") && offset > 0 && line[offset-1] == '"' && offset+2 < len(line) && line[offset+1:offset+3] == "-\"" {
		return true // curl stdin marker, not an identity
	}
	return false
}

func docPrivacyLine(line string) []string {
	classes := make(map[string]bool)
	for _, span := range docPartialV4.FindAllStringIndex(line, -1) {
		token := line[span[0]:span[1]]
		if !strings.ContainsAny(token, "xX*") || !docWordBoundary(line, span[0], span[1]) {
			continue
		}
		addr, err := netip.ParseAddr(strings.NewReplacer("x", "0", "X", "0", "*", "0").Replace(token))
		if err != nil || !docAllowedAddress(addr, "") {
			classes["ipv4_not_documentation_example"] = true
		}
	}
	for _, span := range docIPv4.FindAllStringIndex(line, -1) {
		if !docWordBoundary(line, span[0], span[1]) {
			continue
		}
		addr, err := netip.ParseAddr(line[span[0]:span[1]])
		if err != nil || !docAllowedAddress(addr, line[span[1]:]) {
			classes["ipv4_not_documentation_example"] = true
		}
	}
	for _, span := range docIPv6.FindAllStringIndex(line, -1) {
		token := line[span[0]:span[1]]
		if strings.Count(token, ":") < 2 || !docWordBoundary(line, span[0], span[1]) {
			continue
		}
		addr, err := netip.ParseAddr(strings.TrimRight(token, "."))
		if err == nil && addr.Is6() && !docAllowedAddress(addr, line[span[1]:]) {
			classes["ipv6_not_documentation_example"] = true
		}
	}
	for i := range line {
		if line[i] == '@' && !docAllowedAt(line, i) {
			classes["identity_at_token"] = true
		}
	}
	for name, rule := range map[string]*regexp.Regexp{"absolute_drive_path": docDrive, "personal_directory": docHome, "ssh_key_or_fingerprint": docKey} {
		if rule.MatchString(line) {
			classes[name] = true
		}
	}
	for _, span := range docMAC.FindAllStringIndex(line, -1) {
		// Do not reinterpret six hextets inside a valid IPv6 literal as a MAC.
		insideIPv6 := false
		for _, addrSpan := range docIPv6.FindAllStringIndex(line, -1) {
			if addrSpan[0] <= span[0] && span[1] <= addrSpan[1] {
				addr, err := netip.ParseAddr(strings.TrimRight(line[addrSpan[0]:addrSpan[1]], "."))
				insideIPv6 = err == nil && addr.Is6()
				if insideIPv6 {
					break
				}
			}
		}
		if !insideIPv6 {
			classes["hardware_address"] = true
		}
	}
	commands := []string{strings.TrimSpace(line)}
	for _, match := range docInlineCode.FindAllStringSubmatch(line, -1) {
		commands = append(commands, match[1])
	}
	for _, command := range commands {
		if docLiteralSSHHost(command) {
			classes["literal_ssh_host"] = true
		}
	}
	// Fixed order makes diagnostics deterministic and contains no matched value.
	var out []string
	for _, name := range []string{"ipv4_not_documentation_example", "ipv6_not_documentation_example", "identity_at_token", "absolute_drive_path", "personal_directory", "ssh_key_or_fingerprint", "hardware_address", "literal_ssh_host"} {
		if classes[name] {
			out = append(out, name)
		}
	}
	return out
}

func docSafeDestination(token string) bool {
	token = strings.Trim(token, "\"'")
	if token == "none" || token == "localhost" || strings.HasPrefix(token, "$") ||
		(strings.HasPrefix(token, "<") && strings.HasSuffix(token, ">")) {
		return true
	}
	addr, err := netip.ParseAddr(token)
	return err == nil && docAllowedAddress(addr, "")
}

func docLiteralSSHHost(command string) bool {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return false
	}
	if strings.EqualFold(fields[0], "HostName") || strings.EqualFold(fields[0], "ProxyJump") {
		if len(fields) > 2 && fields[1] == "=" && docSafeDestination(fields[2]) {
			return false
		}
		return len(fields) > 1 && !docSafeDestination(fields[1])
	}
	if strings.HasPrefix(strings.ToLower(fields[0]), "proxyjump=") {
		return !docSafeDestination(fields[0][len("ProxyJump="):])
	}
	if fields[0] != "ssh" {
		return false // prose mentioning SSH is not a shell command
	}
	for i := 1; i < len(fields); i++ {
		arg := fields[i]
		if strings.HasPrefix(arg, "-o") {
			option := strings.TrimPrefix(arg, "-o")
			if option == "" && i+1 < len(fields) {
				i++
				option = fields[i]
			}
			option = strings.Trim(option, "\"'")
			for _, key := range []string{"proxyjump=", "hostname=", "user="} {
				if strings.HasPrefix(strings.ToLower(option), key) && !docSafeDestination(option[len(key):]) {
					return true
				}
			}
			continue
		}
		if strings.HasPrefix(arg, "-l") || strings.HasPrefix(arg, "-J") {
			destination := arg[2:]
			if destination == "" && i+1 < len(fields) {
				i++
				destination = fields[i]
			}
			if !docSafeDestination(destination) {
				return true
			}
			continue
		}
		if (arg == "-p" || arg == "-i" || arg == "-F") && i+1 < len(fields) {
			i++
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		if arg == "\\" || arg == "`" {
			return false // continuation; no destination token on this line
		}
		return !docSafeDestination(arg)
	}
	return false
}

func scanPublicDocs(tree fs.FS) ([]docPrivacyFinding, int, error) {
	return scanPrivacyFiles(tree, []string{"docs", "deploy", "scripts", ".github"}, func(name string) bool {
		return !strings.Contains(name, "/") && strings.HasSuffix(name, ".md")
	}, docPrivacyLine)
}

// Roots are exhaustive, including hidden and future files. No historical-file
// exemptions; findings never contain the matched text.
func scanPrivacyFiles(tree fs.FS, roots []string, rootFile func(string) bool, check func(string) []string) ([]docPrivacyFinding, int, error) {
	var findings []docPrivacyFinding
	files := 0
	err := fs.WalkDir(tree, ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("documentation walk failed")
		}
		if name == "." {
			return nil
		}
		selected := rootFile(name)
		for _, root := range roots {
			selected = selected || name == root || strings.HasPrefix(name, root+"/")
		}
		if !selected {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("documentation symlink rejected")
		}
		if entry.IsDir() {
			return nil
		}
		data, err := fs.ReadFile(tree, name)
		if err != nil || !utf8.Valid(data) {
			return fmt.Errorf("documentation read or encoding failed")
		}
		files++
		for i, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
			for _, class := range check(line) {
				findings = append(findings, docPrivacyFinding{File: name, Line: i + 1, Class: class})
			}
		}
		return nil
	})
	return findings, files, err
}

func TestPublicDocumentationPrivacy(t *testing.T) {
	findings, files, err := scanPublicDocs(os.DirFS(repositoryRoot(t)))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		t.Errorf("%s:%d: %s", f.File, f.Line, f.Class)
	}
	t.Logf("DOC_PRIVACY files=%d findings=%d values_disclosed=0", files, len(findings))
}

func TestPublicDocumentationPrivacySyntax(t *testing.T) {
	good := []string{
		"1.2.3.4", // explicitly retained synthetic example, IPV4_12
		"192.0.2.1 198.51.100.20 203.0.113.3 ::1 [2001:db8::1] 127.0.0.2 0.0.0.0 ::",
		"10.0.0.1 10.0.0.2 10.0.0.0/24 100.64.0.0/10 198.18.0.0/15 128." + "0.0.0/1",
		"$args = @(1, 2)", "$body = @{ key = 1 }", "$text = @'", "'@", "$text = @\"", "\"@",
		"the `@` u32 operator", "public/home/office network", "context::type",
		"wink-stund@.service wink-stund@3478.service wink-stund@3479.service",
		"`main@1234567`", "`github.com/flynn/noise" + "@v1.1.0`", "uses: actions/checkout@v4",
		"`hard_nat_candidate_exhausted@candidates`", "`attempt_expired@ready`",
		"[API](https://pkg.go.dev/github.com/flynn/noise" + "@v1.1.0)",
		"[article](https://medium.com/@%3CAUTHOR%3E/topic)",
		"~/.winkyou-field/c1c.json", "ssh <SSH_DESTINATION>", "ProxyJump=none", "ssh localhost",
		"SSH assembly is isolated", "a literal SSH endpoint authority", "ssh -p <PORT> <SSH_DESTINATION>",
		"ssh -o ProxyJump=none -i <KEY_FILE> <SSH_DESTINATION>",
		"198.51.100.x 203.0.113.* 192.0.2.x",
		"2001:db8:00:11:22:33:44:55", "ssh -l<USER> -J<JUMP_HOST> <SSH_DESTINATION>",
		"ssh -oProxyJump=none -oUser=<USER> <SSH_DESTINATION>",
		"Gateway 192.0.2.1. End.", "uses actions/checkout@v4.",
	}
	for i, line := range good {
		t.Run(fmt.Sprintf("allowed-%02d", i), func(t *testing.T) {
			if len(docPrivacyLine(line)) != 0 {
				t.Fatal("documented syntax rejected; input not echoed")
			}
		})
	}
	bad := []string{
		"hello @someone", "@someone", // prose handles are not PowerShell splatting
		"10.23.45.67", "100.64.0.9", "198.18.0.1", "128." + "0.0.0:9", "128." + "0.0.0/10", "010.0.0.1",
		"fd00::1", "fe80::1%synthetic0", "2001:db8::1%synthetic0", "[::ffff:10.23.45.67]:9",
		"synthetic-user" + "@" + "host.invalid", "ssh synthetic-host", "ProxyJump=" + "synthetic-host",
		"HostName host.invalid", "C:\\synthetic\\file", "C:/synthetic/file", "/home/synthetic/file",
		"\\Users\\<USER>\\file", "ssh-ed25519 SYNTHETIC_NOT_A_KEY", "ssh-rsa SYNTHETIC_NOT_A_KEY",
		"SHA256:" + strings.Repeat("A", 43), "02:00:00:00:00:01",
		"uses: actions/checkout@v4 synthetic-user" + "@" + "host.invalid", "$a = @(1); synthetic-user" + "@" + "host.invalid",
		"`@` synthetic-user" + "@" + "host.invalid", "`main@1234567` synthetic-user" + "@" + "host.invalid",
		"wink-stund" + "@" + "3478.service.extra", "unknown_error" + "@" + "unknown_stage",
		"https://synthetic-user" + "@" + "medium.com/topic", "[ref](https://host.invalid/@synthetic)",
		"ssh -p " + "22 synthetic-host", "ssh -l synthetic-user localhost", "ssh -J synthetic-host localhost",
		"ssh -o User=synthetic-user localhost", "`ssh synthetic-host`",
		"10.23.45.x", "172.23.*.*", "10.23.45.X", "100.64.0.0/10evil", "10.0.0.0/24:22",
		"https://medium.com/@synthetic", "[ref](https://medium.com/topic?key=x" + "@" + "host.invalid)",
		"[ref](https://medium.com/topic#x" + "@" + "host.invalid)",
		"ssh -lsynthetic-user localhost", "ssh -Jsynthetic-host localhost",
		"ssh -oUser=synthetic-user localhost", "ssh -ohostname=host.invalid localhost",
		"hostname host.invalid", "proxyjump=" + "host.invalid", "fd00:0:00:11:22:33:44:55",
		"Gateway 10.23.45.67.", "Gateway 10.23.45.67. End.", "Gateway fd00::1.",
	}
	for i, line := range bad {
		t.Run(fmt.Sprintf("rejected-%02d", i), func(t *testing.T) {
			if len(docPrivacyLine(line)) == 0 {
				t.Fatal("privacy mutation escaped; input not echoed")
			}
		})
	}
}

func TestPublicDocumentationPrivacyProductNetworkToken(t *testing.T) {
	// This fixed product configuration token is not an endpoint or a subnet-wide
	// exemption. Keep the value independent of runtime configuration loading.
	const token = "10.42.0.0/24"
	prefix := netip.MustParsePrefix(token)
	if prefix != prefix.Masked() {
		t.Fatal("product token must be a canonical network prefix")
	}
	good := []string{
		token, "WINK_NETWORK_CIDR=" + token, "\"" + token + "\"",
		"${WINK_NETWORK_CIDR:-" + token + "}", "`" + token + "`",
	}
	for i, line := range good {
		t.Run(fmt.Sprintf("exact-%02d", i), func(t *testing.T) {
			if len(docPrivacyLine(line)) != 0 {
				t.Fatal("exact product prefix rejected; value withheld")
			}
		})
	}
	host := prefix.Addr().Next().String()
	bad := []string{
		prefix.Addr().String(), host, fmt.Sprintf("%s/%d", host, prefix.Bits()),
		fmt.Sprintf("%s/%d", prefix.Addr(), prefix.Bits()-1),
		fmt.Sprintf("%s/%d", prefix.Addr(), prefix.Bits()+1),
		token + "0", token + "evil", token + ":22", token + "/24",
		token + "%synthetic", token + ".", token + " " + host,
	}
	for i, line := range bad {
		t.Run(fmt.Sprintf("reject-%02d", i), func(t *testing.T) {
			if len(docPrivacyLine(line)) == 0 {
				t.Fatal("product prefix exception widened; value withheld")
			}
		})
	}
}

func TestPublicDocumentationPrivacyIncludesEveryFile(t *testing.T) {
	for _, name := range []string{"README.md", ".hidden.md", "future.md", "docs/old.md", "docs/archive/deep/record.md", "docs/templates/new.json", "docs/future/schema.txt", "docs/.hidden.txt", "deploy/future/nested.yaml", "scripts/future/tool.py", "scripts/.hidden", ".github/workflows/future.yml", ".github/future/nested.json"} {
		t.Run(strings.ReplaceAll(name, "/", "-"), func(t *testing.T) {
			tree := fstest.MapFS{name: &fstest.MapFile{Data: []byte("heading\r\nssh synthetic-host\r\n")}}
			findings, files, err := scanPublicDocs(tree)
			if err != nil || files != 1 || len(findings) != 1 || findings[0].File != name || findings[0].Line != 2 {
				t.Fatal("document/template scan boundary or CRLF line witness changed")
			}
			if strings.Contains(fmt.Sprint(findings), "synthetic-host") || path.IsAbs(findings[0].File) {
				t.Fatal("privacy report disclosed a value or absolute path")
			}
		})
	}
	for _, tree := range []fstest.MapFS{
		{"docs/link": &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte("outside")}},
		{"docs/binary": &fstest.MapFile{Data: []byte{0xff}}},
	} {
		if _, _, err := scanPublicDocs(tree); err == nil {
			t.Fatal("unsupported document source was silently skipped")
		}
	}
}

func TestPrivacyLanguageOperatorsDoNotHideIdentities(t *testing.T) {
	operators := []string{
		`"${compose[@]}" config`, `exec "$@"`, `[pscustomobject][ordered]@{ name = 1 }`,
		`$a = @(@(1)); (@(2) -join ',')`, `Write-Output @arguments`, `"@-"`,
		`'@ | ConvertFrom-Json`, `"@ | ConvertFrom-Json`, `@dataclass`,
		`"${User}@${HostName}"`, `"$User@$HostName"`, `f"{user}@{host}"`,
		`"0x3C@8=0x1"`, `HostName = $BHost`,
	}
	identity := "synthetic-user" + "@" + "host.invalid"
	for i, operator := range operators {
		t.Run(fmt.Sprintf("syntax-%02d", i), func(t *testing.T) {
			if len(docPrivacyLine(operator)) != 0 {
				t.Fatal("language syntax classified as an identity")
			}
			if len(docPrivacyLine(operator+" "+identity)) == 0 {
				t.Fatal("syntax exception hid an identity on the same line")
			}
		})
	}
}
