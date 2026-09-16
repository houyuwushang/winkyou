package architecture

import (
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
	"unicode/utf8"
)

var (
	sourceIdentity = regexp.MustCompile(`[A-Za-z0-9_.+-]+@[A-Za-z0-9][A-Za-z0-9_.-]*`)
	sourceJump     = regexp.MustCompile(`(?i)\bssh\s+-p\s+[0-9]+\b|\bProxyJump=[A-Za-z0-9][A-Za-z0-9_.:-]*`)
	sourceKey      = regexp.MustCompile(`ssh-(?:ed25519|rsa)\s+[A-Za-z0-9+/=]{20,}|-----BEGIN (?:(?:OPENSSH|RSA|EC|DSA|ENCRYPTED) )?PRIVATE KEY-----|SHA256:[A-Za-z0-9+/=]{20,}`)
)

func sourceAllowedAddress(addr netip.Addr) bool {
	addr = addr.Unmap()
	if addr.String() == "1.2.3.4" {
		return true
	} // retained public resolver/example
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return true
	}
	for _, prefix := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32", "100.64.0.0/10", "198.18.0.0/15"} {
		if netip.MustParsePrefix(prefix).Contains(addr) {
			return true
		}
	}
	// Public resolver fixtures, not deployment identities or an arbitrary-host exemption.
	for _, resolver := range []string{"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9"} {
		if addr.String() == resolver {
			return true
		}
	}
	// Only global-unicast IPv6 can be a public IPv6 deployment address.
	return addr.Is6() && !netip.PrefixFrom(netip.AddrFrom16([16]byte{0x20}), 3).Contains(addr)
}

func sourcePrivacyLine(line string) []string {
	classes := map[string]bool{}
	for _, rule := range []*regexp.Regexp{docIPv4, docIPv6} {
		// Necessary syntax only: IPv4 needs dots; even compressed IPv6 needs
		// two colons. Avoid allocating hex matches for ordinary Go identifiers.
		if rule == docIPv4 && !strings.Contains(line, ".") || rule == docIPv6 && strings.Count(line, ":") < 2 {
			continue
		}
		for _, span := range rule.FindAllStringIndex(line, -1) {
			token := strings.TrimRight(line[span[0]:span[1]], ".")
			if rule == docIPv6 && strings.Count(token, ":") < 2 {
				continue // hex fragments in ordinary Go identifiers are not IP addresses
			}
			if !docWordBoundary(line, span[0], span[1]) {
				continue
			}
			addr, err := netip.ParseAddr(token)
			if err == nil && docAllowedAddress(addr, line[span[1]:]) {
				continue
			}
			if err == nil && !sourceAllowedAddress(addr) {
				classes["public_address"] = true
			}
		}
	}
	for _, span := range sourceIdentity.FindAllStringIndex(line, -1) {
		if !docAllowedAt(line, span[0]+strings.IndexByte(line[span[0]:span[1]], '@')) {
			classes["identity_destination"] = true
		}
	}
	for _, match := range sourceJump.FindAllString(line, -1) {
		if !strings.EqualFold(match, "ProxyJump=none") {
			classes["ssh_destination"] = true
		}
	}
	if sourceKey.MatchString(line) {
		classes["ssh_key_or_fingerprint"] = true
	}
	var out []string
	for _, class := range []string{"public_address", "identity_destination", "ssh_destination", "ssh_key_or_fingerprint"} {
		if classes[class] {
			out = append(out, class)
		}
	}
	return out
}

func scanSourcePrivacy(tree fs.FS) ([]docPrivacyFinding, int, error) {
	var findings []docPrivacyFinding
	files := 0
	err := fs.WalkDir(tree, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("source walk failed")
		}
		if name == "." {
			return nil
		}
		root := strings.SplitN(name, "/", 2)[0]
		if root != "cmd" && root != "pkg" && root != "internal" && root != "test" {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("source symlink rejected")
		}
		if entry.IsDir() || !strings.HasSuffix(name, ".go") {
			return nil
		}
		data, err := fs.ReadFile(tree, name)
		if err != nil || !utf8.Valid(data) {
			return fmt.Errorf("source read or encoding failed")
		}
		files++
		for i, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
			for _, class := range sourcePrivacyLine(line) {
				findings = append(findings, docPrivacyFinding{File: name, Line: i + 1, Class: class})
			}
		}
		return nil
	})
	return findings, files, err
}

func TestSourceTreePrivacy(t *testing.T) {
	findings, files, err := scanSourcePrivacy(os.DirFS(repositoryRoot(t)))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		t.Errorf("%s:%d: %s", f.File, f.Line, f.Class)
	}
	t.Logf("SOURCE_PRIVACY files=%d findings=%d values_disclosed=0", files, len(findings))
}

func TestSourceTreePrivacySyntax(t *testing.T) {
	good := []string{
		"192.0.2.1", "198.51.100.1", "203.0.113.1", "2001:db8::1",
		"10.23.45.67", "172.16.5.1", "192.168.55.1", "fd01::123", "fc01::1",
		"169.254.1.1", "fe80::1", "127.0.0.1", "::1", "0.0.0.0", "::", "255.255.255.255",
		"100.64.0.1", "198.18.0.1", "224.0.0.1", "ff02::1",
		"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "1.2.3.4", "node-a node-b node-c",
		"ProxyJump=none", "ssh -p <PORT> <SSH_DESTINATION>", "ssh-ed25519", "ssh-rsa",
	}
	for i, input := range good {
		t.Run(fmt.Sprintf("allowed-%02d", i), func(t *testing.T) {
			if len(sourcePrivacyLine(input)) != 0 {
				t.Fatal("source syntax rejected; value withheld")
			}
		})
	}
	// Synthetic negative inputs are assembled, so no literal identity is stored
	// in source just to test rejection. This is not a deployment-value denylist.
	bad := []string{
		"11." + "22.33.44", "2002" + "::1234", "::ffff:" + "11." + "22.33.44",
		"synthetic-user" + "@" + "host.invalid", "ssh -p " + "2345 host.invalid", "ProxyJump=" + "host.invalid",
		"ssh-ed25519 " + strings.Repeat("A", 40), "ssh-rsa " + strings.Repeat("A", 40),
		"SHA256:" + strings.Repeat("A", 43), "-----BEGIN " + "OPENSSH PRIVATE KEY-----", "-----BEGIN " + "PRIVATE KEY-----",
	}
	for i, input := range bad {
		t.Run(fmt.Sprintf("rejected-%02d", i), func(t *testing.T) {
			if len(sourcePrivacyLine(input)) == 0 || len(sourcePrivacyLine("// "+input)) == 0 {
				t.Fatal("source privacy mutation escaped; value withheld")
			}
		})
	}
}

func TestSourceTreePrivacyIncludesEveryFile(t *testing.T) {
	for _, root := range []string{"cmd", "pkg", "internal", "test"} {
		for _, tail := range []string{"main.go", "deep/new.go", "deep/future_test.go", ".hidden/future.go"} {
			name := root + "/" + tail
			t.Run(strings.ReplaceAll(name, "/", "-"), func(t *testing.T) {
				tree := fstest.MapFS{name: &fstest.MapFile{Data: []byte("package synthetic\r\n// " + "11." + "22.33.44\r\n")}}
				findings, files, err := scanSourcePrivacy(tree)
				if err != nil || files != 1 || len(findings) != 1 || findings[0].File != name || findings[0].Line != 2 {
					t.Fatal("source coverage or CRLF witness changed")
				}
			})
		}
	}
	for _, tree := range []fstest.MapFS{
		{"pkg/link": &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte("outside")}},
		{"pkg/binary.go": &fstest.MapFile{Data: []byte{0xff}}},
	} {
		if _, _, err := scanSourcePrivacy(tree); err == nil {
			t.Fatal("unsupported source silently skipped")
		}
	}
}
