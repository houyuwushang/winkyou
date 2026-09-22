//go:build linux && fieldc1c

package c1crouter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"winkyou/internal/v2/fieldc1c"
)

type topology struct {
	snapshot fieldc1c.RouterSnapshot
	journal  *journal
	anchors  [3]*os.File
	owned    [2]*os.File
}

func onlyLoopback(data []byte) bool {
	var links []struct {
		IfName string `json:"ifname"`
	}
	if json.Unmarshal(data, &links) != nil || len(links) != 1 {
		return false
	}
	return links[0].IfName == "lo"
}

func preflightTopology(s fieldc1c.RouterSnapshot) error {
	if os.Geteuid() != 0 {
		return ErrOwnership
	}
	for _, name := range []string{"ip", "nft", "ss", "conntrack", "sysctl"} {
		if _, e := executable(name); e != nil {
			return e
		}
	}
	var limit unix.Rlimit
	if unix.Getrlimit(unix.RLIMIT_NOFILE, &limit) != nil || limit.Cur < MappingHardCap+128 {
		return ErrResource
	}
	for _, ns := range s.Namespaces {
		if _, e := os.Lstat("/var/run/netns/" + ns); !os.IsNotExist(e) {
			return ErrOwnership
		}
	}
	for _, anchor := range s.Configuration.Anchors {
		f, e := openNamespace(anchor.Name, anchor.Inode)
		if e != nil {
			return e
		}
		_ = f.Close()
		b, e := runCommand(context.Background(), anchor.Name, "ip", nil, "-j", "link", "show")
		if e != nil {
			return errIO
		}
		if !onlyLoopback(b) {
			return ErrOwnership
		}
	}
	return nil
}

func (t *topology) create(ctx context.Context) error {
	for i, a := range t.snapshot.Configuration.Anchors {
		f, e := openNamespace(a.Name, a.Inode)
		if e != nil {
			return e
		}
		t.anchors[i] = f
	}
	for i := range t.owned {
		if e := t.createNamespace(i); e != nil {
			return e
		}
	}
	anchors := t.snapshot.Configuration.Anchors
	// Every pair is born in the two named non-init namespaces. Deleting the
	// owned end removes its peer, including a crash before the next journal write.
	pairs := [][4]string{{t.snapshot.Namespaces[0], "lan0", anchors[0].Name, "wyca"}, {t.snapshot.Namespaces[0], "wan0", anchors[1].Name, "wycta"}, {t.snapshot.Namespaces[1], "wan0", anchors[1].Name, "wyctb"}, {t.snapshot.Namespaces[1], "lan0", anchors[2].Name, "wycb"}}
	for _, p := range pairs {
		if _, e := runCommand(ctx, "", "ip", nil, "link", "add", p[1], "netns", p[0], "type", "veth", "peer", "name", p[3], "netns", p[2]); e != nil {
			return errIO
		}
	}
	for i, d := range t.snapshot.Configuration.Domains {
		ep := anchors[0].Name
		epDev := "wyca"
		transitDev := "wycta"
		if i == 1 {
			ep = anchors[2].Name
			epDev = "wycb"
			transitDev = "wyctb"
		}
		for _, binding := range [][3]string{{ep, epDev, d.EndpointPrefix}, {t.snapshot.Namespaces[i], "lan0", d.GatewayPrefix}, {t.snapshot.Namespaces[i], "wan0", d.PublicPrefix}, {anchors[1].Name, transitDev, d.TransitPrefix}} {
			if _, e := runCommand(ctx, binding[0], "ip", nil, "address", "add", binding[2], "dev", binding[1]); e != nil {
				return errIO
			}
			if _, e := runCommand(ctx, binding[0], "ip", nil, "link", "set", binding[1], "up"); e != nil {
				return errIO
			}
		}
		for _, ns := range []string{ep, t.snapshot.Namespaces[i]} {
			if _, e := runCommand(ctx, ns, "ip", nil, "link", "set", "lo", "up"); e != nil {
				return errIO
			}
		}
		gateway := netip.MustParsePrefix(d.GatewayPrefix).Addr().String()
		transit := netip.MustParsePrefix(d.TransitPrefix).Addr().String()
		for _, address := range routeTargets(t.snapshot, i) {
			if _, e := runCommand(ctx, ep, "ip", nil, "route", "add", address+"/32", "via", gateway, "dev", epDev); e != nil {
				return errIO
			}
			if _, e := runCommand(ctx, t.snapshot.Namespaces[i], "ip", nil, "route", "add", address+"/32", "via", transit, "dev", "wan0"); e != nil {
				return errIO
			}
		}
		for _, setting := range []string{"net.ipv4.ip_forward=1", "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.default.rp_filter=0", "net.ipv4.conf.lan0.rp_filter=0", "net.ipv4.conf.wan0.rp_filter=0"} {
			if _, e := runCommand(ctx, t.snapshot.Namespaces[i], "sysctl", nil, "-q", "-w", setting); e != nil {
				return errIO
			}
		}
		if _, e := runCommand(ctx, t.snapshot.Namespaces[i], "nft", strings.NewReader(nftRules(t.snapshot, i)), "-f", "-"); e != nil {
			return errIO
		}
	}
	b, e := runCommand(ctx, anchors[1].Name, "sysctl", nil, "-n", "net.ipv4.ip_forward")
	if e != nil {
		return errIO
	}
	old, e := strconv.Atoi(strings.TrimSpace(string(b)))
	if e != nil || (old != 0 && old != 1) {
		return ErrOwnership
	}
	t.journal.value.TransitForward = &old
	if t.journal.save() != nil {
		return errIO
	}
	if _, e = runCommand(ctx, anchors[1].Name, "sysctl", nil, "-q", "-w", "net.ipv4.ip_forward=1"); e != nil {
		return errIO
	}
	return nil
}

func (t *topology) configureTUN(ctx context.Context, index int) error {
	ns := t.snapshot.Namespaces[index]
	for _, args := range [][]string{{"link", "set", "wyctun", "up"}, {"route", "add", "default", "dev", "wyctun", "table", "102"}, {"rule", "add", "priority", "100", "iif", "lan0", "ipproto", "udp", "lookup", "102"}} {
		if _, e := runCommand(ctx, ns, "ip", nil, args...); e != nil {
			return errIO
		}
	}
	return nil
}

func routeTargets(s fieldc1c.RouterSnapshot, index int) []string {
	peer := netip.MustParsePrefix(s.Configuration.Domains[1-index].PublicPrefix).Addr()
	values := []netip.Addr{peer, s.Observers[0].Addr(), s.Observers[2].Addr()}
	seen := map[netip.Addr]bool{}
	var out []string
	for _, a := range values {
		if !seen[a] {
			seen[a] = true
			out = append(out, a.String())
		}
	}
	return out
}

func nftRules(s fieldc1c.RouterSnapshot, index int) string {
	d := s.Configuration.Domains[index]
	local := netip.MustParsePrefix(d.EndpointPrefix).Addr()
	public := netip.MustParsePrefix(d.PublicPrefix).Addr()
	peer := netip.MustParsePrefix(s.Configuration.Domains[1-index].PublicPrefix).Addr()
	allowed := strings.Join(routeTargets(s, index), ", ")
	port := s.SSHEndpoint.Port()
	return fmt.Sprintf(`create table ip wycrouter
add counter ip wycrouter udp_out
add counter ip wycrouter udp_in
add chain ip wycrouter ingress { type filter hook input priority 0; policy drop; }
add rule ip wycrouter ingress iifname "lo" accept
add rule ip wycrouter ingress ip saddr { %s } ip daddr %s udp dport 40000-65535 counter name udp_in accept
add chain ip wycrouter egress { type filter hook output priority 0; policy drop; }
add rule ip wycrouter egress oifname "lo" accept
add rule ip wycrouter egress ip saddr %s ip daddr { %s } udp sport 40000-65535 counter name udp_out accept
add chain ip wycrouter forward { type filter hook forward priority 0; policy drop; }
add rule ip wycrouter forward iifname "lan0" oifname "wyctun" ip saddr %s ip daddr { %s } ip protocol udp accept
add rule ip wycrouter forward iifname "wyctun" oifname "lan0" ip saddr { %s } ip daddr %s ip protocol udp accept
add rule ip wycrouter forward ip saddr %s ip daddr %s tcp dport %d accept
add rule ip wycrouter forward ip saddr %s ip daddr %s tcp sport %d accept
add rule ip wycrouter forward ip saddr %s ip daddr %s tcp dport %d accept
add rule ip wycrouter forward ip saddr %s ip daddr %s tcp sport %d accept
add chain ip wycrouter prerouting { type nat hook prerouting priority -100; policy accept; }
add rule ip wycrouter prerouting iifname "wan0" ip saddr %s ip daddr %s tcp dport %d dnat to %s:%d
add chain ip wycrouter postrouting { type nat hook postrouting priority 100; policy accept; }
add rule ip wycrouter postrouting oifname "wan0" ip saddr %s ip daddr %s ip protocol tcp snat to %s
`, allowed, public, public, allowed, local, allowed, allowed, local, local, peer, port, peer, local, port, peer, local, port, local, peer, port, peer, public, port, local, port, local, peer, public)
}

// Namespace inode is durably recorded before publishing its mount. Thus a
// crash between publication and the next journal append cannot create an
// unidentifiable live namespace. No init-network configuration is modified.
func (t *topology) createNamespace(index int) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		original, e := os.Open("/proc/thread-self/ns/net")
		if e != nil {
			runtime.UnlockOSThread()
			done <- ErrOwnership
			return
		}
		if unix.Unshare(unix.CLONE_NEWNET) != nil {
			_ = original.Close()
			runtime.UnlockOSThread()
			done <- ErrOwnership
			return
		}
		defer func() {
			if unix.Setns(int(original.Fd()), unix.CLONE_NEWNET) == nil {
				runtime.UnlockOSThread()
			} else {
				e = ErrOwnership
			}
			_ = original.Close()
			done <- e
		}()
		f, err := os.Open("/proc/thread-self/ns/net")
		if err != nil {
			e = ErrOwnership
			return
		}
		keep := false
		defer func() {
			if !keep {
				_ = f.Close()
			}
		}()
		var st unix.Stat_t
		if unix.Fstat(int(f.Fd()), &st) != nil {
			e = ErrOwnership
			return
		}
		t.journal.value.Namespaces[index] = st.Ino
		if t.journal.save() != nil {
			e = errIO
			return
		}
		path := filepath.Join("/var/run/netns", t.snapshot.Namespaces[index])
		// An anonymous inode is recorded before it receives a pathname. There
		// is no create-before-journal crash window, even for an empty mountpoint.
		fd, err := unix.Open("/var/run/netns", unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, 0o600)
		if err != nil {
			e = ErrOwnership
			return
		}
		placeholder := os.NewFile(uintptr(fd), "owned-namespace-mountpoint")
		defer placeholder.Close()
		if unix.Fstat(int(placeholder.Fd()), &st) != nil {
			e = ErrOwnership
			return
		}
		t.journal.value.Placeholders[index] = st.Ino
		if t.journal.save() != nil {
			e = errIO
			return
		}
		if unix.Linkat(fd, "", unix.AT_FDCWD, path, unix.AT_EMPTY_PATH) != nil {
			e = ErrOwnership
			return
		}
		if unix.Mount("/proc/self/fd/"+strconv.Itoa(int(f.Fd())), path, "", unix.MS_BIND, "") != nil {
			e = ErrOwnership
			return
		}
		keep = true
		t.owned[index] = f
	}()
	return <-done
}
