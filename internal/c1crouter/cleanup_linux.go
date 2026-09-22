//go:build linux && fieldc1c

package c1crouter

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const cleanupTimeout = 20 * time.Second

func residueZero(counts Counts) bool {
	for _, p := range []*uint64{counts.SocketResidue, counts.ProcessResidue, counts.ConntrackResidue, counts.NamespaceResidue, counts.VethResidue, counts.NFTResidue} {
		if p == nil || *p != 0 {
			return false
		}
	}
	return true
}
func zero() *uint64 { n := uint64(0); return &n }

func (t *topology) closeFiles() {
	for _, f := range t.owned {
		if f != nil {
			_ = f.Close()
		}
	}
	for _, f := range t.anchors {
		if f != nil {
			_ = f.Close()
		}
	}
}

// Cleanup recomputes every name/operation from the signed local instance. The
// journal only proves identity and progress; it cannot supply an argv or path.
// A mismatch is retained for operator review, never "repaired" by deletion.
func (t *topology) cleanup(counts *Counts) error {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	var result error
	for i, name := range t.snapshot.Namespaces {
		path := filepath.Join("/var/run/netns", name)
		current, e := inode(path)
		if e != nil {
			if _, err := os.Lstat(path); os.IsNotExist(err) {
				continue
			}
			result = errors.Join(result, ErrOwnership)
			continue
		}
		if current == t.journal.value.Placeholders[i] && current != 0 {
			if os.Remove(path) != nil {
				result = errors.Join(result, ErrOwnership)
			}
			continue
		}
		if current != t.journal.value.Namespaces[i] || current == 0 {
			result = errors.Join(result, ErrOwnership)
			continue
		}
		// Quiesce only owned interfaces before flushing kernel flow state.
		// Otherwise a late forwarded TCP close could recreate a flow between
		// the exact namespace flush and the residue readback.
		if data, err := runCommand(ctx, name, "ip", nil, "-j", "link", "show"); err != nil {
			result = errors.Join(result, ErrDrain)
		} else {
			var links []struct {
				Name string `json:"ifname"`
			}
			if json.Unmarshal(data, &links) != nil {
				result = errors.Join(result, ErrDrain)
			} else {
				for _, link := range links {
					if link.Name == "lan0" || link.Name == "wan0" {
						if _, err := runCommand(ctx, name, "ip", nil, "link", "set", link.Name, "down"); err != nil {
							result = errors.Join(result, ErrDrain)
						}
						// Last-reference namespace destruction is asynchronous.
						// Delete the owned veth under RTNL while this namespace
						// still exists, so its anchor peer is gone synchronously.
						if _, err := runCommand(ctx, name, "ip", nil, "link", "del", link.Name); err != nil {
							result = errors.Join(result, ErrDrain)
						}
					}
				}
			}
		}
		// Read the OS before destroying the namespace, rather than treating
		// disappearance of a name as proof that a referenced namespace died.
		if data, err := runCommand(ctx, name, "ss", nil, "-H", "-n", "-a", "-u", "-t"); err != nil || strings.TrimSpace(string(data)) != "" {
			result = errors.Join(result, ErrDrain)
		}
		if data, err := runCommand(ctx, "", "ip", nil, "netns", "pids", name); err != nil || strings.TrimSpace(string(data)) != "" {
			result = errors.Join(result, ErrDrain)
		}
		if _, err := runCommand(ctx, name, "conntrack", nil, "-F"); err != nil {
			result = errors.Join(result, ErrDrain)
		}
		if data, err := runCommand(ctx, name, "conntrack", nil, "-C"); err != nil || strings.TrimSpace(string(data)) != "0" {
			result = errors.Join(result, ErrDrain)
		}
		// Flush only this exact owned namespace's table, never a ruleset.
		if data, err := runCommand(ctx, name, "nft", nil, "-j", "list", "tables"); err != nil {
			result = errors.Join(result, ErrDrain)
		} else if nftPresent(data) {
			if _, err = runCommand(ctx, name, "nft", nil, "delete", "table", "ip", "wycrouter"); err != nil {
				result = errors.Join(result, ErrDrain)
			}
		}
		if data, err := runCommand(ctx, name, "nft", nil, "-j", "list", "tables"); err != nil || nftPresent(data) {
			result = errors.Join(result, ErrDrain)
		}
		if t.owned[i] != nil {
			_ = t.owned[i].Close()
			t.owned[i] = nil
		}
		if unix.Unmount(path, 0) != nil {
			result = errors.Join(result, ErrDrain)
			continue
		}
		if current, err := inode(path); err != nil || current != t.journal.value.Placeholders[i] {
			result = errors.Join(result, ErrOwnership)
			continue
		}
		if os.Remove(path) != nil {
			result = errors.Join(result, ErrDrain)
		}
	}
	if old := t.journal.value.TransitForward; old != nil {
		anchor := t.snapshot.Configuration.Anchors[1]
		f, e := openNamespace(anchor.Name, anchor.Inode)
		if e != nil {
			result = errors.Join(result, e)
		} else {
			_ = f.Close()
			value := strconv.Itoa(*old)
			if _, e = runCommand(ctx, anchor.Name, "sysctl", nil, "-q", "-w", "net.ipv4.ip_forward="+value); e != nil {
				result = errors.Join(result, ErrDrain)
			}
			if b, e := runCommand(ctx, anchor.Name, "sysctl", nil, "-n", "net.ipv4.ip_forward"); e != nil || strings.TrimSpace(string(b)) != value {
				result = errors.Join(result, ErrDrain)
			}
		}
	}
	for _, anchor := range t.snapshot.Configuration.Anchors {
		f, e := openNamespace(anchor.Name, anchor.Inode)
		if e != nil {
			result = errors.Join(result, e)
			continue
		}
		_ = f.Close()
		if data, e := runCommand(ctx, anchor.Name, "ip", nil, "-j", "link", "show"); e != nil || !onlyLoopback(data) {
			result = errors.Join(result, ErrDrain)
		}
	}
	for _, name := range t.snapshot.Namespaces {
		if _, e := os.Lstat(filepath.Join("/var/run/netns", name)); !os.IsNotExist(e) {
			result = errors.Join(result, ErrDrain)
		}
	}
	t.closeFiles()
	if result == nil {
		counts.SocketResidue = zero()
		counts.ProcessResidue = zero()
		counts.ConntrackResidue = zero()
		counts.NamespaceResidue = zero()
		counts.VethResidue = zero()
		counts.NFTResidue = zero()
		t.journal.value.Clean = true
		if t.journal.save() != nil {
			return errIO
		}
	}
	return result
}
func nftPresent(data []byte) bool {
	var result struct {
		NFTables []struct {
			Table *struct{ Name, Family string } `json:"table"`
		} `json:"nftables"`
	}
	if json.Unmarshal(data, &result) != nil {
		return true
	}
	for _, item := range result.NFTables {
		if item.Table != nil {
			return true
		}
	}
	return false
}
