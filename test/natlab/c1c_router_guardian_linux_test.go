//go:build linux && natlab && c1bproof && fieldc1c

package natlab

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"winkyou/internal/c1crouter"
)

func TestLinuxC1cRouterGuardianCrash(t *testing.T) {
	if os.Getenv("WINKYOU_C1C_ROUTER_REQUIRED") != "1" {
		t.Skip("requires disposable router proof")
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("WINKYOU_GATE_B3_DISPOSABLE_RUNNER") != "github-hosted" {
		t.Fatal("shared ceiling proof is restricted to the disposable CI runner")
	}
	requireGateB3Environment(t)
	original := readC1cRouterCeiling(t)
	if original < 40000 {
		t.Fatal("shared ceiling too small for explicit proof")
	}
	// An independent test cleanup is only a safety backstop. Observing a
	// changed value after the tool exits is always RED, even if cleanup succeeds.
	t.Cleanup(func() {
		if got := readC1cRouterCeiling(t); got != original {
			t.Error("router guardian did not restore original ceiling")
			if got == 40000 {
				if _, e := runCommand("sysctl", "-q", "-w", "net.netfilter.nf_conntrack_max="+strconv.FormatUint(original, 10)); e != nil {
					t.Error("router test backstop restore failed")
				}
			}
		}
	})
	topology := c1cRouterAnchors(t)
	profile := gateC1bProfiles[0]
	configs := fieldC1cFixture(t, gateC1bFixture(t, topology, c1cRouterObserverTopology(), profile, false), profile, os.Getenv("WINKYOU_FIELD_C1C_BINARY"))
	router := c1cRouterFixtureMode(t, topology, configs, os.Getenv("WINKYOU_C1C_ROUTER_BINARY"), true)
	done := startC1cRouterHost(t, router)
	select {
	case e := <-done:
		if e != nil {
			t.Fatal("router guardian crash proof failed")
		}
	case <-time.After(55 * time.Second):
		t.Fatal("router guardian crash proof deadline")
	}
	if readC1cRouterCeiling(t) != original {
		t.Fatal("router shared ceiling restore mismatch")
	}
	var summary c1crouter.Summary
	c1cRouterRead(t, router.Summary, &summary)
	if summary.Class != "c1c_router_io_failed" {
		t.Fatalf("ROUTER_CRASH class=%s", summary.Class)
	}
	for _, p := range []*uint64{summary.Counts.SocketResidue, summary.Counts.ProcessResidue, summary.Counts.ConntrackResidue, summary.Counts.NamespaceResidue, summary.Counts.VethResidue, summary.Counts.NFTResidue} {
		if p == nil || *p != 0 {
			t.Fatal("router crash residue unknown or nonzero")
		}
	}
	t.Log("ROUTER_GUARDIAN worker_killed=1 saved=1 readback=1 restored=1 residue=0")
}

func readC1cRouterCeiling(t *testing.T) uint64 {
	t.Helper()
	b, e := runCommand("sysctl", "-n", "net.netfilter.nf_conntrack_max")
	if e != nil {
		t.Fatal("router ceiling witness unavailable")
	}
	n, e := strconv.ParseUint(strings.TrimSpace(b), 10, 64)
	if e != nil {
		t.Fatal("router ceiling witness invalid")
	}
	return n
}

func prepareC1cRouterGuardianMounts(cfg gateC1bHostConfig) error {
	if !gateC1bIsolatedMount(cfg.ParentMount) || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		return errors.New("router guardian isolation unavailable")
	}
	var current, initial unix.Stat_t
	if unix.Stat("/proc/self/ns/net", &current) != nil || unix.Stat("/proc/1/ns/net", &initial) != nil || current.Ino != initial.Ino {
		return errors.New("router guardian init scope unavailable")
	}
	if unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, "") != nil {
		return errors.New("router private mount failed")
	}
	namespaces, e := os.Open("/run/netns")
	if e != nil {
		return e
	}
	defer namespaces.Close()
	locks, e := os.Open("/run/lock")
	if e != nil {
		return e
	}
	defer locks.Close()
	for _, pair := range [][2]string{{cfg.MachineBase, "/var/lib"}, {cfg.HomeDirectory, "/root"}, {cfg.RuntimeBase, "/run"}} {
		if unix.Mount(pair[0], pair[1], "", unix.MS_BIND, "") != nil {
			return errors.New("router private mount failed")
		}
	}
	if unix.Mount(fmt.Sprintf("/proc/self/fd/%d", namespaces.Fd()), "/run/netns", "", unix.MS_BIND|unix.MS_REC, "") != nil {
		return errors.New("router namespace registry failed")
	}
	if unix.Mount(fmt.Sprintf("/proc/self/fd/%d", locks.Fd()), "/run/lock", "", unix.MS_BIND, "") != nil {
		return errors.New("router shared lock identity failed")
	}
	return os.Chdir("/root")
}

func proveC1cRouterGuardianCrash(t *testing.T, cfg c1cRouterHost, done <-chan error) {
	t.Helper()
	c1cRouterWaitFile(t, filepath.Join(cfg.Evidence, "ready.json"), 20*time.Second, done)
	var journal struct {
		ChildPID        int     `json:"child_pid"`
		ChildStart      string  `json:"child_start"`
		CeilingOriginal *uint64 `json:"ceiling_original"`
		CeilingRestored bool    `json:"ceiling_restored"`
	}
	c1cRouterRead(t, filepath.Join(cfg.Evidence, "ownership.json"), &journal)
	if journal.ChildPID <= 1 || journal.ChildStart == "" || journal.CeilingOriginal == nil || readC1cRouterCeiling(t) != 40000 {
		t.Fatal("router guardian live ownership absent")
	}
	fd, e := unix.PidfdOpen(journal.ChildPID, 0)
	if e != nil {
		t.Fatal("router worker identity unavailable")
	}
	defer unix.Close(fd)
	b, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", journal.ChildPID))
	if e != nil {
		t.Fatal("router worker identity unavailable")
	}
	index := strings.LastIndexByte(string(b), ')')
	fields := strings.Fields(string(b[index+1:]))
	if index < 0 || len(fields) < 20 || fields[19] != journal.ChildStart {
		t.Fatal("router worker start identity mismatch")
	}
	if unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0) != nil {
		t.Fatal("router owned worker injection failed")
	}
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("killed worker falsely succeeded")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("router guardian did not reap and restore")
	}
	c1cRouterRead(t, filepath.Join(cfg.Evidence, "ownership.json"), &journal)
	if !journal.CeilingRestored || readC1cRouterCeiling(t) != *journal.CeilingOriginal {
		t.Fatal("router independent guardian restore absent")
	}
}
