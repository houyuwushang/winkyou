//go:build linux && natlab && c1bproof && fieldc1c

package natlab

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"winkyou/internal/c1crouter"
	"winkyou/internal/v2/gatecorchestrator"
)

const c1cRouterHostEnv = "WINKYOU_C1C_ROUTER_HOST"

type c1cRouterInspection struct {
	Out                [2]uint64 `json:"out"`
	In                 [2]uint64 `json:"in"`
	Sockets            [2]int    `json:"sockets"`
	CountsPresent      bool      `json:"counts_present"`
	ResidualNamespaces int       `json:"residual_namespaces"`
	ResidualLinks      int       `json:"residual_links"`
}

func TestLinuxC1cRouterFullInstances(t *testing.T) {
	if os.Getenv("WINKYOU_C1C_ROUTER_REQUIRED") != "1" {
		t.Skip("requires isolated router proof job")
	}
	requireGateB3Environment(t)
	requireGateB3HostConntrackGuard(t)
	fieldBinary, routerBinary := os.Getenv("WINKYOU_FIELD_C1C_BINARY"), os.Getenv("WINKYOU_C1C_ROUTER_BINARY")
	if !filepath.IsAbs(fieldBinary) || !filepath.IsAbs(routerBinary) {
		t.Fatal("router proof images unavailable")
	}
	for sample := 1; sample <= 3; sample++ {
		if !t.Run(fmt.Sprintf("fresh-%d", sample), func(t *testing.T) { testC1cRouterFullInstance(t, fieldBinary, routerBinary) }) {
			t.FailNow()
		}
	}
}

func testC1cRouterFullInstance(t *testing.T, fieldBinary, routerBinary string) {
	armGateB3KernelReleaseMargin(t)
	topology := c1cRouterAnchors(t)
	t.Cleanup(func() { cleanupGateC1bEndpointProcesses(t, topology) })
	profile := gateC1bProfiles[0]
	configs := fieldC1cFixture(t, gateC1bFixture(t, topology, c1cRouterObserverTopology(), profile, false), profile, fieldBinary)
	router := c1cRouterFixture(t, topology, configs, routerBinary)
	routerDone := startC1cRouterHost(t, router)
	c1cRouterWaitFile(t, filepath.Join(router.Evidence, "ready.json"), 20*time.Second, routerDone)
	server := startFieldC1cHost(t, configs[1])
	server.waitFile(t, configs[1].Host.ReadyFile, 5*time.Second)
	client := startFieldC1cHost(t, configs[0])
	deadline := time.Now().Add(55 * time.Second)
	for !fieldC1cHasStage(configs[0].Evidence, gatecorchestrator.StageDataPlaneReady) || !fieldC1cHasStage(configs[1].Evidence, gatecorchestrator.StageDataPlaneReady) {
		if !time.Now().Before(deadline) {
			for i, cfg := range configs {
				terminal := readFieldC1cTerminal(cfg.Evidence)
				t.Logf("ROUTER_ENDPOINT side=%d class=%s stage=%s candidates=%d", i, terminal.Class, fieldC1cLastStage(cfg.Evidence), terminal.Result.Witness.GateB.Emissions.CandidatePackets)
			}
			t.Fatal("router composition did not reach authenticated data-plane ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, e := runNamespaced(topology.clientA, "ping", nil, "-n", "-c", "1", "-W", "2", "192.0.2.101"); e != nil {
		t.Fatal("router kernel echo failed")
	}
	if os.WriteFile(configs[0].Host.StopFile, []byte("owned-sigint\n"), 0o600) != nil {
		t.Fatal("router endpoint stop request failed")
	}
	waitFieldC1cEndpoint(t, client, configs)
	var terminals [2]fieldC1cTerminal
	for i, cfg := range configs {
		until := time.Now().Add(5 * time.Second)
		for {
			terminals[i] = readFieldC1cTerminal(cfg.Evidence)
			if terminals[i].Class != "" {
				break
			}
			if time.Now().After(until) {
				t.Fatal("router endpoint terminal absent")
			}
			time.Sleep(10 * time.Millisecond)
		}
		v := terminals[i]
		if v.Class != "success" || !v.Result.DataPlaneReady || !v.Result.FinishRecorded || !v.Result.Witness.Handoff.AttemptReleased || !v.Result.Witness.InterfaceClosed || !v.Interface.InterfaceAbsent || v.Interface.KernelPacketsRead == 0 || v.Interface.KernelPacketsWritten == 0 {
			t.Fatalf("router endpoint terminal side=%d class=%s ready=%t finish=%t", i, v.Class, v.Result.DataPlaneReady, v.Result.FinishRecorded)
		}
	}
	server.stop(t)
	if os.WriteFile(router.Inspect, []byte("inspect-owned\n"), 0o600) != nil {
		t.Fatal("router witness request failed")
	}
	c1cRouterWaitFile(t, router.Inspection, 10*time.Second, routerDone)
	var inspection c1cRouterInspection
	c1cRouterRead(t, router.Inspection, &inspection)
	if !inspection.CountsPresent {
		t.Fatal("router OS packet counters unavailable")
	}
	for side, terminal := range terminals {
		w := terminal.Result.Witness
		charged := uint64(w.GateB.Emissions.UDPPacketsTotal + w.WireGuard.ReadinessWrites + w.WireGuard.CompletionWrites + len(w.WireGuard.Outbound) + w.WireGuard.ActiveWrites)
		if inspection.Out[side] != charged || inspection.Sockets[side] == 0 {
			t.Fatalf("ROUTER_ACCOUNTING side=%d actual=%d charged=%d sockets=%d", side, inspection.Out[side], charged, inspection.Sockets[side])
		}
		t.Logf("ROUTER_ACCOUNTING side=%d actual=%d charged=%d candidates=%d winner=%d", side, inspection.Out[side], charged, w.GateB.Emissions.CandidatePackets, w.GateB.Emissions.WinnerPackets)
	}
	if os.WriteFile(router.Host.StopFile, []byte("owned-teardown\n"), 0o600) != nil {
		t.Fatal("router teardown request failed")
	}
	select {
	case e := <-routerDone:
		if e != nil {
			t.Fatal("router host terminated unsuccessfully")
		}
	case <-time.After(40 * time.Second):
		t.Fatal("router host teardown deadline")
	}
	var terminal, teardown c1crouter.Summary
	c1cRouterRead(t, router.Summary, &terminal)
	c1cRouterRead(t, router.Teardown, &teardown)
	for _, summary := range []c1crouter.Summary{terminal, teardown} {
		if _, e := summary.Encode(); e != nil || !(summary.Class == "success" || summary.Class == "cancelled") {
			t.Fatalf("ROUTER_TERMINAL stage=%s class=%s", summary.Stage, summary.Class)
		}
		for _, count := range []*uint64{summary.Counts.SocketResidue, summary.Counts.ProcessResidue, summary.Counts.ConntrackResidue, summary.Counts.NamespaceResidue, summary.Counts.VethResidue, summary.Counts.NFTResidue} {
			if count == nil || *count != 0 {
				t.Fatal("router residue is nonzero or unknown")
			}
		}
	}
	if terminal.Counts.Queries == 0 || terminal.Counts.ObserverReplies == 0 || terminal.Counts.Outbound != inspection.Out[0]+inspection.Out[1] {
		t.Fatal("router sampling/OS accounting not witnessed")
	}
	c1cRouterRead(t, router.Inspection+".after", &inspection)
	if inspection.ResidualLinks != 0 || inspection.ResidualNamespaces != 0 {
		t.Fatal("external router residue")
	}
	f, e := os.Open(filepath.Join(router.Evidence, "router.jsonl"))
	if e != nil {
		t.Fatal("router evidence absent")
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	rows := 0
	for scan.Scan() {
		var record struct {
			Observation c1crouter.Observation `json:"observation"`
		}
		if json.Unmarshal(scan.Bytes(), &record) == nil && record.Observation.Role != "" {
			if !record.Observation.Valid() {
				t.Fatal("router unknown measurement lost its reason")
			}
			rows++
		}
	}
	if scan.Err() != nil || rows == 0 {
		t.Fatal("router §5 observations absent")
	}
	t.Logf("ROUTER_PROOF fresh=1 endpoint_success=2 kernel_echo=1 queries=%d observation_rows=%d sockets=0 processes=0 conntrack=0 namespaces=0 veth=0 nft=0", terminal.Counts.Queries, rows)
}

func c1cRouterRead(t *testing.T, path string, v any) {
	t.Helper()
	data, e := os.ReadFile(path)
	if e != nil || json.Unmarshal(data, v) != nil {
		t.Fatal("router private witness unavailable")
	}
}
func c1cRouterWaitFile(t *testing.T, path string, limit time.Duration, done <-chan error) {
	t.Helper()
	timer := time.NewTimer(limit)
	defer timer.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if info, e := os.Stat(path); e == nil && info.Size() > 0 {
			return
		}
		select {
		case <-done:
			t.Fatal("router host stopped before witness")
		case <-timer.C:
			t.Fatal("router witness deadline")
		case <-ticker.C:
		}
	}
}

func startC1cRouterHost(t *testing.T, cfg c1cRouterHost) <-chan error {
	t.Helper()
	metadata := cfg.Host.RequestFile + ".router-host"
	if writeN1JSON(metadata, cfg) != nil {
		t.Fatal("router host metadata failed")
	}
	command := exec.Command("ip", "netns", "exec", cfg.Host.HostNamespace, os.Args[0], "-test.run=^TestC1cRouterHostProcess$", "-test.count=1", "-test.timeout=110s")
	if cfg.GuardianCrash {
		command = exec.Command(os.Args[0], "-test.run=^TestC1cRouterHostProcess$", "-test.count=1", "-test.timeout=110s")
	}
	command.Env = append(os.Environ(), c1cRouterHostEnv+"="+metadata)
	command.Stdout, command.Stderr = io.Discard, io.Discard
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS, Pdeathsig: syscall.SIGKILL, Setpgid: true}
	done, e := startGateC1bOwnedProcess(command)
	if e != nil {
		t.Fatal("router host launch failed")
	}
	finished := make(chan error, 1)
	stopped := make(chan struct{})
	go func() { finished <- <-done; close(stopped) }()
	t.Cleanup(func() {
		select {
		case <-stopped:
		default:
			_ = os.WriteFile(cfg.Host.StopFile, []byte("owned-teardown\n"), 0o600)
			select {
			case <-stopped:
			case <-time.After(40 * time.Second):
				t.Error("router test host residue")
				_ = command.Process.Kill()
			}
		}
	})
	return finished
}

func TestC1cRouterHostProcess(t *testing.T) {
	metadata := os.Getenv(c1cRouterHostEnv)
	if metadata == "" {
		t.Skip("router host subprocess only")
	}
	var cfg c1cRouterHost
	c1cRouterRead(t, metadata, &cfg)
	if !gateC1bIsolatedMount(cfg.Host.ParentMount) || (!cfg.GuardianCrash && !gateC1bCurrentNamespace(cfg.Host.HostNamespace)) || os.Geteuid() != 0 {
		t.Fatal("router host isolation missing")
	}
	var mountErr error
	if cfg.GuardianCrash {
		mountErr = prepareC1cRouterGuardianMounts(cfg.Host)
	} else {
		mountErr = prepareGateC1bPrivateMounts(cfg.Host)
	}
	if mountErr != nil || unix.Mount(cfg.MachineIDFile, "/etc/machine-id", "", unix.MS_BIND, "") != nil {
		t.Fatal("router private host setup failed")
	}
	output, e := os.OpenFile(cfg.Summary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if e != nil {
		t.Fatal("router summary claim failed")
	}
	defer output.Close()
	command := exec.Command(cfg.Binary, "run", "--instance", cfg.Instance)
	command.Stdout, command.Stderr = output, io.Discard
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	done, e := startGateC1bOwnedProcess(command)
	if e != nil {
		t.Fatal("router run launch failed")
	}
	defer func() { _ = command.Process.Kill() }()
	if cfg.GuardianCrash {
		proveC1cRouterGuardianCrash(t, cfg, done)
		return
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(90 * time.Second)
	defer timeout.Stop()
	inspected := false
	for {
		select {
		case e := <-done:
			if e != nil {
				t.Fatal("router image exited before teardown")
			}
			t.Fatal("router ended without explicit teardown")
		case <-timeout.C:
			t.Fatal("router test host limit")
		case <-ticker.C:
			if !inspected {
				if _, e := os.Stat(cfg.Inspect); e == nil {
					witness := c1cRouterInspect(t, cfg, false)
					if writeN1JSON(cfg.Inspection, witness) != nil {
						t.Fatal("router external witness write failed")
					}
					inspected = true
				}
			}
			if _, e := os.Stat(cfg.Host.StopFile); e == nil {
				teardownOutput, e := os.OpenFile(cfg.Teardown, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
				if e != nil {
					t.Fatal("router teardown evidence claim failed")
				}
				teardown := exec.Command(cfg.Binary, "teardown", "--instance", cfg.Instance)
				teardown.Stdout, teardown.Stderr = teardownOutput, io.Discard
				if teardown.Run() != nil {
					_ = teardownOutput.Close()
					t.Fatal("router owned teardown failed")
				}
				_ = teardownOutput.Close()
				select {
				case e := <-done:
					if e != nil {
						t.Fatal("router drain exit failed")
					}
				case <-time.After(3 * time.Second):
					t.Fatal("router guardian did not exit")
				}
				if writeN1JSON(cfg.Inspection+".after", c1cRouterInspect(t, cfg, true)) != nil {
					t.Fatal("router residue witness write failed")
				}
				return
			}
		}
	}
}

func c1cRouterInspect(t *testing.T, cfg c1cRouterHost, after bool) c1cRouterInspection {
	t.Helper()
	var result c1cRouterInspection
	for side, ns := range cfg.Owned {
		if after {
			if _, e := os.Stat(filepath.Join("/var/run/netns", ns)); !os.IsNotExist(e) {
				result.ResidualNamespaces++
			}
			continue
		}
		data, e := runNamespaced(ns, "nft", nil, "-j", "list", "counters", "table", "ip", "wycrouter")
		if e != nil {
			t.Fatal("router external nft read failed")
		}
		var value struct {
			NFTables []struct {
				Counter *struct {
					Name    string `json:"name"`
					Packets uint64 `json:"packets"`
				} `json:"counter"`
			} `json:"nftables"`
		}
		if json.Unmarshal([]byte(data), &value) != nil {
			t.Fatal("router nft witness parse failed")
		}
		found := 0
		for _, row := range value.NFTables {
			if row.Counter != nil {
				switch row.Counter.Name {
				case "udp_out":
					result.Out[side] = row.Counter.Packets
					found++
				case "udp_in":
					result.In[side] = row.Counter.Packets
					found++
				}
			}
		}
		if found != 2 {
			t.Fatal("router OS packet counter missing")
		}
		data, e = runNamespaced(ns, "ss", nil, "-H", "-n", "-u", "-a")
		if e != nil {
			t.Fatal("router external socket read failed")
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if line != "" {
				result.Sockets[side]++
			}
		}
	}
	result.CountsPresent = !after
	if after {
		for _, ns := range []string{cfg.Host.HostNamespace} {
			data, e := runNamespaced(ns, "ip", nil, "-j", "link", "show")
			if e != nil {
				t.Fatal("router external link read failed")
			}
			var links []struct {
				Name string `json:"ifname"`
			}
			if json.Unmarshal([]byte(data), &links) != nil {
				t.Fatal("router link witness invalid")
			}
			for _, link := range links {
				if link.Name != "lo" {
					result.ResidualLinks++
				}
			}
		}
	}
	return result
}
