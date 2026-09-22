//go:build linux && natlab && c1bproof && fieldc1c

package natlab

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"winkyou/internal/c1crouter"
	"winkyou/internal/v2/gatecorchestrator"
)

const c1cRouterHostEnv = "WINKYOU_C1C_ROUTER_HOST"

type c1cRouterInspection struct {
	Out                [2]uint64   `json:"out"`
	In                 [2]uint64   `json:"in"`
	Sockets            [2]int      `json:"sockets"`
	CountsPresent      bool        `json:"counts_present"`
	ResidualNamespaces int         `json:"residual_namespaces"`
	ResidualLinks      int         `json:"residual_links"`
	AnchorLinks        [3][]string `json:"anchor_links"`
}

// Only this derived, fixed-vocabulary shape may leave the private fixture.
// Missing/invalid observations remain null, not a fabricated zero residue.
type c1cRouterFailureSummary struct {
	Source    string  `json:"source"`
	Stage     string  `json:"stage"`
	Class     string  `json:"class"`
	Socket    *uint64 `json:"socket_residue"`
	Process   *uint64 `json:"process_residue"`
	Conntrack *uint64 `json:"conntrack_residue"`
	Namespace *uint64 `json:"namespace_residue"`
	Veth      *uint64 `json:"veth_residue"`
	NFT       *uint64 `json:"nft_residue"`
}

type c1cRouterHostStatus struct {
	TeardownExit int    `json:"teardown_exit"`
	RunExit      int    `json:"run_exit"`
	Wait         string `json:"wait"`
}

func c1cRouterSummaryWitness(source, path string) c1cRouterFailureSummary {
	w := c1cRouterFailureSummary{Source: source, Stage: "unknown", Class: "unavailable"}
	b, err := os.ReadFile(path)
	if err != nil {
		return w
	}
	var s c1crouter.Summary
	if json.Unmarshal(b, &s) != nil {
		w.Class = "invalid"
		return w
	}
	if _, err := s.Encode(); err != nil {
		w.Class = "invalid"
		return w
	}
	w.Stage, w.Class = s.Stage, s.Class
	w.Socket, w.Process, w.Conntrack = s.Counts.SocketResidue, s.Counts.ProcessResidue, s.Counts.ConntrackResidue
	w.Namespace, w.Veth, w.NFT = s.Counts.NamespaceResidue, s.Counts.VethResidue, s.Counts.NFTResidue
	return w
}

func c1cRouterCount(p *uint64) string {
	if p == nil {
		return "unknown"
	}
	return fmt.Sprintf("%d", *p)
}

func c1cRouterLinkNames(namespace string) ([]string, error) {
	// Diagnostics are read-only and bounded even after a failed teardown.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, "ip", "netns", "exec", namespace, "ip", "-j", "link", "show").Output()
	if err != nil {
		return nil, err
	}
	var links []struct {
		Name string `json:"ifname"`
	}
	if err := json.Unmarshal(b, &links); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(links))
	for _, link := range links {
		switch link.Name {
		case "lo", "wyca", "wycb", "wycta", "wyctb":
			names = append(names, link.Name)
		default:
			names = append(names, "other") // never publish an arbitrary interface identity
		}
	}
	sort.Strings(names)
	return names, nil
}

func c1cRouterPublishFailure(t *testing.T, cfg c1cRouterHost) {
	t.Helper()
	var status c1cRouterHostStatus
	status.TeardownExit, status.RunExit, status.Wait = -1, -1, "unknown"
	if b, err := os.ReadFile(cfg.Summary + ".host-status.json"); err == nil {
		var saved c1cRouterHostStatus
		if json.Unmarshal(b, &saved) == nil && saved.TeardownExit >= -1 && saved.TeardownExit <= 255 && saved.RunExit >= -1 && saved.RunExit <= 255 && (saved.Wait == "done" || saved.Wait == "timeout" || saved.Wait == "not_waited") {
			status = saved
		}
	}
	t.Logf("ROUTER_HOST teardown_exit=%d run_exit=%d wait=%s", status.TeardownExit, status.RunExit, status.Wait)
	witnesses := []c1cRouterFailureSummary{c1cRouterSummaryWitness("summary", cfg.Summary), c1cRouterSummaryWitness("teardown", cfg.Teardown)}
	for i, path := range []string{cfg.Inspection, cfg.Inspection + ".after"} {
		w := c1cRouterFailureSummary{Source: []string{"inspection", "after"}[i], Stage: []string{"before", "after"}[i], Class: "unavailable"}
		var value c1cRouterInspection
		if b, err := os.ReadFile(path); err == nil {
			if json.Unmarshal(b, &value) == nil {
				w.Class = "available"
				if i == 1 && value.ResidualNamespaces >= 0 && value.ResidualLinks >= 0 {
					n, v := uint64(value.ResidualNamespaces), uint64(value.ResidualLinks)
					w.Namespace, w.Veth = &n, &v
				} else if i == 0 && value.CountsPresent && value.Sockets[0] >= 0 && value.Sockets[1] >= 0 {
					n := uint64(value.Sockets[0]) + uint64(value.Sockets[1])
					w.Socket = &n
				}
			} else {
				w.Class = "invalid"
			}
		}
		witnesses = append(witnesses, w)
	}
	for _, w := range witnesses {
		t.Logf("ROUTER_FAILURE source=%s stage=%s class=%s sockets=%s processes=%s conntrack=%s namespaces=%s veth=%s nft=%s", w.Source, w.Stage, w.Class, c1cRouterCount(w.Socket), c1cRouterCount(w.Process), c1cRouterCount(w.Conntrack), c1cRouterCount(w.Namespace), c1cRouterCount(w.Veth), c1cRouterCount(w.NFT))
		if err := c1cRouterWritePublicFailure(w); err != nil {
			t.Error("router derived failure evidence unavailable")
		}
	}
	for i, ns := range cfg.Anchors {
		names, err := c1cRouterLinkNames(ns)
		t.Logf("ROUTER_ANCHOR side=%d available=%t ifnames=%v", i, err == nil, names)
	}
}

func c1cRouterWritePublicFailure(w c1cRouterFailureSummary) error {
	// A new exclusive file per observation prevents stale artifacts from being
	// overwritten. Root fixtures explicitly make only sanitized files readable
	// by the unprivileged CI upload step; private evidence stays mode 0600.
	dir := filepath.Join(os.TempDir(), "winkyou-c1c-router-failure")
	if err := os.Mkdir(dir, 0o755); err != nil && !os.IsExist(err) {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("failure evidence directory invalid")
	}
	b, err := json.Marshal(w)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "failure-*.json")
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(append(b, '\n')); err != nil {
		return err
	}
	return f.Chmod(0o644)
}

func c1cRouterHostFailure(t *testing.T, cfg c1cRouterHost, status c1cRouterHostStatus) {
	t.Helper()
	if err := c1cRouterSaveHostFailure(cfg, status); err != nil {
		t.Error("router private failure copy unavailable")
	}
	t.Fatalf("ROUTER_HOST teardown_exit=%d run_exit=%d wait=%s", status.TeardownExit, status.RunExit, status.Wait)
}

func c1cRouterSaveHostFailure(cfg c1cRouterHost, status c1cRouterHostStatus) error {
	// Preserve the exact stdout bytes, including an empty/partial summary.
	b, err := os.ReadFile(cfg.Summary)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(filepath.Dir(cfg.Summary), "host-failure.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(b)
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	return writeN1JSON(cfg.Summary+".host-status.json", status)
}

func c1cRouterExit(err error) int {
	if err == nil {
		return 0
	}
	if e, ok := err.(*exec.ExitError); ok && e.ExitCode() >= 0 {
		return e.ExitCode()
	}
	return -1
}

func TestLinuxC1cRouterFullInstances(t *testing.T) {
	if os.Getenv("WINKYOU_C1C_ROUTER_REQUIRED") != "1" {
		t.Skip("requires isolated router proof job")
	}
	requireGateB3Environment(t)
	requireGateB3HostConntrackGuard(t)
	if !t.Run("failure-summary-contract", TestC1cRouterFailureSummaryProjection) || !t.Run("host-failure-contract", TestC1cRouterHostFailureCopy) {
		t.FailNow()
	}
	if !t.Run("synchronous-delete-contract", TestC1cRouterSynchronousDeleteContract) {
		t.FailNow()
	}
	c1cRouterCleanupReproductionBatches(t)
	fieldBinary, routerBinary := os.Getenv("WINKYOU_FIELD_C1C_BINARY"), os.Getenv("WINKYOU_C1C_ROUTER_BINARY")
	if !filepath.IsAbs(fieldBinary) || !filepath.IsAbs(routerBinary) {
		t.Fatal("router proof images unavailable")
	}
	seenInstances := make(map[string]bool)
	for sample := 1; sample <= 3; sample++ {
		if !t.Run(fmt.Sprintf("fresh-%d", sample), func(t *testing.T) { testC1cRouterFullInstance(t, fieldBinary, routerBinary, seenInstances) }) {
			t.FailNow()
		}
	}
}

func testC1cRouterFullInstance(t *testing.T, fieldBinary, routerBinary string, seenInstances map[string]bool) {
	armGateB3KernelReleaseMargin(t)
	topology := c1cRouterAnchors(t)
	t.Cleanup(func() { cleanupGateC1bEndpointProcesses(t, topology) })
	profile := gateC1bProfiles[0]
	// The fixture's label seeds its synthetic credential/attempt/channel IDs.
	// Keep the frozen predictive profile and cost but allocate a distinct set
	// for each fresh namespace; no ledger reset or artifact reuse proves a run.
	profile.name += "-router-" + topology.clientA
	configs := fieldC1cFixture(t, gateC1bFixture(t, topology, c1cRouterObserverTopology(), profile, false), profile, fieldBinary)
	router := c1cRouterFixture(t, topology, configs, routerBinary)
	defer func() {
		if t.Failed() {
			c1cRouterPublishFailure(t, router)
		}
	}()
	instance := filepath.Base(router.Instance)
	if seenInstances[instance] {
		t.Fatal("router fresh proof reused an authorization instance")
	}
	seenInstances[instance] = true
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
	anchorConfiguration := c1cRouterProtectedAnchorConfiguration(t, router)
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
	var resolution struct {
		Schema         string `json:"schema"`
		WorkerReported bool   `json:"worker_reported"`
		WorkerClass    string `json:"worker_class"`
		CleanAtExit    bool   `json:"clean_at_exit"`
		ChildExitError bool   `json:"child_exit_error"`
		Backstop       string `json:"backstop_cleanup"`
		BackstopClass  string `json:"backstop_class"`
		TerminalClass  string `json:"terminal_class"`
		Rule           int    `json:"rule"`
	}
	resolutionPath := filepath.Join(router.Evidence, "terminal-resolution.json")
	c1cRouterRead(t, resolutionPath, &resolution)
	if stat, err := os.Stat(resolutionPath); err != nil || !stat.Mode().IsRegular() || stat.Mode().Perm() != 0o600 {
		t.Fatal("router terminal resolution is not a private regular file")
	}
	if resolution.Schema != "winkyou-router-terminal-resolution/1" || !resolution.WorkerReported ||
		resolution.WorkerClass != "cancelled" || !resolution.CleanAtExit || resolution.ChildExitError ||
		resolution.Backstop != "not_needed" || resolution.BackstopClass != "" ||
		resolution.TerminalClass != "cancelled" || resolution.Rule != 4 || terminal.Class != resolution.TerminalClass {
		t.Fatal("router full-instance terminal resolution mismatch")
	}
	// Only already-validated fixed labels leave the private evidence boundary.
	t.Logf("ROUTER_RESOLUTION scenario=full worker_reported=%t worker_class=%s clean_at_exit=%t child_exit_error=%t backstop_cleanup=%s backstop_class=empty terminal_class=%s rule=%d", resolution.WorkerReported, resolution.WorkerClass, resolution.CleanAtExit, resolution.ChildExitError, resolution.Backstop, resolution.TerminalClass, resolution.Rule)
	c1cRouterRead(t, router.Inspection+".after", &inspection)
	if inspection.ResidualLinks != 0 || inspection.ResidualNamespaces != 0 {
		t.Fatal("external router residue")
	}
	// run's zero-residue summary precedes teardown's second cleanup. Both
	// summaries above must independently prove all six zeros. Also protect the
	// surviving loopback/rules/nft configuration; only owned veth resources and
	// the recorded ip_forward restoration are excluded from this comparison.
	if after := c1cRouterProtectedAnchorConfiguration(t, router); after != anchorConfiguration {
		t.Fatal("router second cleanup changed protected anchor configuration")
	}
	var ownership struct {
		Clean bool `json:"clean"`
	}
	c1cRouterRead(t, filepath.Join(router.Evidence, "ownership.json"), &ownership)
	if !ownership.Clean {
		t.Fatal("router clean journal witness absent")
	}
	t.Log("ROUTER_IDEMPOTENCE run_zero=1 teardown_zero=1 anchor_config_unchanged=1")
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

func c1cRouterProtectedAnchorConfiguration(t *testing.T, cfg c1cRouterHost) [3][3]string {
	t.Helper()
	var configuration [3][3]string
	for i, ns := range cfg.Anchors {
		for j, argv := range [][]string{{"ip", "-j", "address", "show", "dev", "lo"}, {"ip", "-j", "rule", "show"}, {"nft", "-j", "list", "tables"}} {
			b, err := runNamespaced(ns, argv[0], nil, argv[1:]...)
			if err != nil || !json.Valid([]byte(b)) {
				t.Fatal("router protected anchor read unavailable")
			}
			configuration[i][j] = b
		}
	}
	return configuration
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
				if err := teardown.Run(); err != nil {
					_ = teardownOutput.Close()
					c1cRouterHostFailure(t, cfg, c1cRouterHostStatus{TeardownExit: c1cRouterExit(err), RunExit: -1, Wait: "not_waited"})
				}
				_ = teardownOutput.Close()
				select {
				case e := <-done:
					if e != nil {
						c1cRouterHostFailure(t, cfg, c1cRouterHostStatus{TeardownExit: 0, RunExit: c1cRouterExit(e), Wait: "done"})
					}
				case <-time.After(3 * time.Second):
					c1cRouterHostFailure(t, cfg, c1cRouterHostStatus{TeardownExit: 0, RunExit: -1, Wait: "timeout"})
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
		for i, ns := range cfg.Anchors {
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
			result.AnchorLinks[i], e = c1cRouterLinkNames(ns)
			if e != nil {
				t.Fatal("router anchor names unavailable")
			}
		}
	}
	return result
}

func TestC1cRouterFailureSummaryProjection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "summary.json")
	unknown := c1cRouterSummaryWitness("summary", path)
	if unknown.Class != "unavailable" || unknown.Socket != nil {
		t.Fatal("missing witness fabricated zero")
	}
	raw := []byte(`{"profile":"predictive_edm/1","stage":"terminal","class":"c1c_router_drain_failed","counts":{"socket_residue":0},"private":"synthetic-private-marker"}`)
	if os.WriteFile(path, raw, 0o600) != nil {
		t.Fatal("fixture write failed")
	}
	w := c1cRouterSummaryWitness("summary", path)
	b, err := json.Marshal(w)
	if err != nil || w.Class != "c1c_router_drain_failed" || w.Socket == nil || *w.Socket != 0 || w.Veth != nil || bytes.Contains(b, []byte("synthetic-private-marker")) {
		t.Fatal("summary projection violated evidence or privacy")
	}
	if os.WriteFile(path, []byte(`{"class":"synthetic-private-marker"}`), 0o600) != nil {
		t.Fatal("fixture write failed")
	}
	w = c1cRouterSummaryWitness("summary", path)
	if w.Class != "invalid" || w.Socket != nil {
		t.Fatal("untrusted summary escaped projection")
	}
}

func TestC1cRouterHostFailureCopy(t *testing.T) {
	for _, raw := range [][]byte{nil, []byte(`{"partial":`), []byte("{\"class\":\"c1c_router_drain_failed\"}\n")} {
		dir := t.TempDir()
		cfg := c1cRouterHost{Summary: filepath.Join(dir, "summary.json")}
		if os.WriteFile(cfg.Summary, raw, 0o600) != nil {
			t.Fatal("fixture write failed")
		}
		status := c1cRouterHostStatus{TeardownExit: 0, RunExit: 1, Wait: "done"}
		if c1cRouterSaveHostFailure(cfg, status) != nil {
			t.Fatal("host failure copy failed")
		}
		copyPath := filepath.Join(dir, "host-failure.json")
		got, err := os.ReadFile(copyPath)
		info, statErr := os.Stat(copyPath)
		if err != nil || statErr != nil || info.Mode().Perm() != 0o600 || !bytes.Equal(raw, got) {
			t.Fatal("raw failure bytes or private mode changed")
		}
		if c1cRouterSaveHostFailure(cfg, status) == nil {
			t.Fatal("first failure evidence overwritten")
		}
	}
}

// The minimal reproducer runs before the endpoint matrix, under its existing
// root/isolation authorization. It neither changes the workflow's required
// command/count/cap nor creates a route, address, socket or packet.
func c1cRouterCleanupReproductionBatches(t *testing.T) {
	t.Helper()
	for _, mode := range []string{"idle", "busy"} {
		cmd := exec.Command(os.Args[0], "-test.v", "-test.run=^TestC1cRouterCleanupReproduction$", "-test.count=200", "-test.timeout=2m")
		cmd.Env = append(os.Environ(), "WINKYOU_C1C_ROUTER_REPRO="+mode, "GOMAXPROCS=2")
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS | unix.CLONE_NEWNET, Pdeathsig: syscall.SIGKILL}
		start := time.Now()
		output, err := cmd.CombinedOutput()
		// Do not publish raw child output (testing's source paths are private).
		var samples, hits, failures int
		for _, line := range strings.Split(string(output), "\n") {
			if strings.HasPrefix(line, "--- FAIL: TestC1cRouterCleanupReproduction ") {
				failures++
			}
			if index := strings.Index(line, "ROUTER_REPRO peer_residue="); index >= 0 {
				var n int
				if _, e := fmt.Sscanf(line[index:], "ROUTER_REPRO peer_residue=%d", &n); e == nil && (n == 0 || n == 1) {
					samples++
					hits += n
				}
			}
		}
		t.Logf("ROUTER_REPRO_BATCH mode=%s samples=%d hits=%d child_exit=%d duration_ns=%d", mode, samples, hits, c1cRouterExit(err), time.Since(start).Nanoseconds())
		// The preceding witness-only commit retained the original RED batches.
		// After explicit link deletion every sample is a required zero-residue
		// regression; an observed hit must fail the enclosing required job too.
		if samples != 200 || failures != 0 || hits != 0 || err != nil {
			t.Fatal("router synchronous cleanup regression failed")
		}
	}
}

func TestC1cRouterCleanupReproduction(t *testing.T) {
	mode := os.Getenv("WINKYOU_C1C_ROUTER_REPRO")
	if mode == "" {
		t.Skip("isolated cleanup reproduction subprocess only")
	}
	var current, initial unix.Stat_t
	if (mode != "idle" && mode != "busy") || os.Getenv("WINKYOU_C1C_ROUTER_REQUIRED") != "1" || os.Geteuid() != 0 || unix.Stat("/proc/self/ns/net", &current) != nil || unix.Stat("/proc/1/ns/net", &initial) != nil || current.Ino == initial.Ino {
		t.Fatal("router reproduction isolation missing")
	}
	if unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, "") != nil {
		t.Fatal("router reproduction mount isolation failed")
	}
	registry := t.TempDir()
	if unix.Mount(registry, "/var/run/netns", "", unix.MS_BIND, "") != nil {
		t.Fatal("router reproduction registry failed")
	}
	defer func() {
		if unix.Unmount("/var/run/netns", 0) != nil {
			t.Error("router reproduction registry residue")
		}
	}()
	if mode == "busy" {
		if runtime.GOMAXPROCS(0) != 2 {
			t.Fatal("router stress CPU contract changed")
		}
		stop := make(chan struct{})
		var workers sync.WaitGroup
		for i := 0; i < 2; i++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				for {
					select {
					case <-stop:
						return
					default:
					}
				}
			}()
		}
		defer func() { close(stop); workers.Wait() }()
	}
	const owned, anchor = "wy169owned", "wy169anchor"
	for _, ns := range []string{owned, anchor} {
		if _, err := runCommand("ip", "netns", "add", ns); err != nil {
			t.Fatal("router reproduction namespace creation failed")
		}
		name := ns
		defer func() {
			if _, err := os.Lstat(filepath.Join("/var/run/netns", name)); !os.IsNotExist(err) {
				if _, err := runCommand("ip", "netns", "del", name); err != nil {
					t.Error("router reproduction namespace residue")
				}
			}
		}()
	}
	ownedFile, err := os.Open(filepath.Join("/var/run/netns", owned))
	if err != nil {
		t.Fatal("router reproduction owned reference failed")
	}
	defer ownedFile.Close()
	anchorFile, err := os.Open(filepath.Join("/var/run/netns", anchor))
	if err != nil {
		t.Fatal("router reproduction anchor reference failed")
	}
	defer anchorFile.Close()
	if _, err := runNamespaced(owned, "ip", nil, "link", "add", "lan0", "type", "veth", "peer", "name", "peer0", "netns", anchor); err != nil {
		t.Fatal("router reproduction veth creation failed")
	}
	// Match production order, including readback/flush latency. No
	// held extra reference, artificial cleanup delay or polling manufactures a
	// residual. There is no packet source and no configured address/route.
	if _, err := runNamespaced(owned, "ip", nil, "-j", "link", "show"); err != nil {
		t.Fatal("router reproduction link read failed")
	}
	if _, err := runNamespaced(owned, "ip", nil, "link", "set", "lan0", "down"); err != nil {
		t.Fatal("router reproduction down failed")
	}
	if _, err := runNamespaced(owned, "ip", nil, "link", "del", "lan0"); err != nil {
		t.Fatal("router reproduction synchronous delete failed")
	}
	if b, err := runNamespaced(owned, "ss", nil, "-H", "-n", "-a", "-u", "-t"); err != nil || strings.TrimSpace(b) != "" {
		t.Fatal("router reproduction socket residue")
	}
	if b, err := runCommand("ip", "netns", "pids", owned); err != nil || strings.TrimSpace(b) != "" {
		t.Fatal("router reproduction process residue")
	}
	if _, err := runNamespaced(owned, "conntrack", nil, "-F"); err != nil {
		t.Fatal("router reproduction flush failed")
	}
	if b, err := runNamespaced(owned, "conntrack", nil, "-C"); err != nil || strings.TrimSpace(b) != "0" {
		t.Fatal("router reproduction conntrack residue")
	}
	for i := 0; i < 2; i++ {
		if _, err := runNamespaced(owned, "nft", nil, "-j", "list", "tables"); err != nil {
			t.Fatal("router reproduction nft read failed")
		}
	}
	if ownedFile.Close() != nil {
		t.Fatal("router reproduction close failed")
	}
	path := filepath.Join("/var/run/netns", owned)
	if unix.Unmount(path, 0) != nil || os.Remove(path) != nil {
		t.Fatal("router reproduction namespace removal failed")
	}
	data, err := runNamespaced(anchor, "ip", nil, "-j", "link", "show")
	var links []struct {
		Name string `json:"ifname"`
	}
	if err != nil || json.Unmarshal([]byte(data), &links) != nil {
		t.Fatal("router reproduction peer read failed")
	}
	residual := 0
	for _, link := range links {
		if link.Name == "peer0" {
			residual++
		} else if link.Name != "lo" {
			t.Fatal("router reproduction unexpected link")
		}
	}
	t.Logf("ROUTER_REPRO peer_residue=%d", residual)
	if residual != 0 {
		t.Error("router asynchronous peer residue observed")
	}
}

func TestC1cRouterSynchronousDeleteContract(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("router cleanup source unavailable")
	}
	b, err := os.ReadFile(filepath.Join(filepath.Dir(source), "..", "..", "internal", "c1crouter", "cleanup_linux.go"))
	if err != nil {
		t.Fatal("router cleanup source unavailable")
	}
	valid := func(s string) bool {
		down := strings.Index(s, `"link", "set", link.Name, "down"`)
		del := strings.Index(s, `"link", "del", link.Name`)
		readback := strings.Index(s, `"ss", nil, "-H"`)
		unmount := strings.Index(s, "unix.Unmount(path, 0)")
		return down >= 0 && del > down && readback > del && unmount > readback && strings.Contains(s[del:readback], "result = errors.Join(result, ErrDrain)")
	}
	s := string(b)
	if !valid(s) {
		t.Fatal("owned synchronous deletion is not before namespace destruction")
	}
	if valid(strings.ReplaceAll(s, `"link", "del", link.Name`, `"link", "set", link.Name, "down"`)) {
		t.Fatal("missing synchronous delete mutation accepted")
	}
	start, end := strings.Index(s, `"link", "del", link.Name`), strings.Index(s, `"ss", nil, "-H"`)
	mutation := s[:start] + strings.Replace(s[start:end], "errors.Join(result, ErrDrain)", "result", 1) + s[end:]
	if valid(mutation) {
		t.Fatal("ignored delete error mutation accepted")
	}
}
