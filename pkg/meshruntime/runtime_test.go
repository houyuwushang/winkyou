package meshruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winkyou/pkg/mesh/shortcut"
	"winkyou/pkg/nat/puncher"
	"winkyou/pkg/solver"
	"winkyou/pkg/transport"
	"winkyou/pkg/transport/iceadapter"
)

const runtimeTestStrategyName = "runtime_test_direct"

func TestRuntimeConfigUsesFieldLivenessDefaults(t *testing.T) {
	cfg, err := (runtimeConfig{NodeID: "A", MeshListen: "off", ControlListen: "off"}).normalized()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.KeepAliveInterval != time.Second {
		t.Fatalf("keepalive default = %s, want 1s", cfg.KeepAliveInterval)
	}
	if cfg.PeerTimeout != 30*time.Second {
		t.Fatalf("peer timeout default = %s, want 30s", cfg.PeerTimeout)
	}
	if cfg.Probation != 35*time.Second {
		t.Fatalf("probation default = %s, want 35s", cfg.Probation)
	}
	if cfg.Probation <= cfg.PeerTimeout {
		t.Fatalf("probation %s does not extend beyond peer timeout %s", cfg.Probation, cfg.PeerTimeout)
	}
	if cfg.AttemptTimeout <= 2*cfg.SolveTimeout+cfg.Probation {
		t.Fatalf("attempt timeout %s does not cover solve and reconciliation windows", cfg.AttemptTimeout)
	}
	wantFrameTimeout := 2*cfg.PeerTimeout + tcpFrameRecoveryMargin
	if cfg.TCPFrameTimeout != wantFrameTimeout {
		t.Fatalf("TCP frame timeout default = %s, want %s", cfg.TCPFrameTimeout, wantFrameTimeout)
	}
}

func TestRuntimeConfigTCPFrameTimeoutCoversAsymmetricFailureWindow(t *testing.T) {
	minimum := 2*time.Second + tcpFrameRecoveryMargin
	valid, err := (runtimeConfig{
		NodeID: "A", MeshListen: "off", ControlListen: "off",
		PeerTimeout: time.Second, Probation: time.Second, TCPFrameTimeout: minimum,
	}).normalized()
	if err != nil {
		t.Fatalf("exact minimum frame timeout was rejected: %v", err)
	}
	if valid.TCPFrameTimeout != minimum {
		t.Fatalf("normalized frame timeout = %s, want %s", valid.TCPFrameTimeout, minimum)
	}
	if _, err := (runtimeConfig{
		NodeID: "A", MeshListen: "off", ControlListen: "off",
		PeerTimeout: time.Second, Probation: time.Second, TCPFrameTimeout: minimum - time.Nanosecond,
	}).normalized(); err == nil {
		t.Fatal("frame timeout below the two-peer-timeout floor was accepted")
	}
}

func TestRuntimeConfigTimeoutArithmeticSaturatesAtMaxDuration(t *testing.T) {
	cfg, err := (runtimeConfig{
		NodeID: "A", MeshListen: "off", ControlListen: "off",
		SolveTimeout: maxTimeDuration,
		PeerTimeout:  maxTimeDuration,
		Probation:    maxTimeDuration,
	}).normalized()
	if err != nil {
		t.Fatalf("normalize maximum durations: %v", err)
	}
	if cfg.AttemptTimeout != maxTimeDuration {
		t.Fatalf("saturated attempt timeout = %s, want %s", cfg.AttemptTimeout, maxTimeDuration)
	}
	if cfg.TCPFrameTimeout != maxTimeDuration {
		t.Fatalf("saturated frame timeout = %s, want %s", cfg.TCPFrameTimeout, maxTimeDuration)
	}
	if got := saturatingPositiveDurationSum(maxTimeDuration, time.Second); got != maxTimeDuration {
		t.Fatalf("maximum duration plus slack = %s, want saturation", got)
	}
	if got := saturatingPositiveDurationMultiply(maxTimeDuration, 2); got != maxTimeDuration {
		t.Fatalf("maximum duration doubled = %s, want saturation", got)
	}

	explicit, err := (runtimeConfig{
		NodeID: "A", MeshListen: "off", ControlListen: "off",
		AttemptTimeout:  maxTimeDuration,
		TCPFrameTimeout: maxTimeDuration,
	}).normalized()
	if err != nil {
		t.Fatalf("normalize explicit maximum deadlines: %v", err)
	}
	if explicit.AttemptTimeout != maxTimeDuration || explicit.TCPFrameTimeout != maxTimeDuration {
		t.Fatalf("explicit maximum deadlines changed: attempt=%s frame=%s", explicit.AttemptTimeout, explicit.TCPFrameTimeout)
	}
}

func TestRuntimeConfigNormalizesMaintainedPeersAndRecoveryBounds(t *testing.T) {
	cfg, err := (runtimeConfig{
		NodeID: "B", MeshListen: "off", ControlListen: "off",
		MaintainedPeers: []string{" C ", "A"},
	}).normalized()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cfg.MaintainedPeers, []string{"A", "C"}) {
		t.Fatalf("maintained peers = %v, want [A C]", cfg.MaintainedPeers)
	}
	for name, input := range map[string]runtimeConfig{
		"self": {
			NodeID: "A", MeshListen: "off", ControlListen: "off", MaintainedPeers: []string{"A"},
		},
		"duplicate": {
			NodeID: "A", MeshListen: "off", ControlListen: "off", MaintainedPeers: []string{"B", " B "},
		},
		"backoff": {
			NodeID: "A", MeshListen: "off", ControlListen: "off",
			RecoveryMinBackoff: time.Second, RecoveryMaxBackoff: 500 * time.Millisecond,
		},
		"frame timeout": {
			NodeID: "A", MeshListen: "off", ControlListen: "off",
			PeerTimeout: time.Second, Probation: time.Second, TCPFrameTimeout: time.Second,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := input.normalized(); err == nil {
				t.Fatalf("normalized invalid config: %+v", input)
			}
		})
	}
}

func TestRuntimeConfigValidatesSelfBootstrapInputs(t *testing.T) {
	if _, err := (runtimeConfig{
		NodeID: "A", MeshListen: "off", ControlListen: "off",
		SelfBootstrapSecretFile: "secret.txt",
	}).normalized(); err == nil {
		t.Fatal("secret file without a recovery card was accepted")
	}
	if _, err := (runtimeConfig{
		NodeID: "A", MeshListen: "off", ControlListen: "off",
		RecoveryCardPath: "recovery.json",
	}).normalized(); err == nil {
		t.Fatal("recovery card without maintained peers was accepted")
	}
	cfg, err := (runtimeConfig{
		NodeID: "A", MeshListen: "off", ControlListen: "off",
		MaintainedPeers: []string{" C ", "B"}, RecoveryCardPath: " recovery.json ",
	}).normalized()
	if err != nil {
		t.Fatalf("normalize valid self-bootstrap config: %v", err)
	}
	if cfg.RecoveryCardPath != "recovery.json" || !slices.Equal(cfg.MaintainedPeers, []string{"B", "C"}) {
		t.Fatalf("normalized self-bootstrap config = path %q peers %v", cfg.RecoveryCardPath, cfg.MaintainedPeers)
	}
}

func TestMeshRuntimeCloseRetriesPendingVirtualAliasCleanup(t *testing.T) {
	wantErr := errors.New("transient alias cleanup failure")
	aliases := &fakeVirtualAliasManager{closeErrs: []error{wantErr, nil}}
	runtime, err := newMeshRuntime(runtimeConfig{
		NodeID: "close-retry", MeshListen: "off", ControlListen: "off",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	runtime.tcp.aliasManager = aliases

	if err := runtime.Close(); !errors.Is(err, wantErr) {
		t.Fatalf("first Close() error = %v, want %v", err, wantErr)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("second Close() error = %v, want cleanup retry success", err)
	}
	if aliases.closeCalls != 2 {
		t.Fatalf("alias Close calls = %d, want 2", aliases.closeCalls)
	}
}

func TestMeshRuntimeCopiesVirtualAliasOwnershipOptions(t *testing.T) {
	aliases := &fakeVirtualAliasManager{}
	ownership := &VirtualAliasOwnership{
		Scope: "scope-a", InstanceID: "instance-a", PID: 42,
		ProcessStartID: "process-start-a", StoreDir: "ownership-store",
	}
	runtime, err := newMeshRuntimeWithOptions(runtimeConfig{
		NodeID: "A", VirtualIP: "fd00::a", MeshListen: "off", ControlListen: "off",
		VirtualTCPForwards: []string{"[fd00::b]:22=B"}, virtualAliasManager: aliases,
	}, Options{VirtualAliasOwnership: ownership})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	ownership.Scope = "mutated"
	ownership.InstanceID = "mutated"
	got := runtime.cfg.virtualAliasOwnership
	if got == nil || got.Scope != "scope-a" || got.InstanceID != "instance-a" || got.PID != 42 ||
		got.ProcessStartID != "process-start-a" || got.StoreDir != "ownership-store" {
		t.Fatalf("copied virtual alias ownership = %+v", got)
	}
}

func TestMeshRuntimeConcurrentCloseSerializesVirtualAliasCleanup(t *testing.T) {
	aliases := &fakeVirtualAliasManager{closeErrs: []error{errors.New("transient alias cleanup failure")}}
	runtime, err := newMeshRuntime(runtimeConfig{
		NodeID: "close-concurrent", MeshListen: "off", ControlListen: "off",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	runtime.tcp.aliasManager = aliases

	const callers = 8
	errs := make(chan error, callers)
	var callersWG sync.WaitGroup
	for range callers {
		callersWG.Add(1)
		go func() {
			defer callersWG.Done()
			errs <- runtime.Close()
		}()
	}
	callersWG.Wait()
	close(errs)

	failures := 0
	for err := range errs {
		if err != nil {
			failures++
		}
	}
	if failures != 1 {
		t.Fatalf("concurrent Close errors = %d, want only the initial cleanup failure", failures)
	}
	if aliases.closeCalls != callers {
		t.Fatalf("alias Close calls = %d, want one serialized attempt per caller", aliases.closeCalls)
	}
}

func TestReadSelfBootstrapSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(path, []byte("  shared secret\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	secret, err := readSelfBootstrapSecret(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(secret) != "shared secret" {
		t.Fatalf("secret = %q, want trimmed contents", secret)
	}
	if err := os.WriteFile(path, []byte(" \r\n\t"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSelfBootstrapSecret(path); err == nil {
		t.Fatal("empty secret file was accepted")
	}
}

func TestMeshRuntimeRejoinsAndReplacesBootstrapEdge(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tcpTarget := runtimeTestStartTCPEcho(t)
	defer tcpTarget.Close()

	brokerAB := newRuntimeTestBroker(t, "A", "B")
	defer brokerAB.Close()
	brokerBC := newRuntimeTestBroker(t, "B", "C")
	defer brokerBC.Close()
	factory := func(spec shortcut.AttemptSpec) (solver.Strategy, error) {
		switch {
		case runtimeTestSamePair(spec.LocalNodeID, spec.RemoteNodeID, "A", "B"):
			return &runtimeTestStrategy{spec: spec, broker: brokerAB, remoteReady: make(chan struct{}, 1)}, nil
		case runtimeTestSamePair(spec.LocalNodeID, spec.RemoteNodeID, "B", "C"):
			return &runtimeTestStrategy{spec: spec, broker: brokerBC, remoteReady: make(chan struct{}, 1)}, nil
		default:
			return nil, fmt.Errorf("no runtime test edge for %s-%s", spec.LocalNodeID, spec.RemoteNodeID)
		}
	}
	newConfig := func(nodeID string) runtimeConfig {
		return runtimeConfig{
			NodeID: nodeID, VirtualIP: "fd00::" + stringsToLower(nodeID),
			MeshListen: "127.0.0.1:0", ControlListen: "127.0.0.1:0",
			Lease: 3 * time.Second, RefreshInterval: 50 * time.Millisecond,
			DialRetry: 25 * time.Millisecond, HandshakeTimeout: time.Second,
			SolveTimeout: 2 * time.Second, Probation: 350 * time.Millisecond,
			KeepAliveInterval: 25 * time.Millisecond, PeerTimeout: 250 * time.Millisecond,
			strategyName: runtimeTestStrategyName, strategyFactory: factory,
		}
	}

	runtimeC, err := newMeshRuntime(newConfig("C"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtimeC.Close()
	if err := runtimeC.Start(ctx); err != nil {
		t.Fatal(err)
	}

	configA := newConfig("A")
	configA.InitialPeers = []string{"C=" + runtimeC.MeshAddr()}
	configA.TCPForwards = []string{"127.0.0.1:0=B"}
	runtimeA, err := newMeshRuntime(configA, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtimeA.Close()
	if err := runtimeA.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runtimeTestWait(ctx, func() bool {
		forward, forwardOK := runtimeA.node.Route("C")
		reverse, reverseOK := runtimeC.node.Route("A")
		return forwardOK && reverseOK && slices.Equal(forward.Path, []string{"A", "C"}) &&
			slices.Equal(reverse.Path, []string{"C", "A"})
	}); err != nil {
		t.Fatalf("wait A-C bootstrap: %v", err)
	}

	configB := newConfig("B")
	configB.TCPTarget = tcpTarget.Addr().String()
	runtimeB, err := newMeshRuntime(configB, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtimeB.Close()
	if err := runtimeB.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runtimeC.connectors.Add("B", runtimeB.MeshAddr()); err != nil {
		t.Fatal(err)
	}
	if err := runtimeTestWait(ctx, func() bool {
		forward, forwardOK := runtimeA.node.Route("B")
		reverse, reverseOK := runtimeB.node.Route("A")
		return forwardOK && reverseOK && slices.Equal(forward.Path, []string{"A", "C", "B"}) &&
			slices.Equal(reverse.Path, []string{"B", "C", "A"})
	}); err != nil {
		t.Fatalf("wait B rejoin: %v", err)
	}
	var probe echoResult
	statusCode := runtimeTestPostJSON(t, "http://"+runtimeA.ControlAddr()+"/v1/ping", pingRequest{
		TargetID: "B", Payload: "bootstrap", Timeout: "2s",
	}, &probe)
	if statusCode != http.StatusOK {
		t.Fatalf("bootstrap ping status = %d", statusCode)
	}
	if !slices.Equal(probe.RequestPath, []string{"A", "C", "B"}) {
		t.Fatalf("bootstrap request path = %v, want [A C B]", probe.RequestPath)
	}
	tcpForwards := runtimeA.tcpForwardSnapshot()
	if len(tcpForwards) != 1 || tcpForwards[0].RemoteID != "B" {
		t.Fatalf("A TCP forwards = %+v, want one forward to B", tcpForwards)
	}

	var first shortcutView
	statusCode = runtimeTestPostJSON(t, "http://"+runtimeA.ControlAddr()+"/v1/shortcuts", shortcutRequest{
		TargetID: "B", CoordinatorID: "C", Wait: true, Timeout: "3s",
	}, &first)
	if statusCode != http.StatusOK || first.Phase != shortcut.PhaseStable {
		t.Fatalf("A-B shortcut response = status:%d phase:%s", statusCode, first.Phase)
	}
	if err := runtimeTestWaitShortcut(ctx, first.AttemptID, runtimeA, runtimeB, runtimeC); err != nil {
		t.Fatalf("A-B shortcut consensus: %v", err)
	}
	if err := runtimeTestWait(ctx, func() bool {
		route, ok := runtimeA.node.Route("B")
		return ok && slices.Equal(route.Path, []string{"A", "B"})
	}); err != nil {
		t.Fatalf("wait direct A-B: %v", err)
	}
	if runtimeC.counters.solverForwarded.Load() < 2 {
		t.Fatalf("C forwarded %d solver messages, want at least 2", runtimeC.counters.solverForwarded.Load())
	}
	forwardedBeforeDirectTCP := runtimeC.counters.dataForwarded.Load()
	runtimeTestTCPRoundTrip(t, tcpForwards[0].Listen, []byte("direct TCP over A-B bypasses C"))
	time.Sleep(100 * time.Millisecond)
	if got := runtimeC.counters.dataForwarded.Load(); got != forwardedBeforeDirectTCP {
		t.Fatalf("C forwarded direct A-B TCP frames: before=%d after=%d", forwardedBeforeDirectTCP, got)
	}

	removeRequest, err := http.NewRequest(http.MethodDelete, "http://"+runtimeC.ControlAddr()+"/v1/peers/B", nil)
	if err != nil {
		t.Fatal(err)
	}
	removeResponse, err := http.DefaultClient.Do(removeRequest)
	if err != nil {
		t.Fatalf("remove temporary C-B connector: %v", err)
	}
	_ = removeResponse.Body.Close()
	if removeResponse.StatusCode != http.StatusOK {
		t.Fatalf("remove temporary C-B connector status = %d", removeResponse.StatusCode)
	}
	if err := runtimeTestWait(ctx, func() bool {
		forward, forwardOK := runtimeB.node.Route("C")
		reverse, reverseOK := runtimeC.node.Route("B")
		return !runtimeB.node.HasNeighbor("C") && !runtimeC.node.HasNeighbor("B") &&
			forwardOK && reverseOK && slices.Equal(forward.Path, []string{"B", "A", "C"}) &&
			slices.Equal(reverse.Path, []string{"C", "A", "B"})
	}); err != nil {
		t.Fatalf("wait B-A-C replacement: %v", err)
	}

	var second shortcutView
	statusCode = runtimeTestPostJSON(t, "http://"+runtimeB.ControlAddr()+"/v1/shortcuts", shortcutRequest{
		TargetID: "C", CoordinatorID: "A", Wait: true, Timeout: "3s",
	}, &second)
	if statusCode != http.StatusOK || second.Phase != shortcut.PhaseStable {
		t.Fatalf("B-C shortcut response = status:%d phase:%s", statusCode, second.Phase)
	}
	if err := runtimeTestWaitShortcut(ctx, second.AttemptID, runtimeA, runtimeB, runtimeC); err != nil {
		t.Fatalf("B-C shortcut consensus: %v", err)
	}
	if err := runtimeTestWait(ctx, func() bool {
		route, ok := runtimeB.node.Route("C")
		return ok && slices.Equal(route.Path, []string{"B", "C"})
	}); err != nil {
		t.Fatalf("wait direct B-C: %v", err)
	}
	for _, runtime := range []*meshRuntime{runtimeA, runtimeB, runtimeC} {
		if len(runtime.node.Neighbors()) != 2 {
			t.Fatalf("node %s neighbors = %v, want two direct peers", runtime.cfg.NodeID, runtime.node.Neighbors())
		}
	}

	// Turn a node that started with no TCP configuration into a target at
	// runtime, then add a listener on another already-running node. This is the
	// service-access path used to expose C's SSH over the live B-C mesh edge.
	var dynamicTarget tcpTargetView
	statusCode = runtimeTestJSONRequest(t, http.MethodPut,
		"http://"+runtimeC.ControlAddr()+"/v1/tcp/target",
		tcpTargetRequest{Target: tcpTarget.Addr().String()}, &dynamicTarget)
	if statusCode != http.StatusOK || dynamicTarget.Target != tcpTarget.Addr().String() ||
		dynamicTarget.Source != tcpForwardSourceRuntime {
		t.Fatalf("dynamic C target = status:%d view:%+v", statusCode, dynamicTarget)
	}
	var configuredTarget tcpTargetView
	statusCode = runtimeTestJSONRequest(t, http.MethodPut,
		"http://"+runtimeB.ControlAddr()+"/v1/tcp/target",
		tcpTargetRequest{Target: tcpTarget.Addr().String()}, &configuredTarget)
	if statusCode != http.StatusOK || configuredTarget.Source != tcpForwardSourceConfig {
		t.Fatalf("idempotent configured B target = status:%d view:%+v", statusCode, configuredTarget)
	}
	if statusCode = runtimeTestJSONRequest(t, http.MethodPut,
		"http://"+runtimeB.ControlAddr()+"/v1/tcp/target",
		tcpTargetRequest{Target: "127.0.0.1:1"}, nil); statusCode != http.StatusConflict {
		t.Fatalf("replace configured B target status = %d, want %d", statusCode, http.StatusConflict)
	}
	if statusCode = runtimeTestJSONRequest(t, http.MethodDelete,
		"http://"+runtimeB.ControlAddr()+"/v1/tcp/target", nil, nil); statusCode != http.StatusConflict {
		t.Fatalf("clear configured B target status = %d, want %d", statusCode, http.StatusConflict)
	}

	var dynamicForward tcpForwardView
	statusCode = runtimeTestJSONRequest(t, http.MethodPost,
		"http://"+runtimeB.ControlAddr()+"/v1/tcp/forwards",
		tcpForwardRequest{Listen: "127.0.0.1:0", RemoteID: "C"}, &dynamicForward)
	if statusCode != http.StatusCreated || dynamicForward.ID == "" ||
		dynamicForward.Source != tcpForwardSourceRuntime || dynamicForward.RemoteID != "C" ||
		dynamicForward.RequestedListen != "127.0.0.1:0" || dynamicForward.Listen == "127.0.0.1:0" {
		t.Fatalf("dynamic B-to-C forward = status:%d view:%+v", statusCode, dynamicForward)
	}
	forwardedByABeforeDynamicTCP := runtimeA.counters.dataForwarded.Load()
	runtimeTestTCPRoundTrip(t, dynamicForward.Listen, []byte("dynamic TCP over direct B-C bypasses A"))
	time.Sleep(100 * time.Millisecond)
	if got := runtimeA.counters.dataForwarded.Load(); got != forwardedByABeforeDynamicTCP {
		t.Fatalf("A forwarded direct B-C dynamic TCP frames: before=%d after=%d", forwardedByABeforeDynamicTCP, got)
	}

	var removedForward tcpForwardView
	statusCode = runtimeTestJSONRequest(t, http.MethodDelete,
		"http://"+runtimeB.ControlAddr()+"/v1/tcp/forwards/"+dynamicForward.ID, nil, &removedForward)
	if statusCode != http.StatusOK || removedForward.ID != dynamicForward.ID {
		t.Fatalf("remove dynamic B-to-C forward = status:%d view:%+v", statusCode, removedForward)
	}
	if statusCode = runtimeTestJSONRequest(t, http.MethodDelete,
		"http://"+runtimeB.ControlAddr()+"/v1/tcp/forwards/"+dynamicForward.ID,
		nil, nil); statusCode != http.StatusNotFound {
		t.Fatalf("remove missing dynamic forward status = %d, want %d", statusCode, http.StatusNotFound)
	}
	if statusCode = runtimeTestJSONRequest(t, http.MethodDelete,
		"http://"+runtimeA.ControlAddr()+"/v1/tcp/forwards/"+tcpForwards[0].ID,
		nil, nil); statusCode != http.StatusConflict {
		t.Fatalf("remove configured forward status = %d, want %d", statusCode, http.StatusConflict)
	}
	if conn, dialErr := net.DialTimeout("tcp", dynamicForward.Listen, 200*time.Millisecond); dialErr == nil {
		_ = conn.Close()
		t.Fatalf("removed dynamic forward %s still accepts connections", dynamicForward.Listen)
	}

	var clearedTarget tcpTargetView
	statusCode = runtimeTestJSONRequest(t, http.MethodDelete,
		"http://"+runtimeC.ControlAddr()+"/v1/tcp/target", nil, &clearedTarget)
	if statusCode != http.StatusOK || clearedTarget.Target != "" || clearedTarget.Source != "" {
		t.Fatalf("clear dynamic C target = status:%d view:%+v", statusCode, clearedTarget)
	}
	// B's configured target and A's original configured listener remain intact.
	runtimeTestTCPRoundTrip(t, tcpForwards[0].Listen, []byte("configured A-B TCP survives dynamic B-C lifecycle"))

	response, err := http.Get("http://" + runtimeA.ControlAddr() + "/v1/status")
	if err != nil {
		t.Fatalf("GET A status: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET A status code = %d", response.StatusCode)
	}
	var status statusView
	if err := json.NewDecoder(response.Body).Decode(&status); err != nil {
		t.Fatalf("decode A status: %v", err)
	}
	if status.NodeID != "A" || len(status.Neighbors) != 2 || status.InfrastructureUp || len(status.TCPForwards) != 1 {
		t.Fatalf("A status = node:%s neighbors:%v TCP:%v infrastructure:%t", status.NodeID, status.Neighbors, status.TCPForwards, status.InfrastructureUp)
	}
}

func runtimeTestStartTCPEcho(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buffer := make([]byte, 32<<10)
				for {
					n, err := conn.Read(buffer)
					if n > 0 {
						if _, writeErr := conn.Write(buffer[:n]); writeErr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return listener
}

func runtimeTestTCPRoundTrip(t *testing.T, address string, payload []byte) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatalf("dial routed TCP listener %s: %v", address, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write routed TCP payload: %v", err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatalf("read routed TCP payload: %v", err)
	}
	if !bytes.Equal(response, payload) {
		t.Fatalf("routed TCP response = %q, want %q", response, payload)
	}
}

func runtimeTestPostJSON(t *testing.T, url string, requestBody, responseBody any) int {
	t.Helper()
	return runtimeTestJSONRequest(t, http.MethodPost, url, requestBody, responseBody)
}

func runtimeTestJSONRequest(t *testing.T, method, url string, requestBody, responseBody any) int {
	t.Helper()
	raw, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(method, url, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if responseBody != nil {
		if err := json.NewDecoder(response.Body).Decode(responseBody); err != nil {
			t.Fatalf("decode %s response: %v", url, err)
		}
	}
	return response.StatusCode
}

func stringsToLower(value string) string {
	if value == "A" {
		return "a"
	}
	if value == "B" {
		return "b"
	}
	return "c"
}

func runtimeTestWait(ctx context.Context, condition func() bool) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if condition() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func runtimeTestWaitShortcut(ctx context.Context, attemptID string, runtimes ...*meshRuntime) error {
	return runtimeTestWait(ctx, func() bool {
		for _, runtime := range runtimes {
			status, ok := runtime.shortcuts.Status(attemptID)
			if !ok || status.Phase != shortcut.PhaseStable {
				return false
			}
		}
		return true
	})
}

func runtimeTestSamePair(left, right, wantLeft, wantRight string) bool {
	return (left == wantLeft && right == wantRight) || (left == wantRight && right == wantLeft)
}

type runtimeTestStrategy struct {
	spec        shortcut.AttemptSpec
	broker      *runtimeTestBroker
	remoteReady chan struct{}
}

func (s *runtimeTestStrategy) Name() string { return runtimeTestStrategyName }

func (s *runtimeTestStrategy) Plan(context.Context, solver.SolveInput) ([]solver.Plan, error) {
	return []solver.Plan{{ID: "runtime-test/direct", Strategy: runtimeTestStrategyName}}, nil
}

func (s *runtimeTestStrategy) Execute(ctx context.Context, session solver.SessionIO, _ solver.Plan) (solver.Result, error) {
	if err := session.Send(ctx, solver.Message{
		Kind: solver.MessageKindStrategy, Namespace: runtimeTestStrategyName, Type: "ready",
		Payload: []byte(s.spec.LocalNodeID), ReceivedAt: time.Now().UTC(),
	}); err != nil {
		return solver.Result{}, err
	}
	select {
	case <-ctx.Done():
		return solver.Result{}, ctx.Err()
	case <-s.remoteReady:
	}
	packetTransport, err := s.broker.take(s.spec.LocalNodeID)
	if err != nil {
		return solver.Result{}, err
	}
	return solver.Result{
		Transport: packetTransport,
		Summary: solver.PathSummary{
			PathID: "runtime-test/direct", ConnectionType: "direct", RemoteAddr: packetTransport.RemoteAddr(),
			Role: solver.PathRoleProtectedDirect,
		},
	}, nil
}

func (s *runtimeTestStrategy) HandleMessage(_ context.Context, _ solver.SessionIO, message solver.Message) error {
	if message.Namespace == runtimeTestStrategyName && message.Type == "ready" {
		select {
		case s.remoteReady <- struct{}{}:
		default:
		}
	}
	return nil
}

func (s *runtimeTestStrategy) Close() error { return nil }

type runtimeTestBroker struct {
	t          *testing.T
	mu         sync.Mutex
	conns      map[string]*net.UDPConn
	peers      map[string]*net.UDPAddr
	taken      map[string]bool
	transports map[string]*runtimeTestPacketTransport
}

type runtimeTestPacketTransport struct {
	transport.PacketTransport
	dropWrites atomic.Bool
}

func (t *runtimeTestPacketTransport) WritePacket(ctx context.Context, packet []byte) error {
	if t.dropWrites.Load() {
		return nil
	}
	return t.PacketTransport.WritePacket(ctx, packet)
}

func newRuntimeTestBroker(t *testing.T, leftID, rightID string) *runtimeTestBroker {
	t.Helper()
	left, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	right, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_ = left.Close()
		t.Fatal(err)
	}
	return &runtimeTestBroker{
		t:     t,
		conns: map[string]*net.UDPConn{leftID: left, rightID: right},
		peers: map[string]*net.UDPAddr{
			leftID:  runtimeTestCopyUDP(right.LocalAddr().(*net.UDPAddr)),
			rightID: runtimeTestCopyUDP(left.LocalAddr().(*net.UDPAddr)),
		},
		taken: make(map[string]bool), transports: make(map[string]*runtimeTestPacketTransport),
	}
}

func (b *runtimeTestBroker) take(nodeID string) (transport.PacketTransport, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	conn, peer := b.conns[nodeID], b.peers[nodeID]
	if conn == nil || peer == nil || b.taken[nodeID] {
		return nil, fmt.Errorf("runtime test edge for %s unavailable", nodeID)
	}
	b.taken[nodeID] = true
	result := &puncher.Result{
		Conn: conn, LocalAddr: runtimeTestCopyUDP(conn.LocalAddr().(*net.UDPAddr)), RemoteAddr: runtimeTestCopyUDP(peer),
	}
	wrapped := &runtimeTestPacketTransport{PacketTransport: iceadapter.New(result.Connected(), "runtime-test/direct")}
	if b.transports == nil {
		b.transports = make(map[string]*runtimeTestPacketTransport)
	}
	b.transports[nodeID] = wrapped
	return wrapped, nil
}

func (b *runtimeTestBroker) setDropWrites(nodeID string, drop bool) bool {
	b.mu.Lock()
	packetTransport := b.transports[nodeID]
	b.mu.Unlock()
	if packetTransport == nil {
		return false
	}
	packetTransport.dropWrites.Store(drop)
	return true
}

func (b *runtimeTestBroker) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, conn := range b.conns {
		_ = conn.Close()
	}
}

func runtimeTestCopyUDP(address *net.UDPAddr) *net.UDPAddr {
	return &net.UDPAddr{IP: append(net.IP(nil), address.IP...), Port: address.Port, Zone: address.Zone}
}

var _ solver.Strategy = (*runtimeTestStrategy)(nil)
var _ solver.MessageHandler = (*runtimeTestStrategy)(nil)
