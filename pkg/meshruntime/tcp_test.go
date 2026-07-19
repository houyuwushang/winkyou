package meshruntime

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"winkyou/pkg/mesh"
)

func TestTCPRuntimeAlwaysExistsAndDynamicForwardLifecycle(t *testing.T) {
	runtime := newTCPTestRuntime(t, runtimeConfig{NodeID: "A"})
	if runtime == nil {
		t.Fatal("newTCPRuntime() = nil without startup TCP configuration")
	}
	if _, err := runtime.AddForward("127.0.0.1:0", "B", tcpForwardSourceRuntime); !errors.Is(err, ErrTCPRuntimeNotStarted) {
		t.Fatalf("AddForward() before Start error = %v, want ErrTCPRuntimeNotStarted", err)
	}
	if err := runtime.Start(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	view, err := runtime.AddForward("127.0.0.1:0", "B", "")
	if err != nil {
		t.Fatal(err)
	}
	if view.ID != "runtime-001" || view.Source != tcpForwardSourceRuntime ||
		view.RequestedListen != "127.0.0.1:0" || view.Listen == view.RequestedListen || view.RemoteID != "B" {
		t.Fatalf("dynamic view = %+v", view)
	}
	if got := runtime.Snapshot(); len(got) != 1 || got[0] != view {
		t.Fatalf("Snapshot() = %+v, want %+v", got, view)
	}
	removed, err := runtime.RemoveForward(view.ID)
	if err != nil || removed != view {
		t.Fatalf("RemoveForward() = %+v, %v, want %+v, nil", removed, err, view)
	}
	if _, err := runtime.RemoveForward(view.ID); !errors.Is(err, ErrTCPForwardNotFound) {
		t.Fatalf("second RemoveForward() error = %v, want ErrTCPForwardNotFound", err)
	}
}

func TestNormalizeTCPConfigUsesRuntimeLoopbackRules(t *testing.T) {
	for _, listen := range []string{"127.0.0.2:22025", "LOCALHOST:22025", "[::1]:22025"} {
		t.Run(listen, func(t *testing.T) {
			config := runtimeConfig{NodeID: "A", TCPForwards: []string{listen + "=B"}}
			if err := normalizeTCPConfig(&config); err != nil {
				t.Fatalf("normalizeTCPConfig(%q) error = %v", listen, err)
			}
		})
	}

	config := runtimeConfig{NodeID: "A", TCPForwards: []string{"192.0.2.1:22025=B"}}
	if err := normalizeTCPConfig(&config); err == nil {
		t.Fatal("normalizeTCPConfig(non-loopback) error = nil")
	}
}

func TestNormalizeVirtualTCPConfigUsesIPv6ULAAndExplicitRemote(t *testing.T) {
	config := runtimeConfig{
		NodeID: "A", VirtualIP: "fd00::a",
		VirtualTCPForwards: []string{"[fd00::b]:22=B", "[fd00::b]:8080=B", "[fc00::c]:443=C"},
	}
	if err := normalizeTCPConfig(&config); err != nil {
		t.Fatalf("normalizeTCPConfig(valid virtual listeners) error = %v", err)
	}
	if len(config.tcpForwardSpecs) != 3 {
		t.Fatalf("virtual specs = %+v, want 3", config.tcpForwardSpecs)
	}
	if got := config.tcpForwardSpecs[0].VirtualIP; got != netip.MustParseAddr("fd00::b") {
		t.Fatalf("first virtual IP = %s, want fd00::b", got)
	}

	invalid := map[string]runtimeConfig{
		"own virtual IP": {NodeID: "A", VirtualIP: "fd00::a", VirtualTCPForwards: []string{"[fd00::a]:22=B"}},
		"self remote":    {NodeID: "A", VirtualIP: "fd00::a", VirtualTCPForwards: []string{"[fd00::b]:22=A"}},
		"global IPv6":    {NodeID: "A", VirtualTCPForwards: []string{"[2001:db8::b]:22=B"}},
		"link local":     {NodeID: "A", VirtualTCPForwards: []string{"[fe80::b]:22=B"}},
		"IPv4":           {NodeID: "A", VirtualTCPForwards: []string{"127.0.0.2:22=B"}},
		"host name":      {NodeID: "A", VirtualTCPForwards: []string{"localhost:22=B"}},
		"zero port":      {NodeID: "A", VirtualTCPForwards: []string{"[fd00::b]:0=B"}},
		"missing remote": {NodeID: "A", VirtualTCPForwards: []string{"[fd00::b]:22="}},
		"duplicate":      {NodeID: "A", VirtualTCPForwards: []string{"[fd00::b]:22=B", "[fd00:0:0:0:0:0:0:b]:22=C"}},
	}
	for name, candidate := range invalid {
		t.Run(name, func(t *testing.T) {
			if err := normalizeTCPConfig(&candidate); err == nil {
				t.Fatalf("normalizeTCPConfig(%+v) error = nil", candidate.VirtualTCPForwards)
			}
		})
	}
}

func TestVirtualTCPForwardAliasFailureClosesManager(t *testing.T) {
	wantErr := errors.New("alias add failed")
	cleanupErr := errors.New("alias cleanup failed")
	aliases := &fakeVirtualAliasManager{addErr: wantErr, closeErrs: []error{cleanupErr, nil}}
	runtime := newTCPTestRuntime(t, runtimeConfig{
		NodeID: "A", virtualAliasManager: aliases,
		tcpForwardSpecs: []tcpForwardSpec{{
			Listen: "[fd7f:7769:6b79::b]:22", RemoteID: "B", VirtualIP: netip.MustParseAddr("fd7f:7769:6b79::b"),
		}},
	})
	err := runtime.Start(context.Background(), nil)
	if !errors.Is(err, wantErr) || !errors.Is(err, cleanupErr) {
		t.Fatalf("Start() error = %v, want joined add and cleanup errors", err)
	}
	if len(aliases.added) != 1 || aliases.added[0] != netip.MustParseAddr("fd7f:7769:6b79::b") {
		t.Fatalf("alias Add calls = %v", aliases.added)
	}
	if aliases.closeCalls != 1 {
		t.Fatalf("alias Close calls = %d, want 1", aliases.closeCalls)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("Close() retry error = %v", err)
	}
	if aliases.closeCalls != 2 {
		t.Fatalf("alias Close calls after retry = %d, want 2", aliases.closeCalls)
	}
}

func TestVirtualTCPAcceptPolicyRequiresCurrentDataRoute(t *testing.T) {
	for _, dataCapable := range []bool{false, true} {
		name := "control-only"
		if dataCapable {
			name = "dual-stream"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			nodeA, err := mesh.NewNode(mesh.NodeConfig{
				NodeID: "A", VirtualIP: "fd00::a", Lease: time.Second, RefreshInterval: 20 * time.Millisecond,
			})
			if err != nil {
				t.Fatal(err)
			}
			nodeB, err := mesh.NewNode(mesh.NodeConfig{
				NodeID: "B", VirtualIP: "fd00::b", Lease: time.Second, RefreshInterval: 20 * time.Millisecond,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = nodeA.Close()
				_ = nodeB.Close()
			})
			runtime, err := newTCPRuntime(runtimeConfig{NodeID: "A"}, nodeA)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = runtime.Close() })
			if err := nodeA.Start(ctx); err != nil {
				t.Fatal(err)
			}
			if err := nodeB.Start(ctx); err != nil {
				t.Fatal(err)
			}
			if err := runtime.Start(ctx, nil); err != nil {
				t.Fatal(err)
			}

			controlA, controlB := tcpTestConnPair(t)
			if dataCapable {
				dataA, dataB := tcpTestConnPair(t)
				if err := nodeA.AttachStreams("B", controlA, dataA); err != nil {
					t.Fatal(err)
				}
				if err := nodeB.AttachStreams("A", controlB, dataB); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := nodeA.AttachStream("B", controlA); err != nil {
					t.Fatal(err)
				}
				if err := nodeB.AttachStream("A", controlB); err != nil {
					t.Fatal(err)
				}
			}
			tcpTestWait(t, func() bool {
				member, memberOK := nodeA.Member("B")
				_, routeOK := nodeA.Route("B")
				return memberOK && member.VirtualIP == "fd00::b" && routeOK
			})

			if dataCapable {
				tcpTestWait(t, func() bool {
					_, ok := nodeA.DataRoute("B")
					return ok
				})
				if err := runtime.virtualTCPAcceptPolicy("B", netip.MustParseAddr("fd00::b"))(); err != nil {
					t.Fatalf("data-capable policy error = %v, want nil", err)
				}
			} else {
				if _, ok := nodeA.DataRoute("B"); ok {
					t.Fatal("control-only neighbor unexpectedly has a data route")
				}
				if err := runtime.virtualTCPAcceptPolicy("B", netip.MustParseAddr("fd00::b"))(); err == nil {
					t.Fatal("control-only policy error = nil, want rejection")
				}
			}
		})
	}
}

func TestTCPRuntimeConfiguredStateIsImmutable(t *testing.T) {
	target := tcpTestListener(t)
	runtime := newTCPTestRuntime(t, runtimeConfig{
		NodeID: "A", TCPTarget: target.Addr().String(),
		tcpForwardSpecs: []tcpForwardSpec{{Listen: "127.0.0.1:0", RemoteID: "B"}},
	})
	if err := runtime.Start(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	forwards := runtime.Snapshot()
	if len(forwards) != 1 || forwards[0].ID != "config-001" || forwards[0].Source != tcpForwardSourceConfig {
		t.Fatalf("configured forwards = %+v", forwards)
	}
	configured := forwards[0]
	if _, err := runtime.RemoveForward(configured.ID); !errors.Is(err, ErrTCPConfigImmutable) {
		t.Fatalf("RemoveForward(config) error = %v, want ErrTCPConfigImmutable", err)
	}
	if _, err := runtime.AddForward(configured.Listen, "C", tcpForwardSourceRuntime); !errors.Is(err, ErrTCPConfigImmutable) {
		t.Fatalf("AddForward(config listen) error = %v, want ErrTCPConfigImmutable", err)
	}
	if err := runtime.SetTarget(target.Addr().String()); err != nil {
		t.Fatalf("SetTarget(same configured target) error = %v", err)
	}
	otherTarget := tcpTestListener(t)
	if err := runtime.SetTarget(otherTarget.Addr().String()); !errors.Is(err, ErrTCPConfigImmutable) {
		t.Fatalf("SetTarget(other) error = %v, want ErrTCPConfigImmutable", err)
	}
	if err := runtime.ClearTarget(); !errors.Is(err, ErrTCPConfigImmutable) {
		t.Fatalf("ClearTarget(config) error = %v, want ErrTCPConfigImmutable", err)
	}
	if got := runtime.TargetSnapshot(); got.Target != target.Addr().String() || got.Source != tcpForwardSourceConfig {
		t.Fatalf("TargetSnapshot() = %+v", got)
	}
}

func TestTCPRuntimeTargetLifecycle(t *testing.T) {
	runtime := newTCPTestRuntime(t, runtimeConfig{NodeID: "A"})
	target := tcpTestListener(t)
	if err := runtime.SetTarget(target.Addr().String()); !errors.Is(err, ErrTCPRuntimeNotStarted) {
		t.Fatalf("SetTarget() before Start error = %v, want ErrTCPRuntimeNotStarted", err)
	}
	if err := runtime.Start(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if err := runtime.SetTarget(target.Addr().String()); err != nil {
		t.Fatal(err)
	}
	if got := runtime.TargetSnapshot(); got.Target != target.Addr().String() || got.Source != tcpForwardSourceRuntime {
		t.Fatalf("TargetSnapshot() after set = %+v", got)
	}
	if err := runtime.SetTarget("192.0.2.1:22"); err == nil {
		t.Fatal("SetTarget(non-loopback) error = nil")
	}
	if got := runtime.TargetSnapshot(); got.Target != target.Addr().String() || got.Source != tcpForwardSourceRuntime {
		t.Fatalf("invalid target changed snapshot to %+v", got)
	}
	if err := runtime.ClearTarget(); err != nil {
		t.Fatal(err)
	}
	if got := runtime.TargetSnapshot(); got != (tcpTargetView{}) {
		t.Fatalf("TargetSnapshot() after clear = %+v", got)
	}
}

func TestTCPRuntimeListenerEndRemovesRegistryEntry(t *testing.T) {
	runtime := newTCPTestRuntime(t, runtimeConfig{NodeID: "A"})
	if err := runtime.Start(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	view, err := runtime.AddForward("127.0.0.1:0", "B", tcpForwardSourceRuntime)
	if err != nil {
		t.Fatal(err)
	}
	runtime.mu.Lock()
	listener := runtime.listeners[view.ID].listener
	runtime.mu.Unlock()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	tcpTestWait(t, func() bool {
		runtime.mu.Lock()
		defer runtime.mu.Unlock()
		return runtime.listeners[view.ID] == nil && runtime.dynamicCount == 0
	})
	if _, err := runtime.RemoveForward(view.ID); !errors.Is(err, ErrTCPForwardNotFound) {
		t.Fatalf("RemoveForward(ended) error = %v, want ErrTCPForwardNotFound", err)
	}
}

func TestTCPRuntimeContextOwnsDynamicListenerLifetime(t *testing.T) {
	runtime := newTCPTestRuntime(t, runtimeConfig{NodeID: "A"})
	runtimeCtx, cancelRuntime := context.WithCancel(context.Background())
	if err := runtime.Start(runtimeCtx, nil); err != nil {
		t.Fatal(err)
	}
	view, err := runtime.AddForward("127.0.0.1:0", "B", tcpForwardSourceRuntime)
	if err != nil {
		t.Fatal(err)
	}
	cancelRuntime()
	tcpTestWait(t, func() bool {
		return len(runtime.Snapshot()) == 0
	})
	if _, err := runtime.AddForward("127.0.0.1:0", "B", tcpForwardSourceRuntime); !errors.Is(err, ErrTCPRuntimeClosed) {
		t.Fatalf("AddForward() after runtime context cancellation error = %v, want ErrTCPRuntimeClosed", err)
	}
	if _, err := runtime.RemoveForward(view.ID); !errors.Is(err, ErrTCPRuntimeClosed) {
		t.Fatalf("RemoveForward() after runtime context cancellation error = %v, want ErrTCPRuntimeClosed", err)
	}
}

func TestTCPRuntimeDynamicForwardLimit(t *testing.T) {
	runtime := newTCPTestRuntime(t, runtimeConfig{NodeID: "A"})
	if err := runtime.Start(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	views := make([]tcpForwardView, 0, maxDynamicTCPForwards)
	for range maxDynamicTCPForwards {
		view, err := runtime.AddForward("127.0.0.1:0", "B", tcpForwardSourceRuntime)
		if err != nil {
			t.Fatal(err)
		}
		views = append(views, view)
	}
	if _, err := runtime.AddForward("127.0.0.1:0", "B", tcpForwardSourceRuntime); !errors.Is(err, ErrTCPForwardLimit) {
		t.Fatalf("AddForward() over limit error = %v, want ErrTCPForwardLimit", err)
	}
	if _, err := runtime.RemoveForward(views[0].ID); err != nil {
		t.Fatal(err)
	}
	replacement, err := runtime.AddForward("127.0.0.1:0", "B", tcpForwardSourceRuntime)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.ID != "runtime-065" {
		t.Fatalf("replacement ID = %q, want runtime-065", replacement.ID)
	}
}

func TestTCPRuntimeConcurrentAddRemoveAndClose(t *testing.T) {
	runtime := newTCPTestRuntime(t, runtimeConfig{NodeID: "A"})
	if err := runtime.Start(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	const count = 32
	views := make(chan tcpForwardView, count)
	errs := make(chan error, count)
	var addWG sync.WaitGroup
	for range count {
		addWG.Add(1)
		go func() {
			defer addWG.Done()
			view, err := runtime.AddForward("127.0.0.1:0", "B", tcpForwardSourceRuntime)
			if err != nil {
				errs <- err
				return
			}
			views <- view
		}()
	}
	addWG.Wait()
	close(views)
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent AddForward() error = %v", err)
	}
	var removeWG sync.WaitGroup
	for view := range views {
		view := view
		removeWG.Add(1)
		go func() {
			defer removeWG.Done()
			if _, err := runtime.RemoveForward(view.ID); err != nil {
				t.Errorf("RemoveForward(%s) error = %v", view.ID, err)
			}
		}()
	}
	removeWG.Wait()
	if got := runtime.Snapshot(); len(got) != 0 {
		t.Fatalf("Snapshot() after concurrent remove = %+v", got)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.AddForward("127.0.0.1:0", "B", tcpForwardSourceRuntime); !errors.Is(err, ErrTCPRuntimeClosed) {
		t.Fatalf("AddForward() after Close error = %v, want ErrTCPRuntimeClosed", err)
	}
	if err := runtime.SetTarget("127.0.0.1:22"); !errors.Is(err, ErrTCPRuntimeClosed) {
		t.Fatalf("SetTarget() after Close error = %v, want ErrTCPRuntimeClosed", err)
	}
}

func newTCPTestRuntime(t *testing.T, config runtimeConfig) *tcpRuntime {
	t.Helper()
	node, err := mesh.NewNode(mesh.NodeConfig{NodeID: config.NodeID})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := newTCPRuntime(config, node)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := runtime.Close(); err != nil {
			t.Errorf("tcpRuntime.Close() error = %v", err)
		}
	})
	return runtime
}

func tcpTestListener(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func tcpTestConnPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()
	client, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	var server net.Conn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		_ = client.Close()
		_ = listener.Close()
		t.Fatal(err)
	case <-time.After(time.Second):
		_ = client.Close()
		_ = listener.Close()
		t.Fatal("timed out accepting TCP test pair")
	}
	if err := listener.Close(); err != nil {
		_ = client.Close()
		_ = server.Close()
		t.Fatal(err)
	}
	return client, server
}

func tcpTestWait(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met before timeout")
		}
		time.Sleep(time.Millisecond)
	}
}

type fakeVirtualAliasManager struct {
	mu         sync.Mutex
	added      []netip.Addr
	addErr     error
	closeErrs  []error
	closeCalls int
}

func (m *fakeVirtualAliasManager) Add(address netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.added = append(m.added, address)
	return m.addErr
}

func (m *fakeVirtualAliasManager) Remove(netip.Addr) error { return nil }

func (m *fakeVirtualAliasManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeCalls++
	if len(m.closeErrs) > 0 {
		err := m.closeErrs[0]
		m.closeErrs = m.closeErrs[1:]
		return err
	}
	return nil
}
