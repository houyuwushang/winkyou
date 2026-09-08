//go:build linux && natlab && c1bproof

package natlab

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

func gateC1bLivenessEnabled(cfg gateC1bHostConfig) bool {
	switch cfg.Fault {
	case "liveness-idle", "liveness-blackhole-m2", "liveness-blackhole-m3", "liveness-pause", "liveness-parent-kill", "liveness-consumer-crash":
		return true
	}
	return false
}
func gateC1bProofHostLimit(cfg gateC1bHostConfig) time.Duration {
	if gateC1bLivenessEnabled(cfg) {
		return 320 * time.Second
	}
	return gateC1bHostLimit
}
func gateC1bExpectedLivenessTimeout(cfg gateC1bHostConfig, result gateC1bProcessResult) bool {
	return (cfg.Fault == "liveness-blackhole-m2" || cfg.Fault == "liveness-blackhole-m3" || cfg.Fault == "liveness-parent-kill" || cfg.Fault == "liveness-consumer-crash") && result.Class == "session_liveness_timeout" && result.Product.DataPlaneReady && result.Product.FinishRecorded && result.Product.SessionEnd == "liveness_timeout"
}

func TestLinuxSessionLivenessRequired(t *testing.T) {
	if os.Getenv("WINKYOU_LIVENESS_NETNS_REQUIRED") != "1" {
		t.Skip("liveness requires its dedicated isolated Linux job")
	}
	requireGateB3Environment(t)
	requireGateB3HostConntrackGuard(t)
	// Each CI matrix leg selects one case; an invalid or absent selector fails.
	mode := os.Getenv("WINKYOU_LIVENESS_NETNS_CASE")
	if mode == "parent-kill" || mode == "consumer-crash" {
		testGateC1bLivenessCrash(t, "liveness-"+mode)
		return
	}
	loopback := mode == "loopback-idle" || mode == "loopback-blackhole-m2" || mode == "loopback-blackhole-m3"
	scenario := map[string]string{"loopback-idle": "liveness-idle", "tun-idle": "liveness-idle", "blackhole-m2": "liveness-blackhole-m2", "blackhole-m3": "liveness-blackhole-m3", "loopback-blackhole-m2": "liveness-blackhole-m2", "loopback-blackhole-m3": "liveness-blackhole-m3", "pause": "liveness-pause"}[mode]
	if scenario == "" {
		t.Fatal("required liveness scenario is absent or unknown")
	}
	testGateC1bProfileWithLiveness(t, gateC1bProfiles[0], loopback, scenario)
}

func injectGateC1bLivenessFault(t *testing.T, topology *n2dTopology, configs [2]gateC1bHostConfig, client *gateC1bHostProcess) (time.Time, func()) {
	t.Helper()
	mode := configs[0].Fault
	if mode == "liveness-idle" {
		return time.Time{}, func() {}
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		left, _ := os.ReadFile(configs[0].StageFile)
		right, _ := os.ReadFile(configs[1].StageFile)
		if string(left) == "data_plane_ready" && string(right) == "data_plane_ready" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("liveness post-FINISH boundary unavailable")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if mode == "liveness-pause" {
		// This is a real scheduler pause, NOT system suspend. Both OS clocks
		// continue; fixed-origin divergence is proved separately by fake clocks.
		started := time.Now()
		if client.command.Process.Signal(syscall.SIGSTOP) != nil {
			t.Fatal("isolated SIGSTOP failed")
		}
		time.Sleep(3 * time.Second)
		if client.command.Process.Signal(syscall.SIGCONT) != nil {
			t.Fatal("isolated SIGCONT failed")
		}
		t.Logf("liveness OS scheduling pause_ms=%d system_suspend=false", time.Since(started).Milliseconds())
		return time.Time{}, func() {}
	}
	// First establish one proof at 20s, then a pure UDP blackhole. No new
	// target/socket/attempt is introduced. Namespace input drops do not alter
	// the output packet counters used by the independent OS witness.
	time.Sleep(25 * time.Second)
	var installed []string
	var once sync.Once
	release := func() {
		once.Do(func() {
			for _, ns := range installed {
				if _, err := runNamespaced(ns, "iptables", nil, "-D", "INPUT", "-p", "udp", "-m", "comment", "--comment", "wink-liveness-blackhole", "-j", "DROP"); err != nil {
					t.Error("isolated blackhole cleanup failed")
				}
			}
		})
	}
	t.Cleanup(release)
	for _, ns := range []string{topology.clientA, topology.clientB} {
		args := []string{"-I", "INPUT", "1", "-p", "udp", "-m", "comment", "--comment", "wink-liveness-blackhole", "-j", "DROP"}
		if _, err := runNamespaced(ns, "iptables", nil, args...); err != nil {
			t.Fatal("isolated UDP blackhole failed")
		}
		installed = append(installed, ns)
	}
	return time.Now(), release
}

func validateGateC1bKernelLiveness(t *testing.T, cfg gateC1bHostConfig, result gateC1bProcessResult, faultAt time.Time) {
	t.Helper()
	lv := result.Product.Witness.Liveness
	wg := result.Product.Witness.WireGuard
	if lv == nil || !lv.Drained || !lv.BindingVerified || !wg.Closed || wg.ActivePolicy == nil {
		t.Fatal("kernel liveness binding/drain absent")
	}
	if cfg.Fault == "liveness-idle" && (lv.ElapsedNS < 180*time.Second || lv.PongValidated < 8 || wg.ActivePolicy.HandshakeInitiations+wg.ActivePolicy.HandshakeResponses == 0) {
		t.Fatal("kernel idle/rekey not proved")
	}
	if cfg.UseTUN && (result.TUN.ControlReads != lv.InnerInjected || result.TUN.ControlQueued != 0) {
		t.Fatal("kernel control multiplexing or queue drain not proved")
	}
	if !faultAt.IsZero() {
		limit := 67 * time.Second
		if cfg.Fault == "liveness-blackhole-m2" {
			limit = 47 * time.Second
		}
		if time.Since(faultAt) > limit {
			t.Fatal("kernel blackhole exceeded frozen drain bound")
		}
	}
	t.Logf("kernel liveness case=%s elapsed_ms=%d ping=%d pong=%d proof=%d control=%d rekey_init_response=%d/%d empty=%d drained=true", cfg.Fault, lv.ElapsedNS.Milliseconds(), lv.PingAdmitted, lv.PongAdmitted, lv.PongValidated, wg.ActivePolicy.ControlAdmitted, wg.ActivePolicy.HandshakeInitiations, wg.ActivePolicy.HandshakeResponses, wg.ActivePolicy.EmptyKeepalives)
}

// The original echo/business path still traverses the real kernel TUN. WYCL
// control is injected at the existing inner interface boundary and intercepted
// after WG decrypt: it has NO OS UDP listener. A bounded queue multiplexed by
// the existing Read worker avoids an extra socket or protocol worker.
func (instance *gateC1bKernelInterface) injectLiveness(buffer []byte) (int, error) {
	instance.controlMu.Lock()
	defer instance.controlMu.Unlock()
	if instance.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(buffer) != 92 || buffer[0] != 0x45 || binary.BigEndian.Uint16(buffer[20:22]) != 32113 || binary.BigEndian.Uint16(buffer[22:24]) != 32113 ||
		netip.AddrFrom4([4]byte(buffer[12:16])) != instance.local.Addr() || netip.AddrFrom4([4]byte(buffer[16:20])) != instance.remote.Addr() {
		return 0, errors.New("isolated control injection rejected")
	}
	packet := append([]byte(nil), buffer...)
	select {
	case instance.controlQueue <- packet:
		return len(buffer), nil
	default:
		clear(packet)
		return 0, errors.New("isolated control queue full")
	}
}

func (instance *gateC1bKernelInterface) readWithLiveness(buffer []byte) (int, error) {
	for {
		if instance.closed.Load() {
			return 0, net.ErrClosed
		}
		select {
		case packet := <-instance.controlQueue:
			if len(buffer) < len(packet) {
				clear(packet)
				return 0, io.ErrShortBuffer
			}
			n := copy(buffer, packet)
			clear(packet)
			instance.controlReads.Add(1)
			return n, nil
		default:
		}
		if err := instance.tun.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
			return 0, err
		}
		n, err := instance.tun.Read(buffer)
		if n > 0 {
			instance.kernelReads.Add(1)
			if buffer[0]>>4 != 4 {
				instance.nonIPv4Reads.Add(1)
			}
			return n, nil
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		return n, err
	}
}

func TestSessionLivenessNatlabSelectorsStayFinite(t *testing.T) {
	for _, mode := range []string{"", "unknown", "liveness-field", "liveness-idle-extra"} {
		if gateC1bLivenessEnabled(gateC1bHostConfig{Fault: mode}) {
			t.Fatal("unknown authority accepted")
		}
	}
	if gateC1bInnerPort != 32112 {
		t.Fatal("old kernel echo port changed")
	}
}
