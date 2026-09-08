package gatecorchestrator

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/directconnect/gateb"
	"winkyou/internal/v2/gatecattempt"
	"winkyou/internal/v2/gatecrequest"
	"winkyou/internal/v2/hardnatplan"
	"winkyou/internal/v2/sshassembly"
	"winkyou/pkg/config"
	"winkyou/pkg/tunnel"
)

type preflightLivenessStream struct{ bytes.Buffer }

func (*preflightLivenessStream) Close() error                { return nil }
func (*preflightLivenessStream) SetDeadline(time.Time) error { return nil }

func TestLivenessMissingCapabilityRejectsBeforeAnySSHOrProbeFactory(t *testing.T) {
	private, err := tunnel.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	remote, err := tunnel.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = private.String()
	cfg.GateC.Peers = []config.GateCPeerConfig{{Ref: "synthetic-peer", PublicKey: remote.PublicKey().String(), AllowedIPs: []string{"192.0.2.2/32"}, LocalVirtualIP: "192.0.2.1", PeerVirtualIP: "192.0.2.2", MemoryInterfaceName: "liveness-proof", MemoryMTU: 1280, SessionCeiling: time.Minute, SessionLiveness: &config.SessionLivenessConfig{Mode: "challenge_v1", MissedRounds: 3}}}
	in := preparedInput{configuration: &cfg, request: gatecrequest.Request{Role: gatecattempt.RoleResponder, PeerRef: "synthetic-peer"}, artifact: &gatecattempt.Artifact{LocalRole: gatecattempt.RoleResponder, PlannerProfile: hardnatplan.ProfilePredictiveEdm, ResourceClass: hardnatplan.ResourcePredictive}, machine: &governor.Governor{}, ledger: &governor.PairingAdmissionLedger{}, stream: &preflightLivenessStream{}}
	in.buildVersion = "synthetic-build"
	in.progress = func(Progress) error { return nil }
	in.request.ArtifactFile = "synthetic-artifact.json"
	deps := defaultDependencies()
	deps.innerTapCapable = func() bool { return false }
	sshCalls, factoryCalls := 0, 0
	deps.configureGateB = func(*gateb.Config) { factoryCalls++ }
	deps.openSSH = func(context.Context, sshassembly.Config) (sshProductStream, error) {
		sshCalls++
		return nil, errLivenessUnavailable
	}
	_, err = runPrepared(context.Background(), in, deps)
	var failure *Failure
	if !errors.As(err, &failure) || failure.Class != "session_liveness_unavailable" || failure.CredentialBurned || failure.FinishRecorded == nil || *failure.FinishRecorded || sshCalls != 0 || factoryCalls != 0 {
		t.Fatalf("preflight=%v ssh=%d factory=%d", err, sshCalls, factoryCalls)
	}
}

func TestLivenessTapQueueIsBoundedAndNeverBlocksOnControllerState(t *testing.T) {
	m, _ := testLivenessModel(t, 3)
	c := &livenessController{model: m, stop: make(chan struct{}), inbound: make(chan livenessControlEvent, 2)}
	packet := make([]byte, livenessPacketSize)
	if !c.Deliver(packet) || !c.Deliver(packet) {
		t.Fatal("queue capacity drifted")
	}
	m.mu.Lock() // a stalled controller cannot stall WireGuard ingress
	if c.Deliver(packet) {
		t.Fatal("third event should drop")
	}
	m.mu.Unlock()
	if c.inboundDrops.Load() != 1 || len(c.inbound) != 2 {
		t.Fatal("unbounded ingress or missing drop witness")
	}
	packet[0] = 99
	if event := <-c.inbound; event.packet[0] == 99 {
		t.Fatal("tap retained caller packet memory")
	}
	close(c.stop)
	if c.Deliver(packet) {
		t.Fatal("tap accepted event after revoke")
	}
}
