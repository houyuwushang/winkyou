//go:build c1bproof

package governor_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/natsim"
	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/directconnect/gateb"
	"winkyou/internal/v2/gatecattempt"
	"winkyou/internal/v2/gatecorchestrator"
	"winkyou/internal/v2/gatecrequest"
	"winkyou/internal/v2/hardnatobserve"
	"winkyou/internal/v2/hardnatplan"
	"winkyou/internal/v2/pairgen"
	"winkyou/internal/v2/sshassembly"
	"winkyou/pkg/config"
	"winkyou/pkg/tunnel"
)

func TestGateC1bMemoryProductPipelineReachesPostOOBEcho(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	namespaces := [2]string{t.TempDir(), t.TempDir()}
	for _, namespace := range namespaces {
		if err := governor.PrepareLoopbackCarrierTestNamespace(namespace, now); err != nil {
			t.Fatal(err)
		}
	}
	machines := [2]*governor.Governor{}
	ledgers := [2]*governor.PairingAdmissionLedger{}
	for index, namespace := range namespaces {
		machine, err := governor.AcquireManualTraversalTestGovernor(namespace, "gate-c1b-memory-product")
		if err != nil {
			t.Fatal(err)
		}
		machines[index] = machine
		t.Cleanup(func() { _ = machine.Close() })
		ledgers[index], err = governor.LoopbackCarrierTestLedger(machine)
		if err != nil {
			t.Fatal(err)
		}
	}

	network, err := natsim.NewNetwork(natsim.Config{MaxPacketConns: 32, MaxMappings: 256, QueueCapacity: 4096, MaxDatagram: 2048})
	if err != nil {
		t.Fatal(err)
	}
	defer network.Close()
	model := natsim.Model{Mapping: natsim.MappingEndpointDependent, Allocation: natsim.PortIncrement,
		Filtering: natsim.FilterAddressPortDependent, PortMin: 40000, PortMax: 45000}
	public := [2]netip.Addr{netip.MustParseAddr("198.51.100.10"), netip.MustParseAddr("198.51.100.20")}
	nats := [2]*natsim.NAT{}
	for index := range nats {
		nats[index], err = network.NewNAT(natsim.NATConfig{Name: []string{"left-c1b-product", "right-c1b-product"}[index],
			PublicAddr: public[index], Model: model})
		if err != nil {
			t.Fatal(err)
		}
	}
	topology := hardnatobserve.Topology{Primary: netip.MustParseAddrPort("203.0.113.10:3478"),
		Other: netip.MustParseAddrPort("203.0.113.11:3479")}
	_ = startNATSimRFC5780Responders(t, network, topology)

	set, err := gatecattempt.EncodeArtifactSet(gatecattempt.ArtifactMaterial{
		CredentialID: gateB2OpaqueID("c1b-product-credential"), AttemptID: gateB2OpaqueID("c1b-product-attempt"),
		InitiatorParticipantID: gateB2OpaqueID("c1b-product-initiator"),
		ResponderParticipantID: gateB2OpaqueID("c1b-product-responder"), OOBChannelID: gateB2OpaqueID("c1b-product-channel"),
		PlannerProfile: hardnatplan.ProfilePredictiveEdm, ResourceClass: hardnatplan.ResourcePredictive,
		InitiatorPlannerRole: hardnatplan.RoleInitiator, ResponderPlannerRole: hardnatplan.RoleResponder,
		IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute),
	}, [32]byte{7, 11, 13, 17, 19, 23, 29, 31})
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close()
	artifacts := [2]*gatecattempt.Artifact{}
	artifacts[0], err = gatecattempt.ParseArtifact(set.Initiator, now)
	if err != nil {
		t.Fatal(err)
	}
	artifacts[1], err = gatecattempt.ParseArtifact(set.Responder, now)
	if err != nil {
		t.Fatal(err)
	}

	private := [2]tunnel.PrivateKey{}
	for index := range private {
		private[index], err = tunnel.GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
	}
	virtual := [2]string{"10.88.0.1", "10.88.0.2"}
	configs := [2]*config.Config{}
	requests := [2]gatecrequest.Request{}
	identity := filepath.Join(t.TempDir(), "identity")
	knownHosts := filepath.Join(t.TempDir(), "known-hosts")
	if err := pairgen.WritePrivateFileExclusive(identity, []byte("synthetic-private-test-key")); err != nil {
		t.Fatal(err)
	}
	if err := pairgen.WritePrivateFileExclusive(knownHosts, []byte("synthetic-host-key")); err != nil {
		t.Fatal(err)
	}
	sshEndpoint := netip.MustParseAddrPort("127.0.0.1:2222")
	sshAuthority, err := sshassembly.NewLoopbackAuthority(sshEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	observerEndpoints, err := topology.Endpoints()
	if err != nil {
		t.Fatal(err)
	}
	for index := range configs {
		cfg := config.Default()
		cfg.WireGuard.PrivateKey = private[index].String()
		cfg.GateC.Peers = []config.GateCPeerConfig{{
			Ref: []string{"right", "left"}[index], PublicKey: private[1-index].PublicKey().String(),
			AllowedIPs: []string{virtual[1-index] + "/32"}, LocalVirtualIP: virtual[index], PeerVirtualIP: virtual[1-index],
			MemoryInterfaceName: []string{"wink-c1b-left", "wink-c1b-right"}[index], MemoryMTU: 1280,
			SessionCeiling: 5 * time.Second,
		}}
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
		configs[index] = &cfg
		requests[index] = gatecrequest.Request{
			Role:         []gatecattempt.Role{gatecattempt.RoleInitiator, gatecattempt.RoleResponder}[index],
			ArtifactFile: filepath.Join(t.TempDir(), []string{"initiator.json", "responder.json"}[index]),
			PeerRef:      cfg.GateC.Peers[0].Ref, ExpectedPeerPublicAddress: public[1-index],
			ObserverSet: gatecrequest.ObserverSet{Primary: observerEndpoints[0], AlternatePort: observerEndpoints[1],
				AlternateAddress: observerEndpoints[2], AlternateAddressPort: observerEndpoints[3]},
		}
	}
	requests[0].SSH = &gatecrequest.SSHConfig{Endpoint: sshEndpoint, User: "c1btest", IdentityFile: identity, KnownHostsFile: knownHosts}

	leftStream, rightStream := net.Pipe()
	defer leftStream.Close()
	defer rightStream.Close()
	clock := newGateB2ManualClock(now)
	ready := 0
	var readyMu sync.Mutex
	initiatorCtx, cancelInitiator := context.WithCancel(context.Background())
	defer cancelInitiator()
	responderCtx, cancelResponder := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancelResponder()
	type outcome struct {
		role   directattempt.Role
		result gatecorchestrator.Result
		err    error
		stages []string
	}
	results := make(chan outcome, 2)
	for index := range 2 {
		index := index
		go func() {
			role := []directattempt.Role{directattempt.RoleInitiator, directattempt.RoleResponder}[index]
			var authority sshassembly.SSHEndpointAuthority
			if index == 0 {
				authority = sshAuthority
			}
			var stages []string
			result, runErr := gatecorchestrator.RunMemoryProof([]context.Context{initiatorCtx, responderCtx}[index], gatecorchestrator.MemoryProofOptions{
				Request: requests[index], Artifact: artifacts[index], Config: configs[index], Machine: machines[index],
				Ledger: ledgers[index], SSHAuthority: authority, Stream: []net.Conn{leftStream, rightStream}[index],
				ProbeFactory: &natSimProbeFactory{network: network, nat: nats[index],
					localAddress: []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.20")}[index],
					basePort:     []uint16{30000, 31000}[index], plannerRole: []hardnatplan.Role{hardnatplan.RoleInitiator, hardnatplan.RoleResponder}[index],
					witness: newCandidateWitness()},
				Harness: &gateb.HarnessHooks{NoiseRandom: bytes.NewReader(bytes.Repeat([]byte{byte(40 + index)}, 4096)),
					ObservationRandom: gateB2ObservationRandom(byte(70 + index)), Now: clock.Now, NewTimer: clock.NewTimer, Wait: clock.Wait},
				BuildVersion: "gate-c1b-memory-product", Random: bytes.NewReader(bytes.Repeat([]byte{byte(90 + index)}, 64)),
				InactiveEvery: 100 * time.Millisecond,
				Progress: func(progress gatecorchestrator.Progress) error {
					stages = append(stages, progress.Stage)
					if progress.Stage == gatecorchestrator.StageDataPlaneReady {
						readyMu.Lock()
						ready++
						if ready == 2 {
							cancelInitiator()
						}
						readyMu.Unlock()
					}
					return nil
				},
			})
			results <- outcome{role: role, result: result, err: runErr, stages: stages}
		}()
	}

	var outcomes []outcome
	for range 2 {
		select {
		case got := <-results:
			outcomes = append(outcomes, got)
		case <-time.After(15 * time.Second):
			t.Fatal("Gate C1b memory product pipeline exceeded its bound")
		}
	}
	for _, got := range outcomes {
		if got.err != nil {
			var failure *gatecorchestrator.Failure
			_ = errors.As(got.err, &failure)
			t.Errorf("%s pipeline error=%v cause=%v result=%+v stages=%v", got.role, got.err, failure.Cause, got.result, got.stages)
			continue
		}
		if !got.result.DataPlaneReady || !got.result.FinishRecorded || got.result.Terminal != "success" ||
			!reflect.DeepEqual(got.stages, gatecorchestrator.ProductProgressSequence) {
			t.Errorf("%s result=%+v stages=%v", got.role, got.result, got.stages)
		}
		if got.result.Witness.WireGuard.State != "active" || got.result.Witness.Echo.Drained != true {
			t.Errorf("%s wireguard/echo witness=%+v/%+v", got.role, got.result.Witness.WireGuard, got.result.Witness.Echo)
		}
	}
}
