//go:build c1bproof

package governor_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
	winkcmd "winkyou/cmd/wink/cmd"

	"winkyou/internal/governor"
	"winkyou/internal/natsim"
	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/directconnect/gateb"
	"winkyou/internal/v2/gatecattempt"
	"winkyou/internal/v2/gatecorchestrator"
	"winkyou/internal/v2/gatecrequest"
	"winkyou/internal/v2/gatecstage"
	"winkyou/internal/v2/hardnatobserve"
	"winkyou/internal/v2/hardnatplan"
	"winkyou/internal/v2/pairgen"
	"winkyou/internal/v2/sshassembly"
	"winkyou/pkg/config"
	"winkyou/pkg/tunnel"
)

type gateC1bMemoryProfile struct {
	name                string
	profile             hardnatplan.Profile
	resource            hardnatplan.ResourceClass
	plannerRoles        [2]hardnatplan.Role
	models              [2]natsim.Model
	maxConns            int
	maxMappings         int
	queueCapacity       int
	candidateTime       time.Duration
	activeTime          time.Duration
	acquire             func(string, string) (*governor.Governor, error)
	cli                 bool
	fault               string
	slowFinish          bool
	slowResponderFinish bool
	cancelAfterFinish   bool
}

// Test-only session configuration, not a product deadline or probe allowance.
// The slow fixture must cover the unchanged 3s challenge plus its real 3.5s
// post-fsync delay and local completion; ordinary fixtures retain their 5s cap.
func (profile gateC1bMemoryProfile) sessionCeiling() time.Duration {
	if profile.slowFinish || profile.slowResponderFinish {
		return 10 * time.Second
	}
	return 5 * time.Second
}

var gateC1bMemoryProfiles = []gateC1bMemoryProfile{
	{
		name: "predictive", profile: hardnatplan.ProfilePredictiveEdm, resource: hardnatplan.ResourcePredictive,
		plannerRoles: [2]hardnatplan.Role{hardnatplan.RoleInitiator, hardnatplan.RoleResponder},
		models: [2]natsim.Model{
			{Mapping: natsim.MappingEndpointDependent, Allocation: natsim.PortIncrement,
				Filtering: natsim.FilterAddressPortDependent, PortMin: 40000, PortMax: 45000},
			{Mapping: natsim.MappingEndpointDependent, Allocation: natsim.PortIncrement,
				Filtering: natsim.FilterAddressPortDependent, PortMin: 40000, PortMax: 45000},
		},
		maxConns: 32, maxMappings: 256, queueCapacity: 4096, candidateTime: 100 * time.Millisecond,
		acquire: governor.AcquireManualTraversalTestGovernor,
	},
	{
		name: "asymmetric", profile: hardnatplan.ProfileAsymmetricBirthday, resource: hardnatplan.ResourceAsymmetric,
		plannerRoles: [2]hardnatplan.Role{hardnatplan.RoleMappingSet, hardnatplan.RoleTargetSet},
		models: [2]natsim.Model{
			{Mapping: natsim.MappingEndpointDependent, Allocation: natsim.PortIncrement,
				Filtering: natsim.FilterAddressPortDependent, PortMin: 40000, PortMax: 65535},
			{Mapping: natsim.MappingEndpointIndependent, Allocation: natsim.PortIncrement,
				Filtering: natsim.FilterAddressPortDependent, PortMin: 46000, PortMax: 65535},
		},
		maxConns: 300, maxMappings: 4096, queueCapacity: 4096, candidateTime: 250 * time.Millisecond,
		acquire: governor.AcquireManualTraversalTestGovernor,
	},
	{
		name: "hard-16k", profile: hardnatplan.ProfileHardBirthday, resource: hardnatplan.ResourceHard16KLab,

		plannerRoles: [2]hardnatplan.Role{hardnatplan.RoleInitiator, hardnatplan.RoleResponder},
		models: [2]natsim.Model{
			{Mapping: natsim.MappingEndpointDependent, Allocation: natsim.PortRandom,
				Filtering: natsim.FilterAddressPortDependent, EndpointDependentPortReuse: true,
				PortMin: hardnatplan.DynamicPortMin, PortMax: hardnatplan.DynamicPortMax, RandomSeed: 3},
			{Mapping: natsim.MappingEndpointDependent, Allocation: natsim.PortRandom,
				Filtering: natsim.FilterAddressPortDependent, EndpointDependentPortReuse: true,
				PortMin: hardnatplan.DynamicPortMin, PortMax: hardnatplan.DynamicPortMax, RandomSeed: 4},
		},
		maxConns: 40, maxMappings: 40_000, queueCapacity: 16_398,
		candidateTime: 2 * time.Second, activeTime: 6 * time.Second,
		acquire: governor.AcquireHardNATCampaignTestGovernor,
	},
}

func TestGateC1bMemoryProductPipelineReachesPostOOBEcho(t *testing.T) {
	t.Run("packet_accounting_oracle", testGateC1bPacketAccountingOracle)
	for _, test := range gateC1bMemoryProfiles {
		t.Run(test.name, func(t *testing.T) {
			runGateC1bMemoryProductProfile(t, test.name, test)
		})
	}
}

// Both CI platforms run this entry separately with -race -count=20, preserving
// the three slow proofs without consuming the ordinary pipeline runner's time.
func TestGateC1bMemorySlowDurableFinishReachesPostOOBEcho(t *testing.T) {
	for _, test := range gateC1bMemoryProfiles {
		test.slowFinish = true
		// Consume the already frozen profile absolute envelope, not Hard16's
		// compressed 6s timing fixture. Only the slow session config is 10s.
		test.activeTime = 0
		t.Run(test.name, func(t *testing.T) {
			runGateC1bMemoryProductProfile(t, "slow-finish-"+test.name, test)
		})
	}
}

func TestGateC1bMemoryFixtureSessionWindows(t *testing.T) {
	for _, base := range gateC1bMemoryProfiles {
		for _, scenario := range []string{"ordinary", "cli", "cancel", "evidence-drift", "candidate-exhaustion", "slow-finish", "slow-responder-finish"} {
			t.Run(base.name+"/"+scenario, func(t *testing.T) {
				profile := base
				want := 5 * time.Second
				switch scenario {
				case "cli":
					profile.cli = true
				case "cancel":
					profile.cancelAfterFinish = true
				case "evidence-drift", "candidate-exhaustion":
					profile.cli, profile.fault = true, scenario
				case "slow-finish":
					profile.slowFinish = true
					want = 10 * time.Second
				case "slow-responder-finish":
					profile.slowResponderFinish = true
					want = 10 * time.Second
				}
				if got := profile.sessionCeiling(); got != want {
					t.Fatalf("fixture session ceiling=%s, want %s", got, want)
				}
				if (profile.slowFinish || profile.slowResponderFinish) && profile.sessionCeiling() <= 3*time.Second+3500*time.Millisecond {
					t.Fatal("slow fixture leaves no completion margin after the challenge and injected delay")
				}
				if base.sessionCeiling() != 5*time.Second || profile.activeTime != base.activeTime || profile.candidateTime != base.candidateTime {
					t.Fatal("session configuration changed the base fixture or its attempt timing")
				}
			})
		}
	}
}

// Independent governors, journals and in-memory networks permit parallel
// profiles. Never combine this fault with the initiator's FINISH delay.
func TestGateC1bMemorySlowResponderDurableFinishReachesPostOOBEcho(t *testing.T) {
	for _, test := range gateC1bMemoryProfiles {
		test.slowResponderFinish = true
		test.activeTime = 0
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runGateC1bMemoryProductProfile(t, "slow-responder-finish-"+test.name, test)
		})
	}
}

// Kept as a separate required race-20 step so this new regression does not
// consume the existing three-profile pipeline runner's 12-minute envelope.
// The same fixture, fault, attempt/session deadlines and assertions are used.
func TestGateC1bMemoryCancellationAfterDurableFinish(t *testing.T) {
	profile := gateC1bMemoryProfiles[0]
	profile.cancelAfterFinish = true
	runGateC1bMemoryProductProfile(t, "cancel-after-finish", profile)
}

func TestGateC1bMemoryProductPipelineFresh100(t *testing.T) {
	if os.Getenv("WINKYOU_GATE_C1B_REPEAT_REQUIRED") != "1" {
		t.Skip("Gate C1b 100-run proof was not explicitly required")
	}
	started := time.Now()
	for iteration := range 100 {
		test := gateC1bMemoryProfiles[iteration%len(gateC1bMemoryProfiles)]
		test.cli = true
		if test.candidateTime < 500*time.Millisecond {
			test.candidateTime = 500 * time.Millisecond
		}
		label := test.name + "-fresh-" + strconv.Itoa(iteration)
		if !t.Run(label, func(t *testing.T) { runGateC1bMemoryProductProfile(t, label, test) }) {
			t.FailNow()
		}
	}
	t.Logf("Gate C1b memory lifecycle witness: fresh_namespaces=100 deterministic_schedules=3 residue=0 wall_ms=%d", time.Since(started).Milliseconds())
}

func TestGateC1bMemoryCLIAndClaimedChildPipeline(t *testing.T) {
	for _, profile := range gateC1bMemoryProfiles {
		profile.cli = true
		// The real CLI/slot/process accounting adds scheduler work. Keep this
		// proof below the frozen production window without compressing it to
		// 100ms (one Windows race run exhausted before a sender was scheduled).
		if profile.candidateTime < 500*time.Millisecond {
			profile.candidateTime = 500 * time.Millisecond
		}
		t.Run(profile.name, func(t *testing.T) { runGateC1bMemoryProductProfile(t, "cli-"+profile.name, profile) })
	}
}

func TestGateC1bMemoryCLIEvidenceDriftAndExhaustionAreOneShot(t *testing.T) {
	for _, fault := range []string{"evidence-drift", "candidate-exhaustion"} {
		t.Run(fault, func(t *testing.T) {
			profile := gateC1bMemoryProfiles[0]
			profile.cli, profile.fault = true, fault
			profile.candidateTime = 500 * time.Millisecond
			runGateC1bMemoryProductProfile(t, fault, profile)
		})
	}
}

func runGateC1bMemoryProductProfile(t *testing.T, label string, test gateC1bMemoryProfile) {
	t.Helper()
	// The protocol key includes the validity window. Freeze it so the
	// conditional birthday profiles exercise a reproducible successful
	// schedule instead of turning this composition proof into a probability
	// flake.
	now := time.Date(2026, 8, 29, 16, 0, 0, 0, time.UTC)
	namespaces := [2]string{t.TempDir(), t.TempDir()}
	for _, namespace := range namespaces {
		if err := governor.PrepareLoopbackCarrierTestNamespace(namespace, now); err != nil {
			t.Fatal(err)
		}
	}
	machines := [2]*governor.Governor{}
	ledgers := [2]*governor.PairingAdmissionLedger{}
	for index, namespace := range namespaces {
		machine, err := test.acquire(namespace, "gate-c1b-memory-product-"+label)
		if err != nil {
			t.Fatal(err)
		}
		machines[index] = machine
		defer machine.Close()
		ledgers[index], err = governor.LoopbackCarrierTestLedger(machine)
		if err != nil {
			t.Fatal(err)
		}
		if err := governor.SetCarrierTestLedgerTime(machine, now); err != nil {
			t.Fatal(err)
		}
	}
	network, err := natsim.NewNetwork(natsim.Config{
		MaxPacketConns: test.maxConns, MaxMappings: test.maxMappings,
		QueueCapacity: test.queueCapacity, MaxDatagram: 2048,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer network.Close()
	public := [2]netip.Addr{netip.MustParseAddr("198.51.100.10"), netip.MustParseAddr("198.51.100.20")}
	nats := [2]*natsim.NAT{}
	for index := range nats {
		var changes []natsim.BehaviorChange
		if test.fault != "" {
			after := test.models[index]
			after.PortMin, after.PortMax = 50000, 55000
			boundary := uint64(8) // Changes during the eight-sample evidence suffix.
			if test.fault == "candidate-exhaustion" {
				boundary = 13 // Valid evidence, then a changed mapping before punch.
			}
			changes = []natsim.BehaviorChange{{AfterOutboundPackets: boundary, Model: after}}
		}
		nats[index], err = network.NewNAT(natsim.NATConfig{Name: []string{"left-c1b-product-", "right-c1b-product-"}[index] + label,
			PublicAddr: public[index], Model: test.models[index], Changes: changes})
		if err != nil {
			t.Fatal(err)
		}
	}
	var finishDelayWitness func() governor.C1bFinishDelayProof
	if test.slowFinish && test.slowResponderFinish {
		t.Fatal("FINISH delay fixtures must be independent")
	}
	if test.slowFinish || test.slowResponderFinish {
		side := 0
		if test.slowResponderFinish {
			side = 1
		}
		finishDelayWitness, err = governor.DelayC1bSuccessFinishForProof(machines[side], func() [2]uint64 {
			return [2]uint64{nats[0].Snapshot().OutboundPackets, nats[1].Snapshot().OutboundPackets}
		})
		if err != nil {
			t.Fatal("install test-only durable FINISH delay failed")
		}
	}
	topology := hardnatobserve.Topology{Primary: netip.MustParseAddrPort("203.0.113.10:3478"),
		Other: netip.MustParseAddrPort("203.0.113.11:3479")}
	responders := startNATSimRFC5780Responders(t, network, topology)

	set, err := gatecattempt.EncodeArtifactSet(gatecattempt.ArtifactMaterial{
		CredentialID: gateB2OpaqueID("c1b-product-credential"), AttemptID: gateB2OpaqueID("c1b-product-attempt"),
		InitiatorParticipantID: gateB2OpaqueID("c1b-product-initiator"),
		ResponderParticipantID: gateB2OpaqueID("c1b-product-responder"), OOBChannelID: gateB2OpaqueID("c1b-product-channel"),
		PlannerProfile: test.profile, ResourceClass: test.resource,
		InitiatorPlannerRole: test.plannerRoles[0], ResponderPlannerRole: test.plannerRoles[1],
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
	defer artifacts[0].Close()
	artifacts[1], err = gatecattempt.ParseArtifact(set.Responder, now)
	if err != nil {
		t.Fatal(err)
	}
	defer artifacts[1].Close()

	private := [2]tunnel.PrivateKey{}
	for index := range private {
		private[index], err = tunnel.GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
	}
	virtual := [2]string{"10.88.0.1", "10.88.0.2"}
	interfaceNames := [2]string{"wink-c1b-left", "wink-c1b-right"}
	if test.slowResponderFinish {
		// Parallel memory fixtures still pass real process-local ownership
		// validation. Give each one distinct synthetic routes/interfaces;
		// never bypass the product's collision guard.
		for index, profile := range gateC1bMemoryProfiles {
			if profile.name == test.name {
				virtual = [2]string{"198.51.100." + strconv.Itoa(61+index*4), "198.51.100." + strconv.Itoa(62+index*4)}
				interfaceNames = [2]string{"wc1b-l-" + strconv.Itoa(index), "wc1b-r-" + strconv.Itoa(index)}
			}
		}
	}
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
			MemoryInterfaceName: interfaceNames[index], MemoryMTU: 1280,
			SessionCeiling: test.sessionCeiling(),
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
	if test.slowFinish || test.slowResponderFinish {
		t.Logf("C1b slow fixture session witness: endpoints=2 session_ms=%d", test.sessionCeiling().Milliseconds())
	}
	requests[0].SSH = &gatecrequest.SSHConfig{Endpoint: sshEndpoint, User: "c1btest", IdentityFile: identity, KnownHostsFile: knownHosts}
	var configPaths, requestPaths [2]string
	if test.cli {
		for index := range 2 {
			if err := pairgen.WritePrivateFileExclusive(requests[index].ArtifactFile, [][]byte{set.Initiator, set.Responder}[index]); err != nil {
				t.Fatal("private artifact write failed")
			}
			requestBytes, err := gatecrequest.Encode(requests[index])
			if err != nil {
				t.Fatal("request encoding failed")
			}
			requestPaths[index] = filepath.Join(t.TempDir(), "request.json")
			if err := pairgen.WritePrivateFileExclusive(requestPaths[index], requestBytes); err != nil {
				t.Fatal("private request write failed")
			}
			configBytes, err := yaml.Marshal(configs[index])
			if err != nil {
				t.Fatal("config encoding failed")
			}
			configPaths[index] = filepath.Join(t.TempDir(), "config.yaml")
			if err := pairgen.WritePrivateFileExclusive(configPaths[index], configBytes); err != nil {
				t.Fatal("private config write failed")
			}
			clear(configBytes)
		}
		if err := gatecstage.StageMemoryProof(namespaces[1], requestPaths[1], now); err != nil {
			t.Fatal("durable responder stage failed")
		}
	}

	leftStream, rightStream := net.Pipe()
	defer leftStream.Close()
	defer rightStream.Close()
	clocks := [2]*gateB2ManualClock{newGateB2ManualClock(now), newGateB2ManualClock(now)}
	ready := 0
	var readyMu sync.Mutex
	initiatorCtx, cancelInitiator := context.WithCancel(context.Background())
	defer cancelInitiator()
	responderCtx, cancelResponder := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelResponder()
	var finishCancelWitness func() int32
	if test.cancelAfterFinish {
		finishCancelWitness, err = governor.CancelC1bAfterDurableFinishForProof(machines[0], cancelInitiator)
		if err != nil {
			t.Fatal("install test-only durable FINISH cancellation failed")
		}
	}
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
			proof := gatecorchestrator.MemoryProofOptions{
				Request: requests[index], Artifact: artifacts[index], Config: configs[index], Machine: machines[index],
				Ledger: ledgers[index], SSHAuthority: authority, Stream: []net.Conn{leftStream, rightStream}[index],
				ProbeFactory: &natSimProbeFactory{network: network, nat: nats[index],
					localAddress: []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.20")}[index],
					basePort:     []uint16{30000, 31000}[index], plannerRole: test.plannerRoles[index],
					witness: newCandidateWitness()},
				Harness: &gateb.HarnessHooks{NoiseRandom: bytes.NewReader(bytes.Repeat([]byte{byte(40 + index)}, 4096)),
					ObservationRandom: gateB2ObservationRandom(byte(70 + index)), Now: clocks[index].Now,
					NewTimer: clocks[index].NewTimer, Wait: clocks[index].Wait,
					ActiveEnvelope: test.activeTime, CandidateWindow: test.candidateTime},
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
				StageRoot: namespaces[index],
			}
			var result gatecorchestrator.Result
			var runErr error
			if test.cli {
				arguments := []string{"--config", configPaths[index], "solver", "direct", "child", "--stdio"}
				if index == 0 {
					arguments = []string{"--config", configPaths[index], "solver", "direct", "connect", "--request-file", requestPaths[index]}
				}
				var diagnostics bytes.Buffer
				var output io.Writer = rightStream
				if index == 0 {
					output = io.Discard
				}
				result, runErr = winkcmd.ExecuteGateCMemoryProof([]context.Context{initiatorCtx, responderCtx}[index], arguments,
					rightStream, output, &diagnostics, proof)
				for _, forbidden := range []string{configPaths[index], requestPaths[index], private[index].String(), public[index].String(), namespaces[index]} {
					if strings.Contains(diagnostics.String(), forbidden) {
						runErr = errors.Join(runErr, errors.New("CLI diagnostic privacy violation"))
					}
				}
			} else {
				result, runErr = gatecorchestrator.RunMemoryProof([]context.Context{initiatorCtx, responderCtx}[index], proof)
			}
			results <- outcome{role: role, result: result, err: runErr, stages: stages}
		}()
	}

	var outcomes []outcome
	for range 2 {
		select {
		case got := <-results:
			outcomes = append(outcomes, got)
		case <-time.After(35 * time.Second):
			t.Fatal("Gate C1b memory product pipeline exceeded its bound")
		}
	}
	matchedFault := 0
	var packetProofs [2]gateC1bPacketProof
	for _, got := range outcomes {
		if test.cancelAfterFinish {
			var failure *gatecorchestrator.Failure
			if !errors.As(got.err, &failure) || failure.Retryable || !failure.CredentialBurned ||
				got.result.DataPlaneReady || !got.result.FinishRecorded {
				t.Errorf("%s post-FINISH cancellation lost terminal/durability", got.role)
				continue
			}
			wg, handoff := got.result.Witness.WireGuard, got.result.Witness.Handoff
			side := 0
			if got.role == directattempt.RoleResponder {
				side = 1
			}
			if side == 0 && (!wg.PeerFinishConfirmed || wg.AttemptDetached || wg.State != "closed") {
				t.Error("cancelled initiator activated or lost authenticated FINISHED")
			}
			if side == 0 {
				failure := wg.CompletionFailure
				if failure == nil || failure.Point != "after_durable_finish" || failure.Attempt.State != "canceled" || failure.Session.State != "active" {
					t.Errorf("caller cancellation source was lost: %+v", failure)
				} else {
					t.Logf("C1b cancellation source: %+v", *failure)
				}
			}
			if !wg.FinishRecorded || !handoff.FinishRecorded || !handoff.AttemptReleased || !handoff.OOBDrained ||
				len(wg.Outbound)+wg.ReadinessWrites+wg.CompletionWrites != 3 ||
				len(wg.Inbound)+wg.ReadinessReads+wg.CompletionReads != 3 || wg.ActiveWrites != 0 || wg.ActiveReads != 0 ||
				handoff.Carrier.FramesRead != 8 || handoff.Carrier.FramesWritten != 8 {
				t.Errorf("%s cancelled completion lost ownership/3-packet/drain boundary", got.role)
			}
			if nats[side].Snapshot().OutboundPackets != uint64(got.result.Witness.GateB.Emissions.UDPPacketsTotal+3) {
				t.Errorf("%s cancelled completion emitted outside establishment", got.role)
			}
			t.Logf("C1b cancelled FINISH role=%s class=%s finish=%t detached=%t attempt_released=%t carrier_drained=%t active=0/0",
				got.role, failure.Class, wg.FinishRecorded, wg.AttemptDetached, handoff.AttemptReleased, handoff.OOBDrained)
			continue
		}
		if test.fault != "" {
			var failure *gatecorchestrator.Failure
			if !errors.As(got.err, &failure) || failure.Retryable || !failure.CredentialBurned || got.result.DataPlaneReady {
				t.Fatalf("%s fault lost its terminal: error=%v", got.role, got.err)
			}
			wanted := gateb.ClassCandidateExhausted
			if test.fault == "evidence-drift" {
				wanted = gateb.ClassEvidenceInsufficient
			}
			if failure.Class == wanted || (test.fault == "evidence-drift" && failure.Class == gateb.ClassEvidenceDrifted) {
				matchedFault++
			} else if failure.Class != gateb.ClassOOBStreamClosed {
				t.Fatalf("%s unexpected fault class=%s", got.role, failure.Class)
			}
			gate := got.result.Witness.GateB
			if !gate.CredentialBurned || !gate.FinishRecorded || gate.Bidirectional || gate.Emissions.CandidatePackets > 32 ||
				gate.Emissions.DataPacketsRead != 0 || gate.Emissions.DataPacketsWritten != 0 ||
				got.result.Witness.WireGuard.ReadinessWrites != 0 || got.result.Witness.WireGuard.ActiveWrites != 0 ||
				(test.fault == "evidence-drift" && gate.Emissions.CandidatePackets != 0) {
				t.Fatalf("%s fault emission/finish witness=%+v", got.role, gate)
			}
			if len(got.stages) < 2 || got.stages[len(got.stages)-1] != gatecorchestrator.StageTerminal ||
				!reflect.DeepEqual(got.stages[:len(got.stages)-1], gatecorchestrator.ProductProgressSequence[:len(got.stages)-1]) {
				t.Fatalf("%s fault did not preserve longest completed prefix: %v", got.role, got.stages)
			}
			t.Logf("C1b memory CLI fault=%s role=%s class=%s evidence=%d candidates=%d finish=true retry=0",
				test.fault, got.role, failure.Class, gate.Emissions.EvidencePackets, gate.Emissions.CandidatePackets)
			continue
		}
		if got.err != nil {
			if failure := got.result.Witness.WireGuard.CompletionFailure; failure != nil {
				t.Logf("C1b completion failure role=%s: %+v", got.role, *failure)
			}
			var failure *gatecorchestrator.Failure
			var cause error
			if errors.As(got.err, &failure) {
				cause = failure.Cause
			}
			t.Errorf("%s pipeline error=%v cause=%v result=%+v stages=%v", got.role, got.err, cause, got.result, got.stages)
			continue
		}
		if !got.result.DataPlaneReady || !got.result.FinishRecorded || got.result.Terminal != "success" ||
			!reflect.DeepEqual(got.stages, gatecorchestrator.ProductProgressSequence) {
			t.Errorf("%s result=%+v stages=%v", got.role, got.result, got.stages)
		}
		if got.result.Witness.WireGuard.State != "active" || got.result.Witness.Echo.Drained != true {
			t.Errorf("%s wireguard/echo witness=%+v/%+v", got.role, got.result.Witness.WireGuard, got.result.Witness.Echo)
		}
		wg := got.result.Witness.WireGuard
		if !wg.ConsumerReady || wg.ReadinessWrites != 1 || wg.ReadinessReads != 1 ||
			len(wg.Outbound)+wg.ReadinessWrites+wg.CompletionWrites != 3 || len(wg.Inbound)+wg.ReadinessReads+wg.CompletionReads != 3 {
			t.Errorf("%s shared challenge allowance violated: %+v", got.role, wg)
		}
		endpointIndex := 0
		if got.role == directattempt.RoleResponder {
			endpointIndex = 1
		}
		emissions := got.result.Witness.GateB.Emissions
		packetProofs[endpointIndex] = gateC1bPacketProof{
			emissions: emissions, establishment: len(wg.Outbound) + wg.ReadinessWrites + wg.CompletionWrites,
			active: wg.ActiveWrites, actualUDP: nats[endpointIndex].Snapshot().OutboundPackets,
		}
		t.Logf("C1b packet components: profile=%s slow_finish=%t role=%s evidence=%d candidates=%d winner=%d active_writes=%d UDP=%d",
			test.name, test.slowFinish, got.role, emissions.EvidencePackets, emissions.CandidatePackets,
			emissions.WinnerPackets, wg.ActiveWrites, nats[endpointIndex].Snapshot().OutboundPackets)
		if test.slowFinish || test.slowResponderFinish {
			if !wg.FinishRecorded || !wg.AttemptDetached || (endpointIndex == 0 && !wg.PeerFinishConfirmed) ||
				!got.result.Witness.Handoff.OOBDrained || !got.result.Witness.Handoff.AttemptReleased ||
				got.result.Witness.Handoff.Carrier.FramesRead != 8 || got.result.Witness.Handoff.Carrier.FramesWritten != 8 {
				t.Errorf("%s slow FINISH lost authenticated completion/ownership: %+v", got.role, got.result.Witness.Handoff)
			}
			actualPackets := nats[endpointIndex].Snapshot().OutboundPackets
			t.Logf("C1b slow FINISH profile=%s role=%s data_plane_ready=%t finish=%t peer_confirmed=%t detached=%t completion_w=%d completion_r=%d UDP=%d carrier=8/8 challenge=3/3 echo_drained=%t",
				test.name, got.role, got.result.DataPlaneReady, wg.FinishRecorded, wg.PeerFinishConfirmed,
				wg.AttemptDetached, wg.CompletionWrites, wg.CompletionReads, actualPackets, got.result.Witness.Echo.Drained)
		}
	}
	var delayProof *governor.C1bFinishDelayProof
	if finishDelayWitness != nil {
		proof := finishDelayWitness()
		delayProof = &proof
		t.Logf("C1b slow FINISH durable witness: calls=%d post_fsync_delay_ms=%d UDP_before=%v UDP_after=%v",
			proof.Calls, proof.Waited.Milliseconds(), proof.Before, proof.After)
	}
	if finishCancelWitness != nil && finishCancelWitness() != 1 {
		t.Error("post-fsync caller cancellation was not exactly once")
	}
	if test.fault == "" && !test.cancelAfterFinish {
		if err := validateGateC1bPacketAccounting(test, packetProofs, delayProof); err != nil {
			t.Error(err)
		}
	}
	if test.fault != "" && matchedFault == 0 {
		t.Fatal("fault matrix did not observe its injected root cause")
	}
	for _, responder := range responders {
		_ = responder.Close()
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		counters := network.Snapshot()
		if counters.ActivePacketConns == 0 && counters.ActiveMappings == 0 && counters.QueuedPackets == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s natsim residue=%+v", label, counters)
		}
		time.Sleep(time.Millisecond)
	}
	for index, machine := range machines {
		snapshot := machine.Snapshot()
		if snapshot.ActivePeers != 0 || snapshot.ActiveAttempts != 0 || snapshot.HeavyweightAttempts != 0 ||
			snapshot.Reserved != (governor.Resources{}) || snapshot.SafetyTrip.BlocksActiveWork {
			t.Fatalf("%s side %d governor residue=%+v", label, index, snapshot)
		}
		if test.fault != "" {
			status, err := governor.InspectLoopbackCarrierTestLedger(namespaces[index], now)
			if err != nil || status.Sequence != 3 || status.TwentyFourHourAdmissions != 1 {
				t.Fatalf("fault durable burn/FINISH witness=%+v error=%v", status, err)
			}
		}
		if test.cancelAfterFinish {
			status, inspectErr := governor.InspectLoopbackCarrierTestLedger(namespaces[index], now)
			unfinished, _, occupancyErr := governor.InspectLoopbackCarrierTestOccupancy(namespaces[index], now)
			if inspectErr != nil || occupancyErr != nil || status.Sequence != 3 || status.Records != 3 ||
				status.TwentyFourHourAdmissions != 1 || status.ConsecutiveFailures != 0 || unfinished != 0 {
				t.Errorf("side %d cancellation rewrote or lost successful durable FINISH", index)
			}
		}
	}
	if test.cli {
		if claimed, err := gatecstage.ClaimMemoryProof(namespaces[1], now); err == nil || claimed != nil {
			t.Fatal("child slot was reusable")
		}
	}
}
