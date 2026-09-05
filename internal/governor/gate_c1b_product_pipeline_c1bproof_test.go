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
	name          string
	profile       hardnatplan.Profile
	resource      hardnatplan.ResourceClass
	plannerRoles  [2]hardnatplan.Role
	models        [2]natsim.Model
	maxConns      int
	maxMappings   int
	queueCapacity int
	candidateTime time.Duration
	activeTime    time.Duration
	acquire       func(string, string) (*governor.Governor, error)
	cli           bool
	fault         string
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
	for _, test := range gateC1bMemoryProfiles {
		t.Run(test.name, func(t *testing.T) {
			runGateC1bMemoryProductProfile(t, test.name, test)
		})
	}
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
	for _, got := range outcomes {
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
	}
	if test.cli {
		if claimed, err := gatecstage.ClaimMemoryProof(namespaces[1], now); err == nil || claimed != nil {
			t.Fatal("child slot was reusable")
		}
	}
}
