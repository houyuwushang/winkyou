//go:build linux && natlab

package natlab

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/directconnect/gateb"
	"winkyou/internal/v2/hardnatobserve"
	"winkyou/internal/v2/hardnatplan"
)

const (
	gateB2RequiredEnv       = "WINKYOU_GATE_B2_REQUIRED"
	gateB2EndpointHelperEnv = "WINKYOU_GATE_B2_ENDPOINT_HELPER"
	gateB2HelperConfigEnv   = "WINKYOU_GATE_B2_HELPER_CONFIG"
	gateB2StreamFD          = uintptr(3)
	gateB2EndpointLimit     = 24 * time.Second
)

type gateB2EndpointConfig struct {
	Role            string `json:"role"`
	GovernorDir     string `json:"governor_dir"`
	ArtifactPath    string `json:"artifact_path"`
	ResultPath      string `json:"result_path"`
	ObserverPrimary string `json:"observer_primary"`
	ObserverOther   string `json:"observer_other"`
}

type gateB2EndpointResult struct {
	OK                  bool   `json:"ok"`
	Role                string `json:"role"`
	Terminal            string `json:"terminal"`
	Profile             string `json:"profile"`
	ResourceClass       string `json:"resource_class"`
	ErrorClass          string `json:"error_class,omitempty"`
	ErrorStage          string `json:"error_stage,omitempty"`
	CredentialBurned    bool   `json:"credential_burned"`
	FinishRecorded      bool   `json:"finish_recorded"`
	Bidirectional       bool   `json:"bidirectional"`
	Conditional         bool   `json:"conditional"`
	ProbabilityFloor    uint64 `json:"probability_floor_parts_per_trillion"`
	HandshakeFrames     int    `json:"handshake_frames"`
	ControlFrames       int    `json:"control_frames"`
	EvidencePackets     int    `json:"evidence_packets"`
	CandidatePackets    int    `json:"candidate_packets"`
	WinnerPackets       int    `json:"winner_packets"`
	UDPPackets          int    `json:"udp_packets"`
	DataPacketsRead     int    `json:"data_packets_read"`
	DataPacketsWritten  int    `json:"data_packets_written"`
	SocketsOpened       int    `json:"sockets_opened"`
	TargetsRegistered   int    `json:"targets_registered"`
	FiveTuples          int    `json:"five_tuples"`
	EnvelopeSockets     int    `json:"envelope_sockets"`
	EnvelopeTargets     int    `json:"envelope_targets"`
	EnvelopeFiveTuples  int    `json:"envelope_five_tuples"`
	EnvelopePackets     int    `json:"envelope_packets"`
	EnvelopePPS         int    `json:"envelope_packets_per_second"`
	EnvelopeDurationMS  int64  `json:"envelope_duration_ms"`
	CarrierFramesRead   int    `json:"carrier_frames_read"`
	CarrierFramesWrite  int    `json:"carrier_frames_written"`
	CarrierBytesRead    int    `json:"carrier_bytes_read"`
	CarrierBytesWrite   int    `json:"carrier_bytes_written"`
	CarrierDrained      bool   `json:"carrier_drained"`
	TransportAttached   bool   `json:"transport_attached"`
	TransportAdopted    bool   `json:"transport_adopted"`
	TransportStandby    bool   `json:"transport_standby"`
	ChallengePassed     bool   `json:"challenge_passed"`
	TransportDetached   bool   `json:"transport_detached"`
	TransportDrained    bool   `json:"transport_drained"`
	SafetyState         string `json:"safety_state"`
	SafetyReason        string `json:"safety_reason,omitempty"`
	SafetyBlocksWork    bool   `json:"safety_blocks_work"`
	LedgerSequence      uint64 `json:"ledger_sequence"`
	LedgerRecords       int    `json:"ledger_records"`
	LedgerAdmissions    int    `json:"ledger_admissions"`
	LedgerFailures      int    `json:"ledger_failures"`
	UnfinishedAdmission int    `json:"unfinished_admissions"`
	UnfinishedPackets   int    `json:"unfinished_packets"`
	ActivePeers         int    `json:"active_peers"`
	ActiveAttempts      int    `json:"active_attempts"`
	HeavyweightAttempts int    `json:"heavyweight_attempts"`
	ReservedSockets     int    `json:"reserved_sockets"`
	ReservedTargets     int    `json:"reserved_targets"`
	ReservedFiveTuples  int    `json:"reserved_five_tuples"`
	ReservedPackets     int    `json:"reserved_packets"`
	ElapsedMilliseconds int64  `json:"elapsed_milliseconds"`
}

func TestGateB2EndpointProcess(t *testing.T) {
	if os.Getenv(gateB2EndpointHelperEnv) != "1" {
		return
	}
	var config gateB2EndpointConfig
	if !readN1JSON(os.Getenv(gateB2HelperConfigEnv), &config) || !validGateB2EndpointConfig(config) {
		t.Fatal("Gate B2 endpoint helper configuration rejected")
	}
	started := time.Now()
	result, internalErr := runGateB2Endpoint(config)
	result.ElapsedMilliseconds = time.Since(started).Milliseconds()
	if internalErr != nil {
		result.OK = false
		if result.ErrorClass == "" {
			result.ErrorClass = "internal_error"
		}
	}
	if err := writeN1JSON(config.ResultPath, result); err != nil {
		t.Fatal("Gate B2 endpoint result write failed")
	}
	if internalErr != nil {
		t.Error("Gate B2 endpoint helper failed")
	}
}

func validGateB2EndpointConfig(config gateB2EndpointConfig) bool {
	role := directattempt.Role(config.Role)
	if !role.Valid() || config.GovernorDir == "" || config.ArtifactPath == "" || config.ResultPath == "" {
		return false
	}
	primary, primaryErr := netip.ParseAddrPort(config.ObserverPrimary)
	other, otherErr := netip.ParseAddrPort(config.ObserverOther)
	if primaryErr != nil || otherErr != nil {
		return false
	}
	_, err := (hardnatobserve.Topology{Primary: primary, Other: other}).Endpoints()
	return err == nil
}

func runGateB2Endpoint(config gateB2EndpointConfig) (result gateB2EndpointResult, resultErr error) {
	result.Role = config.Role
	streamFile := os.NewFile(gateB2StreamFD, "gate-b2-oob")
	if streamFile == nil {
		return result, errors.New("bounded stream descriptor unavailable")
	}
	stream, err := net.FileConn(streamFile)
	_ = streamFile.Close()
	if err != nil {
		return result, err
	}
	defer stream.Close()

	artifact, err := os.ReadFile(config.ArtifactPath)
	if err != nil {
		return result, err
	}
	defer clear(artifact)
	primary, _ := netip.ParseAddrPort(config.ObserverPrimary)
	other, _ := netip.ParseAddrPort(config.ObserverOther)

	owner, err := governor.AcquirePreparedNamespace(config.GovernorDir, governor.ScopeMachine, "gate-b2-netns")
	if err != nil {
		return result, err
	}
	machine, err := governor.New(owner, governor.ProfilePhase1ManualTraversal, nil)
	if err != nil {
		_ = owner.Close()
		return result, err
	}
	ledger, err := governor.GateATestPairingLedger(machine)
	if err != nil {
		_ = machine.Close()
		return result, err
	}

	signalContext, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	ctx, cancel := context.WithTimeout(signalContext, 22*time.Second)
	defer cancel()
	gateResult, runErr := gateb.Run(ctx, gateb.Config{
		Machine: machine, Ledger: ledger, Artifact: artifact, Stream: stream,
		ObserverTopology: hardnatobserve.Topology{Primary: primary, Other: other},
		AllowNonLoopback: true, BuildVersion: "gate-b2-netns",
		Progress: func(string, bool) error { return nil },
	})
	result.Terminal = gateResult.Terminal
	result.Profile = string(gateResult.Profile)
	result.ResourceClass = string(gateResult.ResourceClass)
	result.CredentialBurned = gateResult.CredentialBurned
	result.FinishRecorded = gateResult.FinishRecorded
	result.Bidirectional = gateResult.Bidirectional
	result.Conditional = gateResult.Conditional
	result.ProbabilityFloor = gateResult.ProbabilityFloor
	result.HandshakeFrames = gateResult.Emissions.HandshakeFrames
	result.ControlFrames = gateResult.Emissions.ControlFrames
	result.EvidencePackets = gateResult.Emissions.EvidencePackets
	result.CandidatePackets = gateResult.Emissions.CandidatePackets
	result.WinnerPackets = gateResult.Emissions.WinnerPackets
	result.UDPPackets = gateResult.Emissions.UDPPacketsTotal
	result.DataPacketsRead = gateResult.Emissions.DataPacketsRead
	result.DataPacketsWritten = gateResult.Emissions.DataPacketsWritten
	result.SocketsOpened = gateResult.Emissions.SocketsOpened
	result.TargetsRegistered = gateResult.Emissions.TargetsRegistered
	result.FiveTuples = gateResult.Emissions.FiveTuples
	result.EnvelopeSockets = gateResult.ReservedEnvelope.Sockets
	result.EnvelopeTargets = gateResult.ReservedEnvelope.Targets
	result.EnvelopeFiveTuples = gateResult.ReservedEnvelope.FiveTuples
	result.EnvelopePackets = gateResult.ReservedEnvelope.Packets
	result.EnvelopePPS = gateResult.ReservedEnvelope.PacketsPerSecond
	result.EnvelopeDurationMS = gateResult.ReservedEnvelope.DurationMillis
	result.CarrierFramesRead = gateResult.Emissions.CarrierFramesRead
	result.CarrierFramesWrite = gateResult.Emissions.CarrierFramesWrite
	result.CarrierBytesRead = gateResult.Emissions.CarrierBytesRead
	result.CarrierBytesWrite = gateResult.Emissions.CarrierBytesWrite
	result.CarrierDrained = gateResult.CarrierWitness.Drained && gateResult.CarrierWitness.Closed
	result.TransportAttached = gateResult.TransportWitness.Attached
	result.TransportAdopted = gateResult.TransportWitness.Adopted
	result.TransportStandby = gateResult.TransportWitness.Standby
	result.ChallengePassed = gateResult.TransportWitness.ChallengePassed
	result.TransportDetached = gateResult.TransportWitness.AttemptDetached
	result.TransportDrained = gateResult.TransportWitness.Drained && gateResult.TransportWitness.Closed
	result.SafetyState = string(gateResult.SafetyTrip.State)
	result.SafetyBlocksWork = gateResult.SafetyTrip.BlocksActiveWork
	if runErr != nil {
		var failure *gateb.Failure
		if !errors.As(runErr, &failure) {
			resultErr = errors.Join(resultErr, runErr)
		} else {
			result.ErrorClass = failure.Class
			result.ErrorStage = failure.Stage
		}
	}

	status := ledger.Status()
	result.LedgerSequence = status.Sequence
	result.LedgerRecords = status.Records
	result.LedgerAdmissions = status.TwentyFourHourAdmissions
	result.LedgerFailures = status.ConsecutiveFailures
	result.UnfinishedAdmission, result.UnfinishedPackets, err = governor.GateATestLedgerOccupancy(machine)
	if err != nil {
		resultErr = errors.Join(resultErr, err)
	}
	snapshot := machine.Snapshot()
	result.ActivePeers = snapshot.ActivePeers
	result.ActiveAttempts = snapshot.ActiveAttempts
	result.HeavyweightAttempts = snapshot.HeavyweightAttempts
	result.ReservedSockets = snapshot.Reserved.Sockets
	result.ReservedTargets = snapshot.Reserved.Targets
	result.ReservedFiveTuples = snapshot.Reserved.FiveTuples
	result.ReservedPackets = snapshot.Reserved.Packets
	result.SafetyState = string(snapshot.SafetyTrip.State)
	result.SafetyReason = string(snapshot.SafetyTrip.Record.Reason)
	result.SafetyBlocksWork = snapshot.SafetyTrip.BlocksActiveWork
	resultErr = errors.Join(resultErr, machine.Close())
	result.OK = resultErr == nil
	return result, resultErr
}

func gateB2ResultContainsPrivateMaterial(result gateB2EndpointResult) bool {
	payload, err := json.Marshal(result)
	if err != nil {
		return true
	}
	defer clear(payload)
	var decoded map[string]any
	if json.Unmarshal(payload, &decoded) != nil {
		return true
	}
	for _, forbidden := range []string{"endpoint", "address", "hostname", "username", "path", "pid", "psk", "secret", "candidate_port"} {
		if _, exists := decoded[forbidden]; exists {
			return true
		}
	}
	return false
}

func gateB2ExpectedProfile(profile hardnatplan.Profile) (string, string) {
	if profile == hardnatplan.ProfilePredictiveEdm {
		return string(profile), string(hardnatplan.ResourcePredictive)
	}
	return string(profile), string(hardnatplan.ResourceAsymmetric)
}
