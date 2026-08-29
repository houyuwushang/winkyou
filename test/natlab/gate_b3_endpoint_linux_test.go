//go:build linux && natlab

package natlab

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/probeio"
	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/directconnect/gateb"
	"winkyou/internal/v2/hardnatobserve"
)

const (
	gateB3RequiredEnv       = "WINKYOU_GATE_B3_REQUIRED"
	gateB3EndpointHelperEnv = "WINKYOU_GATE_B3_ENDPOINT_HELPER"
	gateB3HelperConfigEnv   = "WINKYOU_GATE_B3_HELPER_CONFIG"
	gateB3EndpointLimit     = 49 * time.Second
	gateB3FaultENOBUFS      = "enobufs_after_evidence"
)

type gateB3EndpointResult struct {
	gateB2EndpointResult
	CampaignState      string `json:"campaign_state"`
	CampaignAdmissions int    `json:"campaign_admissions"`
	CampaignPackets    int    `json:"campaign_packets"`
	CampaignCircuit    bool   `json:"campaign_circuit_open"`
}

func TestGateB3EndpointProcess(t *testing.T) {
	if os.Getenv(gateB3EndpointHelperEnv) != "1" {
		return
	}
	var config gateB2EndpointConfig
	if !readN1JSON(os.Getenv(gateB3HelperConfigEnv), &config) || !validGateB2EndpointConfig(config) || config.ReadyPath == "" {
		t.Fatal("Gate B3 endpoint helper configuration rejected")
	}
	started := time.Now()
	result, internalErr := runGateB3Endpoint(config)
	result.ElapsedMilliseconds = time.Since(started).Milliseconds()
	if internalErr != nil {
		result.OK = false
		if result.ErrorClass == "" {
			result.ErrorClass = "internal_error"
		}
	}
	if err := writeN1JSON(config.ResultPath, result); err != nil {
		t.Fatal("Gate B3 endpoint result write failed")
	}
	if internalErr != nil {
		t.Error("Gate B3 endpoint helper failed")
	}
}

func runGateB3Endpoint(config gateB2EndpointConfig) (result gateB3EndpointResult, resultErr error) {
	result.Role = config.Role
	streamFile := os.NewFile(gateB2StreamFD, "gate-b3-oob")
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
	topology := hardnatobserve.Topology{Primary: primary, Other: other}
	endpoints, err := topology.Endpoints()
	if err != nil {
		return result, err
	}
	side := probeio.GateB2NATLabLeft
	if directattempt.Role(config.Role) == directattempt.RoleResponder {
		side = probeio.GateB2NATLabRight
	}
	var natLabFactory probeio.HardNATCampaignNATLabFactory
	if config.Fault == "" {
		natLabFactory, err = probeio.NewGateB3NATLabFactory(config.Namespace, side, endpoints)
	} else if config.Fault == gateB3FaultENOBUFS {
		natLabFactory, err = probeio.NewGateB3ENOBUFSNATLabFactory(config.Namespace, side, endpoints)
	} else {
		return result, errors.New("Gate B3 fault profile rejected")
	}
	if err != nil {
		return result, err
	}
	for _, forbidden := range []netip.Addr{
		netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("192.0.2.200"), netip.MustParseAddr("198.18.0.1"),
	} {
		if natLabFactory.ValidatePeerAddress(forbidden) == nil {
			return result, errors.New("hard natlab factory accepted an address outside the fixed peer topology")
		}
	}

	owner, err := governor.AcquirePreparedNamespace(config.GovernorDir, governor.ScopeMachine, "gate-b3-netns")
	if err != nil {
		return result, err
	}
	machine, err := governor.New(owner, governor.ProfilePhase1HardNATCampaign, nil)
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
	ctx, cancel := context.WithTimeout(signalContext, gateB3EndpointLimit)
	defer cancel()
	if err := os.WriteFile(config.ReadyPath, []byte("ready\n"), 0o600); err != nil {
		return result, err
	}
	gateResult, runErr := gateb.Run(ctx, gateb.Config{
		Machine: machine, Ledger: ledger, Artifact: artifact, Stream: stream,
		ObserverTopology: topology, HardNATLabFactory: natLabFactory, BuildVersion: "gate-b3-netns",
		Progress: func(string, bool) error { return nil },
	})
	copyGateB3Result(&result, gateResult)
	if runErr != nil {
		var failure *gateb.Failure
		if !errors.As(runErr, &failure) {
			resultErr = errors.Join(resultErr, runErr)
		} else {
			result.ErrorClass = failure.Class
			result.ErrorStage = failure.Stage
		}
	}

	ordinary := ledger.Status()
	result.LedgerSequence = ordinary.Sequence
	result.LedgerRecords = ordinary.Records
	result.LedgerAdmissions = ordinary.TwentyFourHourAdmissions
	result.LedgerFailures = ordinary.ConsecutiveFailures
	campaign := ledger.CampaignStatus()
	result.CampaignState = string(campaign.State)
	result.CampaignAdmissions = campaign.TwentyFourHourAdmissions
	result.CampaignPackets = campaign.TwentyFourHourPackets
	result.CampaignCircuit = campaign.ExplicitResetRequired
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

func copyGateB3Result(result *gateB3EndpointResult, gateResult gateb.Result) {
	if result == nil {
		return
	}
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
}
