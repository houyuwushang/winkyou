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
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/directconnect/gatea"
)

const (
	gateARequiredEnv       = "WINKYOU_GATE_A_REQUIRED"
	gateAEndpointHelperEnv = "WINKYOU_GATE_A_ENDPOINT_HELPER"
	gateAHelperConfigEnv   = "WINKYOU_GATE_A_HELPER_CONFIG"
	gateAStreamFD          = uintptr(3)
	gateAProcessLimit      = 16 * time.Second
)

type gateAEndpointConfig struct {
	Role         string   `json:"role"`
	GovernorDir  string   `json:"governor_dir"`
	ArtifactPath string   `json:"artifact_path"`
	ResultPath   string   `json:"result_path"`
	EventDir     string   `json:"event_dir"`
	PauseStage   string   `json:"pause_stage,omitempty"`
	ReleasePath  string   `json:"release_path,omitempty"`
	STUNTargets  []string `json:"stun_targets"`
}

type gateAEndpointEvent struct {
	Stage string `json:"stage"`
}

type gateAEndpointResult struct {
	OK                  bool   `json:"ok"`
	Role                string `json:"role"`
	Terminal            string `json:"terminal"`
	ErrorClass          string `json:"error_class,omitempty"`
	ErrorStage          string `json:"error_stage,omitempty"`
	CredentialBurned    bool   `json:"credential_burned"`
	FinishRecorded      bool   `json:"finish_recorded"`
	Bidirectional       bool   `json:"bidirectional"`
	MappingBehavior     string `json:"mapping_behavior,omitempty"`
	STUNPackets         int    `json:"stun_packets"`
	DirectPackets       int    `json:"direct_packets"`
	UDPPackets          int    `json:"udp_packets"`
	DataPacketsRead     int    `json:"data_packets_read"`
	DataPacketsWritten  int    `json:"data_packets_written"`
	CarrierFramesRead   int    `json:"carrier_frames_read"`
	CarrierFramesWrite  int    `json:"carrier_frames_written"`
	CarrierDrained      bool   `json:"carrier_drained"`
	TransportAttached   bool   `json:"transport_attached"`
	TransportAdopted    bool   `json:"transport_adopted"`
	TransportStandby    bool   `json:"transport_standby"`
	ChallengePassed     bool   `json:"challenge_passed"`
	TransportDetached   bool   `json:"transport_detached"`
	TransportDrained    bool   `json:"transport_drained"`
	SafetyState         string `json:"safety_state"`
	SafetyBlocksWork    bool   `json:"safety_blocks_work"`
	LedgerSequence      uint64 `json:"ledger_sequence"`
	LedgerRecords       int    `json:"ledger_records"`
	LedgerAdmissions    int    `json:"ledger_admissions"`
	LedgerFailures      int    `json:"ledger_failures"`
	UnfinishedAdmission int    `json:"unfinished_admissions"`
	UnfinishedPackets   int    `json:"unfinished_packets"`
	ActivePeers         int    `json:"active_peers"`
	ActiveAttempts      int    `json:"active_attempts"`
	ReservedSockets     int    `json:"reserved_sockets"`
	ReservedTargets     int    `json:"reserved_targets"`
	ReservedFiveTuples  int    `json:"reserved_five_tuples"`
	ReservedPackets     int    `json:"reserved_packets"`
	ElapsedMilliseconds int64  `json:"elapsed_milliseconds"`
}

func TestGateAEndpointProcess(t *testing.T) {
	if os.Getenv(gateAEndpointHelperEnv) != "1" {
		return
	}
	var config gateAEndpointConfig
	if !readN1JSON(os.Getenv(gateAHelperConfigEnv), &config) || !validGateAEndpointConfig(config) {
		t.Fatal("Gate A endpoint helper configuration rejected")
	}
	started := time.Now()
	result, internalErr := runGateAEndpoint(config)
	result.ElapsedMilliseconds = time.Since(started).Milliseconds()
	if internalErr != nil {
		result.OK = false
		if result.ErrorClass == "" {
			result.ErrorClass = "internal_error"
		}
	}
	if err := writeN1JSON(config.ResultPath, result); err != nil {
		t.Fatal("Gate A endpoint result write failed")
	}
	if internalErr != nil {
		t.Error("Gate A endpoint helper failed")
	}
}

func validGateAEndpointConfig(config gateAEndpointConfig) bool {
	role := directattempt.Role(config.Role)
	if !role.Valid() || config.GovernorDir == "" || config.ArtifactPath == "" ||
		config.ResultPath == "" || config.EventDir == "" || len(config.STUNTargets) != 2 {
		return false
	}
	if config.PauseStage != "" && !gateAProgressStage(config.PauseStage) {
		return false
	}
	for _, target := range config.STUNTargets {
		endpoint, err := netip.ParseAddrPort(target)
		if err != nil || !endpoint.IsValid() || endpoint.Port() == 0 {
			return false
		}
	}
	return true
}

func runGateAEndpoint(config gateAEndpointConfig) (result gateAEndpointResult, resultErr error) {
	result.Role = config.Role
	streamFile := os.NewFile(gateAStreamFD, "gate-a-oob")
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
	stunTargets := make([]netip.AddrPort, 0, 2)
	for _, value := range config.STUNTargets {
		target, parseErr := netip.ParseAddrPort(value)
		if parseErr != nil {
			return result, parseErr
		}
		stunTargets = append(stunTargets, target)
	}

	owner, err := governor.AcquirePreparedNamespace(config.GovernorDir, governor.ScopeMachine, "gate-a-netns")
	if err != nil {
		return result, err
	}
	machine, err := governor.New(owner, governor.ProfilePhase1Machine, nil)
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
	ctx, cancel := context.WithTimeout(signalContext, 13*time.Second)
	defer cancel()
	gateResult, runErr := gatea.Run(ctx, gatea.Config{
		Machine: machine, Ledger: ledger, Artifact: artifact, Stream: stream,
		STUNTargets: stunTargets, AllowNonLoopback: true, BuildVersion: "gate-a-netns",
		Progress: func(stage string, _ bool) error {
			if err := writeN1JSON(filepath.Join(config.EventDir, stage+".json"), gateAEndpointEvent{Stage: stage}); err != nil {
				return err
			}
			if config.PauseStage != stage {
				return nil
			}
			return waitGateARelease(ctx, config.ReleasePath)
		},
	})
	result.Terminal = gateResult.Terminal
	result.CredentialBurned = gateResult.CredentialBurned
	result.FinishRecorded = gateResult.FinishRecorded
	result.Bidirectional = gateResult.Bidirectional
	result.MappingBehavior = gateResult.MappingBehavior
	result.STUNPackets = gateResult.Emissions.STUNPackets
	result.DirectPackets = gateResult.Emissions.DirectPackets
	result.UDPPackets = gateResult.Emissions.UDPPacketsTotal
	result.DataPacketsRead = gateResult.Emissions.DataPacketsRead
	result.DataPacketsWritten = gateResult.Emissions.DataPacketsWritten
	result.CarrierFramesRead = gateResult.Emissions.CarrierFramesRead
	result.CarrierFramesWrite = gateResult.Emissions.CarrierFramesWrite
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
		var failure *gatea.Failure
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
	result.ReservedSockets = snapshot.Reserved.Sockets
	result.ReservedTargets = snapshot.Reserved.Targets
	result.ReservedFiveTuples = snapshot.Reserved.FiveTuples
	result.ReservedPackets = snapshot.Reserved.Packets
	result.SafetyState = string(snapshot.SafetyTrip.State)
	result.SafetyBlocksWork = snapshot.SafetyTrip.BlocksActiveWork
	resultErr = errors.Join(resultErr, machine.Close())
	result.OK = resultErr == nil
	return result, resultErr
}

func waitGateARelease(ctx context.Context, releasePath string) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var release struct {
			Ready bool `json:"ready"`
		}
		if readN1JSON(releasePath, &release) && release.Ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func gateAProgressStage(stage string) bool {
	for _, allowed := range gatea.ProgressSequence {
		if stage == allowed {
			return true
		}
	}
	return false
}

func gateAResultRedacted(result gateAEndpointResult) bool {
	payload, err := json.Marshal(result)
	if err != nil {
		return false
	}
	forbiddenValues := []string{
		n2dClientAAddress, n2dNATALAN, n2dNATAWAN, n2dPublicA,
		n2dPublicB, n2dNATBWAN, n2dNATBLAN, n2dClientBAddress,
	}
	if hostname, err := os.Hostname(); err == nil && len(hostname) >= 3 {
		forbiddenValues = append(forbiddenValues, hostname)
	}
	for _, key := range []string{"USER", "USERNAME"} {
		if value := os.Getenv(key); len(value) >= 3 {
			forbiddenValues = append(forbiddenValues, value)
		}
	}
	if working, err := os.Getwd(); err == nil {
		forbiddenValues = append(forbiddenValues, working)
	}
	if home, err := os.UserHomeDir(); err == nil {
		forbiddenValues = append(forbiddenValues, home)
	}
	for _, forbidden := range forbiddenValues {
		if containsBytes(payload, []byte(forbidden)) {
			return false
		}
	}
	return true
}

func containsBytes(payload, fragment []byte) bool {
	if len(fragment) == 0 || len(payload) < len(fragment) {
		return false
	}
	for offset := 0; offset+len(fragment) <= len(payload); offset++ {
		match := true
		for index := range fragment {
			if payload[offset+index] != fragment[index] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
