//go:build linux && natlab

package natlab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/solverstdio"
	"winkyou/internal/stdiojsonrpc"
	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/directconnect"
)

const n3bActionStdioV2 = "n3b_stdio_v2_attempt"

func testN3BStdioV2EIMSuccess(t *testing.T) {
	topology := newN2DTopology(t, n2dMappingEIM, n2dMappingEIM)
	servers := startN3BServers(t, topology)
	artifacts := buildN2DArtifacts(t, "n3b-stdio-v2-eim", time.Now())
	initiator := newN3BStdioEndpointProcess(t, topology, servers, artifacts, directattempt.RoleInitiator)
	responder := newN3BStdioEndpointProcess(t, topology, servers, artifacts, directattempt.RoleResponder)

	initiator.start(t)
	responder.start(t)
	initiatorResult := initiator.waitResult(t)
	responderResult := responder.waitResult(t)
	assertN2DSuccessResult(t, initiatorResult, directattempt.RoleInitiator)
	assertN2DSuccessResult(t, responderResult, directattempt.RoleResponder)
	counts := requireN2DPacketCounts(t, topology)
	assertN2DPacketResultMatch(t, counts, initiatorResult, responderResult)
	if counts.InitiatorDirect != 2 || counts.ResponderDirect != 1 || counts.InitiatorTotal > 5 || counts.ResponderTotal > 4 {
		t.Fatalf("N3b stdio v2 UDP witness exceeded the frozen N2 envelope: %+v", counts)
	}
	carrier := servers.rendezvous.Stats()
	if carrier.Accepted != 2 || carrier.SlotARead != 7 || carrier.SlotAWritten != 6 || carrier.SlotBRead != 6 || carrier.SlotBWritten != 7 {
		t.Fatalf("N3b stdio v2 carrier witness = accepted:%d A:%d/%d B:%d/%d",
			carrier.Accepted, carrier.SlotARead, carrier.SlotAWritten, carrier.SlotBRead, carrier.SlotBWritten)
	}
	logN2DCounts(t, "n3b_stdio_v2_eim_success", counts, initiatorResult, responderResult)
	assertN2DNoResidue(t, topology, servers)
}

func newN3BStdioEndpointProcess(t testing.TB, topology *n2dTopology, servers *n2dServers, artifacts n2dArtifactPair, role directattempt.Role) *n2dEndpointProcess {
	t.Helper()
	process := newN2DEndpointProcess(t, topology, servers, artifacts, role, n2dActionAttempt, "", "", "")
	process.config.Action = n3bActionStdioV2
	process.config.RendezvousSPKIPin = servers.rendezvousSPKIPin
	if process.config.RendezvousSPKIPin == "" || writeN1JSON(process.configPath, process.config) != nil {
		t.Fatal("N3b stdio endpoint configuration failed")
	}
	return process
}

func runN3BStdioV2Attempt(config n2dEndpointConfig) (result n2dEndpointResult, resultErr error) {
	result = n2dEndpointResult{Role: config.Role, SafetyState: string(governor.SafetyTripClear)}
	artifactFile, err := os.Open(config.ArtifactPath)
	if err != nil {
		result.ErrorClass = "artifact_read"
		return result, errors.New("N3b stdio artifact input rejected")
	}
	artifact, readErr := io.ReadAll(io.LimitReader(artifactFile, directconnect.MaxArtifactBytes+1))
	closeErr := artifactFile.Close()
	if readErr != nil || closeErr != nil || len(artifact) == 0 || len(artifact) > directconnect.MaxArtifactBytes {
		clear(artifact)
		result.ErrorClass = "artifact_read"
		return result, errors.New("N3b stdio artifact input rejected")
	}
	defer clear(artifact)

	inputPayload, err := n3bStdioInput(artifact, config)
	if err != nil {
		result.ErrorClass = "request_encode"
		return result, err
	}
	defer clear(inputPayload)
	var output bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), n2dProcessLimit)
	defer cancel()
	if err := solverstdio.ServeN3BNatlab(ctx, bytes.NewReader(inputPayload), &output, config.GovernorDir); err != nil {
		clear(output.Bytes())
		result.ErrorClass = "stdio_serve"
		return result, errors.New("N3b stdio process failed")
	}
	directResult, stages, err := parseN3BStdioOutput(output.Bytes())
	clear(output.Bytes())
	if err != nil {
		result.ErrorClass = "stdio_result"
		return result, err
	}
	wantStages := []string{
		directconnect.StagePresent, directconnect.StageBurned, directconnect.StageActivated,
		directconnect.StageHandshake, directconnect.StagePrepare, directconnect.StageSocket,
		directconnect.StageSTUN, directconnect.StageReady, directconnect.StageFire,
		directconnect.StagePunchSent, directconnect.StagePunch, directconnect.StageVerify,
		directconnect.StageTerminal,
	}
	if !reflect.DeepEqual(stages, wantStages) || !directResult.Bidirectional || !directResult.PromotedTerminal ||
		!directResult.CredentialBurned || !directResult.FinishRecorded || directResult.Terminal != n2dTerminalSuccess {
		result.ErrorClass = "stdio_contract"
		return result, errors.New("N3b stdio success contract rejected")
	}

	result.OK = true
	result.Terminal = directResult.Terminal
	result.Burned = directResult.CredentialBurned
	result.SameSocket = directResult.PromotedTerminal
	result.STUNPackets = directResult.Emissions.STUNPackets
	result.DirectPackets = directResult.Emissions.DirectPackets
	result.UDPPackets = directResult.Emissions.UDPPacketsTotal
	result.ControlFrames = directResult.Emissions.ControlFrames
	result.HandshakeFrames = directResult.Emissions.HandshakeFrames
	result.CarrierFramesRead = directResult.Emissions.CarrierFramesRead
	result.CarrierFramesWritten = directResult.Emissions.CarrierFramesWrite
	result.CarrierBytesRead = directResult.Emissions.CarrierBytesRead
	result.CarrierBytesWritten = directResult.Emissions.CarrierBytesWrite
	result.LedgerState = string(directResult.PairingLedger.State)
	result.LedgerSequence = directResult.PairingLedger.Sequence
	result.LedgerRecords = directResult.PairingLedger.Records
	result.LedgerAdmissions = directResult.PairingLedger.TwentyFourHourAdmissions
	result.LedgerFailures = directResult.PairingLedger.ConsecutiveFailures
	result.SafetyState = string(directResult.SafetyTrip.State)
	result.SafetyBlocksWork = directResult.SafetyTrip.BlocksActiveWork
	if err := inspectN3BReleasedAuthority(config.GovernorDir, &result); err != nil {
		result.OK = false
		result.ErrorClass = "authority_residue"
		return result, err
	}
	return result, nil
}

func n3bStdioInput(artifact []byte, config n2dEndpointConfig) ([]byte, error) {
	handshake := map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": solverstdio.MethodHandshake,
		"params": map[string]any{"schema_version": solverstdio.SchemaVersionV2, "framing_version": solverstdio.FramingVersion},
	}
	connect := map[string]any{
		"jsonrpc": "2.0", "id": 2, "method": solverstdio.MethodConnectTest,
		"params": map[string]any{
			"auth_scope": "test_only",
			"attempt":    map[string]any{"kind": "direct_oob_artifact", "oob_artifact": json.RawMessage(artifact)},
			"rendezvous": map[string]any{
				"endpoint": config.RendezvousEndpoint, "deployment_tier": directconnect.DeploymentSelfHosted,
				"tls": map[string]any{"verification": directconnect.TLSSPKISHA256, "spki_sha256": config.RendezvousSPKIPin},
			},
			"stun_endpoint": config.STUNEndpoint, "deadline_ms": 15000,
		},
	}
	var framed bytes.Buffer
	writer, err := stdiojsonrpc.NewFrameWriter(&framed, stdiojsonrpc.DefaultLimits().MaxRequestBytes)
	if err != nil {
		return nil, err
	}
	for _, request := range []map[string]any{handshake, connect} {
		payload, err := json.Marshal(request)
		if err != nil {
			return nil, err
		}
		if err := writer.WriteFrame(payload); err != nil {
			clear(payload)
			return nil, err
		}
		clear(payload)
	}
	return append([]byte(nil), framed.Bytes()...), nil
}

func parseN3BStdioOutput(payload []byte) (directconnect.Result, []string, error) {
	reader, err := stdiojsonrpc.NewFrameReader(bytes.NewReader(payload), 1024, 1<<20)
	if err != nil {
		return directconnect.Result{}, nil, err
	}
	var result directconnect.Result
	var stages []string
	handshakeSeen, resultSeen := false, false
	for {
		frame, err := reader.ReadFrame()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return directconnect.Result{}, nil, err
		}
		var envelope struct {
			ID     json.RawMessage        `json:"id"`
			Method string                 `json:"method"`
			Params json.RawMessage        `json:"params"`
			Result json.RawMessage        `json:"result"`
			Error  *stdiojsonrpc.RPCError `json:"error"`
		}
		if err := json.Unmarshal(frame, &envelope); err != nil || envelope.Error != nil {
			clear(frame)
			return directconnect.Result{}, nil, errors.New("N3b stdio returned a terminal error")
		}
		switch {
		case envelope.Method == stdiojsonrpc.ProgressNotificationMethod:
			var progress stdiojsonrpc.Progress
			if json.Unmarshal(envelope.Params, &progress) != nil || string(progress.RequestID) != "2" || progress.RemainingBudgetMS < 0 || progress.RemainingBudgetMS > 15000 ||
				(progress.Stage == directconnect.StageTerminal) != !progress.Cancellable {
				clear(frame)
				return directconnect.Result{}, nil, errors.New("N3b stdio progress rejected")
			}
			stages = append(stages, progress.Stage)
		case string(envelope.ID) == "1":
			var handshake solverstdio.HandshakeResultV2
			if json.Unmarshal(envelope.Result, &handshake) != nil || handshake.SchemaVersion != solverstdio.SchemaVersionV2 ||
				!reflect.DeepEqual(handshake.ConnectTestProfiles, []string{"loopback_complete_bundle", directattempt.ArtifactProfile}) {
				clear(frame)
				return directconnect.Result{}, nil, errors.New("N3b stdio handshake rejected")
			}
			handshakeSeen = true
		case string(envelope.ID) == "2":
			if json.Unmarshal(envelope.Result, &result) != nil {
				clear(frame)
				return directconnect.Result{}, nil, errors.New("N3b stdio result rejected")
			}
			resultSeen = true
		default:
			clear(frame)
			return directconnect.Result{}, nil, errors.New("N3b stdio emitted an unexpected frame")
		}
		clear(frame)
	}
	if !handshakeSeen || !resultSeen {
		return directconnect.Result{}, nil, errors.New("N3b stdio response was incomplete")
	}
	return result, stages, nil
}

func inspectN3BReleasedAuthority(namespace string, result *n2dEndpointResult) error {
	owner, err := governor.AcquirePreparedNamespace(namespace, governor.ScopeMachine, "n3b-residue-witness")
	if err != nil {
		return err
	}
	machine, err := governor.New(owner, governor.ProfilePhase1Machine, nil)
	if err != nil {
		_ = owner.Close()
		return err
	}
	snapshot := machine.Snapshot()
	result.ActivePeers = snapshot.ActivePeers
	result.ActiveAttempts = snapshot.ActiveAttempts
	result.ReservedSockets = snapshot.Reserved.Sockets
	result.ReservedTargets = snapshot.Reserved.Targets
	result.ReservedFiveTuples = snapshot.Reserved.FiveTuples
	result.ReservedPackets = snapshot.Reserved.Packets
	return machine.Close()
}
