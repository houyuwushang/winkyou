//go:build linux && natlab

package natlab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"

	"winkyou/internal/governor"
	"winkyou/internal/solverstdio"
	"winkyou/internal/stdiojsonrpc"
	"winkyou/internal/v2/directconnect"
)

// These are test witnesses, not another protocol parser. Only fixed vocabulary
// and counts survive; messages, endpoints, IDs and RPC payloads never do.
type n3bStdioDiagnostic struct {
	Frames, ProgressCount                    int
	HandshakeSeen, ResultSeen, RPCErrorSeen  bool
	BurnedKnown, Burned                      bool
	Class, Stage, LastProgress, ParseFailure string
	ServeClass                               string
	Stages                                   [16]string
	ResultSuccess, Bidirectional, Promoted   bool
	ResultBurned, FinishRecorded             bool
}

func inspectN3BStdioOutput(payload []byte) n3bStdioDiagnostic {
	diag := n3bStdioDiagnostic{Class: "none", Stage: "none", LastProgress: "none", ParseFailure: "none", ServeClass: "none"}
	reader, err := stdiojsonrpc.NewFrameReader(bytes.NewReader(payload), 1024, 1<<20)
	if err != nil {
		diag.ParseFailure = "framing"
		return diag
	}
	for diag.Frames < 32 {
		frame, err := reader.ReadFrame()
		if errors.Is(err, io.EOF) {
			return diag
		}
		if err != nil {
			diag.ParseFailure = "framing"
			return diag
		}
		diag.Frames++
		var envelope struct {
			ID     json.RawMessage        `json:"id"`
			Method string                 `json:"method"`
			Params json.RawMessage        `json:"params"`
			Result json.RawMessage        `json:"result"`
			Error  *stdiojsonrpc.RPCError `json:"error"`
		}
		err = json.Unmarshal(frame, &envelope)
		clear(frame)
		if err != nil {
			diag.ParseFailure = "json"
			return diag
		}
		if envelope.Error != nil && !diag.RPCErrorSeen {
			diag.RPCErrorSeen = true
			diag.Class = n3bSafeClass(envelope.Error.Data.Class)
			diag.Stage = n3bSafeStage(envelope.Error.Data.Stage)
			if envelope.Error.Data.CredentialBurned != nil {
				diag.BurnedKnown, diag.Burned = true, *envelope.Error.Data.CredentialBurned
			}
		}
		if envelope.Method == stdiojsonrpc.ProgressNotificationMethod {
			var progress stdiojsonrpc.Progress
			if json.Unmarshal(envelope.Params, &progress) != nil {
				diag.ParseFailure = "progress"
				return diag
			}
			if diag.ProgressCount < len(diag.Stages) {
				diag.Stages[diag.ProgressCount] = n3bSafeStage(progress.Stage)
			}
			diag.ProgressCount++
			diag.LastProgress = n3bSafeStage(progress.Stage)
		}
		if envelope.Error == nil {
			diag.HandshakeSeen = diag.HandshakeSeen || string(envelope.ID) == "1"
			diag.ResultSeen = diag.ResultSeen || string(envelope.ID) == "2"
			if string(envelope.ID) == "2" {
				var result directconnect.Result
				if json.Unmarshal(envelope.Result, &result) == nil {
					diag.ResultSuccess = result.Terminal == "success"
					diag.Bidirectional, diag.Promoted = result.Bidirectional, result.PromotedTerminal
					diag.ResultBurned, diag.FinishRecorded = result.CredentialBurned, result.FinishRecorded
				}
			}
		}
	}
	diag.ParseFailure = "frame_limit"
	return diag
}

func n3bSafeClass(class string) string {
	switch class {
	case "", "none":
		return "none"
	case directconnect.ClassUnsupportedAttemptProfile, directconnect.ClassInvalidDirectArtifact,
		directconnect.ClassArtifactNotYetValid, directconnect.ClassArtifactExpired,
		directconnect.ClassRendezvousEndpointInvalid, directconnect.ClassSTUNEndpointInvalid,
		directconnect.ClassRendezvousDNSFailed, directconnect.ClassRendezvousDNSAmbiguous,
		directconnect.ClassRendezvousTLSFailed, directconnect.ClassRendezvousUnreachable,
		directconnect.ClassPresenceTimeout, directconnect.ClassPairingScopeChanged,
		directconnect.ClassLedgerIndeterminate, directconnect.ClassCredentialUsed,
		directconnect.ClassPairingRateLimited, directconnect.ClassPairingCircuitOpen,
		directconnect.ClassActivationFailed, directconnect.ClassSecureHandshakeFailed,
		directconnect.ClassControlAuthentication, directconnect.ClassRendezvousProtocol,
		directconnect.ClassCarrierDomainViolation, directconnect.ClassRendezvousBudgetExceeded,
		directconnect.ClassSTUNSilent, directconnect.ClassSTUNProtocol, directconnect.ClassSTUNSourceMismatch,
		directconnect.ClassReadyRejected, directconnect.ClassPunchTimeout, directconnect.ClassDirectPacketRejected,
		directconnect.ClassVerificationFailed, directconnect.ClassPeerCancelled, directconnect.ClassAttemptExpired,
		directconnect.ClassResourceBudgetExceeded, directconnect.ClassDrainFailed, directconnect.ClassDirectAttemptFailed,
		stdiojsonrpc.ClassParseError, stdiojsonrpc.ClassInvalidRequest, stdiojsonrpc.ClassMethodNotFound,
		stdiojsonrpc.ClassInvalidParams, stdiojsonrpc.ClassInternalError, stdiojsonrpc.ClassRequestTooLarge,
		stdiojsonrpc.ClassRateLimited, stdiojsonrpc.ClassConcurrencyLimit, stdiojsonrpc.ClassDeadlineExceeded,
		stdiojsonrpc.ClassCancelled, solverstdio.ClassSafetyTripActive, solverstdio.ClassHandshakeRequired,
		solverstdio.ClassNotImplemented, solverstdio.ClassIncompatibleVersion, solverstdio.ClassExportFailed,
		solverstdio.ClassGovernorLockUnavailable, solverstdio.ClassInvalidCompleteBundle,
		solverstdio.ClassNonLoopbackBlocked, solverstdio.ClassUserScopeBlocked,
		solverstdio.ClassPairingAdmissionBlocked, solverstdio.ClassConnectTestFailed:
		return class
	default:
		return "unknown"
	}
}

func n3bSafeStage(stage string) string {
	switch stage {
	case "", "none":
		return "none"
	case directconnect.StagePreflight, directconnect.StagePresent, directconnect.StageBurned,
		directconnect.StageActivated, directconnect.StageHandshake, directconnect.StagePrepare,
		directconnect.StageSocket, directconnect.StageSTUN, directconnect.StageReady,
		directconnect.StageFire, directconnect.StagePunchSent, directconnect.StagePunch,
		directconnect.StageVerify, directconnect.StageTerminal:
		return stage
	default:
		return "unknown"
	}
}

func n3bSafeParseFailure(class string) string {
	switch class {
	case "none", "framing", "json", "progress", "frame_limit":
		return class
	default:
		return "unknown"
	}
}

func n3bServeErrorClass(err error) string {
	var ownerHeld *governor.OwnerHeldError
	switch {
	case err == nil:
		return "none"
	case errors.As(err, &ownerHeld):
		return "owner_held"
	case errors.Is(err, governor.ErrNamespaceNotReady), errors.Is(err, governor.ErrNamespaceUnsafe):
		return "namespace"
	case errors.Is(err, governor.ErrSafetyTripped), errors.Is(err, governor.ErrSafetyStateCorrupt), errors.Is(err, governor.ErrSafetyStateUnavailable):
		return "safety"
	case errors.Is(err, governor.ErrPairingLedgerIndeterminate):
		return "ledger"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, governor.ErrCancellationDrainTimeout):
		return "drain"
	default:
		return "other"
	}
}

func n3bSafeServeClass(class string) string {
	switch class {
	case "none", "owner_held", "namespace", "safety", "ledger", "deadline", "canceled", "drain", "other":
		return class
	default:
		return "unknown"
	}
}

// Child output is consumed but never retained or logged. A bounded tail only
// recognizes runtime failure markers split across writes, then is wiped.
type n2dChildOutputDiagnostic struct {
	mu                          sync.Mutex
	tail                        []byte
	race, panic, timeout, fatal bool
}

func (diag *n2dChildOutputDiagnostic) Write(payload []byte) (int, error) {
	diag.mu.Lock()
	defer diag.mu.Unlock()
	for _, value := range payload {
		diag.tail = append(diag.tail, value)
		if len(diag.tail) > 64 {
			copy(diag.tail, diag.tail[len(diag.tail)-64:])
			diag.tail = diag.tail[:64]
		}
		diag.race = diag.race || bytes.Contains(diag.tail, []byte("WARNING: DATA RACE"))
		diag.panic = diag.panic || bytes.Contains(diag.tail, []byte("panic:"))
		diag.timeout = diag.timeout || bytes.Contains(diag.tail, []byte("test timed out"))
		diag.fatal = diag.fatal || bytes.Contains(diag.tail, []byte("fatal error:"))
	}
	return len(payload), nil
}

func (diag *n2dChildOutputDiagnostic) snapshot() [4]bool {
	diag.mu.Lock()
	defer diag.mu.Unlock()
	return [4]bool{diag.race, diag.panic, diag.timeout, diag.fatal}
}

func (diag *n2dChildOutputDiagnostic) clear() {
	diag.mu.Lock()
	defer diag.mu.Unlock()
	clear(diag.tail[:cap(diag.tail)])
	diag.tail = nil
}
