package solverstdio

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"time"

	passivediagnose "winkyou/internal/diagnose"
	"winkyou/internal/governor"
	"winkyou/internal/stdiojsonrpc"
	"winkyou/internal/v2/directconnect"
	"winkyou/internal/v2/loopbackcarrier"
)

type handler struct {
	authority   authority
	diagnose    diagnoseRunner
	writeReport func(string, passivediagnose.Report) (int64, error)
	options     Options
	build       BuildInfo
	limits      stdiojsonrpc.Limits
	handshaken  atomic.Bool
	version     atomic.Uint32
}

func newHandler(authority authority, diagnose diagnoseRunner, writeReport func(string, passivediagnose.Report) (int64, error), options Options, build BuildInfo, limits stdiojsonrpc.Limits) (*handler, error) {
	if authority == nil || diagnose == nil || writeReport == nil {
		return nil, errors.New("stdio API handler dependencies are incomplete")
	}
	if _, err := governor.HardLimits(governor.ProfilePhase1Machine); err != nil {
		return nil, err
	}
	return &handler{authority: authority, diagnose: diagnose, writeReport: writeReport, options: options, build: build, limits: limits}, nil
}

func (handler *handler) Handle(ctx context.Context, request stdiojsonrpc.Request, progress stdiojsonrpc.ProgressReporter) (any, *stdiojsonrpc.RPCError) {
	if request.Method == MethodHandshake {
		return handler.handshake(request)
	}
	if !handler.handshaken.Load() {
		return nil, stdiojsonrpc.NewRPCError(CodeHandshakeRequired, ClassHandshakeRequired, "handshake must complete before this method", false)
	}
	if request.Method != MethodStatus && handler.authority.SafetyTripStatus().BlocksActiveWork {
		return nil, handler.safetyTripError()
	}
	switch request.Method {
	case MethodStatus:
		return handler.status(ctx, request)
	case MethodDiagnose:
		return handler.runDiagnose(ctx, request, progress)
	case MethodExportRedactedReport:
		return handler.export(ctx, request, progress)
	case MethodConnectTest:
		return handler.connectTest(ctx, request, progress)
	default:
		message := "method is not part of the v1 schema"
		if handler.version.Load() == 2 {
			message = "method is not part of the v2 schema"
		}
		return nil, stdiojsonrpc.NewRPCError(stdiojsonrpc.CodeMethodNotFound, stdiojsonrpc.ClassMethodNotFound, message, false)
	}
}

func (handler *handler) handshake(request stdiojsonrpc.Request) (any, *stdiojsonrpc.RPCError) {
	var params handshakeParams
	if rpcErr := decodeMethodParams(request.Params, &params); rpcErr != nil {
		return nil, rpcErr
	}
	requestedVersion := uint32(0)
	switch params.SchemaVersion {
	case SchemaVersion:
		requestedVersion = 1
	case SchemaVersionV2:
		requestedVersion = 2
	}
	currentVersion := handler.version.Load()
	if requestedVersion == 0 || params.FramingVersion != FramingVersion || (currentVersion != 0 && currentVersion != requestedVersion) {
		rpcErr := stdiojsonrpc.NewRPCError(CodeIncompatibleVersion, ClassIncompatibleVersion, "requested schema or framing version is incompatible", false)
		rpcErr.Data.Reason = "server_requires_exact_v1_versions"
		return nil, rpcErr
	}
	hard, err := governor.HardLimits(governor.ProfilePhase1Machine)
	if err != nil {
		return nil, stdiojsonrpc.NewRPCError(stdiojsonrpc.CodeInternalError, stdiojsonrpc.ClassInternalError, "compiled governor limits are unavailable", false)
	}
	result := HandshakeResult{
		SchemaVersion:  SchemaVersion,
		FramingVersion: FramingVersion,
		Build:          handler.build,
		ProtocolLimits: protocolLimits(handler.limits),
		Governor: GovernorHandshake{
			Scope:          governor.ScopeMachine,
			Profile:        governor.ProfilePhase1Machine,
			Mode:           "owner",
			ProxySupported: false,
			Owner:          handler.authority.Info(),
			HardLimits:     governorLimits(hard),
			Remaining:      remainingQuota(hard),
		},
		AuthScope:           "test_only",
		SupportedAuthScopes: []string{"test_only"},
		SafetyTrip:          handler.authority.SafetyTripStatus(),
		Methods:             SupportedMethods(),
		Notifications: []NotificationCapability{{
			Method:                 stdiojsonrpc.ProgressNotificationMethod,
			BindsRequestID:         true,
			ReportsStage:           true,
			ReportsRemainingBudget: true,
			ReportsCancellable:     true,
		}},
	}
	if requestedVersion == 2 {
		resultV2 := HandshakeResultV2{
			SchemaVersion:       SchemaVersionV2,
			FramingVersion:      result.FramingVersion,
			Build:               result.Build,
			ProtocolLimits:      result.ProtocolLimits,
			Governor:            result.Governor,
			AuthScope:           result.AuthScope,
			SupportedAuthScopes: append([]string(nil), result.SupportedAuthScopes...),
			ConnectTestProfiles: append([]string(nil), connectTestProfilesV2...),
			SafetyTrip:          result.SafetyTrip,
			Methods:             append([]string(nil), result.Methods...),
			Notifications:       append([]NotificationCapability(nil), result.Notifications...),
		}
		handler.version.Store(2)
		handler.handshaken.Store(true)
		return resultV2, nil
	}
	handler.version.Store(1)
	handler.handshaken.Store(true)
	return result, nil
}

func (handler *handler) status(ctx context.Context, request stdiojsonrpc.Request) (any, *stdiojsonrpc.RPCError) {
	var params readParams
	if rpcErr := decodeMethodParams(request.Params, &params); rpcErr != nil {
		return nil, rpcErr
	}
	report := handler.diagnose.Run(ctx, passivediagnose.Options{ConfigPath: handler.options.ConfigPath, GovernorScope: governor.ScopeMachine})
	return StatusResult{
		SchemaVersion:          handler.schemaVersion(),
		GeneratedAt:            report.GeneratedAt,
		GovernorScope:          report.GovernorScope,
		Namespace:              report.Namespace,
		MachineNamespace:       report.MachineNamespace,
		Owner:                  report.Owner,
		SafetyTrip:             handler.authority.SafetyTripStatus(),
		PairingLedger:          handler.pairingLedgerStatus(),
		NetworkActivityStarted: false,
	}, nil
}

func (handler *handler) runDiagnose(ctx context.Context, request stdiojsonrpc.Request, progress stdiojsonrpc.ProgressReporter) (any, *stdiojsonrpc.RPCError) {
	var params readParams
	if rpcErr := decodeMethodParams(request.Params, &params); rpcErr != nil {
		return nil, rpcErr
	}
	if rpcErr := reportProgress(progress, "collecting_passive_report", true); rpcErr != nil {
		return nil, rpcErr
	}
	report := handler.diagnose.Run(ctx, passivediagnose.Options{ConfigPath: handler.options.ConfigPath, GovernorScope: governor.ScopeMachine})
	if err := ctx.Err(); err != nil {
		return nil, nil
	}
	if handler.authority.SafetyTripStatus().BlocksActiveWork {
		return nil, handler.safetyTripError()
	}
	if rpcErr := reportProgress(progress, "complete", false); rpcErr != nil {
		return nil, rpcErr
	}
	return report, nil
}

func (handler *handler) export(ctx context.Context, request stdiojsonrpc.Request, progress stdiojsonrpc.ProgressReporter) (any, *stdiojsonrpc.RPCError) {
	var params exportParams
	if rpcErr := decodeMethodParams(request.Params, &params); rpcErr != nil {
		return nil, rpcErr
	}
	if params.Redaction != "" && params.Redaction != passivediagnose.ExportRedaction {
		return nil, stdiojsonrpc.NewRPCError(stdiojsonrpc.CodeInvalidParams, stdiojsonrpc.ClassInvalidParams, "redaction must be strict when specified", false)
	}
	if strings.TrimSpace(params.Path) == "" {
		return nil, stdiojsonrpc.NewRPCError(stdiojsonrpc.CodeInvalidParams, stdiojsonrpc.ClassInvalidParams, "path is required", false)
	}
	if rpcErr := reportProgress(progress, "collecting_passive_report", true); rpcErr != nil {
		return nil, rpcErr
	}
	report := handler.diagnose.Run(ctx, passivediagnose.Options{ConfigPath: handler.options.ConfigPath, GovernorScope: governor.ScopeMachine})
	if err := ctx.Err(); err != nil {
		return nil, nil
	}
	if handler.authority.SafetyTripStatus().BlocksActiveWork {
		return nil, handler.safetyTripError()
	}
	if rpcErr := reportProgress(progress, "writing_redacted_report", false); rpcErr != nil {
		return nil, rpcErr
	}
	written, err := handler.writeReport(params.Path, report)
	if err != nil {
		rpcErr := stdiojsonrpc.NewRPCError(CodeExportFailed, ClassExportFailed, "redacted report could not be written", false)
		rpcErr.Data.Reason = "invalid_or_unavailable_destination"
		return nil, rpcErr
	}
	return ExportResult{Written: true, Redaction: passivediagnose.ExportRedaction, Bytes: written}, nil
}

func (handler *handler) connectTest(ctx context.Context, request stdiojsonrpc.Request, progress stdiojsonrpc.ProgressReporter) (any, *stdiojsonrpc.RPCError) {
	if handler.version.Load() == 2 {
		return handler.connectTestV2(ctx, request, progress)
	}
	return handler.connectTestV1(ctx, request, progress)
}

func (handler *handler) connectTestV1(ctx context.Context, request stdiojsonrpc.Request, progress stdiojsonrpc.ProgressReporter) (any, *stdiojsonrpc.RPCError) {
	defer clear(request.Params)
	var params connectTestParams
	if rpcErr := decodeMethodParams(request.Params, &params); rpcErr != nil {
		return nil, rpcErr
	}
	defer clear(params.CompleteBundle)
	if params.AuthScope != "test_only" {
		return nil, stdiojsonrpc.NewRPCError(stdiojsonrpc.CodeInvalidParams, stdiojsonrpc.ClassInvalidParams, "auth_scope must be test_only", false)
	}
	connector, ok := handler.authority.(connectTestAuthority)
	if !ok {
		rpcErr := stdiojsonrpc.NewRPCError(CodeNotImplemented, ClassNotImplemented, "connect_test authority is unavailable", false)
		rpcErr.Data.Reason = "loopback_carrier_not_available"
		return nil, rpcErr
	}
	if rpcErr := reportProgress(progress, "validating_complete_bundle", true); rpcErr != nil {
		return nil, rpcErr
	}
	var progressErr error
	result, err := connector.ConnectTest(ctx, params.CompleteBundle, handler.build.Version, func(stage loopbackcarrier.ProgressStage) error {
		if progressErr != nil {
			return progressErr
		}
		progressErr = progress.Report(string(stage), true)
		return progressErr
	})
	clear(params.CompleteBundle)
	if progressErr != nil {
		return nil, stdiojsonrpc.NewRPCError(stdiojsonrpc.CodeInternalError, stdiojsonrpc.ClassInternalError, "progress notification could not be delivered", false)
	}
	if err != nil {
		return nil, connectTestError(err)
	}
	if rpcErr := reportProgress(progress, "terminal_finish_recorded", false); rpcErr != nil {
		return nil, rpcErr
	}
	return ConnectTestResult{
		Result:        result,
		PairingLedger: connector.PairingLedgerStatus(),
	}, nil
}

func (handler *handler) connectTestV2(ctx context.Context, request stdiojsonrpc.Request, progress stdiojsonrpc.ProgressReporter) (any, *stdiojsonrpc.RPCError) {
	defer clear(request.Params)
	if duplicateObjectMember(request.Params) {
		return nil, stdiojsonrpc.NewRPCError(stdiojsonrpc.CodeInvalidParams, stdiojsonrpc.ClassInvalidParams, "params contain duplicate members", false)
	}
	var params connectTestV2Params
	if rpcErr := decodeMethodParams(request.Params, &params); rpcErr != nil {
		return nil, rpcErr
	}
	var outerMembers map[string]json.RawMessage
	if err := json.Unmarshal(request.Params, &outerMembers); err != nil {
		return nil, stdiojsonrpc.NewRPCError(stdiojsonrpc.CodeInvalidParams, stdiojsonrpc.ClassInvalidParams, "params do not match the method schema", false)
	}
	defer clearRawMembers(outerMembers)
	_, hasRendezvous := outerMembers["rendezvous"]
	_, hasSTUNEndpoint := outerMembers["stun_endpoint"]
	defer clear(params.Attempt)
	if params.AuthScope != "test_only" {
		return nil, stdiojsonrpc.NewRPCError(stdiojsonrpc.CodeInvalidParams, stdiojsonrpc.ClassInvalidParams, "auth_scope must be test_only", false)
	}
	if len(params.Attempt) == 0 {
		return nil, stdiojsonrpc.NewRPCError(stdiojsonrpc.CodeInvalidParams, stdiojsonrpc.ClassInvalidParams, "attempt is required", false)
	}
	if duplicateObjectMember(params.Attempt) {
		return nil, stdiojsonrpc.NewRPCError(stdiojsonrpc.CodeInvalidParams, stdiojsonrpc.ClassInvalidParams, "attempt contains duplicate members", false)
	}
	var attempt connectTestAttemptV2
	if rpcErr := decodeMethodParams(params.Attempt, &attempt); rpcErr != nil {
		return nil, rpcErr
	}
	var attemptMembers map[string]json.RawMessage
	if err := json.Unmarshal(params.Attempt, &attemptMembers); err != nil {
		return nil, stdiojsonrpc.NewRPCError(stdiojsonrpc.CodeInvalidParams, stdiojsonrpc.ClassInvalidParams, "attempt does not match the method schema", false)
	}
	defer clearRawMembers(attemptMembers)
	_, hasCompleteBundle := attemptMembers["complete_bundle"]
	_, hasOOBArtifact := attemptMembers["oob_artifact"]
	defer clear(attempt.CompleteBundle)
	defer clear(attempt.OOBArtifact)

	switch attempt.Kind {
	case "loopback_complete_bundle":
		if !hasCompleteBundle || len(attempt.CompleteBundle) == 0 || hasOOBArtifact || hasRendezvous || hasSTUNEndpoint {
			return nil, stdiojsonrpc.NewRPCError(stdiojsonrpc.CodeInvalidParams, stdiojsonrpc.ClassInvalidParams, "loopback attempt fields are mutually exclusive", false)
		}
		legacyParams, err := json.Marshal(connectTestParams{
			AuthScope: params.AuthScope, CompleteBundle: attempt.CompleteBundle, DeadlineMS: params.DeadlineMS,
		})
		if err != nil {
			return nil, stdiojsonrpc.NewRPCError(stdiojsonrpc.CodeInternalError, stdiojsonrpc.ClassInternalError, "loopback request could not be prepared", false)
		}
		defer clear(legacyParams)
		legacyRequest := request
		legacyRequest.Params = legacyParams
		return handler.connectTestV1(ctx, legacyRequest, progress)

	case "direct_oob_artifact":
		if !hasOOBArtifact || len(attempt.OOBArtifact) == 0 || len(attempt.OOBArtifact) > directconnect.MaxArtifactBytes || hasCompleteBundle ||
			!hasRendezvous || !hasSTUNEndpoint || params.Rendezvous == nil || params.STUNEndpoint == "" {
			return nil, stdiojsonrpc.NewRPCError(stdiojsonrpc.CodeInvalidParams, stdiojsonrpc.ClassInvalidParams, "direct attempt fields are incomplete or mutually exclusive", false)
		}
		rendezvousRaw := outerMembers["rendezvous"]
		if duplicateObjectMember(rendezvousRaw) {
			return nil, stdiojsonrpc.NewRPCError(stdiojsonrpc.CodeInvalidParams, stdiojsonrpc.ClassInvalidParams, "rendezvous contains duplicate members", false)
		}
		var rendezvousMembers map[string]json.RawMessage
		if json.Unmarshal(rendezvousRaw, &rendezvousMembers) != nil {
			return nil, stdiojsonrpc.NewRPCError(stdiojsonrpc.CodeInvalidParams, stdiojsonrpc.ClassInvalidParams, "rendezvous does not match the method schema", false)
		}
		defer clearRawMembers(rendezvousMembers)
		if tlsRaw, present := rendezvousMembers["tls"]; present && duplicateObjectMember(tlsRaw) {
			return nil, stdiojsonrpc.NewRPCError(stdiojsonrpc.CodeInvalidParams, stdiojsonrpc.ClassInvalidParams, "tls contains duplicate members", false)
		}
		if params.DeadlineMS != nil && (*params.DeadlineMS <= 0 || *params.DeadlineMS > 15000) {
			rpcErr := stdiojsonrpc.NewRPCError(stdiojsonrpc.CodeInvalidParams, stdiojsonrpc.ClassInvalidParams, "deadline_ms exceeds the direct attempt hard limit", false)
			rpcErr.Data.Limit = 15000
			return nil, rpcErr
		}
		connector, ok := handler.authority.(directConnectAuthority)
		if !ok {
			return nil, stdiojsonrpc.NewRPCError(stdiojsonrpc.CodeInternalError, stdiojsonrpc.ClassInternalError, "direct connect_test authority is unavailable", false)
		}
		result, err := connector.ConnectDirect(ctx, directconnect.Config{
			Artifact: attempt.OOBArtifact,
			Rendezvous: directconnect.RendezvousConfig{
				Endpoint:       params.Rendezvous.Endpoint,
				DeploymentTier: params.Rendezvous.DeploymentTier,
				TLS: directconnect.TLSConfig{
					Verification: params.Rendezvous.TLS.Verification,
					ServerName:   params.Rendezvous.TLS.ServerName,
					SPKISHA256:   params.Rendezvous.TLS.SPKISHA256,
				},
			},
			STUNEndpoint: params.STUNEndpoint,
			BuildVersion: handler.build.Version,
			Progress: func(stage string, cancellable bool) error {
				return progress.Report(stage, cancellable)
			},
		})
		clear(attempt.OOBArtifact)
		if err != nil {
			if errors.Is(err, directconnect.ErrProgressDelivery) {
				return nil, stdiojsonrpc.NewRPCError(stdiojsonrpc.CodeInternalError, stdiojsonrpc.ClassInternalError, "progress notification could not be delivered", false)
			}
			return nil, directConnectError(err)
		}
		return result, nil

	default:
		if rpcErr := reportProgress(progress, directconnect.StageTerminal, false); rpcErr != nil {
			return nil, rpcErr
		}
		return nil, directConnectError(&directconnect.Failure{
			Class: directconnect.ClassUnsupportedAttemptProfile, Stage: directconnect.StagePreflight,
			CredentialBurned: false, TerminalCategory: directconnect.CategoryPreflightRejected,
		})
	}
}

func directConnectError(err error) *stdiojsonrpc.RPCError {
	var failure *directconnect.Failure
	if !errors.As(err, &failure) || failure == nil {
		failure = &directconnect.Failure{
			Class: directconnect.ClassDirectAttemptFailed, Stage: directconnect.StagePreflight,
			TerminalCategory: directconnect.CategoryPreflightRejected,
		}
	}
	rpcErr := stdiojsonrpc.NewRPCError(CodeDirectConnectFailed, failure.Class, "terminal direct connect_test failed", false)
	rpcErr.Data.Reason = failure.Class
	rpcErr.Data.Stage = failure.Stage
	burned := failure.CredentialBurned
	rpcErr.Data.CredentialBurned = &burned
	rpcErr.Data.TerminalCategory = failure.TerminalCategory
	return rpcErr
}

func connectTestError(err error) *stdiojsonrpc.RPCError {
	var code int
	var class, message string
	switch {
	case errors.Is(err, loopbackcarrier.ErrNonLoopbackBlocked):
		code, class, message = CodeNonLoopbackBlocked, ClassNonLoopbackBlocked, "connect_test permits literal loopback endpoints only"
	case errors.Is(err, loopbackcarrier.ErrUserScopeBlocked):
		code, class, message = CodeUserScopeBlocked, ClassUserScopeBlocked, "connect_test requires machine scope on both participants"
	case errors.Is(err, loopbackcarrier.ErrInvalidBundle):
		code, class, message = CodeInvalidCompleteBundle, ClassInvalidCompleteBundle, "complete_bundle failed strict validation"
	case errors.Is(err, governor.ErrPairingAdmissionRejected), errors.Is(err, governor.ErrPairingCredentialUsed), errors.Is(err, governor.ErrPairingAdmissionRateLimited), errors.Is(err, governor.ErrPairingAdmissionCircuitOpen):
		code, class, message = CodePairingAdmissionBlocked, ClassPairingAdmissionBlocked, "durable pairing admission rejected the attempt"
	default:
		code, class, message = CodeConnectTestFailed, ClassConnectTestFailed, "terminal loopback connect_test failed"
	}
	rpcErr := stdiojsonrpc.NewRPCError(code, class, message, false)
	rpcErr.Data.Reason = class
	return rpcErr
}

func (handler *handler) schemaVersion() string {
	if handler != nil && handler.version.Load() == 2 {
		return SchemaVersionV2
	}
	return SchemaVersion
}

func (handler *handler) pairingLedgerStatus() governor.PairingLedgerStatus {
	if authority, ok := handler.authority.(interface {
		PairingLedgerStatus() governor.PairingLedgerStatus
	}); ok {
		return authority.PairingLedgerStatus()
	}
	return unavailablePairingLedgerStatus("pairing ledger status is unavailable from this authority")
}

func (handler *handler) safetyTripError() *stdiojsonrpc.RPCError {
	status := handler.authority.SafetyTripStatus()
	rpcErr := stdiojsonrpc.NewRPCError(CodeSafetyTripActive, ClassSafetyTripActive, "the safety trip blocks this method", false)
	rpcErr.Data.Reason = string(status.State)
	return rpcErr
}

func (handler *handler) deadline(request stdiojsonrpc.Request) (time.Duration, *stdiojsonrpc.RPCError) {
	if len(request.Params) == 0 {
		return 0, nil
	}
	directV2 := handler.version.Load() == 2 && request.Method == MethodConnectTest && requestIsDirectV2(request.Params)
	var members map[string]json.RawMessage
	if err := json.Unmarshal(request.Params, &members); err != nil {
		return 0, stdiojsonrpc.NewRPCError(stdiojsonrpc.CodeInvalidParams, stdiojsonrpc.ClassInvalidParams, "params do not match the method schema", false)
	}
	raw, present := members["deadline_ms"]
	if !present {
		if directV2 {
			return 15 * time.Second, nil
		}
		return 0, nil
	}
	var milliseconds int64
	if err := json.Unmarshal(raw, &milliseconds); err != nil || milliseconds <= 0 {
		return 0, stdiojsonrpc.NewRPCError(stdiojsonrpc.CodeInvalidParams, stdiojsonrpc.ClassInvalidParams, "deadline_ms must be a positive integer", false)
	}
	maximum := handler.limits.MaxDeadline.Milliseconds()
	if directV2 && maximum > 15000 {
		maximum = 15000
	}
	if milliseconds > maximum {
		rpcErr := stdiojsonrpc.NewRPCError(stdiojsonrpc.CodeInvalidParams, stdiojsonrpc.ClassInvalidParams, "deadline_ms exceeds the protocol hard limit", false)
		rpcErr.Data.Limit = maximum
		return 0, rpcErr
	}
	return time.Duration(milliseconds) * time.Millisecond, nil
}

func requestIsDirectV2(raw json.RawMessage) bool {
	var outer struct {
		Attempt json.RawMessage `json:"attempt"`
	}
	if err := json.Unmarshal(raw, &outer); err != nil || len(outer.Attempt) == 0 {
		return false
	}
	var attempt struct {
		Kind string `json:"kind"`
	}
	return json.Unmarshal(outer.Attempt, &attempt) == nil && attempt.Kind == "direct_oob_artifact"
}

func clearRawMembers(members map[string]json.RawMessage) {
	for key, value := range members {
		clear(value)
		delete(members, key)
	}
}

// duplicateObjectMember checks only the selected object level. Nested secret
// objects remain the responsibility of their existing strict parser so their
// stable error class does not change.
func duplicateObjectMember(raw json.RawMessage) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return false
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		nameToken, err := decoder.Token()
		if err != nil {
			return false
		}
		name, ok := nameToken.(string)
		if !ok {
			return false
		}
		if _, exists := seen[name]; exists {
			return true
		}
		seen[name] = struct{}{}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return false
		}
		clear(value)
	}
	return false
}

func decodeMethodParams(raw json.RawMessage, destination any) *stdiojsonrpc.RPCError {
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return stdiojsonrpc.NewRPCError(stdiojsonrpc.CodeInvalidParams, stdiojsonrpc.ClassInvalidParams, "params do not match the method schema", false)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return stdiojsonrpc.NewRPCError(stdiojsonrpc.CodeInvalidParams, stdiojsonrpc.ClassInvalidParams, "params contain trailing JSON", false)
	}
	return nil
}

func reportProgress(progress stdiojsonrpc.ProgressReporter, stage string, cancellable bool) *stdiojsonrpc.RPCError {
	if progress == nil {
		return stdiojsonrpc.NewRPCError(stdiojsonrpc.CodeInternalError, stdiojsonrpc.ClassInternalError, "progress reporter is unavailable", false)
	}
	if err := progress.Report(stage, cancellable); err != nil {
		return stdiojsonrpc.NewRPCError(stdiojsonrpc.CodeInternalError, stdiojsonrpc.ClassInternalError, "progress notification could not be delivered", false)
	}
	return nil
}
