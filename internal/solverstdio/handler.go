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
)

type handler struct {
	authority   authority
	diagnose    diagnoseRunner
	writeReport func(string, passivediagnose.Report) (int64, error)
	options     Options
	build       BuildInfo
	limits      stdiojsonrpc.Limits
	handshaken  atomic.Bool
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
		return handler.connectTest(request)
	default:
		return nil, stdiojsonrpc.NewRPCError(stdiojsonrpc.CodeMethodNotFound, stdiojsonrpc.ClassMethodNotFound, "method is not part of the v1 schema", false)
	}
}

func (handler *handler) handshake(request stdiojsonrpc.Request) (any, *stdiojsonrpc.RPCError) {
	var params handshakeParams
	if rpcErr := decodeMethodParams(request.Params, &params); rpcErr != nil {
		return nil, rpcErr
	}
	if params.SchemaVersion != SchemaVersion || params.FramingVersion != FramingVersion {
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
		AuthScope:           "none",
		SupportedAuthScopes: []string{},
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
		SchemaVersion:          SchemaVersion,
		GeneratedAt:            report.GeneratedAt,
		GovernorScope:          report.GovernorScope,
		Namespace:              report.Namespace,
		MachineNamespace:       report.MachineNamespace,
		Owner:                  report.Owner,
		SafetyTrip:             handler.authority.SafetyTripStatus(),
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

func (handler *handler) connectTest(request stdiojsonrpc.Request) (any, *stdiojsonrpc.RPCError) {
	var params connectTestParams
	if rpcErr := decodeMethodParams(request.Params, &params); rpcErr != nil {
		return nil, rpcErr
	}
	rpcErr := stdiojsonrpc.NewRPCError(CodeNotImplemented, ClassNotImplemented, "connect_test is present in v1 but is not implemented", false)
	rpcErr.Data.Reason = "crypto_adr_vectors_and_independent_security_review_required"
	return nil, rpcErr
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
	var members map[string]json.RawMessage
	if err := json.Unmarshal(request.Params, &members); err != nil {
		return 0, stdiojsonrpc.NewRPCError(stdiojsonrpc.CodeInvalidParams, stdiojsonrpc.ClassInvalidParams, "params do not match the method schema", false)
	}
	raw, present := members["deadline_ms"]
	if !present {
		return 0, nil
	}
	var milliseconds int64
	if err := json.Unmarshal(raw, &milliseconds); err != nil || milliseconds <= 0 {
		return 0, stdiojsonrpc.NewRPCError(stdiojsonrpc.CodeInvalidParams, stdiojsonrpc.ClassInvalidParams, "deadline_ms must be a positive integer", false)
	}
	maximum := handler.limits.MaxDeadline.Milliseconds()
	if milliseconds > maximum {
		rpcErr := stdiojsonrpc.NewRPCError(stdiojsonrpc.CodeInvalidParams, stdiojsonrpc.ClassInvalidParams, "deadline_ms exceeds the protocol hard limit", false)
		rpcErr.Data.Limit = maximum
		return 0, rpcErr
	}
	return time.Duration(milliseconds) * time.Millisecond, nil
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
