package wireadapter

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/solver"
)

const (
	probeParamAddr       = "addr"
	probeParamPayload    = "payload"
	probeParamExpect     = "expect"
	probeParamMessage    = "message"
	probeParamReply      = "reply"
	probeParamEvent      = "event"
	probeParamDurationMS = "duration_ms"
	probeDetailEscape    = "_wire_detail."
)

var structuredProbeParams = map[string]struct{}{
	probeParamAddr:       {},
	probeParamPayload:    {},
	probeParamExpect:     {},
	probeParamMessage:    {},
	probeParamReply:      {},
	probeParamEvent:      {},
	probeParamDurationMS: {},
}

// ProbeStepFromWire maps the v1 structured wire fields into the generic
// solver-domain Action/Params/Timeout representation. Structured fields win
// over colliding Details entries so untrusted details cannot shadow behavior;
// colliding details are retained under an adapter-reserved escape prefix.
func ProbeStepFromWire(step rproto.ProbeStep) solver.ProbeStep {
	params := make(map[string]string, 7+len(step.Details))
	setProbeParam(params, probeParamAddr, step.Addr)
	setProbeParam(params, probeParamPayload, step.Payload)
	setProbeParam(params, probeParamExpect, step.Expect)
	setProbeParam(params, probeParamMessage, step.Message)
	setProbeParam(params, probeParamReply, step.Reply)
	setProbeParam(params, probeParamEvent, step.Event)
	if step.DurationMS != 0 {
		params[probeParamDurationMS] = strconv.Itoa(step.DurationMS)
	}
	for key, value := range step.Details {
		if _, reserved := structuredProbeParams[key]; reserved {
			params[probeDetailEscape+key] = value
			continue
		}
		params[key] = value
	}
	return solver.NormalizeProbeStep(solver.ProbeStep{
		Action:  step.Type,
		Params:  params,
		Timeout: time.Duration(step.TimeoutMS) * time.Millisecond,
	})
}

// ProbeStepToWire maps the generic solver-domain representation to the v1
// structured rendezvous DTO. Non-reserved params remain wire Details.
func ProbeStepToWire(step solver.ProbeStep) rproto.ProbeStep {
	normalized := solver.NormalizeProbeStep(step)
	return rproto.ProbeStep{
		Type:       normalized.Action,
		Addr:       normalized.Params[probeParamAddr],
		Payload:    normalized.Params[probeParamPayload],
		Expect:     normalized.Params[probeParamExpect],
		Message:    normalized.Params[probeParamMessage],
		Reply:      normalized.Params[probeParamReply],
		DurationMS: parseProbeInt(normalized.Params[probeParamDurationMS]),
		TimeoutMS:  int(normalized.Timeout.Milliseconds()),
		Event:      normalized.Params[probeParamEvent],
		Details:    probeDetailsFromParams(normalized.Params),
	}
}

// ProbeStepDetails returns the owned v1 details view of a domain step. Probe
// runners use this to retain wire Details that collide with structured fields.
func ProbeStepDetails(step solver.ProbeStep) map[string]string {
	return probeDetailsFromParams(solver.NormalizeProbeStep(step).Params)
}

// ProbeScriptFromWire converts and owns a rendezvous probe script.
func ProbeScriptFromWire(script rproto.ProbeScript) solver.ProbeScript {
	steps := make([]solver.ProbeStep, len(script.Steps))
	for i := range script.Steps {
		steps[i] = ProbeStepFromWire(script.Steps[i])
	}
	return solver.NormalizeProbeScript(solver.ProbeScript{
		ScriptType: script.ScriptType,
		PlanID:     script.PlanID,
		Steps:      steps,
	})
}

// ProbeScriptToWire converts and owns a solver probe script.
func ProbeScriptToWire(script solver.ProbeScript) rproto.ProbeScript {
	normalized := solver.NormalizeProbeScript(script)
	steps := make([]rproto.ProbeStep, len(normalized.Steps))
	for i := range normalized.Steps {
		steps[i] = ProbeStepToWire(normalized.Steps[i])
	}
	return rproto.ProbeScript{
		ScriptType: normalized.ScriptType,
		PlanID:     normalized.PlanID,
		Steps:      steps,
	}
}

// ProbeResultFromWire converts and owns a rendezvous probe result. The legacy
// wire PathID field was ignored by the pre-domain adapter and remains ignored;
// SelectedPathID is the canonical result field.
func ProbeResultFromWire(result rproto.ProbeResult) solver.ProbeResult {
	events := make([]solver.Observation, len(result.Events))
	for i := range result.Events {
		events[i] = ObservationFromWire(result.Events[i])
	}
	return solver.NormalizeProbeResult(solver.ProbeResult{
		ScriptType:     result.ScriptType,
		PlanID:         result.PlanID,
		Success:        result.Success,
		Events:         events,
		SelectedPathID: result.SelectedPathID,
		ErrorClass:     result.ErrorClass,
		FinishedAt:     result.FinishedAt,
	})
}

// ProbeResultToWire converts and owns a solver probe result.
func ProbeResultToWire(result solver.ProbeResult) rproto.ProbeResult {
	normalized := solver.NormalizeProbeResult(result)
	events := make([]rproto.Observation, len(normalized.Events))
	for i := range normalized.Events {
		events[i] = ObservationToWire(normalized.Events[i])
	}
	return rproto.ProbeResult{
		ScriptType:     normalized.ScriptType,
		PlanID:         normalized.PlanID,
		Success:        normalized.Success,
		Events:         events,
		SelectedPathID: normalized.SelectedPathID,
		ErrorClass:     normalized.ErrorClass,
		FinishedAt:     normalized.FinishedAt,
	}
}

func setProbeParam(params map[string]string, key, value string) {
	if value != "" {
		params[key] = value
	}
}

func probeDetailsFromParams(params map[string]string) map[string]string {
	if len(params) == 0 {
		return nil
	}
	details := make(map[string]string, len(params))
	for key, value := range params {
		if strings.HasPrefix(key, probeDetailEscape) {
			detailKey := strings.TrimPrefix(key, probeDetailEscape)
			if detailKey != "" {
				details[detailKey] = value
			}
			continue
		}
		if _, structured := structuredProbeParams[key]; structured {
			continue
		}
		details[key] = value
	}
	if len(details) == 0 {
		return nil
	}
	return details
}

func parseProbeInt(value string) int {
	if value == "" {
		return 0
	}
	var parsed int
	_, _ = fmt.Sscanf(value, "%d", &parsed)
	return parsed
}
