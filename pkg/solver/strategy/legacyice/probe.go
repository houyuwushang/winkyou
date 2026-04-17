package legacyice

import (
	"context"
	"fmt"
	"time"

	pmodel "winkyou/pkg/probe/model"
	"winkyou/pkg/solver"
)

func (s *Strategy) BuildPreflightProbe(ctx context.Context, input solver.ProbeInput) (*solver.ProbeScript, solver.ProbePolicy, error) {
	_ = ctx

	// Conservative preflight: minimal probe to verify basic connectivity readiness
	script := pmodel.NewScript(pmodel.ScriptTypePreflight, "probe/preflight").
		AddSleep(25).
		AddReport("probe_ready", map[string]string{
			"script_type": pmodel.ScriptTypePreflight,
			"strategy":    StrategyName,
		}).
		Build()

	policy := solver.ProbePolicy{
		Optional: true,
		Timeout:  500 * time.Millisecond,
		Reason:   "preflight_connectivity_check",
	}

	solverScript := &solver.ProbeScript{
		ScriptType: script.ScriptType,
		PlanID:     script.PlanID,
		Steps:      make([]solver.ProbeStep, len(script.Steps)),
	}

	for i, step := range script.Steps {
		solverScript.Steps[i] = solver.ProbeStep{
			Action:  step.Type,
			Params:  convertStepParams(step),
			Timeout: time.Duration(step.TimeoutMS) * time.Millisecond,
		}
	}

	return solverScript, policy, nil
}

func convertStepParams(step pmodel.Step) map[string]string {
	params := make(map[string]string)
	if step.Addr != "" {
		params["addr"] = step.Addr
	}
	if step.Payload != "" {
		params["payload"] = step.Payload
	}
	if step.Expect != "" {
		params["expect"] = step.Expect
	}
	if step.Message != "" {
		params["message"] = step.Message
	}
	if step.Reply != "" {
		params["reply"] = step.Reply
	}
	if step.Event != "" {
		params["event"] = step.Event
	}
	if step.DurationMS > 0 {
		params["duration_ms"] = fmt.Sprintf("%d", step.DurationMS)
	}
	for k, v := range step.Details {
		params[k] = v
	}
	return params
}
