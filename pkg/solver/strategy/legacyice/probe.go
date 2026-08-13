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

	evidence := summarizeProbeEvidence(input)
	reportDetails := map[string]string{
		"script_type":      pmodel.ScriptTypePreflight,
		"strategy":         StrategyName,
		"session_id":       input.SessionID,
		"remote_node_id":   input.RemoteNodeID,
		"evidence_hint":    evidence.hint(),
		"direct_failures":  fmt.Sprintf("%d", evidence.DirectFailures),
		"direct_successes": fmt.Sprintf("%d", evidence.DirectSuccesses),
		"relay_successes":  fmt.Sprintf("%d", evidence.RelaySuccesses),
	}

	script := pmodel.NewScript(pmodel.ScriptTypePreflight, "probe/preflight").
		AddSleep(25).
		AddReport("probe_ready", reportDetails).
		Build()

	policy := solver.ProbePolicy{
		Optional: true,
		Timeout:  500 * time.Millisecond,
		Reason:   "preflight_connectivity_check",
	}

	return &script, policy, nil
}
