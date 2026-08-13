package model

import "winkyou/pkg/solver"

const (
	StrategyName        = "probe_lab"
	ScriptTypePreflight = "preflight_v1"
	StepUDPSend         = "udp_send"
	StepUDPListen       = "udp_listen"
	StepTCPCheck        = "tcp_check"
	StepSleep           = "sleep"
	StepReport          = "report"
)

// These aliases keep the probe package's constants and builder API while the
// solver package remains the only authority for probe domain values.
type Script = solver.ProbeScript
type Step = solver.ProbeStep
type Result = solver.ProbeResult
