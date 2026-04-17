package model

import (
	"time"

	"winkyou/pkg/solver"
)

const (
	StrategyName  = "probe_lab"
	StepUDPSend   = "udp_send"
	StepUDPListen = "udp_listen"
	StepTCPCheck  = "tcp_check"
	StepSleep     = "sleep"
	StepReport    = "report"
)

type Script struct {
	PlanID string `json:"plan_id,omitempty"`
	Steps  []Step `json:"steps,omitempty"`
}

type Step struct {
	Type       string            `json:"type"`
	Addr       string            `json:"addr,omitempty"`
	Payload    string            `json:"payload,omitempty"`
	Expect     string            `json:"expect,omitempty"`
	Message    string            `json:"message,omitempty"`
	Reply      string            `json:"reply,omitempty"`
	DurationMS int               `json:"duration_ms,omitempty"`
	TimeoutMS  int               `json:"timeout_ms,omitempty"`
	Event      string            `json:"event,omitempty"`
	Details    map[string]string `json:"details,omitempty"`
}

type Result struct {
	PlanID         string               `json:"plan_id,omitempty"`
	Success        bool                 `json:"success"`
	Events         []solver.Observation `json:"events,omitempty"`
	SelectedPathID string               `json:"selected_path_id,omitempty"`
	ErrorClass     string               `json:"error_class,omitempty"`
	FinishedAt     time.Time            `json:"finished_at"`
}
