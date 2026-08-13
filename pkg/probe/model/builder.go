package model

import (
	"strconv"
	"time"

	"winkyou/pkg/solver"
)

// Builder provides a fluent interface for constructing probe scripts
type Builder struct {
	script Script
}

// NewScript creates a new script builder
func NewScript(scriptType, planID string) *Builder {
	return &Builder{
		script: Script{
			ScriptType: scriptType,
			PlanID:     planID,
			Steps:      []solver.ProbeStep{},
		},
	}
}

// AddSleep adds a sleep step
func (b *Builder) AddSleep(ms int) *Builder {
	b.script.Steps = append(b.script.Steps, Step{
		Action: StepSleep,
		Params: map[string]string{
			"duration_ms": strconv.Itoa(ms),
		},
	})
	return b
}

// AddReport adds a report event step
func (b *Builder) AddReport(event string, details map[string]string) *Builder {
	params := map[string]string{"event": event}
	for key, value := range details {
		params[key] = value
	}
	b.script.Steps = append(b.script.Steps, Step{
		Action: StepReport,
		Params: params,
	})
	return b
}

// AddUDPSend adds a UDP send step
func (b *Builder) AddUDPSend(addr, payload string, timeoutMS int) *Builder {
	b.script.Steps = append(b.script.Steps, Step{
		Action:  StepUDPSend,
		Params:  map[string]string{"addr": addr, "payload": payload},
		Timeout: time.Duration(timeoutMS) * time.Millisecond,
	})
	return b
}

// AddUDPListen adds a UDP listen step
func (b *Builder) AddUDPListen(addr, expect string, timeoutMS int) *Builder {
	b.script.Steps = append(b.script.Steps, Step{
		Action:  StepUDPListen,
		Params:  map[string]string{"addr": addr, "expect": expect},
		Timeout: time.Duration(timeoutMS) * time.Millisecond,
	})
	return b
}

// AddTCPCheck adds a TCP connectivity check step
func (b *Builder) AddTCPCheck(addr string, timeoutMS int) *Builder {
	b.script.Steps = append(b.script.Steps, Step{
		Action:  StepTCPCheck,
		Params:  map[string]string{"addr": addr},
		Timeout: time.Duration(timeoutMS) * time.Millisecond,
	})
	return b
}

// Build returns the constructed script
func (b *Builder) Build() Script {
	return solver.CloneProbeScript(b.script)
}
