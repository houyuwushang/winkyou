package model

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
			Steps:      []Step{},
		},
	}
}

// AddSleep adds a sleep step
func (b *Builder) AddSleep(ms int) *Builder {
	b.script.Steps = append(b.script.Steps, Step{
		Type:       StepSleep,
		DurationMS: ms,
	})
	return b
}

// AddReport adds a report event step
func (b *Builder) AddReport(event string, details map[string]string) *Builder {
	b.script.Steps = append(b.script.Steps, Step{
		Type:    StepReport,
		Event:   event,
		Details: details,
	})
	return b
}

// AddUDPSend adds a UDP send step
func (b *Builder) AddUDPSend(addr, payload string, timeoutMS int) *Builder {
	b.script.Steps = append(b.script.Steps, Step{
		Type:      StepUDPSend,
		Addr:      addr,
		Payload:   payload,
		TimeoutMS: timeoutMS,
	})
	return b
}

// AddUDPListen adds a UDP listen step
func (b *Builder) AddUDPListen(addr, expect string, timeoutMS int) *Builder {
	b.script.Steps = append(b.script.Steps, Step{
		Type:      StepUDPListen,
		Addr:      addr,
		Expect:    expect,
		TimeoutMS: timeoutMS,
	})
	return b
}

// AddTCPCheck adds a TCP connectivity check step
func (b *Builder) AddTCPCheck(addr string, timeoutMS int) *Builder {
	b.script.Steps = append(b.script.Steps, Step{
		Type:      StepTCPCheck,
		Addr:      addr,
		TimeoutMS: timeoutMS,
	})
	return b
}

// Build returns the constructed script
func (b *Builder) Build() Script {
	return b.script
}
