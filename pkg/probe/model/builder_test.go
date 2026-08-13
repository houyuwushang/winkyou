package model

import "testing"

func TestBuilderBuildsScriptRunCompatibleScript(t *testing.T) {
	script := NewScript(ScriptTypePreflight, "probe/preflight").
		AddSleep(25).
		AddReport("probe_ready", map[string]string{"reason": "builder_test"}).
		AddUDPSend("127.0.0.1:9999", "ping", 100).
		AddUDPListen(":9998", "pong", 100).
		AddTCPCheck("127.0.0.1:80", 100).
		Build()

	if script.ScriptType != ScriptTypePreflight {
		t.Fatalf("ScriptType = %q, want %q", script.ScriptType, ScriptTypePreflight)
	}
	if script.PlanID != "probe/preflight" {
		t.Fatalf("PlanID = %q, want probe/preflight", script.PlanID)
	}
	if len(script.Steps) != 5 {
		t.Fatalf("step count = %d, want 5", len(script.Steps))
	}
	if script.Steps[0].Action != StepSleep {
		t.Fatalf("step 0 type = %q, want %q", script.Steps[0].Action, StepSleep)
	}
	if script.Steps[1].Action != StepReport {
		t.Fatalf("step 1 type = %q, want %q", script.Steps[1].Action, StepReport)
	}
	if script.Steps[2].Action != StepUDPSend {
		t.Fatalf("step 2 type = %q, want %q", script.Steps[2].Action, StepUDPSend)
	}
	if script.Steps[3].Action != StepUDPListen {
		t.Fatalf("step 3 type = %q, want %q", script.Steps[3].Action, StepUDPListen)
	}
	if script.Steps[4].Action != StepTCPCheck {
		t.Fatalf("step 4 type = %q, want %q", script.Steps[4].Action, StepTCPCheck)
	}
}
