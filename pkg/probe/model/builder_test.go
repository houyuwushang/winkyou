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
	if script.Steps[0].Type != StepSleep {
		t.Fatalf("step 0 type = %q, want %q", script.Steps[0].Type, StepSleep)
	}
	if script.Steps[1].Type != StepReport {
		t.Fatalf("step 1 type = %q, want %q", script.Steps[1].Type, StepReport)
	}
	if script.Steps[2].Type != StepUDPSend {
		t.Fatalf("step 2 type = %q, want %q", script.Steps[2].Type, StepUDPSend)
	}
	if script.Steps[3].Type != StepUDPListen {
		t.Fatalf("step 3 type = %q, want %q", script.Steps[3].Type, StepUDPListen)
	}
	if script.Steps[4].Type != StepTCPCheck {
		t.Fatalf("step 4 type = %q, want %q", script.Steps[4].Type, StepTCPCheck)
	}
}
