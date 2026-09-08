package architecture

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestSessionLivenessBoundaryAndEnforcementShape(t *testing.T) {
	root := repositoryRoot(t)
	if got, err := sessionLivenessViolations(root); err != nil || len(got) != 0 {
		t.Fatalf("liveness authority drift: %v %v", got, err)
	}
}

func sessionLivenessViolations(root string) ([]string, error) {
	var violations []string
	owners := map[string]map[string]bool{
		"SetInnerTap":                {"pkg/tunnel/inner_tap.go": true, "internal/v2/gatecorchestrator/liveness_controller.go": true},
		"ArmActivePolicy":            {"internal/probeio/wireguard_active_policy.go": true, "internal/v2/gatecorchestrator/liveness_controller.go": true},
		"armLiveness":                {"internal/v2/gatecorchestrator/liveness_controller.go": true, "internal/v2/gatecorchestrator/orchestrator.go": true},
		"livenessProofHook":          {"internal/v2/gatecorchestrator/types.go": true, "internal/v2/gatecorchestrator/orchestrator.go": true, "internal/v2/gatecorchestrator/memory_proof_c1bproof.go": true},
		"LivenessMemoryProofControl": {"internal/v2/gatecorchestrator/memory_proof_c1bproof.go": true},
	}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != root && (strings.HasPrefix(entry.Name(), ".") || entry.Name() == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		relative, _ := filepath.Rel(root, path)
		relative = filepath.ToSlash(relative)
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok {
				if allowed, watched := owners[id.Name]; watched && !allowed[relative] {
					violations = append(violations, relative+" uses unapproved liveness authority "+id.Name)
				}
			}
			return true
		})
		if strings.HasPrefix(relative, "pkg/tunnel/") {
			for _, spec := range f.Imports {
				imp, _ := strconv.Unquote(spec.Path.Value)
				if strings.HasPrefix(imp, modulePath+"/internal/v2/") || imp == modulePath+"/internal/probeio" || imp == modulePath+"/internal/governor" {
					violations = append(violations, "tunnel acquired liveness domain dependency")
				}
			}
		}
		if strings.HasPrefix(relative, "internal/v2/gatecorchestrator/liveness_") {
			for _, spec := range f.Imports {
				imp, _ := strconv.Unquote(spec.Path.Value)
				if imp == "net" || imp == "os/exec" || imp == "syscall" || strings.HasPrefix(imp, "golang.org/x/sys/") {
					violations = append(violations, "liveness acquired raw capability")
				}
			}
			ast.Inspect(f, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok {
					switch sel.Sel.Name {
					case "OpenProbeSocket", "RegisterTarget", "NewUDPFactory", "Promote", "Listen", "Dial", "Background", "TODO", "ReceivePacket", "Sleep", "AfterFunc":
						violations = append(violations, "liveness forbidden "+sel.Sel.Name)
					}
				}
				return true
			})
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok {
					continue
				}
				workers, timers := 0, 0
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					if _, ok := n.(*ast.GoStmt); ok {
						workers++
					}
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok && (sel.Sel.Name == "NewTimer" || sel.Sel.Name == "NewTicker" || sel.Sel.Name == "After") {
						timers++
					}
					if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "make" && len(call.Args) > 1 {
						if _, ok := call.Args[0].(*ast.ChanType); ok {
							cap, literal := call.Args[1].(*ast.BasicLit)
							value := 99
							if literal {
								value, _ = strconv.Atoi(cap.Value)
							}
							if !literal || value > 2 {
								violations = append(violations, "liveness queue exceeds two")
							}
						}
					}
					return true
				})
				if workers > 0 && (fn.Name.Name != "armLiveness" || workers != 2) {
					violations = append(violations, "liveness worker topology drift")
				}
				if timers > 0 && (timers != 1 || (fn.Name.Name != "watchdog" && fn.Name.Name != "run" && fn.Name.Name != "drain")) {
					violations = append(violations, "liveness timer topology drift")
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, shape := range []struct {
		file     string
		required []string
	}{
		{"internal/v2/gatecorchestrator/liveness_model.go", []string{
			"m.proofSent = pending.sent", "m.eventAgeLocked(m.proofSent)", "m.eventAgeLocked(m.pending.sent)",
			"message.sequence != pending.message.sequence || message.nonce != pending.message.nonce",
			"m.windowExpiredLocked(e.window)", "age >= livenessWriteWindow", "proofAge >= m.budget.lease",
			"m.peerHigh = message.sequence", "if !m.admitLocked(livenessPong)",
			"if !m.admitLocked(livenessPing)", "found < 0 || m.writing", "m.witness.AdmissionBypass++",
			"m.nextSlot = (m.elapsed/livenessInterval + 1) * livenessInterval",
			"return m.clock.instant().mono", "now := m.clock.instant().mono", "now-m.window[i] < livenessInterval",
			"sent: m.clock.instant(), proofSent: m.proofSent",
		}},
		{"internal/v2/gatecorchestrator/liveness_clock.go", []string{
			"now.mono-sent.mono, now.utc.Sub(sent.utc)", "return max(mono, utc), nil",
			"!sent.utc.Add(utc).Equal(now.utc)", "m < c.lastMono", "utc < mono-livenessClockTolerance",
		}},
		{"internal/v2/gatecorchestrator/liveness_controller.go", []string{
			"Permit: c.permit", "case <-c.stop:", "go c.writer()", "go c.watchdog()",
			"c.model.beginWrite(e)", "c.ni.InjectPacket(e.packet)",
			"Elapsed: model.currentMonotonicElapsed", "c.model.windowExpiredLocked(c.model.writeWindow)",
		}},
		{"internal/probeio/wireguard_active_policy.go", []string{
			"!gate.finishRecorded || !gate.detached", "gate.activePolicy != nil", "p.policy.Permit()",
			"p.used == len(p.window)", "p.witness.ControlAdmitted >= p.witness.ControlLimit",
		}},
	} {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(shape.file)))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, fragment := range shape.required {
			if !strings.Contains(string(data), fragment) {
				violations = append(violations, shape.file+" missing enforcement "+fragment)
			}
		}
	}
	if data, err := os.ReadFile(filepath.Join(root, "internal/v2/gatecorchestrator/orchestrator.go")); err == nil {
		if !orderedLivenessText(string(data), "handoff.FinishAndDetach(sessionCtx)", "postOOBEcho(sessionCtx", "newLivenessModel(", "armLiveness(", "result.DataPlaneReady = true") {
			violations = append(violations, "liveness armed before FINISH/echo")
		}
		if !orderedLivenessText(string(data), "var liveness *livenessController", "boundedTunnelStop(tun)", "if liveness != nil", "result.Witness.Handoff = handoff.Witness()", "result.Witness.WireGuard = result.Witness.Handoff.Transport", "tun.Start()") {
			violations = append(violations, "liveness terminal witness precedes WireGuard worker join")
		}
	}
	if data, err := os.ReadFile(filepath.Join(root, "internal/probeio/wireguard_session_gate.go")); err == nil {
		source := string(data)
		start := strings.Index(source, "policy := gate.activePolicy")
		if start < 0 || !orderedLivenessText(source[start:], "policy.beforeWrite(packet)", "gate.operationContext(ctx, state)", "gate.transport.WritePacket(opCtx, packet)") {
			violations = append(violations, "active write bypasses local permit/accounting")
		}
	}
	if data, err := os.ReadFile(filepath.Join(root, "internal/v2/gatecorchestrator/liveness_model.go")); err == nil {
		parsed, _ := parser.ParseFile(token.NewFileSet(), "model.go", data, 0)
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				assign, ok := n.(*ast.AssignStmt)
				if !ok {
					return true
				}
				for _, lhs := range assign.Lhs {
					if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "proofSent" && fn.Name.Name != "receive" {
						violations = append(violations, "only authenticated PONG may renew permit")
					}
				}
				return true
			})
		}
	}
	return uniqueSortedStrings(violations), nil
}

func orderedLivenessText(source string, fragments ...string) bool {
	for _, fragment := range fragments {
		index := strings.Index(source, fragment)
		if index < 0 {
			return false
		}
		source = source[index+len(fragment):]
	}
	return true
}

func TestSessionLivenessGateRejectsSnapshotBeforeWorkerJoin(t *testing.T) {
	root := t.TempDir()
	writeArchitectureMutation(t, root, "internal/v2/gatecorchestrator/orchestrator.go", `package gatecorchestrator
func f() {
    var liveness *livenessController
    if liveness != nil {
        result.Witness.Handoff = handoff.Witness()
        result.Witness.WireGuard = result.Witness.Handoff.Transport
    }
    boundedTunnelStop(tun)
    tun.Start()
}`)
	got, err := sessionLivenessViolations(root)
	if err != nil || !containsLineFragment(got, "witness precedes WireGuard worker join") {
		t.Fatalf("early snapshot mutation missed: %v %v", got, err)
	}
}

func TestSessionLivenessGateRejectsAuthorityAndLayerMutations(t *testing.T) {
	for _, tc := range []struct{ file, source, want string }{
		{"pkg/runtime/bypass.go", "package runtime; func f(){ _ = SetInnerTap; _ = ArmActivePolicy }", "unapproved liveness authority"},
		{"pkg/tunnel/bypass.go", "package tunnel; import _ \"winkyou/internal/v2/gatecorchestrator\"", "domain dependency"},
		{"internal/v2/gatecorchestrator/liveness_bypass.go", "package gatecorchestrator; import \"net\"; var _=net.Dial", "raw capability"},
		{"internal/v2/gatecorchestrator/liveness_bypass.go", "package gatecorchestrator; func f(){ _=controller.OpenProbeSocket; _=controller.RegisterTarget; _=context.Background }", "forbidden"},
	} {
		t.Run(tc.want+tc.file, func(t *testing.T) {
			root := t.TempDir()
			writeArchitectureMutation(t, root, tc.file, tc.source)
			got, err := sessionLivenessViolations(root)
			if err != nil || !containsLineFragment(got, tc.want) {
				t.Fatalf("mutation missed: %v %v", got, err)
			}
		})
	}
}

func TestSessionLivenessGateDetectsEarlyArmRawRenewalAndBypass(t *testing.T) {
	repository := repositoryRoot(t)
	for i, tc := range []struct{ file, old, replacement, want string }{
		{"internal/v2/gatecorchestrator/orchestrator.go", "postOOBEcho(sessionCtx", "mutatedEcho(sessionCtx", "armed before FINISH"},
		{"internal/probeio/wireguard_session_gate.go", "policy.beforeWrite(packet)", "nilPolicyCheck(packet)", "bypasses local permit"},
		{"internal/v2/gatecorchestrator/liveness_model.go", "m.proofSent = pending.sent", "m.proofSent = m.clock.instant()", "missing enforcement"},
		{"internal/v2/gatecorchestrator/liveness_model.go", "m.windowExpiredLocked(e.window)", "false, error(nil)", "missing enforcement"},
		{"internal/v2/gatecorchestrator/liveness_model.go", "now := m.clock.instant().mono", "now := m.elapsed", "missing enforcement"},
		{"internal/v2/gatecorchestrator/liveness_model.go", "return m.clock.instant().mono", "return m.elapsed", "missing enforcement"},
		{"internal/v2/gatecorchestrator/liveness_controller.go", "Elapsed: model.currentMonotonicElapsed", "Elapsed: model.originMaxElapsed", "missing enforcement"},
		{"internal/v2/gatecorchestrator/liveness_controller.go", "c.model.windowExpiredLocked(c.model.writeWindow)", "false, error(nil)", "missing enforcement"},
		{"internal/v2/gatecorchestrator/liveness_clock.go", "now.mono-sent.mono, now.utc.Sub(sent.utc)", "now.mono, now.utc.Sub(c.utc0)", "missing enforcement"},
		{"internal/v2/gatecorchestrator/liveness_model.go", "if !m.admitLocked(livenessPing)", "if false", "missing enforcement"},
		{"internal/probeio/wireguard_active_policy.go", "p.used == len(p.window)", "false", "missing enforcement"},
		{"internal/v2/gatecorchestrator/liveness_model.go", "func (m *livenessModel) receive(", "func (m *livenessModel) rawRX(", "only authenticated PONG"},
		{"internal/v2/gatecorchestrator/liveness_controller.go", "make(chan livenessControlEvent, 2)", "make(chan livenessControlEvent, 3)", "queue exceeds two"},
		{"internal/v2/gatecorchestrator/liveness_controller.go", "go c.writer()", "go c.writer(); go c.writer()", "worker topology drift"},
	} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(repository, filepath.FromSlash(tc.file)))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), tc.old) {
				t.Fatal("mutation did not apply")
			}
			root := t.TempDir()
			writeArchitectureMutation(t, root, tc.file, strings.Replace(string(data), tc.old, tc.replacement, 1))
			got, err := sessionLivenessViolations(root)
			if err != nil || !containsLineFragment(got, tc.want) {
				t.Fatalf("mutation missed: %v %v", got, err)
			}
		})
	}
}
