package natlab

import (
	"strings"
	"testing"
)

func TestRecipesFreezeFiveReviewedScenarios(t *testing.T) {
	tests := []struct {
		scenario   Scenario
		doubleNAT  bool
		initial    NATMode
		dropUDP    bool
		transition bool
	}{
		{ScenarioEIMPreserving, false, NATModeMasquerade, false, false},
		{ScenarioRandomFully, false, NATModeMasqueradeRandom, false, false},
		{ScenarioUDPBlocked, false, NATModeMasquerade, true, false},
		{ScenarioCGNAT, true, NATModeMasquerade, false, false},
		{ScenarioBehaviorSwap, false, NATModeMasquerade, false, true},
	}
	for _, test := range tests {
		t.Run(string(test.scenario), func(t *testing.T) {
			recipe, err := RecipeFor(test.scenario)
			if err != nil {
				t.Fatalf("recipe: %v", err)
			}
			if recipe.DoubleNAT != test.doubleNAT || recipe.InitialNAT != test.initial || recipe.DropUDP != test.dropUDP || (recipe.TransitionNAT != nil) != test.transition {
				t.Fatalf("recipe = %+v", recipe)
			}
		})
	}
	if _, err := RecipeFor("unreviewed"); err == nil {
		t.Fatal("unknown scenario was accepted")
	}
}

func TestTopologyPlanMovesEveryVethEndAndCoversFiveOrSixNamespaces(t *testing.T) {
	for _, invalid := range []string{"", "UPPER", "has-dash", "toolong"} {
		if _, err := NewTopologyPlan(invalid, false); err == nil {
			t.Fatalf("invalid suffix %q accepted", invalid)
		}
	}
	for _, doubleNAT := range []bool{false, true} {
		plan, err := NewTopologyPlan("a1b2c3", doubleNAT)
		if err != nil {
			t.Fatalf("plan double_nat=%t: %v", doubleNAT, err)
		}
		wantNamespaces := 5
		wantLinks := 4
		if doubleNAT {
			wantNamespaces = 6
			wantLinks = 5
		}
		if len(plan.NamespaceNames()) != wantNamespaces || len(plan.Links) != wantLinks {
			t.Fatalf("plan double_nat=%t namespaces=%d links=%d", doubleNAT, len(plan.NamespaceNames()), len(plan.Links))
		}
		seenHostNames := make(map[string]struct{})
		for _, link := range plan.Links {
			if link.Left.Namespace == "" || link.Right.Namespace == "" || link.Left.Name == "" || link.Right.Name == "" {
				t.Fatalf("link leaves a host-side endpoint: %+v", link)
			}
			for _, name := range []string{link.HostLeft, link.HostRight} {
				if len(name) > 15 {
					t.Fatalf("host veth name exceeds IFNAMSIZ: %q", name)
				}
				if _, exists := seenHostNames[name]; exists {
					t.Fatalf("duplicate host veth name %q", name)
				}
				seenHostNames[name] = struct{}{}
			}
		}
	}
}

func TestCleanupPlanDeletesNamespacesBeforeDefensiveHostLinks(t *testing.T) {
	plan, err := NewTopologyPlan("clean1", true)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	steps := plan.CleanupSteps()
	if len(steps) != len(plan.NamespaceNames())+2*len(plan.Links) {
		t.Fatalf("cleanup steps = %d", len(steps))
	}
	seenHostLink := false
	seen := make(map[string]struct{})
	for _, step := range steps {
		if _, duplicate := seen[string(step.Kind)+":"+step.Name]; duplicate {
			t.Fatalf("duplicate cleanup target: %+v", step)
		}
		seen[string(step.Kind)+":"+step.Name] = struct{}{}
		switch step.Kind {
		case CleanupNamespace:
			if seenHostLink {
				t.Fatalf("namespace cleanup appears after host-link cleanup: %+v", step)
			}
		case CleanupHostLink:
			seenHostLink = true
		default:
			t.Fatalf("unknown cleanup kind: %+v", step)
		}
	}
}

func TestNATRestoreScriptIsCompleteAtomicTableInput(t *testing.T) {
	plain, err := NATRestoreScript("wan0", NATModeMasquerade)
	if err != nil {
		t.Fatalf("plain restore: %v", err)
	}
	random, err := NATRestoreScript("wan0", NATModeMasqueradeRandom)
	if err != nil {
		t.Fatalf("random restore: %v", err)
	}
	for name, script := range map[string]string{"plain": plain, "random": random} {
		if !strings.HasPrefix(script, "*nat\n") || !strings.HasSuffix(script, "COMMIT\n") || strings.Count(script, "POSTROUTING") != 2 {
			t.Fatalf("%s script is not a complete nat table transaction:\n%s", name, script)
		}
	}
	if strings.Contains(plain, "--random-fully") || !strings.Contains(random, "--random-fully") {
		t.Fatalf("mode scripts plain=%q random=%q", plain, random)
	}
	if _, err := NATRestoreScript("wan0;bad", NATModeMasquerade); err == nil {
		t.Fatal("unsafe interface name accepted")
	}
}
