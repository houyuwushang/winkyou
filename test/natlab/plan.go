// Package natlab provides a root-only Linux network-namespace laboratory for
// repeatable NAT observations. The platform-neutral plan and recipe layer is
// intentionally testable without opening sockets or changing host networking.
package natlab

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

type Scenario string

const (
	ScenarioEIMPreserving Scenario = "eim_port_preserving"
	ScenarioRandomFully   Scenario = "random_port"
	ScenarioUDPBlocked    Scenario = "udp_blocked"
	ScenarioCGNAT         Scenario = "cgnat_double_nat"
	ScenarioBehaviorSwap  Scenario = "mid_attempt_behavior_change"
)

type NATMode string

const (
	NATModeMasquerade       NATMode = "masquerade"
	NATModeMasqueradeRandom NATMode = "masquerade_random_fully"
)

type Recipe struct {
	Scenario      Scenario
	DoubleNAT     bool
	InitialNAT    NATMode
	DropUDP       bool
	TransitionNAT *NATMode
}

func RecipeFor(scenario Scenario) (Recipe, error) {
	recipe := Recipe{Scenario: scenario, InitialNAT: NATModeMasquerade}
	switch scenario {
	case ScenarioEIMPreserving:
	case ScenarioRandomFully:
		recipe.InitialNAT = NATModeMasqueradeRandom
	case ScenarioUDPBlocked:
		recipe.DropUDP = true
	case ScenarioCGNAT:
		recipe.DoubleNAT = true
	case ScenarioBehaviorSwap:
		transition := NATModeMasqueradeRandom
		recipe.TransitionNAT = &transition
	default:
		return Recipe{}, fmt.Errorf("natlab: unknown scenario %q", scenario)
	}
	return recipe, nil
}

type LinkEnd struct {
	Namespace string
	Name      string
	CIDR      string
}

type LinkPlan struct {
	HostLeft  string
	HostRight string
	Left      LinkEnd
	Right     LinkEnd
}

type RoutePlan struct {
	Namespace string
	Via       string
}

type TopologyPlan struct {
	Suffix       string
	ClientA      string
	NATA         string
	NATA2        string
	Internet     string
	NATB         string
	ClientB      string
	Links        []LinkPlan
	Routes       []RoutePlan
	Forwarders   []string
	STUNAddress  string
	OuterAddress string
}

type CleanupKind string

const (
	CleanupNamespace CleanupKind = "namespace"
	CleanupHostLink  CleanupKind = "host_veth"
)

type CleanupStep struct {
	Kind CleanupKind
	Name string
}

var (
	safeNamePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	safeSuffixPattern = regexp.MustCompile(`^[a-z0-9]{1,6}$`)
)

func NewTopologyPlan(suffix string, doubleNAT bool) (TopologyPlan, error) {
	if !safeSuffixPattern.MatchString(suffix) {
		return TopologyPlan{}, errors.New("natlab: suffix must be 1-6 lowercase ASCII letters or digits")
	}
	prefix := "wy-" + suffix + "-"
	plan := TopologyPlan{
		Suffix:       suffix,
		ClientA:      prefix + "ca",
		NATA:         prefix + "na",
		Internet:     prefix + "inet",
		NATB:         prefix + "nb",
		ClientB:      prefix + "cb",
		STUNAddress:  "198.18.0.2:3478",
		OuterAddress: "198.18.0.1",
	}
	linkIndex := 0
	addLink := func(left LinkEnd, right LinkEnd) {
		linkIndex++
		stem := fmt.Sprintf("w%s%02d", suffix, linkIndex)
		plan.Links = append(plan.Links, LinkPlan{HostLeft: stem + "a", HostRight: stem + "b", Left: left, Right: right})
	}
	addLink(
		LinkEnd{Namespace: plan.ClientA, Name: "eth0", CIDR: "192.0.2.2/24"},
		LinkEnd{Namespace: plan.NATA, Name: "lan0", CIDR: "192.0.2.1/24"},
	)
	if doubleNAT {
		plan.NATA2 = prefix + "na2"
		addLink(
			LinkEnd{Namespace: plan.NATA, Name: "wan0", CIDR: "100.64.0.2/30"},
			LinkEnd{Namespace: plan.NATA2, Name: "lan0", CIDR: "100.64.0.1/30"},
		)
		addLink(
			LinkEnd{Namespace: plan.NATA2, Name: "wan0", CIDR: "198.18.0.1/30"},
			LinkEnd{Namespace: plan.Internet, Name: "a0", CIDR: "198.18.0.2/30"},
		)
		plan.Routes = append(plan.Routes,
			RoutePlan{Namespace: plan.NATA, Via: "100.64.0.1"},
			RoutePlan{Namespace: plan.NATA2, Via: "198.18.0.2"},
		)
		plan.Forwarders = append(plan.Forwarders, plan.NATA2)
	} else {
		addLink(
			LinkEnd{Namespace: plan.NATA, Name: "wan0", CIDR: "198.18.0.1/30"},
			LinkEnd{Namespace: plan.Internet, Name: "a0", CIDR: "198.18.0.2/30"},
		)
		plan.Routes = append(plan.Routes, RoutePlan{Namespace: plan.NATA, Via: "198.18.0.2"})
	}
	addLink(
		LinkEnd{Namespace: plan.Internet, Name: "b0", CIDR: "198.18.0.5/30"},
		LinkEnd{Namespace: plan.NATB, Name: "wan0", CIDR: "198.18.0.6/30"},
	)
	addLink(
		LinkEnd{Namespace: plan.NATB, Name: "lan0", CIDR: "198.51.100.1/24"},
		LinkEnd{Namespace: plan.ClientB, Name: "eth0", CIDR: "198.51.100.2/24"},
	)
	plan.Routes = append(plan.Routes,
		RoutePlan{Namespace: plan.ClientA, Via: "192.0.2.1"},
		RoutePlan{Namespace: plan.NATB, Via: "198.18.0.5"},
		RoutePlan{Namespace: plan.ClientB, Via: "198.51.100.1"},
	)
	plan.Forwarders = append(plan.Forwarders, plan.NATA, plan.Internet, plan.NATB)
	return plan, nil
}

func (plan TopologyPlan) NamespaceNames() []string {
	names := []string{plan.ClientA, plan.NATA}
	if plan.NATA2 != "" {
		names = append(names, plan.NATA2)
	}
	return append(names, plan.Internet, plan.NATB, plan.ClientB)
}

// CleanupSteps returns broad resources last-created-first. Namespace deletion
// removes both moved veth ends; explicit host-link steps are defensive for a
// setup failure that occurred between creating and moving the pair.
func (plan TopologyPlan) CleanupSteps() []CleanupStep {
	var steps []CleanupStep
	names := plan.NamespaceNames()
	for index := len(names) - 1; index >= 0; index-- {
		steps = append(steps, CleanupStep{Kind: CleanupNamespace, Name: names[index]})
	}
	for index := len(plan.Links) - 1; index >= 0; index-- {
		steps = append(steps,
			CleanupStep{Kind: CleanupHostLink, Name: plan.Links[index].HostLeft},
			CleanupStep{Kind: CleanupHostLink, Name: plan.Links[index].HostRight},
		)
	}
	return steps
}

func NATRestoreScript(outboundInterface string, mode NATMode) (string, error) {
	if !safeNamePattern.MatchString(outboundInterface) || len(outboundInterface) > 15 {
		return "", errors.New("natlab: invalid outbound interface")
	}
	rule := "-A POSTROUTING -o " + outboundInterface + " -j MASQUERADE"
	switch mode {
	case NATModeMasquerade:
	case NATModeMasqueradeRandom:
		rule += " --random-fully"
	default:
		return "", fmt.Errorf("natlab: unsupported NAT mode %q", mode)
	}
	return strings.Join([]string{
		"*nat",
		":PREROUTING ACCEPT [0:0]",
		":INPUT ACCEPT [0:0]",
		":OUTPUT ACCEPT [0:0]",
		":POSTROUTING ACCEPT [0:0]",
		rule,
		"COMMIT",
		"",
	}, "\n"), nil
}
