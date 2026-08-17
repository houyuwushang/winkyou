//go:build linux

package natlab

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

const commandTimeout = 10 * time.Second

type Topology struct {
	Plan               TopologyPlan
	ownedNamespaces    map[string]struct{}
	ownedHostLinkNames map[string]struct{}
}

func CreateTopology(plan TopologyPlan) (*Topology, error) {
	topology := &Topology{
		Plan:               plan,
		ownedNamespaces:    make(map[string]struct{}),
		ownedHostLinkNames: make(map[string]struct{}),
	}
	fail := func(cause error) (*Topology, error) {
		return nil, errors.Join(cause, topology.Cleanup(), topology.AssertNoLeaks())
	}
	for _, namespace := range plan.NamespaceNames() {
		if _, err := runCommand("ip", "netns", "add", namespace); err != nil {
			return fail(err)
		}
		topology.ownedNamespaces[namespace] = struct{}{}
		if _, err := runCommand("ip", "-n", namespace, "link", "set", "lo", "up"); err != nil {
			return fail(err)
		}
	}
	for _, link := range plan.Links {
		if _, err := runCommand("ip", "link", "add", link.HostLeft, "type", "veth", "peer", "name", link.HostRight); err != nil {
			return fail(err)
		}
		topology.ownedHostLinkNames[link.HostLeft] = struct{}{}
		topology.ownedHostLinkNames[link.HostRight] = struct{}{}
		if _, err := runCommand("ip", "link", "set", link.HostLeft, "netns", link.Left.Namespace); err != nil {
			return fail(err)
		}
		if _, err := runCommand("ip", "link", "set", link.HostRight, "netns", link.Right.Namespace); err != nil {
			return fail(err)
		}
		if err := configureLinkEnd(link.Left, link.HostLeft); err != nil {
			return fail(err)
		}
		if err := configureLinkEnd(link.Right, link.HostRight); err != nil {
			return fail(err)
		}
	}
	for _, route := range plan.Routes {
		if _, err := runCommand("ip", "-n", route.Namespace, "route", "replace", "default", "via", route.Via); err != nil {
			return fail(err)
		}
	}
	filterRestore := "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n"
	for _, namespace := range plan.Forwarders {
		if _, err := runNamespaced(namespace, "sysctl", nil, "-qw", "net.ipv4.ip_forward=1"); err != nil {
			return fail(err)
		}
		if _, err := runNamespaced(namespace, "iptables-restore", strings.NewReader(filterRestore)); err != nil {
			return fail(err)
		}
	}
	return topology, nil
}

func configureLinkEnd(end LinkEnd, temporaryName string) error {
	if _, err := runCommand("ip", "-n", end.Namespace, "link", "set", temporaryName, "name", end.Name); err != nil {
		return err
	}
	if _, err := runCommand("ip", "-n", end.Namespace, "addr", "add", end.CIDR, "dev", end.Name); err != nil {
		return err
	}
	if _, err := runCommand("ip", "-n", end.Namespace, "link", "set", end.Name, "up"); err != nil {
		return err
	}
	return nil
}

func (topology *Topology) ApplyRecipe(recipe Recipe) error {
	if topology == nil {
		return errors.New("natlab: topology is nil")
	}
	if recipe.DoubleNAT != (topology.Plan.NATA2 != "") {
		return errors.New("natlab: recipe and topology disagree about the second NAT layer")
	}
	if err := topology.ApplyNAT(topology.Plan.NATA, recipe.InitialNAT); err != nil {
		return err
	}
	if topology.Plan.NATA2 != "" {
		if err := topology.ApplyNAT(topology.Plan.NATA2, NATModeMasquerade); err != nil {
			return err
		}
	}
	if err := topology.ApplyNAT(topology.Plan.NATB, NATModeMasquerade); err != nil {
		return err
	}
	if recipe.DropUDP {
		if _, err := runNamespaced(topology.Plan.NATA, "iptables", nil, "-I", "FORWARD", "1", "-p", "udp", "-j", "DROP"); err != nil {
			return err
		}
	}
	return nil
}

// ApplyNAT atomically replaces the complete nat table in one namespace.
func (topology *Topology) ApplyNAT(namespace string, mode NATMode) error {
	if topology == nil || !topology.ownsNamespace(namespace) {
		return errors.New("natlab: NAT namespace is outside this topology")
	}
	script, err := NATRestoreScript("wan0", mode)
	if err != nil {
		return err
	}
	_, err = runNamespaced(namespace, "iptables-restore", strings.NewReader(script))
	return err
}

func (topology *Topology) MasqueradePackets(namespace string) (uint64, error) {
	if topology == nil || !topology.ownsNamespace(namespace) {
		return 0, errors.New("natlab: counter namespace is outside this topology")
	}
	output, err := runNamespaced(namespace, "iptables", nil, "-t", "nat", "-L", "POSTROUTING", "-v", "-n", "-x")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[2] != "MASQUERADE" {
			continue
		}
		packets, parseErr := strconv.ParseUint(fields[0], 10, 64)
		if parseErr != nil {
			return 0, fmt.Errorf("natlab: parse MASQUERADE counter %q: %w", fields[0], parseErr)
		}
		return packets, nil
	}
	return 0, errors.New("natlab: MASQUERADE rule counter is missing")
}

func (topology *Topology) NamespacePath(namespace string) (string, error) {
	if topology == nil || !topology.ownsNamespace(namespace) {
		return "", errors.New("natlab: namespace is outside this topology")
	}
	return "/var/run/netns/" + namespace, nil
}

func (topology *Topology) Cleanup() error {
	if topology == nil {
		return nil
	}
	var result error
	for _, step := range topology.Plan.CleanupSteps() {
		switch step.Kind {
		case CleanupNamespace:
			if _, owned := topology.ownedNamespaces[step.Name]; !owned {
				continue
			}
			exists, err := namespaceExists(step.Name)
			if err != nil {
				result = errors.Join(result, err)
				continue
			}
			if exists {
				_, err = runCommand("ip", "netns", "del", step.Name)
				result = errors.Join(result, err)
			}
		case CleanupHostLink:
			if _, owned := topology.ownedHostLinkNames[step.Name]; !owned {
				continue
			}
			exists, err := hostLinkExists(step.Name)
			if err != nil {
				result = errors.Join(result, err)
				continue
			}
			if exists {
				_, err = runCommand("ip", "link", "del", step.Name)
				result = errors.Join(result, err)
			}
		}
	}
	return result
}

func (topology *Topology) AssertNoLeaks() error {
	if topology == nil {
		return nil
	}
	var leaks []string
	for namespace := range topology.ownedNamespaces {
		exists, err := namespaceExists(namespace)
		if err != nil {
			return err
		}
		if exists {
			leaks = append(leaks, "netns:"+namespace)
		}
	}
	for name := range topology.ownedHostLinkNames {
		exists, err := hostLinkExists(name)
		if err != nil {
			return err
		}
		if exists {
			leaks = append(leaks, "veth:"+name)
		}
	}
	if len(leaks) > 0 {
		sort.Strings(leaks)
		return fmt.Errorf("natlab: leaked resources: %s", strings.Join(leaks, ","))
	}
	return nil
}

func (topology *Topology) ownsNamespace(candidate string) bool {
	_, owned := topology.ownedNamespaces[candidate]
	return owned
}

func namespaceExists(name string) (bool, error) {
	output, err := runCommand("ip", "netns", "list")
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == name {
			return true, nil
		}
	}
	return false, nil
}

func hostLinkExists(name string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, "ip", "link", "show", "dev", name)
	output, err := command.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		message := strings.ToLower(string(output))
		if strings.Contains(message, "does not exist") || strings.Contains(message, "cannot find device") {
			return false, nil
		}
		return false, fmt.Errorf("natlab: inspect host link %q: %w: %s", name, err, strings.TrimSpace(string(output)))
	}
	return true, nil
}

func runNamespaced(namespace, program string, input *strings.Reader, args ...string) (string, error) {
	commandArgs := append([]string{"netns", "exec", namespace, program}, args...)
	return runCommandInput(input, "ip", commandArgs...)
}

func runCommand(program string, args ...string) (string, error) {
	return runCommandInput(nil, program, args...)
}

func runCommandInput(input *strings.Reader, program string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, program, args...)
	if input != nil {
		command.Stdin = input
	}
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		return string(output), fmt.Errorf("natlab: %s timed out: %w", program, ctx.Err())
	}
	if err != nil {
		return string(output), fmt.Errorf("natlab: %s %s: %w: %s", program, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}
