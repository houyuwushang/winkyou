//go:build linux && natlab

package natlab

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

type n2dNATPlan struct {
	Script         string
	TrafficControl [][]string
}

// EIM/EIF is the single-endpoint reference model, not a claim about arbitrary
// consumer routers. Conntrack DNAT+SNAT can implicitly remap a UDP source port
// on tuple collision; omitting --to-source ports does NOT guarantee EIM.
// Instead tc's stateless nat action changes only IPv4 addresses/checksums. It
// cannot allocate a different port, and two simultaneous openers need no NAT
// entry winner. TCP retains its original SNAT; restricted/EDM retain their
// original conntrack rules. All socket binding and protocol timing are unchanged.
// Specification: https://man7.org/linux/man-pages/man8/tc-nat.8.html
func n2dNATPlanFor(mode n2dMappingMode, publicAddress, privateAddress string) (n2dNATPlan, error) {
	if !mode.valid() || !((publicAddress == n2dNATAWAN && privateAddress == n2dClientAAddress) ||
		(publicAddress == n2dNATBWAN && privateAddress == n2dClientBAddress)) {
		return n2dNATPlan{}, errors.New("N2d NAT model binding rejected")
	}
	var plan n2dNATPlan
	lines := []string{"*nat", ":PREROUTING ACCEPT [0:0]", ":INPUT ACCEPT [0:0]",
		":OUTPUT ACCEPT [0:0]", ":POSTROUTING ACCEPT [0:0]"}
	if mode == n2dMappingEIM {
		plan.TrafficControl = [][]string{
			{"qdisc", "add", "dev", "wan0", "clsact"},
			{"filter", "add", "dev", "wan0", "ingress", "protocol", "ip", "pref", "1",
				"flower", "skip_hw", "ip_proto", "udp", "dst_ip", publicAddress + "/32",
				"action", "nat", "ingress", publicAddress + "/32", privateAddress},
			{"filter", "add", "dev", "wan0", "egress", "protocol", "ip", "pref", "1",
				"flower", "skip_hw", "ip_proto", "udp", "src_ip", privateAddress + "/32",
				"action", "nat", "egress", privateAddress + "/32", publicAddress},
		}
	} else {
		udp := "-A POSTROUTING -s " + privateAddress + "/32 -o wan0 -p udp -j SNAT --to-source " + publicAddress
		if mode == n2dMappingEDM {
			udp += " --random-fully"
		}
		lines = append(lines, udp)
	}
	lines = append(lines,
		"-A POSTROUTING -s "+privateAddress+"/32 -o wan0 -p tcp -j SNAT --to-source "+publicAddress,
		"COMMIT", "")
	plan.Script = strings.Join(lines, "\n")
	if mode == n2dMappingEIM {
		// A TCP NAT table also installs netfilter's null-NAT binding path
		// for tracked UDP. That path can still allocate per-protocol parts.
		// Bypass it ONLY for this stateless reference's transit UDP. tc WAN
		// ingress has already changed the destination before raw PREROUTING.
		plan.Script = "*raw\n:PREROUTING ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n" +
			"-A PREROUTING -i lan0 -p udp -s " + privateAddress + "/32 -j NOTRACK\n" +
			"-A PREROUTING -i wan0 -p udp -d " + privateAddress + "/32 -j NOTRACK\nCOMMIT\n" + plan.Script
	}
	return plan, nil
}

var n2dTCActionStats = regexp.MustCompile(`(?m)^\s*Sent [0-9]+ bytes ([0-9]+) pkt \(dropped ([0-9]+),`)
var n2dConntrackListStats = regexp.MustCompile(`\b([0-9]+) flow entries have been shown\.`)

func n2dNoTrackedUDP(output string) bool {
	matches := n2dConntrackListStats.FindAllStringSubmatch(output, -1)
	return len(matches) == 1 && matches[0][1] == "0" && !strings.Contains(output, "src=")
}

// The entire tc output is private/transient. An absent or ambiguous statistic
// is unavailable evidence, not zero. Each direction owns exactly one action.
func n2dTCTranslationPackets(output string) (uint64, error) {
	matches := n2dTCActionStats.FindAllStringSubmatch(output, -1)
	if len(matches) != 1 || matches[0][2] != "0" {
		return 0, errors.New("N2d translation counter unavailable or dropped")
	}
	count, err := strconv.ParseUint(matches[0][1], 10, 64)
	if err != nil {
		return 0, errors.New("N2d translation counter rejected")
	}
	return count, nil
}

func (topology *n2dTopology) eimTranslationCounts() ([2][2]uint64, error) {
	var counts [2][2]uint64 // side, then ingress/egress; never ports or addresses
	if topology.leftMode != n2dMappingEIM || topology.rightMode != n2dMappingEIM {
		return counts, errors.New("N2d translation witness requires EIM pair")
	}
	for side, namespace := range []string{topology.natA, topology.natB} {
		tracked, err := runNamespaced(namespace, "conntrack", nil, "-L", "-p", "udp")
		if err != nil || !n2dNoTrackedUDP(tracked) {
			return counts, errors.New("N2d EIM UDP conntrack bypass witness failed")
		}
		for direction, hook := range []string{"ingress", "egress"} {
			output, err := runNamespaced(namespace, "tc", nil, "-s", "filter", "show", "dev", "wan0", hook)
			if err != nil {
				return counts, errors.New("N2d translation counter query failed")
			}
			counts[side][direction], err = n2dTCTranslationPackets(output)
			if err != nil {
				return counts, err
			}
		}
	}
	return counts, nil
}

func assertN2DEIMTranslationCounts(t testing.TB, topology *n2dTopology, packets n2dPacketCounts) {
	t.Helper()
	counts, err := topology.eimTranslationCounts()
	want := [2][2]uint64{
		{packets.InitiatorSTUN + packets.ResponderDirect, packets.InitiatorTotal},
		{packets.ResponderSTUN + packets.InitiatorDirect, packets.ResponderTotal},
	}
	if err != nil || counts != want {
		t.Fatalf("N2d EIM IP-only translation witness valid=%t got=%v want=%v", err == nil, counts, want)
	}
	t.Logf("N2D_EIM_TRANSLATION ip_only=true udp_conntrack=0 ingress_egress=%v exact=true", counts)
}
