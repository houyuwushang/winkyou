//go:build linux && natlab

package natlab

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestN2DEIMMappingContract(t *testing.T) {
	for _, pair := range [][2]string{{n2dNATAWAN, n2dClientAAddress}, {n2dNATBWAN, n2dClientBAddress}} {
		publicAddress, privateAddress := pair[0], pair[1]
		for _, mode := range []n2dMappingMode{n2dMappingEIM, n2dMappingEIMRestricted, n2dMappingEDM} {
			plan, err := n2dNATPlanFor(mode, publicAddress, privateAddress)
			if err != nil {
				t.Fatal("documented disposable model rejected")
			}
			prefix := "*nat\n:PREROUTING ACCEPT [0:0]\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n"
			if mode == n2dMappingEIM {
				prefix = "*raw\n:PREROUTING ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n" +
					"-A PREROUTING -i lan0 -p udp -s " + privateAddress + "/32 -j NOTRACK\n" +
					"-A PREROUTING -i wan0 -p udp -d " + privateAddress + "/32 -j NOTRACK\nCOMMIT\n" + prefix
			}
			suffix := "-A POSTROUTING -s " + privateAddress + "/32 -o wan0 -p tcp -j SNAT --to-source " + publicAddress + "\nCOMMIT\n"
			udp := ""
			if mode != n2dMappingEIM {
				udp = "-A POSTROUTING -s " + privateAddress + "/32 -o wan0 -p udp -j SNAT --to-source " + publicAddress
				if mode == n2dMappingEDM {
					udp += " --random-fully"
				}
				udp += "\n"
			}
			if plan.Script != prefix+udp+suffix {
				t.Fatal("EIM reintroduced UDP conntrack NAT or changed restricted/EDM/TCP rules")
			}
			if mode != n2dMappingEIM {
				if len(plan.TrafficControl) != 0 {
					t.Fatal("stateless EIM translation escaped into a filtered model")
				}
				continue
			}
			want := [][]string{
				{"qdisc", "add", "dev", "wan0", "clsact"},
				strings.Fields("filter add dev wan0 ingress protocol ip pref 1 flower skip_hw ip_proto udp dst_ip " + publicAddress + "/32 action nat ingress " + publicAddress + "/32 " + privateAddress),
				strings.Fields("filter add dev wan0 egress protocol ip pref 1 flower skip_hw ip_proto udp src_ip " + privateAddress + "/32 action nat egress " + privateAddress + "/32 " + publicAddress),
			}
			check := func(candidate n2dNATPlan) bool {
				return candidate.Script == prefix+suffix && reflect.DeepEqual(candidate.TrafficControl, want)
			}
			if !check(plan) {
				t.Fatal("stateless translation changed family, addresses, UDP scope or hook")
			}
			// Deterministic mutations: the old conntrack recipe, one-sided
			// translation, direction inversion and layer-four rewrites all fail.
			old := plan
			old.Script = prefix + "-A POSTROUTING -p udp -j SNAT --to-source " + publicAddress + "\n" + suffix
			if check(old) {
				t.Fatal("implicit source-port remapping reaccepted")
			}
			tracked := plan
			tracked.Script = strings.ReplaceAll(tracked.Script, "-j NOTRACK", "-j ACCEPT")
			if check(tracked) {
				t.Fatal("UDP null-NAT binding path reaccepted")
			}
			for index := range plan.TrafficControl {
				mutated, _ := n2dNATPlanFor(mode, publicAddress, privateAddress)
				mutated.TrafficControl[index] = append(mutated.TrafficControl[index], "pedit", "munge", "udp", "sport", "set", "9")
				if check(mutated) {
					t.Fatal("UDP port rewrite accepted")
				}
			}
			missing := plan
			missing.TrafficControl = missing.TrafficControl[:2]
			if check(missing) {
				t.Fatal("missing source translation accepted")
			}
			inverted, _ := n2dNATPlanFor(mode, publicAddress, privateAddress)
			inverted.TrafficControl[1][17] = "egress"
			if check(inverted) {
				t.Fatal("destination/source direction inversion accepted")
			}
		}
	}
	for _, invalid := range []struct {
		mode n2dMappingMode
		pub  string
		priv string
	}{
		{"unknown", n2dNATAWAN, n2dClientAAddress},
		{n2dMappingEIM, "", ""},
		{n2dMappingEIM, n2dNATAWAN, n2dClientBAddress},
		{n2dMappingEIM, "192.0.2.254", n2dClientAAddress},
		{n2dMappingEIM, "SYNTHETIC_PRIVATE", "SYNTHETIC_PRIVATE"},
	} {
		plan, err := n2dNATPlanFor(invalid.mode, invalid.pub, invalid.priv)
		if err == nil || plan.Script != "" || len(plan.TrafficControl) != 0 {
			t.Fatal("unknown model or non-topology address acquired an executable plan")
		}
	}
	t.Run("counter_parser", testN2DEIMCounterParser)
	t.Run("actual_wiring", testN2DEIMMappingWiring)
}

func testN2DEIMCounterParser(t *testing.T) {
	for _, sample := range []struct {
		text string
		want bool
	}{
		{"conntrack v1.4.7 (conntrack-tools): 0 flow entries have been shown.\n", true},
		{"", false}, {"SYNTHETIC_PRIVATE", false},
		{"1 flow entries have been shown.", false},
		{"udp src=SYNTHETIC_PRIVATE\n0 flow entries have been shown.", false},
		{"0 flow entries have been shown.\n0 flow entries have been shown.", false},
	} {
		if n2dNoTrackedUDP(sample.text) != sample.want {
			t.Fatal("conntrack unavailable/ambiguous/nonzero treated as zero")
		}
	}
	for _, test := range []struct {
		text  string
		count uint64
		valid bool
	}{
		{"Sent 160 bytes 2 pkt (dropped 0, overlimits 0 requeues 0)", 2, true},
		{"SYNTHETIC_PRIVATE\r\n  Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0)\r\n", 0, true},
		{"", 0, false},
		{"Sent 160 bytes 2 pkt (dropped 1, overlimits 0 requeues 0)", 0, false},
		{"Sent 0 bytes 0 pkt (dropped 0,\nSent 0 bytes 0 pkt (dropped 0,", 0, false},
		{"Sent 0 bytes 18446744073709551616 pkt (dropped 0,", 0, false},
		{"SYNTHETIC_PRIVATE", 0, false},
	} {
		count, err := n2dTCTranslationPackets(test.text)
		if (err == nil) != test.valid || count != test.count || (err != nil && strings.Contains(err.Error(), "SYNTHETIC_PRIVATE")) {
			t.Fatal("counter validation or error redaction failed")
		}
	}
}

func testN2DEIMMappingWiring(t *testing.T) {
	for _, file := range []struct {
		name  string
		sites []string
	}{
		{"n2d_topology_linux_test.go", []string{
			"n2dNATPlanFor(mode, publicAddress, privateAddress)",
			"strings.NewReader(plan.Script)", "range plan.TrafficControl",
			"runNamespaced(namespace, \"tc\", nil, args...)",
		}},
		{"n2d_e2e_linux_test.go", []string{"t.Run(\"eim_mapping_contract\", TestN2DEIMMappingContract)", "assertN2DEIMTranslationCounts(t, topology, counts)"}},
		{"n3b_stdio_linux_test.go", []string{"assertN2DEIMTranslationCounts(t, topology, counts)"}},
	} {
		payload, err := os.ReadFile(file.name)
		if os.IsNotExist(err) {
			payload, err = os.ReadFile(filepath.Join("test", "natlab", file.name))
		}
		if err != nil {
			t.Fatal("N2d fixture source unavailable")
		}
		check := func(source string) bool {
			for _, site := range file.sites {
				if !strings.Contains(source, site) {
					return false
				}
			}
			return true
		}
		if !check(string(payload)) {
			t.Fatal("N2d EIM translation or OS witness disconnected")
		}
		for _, site := range file.sites {
			if check(strings.ReplaceAll(string(payload), site, "REMOVED")) {
				t.Fatal("disconnected EIM fixture mutation accepted")
			}
		}
	}
}
