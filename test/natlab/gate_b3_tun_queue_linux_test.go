//go:build linux && natlab

package natlab

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"winkyou/internal/v2/hardnatbudget"
)

// Only called with a fresh topology's owned NAT namespace and TUN name.
// No host/default/sysctl mutation, and no product caller can import tests.
func configureGateB3TUNQueue(namespace, name string, capacity int) error {
	if namespace == "" || name == "" || capacity < 1 || capacity > hardnatbudget.Hard16ActualPacketsMaximum {
		return errors.New("Gate B3 TUN queue allowance rejected")
	}
	// This topology is IPv4-only. Prevent the new TUN's own IPv6 address/MLD
	// traffic from occupying the ring or polluting the exact UDP witness.
	// This changes only this fresh test interface, never host IPv6/sysctls.
	if _, err := runCommand("ip", "-n", namespace, "link", "set", "dev", name,
		"txqueuelen", strconv.Itoa(capacity), "addrgenmode", "none", "multicast", "off"); err != nil {
		return errors.New("Gate B3 TUN queue installation failed")
	}
	actual, err := readGateB3TUNValue(namespace, name, "tx_queue_len")
	if err != nil || actual != uint64(capacity) {
		return errors.New("Gate B3 TUN queue readback failed")
	}
	return nil
}

func readGateB3TUNValue(namespace, name, field string) (uint64, error) {
	if field != "tx_queue_len" && field != "statistics/tx_dropped" {
		return 0, errors.New("Gate B3 TUN counter rejected")
	}
	output, err := runNamespaced(namespace, "cat", nil, "/sys/class/net/"+name+"/"+field)
	if err != nil {
		return 0, errors.New("Gate B3 TUN counter unavailable")
	}
	value, err := strconv.ParseUint(strings.TrimSpace(output), 10, 64)
	if err != nil {
		return 0, errors.New("Gate B3 TUN counter invalid")
	}
	return value, nil
}

// A paused reader makes kernel queue loss deterministic, independent of
// machine speed, NAT timers, conntrack snapshots or solver behavior. Both
// cases emit the same 48 synthetic packets ONCE in disposable TEST-NET netns.
// The short queue loses exactly sixteen; the bounded production-harness
// configuration must retain all packets without relaxing the equality.
func testGateB3TUNIngressQueueContract(t *testing.T) {
	for _, capacity := range []int{32, hardnatbudget.Hard16ActualPacketsMaximum} {
		t.Run(strconv.Itoa(capacity), func(t *testing.T) {
			topology := newN2DTopology(t, n2dMappingEDM, n2dMappingEDM)
			const sent = 48
			want := sent
			if capacity < want {
				want = capacity
			}
			var received, dropped uint64
			stage := "setup"
			err := RunInNamespace(topology.natA, func() error {
				name := gateB2TUNName(topology.natA)
				tun, err := openGateB2TUN(name)
				if err != nil {
					return err
				}
				defer tun.Close()
				if err := configureGateB3TUNQueue(topology.natA, name, capacity); err != nil {
					return err
				}
				if _, err := runCommand("ip", "-n", topology.natA, "link", "set", "dev", name, "up"); err != nil {
					return err
				}
				if _, err := runCommand("ip", "-n", topology.natA, "route", "add", n2dNATBWAN+"/32", "dev", name); err != nil {
					return err
				}
				before, err := readGateB3TUNValue(topology.natA, name, "statistics/tx_dropped")
				if err != nil {
					return err
				}
				socket, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort(n2dNATAWAN+":0")))
				if err != nil {
					return err
				}
				defer socket.Close()
				if err := socket.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
					return err
				}
				target := netip.MustParseAddrPort(n2dNATBWAN + ":51000")
				stage = "send"
				for ordinal := 0; ordinal < sent; ordinal++ {
					var payload [8]byte
					binary.BigEndian.PutUint64(payload[:], uint64(ordinal))
					if n, err := socket.WriteToUDPAddrPort(payload[:], target); err != nil || n != len(payload) {
						return errors.New("TUN proof write failed")
					}
				}
				after, err := readGateB3TUNValue(topology.natA, name, "statistics/tx_dropped")
				if err != nil || after < before {
					return errors.New("TUN proof drop counter failed")
				}
				dropped = after - before
				stage = "drop_count"
				if dropped != uint64(sent-want) {
					return errors.New("TUN proof kernel loss differed from exact queue overflow")
				}
				if err := tun.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
					return err
				}
				var buffer [256]byte
				stage = "read_order"
				for ordinal := 0; ordinal < want; ordinal++ {
					n, err := tun.Read(buffer[:])
					if err != nil {
						return err
					}
					packet, err := parseGateB2IPv4UDP(buffer[:n])
					if err != nil || len(packet.payload) != 8 || binary.BigEndian.Uint64(packet.payload) != uint64(ordinal) {
						return errors.New("TUN proof queue order or bytes changed")
					}
					received++
				}
				return nil
			})
			if err != nil {
				t.Errorf("TUN ingress proof failed: stage=%s received=%d dropped=%d deadline=%t", stage, received, dropped, errors.Is(err, os.ErrDeadlineExceeded))
			}
			if _, remaining, err := topology.flushConntrack(); err != nil || remaining != 0 {
				t.Error("TUN proof conntrack residue")
			}
			if sockets, processes, err := waitGateB2NoOSResidue(topology, gateB2TerminalMargin); err != nil || sockets != 0 || processes != 0 {
				t.Error("TUN proof OS residue")
			}
			if err := topology.cleanup(); err != nil {
				t.Fatal("TUN proof topology cleanup failed")
			}
			if err := topology.assertNoLeaks(); err != nil {
				t.Fatal("TUN proof namespace/veth residue")
			}
			t.Logf("TUN ingress queue witness: capacity=%d sent=%d received=%d dropped=%d proof_passed=%t", capacity, sent, received, dropped, !t.Failed())
		})
	}
	if configureGateB3TUNQueue("", "", hardnatbudget.Hard16ActualPacketsMaximum+1) == nil {
		t.Fatal("TUN queue accepted an out-of-scope capacity")
	}
}
