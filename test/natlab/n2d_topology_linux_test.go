//go:build linux && natlab

package natlab

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"winkyou/internal/stunserver"
	"winkyou/internal/v2/rendezvouscarrier"
)

const (
	n2dClientAAddress = "192.0.2.2"
	n2dNATALAN        = "192.0.2.1"
	n2dNATAWAN        = "198.51.100.1"
	n2dPublicA        = "198.51.100.2"
	n2dPublicB        = "203.0.113.1"
	n2dNATBWAN        = "203.0.113.2"
	n2dNATBLAN        = "192.0.2.5"
	n2dClientBAddress = "192.0.2.6"

	n2dEndpointInterface = "eth0"
	n2dTerminalMargin    = 2 * time.Second
)

type n2dMappingMode string

const (
	n2dMappingEIM n2dMappingMode = "eim"
	n2dMappingEDM n2dMappingMode = "edm"
)

var n2dTopologySequence atomic.Uint32

type n2dLink struct {
	hostLeft, hostRight string
	leftNamespace       string
	leftName            string
	leftCIDR            string
	rightNamespace      string
	rightName           string
	rightCIDR           string
}

type n2dTopology struct {
	clientA, natA, public, natB, clientB string
	links                                []n2dLink
	leftMode, rightMode                  n2dMappingMode
	cleanOnce                            sync.Once
	cleanErr                             error
}

type n2dPacketCounts struct {
	InitiatorSTUN   uint64
	InitiatorDirect uint64
	InitiatorTotal  uint64
	ResponderSTUN   uint64
	ResponderDirect uint64
	ResponderTotal  uint64
}

type n2dResidualWitness struct {
	SocketsBeforeClose int
	SocketsAfterClose  int
	Processes          int
	ConntrackBefore    int
	ConntrackAfter     int
}

func newN2DTopology(t interface {
	Helper()
	Fatal(args ...any)
	Cleanup(func())
}, leftMode, rightMode n2dMappingMode) *n2dTopology {
	t.Helper()
	if !leftMode.valid() || !rightMode.valid() {
		t.Fatal("N2d NAT mode rejected")
	}
	sequence := n2dTopologySequence.Add(1)
	suffix := fmt.Sprintf("%06x", (uint32(time.Now().UnixNano())+sequence)&0xffffff)
	prefix := "wy2" + suffix
	topology := &n2dTopology{
		clientA: prefix + "ca", natA: prefix + "na", public: prefix + "pub",
		natB: prefix + "nb", clientB: prefix + "cb", leftMode: leftMode, rightMode: rightMode,
	}
	add := func(index int, leftNamespace, leftName, leftCIDR, rightNamespace, rightName, rightCIDR string) {
		stem := fmt.Sprintf("d%s%d", suffix, index)
		topology.links = append(topology.links, n2dLink{
			hostLeft: stem + "a", hostRight: stem + "b",
			leftNamespace: leftNamespace, leftName: leftName, leftCIDR: leftCIDR,
			rightNamespace: rightNamespace, rightName: rightName, rightCIDR: rightCIDR,
		})
	}
	add(1, topology.clientA, n2dEndpointInterface, n2dClientAAddress+"/30", topology.natA, "lan0", n2dNATALAN+"/30")
	add(2, topology.natA, "wan0", n2dNATAWAN+"/29", topology.public, "a0", n2dPublicA+"/29")
	add(3, topology.public, "b0", n2dPublicB+"/29", topology.natB, "wan0", n2dNATBWAN+"/29")
	add(4, topology.natB, "lan0", n2dNATBLAN+"/30", topology.clientB, n2dEndpointInterface, n2dClientBAddress+"/30")
	t.Cleanup(func() { _ = topology.cleanup() })
	if err := topology.create(); err != nil {
		_ = topology.cleanup()
		t.Fatal("N2d isolated topology setup failed")
	}
	return topology
}

func (mode n2dMappingMode) valid() bool { return mode == n2dMappingEIM || mode == n2dMappingEDM }

func (topology *n2dTopology) namespaces() []string {
	return []string{topology.clientA, topology.natA, topology.public, topology.natB, topology.clientB}
}

func (topology *n2dTopology) create() error {
	for _, namespace := range topology.namespaces() {
		if _, err := runCommand("ip", "netns", "add", namespace); err != nil {
			return err
		}
		if _, err := runCommand("ip", "-n", namespace, "link", "set", "lo", "up"); err != nil {
			return err
		}
	}
	for _, link := range topology.links {
		if _, err := runCommand("ip", "link", "add", link.hostLeft, "type", "veth", "peer", "name", link.hostRight); err != nil {
			return err
		}
		if _, err := runCommand("ip", "link", "set", link.hostLeft, "netns", link.leftNamespace); err != nil {
			return err
		}
		if _, err := runCommand("ip", "link", "set", link.hostRight, "netns", link.rightNamespace); err != nil {
			return err
		}
		if err := n2dConfigureEnd(link.leftNamespace, link.hostLeft, link.leftName, link.leftCIDR); err != nil {
			return err
		}
		if err := n2dConfigureEnd(link.rightNamespace, link.hostRight, link.rightName, link.rightCIDR); err != nil {
			return err
		}
	}
	for namespace, gateway := range map[string]string{
		topology.clientA: n2dNATALAN,
		topology.natA:    n2dPublicA,
		topology.natB:    n2dPublicB,
		topology.clientB: n2dNATBLAN,
	} {
		if _, err := runCommand("ip", "-n", namespace, "route", "replace", "default", "via", gateway); err != nil {
			return err
		}
	}
	for _, namespace := range []string{topology.natA, topology.public, topology.natB} {
		if _, err := runNamespaced(namespace, "sysctl", nil, "-qw", "net.ipv4.ip_forward=1"); err != nil {
			return err
		}
		filter := "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n"
		if _, err := runNamespaced(namespace, "iptables-restore", strings.NewReader(filter)); err != nil {
			return err
		}
	}
	if err := topology.applyNAT(topology.natA, topology.leftMode); err != nil {
		return err
	}
	return topology.applyNAT(topology.natB, topology.rightMode)
}

func n2dConfigureEnd(namespace, temporaryName, finalName, cidr string) error {
	if _, err := runCommand("ip", "-n", namespace, "link", "set", temporaryName, "name", finalName); err != nil {
		return err
	}
	if _, err := runCommand("ip", "-n", namespace, "addr", "add", cidr, "dev", finalName); err != nil {
		return err
	}
	_, err := runCommand("ip", "-n", namespace, "link", "set", finalName, "up")
	return err
}

func (topology *n2dTopology) applyNAT(namespace string, mode n2dMappingMode) error {
	rule := "-A POSTROUTING -o wan0 -j MASQUERADE"
	if mode == n2dMappingEDM {
		rule += " --random-fully"
	}
	script := strings.Join([]string{
		"*nat", ":PREROUTING ACCEPT [0:0]", ":INPUT ACCEPT [0:0]", ":OUTPUT ACCEPT [0:0]",
		":POSTROUTING ACCEPT [0:0]", rule, "COMMIT", "",
	}, "\n")
	_, err := runNamespaced(namespace, "iptables-restore", strings.NewReader(script))
	return err
}

func (topology *n2dTopology) installPacketCounters(stunPort uint16) error {
	if stunPort == 0 {
		return errors.New("zero STUN port")
	}
	for _, endpoint := range []struct {
		namespace  string
		peerPublic string
	}{
		{topology.clientA, n2dNATBWAN},
		{topology.clientB, n2dNATAWAN},
	} {
		commands := [][]string{
			{"-w", "5", "-N", "WYN2D_TOTAL"},
			{"-w", "5", "-A", "WYN2D_TOTAL", "-j", "RETURN"},
			{"-w", "5", "-A", "OUTPUT", "-o", n2dEndpointInterface, "-p", "udp", "-j", "WYN2D_TOTAL"},
			{"-w", "5", "-N", "WYN2D_STUN"},
			{"-w", "5", "-A", "WYN2D_STUN", "-j", "RETURN"},
			{"-w", "5", "-A", "OUTPUT", "-o", n2dEndpointInterface, "-p", "udp", "-d", n2dPublicA, "--dport", strconv.Itoa(int(stunPort)), "-j", "WYN2D_STUN"},
			{"-w", "5", "-N", "WYN2D_DIRECT"},
			{"-w", "5", "-A", "WYN2D_DIRECT", "-j", "RETURN"},
			{"-w", "5", "-A", "OUTPUT", "-o", n2dEndpointInterface, "-p", "udp", "-d", endpoint.peerPublic, "-j", "WYN2D_DIRECT"},
		}
		for _, args := range commands {
			if _, err := runNamespaced(endpoint.namespace, "iptables", nil, args...); err != nil {
				return err
			}
		}
	}
	return nil
}

func (topology *n2dTopology) packetCounts() (n2dPacketCounts, error) {
	leftSTUN, err := n2dChainPackets(topology.clientA, "WYN2D_STUN")
	if err != nil {
		return n2dPacketCounts{}, err
	}
	leftDirect, err := n2dChainPackets(topology.clientA, "WYN2D_DIRECT")
	if err != nil {
		return n2dPacketCounts{}, err
	}
	leftTotal, err := n2dChainPackets(topology.clientA, "WYN2D_TOTAL")
	if err != nil {
		return n2dPacketCounts{}, err
	}
	rightSTUN, err := n2dChainPackets(topology.clientB, "WYN2D_STUN")
	if err != nil {
		return n2dPacketCounts{}, err
	}
	rightDirect, err := n2dChainPackets(topology.clientB, "WYN2D_DIRECT")
	if err != nil {
		return n2dPacketCounts{}, err
	}
	rightTotal, err := n2dChainPackets(topology.clientB, "WYN2D_TOTAL")
	if err != nil {
		return n2dPacketCounts{}, err
	}
	return n2dPacketCounts{
		InitiatorSTUN: leftSTUN, InitiatorDirect: leftDirect, InitiatorTotal: leftTotal,
		ResponderSTUN: rightSTUN, ResponderDirect: rightDirect, ResponderTotal: rightTotal,
	}, nil
}

func n2dChainPackets(namespace, chain string) (uint64, error) {
	output, err := runNamespaced(namespace, "iptables", nil, "-w", "5", "-L", chain, "-v", "-n", "-x")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[2] != "RETURN" {
			continue
		}
		return strconv.ParseUint(fields[0], 10, 64)
	}
	return 0, errors.New("counter missing")
}

func (topology *n2dTopology) socketCount() (int, error) {
	total := 0
	for _, namespace := range topology.namespaces() {
		output, err := runNamespaced(namespace, "ss", nil, "-H", "-a", "-n", "-t", "-u")
		if err != nil {
			return 0, err
		}
		for _, line := range strings.Split(output, "\n") {
			if strings.TrimSpace(line) != "" {
				total++
			}
		}
	}
	return total, nil
}

func (topology *n2dTopology) processCount() (int, error) {
	total := 0
	for _, namespace := range topology.namespaces() {
		output, err := runCommand("ip", "netns", "pids", namespace)
		if err != nil {
			return 0, err
		}
		for _, field := range strings.Fields(output) {
			if _, err := strconv.Atoi(field); err != nil {
				return 0, err
			}
			total++
		}
	}
	return total, nil
}

func (topology *n2dTopology) flushConntrack() (before, after int, resultErr error) {
	for _, namespace := range topology.namespaces() {
		output, err := runNamespaced(namespace, "conntrack", nil, "-C")
		if err != nil {
			return 0, 0, err
		}
		count, err := strconv.Atoi(strings.TrimSpace(output))
		if err != nil {
			return 0, 0, err
		}
		before += count
		if _, err := runNamespaced(namespace, "conntrack", nil, "-F"); err != nil {
			return 0, 0, err
		}
		output, err = runNamespaced(namespace, "conntrack", nil, "-C")
		if err != nil {
			return 0, 0, err
		}
		count, err = strconv.Atoi(strings.TrimSpace(output))
		if err != nil {
			return 0, 0, err
		}
		after += count
	}
	return before, after, nil
}

func (topology *n2dTopology) cleanup() error {
	if topology == nil {
		return nil
	}
	topology.cleanOnce.Do(func() {
		for index := len(topology.namespaces()) - 1; index >= 0; index-- {
			namespace := topology.namespaces()[index]
			exists, err := namespaceExists(namespace)
			if err != nil {
				topology.cleanErr = errors.Join(topology.cleanErr, err)
				continue
			}
			if exists {
				_, err = runCommand("ip", "netns", "del", namespace)
				topology.cleanErr = errors.Join(topology.cleanErr, err)
			}
		}
		for _, link := range topology.links {
			for _, name := range []string{link.hostLeft, link.hostRight} {
				exists, err := hostLinkExists(name)
				if err != nil {
					topology.cleanErr = errors.Join(topology.cleanErr, err)
					continue
				}
				if exists {
					_, err = runCommand("ip", "link", "del", name)
					topology.cleanErr = errors.Join(topology.cleanErr, err)
				}
			}
		}
	})
	return topology.cleanErr
}

func (topology *n2dTopology) assertNoLeaks() error {
	for _, namespace := range topology.namespaces() {
		exists, err := namespaceExists(namespace)
		if err != nil || exists {
			return errors.Join(errors.New("namespace residue"), err)
		}
	}
	for _, link := range topology.links {
		for _, name := range []string{link.hostLeft, link.hostRight} {
			exists, err := hostLinkExists(name)
			if err != nil || exists {
				return errors.Join(errors.New("veth residue"), err)
			}
		}
	}
	return nil
}

type n2dServers struct {
	stun               *stunserver.Server
	stunCancel         context.CancelFunc
	stunDone           chan error
	rendezvous         *rendezvouscarrier.N2DTestServer
	rendezvousEndpoint string
	closeOnce          sync.Once
	closeErr           error
}

func startN2DServers(t interface {
	Helper()
	Fatal(args ...any)
	Cleanup(func())
}, topology *n2dTopology) *n2dServers {
	t.Helper()
	servers := &n2dServers{stunDone: make(chan error, 1)}
	err := RunInNamespace(topology.public, func() error {
		stun, err := stunserver.Open(stunserver.Config{
			ListenAddr: netip.AddrPortFrom(netip.MustParseAddr(n2dPublicA), 0), MaxPPS: 20,
		})
		if err != nil {
			return err
		}
		listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP(n2dPublicA), Port: 0})
		if err != nil {
			_ = stun.Close()
			return err
		}
		rendezvous, err := rendezvouscarrier.StartN2DTestServer(listener)
		if err != nil {
			_ = listener.Close()
			_ = stun.Close()
			return err
		}
		servers.stun = stun
		servers.rendezvous = rendezvous
		servers.rendezvousEndpoint = listener.Addr().String()
		return nil
	})
	if err != nil {
		t.Fatal("N2d isolated servers failed to start")
	}
	stunContext, cancel := context.WithCancel(context.Background())
	servers.stunCancel = cancel
	go func() { servers.stunDone <- servers.stun.Serve(stunContext) }()
	if err := topology.installPacketCounters(servers.stun.ListenAddr().Port()); err != nil {
		_ = servers.Close()
		t.Fatal("N2d packet counter setup failed")
	}
	t.Cleanup(func() { _ = servers.Close() })
	return servers
}

func (servers *n2dServers) Close() error {
	if servers == nil {
		return nil
	}
	servers.closeOnce.Do(func() {
		if servers.stunCancel != nil {
			servers.stunCancel()
		}
		if servers.stun != nil {
			servers.closeErr = errors.Join(servers.closeErr, servers.stun.Close())
		}
		if servers.stunDone != nil {
			select {
			case err := <-servers.stunDone:
				servers.closeErr = errors.Join(servers.closeErr, err)
			case <-time.After(n2dTerminalMargin):
				servers.closeErr = errors.Join(servers.closeErr, errors.New("STUN server drain timeout"))
			}
		}
		if servers.rendezvous != nil {
			servers.closeErr = errors.Join(servers.closeErr, servers.rendezvous.Close())
		}
	})
	return servers.closeErr
}

func (servers *n2dServers) stunEndpoint() string {
	if servers == nil || servers.stun == nil {
		return ""
	}
	return servers.stun.ListenAddr().String()
}
