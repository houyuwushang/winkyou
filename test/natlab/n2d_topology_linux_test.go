//go:build linux && natlab

package natlab

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
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
	// n2dMappingEIMRestricted keeps endpoint-independent, port-preserving
	// SNAT but omits the static DNAT, so netfilter conntrack imposes real
	// address+port-dependent reply filtering. This is the classic
	// port-restricted cone that the blind simultaneous-open design targets:
	// an inbound direct packet passes only after the local endpoint has sent
	// outbound to that exact peer mapping.
	n2dMappingEIMRestricted n2dMappingMode = "eim_restricted"
	n2dMappingEDM           n2dMappingMode = "edm"
)

var n2dTopologySequence atomic.Uint32

type n2dTopologySetupError struct {
	stage string
	cause error
}

func (setupErr *n2dTopologySetupError) Error() string { return setupErr.stage }
func (setupErr *n2dTopologySetupError) Unwrap() error { return setupErr.cause }

func n2dTopologySetupStage(err error) string {
	var setupErr *n2dTopologySetupError
	if errors.As(err, &setupErr) && setupErr.stage != "" {
		return setupErr.stage
	}
	return "unknown"
}

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
	// A process-local atomic suffix is collision-free across parallel and rapid
	// teardown/recreate tests. The previous low 24 wall-clock bits wrapped every
	// 16.8ms and occasionally reused a still-draining namespace name.
	suffix := fmt.Sprintf("%08x", sequence)
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
		t.Fatal("N2d isolated topology setup failed: " + n2dTopologySetupStage(err))
	}
	return topology
}

func (mode n2dMappingMode) valid() bool {
	return mode == n2dMappingEIM || mode == n2dMappingEIMRestricted || mode == n2dMappingEDM
}

func (topology *n2dTopology) namespaces() []string {
	return []string{topology.clientA, topology.natA, topology.public, topology.natB, topology.clientB}
}

func (topology *n2dTopology) create() (err error) {
	stage := "namespace_create"
	defer func() {
		if err != nil {
			err = &n2dTopologySetupError{stage: stage, cause: err}
		}
	}()
	for _, namespace := range topology.namespaces() {
		if _, err := runCommand("ip", "netns", "add", namespace); err != nil {
			return err
		}
		if _, err := runCommand("ip", "-n", namespace, "link", "set", "lo", "up"); err != nil {
			return err
		}
	}
	stage = "link_create"
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
	stage = "route_config"
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
	stage = "forwarding_filter"
	for _, namespace := range []string{topology.natA, topology.public, topology.natB} {
		if _, err := runNamespaced(namespace, "sysctl", nil, "-qw", "net.ipv4.ip_forward=1"); err != nil {
			return err
		}
		filter := "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n"
		if _, err := runNamespaced(namespace, "iptables-restore", strings.NewReader(filter)); err != nil {
			return err
		}
	}
	stage = "nat_config"
	if err := topology.applyNAT(topology.natA, topology.leftMode, n2dNATAWAN, n2dClientAAddress); err != nil {
		return err
	}
	if err := topology.applyNAT(topology.natB, topology.rightMode, n2dNATBWAN, n2dClientBAddress); err != nil {
		return err
	}
	// A consumer router's WAN firewall drops unsolicited UDP addressed to the
	// gateway itself instead of accepting it into the local stack. Without
	// this, an early peer opener that races ahead of the local pinhole is
	// "confirmed" into conntrack as a NAT-local flow, poisons the SNAT port
	// table, and evicts port preservation for the very mapping under test.
	// The DNAT-based EIM reference tier translates before INPUT and stays
	// unaffected; the restricted and EDM tiers rely on this default-deny.
	stage = "inbound_filter"
	for _, gateway := range []struct{ namespace, address string }{
		{topology.natA, n2dNATAWAN},
		{topology.natB, n2dNATBWAN},
	} {
		if _, err := runNamespaced(gateway.namespace, "iptables", nil,
			"-w", "5", "-A", "INPUT", "-i", "wan0", "-p", "udp", "-d", gateway.address, "-j", "DROP"); err != nil {
			return err
		}
	}
	// Model propagation delay on every WAN-chain link. In any real deployment
	// the FIRE control path crosses the rendezvous (>= milliseconds) while the
	// initiator's SYN egress follows its FIRE write within microseconds, so
	// the initiator's pinhole always exists before the responder's blind
	// SYN_ACK can arrive. A zero-latency namespace inverts that ordering and
	// the filtered SYN_ACK has no retransmission by frozen design. 5ms per
	// link restores the physical ordering deterministically without touching
	// protocol semantics.
	stage = "netem_config"
	for _, hop := range []struct{ namespace, device string }{
		{topology.natA, "wan0"},
		{topology.natB, "wan0"},
		{topology.public, "a0"},
		{topology.public, "b0"},
	} {
		if _, err := runNamespaced(hop.namespace, "tc", nil,
			"qdisc", "add", "dev", hop.device, "root", "netem", "delay", "5ms"); err != nil {
			return err
		}
	}
	return nil
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

func (topology *n2dTopology) applyNAT(namespace string, mode n2dMappingMode, publicAddress, privateAddress string) error {
	if !netip.MustParseAddr(publicAddress).Is4() || !netip.MustParseAddr(privateAddress).Is4() {
		return errors.New("N2d NAT address is not IPv4")
	}
	// The EIM reference case uses an explicit one-endpoint, port-preserving UDP
	// mapping in both directions. Plain SNAT is insufficient evidence because
	// conntrack would still impose destination-specific reply filtering. EDM
	// deliberately keeps that filtering and requests a fresh random source port
	// for each destination tuple.
	rules := []string{
		"-A PREROUTING -i wan0 -p udp -d " + publicAddress + " -j DNAT --to-destination " + privateAddress,
		"-A POSTROUTING -s " + privateAddress + "/32 -o wan0 -p udp -j SNAT --to-source " + publicAddress,
		"-A POSTROUTING -s " + privateAddress + "/32 -o wan0 -p tcp -j SNAT --to-source " + publicAddress,
	}
	if mode == n2dMappingEIMRestricted {
		rules = []string{
			"-A POSTROUTING -s " + privateAddress + "/32 -o wan0 -p udp -j SNAT --to-source " + publicAddress,
			"-A POSTROUTING -s " + privateAddress + "/32 -o wan0 -p tcp -j SNAT --to-source " + publicAddress,
		}
	}
	if mode == n2dMappingEDM {
		rules = []string{
			"-A POSTROUTING -s " + privateAddress + "/32 -o wan0 -p udp -j SNAT --to-source " + publicAddress + " --random-fully",
			"-A POSTROUTING -s " + privateAddress + "/32 -o wan0 -p tcp -j SNAT --to-source " + publicAddress,
		}
	}
	scriptLines := []string{
		"*nat", ":PREROUTING ACCEPT [0:0]", ":INPUT ACCEPT [0:0]", ":OUTPUT ACCEPT [0:0]",
		":POSTROUTING ACCEPT [0:0]",
	}
	scriptLines = append(scriptLines, rules...)
	scriptLines = append(scriptLines, "COMMIT", "")
	script := strings.Join(scriptLines, "\n")
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
		output, err := runNamespaced(namespace, "ss", nil, "-H", "-a", "-n", "-t", "-u", "-p")
		if err != nil {
			return 0, err
		}
		for _, line := range strings.Split(output, "\n") {
			// ss may retain TCP TIME-WAIT or other kernel protocol state after
			// every owning process has closed its descriptor. Count only sockets
			// still owned by a process; conntrack is witnessed separately below.
			if strings.Contains(line, "users:((") {
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
	rendezvousSPKIPin  string
	closeOnce          sync.Once
	closeErr           error
}

func startN2DServers(t interface {
	Helper()
	Fatal(args ...any)
	Cleanup(func())
}, topology *n2dTopology) *n2dServers {
	return startN2DServersMode(t, topology, false)
}

func startN3BServers(t interface {
	Helper()
	Fatal(args ...any)
	Cleanup(func())
}, topology *n2dTopology) *n2dServers {
	return startN2DServersMode(t, topology, true)
}

func startN2DServersMode(t interface {
	Helper()
	Fatal(args ...any)
	Cleanup(func())
}, topology *n2dTopology, secure bool) *n2dServers {
	t.Helper()
	servers := &n2dServers{stunDone: make(chan error, 1)}
	var tlsConfig *tls.Config
	if secure {
		certificate, pin, err := n3bTestCertificate()
		if err != nil {
			t.Fatal("N3b isolated TLS fixture setup failed")
		}
		servers.rendezvousSPKIPin = pin
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		}
	}
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
		var rendezvousListener net.Listener = listener
		if tlsConfig != nil {
			rendezvousListener = tls.NewListener(listener, tlsConfig.Clone())
		}
		rendezvous, err := rendezvouscarrier.StartN2DTestServer(rendezvousListener)
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

func n3bTestCertificate() (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(320), Subject: pkix.Name{CommonName: "natlab-only"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP(n2dPublicA)},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		clear(der)
		return tls.Certificate{}, "", err
	}
	digest := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	pin := base64.RawURLEncoding.EncodeToString(digest[:])
	clear(digest[:])
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pin, nil
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
