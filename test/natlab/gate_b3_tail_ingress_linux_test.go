//go:build linux && natlab

package natlab

const gateB3TailIngressChain = "WYGATEB3_TAIL"

func (topology *n2dTopology) installGateB3TailIngressCounters() error {
	// Only the two disposable endpoint namespaces, never initial/host rules.
	// RETURN is counting-only: no accept/drop, queue, retry or NAT changes.
	for _, namespace := range []string{topology.clientA, topology.clientB} {
		for _, args := range [][]string{
			{"-w", "5", "-N", gateB3TailIngressChain},
			{"-w", "5", "-A", gateB3TailIngressChain, "-j", "RETURN"},
			{"-w", "5", "-A", "INPUT", "-i", n2dEndpointInterface, "-p", "udp", "-m", "u32", "--u32", gateB3TailIngressU32(), "-j", gateB3TailIngressChain},
		} {
			if _, err := runNamespaced(namespace, "iptables", nil, args...); err != nil {
				return err
			}
		}
	}
	return nil
}

type gateB3TailIngressCount struct {
	packets uint64
	valid   bool
}

func (topology *n2dTopology) gateB3TailIngressCounts() [2]gateB3TailIngressCount {
	var out [2]gateB3TailIngressCount
	for side, namespace := range []string{topology.clientA, topology.clientB} {
		count, err := n2dChainPackets(namespace, gateB3TailIngressChain)
		out[side] = gateB3TailIngressCount{packets: count, valid: err == nil}
	}
	return out
}
