package netif

import "net"

// noopInterface is a stub NetworkInterface that returns ErrNotImplemented
// for all operational methods. It is used during skeleton development and
// as the fallback when no real backend is available yet.
type noopInterface struct {
	name    string
	ifType  string
	mtu     int
}

func newNoopInterface(cfg Config) *noopInterface {
	t := cfg.Backend
	if t == "" || t == "auto" {
		t = "noop"
	}
	return &noopInterface{
		name:   "wink0",
		ifType: t,
		mtu:    cfg.MTU,
	}
}

func (n *noopInterface) Name() string  { return n.name }
func (n *noopInterface) Type() string  { return n.ifType }
func (n *noopInterface) MTU() int      { return n.mtu }

func (n *noopInterface) Read(buf []byte) (int, error)  { return 0, ErrNotImplemented }
func (n *noopInterface) Write(buf []byte) (int, error) { return 0, ErrNotImplemented }
func (n *noopInterface) Close() error                  { return nil }

func (n *noopInterface) SetIP(ip net.IP, mask net.IPMask) error       { return ErrNotImplemented }
func (n *noopInterface) AddRoute(dst *net.IPNet, gateway net.IP) error    { return ErrNotImplemented }
func (n *noopInterface) RemoveRoute(dst *net.IPNet) error                 { return ErrNotImplemented }
