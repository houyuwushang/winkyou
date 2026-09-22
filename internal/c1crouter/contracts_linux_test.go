//go:build linux && fieldc1c

package c1crouter

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"winkyou/internal/v2/fieldc1c"
	"winkyou/internal/v2/hardnatplan"
)

func TestRouterInheritedBlockingPipeHasBoundedAdoption(t *testing.T) {
	for _, valid := range []bool{true, false} {
		fds := make([]int, 2)
		if unix.Pipe2(fds, unix.O_CLOEXEC) != nil {
			t.Fatal("pipe fixture unavailable")
		}
		digest := strings.Repeat("a", 64)
		token := digest
		if !valid {
			token = token[:32]
		}
		_, writeErr := unix.Write(fds[1], []byte(token))
		_ = unix.Close(fds[1])
		if writeErr != nil {
			_ = unix.Close(fds[0])
			t.Fatal("pipe fixture write failed")
		}
		err := readAdoptionToken(fds[0], digest)
		if (err == nil) != valid {
			t.Fatal("inherited pipe was unpollable or partial adoption accepted")
		}
	}
}

func TestRouterUnknownResidueCannotPass(t *testing.T) {
	base := Counts{SocketResidue: zero(), ProcessResidue: zero(), ConntrackResidue: zero(), NamespaceResidue: zero(), VethResidue: zero(), NFTResidue: zero()}
	if !residueZero(base) {
		t.Fatal("zero witnesses rejected")
	}
	for i := 0; i < 6; i++ {
		mutant := base
		fields := []**uint64{&mutant.SocketResidue, &mutant.ProcessResidue, &mutant.ConntrackResidue, &mutant.NamespaceResidue, &mutant.VethResidue, &mutant.NFTResidue}
		*fields[i] = nil
		if residueZero(mutant) {
			t.Fatal("omitted resource witness passed")
		}
		n := uint64(1)
		*fields[i] = &n
		if residueZero(mutant) {
			t.Fatal("residual resource passed")
		}
	}
}

func TestRouterCeilingFalseNeedsNoJournalOrHostWrite(t *testing.T) {
	g, e := acquireCeiling(fieldc1c.RouterSnapshot{}, nil)
	if e != nil || g == nil || g.lock != nil || g.restore() != nil {
		t.Fatal("false authority touched a host resource")
	}
	// True alone grants nothing, including an expired/unbound snapshot.
	_, e = acquireCeiling(fieldc1c.RouterSnapshot{Configuration: fieldc1c.RouterConfiguration{AllowGlobalConntrackCeiling: true}}, nil)
	if !errors.Is(e, ErrInvalid) {
		t.Fatal("true unbound authority accepted")
	}
}

func TestRouterHardPortsHavePerRemoteCompleteUniverse(t *testing.T) {
	r := &natRouter{cfg: fieldc1c.RouterDomain{Mode: "apdm_uniform16/1"}, perTarget: map[netip.AddrPort]uint32{}}
	observer, peer := netip.MustParseAddrPort("198.51.100.2:3478"), netip.MustParseAddrPort("203.0.113.2:50000")
	for i := 0; i < 13; i++ {
		p, e := r.reservePort(observer)
		if e != nil || p < 49152 {
			t.Fatal("hard evidence not in random universe")
		}
	}
	seen := map[uint16]bool{}
	for i := 0; i < 16384; i++ {
		p, e := r.reservePort(peer)
		if e != nil || p < 49152 || seen[p] {
			t.Fatal("hard permutation duplicate or evidence reduced direct space")
		}
		seen[p] = true
	}
	if _, e := r.reservePort(peer); !errors.Is(e, ErrResource) {
		t.Fatal("per-remote universe overflow allowed")
	}
	if r.perTarget[observer] != 13 {
		t.Fatal("observer counter changed")
	}
}

func TestRouterCloseBeforeStartClosesFutureOpens(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	r := &natRouter{ctx: ctx, cancel: cancel, done: make(chan error, 1), budget: new(atomic.Uint64)}
	if r.close() != nil || !r.closed || ctx.Err() == nil {
		t.Fatal("unstarted router did not revoke")
	}
	if r.close() != nil {
		t.Fatal("unstarted terminal not idempotent")
	}
}

func TestRouterRFC5780ResponseUsesExistingCodec(t *testing.T) {
	var tx hardnatplan.TransactionID
	tx[0] = 1
	for _, origin := range []netip.AddrPort{netip.MustParseAddrPort("198.51.100.2:3478"), netip.MustParseAddrPort("203.0.113.1:3479")} {
		mapped := netip.MustParseAddrPort("192.0.2.2:40000")
		other := netip.MustParseAddrPort("203.0.113.1:3479")
		if origin == other {
			other = netip.MustParseAddrPort("198.51.100.2:3478")
		}
		v := hardnatplan.BehaviorAttributes{Mapped: planAddress(mapped), HasMapped: true, ResponseOrigin: planAddress(origin), HasResponseOrigin: true, OtherAddress: planAddress(other), HasOtherAddress: true}
		b, e := hardnatplan.BuildBehaviorBindingSuccess(tx, v)
		if e != nil {
			t.Fatal(e)
		}
		got, e := hardnatplan.ParseBehaviorBindingSuccess(b, tx)
		if e != nil || got != v {
			t.Fatal("observer wire mismatch")
		}
	}
}

func TestRouterNFTIsOwnedAndUDPHasNoKernelRewrite(t *testing.T) {
	s := fieldc1c.RouterSnapshot{SSHEndpoint: netip.MustParseAddrPort("203.0.113.2:22"), Observers: [4]netip.AddrPort{netip.MustParseAddrPort("198.51.100.2:3478"), netip.MustParseAddrPort("198.51.100.2:3479"), netip.MustParseAddrPort("203.0.113.1:3478"), netip.MustParseAddrPort("203.0.113.1:3479")}, Configuration: fieldc1c.RouterConfiguration{Domains: []fieldc1c.RouterDomain{{EndpointPrefix: "192.0.2.2/30", PublicPrefix: "198.51.100.1/29"}, {EndpointPrefix: "192.0.2.6/30", PublicPrefix: "203.0.113.2/29"}}}}
	for side := 0; side < 2; side++ {
		rules := nftRules(s, side)
		if !strings.HasPrefix(rules, "create table ip wycrouter\n") || strings.Contains(rules, "flush ruleset") {
			t.Fatal("nft ownership weakened")
		}
		for _, line := range strings.Split(rules, "\n") {
			if strings.Contains(line, "nat to") && !strings.Contains(line, "tcp") {
				t.Fatal("UDP mapping escaped TUN allocator")
			}
		}
	}
	if DrainTimeout != 2*time.Second || QueryTimeout != time.Second || MaxConsecutiveQueryErrors != 8 {
		t.Fatal("frozen sampling or drain changed")
	}
}
