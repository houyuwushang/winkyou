//go:build c1bproof

package governor_test

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"winkyou/internal/probeio"
)

type livenessAutomaticDatagram struct {
	probeio.Datagram // the counter unit test never opens or reads a transport
	short            bool
	err              error
}

func (d livenessAutomaticDatagram) WriteTo(_ context.Context, packet []byte, _ netip.AddrPort) (int, error) {
	n := len(packet)
	if d.short {
		n--
	}
	return n, d.err
}

func TestSessionLivenessAutomaticWitnessCountsOnlyCompletedPostFaultDatagrams(t *testing.T) {
	for _, tc := range []struct {
		name          string
		mode          int
		post, short   bool
		err           error
		kind          uint32
		size          int
		handshake, ka uint64
	}{
		{"initiation", 3, true, false, nil, 1, 148, 1, 0},
		{"response", 3, true, false, nil, 2, 92, 1, 0},
		{"empty", 3, true, false, nil, 4, 32, 0, 1},
		{"pre-fault", 3, false, false, nil, 1, 148, 0, 0},
		{"failed", 3, true, false, errors.New("synthetic write failed"), 1, 148, 0, 0},
		{"short", 3, true, true, nil, 4, 32, 0, 0},
		{"other-case", 1, true, false, nil, 1, 148, 0, 0},
		{"wrong-length", 3, true, false, nil, 1, 32, 0, 0},
		{"business", 3, true, false, nil, 4, 80, 0, 0},
		{"liveness", 3, true, false, nil, 4, 128, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &gateC1bLivenessCase{trafficSide: tc.mode}
			if tc.post {
				p.faultAt.Store(1)
			}
			packet := make([]byte, tc.size)
			binary.LittleEndian.PutUint32(packet, tc.kind)
			d := livenessLossDatagram{Datagram: livenessAutomaticDatagram{short: tc.short, err: tc.err}, proof: p, side: 1}
			_, _ = d.WriteTo(context.Background(), packet, netip.AddrPort{})
			if p.controlPackets[1].Load() != tc.handshake || p.emptyPackets[1].Load() != tc.ka || p.controlPackets[0].Load()+p.emptyPackets[0].Load() != 0 {
				t.Fatal("nonproof emission witness confused admission, direction, phase or subtype")
			}
		})
	}
}
