package gatecorchestrator

import (
	"context"
	"errors"
	"net"

	"winkyou/pkg/session"
)

type fixedPeerProvider struct {
	peerID string
	peer   *session.BindingPeer
}

func (provider fixedPeerProvider) BindingPeer(ctx context.Context, peerID string) (*session.BindingPeer, error) {
	if ctx == nil || ctx.Err() != nil || provider.peer == nil || peerID == "" || peerID != provider.peerID {
		return nil, errors.New("gatecorchestrator: trusted peer binding is unavailable")
	}
	copyValue := *provider.peer
	copyValue.AllowedIPs = append([]net.IPNet(nil), provider.peer.AllowedIPs...)
	return &copyValue, nil
}

var _ session.BindingPeerProvider = fixedPeerProvider{}
