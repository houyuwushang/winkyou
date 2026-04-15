package client

import (
	"context"
	"fmt"

	coordclient "winkyou/pkg/coordinator/client"
	rproto "winkyou/pkg/rendezvous/proto"
)

type Channel struct {
	coord coordclient.CoordinatorClient
}

func NewChannel(coord coordclient.CoordinatorClient) *Channel {
	return &Channel{coord: coord}
}

func (c *Channel) SendEnvelope(ctx context.Context, to string, envelope rproto.SessionEnvelope) error {
	if c == nil || c.coord == nil {
		return fmt.Errorf("rendezvous: coordinator channel is nil")
	}
	payload, err := rproto.MarshalEnvelope(envelope)
	if err != nil {
		return err
	}
	return c.coord.SendSignal(ctx, to, coordclient.SIGNAL_UNSPECIFIED, payload)
}

func EnvelopeFromSignal(signal *coordclient.SignalNotification) (rproto.SessionEnvelope, bool, error) {
	if signal == nil || signal.Type != coordclient.SIGNAL_UNSPECIFIED || len(signal.Payload) == 0 {
		return rproto.SessionEnvelope{}, false, nil
	}
	envelope, err := rproto.UnmarshalEnvelope(signal.Payload)
	if err != nil {
		return rproto.SessionEnvelope{}, true, err
	}
	return envelope, true, nil
}
