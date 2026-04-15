package client

import (
	"context"
	"testing"
	"time"

	coordclient "winkyou/pkg/coordinator/client"
	rproto "winkyou/pkg/rendezvous/proto"
)

type fakeCoordinatorClient struct {
	to      string
	typ     coordclient.SignalType
	payload []byte
}

func (f *fakeCoordinatorClient) Connect(context.Context) error { return nil }
func (f *fakeCoordinatorClient) Close() error                  { return nil }
func (f *fakeCoordinatorClient) Register(context.Context, *coordclient.RegisterRequest) (*coordclient.RegisterResponse, error) {
	return nil, nil
}
func (f *fakeCoordinatorClient) StartHeartbeat(context.Context, time.Duration) error { return nil }
func (f *fakeCoordinatorClient) StopHeartbeat()                                      {}
func (f *fakeCoordinatorClient) ListPeers(context.Context, ...coordclient.ListOption) ([]*coordclient.PeerInfo, error) {
	return nil, nil
}
func (f *fakeCoordinatorClient) GetPeer(context.Context, string) (*coordclient.PeerInfo, error) {
	return nil, nil
}
func (f *fakeCoordinatorClient) SendSignal(ctx context.Context, to string, signalType coordclient.SignalType, payload []byte) error {
	f.to = to
	f.typ = signalType
	f.payload = append([]byte(nil), payload...)
	return nil
}
func (f *fakeCoordinatorClient) OnSignal(func(*coordclient.SignalNotification)) {}
func (f *fakeCoordinatorClient) OnPeerUpdate(func(*coordclient.PeerInfo, coordclient.PeerEvent)) {
}

func TestChannelSendEnvelopeAndDecode(t *testing.T) {
	coord := &fakeCoordinatorClient{}
	channel := NewChannel(coord)

	envelope := rproto.SessionEnvelope{
		SessionID: "session/node-a/node-b",
		FromNode:  "node-a",
		ToNode:    "node-b",
		MsgType:   rproto.MsgTypeCapability,
		Seq:       1,
		Payload:   rproto.MustPayload(rproto.Capability{Strategies: []string{"legacy_ice_udp"}}),
	}

	if err := channel.SendEnvelope(context.Background(), "node-b", envelope); err != nil {
		t.Fatalf("SendEnvelope() error = %v", err)
	}
	if coord.to != "node-b" {
		t.Fatalf("SendEnvelope() to = %q, want node-b", coord.to)
	}
	if coord.typ != coordclient.SIGNAL_UNSPECIFIED {
		t.Fatalf("SendEnvelope() type = %v, want SIGNAL_UNSPECIFIED", coord.typ)
	}

	decoded, ok, err := EnvelopeFromSignal(&coordclient.SignalNotification{
		FromNode: "node-a",
		ToNode:   "node-b",
		Type:     coordclient.SIGNAL_UNSPECIFIED,
		Payload:  coord.payload,
	})
	if err != nil {
		t.Fatalf("EnvelopeFromSignal() error = %v", err)
	}
	if !ok {
		t.Fatal("EnvelopeFromSignal() ok = false, want true")
	}
	if decoded.SessionID != envelope.SessionID || decoded.MsgType != envelope.MsgType {
		t.Fatalf("decoded envelope = %+v, want session_id=%q msg_type=%q", decoded, envelope.SessionID, envelope.MsgType)
	}
}
