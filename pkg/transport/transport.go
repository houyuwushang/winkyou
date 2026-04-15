package transport

import (
	"context"
	"net"
	"time"
)

type PacketMeta struct {
	ReceivedAt time.Time
	PathID     string
}

type PacketTransport interface {
	ReadPacket(ctx context.Context, dst []byte) (n int, meta PacketMeta, err error)
	WritePacket(ctx context.Context, pkt []byte) error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	Close() error
}
