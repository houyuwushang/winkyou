package selfhosted

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	protocolVersion = 1
	helloKind       = 1
	helloAckKind    = 2
	helloNonceSize  = 16
	helloMACSize    = 16
	maxHelloNodeID  = 1024
	helloHeaderSize = 4 + 1 + 1 + 8 + helloNonceSize + helloNonceSize + 2
)

var helloMagic = [4]byte{'W', 'K', 'S', 'B'}

type helloFrame struct {
	Kind    byte
	Session [8]byte
	Nonce   [helloNonceSize]byte
	Echo    [helloNonceSize]byte
	NodeID  string
}

func pairKey(localID, peerID string, sharedSecret []byte) ([32]byte, error) {
	localID = strings.TrimSpace(localID)
	peerID = strings.TrimSpace(peerID)
	if localID == "" || peerID == "" || localID == peerID {
		return [32]byte{}, fmt.Errorf("selfbootstrap: pair requires distinct non-empty node IDs")
	}
	left, right := localID, peerID
	if right < left {
		left, right = right, left
	}
	mac := hmac.New(sha256.New, sharedSecret)
	_, _ = mac.Write([]byte("wink-selfbootstrap-pair-v1\x00"))
	_, _ = mac.Write([]byte(left))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(right))
	var result [32]byte
	copy(result[:], mac.Sum(nil))
	return result, nil
}

func pairSession(key [32]byte) [8]byte {
	// This stable value lets independently restarted peers recognize punch
	// traffic without signaling. It is only a pair discriminator: freshness and
	// peer proof come from the random HELLO nonce and its authenticated echo.
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("wink-selfbootstrap-punch-v1"))
	var session [8]byte
	copy(session[:], mac.Sum(nil))
	return session
}

func encodeHello(key [32]byte, frame helloFrame) ([]byte, error) {
	frame.NodeID = strings.TrimSpace(frame.NodeID)
	if frame.Kind != helloKind && frame.Kind != helloAckKind {
		return nil, fmt.Errorf("selfbootstrap: unsupported hello kind %d", frame.Kind)
	}
	if frame.NodeID == "" || len(frame.NodeID) > maxHelloNodeID {
		return nil, fmt.Errorf("selfbootstrap: hello node ID length %d is invalid", len(frame.NodeID))
	}
	raw := make([]byte, helloHeaderSize+len(frame.NodeID)+helloMACSize)
	copy(raw[0:4], helloMagic[:])
	raw[4] = protocolVersion
	raw[5] = frame.Kind
	copy(raw[6:14], frame.Session[:])
	copy(raw[14:14+helloNonceSize], frame.Nonce[:])
	copy(raw[14+helloNonceSize:14+2*helloNonceSize], frame.Echo[:])
	binary.BigEndian.PutUint16(raw[14+2*helloNonceSize:helloHeaderSize], uint16(len(frame.NodeID)))
	copy(raw[helloHeaderSize:], frame.NodeID)
	tag := helloTag(key, raw[:len(raw)-helloMACSize])
	copy(raw[len(raw)-helloMACSize:], tag[:])
	return raw, nil
}

func decodeHello(key [32]byte, raw []byte) (helloFrame, error) {
	if len(raw) < helloHeaderSize+1+helloMACSize {
		return helloFrame{}, fmt.Errorf("selfbootstrap: hello frame is too short")
	}
	if string(raw[:4]) != string(helloMagic[:]) || raw[4] != protocolVersion {
		return helloFrame{}, fmt.Errorf("selfbootstrap: invalid hello header")
	}
	nodeLength := int(binary.BigEndian.Uint16(raw[14+2*helloNonceSize : helloHeaderSize]))
	if nodeLength < 1 || nodeLength > maxHelloNodeID || helloHeaderSize+nodeLength+helloMACSize != len(raw) {
		return helloFrame{}, fmt.Errorf("selfbootstrap: invalid hello node ID length %d", nodeLength)
	}
	expected := helloTag(key, raw[:len(raw)-helloMACSize])
	if subtle.ConstantTimeCompare(expected[:], raw[len(raw)-helloMACSize:]) != 1 {
		return helloFrame{}, fmt.Errorf("selfbootstrap: hello authentication failed")
	}
	frame := helloFrame{Kind: raw[5], NodeID: string(raw[helloHeaderSize : helloHeaderSize+nodeLength])}
	if frame.Kind != helloKind && frame.Kind != helloAckKind {
		return helloFrame{}, fmt.Errorf("selfbootstrap: unsupported hello kind %d", frame.Kind)
	}
	copy(frame.Session[:], raw[6:14])
	copy(frame.Nonce[:], raw[14:14+helloNonceSize])
	copy(frame.Echo[:], raw[14+helloNonceSize:14+2*helloNonceSize])
	if strings.TrimSpace(frame.NodeID) != frame.NodeID || frame.NodeID == "" {
		return helloFrame{}, fmt.Errorf("selfbootstrap: invalid hello node ID")
	}
	return frame, nil
}

func helloTag(key [32]byte, raw []byte) [helloMACSize]byte {
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write(raw)
	var result [helloMACSize]byte
	copy(result[:], mac.Sum(nil))
	return result
}

type helloConfig struct {
	Interval time.Duration
	Settle   time.Duration
	Rand     io.Reader
}

// authenticatePeer verifies that the socket reached the configured peer before
// its ownership moves to PacketNeighborSession. Success requires an
// authenticated ACK that echoes this invocation's fresh local nonce; a
// captured HELLO alone is deliberately insufficient. Punch packets left in the
// UDP receive queue and unrelated datagrams are ignored. Without a shared
// secret, the MAC binds node IDs but does not defend against an active attacker.
func authenticatePeer(
	ctx context.Context,
	conn net.Conn,
	localID, peerID string,
	key [32]byte,
	session [8]byte,
	config helloConfig,
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if conn == nil {
		return fmt.Errorf("selfbootstrap: hello connection is required")
	}
	defer func() { _ = conn.SetDeadline(time.Time{}) }()
	if config.Interval <= 0 {
		config.Interval = 200 * time.Millisecond
	}
	if config.Settle <= 0 {
		config.Settle = time.Second
	}
	if config.Rand == nil {
		config.Rand = rand.Reader
	}
	var localNonce [helloNonceSize]byte
	if _, err := io.ReadFull(config.Rand, localNonce[:]); err != nil {
		return fmt.Errorf("selfbootstrap: generate hello nonce: %w", err)
	}

	var peerNonce [helloNonceSize]byte
	havePeerNonce := false
	authenticated := false
	settleUntil := time.Time{}
	nextSend := time.Time{}
	buffer := make([]byte, helloHeaderSize+maxHelloNodeID+helloMACSize)
	for {
		now := time.Now()
		if err := ctx.Err(); err != nil {
			return err
		}
		if authenticated && !settleUntil.IsZero() && !now.Before(settleUntil) {
			return nil
		}
		if nextSend.IsZero() || !now.Before(nextSend) {
			hello, err := encodeHello(key, helloFrame{
				Kind: helloKind, Session: session, Nonce: localNonce, NodeID: localID,
			})
			if err != nil {
				return err
			}
			if err := writeHello(ctx, conn, hello, config.Interval); err != nil {
				return err
			}
			if havePeerNonce {
				ack, err := encodeHello(key, helloFrame{
					Kind: helloAckKind, Session: session, Nonce: localNonce,
					Echo: peerNonce, NodeID: localID,
				})
				if err != nil {
					return err
				}
				if err := writeHello(ctx, conn, ack, config.Interval); err != nil {
					return err
				}
			}
			nextSend = now.Add(config.Interval)
		}

		readUntil := nextSend
		if authenticated && settleUntil.Before(readUntil) {
			readUntil = settleUntil
		}
		if deadline, ok := ctx.Deadline(); ok && deadline.Before(readUntil) {
			readUntil = deadline
		}
		_ = conn.SetReadDeadline(readUntil)
		n, err := conn.Read(buffer)
		if err != nil {
			var networkError net.Error
			if errors.As(err, &networkError) && networkError.Timeout() {
				continue
			}
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			return fmt.Errorf("selfbootstrap: read peer hello: %w", err)
		}
		frame, err := decodeHello(key, buffer[:n])
		if err != nil || frame.Session != session || frame.NodeID != peerID {
			continue
		}
		switch frame.Kind {
		case helloKind:
			peerNonce = frame.Nonce
			havePeerNonce = true
			nextSend = time.Time{}
		case helloAckKind:
			if frame.Echo == localNonce {
				peerNonce = frame.Nonce
				havePeerNonce = true
				if !authenticated {
					authenticated = true
					settleUntil = time.Now().Add(config.Settle)
				}
				nextSend = time.Time{}
			}
		}
	}
}

func writeHello(ctx context.Context, conn net.Conn, raw []byte, interval time.Duration) error {
	deadline := time.Now().Add(interval)
	if parentDeadline, ok := ctx.Deadline(); ok && parentDeadline.Before(deadline) {
		deadline = parentDeadline
	}
	_ = conn.SetWriteDeadline(deadline)
	written, err := conn.Write(raw)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("selfbootstrap: write peer hello: %w", err)
	}
	if written != len(raw) {
		return fmt.Errorf("selfbootstrap: short peer hello write: wrote %d of %d bytes", written, len(raw))
	}
	return nil
}
