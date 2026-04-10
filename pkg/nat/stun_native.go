package nat

// stun_native.go — pure-Go STUN Binding client using the standard library.

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// stunDefaultTimeout is the per-request timeout when the caller's context
// has no deadline.
const stunDefaultTimeout = 3 * time.Second

// stunMaxPacket is the maximum STUN response size we'll read.
const stunMaxPacket = 1024

// stunResult holds the outcome of a single STUN Binding transaction.
type stunResult struct {
	// LocalAddr is the local address the UDP socket was bound to.
	LocalAddr *net.UDPAddr
	// MappedAddr is the reflexive address reported by the server.
	MappedAddr *net.UDPAddr
	// ServerAddr is the resolved address of the STUN server.
	ServerAddr *net.UDPAddr
}

// stunBind sends a STUN Binding Request to serverAddr and returns the
// mapped address from the response. It respects ctx for cancellation and
// deadline.
//
// serverAddr can be in "stun:host:port" or "host:port" format.
func stunBind(ctx context.Context, serverAddr string) (*stunResult, error) {
	host, port, err := parseSTUNAddr(serverAddr)
	if err != nil {
		return nil, err
	}
	addrStr := net.JoinHostPort(host, port)

	// Resolve the server address.
	raddr, err := net.ResolveUDPAddr("udp4", addrStr)
	if err != nil {
		return nil, fmt.Errorf("stun: resolve %q: %w", addrStr, err)
	}

	// Open a UDP socket bound to any local address.
	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return nil, fmt.Errorf("stun: listen: %w", err)
	}
	defer conn.Close()

	return stunBindConn(ctx, conn, raddr)
}

// stunBindConn performs a STUN Binding transaction over an existing
// PacketConn. This is useful for tests and for reusing a socket across
// multiple STUN servers (needed for NAT type detection).
func stunBindConn(ctx context.Context, conn net.PacketConn, raddr *net.UDPAddr) (*stunResult, error) {
	txID, err := newTransactionID()
	if err != nil {
		return nil, fmt.Errorf("stun: txid: %w", err)
	}

	req := buildBindingRequest(txID)

	// Set deadline from context, or use default.
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(stunDefaultTimeout)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("stun: set deadline: %w", err)
	}

	// Send request.
	if _, err := conn.WriteTo(req, raddr); err != nil {
		return nil, fmt.Errorf("stun: send to %s: %w", raddr, err)
	}

	// Read response — loop to skip stray packets.
	buf := make([]byte, stunMaxPacket)
	for {
		// Check context cancellation.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		n, _, readErr := conn.ReadFrom(buf)
		if readErr != nil {
			return nil, fmt.Errorf("stun: read: %w", readErr)
		}

		msg, parseErr := parseSTUNMessage(buf[:n])
		if parseErr != nil {
			continue // not a valid STUN message, skip
		}

		// Verify transaction ID matches.
		if msg.transactionID != txID {
			continue
		}

		if msg.msgType == stunMsgTypeBindingError {
			return nil, fmt.Errorf("stun: server returned error response")
		}
		if msg.msgType != stunMsgTypeBindingResp {
			continue
		}

		mapped, err := msg.extractMappedAddr()
		if err != nil {
			return nil, err
		}

		localAddr, _ := conn.LocalAddr().(*net.UDPAddr)

		return &stunResult{
			LocalAddr:  localAddr,
			MappedAddr: mapped,
			ServerAddr: raddr,
		}, nil
	}
}

// parseSTUNAddr normalises a STUN server address string.
// Accepted formats: "stun:host:port", "host:port", "stun:host" (default port 3478).
func parseSTUNAddr(s string) (host, port string, err error) {
	s = strings.TrimPrefix(s, "stun:")
	h, p, splitErr := net.SplitHostPort(s)
	if splitErr != nil {
		// No port — use default STUN port.
		return s, "3478", nil
	}
	return h, p, nil
}
