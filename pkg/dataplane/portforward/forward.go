// Package portforward carries reliable TCP streams over an already punched UDP
// socket. It is deliberately independent of WireGuard, Wintun, and any virtual
// network interface.
package portforward

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	quic "github.com/quic-go/quic-go"
)

const (
	minimumSecretBytes = 32
	requestOpen        = byte(1)
	statusOK           = byte(0)
	statusDialFailed   = byte(1)
	maxStatusMessage   = 1024
)

type LogFunc func(format string, args ...any)

// ServerConfig exposes one fixed TCP target through a punched UDP socket. The
// packet connection is owned by RunServer and is closed when it returns.
type ServerConfig struct {
	PacketConn  *net.UDPConn
	PeerAddr    *net.UDPAddr
	Secret      []byte
	Target      string
	DialTimeout time.Duration
	OnReady     func(local, remote net.Addr)
	Logf        LogFunc
}

// ClientConfig exposes a local TCP listener whose connections are forwarded to
// the server's fixed target. The packet connection is owned by RunClient.
type ClientConfig struct {
	PacketConn *net.UDPConn
	PeerAddr   *net.UDPAddr
	Secret     []byte
	Listen     string
	OnReady    func(listener, local, remote net.Addr)
	Logf       LogFunc
}

func RunServer(ctx context.Context, cfg ServerConfig) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateCommon(cfg.PacketConn, cfg.PeerAddr, cfg.Secret); err != nil {
		return err
	}
	if err := validateTCPAddress("target", cfg.Target); err != nil {
		return err
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 10 * time.Second
	}

	tlsConfig, err := makeTLSConfig(cfg.Secret, "server", "client", true)
	if err != nil {
		return err
	}
	transport := newQUICTransport(cfg.PacketConn, cfg.PeerAddr, cfg.Secret)
	defer closeTransport(transport, cfg.PacketConn)

	listener, err := transport.Listen(tlsConfig, quicConfig())
	if err != nil {
		return fmt.Errorf("portforward: listen QUIC: %w", err)
	}
	defer listener.Close()

	conn, err := listener.Accept(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("portforward: accept QUIC: %w", err)
	}
	runCtx, cancelRun := context.WithCancel(ctx)
	if cfg.OnReady != nil {
		cfg.OnReady(conn.LocalAddr(), conn.RemoteAddr())
	}

	var wg sync.WaitGroup
	defer func() {
		cancelRun()
		_ = conn.CloseWithError(0, "forwarder stopped")
		wg.Wait()
	}()
	for {
		stream, err := conn.AcceptStream(runCtx)
		if err != nil {
			if runCtx.Err() != nil || conn.Context().Err() != nil {
				return nil
			}
			return fmt.Errorf("portforward: accept stream: %w", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := serveTargetStream(runCtx, stream, cfg.Target, cfg.DialTimeout, cfg.Logf); err != nil && runCtx.Err() == nil {
				logf(cfg.Logf, "target stream failed: %v", err)
			}
		}()
	}
}

func RunClient(ctx context.Context, cfg ClientConfig) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateCommon(cfg.PacketConn, cfg.PeerAddr, cfg.Secret); err != nil {
		return err
	}
	if strings.TrimSpace(cfg.Listen) == "" {
		cfg.Listen = "127.0.0.1:0"
	}
	if err := validateTCPAddress("listen", cfg.Listen); err != nil {
		return err
	}

	tlsConfig, err := makeTLSConfig(cfg.Secret, "client", "server", false)
	if err != nil {
		return err
	}
	transport := newQUICTransport(cfg.PacketConn, cfg.PeerAddr, cfg.Secret)
	defer closeTransport(transport, cfg.PacketConn)

	conn, err := transport.Dial(ctx, cfg.PeerAddr, tlsConfig, quicConfig())
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("portforward: dial QUIC: %w", err)
	}
	defer conn.CloseWithError(0, "forwarder stopped")

	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("portforward: listen TCP on %s: %w", cfg.Listen, err)
	}
	defer listener.Close()
	if cfg.OnReady != nil {
		cfg.OnReady(listener.Addr(), conn.LocalAddr(), conn.RemoteAddr())
	}

	runCtx, cancelRun := context.WithCancel(ctx)
	stop := make(chan struct{})
	go func() {
		select {
		case <-runCtx.Done():
		case <-conn.Context().Done():
		case <-stop:
			return
		}
		_ = listener.Close()
	}()
	defer close(stop)

	var wg sync.WaitGroup
	defer func() {
		cancelRun()
		_ = listener.Close()
		_ = conn.CloseWithError(0, "forwarder stopped")
		wg.Wait()
	}()
	for {
		localConn, err := listener.Accept()
		if err != nil {
			if runCtx.Err() != nil || conn.Context().Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("portforward: accept local TCP: %w", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer localConn.Close()
			if err := forwardLocalConn(runCtx, conn, localConn, cfg.Logf); err != nil && runCtx.Err() == nil {
				logf(cfg.Logf, "local stream %s failed: %v", localConn.RemoteAddr(), err)
			}
		}()
	}
}

func newQUICTransport(packetConn *net.UDPConn, peer *net.UDPAddr, secret []byte) *quic.Transport {
	_ = packetConn.SetReadBuffer(4 << 20)
	_ = packetConn.SetWriteBuffer(4 << 20)
	resetKey := quic.StatelessResetKey(deriveQUICKey(secret, "stateless-reset"))
	tokenKey := quic.TokenGeneratorKey(deriveQUICKey(secret, "token"))
	return &quic.Transport{
		Conn:              packetConn,
		StatelessResetKey: &resetKey,
		TokenGeneratorKey: &tokenKey,
		ConnContext: func(ctx context.Context, info *quic.ClientInfo) (context.Context, error) {
			if !sameUDPAddr(info.RemoteAddr, peer) {
				return nil, fmt.Errorf("portforward: rejected unexpected peer %s", info.RemoteAddr)
			}
			return ctx, nil
		},
	}
}

func quicConfig() *quic.Config {
	return &quic.Config{
		Versions:                []quic.Version{quic.Version1},
		HandshakeIdleTimeout:    20 * time.Second,
		MaxIdleTimeout:          5 * time.Minute,
		KeepAlivePeriod:         10 * time.Second,
		MaxIncomingStreams:      128,
		MaxIncomingUniStreams:   -1,
		DisablePathMTUDiscovery: true,
	}
}

func serveTargetStream(ctx context.Context, stream *quic.Stream, target string, timeout time.Duration, logger LogFunc) error {
	request := []byte{0}
	if _, err := io.ReadFull(stream, request); err != nil {
		return fmt.Errorf("read stream request: %w", err)
	}
	if request[0] != requestOpen {
		_ = writeStatus(stream, statusDialFailed, "unsupported stream request")
		_ = stream.Close()
		return fmt.Errorf("unsupported stream request %d", request[0])
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	targetConn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", target)
	if err != nil {
		_ = writeStatus(stream, statusDialFailed, err.Error())
		_ = stream.Close()
		return fmt.Errorf("dial target %s: %w", target, err)
	}
	defer targetConn.Close()
	logf(logger, "stream=%d target connected: %s", stream.StreamID(), target)
	if err := writeStatus(stream, statusOK, ""); err != nil {
		return fmt.Errorf("write target status: %w", err)
	}
	logf(logger, "stream=%d target accepted", stream.StreamID())
	return bridgeTCPAndQUIC(ctx, targetConn, stream, logger)
}

func forwardLocalConn(ctx context.Context, conn *quic.Conn, localConn net.Conn, logger LogFunc) error {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open QUIC stream: %w", err)
	}
	logf(logger, "stream=%d opened for local %s", stream.StreamID(), localConn.RemoteAddr())
	if _, err := stream.Write([]byte{requestOpen}); err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return fmt.Errorf("write stream request: %w", err)
	}
	code, message, err := readStatus(stream)
	if err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return fmt.Errorf("read target status: %w", err)
	}
	if code != statusOK {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return fmt.Errorf("remote target rejected stream: %s", message)
	}
	logf(logger, "stream=%d remote target accepted", stream.StreamID())
	return bridgeTCPAndQUIC(ctx, localConn, stream, logger)
}

func bridgeTCPAndQUIC(ctx context.Context, tcpConn net.Conn, stream *quic.Stream, logger LogFunc) error {
	type copyResult struct {
		direction string
		err       error
	}
	results := make(chan copyResult, 2)

	go func() {
		_, err := copyBuffered(stream, tcpConn)
		_ = stream.Close()
		results <- copyResult{direction: "tcp-to-quic", err: err}
	}()
	logf(logger, "stream=%d forwarding started", stream.StreamID())
	go func() {
		_, err := copyBuffered(tcpConn, stream)
		if closeWriter, ok := tcpConn.(interface{ CloseWrite() error }); ok {
			_ = closeWriter.CloseWrite()
		}
		results <- copyResult{direction: "quic-to-tcp", err: err}
	}()

	var firstErr error
	for completed := 0; completed < 2; completed++ {
		select {
		case <-ctx.Done():
			stream.CancelRead(0)
			stream.CancelWrite(0)
			_ = tcpConn.Close()
			return ctx.Err()
		case result := <-results:
			if result.err != nil && !isBenignCopyError(result.err) && firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", result.direction, result.err)
				stream.CancelRead(0)
				stream.CancelWrite(0)
				_ = tcpConn.Close()
			}
		}
	}
	_ = tcpConn.Close()
	return firstErr
}

// copyBuffered intentionally hides optional io.WriterTo/io.ReaderFrom methods.
// In particular, net.TCPConn's platform zero-copy path is not appropriate when
// the other side is a userspace QUIC stream.
func copyBuffered(dst io.Writer, src io.Reader) (int64, error) {
	type readerOnly struct{ io.Reader }
	type writerOnly struct{ io.Writer }
	buf := make([]byte, 32*1024)
	return io.CopyBuffer(writerOnly{dst}, readerOnly{src}, buf)
}

func writeStatus(w io.Writer, code byte, message string) error {
	messageBytes := []byte(message)
	if len(messageBytes) > maxStatusMessage {
		messageBytes = messageBytes[:maxStatusMessage]
	}
	header := []byte{code, 0, 0}
	binary.BigEndian.PutUint16(header[1:], uint16(len(messageBytes)))
	if _, err := w.Write(header); err != nil {
		return err
	}
	if len(messageBytes) == 0 {
		return nil
	}
	_, err := w.Write(messageBytes)
	return err
}

func readStatus(r io.Reader) (byte, string, error) {
	header := make([]byte, 3)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, "", err
	}
	length := int(binary.BigEndian.Uint16(header[1:]))
	if length > maxStatusMessage {
		return 0, "", fmt.Errorf("status message too large: %d", length)
	}
	message := make([]byte, length)
	if _, err := io.ReadFull(r, message); err != nil {
		return 0, "", err
	}
	return header[0], string(message), nil
}

func validateCommon(packetConn *net.UDPConn, peer *net.UDPAddr, secret []byte) error {
	if packetConn == nil {
		return fmt.Errorf("portforward: punched UDP connection is required")
	}
	if peer == nil || peer.IP == nil || peer.Port <= 0 {
		return fmt.Errorf("portforward: punched peer address is required")
	}
	if len(secret) < minimumSecretBytes {
		return fmt.Errorf("portforward: shared secret must contain at least %d bytes", minimumSecretBytes)
	}
	return nil
}

func validateTCPAddress(label, address string) error {
	host, port, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return fmt.Errorf("portforward: invalid %s address %q: %w", label, address, err)
	}
	if strings.TrimSpace(port) == "" {
		return fmt.Errorf("portforward: %s port is required", label)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 0 || portNumber > 65535 || (label == "target" && portNumber == 0) {
		return fmt.Errorf("portforward: invalid %s port %q", label, port)
	}
	if label == "target" && strings.TrimSpace(host) == "" {
		return fmt.Errorf("portforward: target host is required")
	}
	return nil
}

func sameUDPAddr(got net.Addr, want *net.UDPAddr) bool {
	udp, ok := got.(*net.UDPAddr)
	if !ok || udp == nil || want == nil {
		return false
	}
	return udp.Port == want.Port && udp.Zone == want.Zone && udp.IP.Equal(want.IP)
}

func isBenignCopyError(err error) bool {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
		return true
	}
	// Windows OpenSSH commonly closes its side with WSAECONNRESET (10054)
	// after it has received the peer's FIN. Treat that completed half-close as
	// EOF instead of resetting the corresponding QUIC stream.
	return errors.Is(err, syscall.Errno(10054))
}

func closeTransport(transport *quic.Transport, packetConn *net.UDPConn) {
	if transport != nil {
		_ = transport.Close()
	}
	if packetConn != nil {
		_ = packetConn.Close()
	}
}

func logf(fn LogFunc, format string, args ...any) {
	if fn != nil {
		fn(format, args...)
	}
}
