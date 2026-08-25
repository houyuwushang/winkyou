package rendezvousserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"crypto/tls"

	"winkyou/internal/v2/rendezvousadmission"
	"winkyou/internal/v2/rendezvouswire"
)

func TestOneShotServerCompletesExactOpaqueEnvelopeAndClosesListener(t *testing.T) {
	config, association := serverTestConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	done := make(chan TerminalRecord, 1)
	go func() { done <- Serve(ctx, config) }()

	a := dialTestTLS(t, config.ListenAddress)
	defer a.Close()
	writePresence(t, a, association, rendezvouswire.SlotA)
	b := dialTestTLS(t, config.ListenAddress)
	defer b.Close()
	writePresence(t, b, association, rendezvouswire.SlotB)
	readKind(t, a, rendezvouswire.KindPresenceReady)
	readKind(t, b, rendezvouswire.KindPresenceReady)

	if connection, err := net.DialTimeout("tcp", config.ListenAddress, 100*time.Millisecond); err == nil {
		_ = connection.Close()
		t.Fatal("third connection reached a listener after both slots were accepted")
	}
	writeKind(t, a, rendezvouswire.KindActivate, nil)
	writeKind(t, b, rendezvouswire.KindActivate, nil)
	readKind(t, a, rendezvouswire.KindActivateReady)
	readKind(t, b, rendezvouswire.KindActivateReady)

	handshakeA := bytesOf(0x11, rendezvouswire.HandshakePayloadBytes)
	handshakeB := bytesOf(0x22, rendezvouswire.HandshakePayloadBytes)
	writeKind(t, a, rendezvouswire.KindHandshake, handshakeA)
	writeKind(t, b, rendezvouswire.KindHandshake, handshakeB)
	if got := readKind(t, a, rendezvouswire.KindHandshake); !reflect.DeepEqual(got, handshakeB) {
		t.Fatal("slot A did not receive slot B's opaque handshake")
	}
	if got := readKind(t, b, rendezvouswire.KindHandshake); !reflect.DeepEqual(got, handshakeA) {
		t.Fatal("slot B did not receive slot A's opaque handshake")
	}

	for index := 0; index < 4; index++ {
		writeKind(t, a, rendezvouswire.KindControl, bytesOf(byte(0x30+index), rendezvouswire.MinControlPayloadBytes))
	}
	for index := 0; index < 3; index++ {
		writeKind(t, b, rendezvouswire.KindControl, bytesOf(byte(0x40+index), rendezvouswire.MinControlPayloadBytes))
	}
	for index := 0; index < 3; index++ {
		readKind(t, a, rendezvouswire.KindControl)
	}
	for index := 0; index < 4; index++ {
		readKind(t, b, rendezvouswire.KindControl)
	}

	select {
	case record := <-done:
		if record.Class != ClassCompleted || record.AcceptedConnections != 2 || record.FramesRead != 13 || record.FramesWritten != 13 ||
			record.BytesRead <= 0 || record.BytesWritten <= 0 {
			t.Fatalf("terminal record = %+v", record)
		}
		payload := string(MarshalTerminal(record))
		for _, forbidden := range []string{config.ListenAddress, association, config.TLSCertFile, config.TLSKeyFile, config.AssociationFile} {
			if strings.Contains(payload, forbidden) {
				t.Fatalf("terminal record leaked private input: %s", payload)
			}
		}
	case <-ctx.Done():
		t.Fatal("one-shot server did not terminate")
	}
}

func TestOneShotServerPresenceAndHalfTLSAreBounded(t *testing.T) {
	t.Run("wrong first frame", func(t *testing.T) {
		config, _ := serverTestConfig(t)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		done := make(chan TerminalRecord, 1)
		go func() { done <- Serve(ctx, config) }()
		connection := dialTestTLS(t, config.ListenAddress)
		defer connection.Close()
		writeKind(t, connection, rendezvouswire.KindActivate, nil)
		record := <-done
		if record.Class != ClassProtocolViolation || record.AcceptedConnections != 1 {
			t.Fatalf("wrong first frame = %+v", record)
		}
	})

	t.Run("wrong first frame drains already accepted second socket", func(t *testing.T) {
		config, _ := serverTestConfig(t)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		done := make(chan TerminalRecord, 1)
		go func() { done <- Serve(ctx, config) }()
		first := dialTestTLS(t, config.ListenAddress)
		defer first.Close()
		second := dialTestTLS(t, config.ListenAddress)
		defer second.Close()
		writeKind(t, first, rendezvouswire.KindActivate, nil)
		record := <-done
		if record.Class != ClassProtocolViolation || record.AcceptedConnections != 2 {
			t.Fatalf("wrong first frame with second socket = %+v", record)
		}
		if err := second.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if _, err := second.Read(make([]byte, 1)); err == nil {
			t.Fatal("second accepted socket survived terminal first-frame failure")
		}
		assertAddressRebinds(t, config.ListenAddress)
	})

	t.Run("missing peer", func(t *testing.T) {
		config, association := serverTestConfig(t)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		done := make(chan TerminalRecord, 1)
		started := time.Now()
		go func() { done <- Serve(ctx, config) }()
		connection := dialTestTLS(t, config.ListenAddress)
		writePresence(t, connection, association, rendezvouswire.SlotA)
		defer connection.Close()
		record := <-done
		if record.Class != ClassPresenceTimeout || record.AcceptedConnections != 1 || record.FramesRead != 1 || record.BytesRead <= 0 || time.Since(started) > 4*time.Second {
			t.Fatalf("presence timeout = %+v after %s", record, time.Since(started))
		}
	})

	t.Run("half tls", func(t *testing.T) {
		config, association := serverTestConfig(t)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		done := make(chan TerminalRecord, 1)
		started := time.Now()
		go func() { done <- Serve(ctx, config) }()
		connection := dialTestTCP(t, config.ListenAddress)
		defer connection.Close()
		second := dialTestTLS(t, config.ListenAddress)
		defer second.Close()
		writePresence(t, second, association, rendezvouswire.SlotB)
		record := <-done
		if record.Class != ClassTLSFailed || record.AcceptedConnections != 2 || time.Since(started) > 4*time.Second {
			t.Fatalf("half TLS = %+v after %s", record, time.Since(started))
		}
	})
}

func TestServerBudgetAndTerminalSchemaAreFixed(t *testing.T) {
	current := &side{framesRead: MaxFramesPerDirection, bytesRead: MaxApplicationBytes}
	if current.chargeRead(1) {
		t.Fatal("read budget accepted a ninth frame")
	}
	record := TerminalRecord{Event: "terminal", Class: ClassBudgetExceeded, AcceptedConnections: 2, FramesRead: 8, FramesWritten: 7, BytesRead: 8256, BytesWritten: 100}
	payload := MarshalTerminal(record)
	defer clear(payload)
	var members map[string]json.RawMessage
	if err := json.Unmarshal(payload, &members); err != nil {
		t.Fatal(err)
	}
	want := []string{"event", "class", "accepted_connections", "frames_read", "frames_written", "bytes_read", "bytes_written"}
	for _, name := range want {
		delete(members, name)
	}
	if len(members) != 0 || len(want) != 7 {
		t.Fatalf("terminal schema drifted: %s", payload)
	}
}

func TestServerRejectsOversizedFrameAsBudgetExceeded(t *testing.T) {
	config, association := serverTestConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan TerminalRecord, 1)
	go func() { done <- Serve(ctx, config) }()
	a, b := activateTestPair(t, config.ListenAddress, association)
	defer a.Close()
	defer b.Close()
	header := []byte{'W', 'Y', 'R', 'C', rendezvouswire.Version, byte(rendezvouswire.KindControl), 0x04, 0x01}
	if _, err := a.Write(header); err != nil {
		t.Fatal(err)
	}
	select {
	case record := <-done:
		if record.Class != ClassBudgetExceeded || record.AcceptedConnections != 2 {
			t.Fatalf("oversized frame terminal = %+v", record)
		}
	case <-ctx.Done():
		t.Fatal("oversized frame did not terminate the one-shot server")
	}
}

func TestServerHalfFrameAndCancellationDrainSockets(t *testing.T) {
	t.Run("half frame obeys tighter caller deadline", func(t *testing.T) {
		config, association := serverTestConfig(t)
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		done := make(chan TerminalRecord, 1)
		go func() { done <- Serve(ctx, config) }()
		a, b := activateTestPair(t, config.ListenAddress, association)
		defer a.Close()
		defer b.Close()
		if _, err := a.Write([]byte{'W', 'Y', 'R', 'C'}); err != nil {
			t.Fatal(err)
		}
		record := <-done
		if record.Class != ClassDeadlineExceeded {
			t.Fatalf("half-frame terminal = %+v", record)
		}
		assertAddressRebinds(t, config.ListenAddress)
	})

	t.Run("explicit cancellation", func(t *testing.T) {
		config, association := serverTestConfig(t)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan TerminalRecord, 1)
		go func() { done <- Serve(ctx, config) }()
		a := dialTestTLS(t, config.ListenAddress)
		defer a.Close()
		writePresence(t, a, association, rendezvouswire.SlotA)
		cancel()
		record := <-done
		if record.Class != ClassShutdown || record.AcceptedConnections != 1 {
			t.Fatalf("cancel terminal = %+v", record)
		}
		assertAddressRebinds(t, config.ListenAddress)
	})
}

func TestServerCrashProcess(t *testing.T) {
	if encoded := os.Getenv("WINKYOU_RENDEZVOUS_CRASH_CONFIG"); encoded != "" {
		payload, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		var config Config
		if err := json.Unmarshal(payload, &config); err != nil {
			t.Fatal(err)
		}
		clear(payload)
		_ = Serve(context.Background(), config)
		return
	}
	config, _ := serverTestConfig(t)
	payload, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestServerCrashProcess$", "-test.count=1")
	command.Env = append(os.Environ(), "WINKYOU_RENDEZVOUS_CRASH_CONFIG="+base64.RawURLEncoding.EncodeToString(payload))
	clear(payload)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	connection := dialTestTCP(t, config.ListenAddress)
	_ = connection.Close()
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("crash witness subprocess unexpectedly exited cleanly")
	}
	assertAddressRebinds(t, config.ListenAddress)
}

func TestListenAddressRequiresCanonicalLiteral(t *testing.T) {
	for _, valid := range []string{"127.0.0.1:443", "0.0.0.0:443", "192.0.2.10:443", "[::1]:443", "[::]:443"} {
		if !validListenAddress(valid) {
			t.Errorf("canonical literal %q rejected", valid)
		}
	}
	for _, invalid := range []string{"localhost:443", "127.0.0.1:0", "127.000.000.001:443", "[2001:0db8::1]:443", "[::ffff:192.0.2.1]:443", "224.0.0.1:443"} {
		if validListenAddress(invalid) {
			t.Errorf("non-canonical or forbidden listen address %q accepted", invalid)
		}
	}
}

func serverTestConfig(t *testing.T) (Config, string) {
	t.Helper()
	root := t.TempDir()
	certificatePath, keyPath := writeTestCertificate(t, root)
	now := time.Now().UTC().Truncate(time.Second)
	association := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
	admissionPayload, err := json.Marshal(rendezvousadmission.Admission{
		Profile: rendezvouswire.PresenceProfile, AssociationID: association,
		IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339),
	})
	if err != nil {
		t.Fatal(err)
	}
	admissionPath := filepath.Join(root, "admission.json")
	if err := os.WriteFile(admissionPath, admissionPayload, 0o600); err != nil {
		t.Fatal(err)
	}
	clear(admissionPayload)
	return Config{
		ListenAddress: reserveTestAddress(t), TLSCertFile: certificatePath,
		TLSKeyFile: keyPath, AssociationFile: admissionPath,
	}, association
}

func reserveTestAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func dialTestTCP(t *testing.T, address string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		connection, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			return connection
		}
		if time.Now().After(deadline) {
			t.Fatalf("dial test server: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func dialTestTLS(t *testing.T, address string) *tls.Conn {
	t.Helper()
	raw := dialTestTCP(t, address)
	connection := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	})
	if err := connection.Handshake(); err != nil {
		_ = raw.Close()
		t.Fatalf("TLS handshake: %v", err)
	}
	if connection.ConnectionState().Version != tls.VersionTLS13 {
		t.Fatal("server negotiated a non-TLS-1.3 version")
	}
	return connection
}

func writePresence(t *testing.T, connection io.Writer, association string, slot rendezvouswire.Slot) {
	t.Helper()
	payload, err := rendezvouswire.PresencePayload(association, slot)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(payload)
	writeKind(t, connection, rendezvouswire.KindPresence, payload)
}

func writeKind(t *testing.T, writer io.Writer, kind rendezvouswire.Kind, payload []byte) {
	t.Helper()
	frame, err := rendezvouswire.Encode(kind, payload)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(frame)
	if _, err := writer.Write(frame); err != nil {
		t.Fatal(err)
	}
}

func readKind(t *testing.T, reader io.Reader, kind rendezvouswire.Kind) []byte {
	t.Helper()
	frame, _, err := rendezvouswire.Decode(reader)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Kind != kind {
		clear(frame.Payload)
		t.Fatalf("frame kind = %d, want %d", frame.Kind, kind)
	}
	return frame.Payload
}

func activateTestPair(t *testing.T, address, association string) (*tls.Conn, *tls.Conn) {
	t.Helper()
	a := dialTestTLS(t, address)
	writePresence(t, a, association, rendezvouswire.SlotA)
	b := dialTestTLS(t, address)
	writePresence(t, b, association, rendezvouswire.SlotB)
	readKind(t, a, rendezvouswire.KindPresenceReady)
	readKind(t, b, rendezvouswire.KindPresenceReady)
	writeKind(t, a, rendezvouswire.KindActivate, nil)
	writeKind(t, b, rendezvouswire.KindActivate, nil)
	readKind(t, a, rendezvouswire.KindActivateReady)
	readKind(t, b, rendezvouswire.KindActivateReady)
	return a, b
}

func assertAddressRebinds(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		listener, err := net.Listen("tcp", address)
		if err == nil {
			_ = listener.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("server socket residue at redacted test address: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func bytesOf(value byte, count int) []byte {
	payload := make([]byte, count)
	for index := range payload {
		payload[index] = value
	}
	return payload
}

func writeTestCertificate(t *testing.T, directory string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "winkyou-test-only"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificatePath := filepath.Join(directory, "server.crt")
	keyPath := filepath.Join(directory, "server.key")
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	clear(keyDER)
	defer clear(certificatePEM)
	defer clear(keyPEM)
	if err := os.WriteFile(certificatePath, certificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certificatePath, keyPath
}
