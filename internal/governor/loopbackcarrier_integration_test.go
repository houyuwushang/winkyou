package governor_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/loopbackcarrier"
	"winkyou/internal/v2/pairingcontext"
	"winkyou/internal/v2/punchproto"
)

const (
	loopbackHelperEnabledEnv = "WINKYOU_LOOPBACK_CARRIER_HELPER"
	loopbackHelperConfigEnv  = "WINKYOU_LOOPBACK_CARRIER_CONFIG"
)

type loopbackHelperConfig struct {
	Namespace  string          `json:"namespace"`
	Bundle     json.RawMessage `json:"bundle"`
	ResultPath string          `json:"result_path"`
	ReadyPath  string          `json:"ready_path"`
}

type loopbackHelperResult struct {
	Success  bool   `json:"success"`
	Terminal string `json:"terminal,omitempty"`
	Packets  int    `json:"packets,omitempty"`
	Error    string `json:"error,omitempty"`
}

func TestLoopbackCarrierProcessHelper(t *testing.T) {
	if os.Getenv(loopbackHelperEnabledEnv) != "1" {
		return
	}
	configPayload, err := os.ReadFile(os.Getenv(loopbackHelperConfigEnv))
	if err != nil {
		t.Fatalf("read helper config: %v", err)
	}
	defer clear(configPayload)
	var config loopbackHelperConfig
	decoder := json.NewDecoder(bytes.NewReader(configPayload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		t.Fatalf("decode helper config: %v", err)
	}
	defer clear(config.Bundle)
	machine, err := governor.AcquireLoopbackCarrierTestGovernor(config.Namespace, "loopback-carrier-subprocess")
	if err != nil {
		t.Fatalf("acquire helper governor: %v", err)
	}
	defer machine.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	readyWritten := false
	result, connectErr := loopbackcarrier.Connect(ctx, machine, config.Bundle, "loopback-carrier-subprocess", func(stage loopbackcarrier.ProgressStage) error {
		if stage != loopbackcarrier.ProgressStageSocketReady {
			return nil
		}
		if readyWritten {
			return errors.New("duplicate socket-ready stage")
		}
		readyWritten = true
		file, err := os.OpenFile(config.ReadyPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		return file.Close()
	})
	clear(config.Bundle)
	helperResult := loopbackHelperResult{Success: connectErr == nil, Terminal: result.Terminal, Packets: result.OutboundPackets}
	if connectErr != nil {
		helperResult.Error = "connect_test_failed"
	}
	encoded, err := json.Marshal(helperResult)
	if err != nil {
		t.Fatalf("marshal helper result: %v", err)
	}
	if err := os.WriteFile(config.ResultPath, encoded, 0o600); err != nil {
		t.Fatalf("write helper result: %v", err)
	}
	if connectErr != nil {
		t.Fatalf("helper connect_test: %v", connectErr)
	}
}

func TestLoopbackCarrierTwoRealProcessesUseIndependentDurableJournals(t *testing.T) {
	if governor.LoopbackCarrierSubprocessRaceEnabled() {
		t.Skip("real-process carrier witness runs once outside race; in-process carrier and gate state tests run under race")
	}
	witness, initiatorLocal, responderLocal := newProcessTopology(t, nil)
	defer witness.close()
	now := time.Now().UTC().Truncate(time.Second)
	initiatorNamespace := t.TempDir()
	responderNamespace := t.TempDir()
	if err := governor.PrepareLoopbackCarrierTestNamespace(initiatorNamespace, now); err != nil {
		t.Fatalf("prepare initiator journal: %v", err)
	}
	if err := governor.PrepareLoopbackCarrierTestNamespace(responderNamespace, now); err != nil {
		t.Fatalf("prepare responder journal: %v", err)
	}
	secret := repeatedKey(61)
	initiatorBundle, responderBundle := processBundles(t, initiatorLocal, responderLocal, witness.initiatorProxy, witness.responderProxy, secret, now)
	initiator := newCarrierProcess(t, initiatorNamespace, initiatorBundle)
	responder := newCarrierProcess(t, responderNamespace, responderBundle)

	ctx, cancel := context.WithCancel(context.Background())
	witness.start(ctx)
	if err := responder.command.Start(); err != nil {
		cancel()
		t.Fatalf("start responder: %v", err)
	}
	waitForReady(t, responder)
	if err := initiator.command.Start(); err != nil {
		_ = responder.command.Process.Kill()
		cancel()
		t.Fatalf("start initiator: %v", err)
	}
	initiatorErr := initiator.command.Wait()
	responderErr := responder.command.Wait()
	cancel()
	witness.wait.Wait()
	if initiatorErr != nil || responderErr != nil {
		t.Fatalf("subprocess results = initiator %v stderr=%s; responder %v stderr=%s", initiatorErr, initiator.stderr.String(), responderErr, responder.stderr.String())
	}
	assertHelperSuccess(t, initiator.resultPath, 3)
	assertHelperSuccess(t, responder.resultPath, 2)
	if witness.initiatorPackets.Load() != 3 || witness.responderPackets.Load() != 2 {
		t.Fatalf("parent UDP witness = %d/%d, want 3/2", witness.initiatorPackets.Load(), witness.responderPackets.Load())
	}
	for role, namespace := range map[string]string{"initiator": initiatorNamespace, "responder": responderNamespace} {
		status, err := governor.InspectLoopbackCarrierTestLedger(namespace, time.Now())
		if err != nil || status.Sequence != 3 || status.Records != 3 || status.OneHourAdmissions != 1 || status.ConsecutiveFailures != 0 {
			t.Fatalf("%s journal = %+v/%v, want initialize+admit+success", role, status, err)
		}
	}
	assertReusable(t, initiatorLocal)
	assertReusable(t, responderLocal)
}

func TestLoopbackCarrierCrashAfterNoiseMessageOneBurnsAndRestartEmitsZero(t *testing.T) {
	if governor.LoopbackCarrierSubprocessRaceEnabled() {
		t.Skip("process-kill witness runs once outside race")
	}
	witness, local, unusedResponder := newProcessTopology(t, nil)
	defer witness.close()
	now := time.Now().UTC().Truncate(time.Second)
	namespace := t.TempDir()
	if err := governor.PrepareLoopbackCarrierTestNamespace(namespace, now); err != nil {
		t.Fatal(err)
	}
	secret := repeatedKey(71)
	bundle, _ := processBundles(t, local, unusedResponder, witness.initiatorProxy, witness.responderProxy, secret, now)
	ctx, cancel := context.WithCancel(context.Background())
	witness.start(ctx)
	first := newCarrierProcess(t, namespace, bundle)
	if err := first.command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	waitForCounter(t, &witness.initiatorPackets, 1)
	if err := first.command.Process.Kill(); err != nil {
		cancel()
		t.Fatal(err)
	}
	_ = first.command.Wait()
	status, err := governor.InspectLoopbackCarrierTestLedger(namespace, time.Now())
	if err != nil || status.Sequence != 2 || status.Records != 2 || status.OneHourAdmissions != 1 {
		cancel()
		t.Fatalf("journal after message-one crash = %+v/%v", status, err)
	}
	before := witness.initiatorPackets.Load()
	restart := newCarrierProcess(t, namespace, bundle)
	if err := restart.command.Run(); err == nil {
		cancel()
		t.Fatal("burned credential restart unexpectedly succeeded")
	}
	assertHelperFailure(t, restart.resultPath)
	time.Sleep(100 * time.Millisecond)
	if after := witness.initiatorPackets.Load(); after != before {
		cancel()
		t.Fatalf("restart emitted %d packet(s), want zero", after-before)
	}
	cancel()
	witness.wait.Wait()
	assertReusable(t, local)
}

func TestLoopbackCarrierCrashBeforePromoteBurnsAndRestartEmitsZero(t *testing.T) {
	if governor.LoopbackCarrierSubprocessRaceEnabled() {
		t.Skip("process-kill witness runs once outside race")
	}
	droppedSYNACK := make(chan struct{})
	var signalOnce sync.Once
	filter := func(fromInitiator bool, ordinal int, _ []byte) bool {
		if !fromInitiator && ordinal == 2 {
			signalOnce.Do(func() { close(droppedSYNACK) })
			return false
		}
		return true
	}
	witness, initiatorLocal, responderLocal := newProcessTopology(t, filter)
	defer witness.close()
	now := time.Now().UTC().Truncate(time.Second)
	initiatorNamespace := t.TempDir()
	responderNamespace := t.TempDir()
	if err := governor.PrepareLoopbackCarrierTestNamespace(initiatorNamespace, now); err != nil {
		t.Fatal(err)
	}
	if err := governor.PrepareLoopbackCarrierTestNamespace(responderNamespace, now); err != nil {
		t.Fatal(err)
	}
	initiatorBundle, responderBundle := processBundles(t, initiatorLocal, responderLocal, witness.initiatorProxy, witness.responderProxy, repeatedKey(72), now)
	initiator := newCarrierProcess(t, initiatorNamespace, initiatorBundle)
	responder := newCarrierProcess(t, responderNamespace, responderBundle)
	ctx, cancel := context.WithCancel(context.Background())
	witness.start(ctx)
	if err := responder.command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	waitForReady(t, responder)
	if err := initiator.command.Start(); err != nil {
		_ = responder.command.Process.Kill()
		cancel()
		t.Fatal(err)
	}
	select {
	case <-droppedSYNACK:
	case <-time.After(10 * time.Second):
		_ = initiator.command.Process.Kill()
		_ = responder.command.Process.Kill()
		cancel()
		t.Fatal("pair did not reach the pre-Promote hold point")
	}
	_ = initiator.command.Process.Kill()
	_ = responder.command.Process.Kill()
	_ = initiator.command.Wait()
	_ = responder.command.Wait()
	status, err := governor.InspectLoopbackCarrierTestLedger(initiatorNamespace, time.Now())
	if err != nil || status.Sequence != 2 || status.Records != 2 || status.OneHourAdmissions != 1 {
		cancel()
		t.Fatalf("initiator journal after pre-Promote crash = %+v/%v", status, err)
	}
	beforeInitiator := witness.initiatorPackets.Load()
	beforeResponder := witness.responderPackets.Load()
	restart := newCarrierProcess(t, initiatorNamespace, initiatorBundle)
	if err := restart.command.Run(); err == nil {
		cancel()
		t.Fatal("pre-Promote burned credential restart unexpectedly succeeded")
	}
	assertHelperFailure(t, restart.resultPath)
	time.Sleep(100 * time.Millisecond)
	if witness.initiatorPackets.Load() != beforeInitiator || witness.responderPackets.Load() != beforeResponder {
		cancel()
		t.Fatal("pre-Promote restart emitted a packet")
	}
	cancel()
	witness.wait.Wait()
	assertReusable(t, initiatorLocal)
	assertReusable(t, responderLocal)
}

type carrierProcess struct {
	command    *exec.Cmd
	stderr     bytes.Buffer
	resultPath string
	readyPath  string
}

func newCarrierProcess(t *testing.T, namespace string, bundle []byte) *carrierProcess {
	t.Helper()
	directory := t.TempDir()
	resultPath := filepath.Join(directory, "result.json")
	readyPath := filepath.Join(directory, "socket-ready")
	configPath := filepath.Join(directory, "config.json")
	configPayload, err := json.Marshal(loopbackHelperConfig{Namespace: namespace, Bundle: bundle, ResultPath: resultPath, ReadyPath: readyPath})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, configPayload, 0o600); err != nil {
		t.Fatal(err)
	}
	clear(configPayload)
	process := &carrierProcess{resultPath: resultPath, readyPath: readyPath}
	process.command = exec.Command(os.Args[0], "-test.run=^TestLoopbackCarrierProcessHelper$", "-test.count=1", "-test.timeout=120s")
	process.command.Env = append(os.Environ(), loopbackHelperEnabledEnv+"=1", loopbackHelperConfigEnv+"="+configPath)
	process.command.Stdout = io.Discard
	process.command.Stderr = &process.stderr
	return process
}

func assertHelperSuccess(t *testing.T, path string, packets int) {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read helper result: %v", err)
	}
	var result loopbackHelperResult
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatal(err)
	}
	if !result.Success || result.Terminal != "success" || result.Packets != packets || result.Error != "" {
		t.Fatalf("helper result = %+v", result)
	}
}

func assertHelperFailure(t *testing.T, path string) {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read failed helper result: %v", err)
	}
	var result loopbackHelperResult
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatal(err)
	}
	if result.Success || result.Error != "connect_test_failed" || result.Packets != 0 || result.Terminal != "" {
		t.Fatalf("failed helper result = %+v", result)
	}
}

func processBundles(t *testing.T, initiatorLocal, responderLocal, initiatorProxy, responderProxy netip.AddrPort, secret [32]byte, now time.Time) ([]byte, []byte) {
	t.Helper()
	offer := map[string]any{
		"artifact": "offer", "protocol": pairingcontext.ProtocolVersion, "auth_scope": pairingcontext.AuthScope,
		"credential_id": processID(1), "pairing_secret": base64.RawURLEncoding.EncodeToString(secret[:]),
		"attempt_id": processID(2), "observation_generation": "1", "initiator_participant_id": processID(3),
		"initiator_governor_scope": pairingcontext.GovernorScopeMachine,
		"secure_channel_profile":   pairingcontext.SelectedSecureChannelProfile,
		"issued_at":                now.Format(time.RFC3339), "expires_at": now.Add(5 * time.Minute).Format(time.RFC3339),
	}
	secretFree := make(map[string]any, len(offer)-1)
	for key, value := range offer {
		if key != "pairing_secret" {
			secretFree[key] = value
		}
	}
	canonical, err := pairingcontext.CanonicalizeFlatStringObject(secretFree)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	clear(canonical)
	acceptance := map[string]any{
		"artifact": pairingcontext.PairingArtifactAcceptance, "protocol": pairingcontext.ProtocolVersion, "auth_scope": pairingcontext.AuthScope,
		"credential_id": processID(1), "attempt_id": processID(2), "observation_generation": "1",
		"initiator_participant_id": processID(3), "responder_participant_id": processID(4),
		"initiator_governor_scope": pairingcontext.GovernorScopeMachine, "responder_governor_scope": pairingcontext.GovernorScopeMachine,
		"secure_channel_profile": pairingcontext.SelectedSecureChannelProfile,
		"issued_at":              now.Format(time.RFC3339), "expires_at": now.Add(5 * time.Minute).Format(time.RFC3339),
		"offer_fingerprint": base64.RawURLEncoding.EncodeToString(digest[:]),
	}
	clear(digest[:])
	build := func(role punchproto.Role, local, peer netip.AddrPort) []byte {
		payload, err := json.Marshal(map[string]any{
			"local_role": string(role), "local_endpoint": local.String(), "peer_endpoint": peer.String(),
			"offer": offer, "acceptance": acceptance,
		})
		if err != nil {
			t.Fatal(err)
		}
		return payload
	}
	return build(punchproto.RoleInitiator, initiatorLocal, initiatorProxy), build(punchproto.RoleResponder, responderLocal, responderProxy)
}

func processID(seed byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{seed}, 16))
}

func repeatedKey(seed byte) [32]byte {
	var key [32]byte
	for index := range key {
		key[index] = seed
	}
	return key
}

type processWitness struct {
	initiatorConn, responderConn       *net.UDPConn
	initiatorProxy, responderProxy     netip.AddrPort
	initiatorDest, responderDest       netip.AddrPort
	initiatorPackets, responderPackets atomic.Int64
	wait                               sync.WaitGroup
	filter                             func(bool, int, []byte) bool
}

func newProcessTopology(t *testing.T, filter func(bool, int, []byte) bool) (*processWitness, netip.AddrPort, netip.AddrPort) {
	t.Helper()
	// Hold both proxy sockets before selecting carrier endpoints. On Windows the
	// ephemeral allocator may immediately recycle a just-released carrier port
	// for a subsequently opened proxy, which makes the child correctly fail its
	// bind and turns a topology bug into an apparent carrier failure.
	initiatorConn := listen(t)
	responderConn := listen(t)
	initiatorLocalConn := listen(t)
	responderLocalConn := listen(t)
	initiatorDest := address(initiatorLocalConn)
	responderDest := address(responderLocalConn)
	if err := initiatorLocalConn.Close(); err != nil {
		t.Fatalf("release initiator carrier endpoint: %v", err)
	}
	if err := responderLocalConn.Close(); err != nil {
		t.Fatalf("release responder carrier endpoint: %v", err)
	}
	witness := &processWitness{
		initiatorConn: initiatorConn, responderConn: responderConn,
		initiatorProxy: address(initiatorConn), responderProxy: address(responderConn),
		initiatorDest: initiatorDest, responderDest: responderDest,
		filter: filter,
	}
	return witness, initiatorDest, responderDest
}

func (witness *processWitness) start(ctx context.Context) {
	witness.wait.Add(2)
	go witness.forward(ctx, witness.initiatorConn, witness.responderConn, witness.responderDest, &witness.initiatorPackets, true)
	go witness.forward(ctx, witness.responderConn, witness.initiatorConn, witness.initiatorDest, &witness.responderPackets, false)
}

func (witness *processWitness) forward(ctx context.Context, reader, writer *net.UDPConn, destination netip.AddrPort, count *atomic.Int64, fromInitiator bool) {
	defer witness.wait.Done()
	buffer := make([]byte, punchproto.MaxPacketBytes+1)
	defer clear(buffer)
	for {
		_ = reader.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		n, _, err := reader.ReadFromUDPAddrPort(buffer)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			var networkErr net.Error
			if errors.As(err, &networkErr) && networkErr.Timeout() {
				continue
			}
			return
		}
		ordinal := int(count.Add(1))
		if witness.filter != nil && !witness.filter(fromInitiator, ordinal, buffer[:n]) {
			continue
		}
		_, _ = writer.WriteToUDPAddrPort(buffer[:n], destination)
	}
}

func (witness *processWitness) close() {
	_ = witness.initiatorConn.Close()
	_ = witness.responderConn.Close()
	witness.wait.Wait()
}

func listen(t *testing.T) *net.UDPConn {
	t.Helper()
	connection, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	return connection
}

func address(connection *net.UDPConn) netip.AddrPort {
	return connection.LocalAddr().(*net.UDPAddr).AddrPort()
}

func waitForReady(t *testing.T, process *carrierProcess) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(process.readyPath); err == nil {
			return
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("inspect subprocess readiness witness: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("subprocess did not publish socket readiness; stderr=%s", process.stderr.String())
}

func assertReusable(t *testing.T, endpoint netip.AddrPort) {
	t.Helper()
	connection, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(endpoint))
	if err != nil {
		t.Fatalf("subprocess left socket open: %v", err)
	}
	_ = connection.Close()
}

func waitForCounter(t *testing.T, counter *atomic.Int64, wanted int64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if counter.Load() >= wanted {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("packet witness = %d, want at least %d", counter.Load(), wanted)
}
