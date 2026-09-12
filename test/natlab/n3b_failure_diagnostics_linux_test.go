//go:build linux && natlab

package natlab

import (
	"testing"
	"time"
)

func logN2DEndpointFailure(t testing.TB, process *n2dEndpointProcess) {
	t.Helper()
	var result n2dEndpointResult
	readable := readN1JSON(process.resultPath, &result)
	exited := false
	select {
	case <-process.done:
		exited = true
	default:
	}
	process.waitMu.Lock()
	waitErr := process.waitErr
	process.waitMu.Unlock()
	class := "unknown"
	switch result.ErrorClass {
	case "", "artifact_read", "artifact_rejected", "request_encode", "stdio_serve", "stdio_result", "stdio_contract",
		"authority_residue", "internal_error", "governor_acquire", "carrier_preconnect", "presence_timeout",
		"presence_failed", "event_write", "context_digest", "durable_burn", "authorization_consume",
		"replay_not_rejected", "credential_used", "second_socket", "third_target", "sixth_packet":
		class = result.ErrorClass
	}
	t.Logf("N2D_ENDPOINT_FAILURE role=%s result_read=%t exited=%t wait=%+v runtime_markers=%v ok=%t harness_class=%s elapsed_ms=%d",
		process.config.Role, readable, exited, gateB3SafeError(waitErr, nil), process.output.snapshot(), result.OK, class, result.ElapsedMilliseconds)
	if diag := result.StdioDiagnostic; diag != nil {
		var stages [16]string
		for index, stage := range diag.Stages {
			stages[index] = n3bSafeStage(stage)
		}
		t.Logf("N3B_STDIO_FAILURE role=%s frames=%d progress=%d handshake=%t result=%t rpc_error=%t class=%s stage=%s burned_known=%t burned=%t last_progress=%s parse=%s serve=%s",
			process.config.Role, diag.Frames, diag.ProgressCount, diag.HandshakeSeen, diag.ResultSeen, diag.RPCErrorSeen,
			n3bSafeClass(diag.Class), n3bSafeStage(diag.Stage), diag.BurnedKnown, diag.Burned, n3bSafeStage(diag.LastProgress), n3bSafeParseFailure(diag.ParseFailure), n3bSafeServeClass(diag.ServeClass))
		t.Logf("N3B_STDIO_CONTRACT role=%s stages=%v result_success=%t bidirectional=%t promoted=%t burned=%t finish=%t",
			process.config.Role, stages, diag.ResultSuccess, diag.Bidirectional, diag.Promoted, diag.ResultBurned, diag.FinishRecorded)
		t.Logf("N3B_CAUSE_FAILURE role=%s seen=%t cause=%s context=%s operation=%s network_timeout=%t",
			process.config.Role, diag.Cause.Seen, n3bSafeCauseWord(diag.Cause.Cause), n3bSafeCauseWord(diag.Cause.Context), n3bSafeCauseWord(diag.Cause.Operation), diag.Cause.NetworkTimeout)
	}
}

// This runs only after the original Fatal. Observe both children before kill,
// then independently drain every resource even if an earlier witness fails.
// It never turns a failed scenario into success or treats an invalid query as 0.
func n3bFailedCaseDiagnostics(t testing.TB, topology *n2dTopology, servers *n2dServers, left, right *n2dEndpointProcess) {
	t.Helper()
	logN2DEndpointFailure(t, left)
	logN2DEndpointFailure(t, right)
	left.stop()
	right.stop()
	logN2DEndpointFailure(t, left)
	logN2DEndpointFailure(t, right)
	if servers != nil && servers.rendezvous != nil {
		stats := servers.rendezvous.Stats()
		t.Logf("N3B_FAILURE_CARRIER accepted=%d active=%d frames_A=%d/%d frames_B=%d/%d",
			stats.Accepted, stats.Active, stats.SlotARead, stats.SlotAWritten, stats.SlotBRead, stats.SlotBWritten)
	}
	serverErr := servers.Close()
	t.Logf("N3B_FAILURE_SERVER_CLOSE valid=%t error=%+v", serverErr == nil, gateB3SafeError(serverErr, nil))
	before, beforeErr := topology.packetCounts()
	time.Sleep(100 * time.Millisecond)
	after, afterErr := topology.packetCounts()
	packetsValid := beforeErr == nil && afterErr == nil
	t.Logf("N3B_FAILURE_PACKETS before=%+v after=%+v valid=%t stable=%t", before, after, packetsValid, packetsValid && before == after)
	sockets, socketErr := topology.socketCount()
	processes, processErr := topology.processCount()
	t.Logf("N3B_FAILURE_OS sockets=%d sockets_valid=%t processes=%d processes_valid=%t", sockets, socketErr == nil, processes, processErr == nil)
	ctBefore, ctAfter, ctErr := topology.flushConntrack()
	t.Logf("N3B_FAILURE_CONNTRACK before=%d after=%d valid=%t", ctBefore, ctAfter, ctErr == nil)
	cleanupErr := topology.cleanup()
	leakErr := topology.assertNoLeaks()
	t.Logf("N3B_FAILURE_TOPOLOGY cleanup_valid=%t no_leaks=%t", cleanupErr == nil, leakErr == nil)
	if serverErr != nil || !packetsValid || before != after || socketErr != nil || sockets != 0 ||
		processErr != nil || processes != 0 || ctErr != nil || ctAfter != 0 || cleanupErr != nil || leakErr != nil {
		t.Error("N3b failed-case cleanup has an unavailable or unsuccessful witness; original failure retained")
	}
}
