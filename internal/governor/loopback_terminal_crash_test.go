package governor_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/loopbackcarrier"
)

func TestLoopbackTerminalRevokeCrashHelper(t *testing.T) {
	if os.Getenv("WINKYOU_TERMINAL_REVOKE_CRASH_HELPER") != "1" {
		return
	}
	payload, err := os.ReadFile(os.Getenv(loopbackHelperConfigEnv))
	if err != nil {
		t.Fatal("read synthetic child configuration")
	}
	defer clear(payload)
	var config loopbackHelperConfig
	if err := json.Unmarshal(payload, &config); err != nil {
		t.Fatal("decode synthetic child configuration")
	}
	defer clear(config.Bundle)
	machine, err := governor.AcquireLoopbackCarrierTestGovernor(config.Namespace, "terminal-crash-test")
	if err != nil {
		t.Fatal("acquire synthetic owner")
	}
	defer machine.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := governor.BeforeLoopbackCarrierFinishWrite(machine, func(reason governor.PairingTerminalReason) error {
		if reason != governor.PairingTerminalCarrierError {
			return errors.New("unexpected held FINISH reason")
		}
		// The parent observes a live child at this exact pre-append boundary,
		// proves its UDP endpoint is already reusable, then kills the child.
		if err := os.WriteFile(config.ReadyPath, []byte("finish_not_appended"), 0o600); err != nil {
			return errors.New("publish terminal hold witness")
		}
		<-ctx.Done()
		return ctx.Err()
	}); err != nil {
		t.Fatal("install pre-FINISH hold")
	}
	_, _ = loopbackcarrier.Connect(ctx, machine, config.Bundle, "terminal-crash-test", func(loopbackcarrier.ProgressStage) error {
		return errors.New("synthetic terminal before first emission")
	})
	t.Fatal("parent did not kill the held terminal child")
}

func TestLoopbackTerminalRevokeCrashRetainsBurnAndRestartEmitsZero(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	namespace := t.TempDir()
	if err := governor.PrepareLoopbackCarrierTestNamespace(namespace, now); err != nil {
		t.Fatal(err)
	}
	local := reserveLoopbackEndpoint(t)
	peer := reserveLoopbackEndpoint(t)
	// A real, independent loopback receiver witnesses both the killed run and
	// its restarted artifact. No endpoint or process identity is logged.
	receiver, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(peer))
	if err != nil {
		t.Fatal("start synthetic emission witness")
	}
	defer receiver.Close()
	bundle, unused := processBundles(t, local, peer, peer, local, repeatedKey(83), now)
	defer clear(bundle)
	clear(unused)
	child := newCarrierProcess(t, namespace, bundle)
	child.command.Args[1] = "-test.run=^TestLoopbackTerminalRevokeCrashHelper$"
	child.command.Env = append(child.command.Env, "WINKYOU_TERMINAL_REVOKE_CRASH_HELPER=1")
	if err := child.command.Start(); err != nil {
		t.Fatal("start terminal child")
	}
	waited := false
	defer func() {
		if !waited {
			_ = child.command.Process.Kill()
			_ = child.command.Wait()
		}
	}()
	waitForReady(t, child)
	assertReusable(t, local) // child still holds BURN and has not written FINISH
	if err := child.command.Process.Kill(); err != nil {
		t.Fatal("kill held terminal child")
	}
	_ = child.command.Wait()
	waited = true
	ledger, err := governor.InspectLoopbackCarrierTestLedger(namespace, time.Now())
	admissions, packets, occupancyErr := governor.InspectLoopbackCarrierTestOccupancy(namespace, time.Now())
	if err != nil || occupancyErr != nil || ledger.Sequence != 2 || ledger.Records != 2 || ledger.TwentyFourHourAdmissions != 1 || ledger.TwentyFourHourPackets != 3 || admissions != 1 || packets != 3 {
		t.Fatalf("crash lost durable charge: sequence=%d records=%d admissions=%d packets=%d", ledger.Sequence, ledger.Records, admissions, packets)
	}
	restart := newCarrierProcess(t, namespace, bundle)
	if err := restart.command.Run(); err == nil {
		t.Fatal("burned credential restart unexpectedly succeeded")
	}
	assertHelperFailure(t, restart.resultPath)
	after, err := governor.InspectLoopbackCarrierTestLedger(namespace, time.Now())
	afterAdmissions, afterPackets, occupancyErr := governor.InspectLoopbackCarrierTestOccupancy(namespace, time.Now())
	if err != nil || occupancyErr != nil || after.Sequence != 2 || afterAdmissions != 1 || afterPackets != 3 {
		t.Fatal("restart rewrote or refunded unfinished admission")
	}
	if err := receiver.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := receiver.ReadFromUDPAddrPort(make([]byte, 128)); err == nil {
		t.Fatal("terminal crash or burned restart emitted a packet")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatal("emission witness failed instead of observing silence")
	}
	assertReusable(t, local)
	owner, err := governor.AcquireLoopbackCarrierTestGovernor(namespace, "terminal-crash-reopen")
	if err != nil {
		t.Fatal("owner lock or safety state not recoverable after child exit")
	}
	if owner.Snapshot().SafetyTrip.State != governor.SafetyTripClear {
		t.Fatal("clean terminal revoke persisted a safety trip")
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	t.Log("O2_CRASH pre_finish_rebind=true journal_records=2 unfinished_admissions=1 unfinished_packets=3 restart_emissions=0 processes=0 owner_lock_reacquired=true safety=clear")
}
