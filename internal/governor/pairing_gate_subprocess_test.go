package governor

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

const (
	pairingGateHelperEnabledEnv   = "WINKYOU_PAIRING_GATE_HELPER"
	pairingGateHelperNamespaceEnv = "WINKYOU_PAIRING_GATE_NAMESPACE"
	pairingGateHelperScenarioEnv  = "WINKYOU_PAIRING_GATE_SCENARIO"
	pairingGateHelperBundleEnv    = "WINKYOU_PAIRING_GATE_BUNDLE"
	pairingGateHelperClockEnv     = "WINKYOU_PAIRING_GATE_CLOCK"
	pairingGateHelperWitnessEnv   = "WINKYOU_PAIRING_GATE_WITNESS"

	pairingGateCrashExitCode = 86
)

var pairingGateWitnessMarker = []byte{0x00, 'W', 'I', 'N', 'K', 'Y', 'O', 'U', '-', 'P', 'A', 'R', 'E', 'N', 'T', 0xfe}

type pairingGateSubprocessResult struct {
	witnesses int
	stdout    []byte
	stderr    []byte
	err       error
}

func TestPairingAdmissionGateSubprocessHelper(t *testing.T) {
	if os.Getenv(pairingGateHelperEnabledEnv) != "1" {
		return
	}
	namespace := os.Getenv(pairingGateHelperNamespaceEnv)
	scenario := os.Getenv(pairingGateHelperScenarioEnv)
	bundle := os.Getenv(pairingGateHelperBundleEnv)
	logicalNow, err := time.Parse(time.RFC3339Nano, os.Getenv(pairingGateHelperClockEnv))
	if err != nil {
		t.Fatalf("parse helper clock: %v", err)
	}
	witness, err := base64.RawStdEncoding.DecodeString(os.Getenv(pairingGateHelperWitnessEnv))
	if err != nil || len(witness) == 0 {
		t.Fatalf("decode parent witness: %v", err)
	}

	owner, err := AcquirePreparedNamespace(namespace, ScopeMachine, "pairing-gate-helper")
	if errors.Is(err, ErrOwnerHeld) {
		return
	}
	if err != nil {
		t.Fatalf("acquire helper owner: %v", err)
	}
	defer func() { _ = owner.Close() }()
	ledger := &PairingAdmissionLedger{
		owner:           owner,
		ownerInstanceID: owner.Info().InstanceID,
		path:            filepath.Join(namespace, pairingLedgerFilename),
		now:             func() time.Time { return logicalNow },
		validateFile:    validateTestPairingLedgerFile,
	}
	owner.mu.Lock()
	owner.pairingLedger = ledger
	owner.mu.Unlock()
	governor, err := New(owner, ProfilePhase1Machine, nil)
	if err != nil {
		return
	}
	defer func() { _ = governor.Close() }()
	peer, err := governor.AcquirePeer("pairing-gate-subprocess")
	if err != nil {
		t.Fatalf("acquire helper peer: %v", err)
	}
	request := testPairingRequest("subprocess-"+bundle, logicalNow, 8)
	attemptContext, cancelAttempt := context.WithCancel(context.Background())
	defer cancelAttempt()
	attempt, err := peer.AcquireAttempt(attemptContext, AttemptRequest{
		ID:        request.AttemptID,
		Operation: OperationConnectTest,
		Cost: AttemptCost{
			Resources: request.Envelope.resources(),
			Duration:  time.Duration(request.Envelope.DurationMillis) * time.Millisecond,
		},
	})
	if err != nil {
		return
	}

	crash := func() error {
		os.Exit(pairingGateCrashExitCode)
		return nil
	}
	gate := NewPairingAdmissionGate()
	switch scenario {
	case "before_burn_crash":
		gate.hooks.afterPrecheck = crash
	case "append_mid_crash":
		ledger.hooks.writeFrame = func(file *os.File, _ pairingJournalRecord, frame []byte) (int, error) {
			written, writeErr := file.Write(frame[:len(frame)/2])
			if writeErr == nil {
				writeErr = file.Sync()
			}
			if writeErr != nil {
				return written, writeErr
			}
			os.Exit(pairingGateCrashExitCode)
			return written, nil
		}
	case "after_fsync_crash":
		ledger.hooks.afterSync = func(pairingJournalRecord) error {
			return crash()
		}
	case "before_postcheck_crash":
		gate.hooks.beforePostcheck = crash
	case "after_postcheck_crash":
		gate.hooks.afterPostcheck = crash
	case "trip_before_burn":
		_, _ = governor.Trip(SafetyTripEvent{Reason: SafetyTripOperator, Detail: "subprocess trip before burn"})
	case "trip_after_burn":
		gate.hooks.afterDurableAdmission = func() error {
			_, tripErr := governor.Trip(SafetyTripEvent{Reason: SafetyTripOperator, Detail: "subprocess trip after burn"})
			return tripErr
		}
	case "emit_before_burn_mutation":
		if _, err := os.Stdout.Write(witness); err != nil {
			t.Fatalf("write mutation witness: %v", err)
		}
		os.Exit(pairingGateCrashExitCode)
	}

	committed, err := gate.Commit(attemptContext, attempt, request)
	if err != nil || committed == nil {
		return
	}
	authorization, err := committed.ConsumeForCarrier(attemptContext)
	if err != nil || authorization == nil {
		return
	}
	if scenario == "trip_before_first" {
		_, _ = governor.Trip(SafetyTripEvent{Reason: SafetyTripOperator, Detail: "subprocess trip before first byte"})
	}
	if err := authorization.BeforeFirstEmission(attemptContext); err != nil {
		return
	}
	if _, err := os.Stdout.Write(witness); err != nil {
		t.Fatalf("write parent-owned witness: %v", err)
	}
	switch scenario {
	case "after_first_byte_crash":
		os.Exit(pairingGateCrashExitCode)
	case "terminal_write_crash":
		ledger.hooks.writeFrame = func(file *os.File, record pairingJournalRecord, frame []byte) (int, error) {
			if record.Type != pairingRecordFinish {
				return file.Write(frame)
			}
			written, writeErr := file.Write(frame[:len(frame)/2])
			if writeErr == nil {
				writeErr = file.Sync()
			}
			if writeErr != nil {
				return written, writeErr
			}
			os.Exit(pairingGateCrashExitCode)
			return written, nil
		}
		_ = authorization.Finish(PairingTerminalSuccess)
	case "trip_after_first":
		_, _ = governor.Trip(SafetyTripEvent{Reason: SafetyTripOperator, Detail: "subprocess trip after first byte"})
		<-authorization.Stopping()
		_ = authorization.Finish(PairingTerminalCancelled)
	default:
		_ = authorization.Finish(PairingTerminalSuccess)
	}
}

func TestPairingAdmissionGateCrashMatrixUsesParentWitness(t *testing.T) {
	if pairingGateRaceEnabled {
		t.Skip("subprocess crash matrix runs once outside the race build; gate state tests run under race")
	}
	tests := []struct {
		name                string
		scenario            string
		wantWitnesses       int
		wantIndeterminate   bool
		wantSequenceAtLeast uint64
		wantRetryWitnesses  int
	}{
		{name: "before burn", scenario: "before_burn_crash", wantWitnesses: 0, wantSequenceAtLeast: 1, wantRetryWitnesses: 1},
		{name: "append middle", scenario: "append_mid_crash", wantWitnesses: 0, wantIndeterminate: true, wantRetryWitnesses: 0},
		{name: "after fsync before return", scenario: "after_fsync_crash", wantWitnesses: 0, wantSequenceAtLeast: 2, wantRetryWitnesses: 0},
		{name: "before postcheck", scenario: "before_postcheck_crash", wantWitnesses: 0, wantSequenceAtLeast: 2, wantRetryWitnesses: 0},
		{name: "after postcheck", scenario: "after_postcheck_crash", wantWitnesses: 0, wantSequenceAtLeast: 2, wantRetryWitnesses: 0},
		{name: "after first byte", scenario: "after_first_byte_crash", wantWitnesses: 1, wantSequenceAtLeast: 2, wantRetryWitnesses: 0},
		{name: "during terminal write", scenario: "terminal_write_crash", wantWitnesses: 1, wantIndeterminate: true, wantRetryWitnesses: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			namespace, logicalNow := preparePairingGateSubprocessNamespace(t)
			result := runPairingGateSubprocess(t, namespace, test.scenario, "crash-matrix", logicalNow)
			if result.witnesses != test.wantWitnesses {
				t.Fatalf("external witnesses = %d, want %d; err=%v stdout=%q stderr=%s", result.witnesses, test.wantWitnesses, result.err, result.stdout, result.stderr)
			}
			snapshot, readErr := readPairingLedgerSnapshot(filepath.Join(namespace, pairingLedgerFilename), logicalNow, "", validateTestPairingLedgerFile)
			if test.wantIndeterminate {
				if !errors.Is(readErr, ErrPairingLedgerIndeterminate) {
					t.Fatalf("journal after crash = %+v/%v, want indeterminate", snapshot.status, readErr)
				}
			} else if readErr != nil || snapshot.sequence < test.wantSequenceAtLeast {
				t.Fatalf("journal after crash = sequence %d/%v, want >= %d", snapshot.sequence, readErr, test.wantSequenceAtLeast)
			}
			retry := runPairingGateSubprocess(t, namespace, "normal", "crash-matrix", logicalNow.Add(time.Second))
			if retry.witnesses != test.wantRetryWitnesses {
				t.Fatalf("retry external witnesses = %d, want %d; err=%v stdout=%q stderr=%s", retry.witnesses, test.wantRetryWitnesses, retry.err, retry.stdout, retry.stderr)
			}
		})
	}
}

func TestPairingAdmissionGateSafetyTripEmissionBoundary(t *testing.T) {
	if pairingGateRaceEnabled {
		t.Skip("subprocess witness matrix runs once outside the race build")
	}
	tests := []struct {
		scenario      string
		wantWitnesses int
	}{
		{scenario: "trip_before_burn", wantWitnesses: 0},
		{scenario: "trip_after_burn", wantWitnesses: 0},
		{scenario: "trip_before_first", wantWitnesses: 0},
		{scenario: "trip_after_first", wantWitnesses: 1},
	}
	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			namespace, logicalNow := preparePairingGateSubprocessNamespace(t)
			result := runPairingGateSubprocess(t, namespace, test.scenario, test.scenario, logicalNow)
			if result.witnesses != test.wantWitnesses {
				t.Fatalf("external witnesses = %d, want %d; err=%v stdout=%q stderr=%s", result.witnesses, test.wantWitnesses, result.err, result.stdout, result.stderr)
			}
		})
	}
}

func TestPairingAdmissionGateSameCredential32ProcessCompetition(t *testing.T) {
	if pairingGateRaceEnabled {
		t.Skip("32-process competition runs once outside the race build")
	}
	namespace, logicalNow := preparePairingGateSubprocessNamespace(t)
	const contenders = 32
	commands := make([]*pairingGateRunningCommand, 0, contenders)
	for index := 0; index < contenders; index++ {
		command := newPairingGateSubprocessCommand(namespace, "normal", "same-credential", logicalNow)
		if err := command.command.Start(); err != nil {
			t.Fatalf("start contender %d: %v", index, err)
		}
		commands = append(commands, command)
	}
	witnesses := 0
	for index, command := range commands {
		err := command.command.Wait()
		if err != nil {
			t.Fatalf("contender %d: %v; stdout=%q stderr=%s", index, err, command.stdout.Bytes(), command.stderr.String())
		}
		witnesses += bytes.Count(command.stdout.Bytes(), pairingGateWitnessMarker)
	}
	if witnesses != 1 {
		t.Fatalf("parent-observed emissions = %d, want exactly 1", witnesses)
	}
}

func TestPairingAdmissionGateSameBundle1000ProcessRestarts(t *testing.T) {
	if pairingGateRaceEnabled {
		t.Skip("1000 process restarts run once outside the race build")
	}
	namespace, logicalNow := preparePairingGateSubprocessNamespace(t)
	const restarts = 1000
	witnesses := 0
	for restart := 0; restart < restarts; restart++ {
		result := runPairingGateSubprocess(t, namespace, "normal", "same-bundle-1000", logicalNow)
		if result.err != nil {
			t.Fatalf("restart %d: %v; stdout=%q stderr=%s", restart, result.err, result.stdout, result.stderr)
		}
		witnesses += result.witnesses
		if witnesses > 1 {
			t.Fatalf("restart %d raised parent-observed emissions to %d", restart, witnesses)
		}
	}
	if witnesses != 1 {
		t.Fatalf("parent-observed emissions across %d restarts = %d, want 1", restarts, witnesses)
	}
}

func TestPairingAdmissionGateFreshCredentialRestartWindows(t *testing.T) {
	if pairingGateRaceEnabled {
		t.Skip("fresh-credential process windows run once outside the race build")
	}
	tests := []struct {
		name      string
		attempts  int
		step      time.Duration
		wantEmits int
	}{
		{name: "one hour", attempts: 5, step: time.Minute, wantEmits: pairingAdmissionOneHourLimit},
		{name: "twenty four hours", attempts: 13, step: 61 * time.Minute, wantEmits: pairingAdmissionDayLimit},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			namespace, base := preparePairingGateSubprocessNamespace(t)
			witnesses := 0
			for index := 0; index < test.attempts; index++ {
				logicalNow := base.Add(time.Duration(index) * test.step)
				result := runPairingGateSubprocess(t, namespace, "normal", "fresh-"+strconv.Itoa(index), logicalNow)
				if result.err != nil {
					t.Fatalf("restart %d: %v; stdout=%q stderr=%s", index, result.err, result.stdout, result.stderr)
				}
				witnesses += result.witnesses
			}
			if witnesses != test.wantEmits {
				t.Fatalf("parent-observed emissions = %d, want %d", witnesses, test.wantEmits)
			}
		})
	}
}

func TestPairingAdmissionGateWitnessDetectsEmitBeforeBurnMutation(t *testing.T) {
	if pairingGateRaceEnabled {
		t.Skip("subprocess mutation runs once outside the race build")
	}
	namespace, logicalNow := preparePairingGateSubprocessNamespace(t)
	result := runPairingGateSubprocess(t, namespace, "emit_before_burn_mutation", "mutation", logicalNow)
	if err := requireZeroParentWitness(result); err == nil {
		t.Fatal("parent witness failed to detect emit-before-burn mutation")
	}
	if result.witnesses != 1 {
		t.Fatalf("mutation witnesses = %d, want detector input 1", result.witnesses)
	}
	snapshot, err := readPairingLedgerSnapshot(filepath.Join(namespace, pairingLedgerFilename), logicalNow, "", validateTestPairingLedgerFile)
	if err != nil || snapshot.sequence != 1 {
		t.Fatalf("mutation journal = sequence %d/%v, want no burn", snapshot.sequence, err)
	}
}

func preparePairingGateSubprocessNamespace(t *testing.T) (string, time.Time) {
	t.Helper()
	namespace := t.TempDir()
	logicalNow := time.Now().UTC().Truncate(time.Millisecond)
	if err := createPairingLedgerFile(filepath.Join(namespace, pairingLedgerFilename), 0o600, logicalNow, false); err != nil {
		t.Fatalf("create subprocess journal: %v", err)
	}
	prepareTestSafetyTrip(t, namespace)
	return namespace, logicalNow
}

func runPairingGateSubprocess(t *testing.T, namespace, scenario, bundle string, logicalNow time.Time) pairingGateSubprocessResult {
	t.Helper()
	running := newPairingGateSubprocessCommand(namespace, scenario, bundle, logicalNow)
	err := running.command.Run()
	return pairingGateSubprocessResult{
		witnesses: bytes.Count(running.stdout.Bytes(), pairingGateWitnessMarker),
		stdout:    append([]byte(nil), running.stdout.Bytes()...),
		stderr:    append([]byte(nil), running.stderr.Bytes()...),
		err:       err,
	}
}

type pairingGateRunningCommand struct {
	command *exec.Cmd
	stdout  bytes.Buffer
	stderr  bytes.Buffer
}

func newPairingGateSubprocessCommand(namespace, scenario, bundle string, logicalNow time.Time) *pairingGateRunningCommand {
	running := &pairingGateRunningCommand{}
	running.command = exec.Command(os.Args[0], "-test.run=^TestPairingAdmissionGateSubprocessHelper$", "-test.count=1", "-test.timeout=30s")
	running.command.Env = append(
		os.Environ(),
		pairingGateHelperEnabledEnv+"=1",
		pairingGateHelperNamespaceEnv+"="+namespace,
		pairingGateHelperScenarioEnv+"="+scenario,
		pairingGateHelperBundleEnv+"="+bundle,
		pairingGateHelperClockEnv+"="+logicalNow.Format(time.RFC3339Nano),
		pairingGateHelperWitnessEnv+"="+base64.RawStdEncoding.EncodeToString(pairingGateWitnessMarker),
	)
	running.command.Stdout = &running.stdout
	running.command.Stderr = &running.stderr
	return running
}

func requireZeroParentWitness(result pairingGateSubprocessResult) error {
	if result.witnesses != 0 {
		return fmt.Errorf("parent observed %d emission witness(es)", result.witnesses)
	}
	return nil
}
