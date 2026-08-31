package sshassembly

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/gatecrequest"
	"winkyou/internal/v2/hardnatbudget"
	"winkyou/internal/v2/hardnatplan"
	"winkyou/internal/v2/pairgen"
	"winkyou/internal/v2/rendezvouswire"
)

const (
	processHelperRoleKey = "WINKYOU_C1A_PROCESS_HELPER_ROLE"
	processHelperPIDKey  = "WINKYOU_C1A_PROCESS_HELPER_PID_FILE"
)

func TestOwnedChildDiesWithParent(t *testing.T) {
	switch os.Getenv(processHelperRoleKey) {
	case "child":
		for {
			time.Sleep(time.Hour)
		}
	case "parent":
		platform, err := currentPlatform()
		if err != nil {
			t.Fatal("parent-death helper platform is unsupported")
		}
		environment, err := fixedEnvironment(platform)
		if err != nil {
			t.Fatal("parent-death helper environment is unavailable")
		}
		environment = append(environment, processHelperRoleKey+"=child")
		process, err := (execProcessRunner{}).Start(processSpec{
			executable: os.Args[0], arguments: []string{"-test.run=^TestOwnedChildDiesWithParent$"}, environment: environment,
		})
		if err != nil {
			t.Fatal("contained child failed to start")
		}
		owned, ok := process.(*execOwnedProcess)
		if !ok || owned.command == nil || owned.command.Process == nil {
			t.Fatal("contained child has no process witness")
		}
		pidFile := os.Getenv(processHelperPIDKey)
		if pidFile == "" || os.WriteFile(pidFile, []byte(strconv.Itoa(owned.command.Process.Pid)), 0o600) != nil {
			t.Fatal("contained child PID witness is unavailable")
		}
		for {
			time.Sleep(time.Hour)
		}
	}
	if _, err := currentPlatform(); err != nil {
		t.Skip("owned child parent-death containment is unsupported on this platform")
	}

	pidFile := filepath.Join(t.TempDir(), "child.pid")
	command := exec.Command(os.Args[0], "-test.run=^TestOwnedChildDiesWithParent$")
	command.Env = helperParentEnvironment(os.Environ(), pidFile)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		t.Fatal("parent-death witness helper failed to start")
	}
	parentReaped := false
	defer func() {
		if !parentReaped {
			_ = command.Process.Kill()
			_, _ = command.Process.Wait()
		}
	}()
	childPID := waitProcessHelperPID(t, pidFile)
	defer killProcessForTest(childPID)
	if err := command.Process.Kill(); err != nil {
		t.Fatal("parent-death witness could not terminate its parent helper")
	}
	_, _ = command.Process.Wait()
	parentReaped = true
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if processGoneForTest(childPID) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("contained child survived its parent process")
}

func TestOwnedProcessRunnerForcedKillLeavesNoProcess(t *testing.T) {
	if os.Getenv(processHelperRoleKey) != "" {
		t.Skip("helper subprocess")
	}
	platform, err := currentPlatform()
	if err != nil {
		t.Skip("owned child containment is unsupported on this platform")
	}
	environment, err := fixedEnvironment(platform)
	if err != nil {
		t.Fatal("contained helper environment is unavailable")
	}
	environment = append(environment, processHelperRoleKey+"=child")
	process, err := (execProcessRunner{}).Start(processSpec{
		executable: os.Args[0], arguments: []string{"-test.run=^TestOwnedChildDiesWithParent$"}, environment: environment,
	})
	if err != nil {
		t.Fatal("contained helper failed to start")
	}
	owned, ok := process.(*execOwnedProcess)
	if !ok || owned.command == nil || owned.command.Process == nil {
		t.Fatal("contained helper has no process witness")
	}
	pid := owned.command.Process.Pid
	defer killProcessForTest(pid)
	if err := process.Kill(); err != nil {
		t.Fatal("contained helper could not be force-killed")
	}
	_ = process.Wait()
	if !processGoneForTest(pid) {
		t.Fatal("force-killed contained helper left process residue")
	}
}

func helperParentEnvironment(base []string, pidFile string) []string {
	filtered := make([]string, 0, len(base)+2)
	for _, value := range base {
		if strings.HasPrefix(value, processHelperRoleKey+"=") || strings.HasPrefix(value, processHelperPIDKey+"=") {
			continue
		}
		filtered = append(filtered, value)
	}
	return append(filtered, processHelperRoleKey+"=parent", processHelperPIDKey+"="+pidFile)
}

func waitProcessHelperPID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		payload, err := os.ReadFile(path)
		if err == nil {
			pid, parseErr := strconv.Atoi(string(payload))
			clear(payload)
			if parseErr == nil && pid > 0 {
				return pid
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("contained child PID witness was not produced")
	return 0
}

func TestOrdinaryAuthorityIsLoopbackOnlyAndRequestMustMatch(t *testing.T) {
	if _, err := NewLoopbackAuthority(netip.MustParseAddrPort("203.0.113.8:22")); !errors.Is(err, ErrAuthorityInvalid) {
		t.Fatalf("non-loopback authority error=%v", err)
	}
	authority, err := NewLoopbackAuthority(netip.MustParseAddrPort("127.0.0.1:22"))
	if err != nil {
		t.Fatal(err)
	}
	local := testLocalSSHConfig(t)
	local.Endpoint = netip.MustParseAddrPort("127.0.0.1:23")
	if _, err := BindClientConfig(authority, local); !errors.Is(err, ErrProfileInvalid) {
		t.Fatalf("mismatched endpoint error=%v", err)
	}
}

func TestFixedOpenSSHArgvGoldenAndEnvironment(t *testing.T) {
	client := testClientConfig(t)
	arguments, err := buildArguments(client)
	if err != nil {
		t.Fatal(err)
	}
	for _, platform := range []Platform{PlatformWindows, PlatformLinux} {
		executable, err := executableFor(platform)
		if err != nil {
			t.Fatal(err)
		}
		environment, err := fixedEnvironment(platform)
		if err != nil {
			t.Fatal(err)
		}
		actual := "executable=" + executable + "\n" +
			"environment=" + strings.Join(environment, ";") + "\n" +
			strings.Join(normalizeArguments(arguments, client), "\n") + "\n"
		golden := filepath.Join("testdata", "ssh_argv_"+string(platform)+".golden")
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Fatalf("read %s: %v", golden, err)
		}
		if actual != strings.ReplaceAll(string(want), "\r\n", "\n") {
			t.Fatalf("%s fixed argv differs from reviewed golden", platform)
		}
	}
	joined := " " + strings.Join(arguments, " ") + " "
	for _, required := range []string{
		" -F none ", " -T ", " IdentityAgent=none ", " GlobalKnownHostsFile=none ",
		" ProxyCommand=none ", " ProxyJump=none ", " ClearAllForwardings=yes ",
		" SessionType=default ", " EscapeChar=none ", " " + FixedRemoteCommand + " ",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("fixed argv is missing reviewed option %q", required)
		}
	}
	for _, forbidden := range []string{" -L ", " -R ", " -D ", " -W ", " -N ", " -s "} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("fixed argv contains forbidden option %q", forbidden)
		}
	}
}

func TestSystemOpenSSHEffectiveConfigMatchesReviewedSubset(t *testing.T) {
	platform, err := currentPlatform()
	if err != nil {
		t.Skip(err)
	}
	executable, err := executableFor(platform)
	if err != nil || validateSystemExecutable(executable) != nil {
		t.Fatalf("reviewed system OpenSSH path unavailable on %s", platform)
	}
	client := testClientConfig(t)
	arguments, err := buildArguments(client)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, append([]string{"-G"}, arguments...)...)
	command.Env, err = fixedEnvironment(platform)
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.CombinedOutput()
	defer clear(output)
	if err != nil {
		t.Fatalf("system ssh -G rejected the reviewed fixed profile on %s with a private diagnostic", platform)
	}
	actual := normalizeEffectiveConfig(output, client)
	wantPayload, err := os.ReadFile(filepath.Join("testdata", "ssh_effective.golden"))
	if err != nil {
		t.Fatal(err)
	}
	want := strings.ReplaceAll(string(wantPayload), "\r\n", "\n")
	if actual != want {
		t.Fatalf("system ssh -G effective subset differs from reviewed golden on %s", platform)
	}
}

func TestOpenClientConsumesExclusiveLeaseAndDrainsGracefully(t *testing.T) {
	runner := &fakeRunner{behavior: echoChild}
	config, lease := testAssemblyConfig(t)
	stream, err := openClient(context.Background(), config, fakeDependencies(runner))
	if err != nil {
		t.Fatalf("openClient: %v", err)
	}
	if _, err := openClient(context.Background(), config, fakeDependencies(runner)); !errors.Is(err, governor.ErrExclusiveClaimUsed) {
		t.Fatalf("second spawn error=%v, want exclusive claim rejection", err)
	}
	payload := []byte("bounded-child-stream")
	if n, err := stream.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("Write n=%d err=%v", n, err)
	}
	read := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, read); err != nil || !bytes.Equal(read, payload) {
		t.Fatalf("ReadFull payload=%q err=%v", read, err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	witness := stream.Witness()
	if runner.Calls() != 1 || !witness.Spawned || !witness.Exited || witness.Killed || !witness.Drained ||
		witness.StdinBytes != len(payload) || witness.StdoutBytes != len(payload) || !lease.drain.completed {
		t.Fatalf("calls=%d witness=%+v drain=%+v", runner.Calls(), witness, lease.drain)
	}
}

func TestOpenClientAcceptsOnlyTheThreeExactProfileEnvelopes(t *testing.T) {
	for _, test := range []struct {
		name     string
		profile  hardnatplan.Profile
		resource hardnatplan.ResourceClass
	}{
		{"predictive", hardnatplan.ProfilePredictiveEdm, hardnatplan.ResourcePredictive},
		{"asymmetric", hardnatplan.ProfileAsymmetricBirthday, hardnatplan.ResourceAsymmetric},
		{"hard16", hardnatplan.ProfileHardBirthday, hardnatplan.ResourceHard16KLab},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := &fakeRunner{behavior: echoChild}
			config, _ := testAssemblyConfigFor(t, test.profile, test.resource)
			stream, err := openClient(context.Background(), config, fakeDependencies(runner))
			if err != nil {
				t.Fatalf("exact profile envelope rejected: %v", err)
			}
			if err := stream.Close(); err != nil || runner.Calls() != 1 || !stream.Witness().Drained {
				t.Fatal("exact profile child did not terminate with a complete drain")
			}
		})
	}
}

func TestOpenClientConsumesARealGovernorAttemptLease(t *testing.T) {
	namespace := t.TempDir()
	prepareClearSafetyTripForAssemblyTest(t, namespace)
	owner, err := governor.AcquirePreparedNamespace(namespace, governor.ScopeMachine, "gate-c1a-real-lease")
	if err != nil {
		t.Fatal("real governor owner acquisition failed")
	}
	machine, err := governor.New(owner, governor.ProfilePhase1ManualTraversal, nil)
	if err != nil {
		_ = owner.Close()
		t.Fatal("real governor construction failed")
	}
	defer machine.Close()
	peer, err := machine.AcquirePeer("gate-c1a-peer")
	if err != nil {
		t.Fatal("real governor peer lease failed")
	}
	defer peer.Close()
	envelope, err := hardnatbudget.For(hardnatplan.ProfilePredictiveEdm, hardnatplan.ResourcePredictive)
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := peer.AcquireAttempt(context.Background(), governor.AttemptRequest{
		ID: "gate-c1a-attempt", Operation: governor.OperationPrediction, Cost: envelope.Cost,
	})
	if err != nil {
		t.Fatal("real governor attempt lease failed")
	}
	defer attempt.Close()
	config := Config{
		Lease: attempt, Client: testClientConfig(t), PlannerProfile: hardnatplan.ProfilePredictiveEdm,
		ResourceClass: hardnatplan.ResourcePredictive, ActiveDeadline: time.Now().Add(19 * time.Second),
	}
	runner := &fakeRunner{behavior: echoChild}
	stream, err := openClient(context.Background(), config, fakeDependencies(runner))
	if err != nil {
		t.Fatal("real governor attempt was not accepted by the assembly")
	}
	if err := stream.Close(); err != nil || runner.Calls() != 1 || !stream.Witness().Drained {
		t.Fatal("real governor attempt child did not drain")
	}
	if snapshot := machine.Snapshot(); snapshot.ActiveAttempts != 1 || snapshot.Reserved != envelope.Cost.Resources {
		t.Fatal("assembly released or changed its caller-owned attempt reservation")
	}
}

func prepareClearSafetyTripForAssemblyTest(t *testing.T, namespace string) {
	t.Helper()
	record := governor.SafetyTripRecord{
		SchemaVersion: 1, State: governor.SafetyTripClear,
		UpdatedAt: time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC),
	}
	recordPayload, err := json.Marshal(record)
	if err != nil {
		t.Fatal("test safety record encoding failed")
	}
	checksum := sha256.Sum256(recordPayload)
	payload, err := json.Marshal(struct {
		Record   governor.SafetyTripRecord `json:"record"`
		Checksum string                    `json:"checksum"`
	}{Record: record, Checksum: hex.EncodeToString(checksum[:])})
	clear(recordPayload)
	clear(checksum[:])
	if err != nil {
		t.Fatal("test safety envelope encoding failed")
	}
	payload = append([]byte{'C'}, append(payload, '\n')...)
	defer clear(payload)
	if err := os.WriteFile(filepath.Join(namespace, "safety-trip.json"), payload, 0o600); err != nil {
		t.Fatal("test safety state initialization failed")
	}
}

func TestOpenClientRejectsCostAndExpiredAuthorityBeforeSpawn(t *testing.T) {
	runner := &fakeRunner{behavior: echoChild}
	config, lease := testAssemblyConfig(t)
	lease.request.Cost.Resources.Packets++
	if _, err := openClient(context.Background(), config, fakeDependencies(runner)); !errors.Is(err, ErrProfileInvalid) {
		t.Fatalf("cost mismatch error=%v", err)
	}
	if runner.Calls() != 0 || len(lease.claims) != 0 {
		t.Fatalf("cost mismatch reached claim/spawn: calls=%d claims=%v", runner.Calls(), lease.claims)
	}

	config, lease = testAssemblyConfig(t)
	config.ActiveDeadline = time.Now().Add(21 * time.Second)
	if _, err := openClient(context.Background(), config, fakeDependencies(runner)); !errors.Is(err, ErrProfileInvalid) {
		t.Fatalf("raised deadline error=%v", err)
	}
	if runner.Calls() != 0 || len(lease.claims) != 0 {
		t.Fatal("raised deadline reached claim/spawn")
	}
}

func TestFakeChildFramingHalfStickyAndBannerFailure(t *testing.T) {
	presence, err := rendezvouswire.PresencePayloadForProfile(
		rendezvouswire.CallerProvidedStreamProfile, "AQEBAQEBAQEBAQEBAQEBAQ", rendezvouswire.SlotA,
	)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := rendezvouswire.EncodeForProfile(rendezvouswire.CallerProvidedStreamProfile, rendezvouswire.KindPresence, presence)
	second, _ := rendezvouswire.EncodeForProfile(rendezvouswire.CallerProvidedStreamProfile, rendezvouswire.KindActivate, nil)
	runner := &fakeRunner{behavior: func(process *fakeProcess) {
		_, _ = process.stdoutWriter.Write(first[:3])
		_, _ = process.stdoutWriter.Write(append(append([]byte(nil), first[3:]...), second...))
		process.finish(nil)
	}}
	config, _ := testAssemblyConfig(t)
	stream, err := openClient(context.Background(), config, fakeDependencies(runner))
	if err != nil {
		t.Fatal(err)
	}
	decoded, _, err := rendezvouswire.DecodeForProfile(stream, rendezvouswire.CallerProvidedStreamProfile)
	if err != nil || decoded.Kind != rendezvouswire.KindPresence {
		t.Fatalf("first frame=%+v err=%v", decoded, err)
	}
	decoded, _, err = rendezvouswire.DecodeForProfile(stream, rendezvouswire.CallerProvidedStreamProfile)
	if err != nil || decoded.Kind != rendezvouswire.KindActivate {
		t.Fatalf("second frame=%+v err=%v", decoded, err)
	}
	_ = stream.Close()

	bannerRunner := &fakeRunner{behavior: func(process *fakeProcess) {
		_, _ = process.stdoutWriter.Write([]byte("unauthorized banner\n"))
		process.finish(nil)
	}}
	config, _ = testAssemblyConfig(t)
	banner, err := openClient(context.Background(), config, fakeDependencies(bannerRunner))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := rendezvouswire.DecodeForProfile(banner, rendezvouswire.CallerProvidedStreamProfile); !errors.Is(err, rendezvouswire.ErrInvalidFrame) {
		t.Fatalf("banner decode error=%v", err)
	}
	_ = banner.Close()
}

func TestFakeChildCancellationDeadlineWriterFailureAndForcedKill(t *testing.T) {
	t.Run("cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		runner := &fakeRunner{behavior: echoChild}
		config, _ := testAssemblyConfig(t)
		stream, err := openClient(ctx, config, fakeDependencies(runner))
		if err != nil {
			t.Fatal(err)
		}
		cancel()
		waitClosed(t, stream)
		if !stream.Witness().Drained {
			t.Fatal("cancelled stream did not drain")
		}
	})

	t.Run("deadline", func(t *testing.T) {
		runner := &fakeRunner{behavior: echoChild}
		config, _ := testAssemblyConfig(t)
		stream, err := openClient(context.Background(), config, fakeDependencies(runner))
		if err != nil {
			t.Fatal(err)
		}
		if err := stream.SetDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		waitClosed(t, stream)
		if !stream.Witness().Deadline || !errors.Is(stream.TerminalError(), ErrDeadline) {
			t.Fatalf("deadline witness=%+v terminal=%v", stream.Witness(), stream.TerminalError())
		}
	})

	t.Run("writer error", func(t *testing.T) {
		runner := &fakeRunner{behavior: func(process *fakeProcess) {
			_ = process.stdinReader.Close()
			<-process.killRequested
		}}
		config, _ := testAssemblyConfig(t)
		stream, err := openClient(context.Background(), config, fakeDependencies(runner))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := stream.Write([]byte("x")); !errors.Is(err, ErrChildTerminated) {
			t.Fatalf("writer error=%v", err)
		}
		_ = stream.Close()
	})

	t.Run("forced kill", func(t *testing.T) {
		runner := &fakeRunner{behavior: func(process *fakeProcess) { <-process.killRequested }}
		config, _ := testAssemblyConfig(t)
		stream, err := openClient(context.Background(), config, fakeDependencies(runner))
		if err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		if err := stream.Close(); err != nil {
			t.Fatal(err)
		}
		elapsed := time.Since(started)
		if !stream.Witness().Killed || elapsed < DrainTimeout-100*time.Millisecond || elapsed > DrainTimeout+time.Second {
			t.Fatalf("forced kill witness=%+v elapsed=%s", stream.Witness(), elapsed)
		}
	})
}

func TestStderrIsBoundedClassifiedAndNeverReturned(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		want    error
	}{
		{"host identity", []byte("Host key verification failed."), ErrHostIdentity},
		{"transport", []byte("Permission denied (publickey)."), ErrTransport},
		{"exact budget", bytes.Repeat([]byte{'x'}, MaxStderrBytes), ErrChildTerminated},
		{"overflow", bytes.Repeat([]byte{'x'}, MaxStderrBytes+1), ErrBudgetExceeded},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &fakeRunner{behavior: func(process *fakeProcess) {
				_, _ = process.stderrWriter.Write(test.payload)
				process.finish(errors.New("stable fake exit"))
			}}
			config, _ := testAssemblyConfig(t)
			stream, err := openClient(context.Background(), config, fakeDependencies(runner))
			if err != nil {
				t.Fatal(err)
			}
			waitClosed(t, stream)
			if !errors.Is(stream.TerminalError(), test.want) {
				t.Fatalf("terminal class=%v, want %v", stream.TerminalError(), test.want)
			}
			witness := stream.Witness()
			if witness.StderrBytes != len(test.payload) || !witness.Drained {
				t.Fatalf("stderr witness=%+v", witness)
			}
		})
	}
}

func normalizeArguments(arguments []string, client ClientConfig) []string {
	result := append([]string(nil), arguments...)
	for index := range result {
		result[index] = strings.ReplaceAll(result[index], client.identityFile, "<IDENTITY>")
		result[index] = strings.ReplaceAll(result[index], client.knownHostsFile, "<KNOWN_HOSTS>")
	}
	return result
}

func normalizeEffectiveConfig(output []byte, client ClientConfig) string {
	wanted := map[string]bool{
		"batchmode": true, "numberofpasswordprompts": true, "passwordauthentication": true,
		"kbdinteractiveauthentication": true, "gssapiauthentication": true, "pubkeyauthentication": true,
		"identitiesonly": true, "identityagent": true, "stricthostkeychecking": true, "updatehostkeys": true,
		"verifyhostkeydns": true, "checkhostip": true, "globalknownhostsfile": true, "controlmaster": true,
		"controlpersist": true, "proxycommand": true, "proxyjump": true, "canonicalizehostname": true,
		"clearallforwardings": true, "forwardagent": true, "forwardx11": true, "tunnel": true,
		"permitlocalcommand": true, "sessiontype": true, "escapechar": true, "connectionattempts": true,
		"connecttimeout": true, "user": true, "port": true, "hostname": true,
	}
	values := make(map[string]string, len(wanted))
	// OpenSSH omits these keys entirely when their effective value is the
	// disabled sentinel "none". The argv golden independently proves the
	// explicit overrides; normalize omission to that documented value.
	values["proxycommand"] = "none"
	values["proxyjump"] = "none"
	for _, line := range strings.Split(strings.ReplaceAll(string(output), "\r\n", "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !wanted[fields[0]] {
			continue
		}
		value := strings.Join(fields[1:], " ")
		switch value {
		case "true":
			value = "yes"
		case "false":
			value = "no"
		}
		value = strings.ReplaceAll(value, client.identityFile, "<IDENTITY>")
		value = strings.ReplaceAll(value, client.knownHostsFile, "<KNOWN_HOSTS>")
		values[fields[0]] = value
	}
	keys := make([]string, 0, len(wanted))
	for key := range wanted {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var result strings.Builder
	for _, key := range keys {
		result.WriteString(key)
		result.WriteByte('=')
		result.WriteString(values[key])
		result.WriteByte('\n')
	}
	return result.String()
}

func testClientConfig(t *testing.T) ClientConfig {
	t.Helper()
	authority, err := NewLoopbackAuthority(netip.MustParseAddrPort("127.0.0.1:22"))
	if err != nil {
		t.Fatal(err)
	}
	client, err := BindClientConfig(authority, testLocalSSHConfig(t))
	if err != nil {
		t.Fatalf("BindClientConfig: %v", err)
	}
	return client
}

func testLocalSSHConfig(t *testing.T) gatecrequest.SSHConfig {
	t.Helper()
	root := t.TempDir()
	identity := filepath.Join(root, "identity")
	knownHosts := filepath.Join(root, "known_hosts")
	if err := pairgen.WritePrivateFileExclusive(identity, []byte("synthetic-test-key-material")); err != nil {
		t.Fatalf("write identity: %v", err)
	}
	if err := pairgen.WritePrivateFileExclusive(knownHosts, []byte("[127.0.0.1]:22 ssh-ed25519 AAAAC3NzaSyntheticTestOnly")); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	return gatecrequest.SSHConfig{
		Endpoint: netip.MustParseAddrPort("127.0.0.1:22"), User: "gate-c-user",
		IdentityFile: identity, KnownHostsFile: knownHosts,
	}
}

func testAssemblyConfig(t *testing.T) (Config, *fakeLease) {
	t.Helper()
	return testAssemblyConfigFor(t, hardnatplan.ProfilePredictiveEdm, hardnatplan.ResourcePredictive)
}

func testAssemblyConfigFor(t *testing.T, profile hardnatplan.Profile, resource hardnatplan.ResourceClass) (Config, *fakeLease) {
	t.Helper()
	envelope, err := hardnatbudget.For(profile, resource)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := hardnatbudget.Operation(profile)
	if err != nil {
		t.Fatal(err)
	}
	lease := &fakeLease{
		request: governor.AttemptRequest{ID: "gate-c-test-attempt", Operation: operation, Cost: envelope.Cost},
		claims:  make(map[string]struct{}), stopping: make(chan struct{}), drain: &fakeDrain{},
	}
	active, err := hardnatbudget.ActiveDuration(profile, resource)
	if err != nil {
		t.Fatal(err)
	}
	return Config{
		Client: testClientConfig(t), PlannerProfile: profile, ResourceClass: resource,
		ActiveDeadline: time.Now().Add(active - time.Second), testLease: lease,
	}, lease
}

func fakeDependencies(runner processRunner) dependencies {
	return dependencies{now: time.Now, platform: PlatformLinux, runner: runner, validateExecutable: func(string) error { return nil }}
}

type fakeLease struct {
	mu       sync.Mutex
	request  governor.AttemptRequest
	claims   map[string]struct{}
	stopping chan struct{}
	drain    *fakeDrain
}

func (lease *fakeLease) Request() governor.AttemptRequest { return lease.request }
func (lease *fakeLease) ClaimExclusive(name string) error {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if _, exists := lease.claims[name]; exists {
		return governor.ErrExclusiveClaimUsed
	}
	lease.claims[name] = struct{}{}
	return nil
}
func (lease *fakeLease) RegisterDrain(string) (governor.DrainHandle, error) { return lease.drain, nil }
func (lease *fakeLease) Stopping() <-chan struct{}                          { return lease.stopping }

type fakeDrain struct {
	mu        sync.Mutex
	completed bool
}

func (drain *fakeDrain) Complete() error {
	drain.mu.Lock()
	drain.completed = true
	drain.mu.Unlock()
	return nil
}

type fakeRunner struct {
	mu       sync.Mutex
	specs    []processSpec
	behavior func(*fakeProcess)
}

func (runner *fakeRunner) Start(spec processSpec) (ownedProcess, error) {
	runner.mu.Lock()
	runner.specs = append(runner.specs, spec)
	runner.mu.Unlock()
	process := newFakeProcess()
	if runner.behavior != nil {
		go runner.behavior(process)
	}
	return process, nil
}

func (runner *fakeRunner) Calls() int {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return len(runner.specs)
}

type fakeProcess struct {
	stdinReader   *io.PipeReader
	stdinWriter   *io.PipeWriter
	stdoutReader  *io.PipeReader
	stdoutWriter  *io.PipeWriter
	stderrReader  *io.PipeReader
	stderrWriter  *io.PipeWriter
	done          chan struct{}
	killRequested chan struct{}
	finishOnce    sync.Once
	killOnce      sync.Once
	mu            sync.Mutex
	waitErr       error
}

func newFakeProcess() *fakeProcess {
	stdinReader, stdinWriter := io.Pipe()
	stdoutReader, stdoutWriter := io.Pipe()
	stderrReader, stderrWriter := io.Pipe()
	return &fakeProcess{
		stdinReader: stdinReader, stdinWriter: stdinWriter, stdoutReader: stdoutReader, stdoutWriter: stdoutWriter,
		stderrReader: stderrReader, stderrWriter: stderrWriter, done: make(chan struct{}), killRequested: make(chan struct{}),
	}
}

func (process *fakeProcess) Stdin() io.WriteCloser { return process.stdinWriter }
func (process *fakeProcess) Stdout() io.ReadCloser { return process.stdoutReader }
func (process *fakeProcess) Stderr() io.ReadCloser { return process.stderrReader }
func (process *fakeProcess) Wait() error {
	<-process.done
	process.mu.Lock()
	defer process.mu.Unlock()
	return process.waitErr
}
func (process *fakeProcess) Kill() error {
	process.killOnce.Do(func() { close(process.killRequested) })
	process.finish(errors.New("fake process killed"))
	return nil
}
func (process *fakeProcess) finish(err error) {
	process.finishOnce.Do(func() {
		process.mu.Lock()
		process.waitErr = err
		process.mu.Unlock()
		_ = process.stdinReader.Close()
		_ = process.stdoutWriter.Close()
		_ = process.stderrWriter.Close()
		close(process.done)
	})
}

func echoChild(process *fakeProcess) {
	_, _ = io.Copy(process.stdoutWriter, process.stdinReader)
	process.finish(nil)
}

func waitClosed(t *testing.T, stream *Stream) {
	t.Helper()
	select {
	case <-stream.closed:
	case <-time.After(3 * time.Second):
		t.Fatal("stream did not close within bounded drain")
	}
}

func TestNoParentSSHEnvironmentIsInherited(t *testing.T) {
	for _, platform := range []Platform{PlatformWindows, PlatformLinux} {
		environment, err := fixedEnvironment(platform)
		if err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(environment, "\n")
		for _, forbidden := range []string{"SSH_AUTH_SOCK", "SSH_ASKPASS", "USERPROFILE", "HOME=", "PATH="} {
			if strings.Contains(joined, forbidden) {
				t.Fatalf("%s environment contains %s", platform, forbidden)
			}
		}
	}
}
