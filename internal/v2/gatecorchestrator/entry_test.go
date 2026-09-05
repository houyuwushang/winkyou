package gatecorchestrator

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/directconnect/gateb"
	"winkyou/internal/v2/gatecattempt"
	"winkyou/internal/v2/gatecrequest"
	"winkyou/internal/v2/gatecstage"
	"winkyou/internal/v2/hardnatobserve"
	"winkyou/internal/v2/hardnatplan"
	"winkyou/internal/v2/oobcarrier"
	"winkyou/internal/v2/sshassembly"
	"winkyou/pkg/config"
	"winkyou/pkg/tunnel"
)

func TestResponderClaimImmediatelyCompetesForMachineBeforeStreamAdoption(t *testing.T) {
	now := time.Now().UTC()
	acquireErr := errors.New("synthetic machine owner conflict")
	steps := make([]string, 0, 3)
	deps := defaultDependencies()
	deps.now = func() time.Time { return now }
	deps.claimPending = func(got time.Time) (*gatecstage.Claimed, error) {
		steps = append(steps, "claim")
		if !got.Equal(now) {
			t.Fatalf("claim time=%v want=%v", got, now)
		}
		return &gatecstage.Claimed{
			Request: gatecrequest.Request{Role: gatecattempt.RoleResponder},
			Artifact: &gatecattempt.Artifact{
				LocalRole: gatecattempt.RoleResponder, PlannerProfile: hardnatplan.ProfilePredictiveEdm,
				ResourceClass: hardnatplan.ResourcePredictive,
			},
		}, nil
	}
	deps.acquireMachine = func(hardnatplan.Profile, hardnatplan.ResourceClass, string) (*governor.Governor, *governor.PairingAdmissionLedger, error) {
		steps = append(steps, "machine")
		return nil, nil, acquireErr
	}
	deps.newChildStream = func(io.Reader, io.Writer, time.Time) (oobcarrier.BoundedStream, error) {
		steps = append(steps, "stream")
		return nil, errors.New("must not adopt stream")
	}
	_, err := runResponderStdio(context.Background(), &bytes.Buffer{}, &bytes.Buffer{}, ResponderOptions{
		Config: &config.Config{}, BuildVersion: "test-build", Progress: func(Progress) error { return nil },
	}, deps)
	var failure *Failure
	if !errors.As(err, &failure) || !errors.Is(err, acquireErr) || failure.Stage != StagePreflight || failure.CredentialBurned {
		t.Fatalf("error=%v failure=%+v", err, failure)
	}
	if !reflect.DeepEqual(steps, []string{"claim", "machine"}) {
		t.Fatalf("steps=%v", steps)
	}
}

func TestResponderInvalidInvocationDoesNotConsumeStage(t *testing.T) {
	claimed := 0
	deps := defaultDependencies()
	deps.claimPending = func(time.Time) (*gatecstage.Claimed, error) {
		claimed++
		return nil, errors.New("unexpected claim")
	}
	_, err := runResponderStdio(context.Background(), nil, &bytes.Buffer{}, ResponderOptions{
		Config: &config.Config{}, BuildVersion: "test-build", Progress: func(Progress) error { return nil },
	}, deps)
	if err == nil || claimed != 0 {
		t.Fatalf("error=%v claimed=%d", err, claimed)
	}
}

func TestConflictPreflightRejectsBeforeSSHOrGateBFactory(t *testing.T) {
	privateKey, err := tunnel.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	peerPrivateKey, err := tunnel.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	configuration := config.Default()
	configuration.WireGuard.PrivateKey = privateKey.String()
	configuration.GateC.Peers = []config.GateCPeerConfig{{
		Ref: "peer", PublicKey: peerPrivateKey.PublicKey().String(), AllowedIPs: []string{"10.88.0.2/32"},
		LocalVirtualIP: "10.88.0.1", PeerVirtualIP: "10.88.0.2", MemoryInterfaceName: "wink-c1b-conflict",
		MemoryMTU: 1280, SessionCeiling: time.Minute,
	}}
	if err := configuration.Validate(); err != nil {
		t.Fatal(err)
	}
	topology := hardnatobserve.Topology{
		Primary: netip.MustParseAddrPort("203.0.113.10:3478"), Other: netip.MustParseAddrPort("203.0.113.11:3479"),
	}
	observerEndpoints, err := topology.Endpoints()
	if err != nil {
		t.Fatal(err)
	}
	sshAuthority, err := sshassembly.NewLoopbackAuthority(netip.MustParseAddrPort("127.0.0.1:2222"))
	if err != nil {
		t.Fatal(err)
	}
	input := preparedInput{
		request: gatecrequest.Request{
			Role: gatecattempt.RoleInitiator, ArtifactFile: "private-artifact.json", PeerRef: "peer",
			ExpectedPeerPublicAddress: netip.MustParseAddr("198.51.100.20"),
			ObserverSet: gatecrequest.ObserverSet{Primary: observerEndpoints[0], AlternatePort: observerEndpoints[1],
				AlternateAddress: observerEndpoints[2], AlternateAddressPort: observerEndpoints[3]},
			SSH: &gatecrequest.SSHConfig{Endpoint: netip.MustParseAddrPort("127.0.0.1:2222")},
		},
		artifact: &gatecattempt.Artifact{
			LocalRole: gatecattempt.RoleInitiator, PlannerProfile: hardnatplan.ProfilePredictiveEdm,
			ResourceClass: hardnatplan.ResourcePredictive,
		},
		configuration: &configuration, configPath: "private-config.yaml", buildVersion: "test-build",
		machine: &governor.Governor{}, ledger: &governor.PairingAdmissionLedger{}, sshAuthority: sshAuthority,
		progress: func(Progress) error { return nil },
	}

	tests := []struct {
		name  string
		state conflictState
	}{
		{"wink up", conflictState{WinkUpRunning: true}},
		{"private key", conflictState{PrivateKeyInUse: true}},
		{"interface", conflictState{InterfaceInUse: true}},
		{"route", conflictState{RouteInUse: true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sshCalls, factoryCalls := 0, 0
			deps := defaultDependencies()
			deps.inspectConflict = func(context.Context, preparedInput, trustedPeer) (conflictState, error) {
				return test.state, nil
			}
			deps.configureGateB = func(*gateb.Config) { factoryCalls++ }
			deps.openSSH = func(context.Context, sshassembly.Config) (sshProductStream, error) {
				sshCalls++
				return nil, errors.New("must not spawn")
			}
			_, runErr := runPrepared(context.Background(), input, deps)
			var failure *Failure
			if !errors.As(runErr, &failure) || failure.Class != ClassRequestInvalid || failure.Stage != StagePreflight ||
				failure.CredentialBurned || sshCalls != 0 || factoryCalls != 0 {
				t.Fatalf("error=%v failure=%+v ssh=%d factory=%d", runErr, failure, sshCalls, factoryCalls)
			}
		})
	}
}
