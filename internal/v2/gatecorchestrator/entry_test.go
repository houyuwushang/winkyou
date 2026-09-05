package gatecorchestrator

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/gatecattempt"
	"winkyou/internal/v2/gatecrequest"
	"winkyou/internal/v2/gatecstage"
	"winkyou/internal/v2/hardnatplan"
	"winkyou/internal/v2/oobcarrier"
	"winkyou/pkg/config"
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
