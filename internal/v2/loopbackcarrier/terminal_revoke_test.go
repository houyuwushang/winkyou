package loopbackcarrier

import (
	"context"
	"errors"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/punchproto"
)

type terminalWitnessAuthorization struct {
	*fakeAuthorization
	onFinish func() error
}

func (a terminalWitnessAuthorization) Finish(reason governor.PairingTerminalReason) error {
	return errors.Join(a.fakeAuthorization.Finish(reason), a.onFinish())
}

type terminalErrorLease struct {
	*fakeAttemptLease
	drainErr, closeErr error
}

type terminalErrorDrain struct {
	governor.DrainHandle
	err error
}

func (d terminalErrorDrain) Complete() error {
	return errors.Join(d.DrainHandle.Complete(), d.err)
}

func (l terminalErrorLease) RegisterDrain(name string) (governor.DrainHandle, error) {
	drain, err := l.fakeAttemptLease.RegisterDrain(name)
	if err != nil {
		return nil, err
	}
	return terminalErrorDrain{drain, l.drainErr}, nil
}

func (l terminalErrorLease) Close() error {
	return errors.Join(l.fakeAttemptLease.Close(), l.closeErr)
}

func TestTerminalRevokePrecedesFinishAndPreservesEveryError(t *testing.T) {
	target := listenLoopback(t)
	defer target.Close()
	localHolder := listenLoopback(t)
	local := udpAddrPort(localHolder.LocalAddr())
	if err := localHolder.Close(); err != nil {
		t.Fatal(err)
	}
	base := newFakeAttemptLease("terminal-order-peer")
	progressErr := errors.New("synthetic progress error")
	drainErr := errors.New("synthetic revoke error")
	finishErr := errors.New("synthetic finish error")
	closeErr := errors.New("synthetic close error")
	lease := terminalErrorLease{base, drainErr, closeErr}
	finishCalls := 0
	authorization := terminalWitnessAuthorization{&fakeAuthorization{lease: base}, func() error {
		finishCalls++
		base.mu.Lock()
		drains, stopping := base.drains, base.stoppingClosed
		base.mu.Unlock()
		if drains != 0 || stopping {
			t.Errorf("FINISH must observe probe drain complete but attempt live: drains=%d stopping=%t", drains, stopping)
		}
		// This OS rebind is inside FINISH, not after carrier.run returns.
		assertEndpointReusable(t, local)
		return finishErr
	}}
	carrier := &admittedCarrier{
		authorization: authorization, attempt: lease,
		bundle:       testPreparedBundle(punchproto.RoleResponder, local, udpAddrPort(target.LocalAddr()), repeatedSecret(82)),
		buildVersion: "terminal-order-test", progress: func(ProgressStage) error { return progressErr },
	}
	defer carrier.bundle.zeroize()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_, err := carrier.run(ctx)
	for _, want := range []error{progressErr, drainErr, finishErr, closeErr, ErrCarrierTerminal} {
		if !errors.Is(err, want) {
			t.Errorf("terminal return lost %v: %v", want, err)
		}
	}
	if finishCalls != 1 || authorization.reason != governor.PairingTerminalCarrierError || authorization.finishAfterStopping || ctx.Err() != nil {
		t.Fatal("revoke error skipped FINISH, released early, or required the fixture deadline")
	}
	select {
	case <-base.Done():
	default:
		t.Fatal("final Close did not release attempt")
	}
}
