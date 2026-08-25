package directconnect

import (
	"context"
	"errors"

	"winkyou/internal/governor"
	"winkyou/internal/probeio"
	"winkyou/internal/stunobserve"
	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/rendezvouscarrier"
)

func artifactFailure(err error) error {
	class := ClassInvalidDirectArtifact
	switch {
	case errors.Is(err, directattempt.ErrCredentialNotYetValid):
		class = ClassArtifactNotYetValid
	case errors.Is(err, directattempt.ErrCredentialExpired):
		class = ClassArtifactExpired
	case errors.Is(err, directattempt.ErrUnsupportedProfile):
		class = ClassUnsupportedAttemptProfile
	}
	return preflightFailure(class, err)
}

func preflightFailure(class string, cause error) error {
	return &Failure{
		Class: class, Stage: StagePreflight, CredentialBurned: false,
		TerminalCategory: CategoryPreflightRejected, Cause: cause,
	}
}

func classifyAdmission(err error) (string, string) {
	switch {
	case errors.Is(err, governor.ErrPairingCredentialUsed):
		return ClassCredentialUsed, CategoryAdmissionBlocked
	case errors.Is(err, governor.ErrPairingAdmissionRateLimited):
		return ClassPairingRateLimited, CategoryAdmissionBlocked
	case errors.Is(err, governor.ErrPairingAdmissionCircuitOpen):
		return ClassPairingCircuitOpen, CategoryAdmissionBlocked
	case errors.Is(err, governor.ErrPairingMachineScopeRequired), errors.Is(err, governor.ErrCommittedAttemptInvalid):
		return ClassPairingScopeChanged, CategoryAdmissionBlocked
	case errors.Is(err, governor.ErrPairingLedgerIndeterminate),
		errors.Is(err, governor.ErrPairingLedgerNotInitialized),
		errors.Is(err, governor.ErrPairingLedgerCapacity),
		errors.Is(err, governor.ErrPairingLedgerClockRollback):
		return ClassLedgerIndeterminate, CategoryAdmissionBlocked
	default:
		return ClassDirectAttemptFailed, CategoryAdmissionBlocked
	}
}

func (runtime *runtime) failure(class, stage string, cause error) error {
	category := CategoryPreflightRejected
	if runtime != nil && runtime.burned {
		category = CategoryAttemptFailed
	}
	if runtime != nil && runtime.requestContext != nil && runtime.requestContext.Err() != nil &&
		(errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded)) {
		category = CategoryCancelled
	}
	if errors.Is(cause, governor.ErrSafetyTripped) || (runtime != nil && runtime.config.Machine != nil && runtime.config.Machine.Snapshot().SafetyTrip.BlocksActiveWork) {
		category = CategorySafetyTripped
	}
	return &Failure{
		Class: class, Stage: stage, CredentialBurned: runtime != nil && runtime.burned,
		TerminalCategory: category, Cause: cause,
	}
}

func (runtime *runtime) classify(stage string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrProgressDelivery) {
		return runtime.failure(ClassDirectAttemptFailed, stage, err)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		if stage == StagePunch || stage == StagePunchSent {
			return runtime.failure(ClassPunchTimeout, StagePunch, err)
		}
		return runtime.failure(ClassAttemptExpired, stage, err)
	}
	if errors.Is(err, governor.ErrSafetyTripped) {
		return runtime.failure(ClassResourceBudgetExceeded, stage, err)
	}
	if errors.Is(err, governor.ErrPairingAdmissionRejected) ||
		errors.Is(err, governor.ErrPairingCredentialUsed) ||
		errors.Is(err, governor.ErrPairingAdmissionRateLimited) ||
		errors.Is(err, governor.ErrPairingAdmissionCircuitOpen) ||
		errors.Is(err, governor.ErrPairingLedgerIndeterminate) ||
		errors.Is(err, governor.ErrPairingLedgerNotInitialized) ||
		errors.Is(err, governor.ErrPairingLedgerCapacity) ||
		errors.Is(err, governor.ErrPairingMachineScopeRequired) {
		class, category := classifyAdmission(err)
		failure := runtime.failure(class, stage, err).(*Failure)
		failure.TerminalCategory = category
		return failure
	}
	if errors.Is(err, governor.ErrCommittedAttemptInvalid) {
		failure := runtime.failure(ClassPairingScopeChanged, stage, err).(*Failure)
		failure.TerminalCategory = CategoryAdmissionBlocked
		return failure
	}
	if errors.Is(err, rendezvouscarrier.ErrDNSFailed) {
		return runtime.failure(ClassRendezvousDNSFailed, StagePreflight, err)
	}
	if errors.Is(err, rendezvouscarrier.ErrDNSAmbiguous) {
		return runtime.failure(ClassRendezvousDNSAmbiguous, StagePreflight, err)
	}
	if errors.Is(err, rendezvouscarrier.ErrTLSConfig) || errors.Is(err, rendezvouscarrier.ErrTLSHandshake) {
		return runtime.failure(ClassRendezvousTLSFailed, StagePreflight, err)
	}
	if errors.Is(err, rendezvouscarrier.ErrTargetForbidden) || errors.Is(err, rendezvouscarrier.ErrInvalidConfig) {
		return runtime.failure(ClassRendezvousEndpointInvalid, StagePreflight, err)
	}
	if errors.Is(err, rendezvouscarrier.ErrCarrierTransport) && !runtime.burned {
		return runtime.failure(ClassRendezvousUnreachable, StagePreflight, err)
	}
	if errors.Is(err, rendezvouscarrier.ErrPresenceTimeout) {
		return runtime.failure(ClassPresenceTimeout, StageTerminal, err)
	}
	if errors.Is(err, rendezvouscarrier.ErrCarrierDomain) {
		return runtime.failure(ClassCarrierDomainViolation, stage, err)
	}
	if errors.Is(err, rendezvouscarrier.ErrApplicationBudget) {
		return runtime.failure(ClassRendezvousBudgetExceeded, stage, err)
	}
	if errors.Is(err, rendezvouscarrier.ErrPreBurnSecureFrame) ||
		errors.Is(err, rendezvouscarrier.ErrHandshakeOrder) ||
		errors.Is(err, rendezvouscarrier.ErrInvalidFrame) {
		return runtime.failure(ClassRendezvousProtocol, stage, err)
	}
	if errors.Is(err, directattempt.ErrCancelled) {
		failure := runtime.failure(ClassPeerCancelled, stage, err).(*Failure)
		failure.TerminalCategory = CategoryCancelled
		return failure
	}
	if stage == StageActivated {
		return runtime.failure(ClassActivationFailed, StageActivated, err)
	}
	if stage == StageHandshake {
		return runtime.failure(ClassSecureHandshakeFailed, StageHandshake, err)
	}
	if errors.Is(err, stunobserve.ErrTimeout) {
		return runtime.failure(ClassSTUNSilent, StageSTUN, err)
	}
	if errors.Is(err, stunobserve.ErrSourceMismatch) {
		return runtime.failure(ClassSTUNSourceMismatch, StageSTUN, err)
	}
	if stage == StageSTUN && (errors.Is(err, stunobserve.ErrMagicCookieMismatch) ||
		errors.Is(err, stunobserve.ErrTransactionMismatch) ||
		errors.Is(err, stunobserve.ErrAttributeLength) ||
		errors.Is(err, stunobserve.ErrUnknownRequiredAttribute) ||
		errors.Is(err, stunobserve.ErrUnsupportedAttribute) ||
		errors.Is(err, stunobserve.ErrMappedAddressMissing) ||
		errors.Is(err, stunobserve.ErrMappedAddressInvalid) ||
		errors.Is(err, stunobserve.ErrTruncatedMessage) ||
		errors.Is(err, stunobserve.ErrMessageTooLarge) ||
		errors.Is(err, stunobserve.ErrUnexpectedMessage)) {
		return runtime.failure(ClassSTUNProtocol, StageSTUN, err)
	}
	if errors.Is(err, probeio.ErrHardLimit) || errors.Is(err, probeio.ErrResourceExhausted) ||
		errors.Is(err, probeio.ErrWriteFailures) || errors.Is(err, governor.ErrExclusiveClaimUsed) {
		return runtime.failure(ClassResourceBudgetExceeded, stage, err)
	}
	if stage == StageReady && errors.Is(err, directattempt.ErrInvalidReady) {
		return runtime.failure(ClassReadyRejected, StageReady, err)
	}
	if stage == StagePunch || stage == StagePunchSent {
		if errors.Is(err, probeio.ErrReplyRejected) || errors.Is(err, directattempt.ErrInvalidFrame) ||
			errors.Is(err, directattempt.ErrInvalidSequence) || errors.Is(err, directattempt.ErrInvalidTransition) {
			return runtime.failure(ClassDirectPacketRejected, StagePunch, err)
		}
		return runtime.failure(ClassPunchTimeout, StagePunch, err)
	}
	if stage == StageVerify {
		return runtime.failure(ClassVerificationFailed, StageVerify, err)
	}
	if stage == StagePrepare || stage == StageReady || stage == StageFire {
		if errors.Is(err, directattempt.ErrInvalidFrame) || errors.Is(err, directattempt.ErrInvalidSequence) ||
			errors.Is(err, directattempt.ErrInvalidTransition) || errors.Is(err, directattempt.ErrTerminal) {
			return runtime.failure(ClassControlAuthentication, stage, err)
		}
	}
	return runtime.failure(ClassDirectAttemptFailed, stage, err)
}

func terminalReason(err error) governor.PairingTerminalReason {
	if err == nil {
		return governor.PairingTerminalSuccess
	}
	var failure *Failure
	_ = errors.As(err, &failure)
	if failure != nil {
		switch failure.Class {
		case ClassAttemptExpired, ClassPunchTimeout, ClassSTUNSilent:
			return governor.PairingTerminalExpired
		case ClassPeerCancelled:
			return governor.PairingTerminalCancelled
		case ClassPairingScopeChanged:
			return governor.PairingTerminalScopeChanged
		case ClassRendezvousUnreachable, ClassPresenceTimeout, ClassActivationFailed:
			return governor.PairingTerminalCarrierError
		}
	}
	if errors.Is(err, context.Canceled) {
		return governor.PairingTerminalCancelled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return governor.PairingTerminalExpired
	}
	return governor.PairingTerminalProtocolError
}
