package testpairing

import (
	"strconv"
	"time"

	"winkyou/internal/v2/pairingcontext"
)

const (
	SelectedSecureChannelProfile = pairingcontext.SelectedSecureChannelProfile
	SelectedNoiseProtocolName    = pairingcontext.SelectedNoiseProtocolName
	NoisePrologueLabel           = pairingcontext.NoisePrologueLabel

	PairingArtifactAcceptance = pairingcontext.PairingArtifactAcceptance
	ChannelRoleInitiator      = pairingcontext.ChannelRoleInitiator
	ChannelRoleResponder      = pairingcontext.ChannelRoleResponder
	FeatureDisabled           = pairingcontext.FeatureDisabled
)

var ErrInvalidFlatStringObject = pairingcontext.ErrInvalidFlatStringObject

type PairingContext = pairingcontext.PairingContext

// PairingContextFromAttempt adapts the simulation context to the shared,
// secret-free pairing context without granting the simulator carrier authority.
func PairingContextFromAttempt(attempt AttemptContext, offerFingerprint string) PairingContext {
	return PairingContext{
		Artifact:               PairingArtifactAcceptance,
		Protocol:               attempt.Protocol,
		AuthScope:              attempt.AuthScope,
		CredentialID:           attempt.CredentialID,
		AttemptID:              attempt.AttemptID,
		ObservationGeneration:  strconv.FormatUint(attempt.ObservationGeneration, 10),
		InitiatorParticipantID: attempt.InitiatorParticipantID,
		ResponderParticipantID: attempt.ResponderParticipantID,
		InitiatorGovernorScope: string(attempt.InitiatorGovernorScope),
		ResponderGovernorScope: string(attempt.ResponderGovernorScope),
		SecureChannelProfile:   attempt.SecureChannelProfile,
		IssuedAt:               attempt.IssuedAt.Format(time.RFC3339),
		ExpiresAt:              attempt.ExpiresAt.Format(time.RFC3339),
		OfferFingerprint:       offerFingerprint,
		InitiatorChannelRole:   ChannelRoleInitiator,
		ResponderChannelRole:   ChannelRoleResponder,
		EarlyData:              FeatureDisabled,
		Resumption:             FeatureDisabled,
		RuntimeFallback:        FeatureDisabled,
	}
}

func CanonicalizePairingContext(context PairingContext) ([]byte, error) {
	return pairingcontext.CanonicalizePairingContext(context)
}

func CanonicalizeFlatStringObject(object map[string]any) ([]byte, error) {
	return pairingcontext.CanonicalizeFlatStringObject(object)
}

func BuildNoisePrologue(context PairingContext) ([]byte, error) {
	return pairingcontext.BuildNoisePrologue(context)
}
