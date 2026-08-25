package directattempt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"winkyou/internal/v2/pairingcontext"
)

// ArtifactMaterial is the non-secret, generation-wide material shared by the
// two recipient artifacts. Callers remain responsible for obtaining every ID
// and the PSK from a cryptographically secure random source.
type ArtifactMaterial struct {
	CredentialID           string
	AttemptID              string
	InitiatorParticipantID string
	ResponderParticipantID string
	AssociationID          string
	IssuedAt               time.Time
	ExpiresAt              time.Time
}

type generatedWireArtifact struct {
	Artifact                string                 `json:"artifact"`
	DirectAttemptProfile    string                 `json:"direct_attempt_profile"`
	RendezvousProfile       string                 `json:"rendezvous_profile"`
	RendezvousAssociationID string                 `json:"rendezvous_association_id"`
	LocalRole               string                 `json:"local_role"`
	Protocol                string                 `json:"protocol"`
	AuthScope               string                 `json:"auth_scope"`
	CredentialID            string                 `json:"credential_id"`
	PairingSecret           generatedPairingSecret `json:"pairing_secret"`
	AttemptID               string                 `json:"attempt_id"`
	ObservationGeneration   string                 `json:"observation_generation"`
	InitiatorParticipantID  string                 `json:"initiator_participant_id"`
	ResponderParticipantID  string                 `json:"responder_participant_id"`
	InitiatorGovernorScope  string                 `json:"initiator_governor_scope"`
	ResponderGovernorScope  string                 `json:"responder_governor_scope"`
	SecureChannelProfile    string                 `json:"secure_channel_profile"`
	IssuedAt                string                 `json:"issued_at"`
	ExpiresAt               string                 `json:"expires_at"`
	ArtifactFingerprint     string                 `json:"artifact_fingerprint"`
}

type generatedPairingSecret [32]byte

func (secret generatedPairingSecret) MarshalJSON() ([]byte, error) {
	encoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(secret)))
	base64.RawURLEncoding.Encode(encoded, secret[:])
	payload := make([]byte, 0, len(encoded)+2)
	payload = append(payload, '"')
	payload = append(payload, encoded...)
	payload = append(payload, '"')
	clear(encoded)
	return payload, nil
}

// EncodeArtifactPair creates the two strict recipient encodings and their
// shared fingerprint. It performs no I/O and self-checks both encodings with
// ParseArtifact before returning.
func EncodeArtifactPair(material ArtifactMaterial, psk [32]byte) (initiator, responder []byte, fingerprint string, err error) {
	issuedAt := material.IssuedAt.UTC()
	expiresAt := material.ExpiresAt.UTC()
	if issuedAt.Nanosecond() != 0 || expiresAt.Nanosecond() != 0 || expiresAt.Sub(issuedAt) != 10*time.Minute {
		return nil, nil, "", ErrInvalidArtifact
	}
	identifiers := []string{
		material.CredentialID,
		material.AttemptID,
		material.InitiatorParticipantID,
		material.ResponderParticipantID,
		material.AssociationID,
	}
	seen := make(map[string]struct{}, len(identifiers))
	for _, identifier := range identifiers {
		if !validBase64URL(identifier, 16) {
			return nil, nil, "", ErrInvalidArtifact
		}
		if _, duplicate := seen[identifier]; duplicate {
			return nil, nil, "", ErrInvalidArtifact
		}
		seen[identifier] = struct{}{}
	}
	base := wireArtifact{
		Artifact: ArtifactProfile, DirectAttemptProfile: DirectAttemptProfile,
		RendezvousProfile: RendezvousPresenceProfile, RendezvousAssociationID: material.AssociationID,
		Protocol: pairingcontext.ProtocolVersion, AuthScope: pairingcontext.AuthScope,
		CredentialID: material.CredentialID, AttemptID: material.AttemptID,
		ObservationGeneration: "1", InitiatorParticipantID: material.InitiatorParticipantID,
		ResponderParticipantID: material.ResponderParticipantID,
		InitiatorGovernorScope: pairingcontext.GovernorScopeMachine,
		ResponderGovernorScope: pairingcontext.GovernorScopeMachine,
		SecureChannelProfile:   pairingcontext.SelectedSecureChannelProfile,
		IssuedAt:               issuedAt.Format(time.RFC3339), ExpiresAt: expiresAt.Format(time.RFC3339),
	}
	fingerprint, err = artifactFingerprint(&base)
	if err != nil {
		return nil, nil, "", errors.Join(ErrInvalidArtifact, err)
	}
	encode := func(role Role) ([]byte, error) {
		wire := generatedWireArtifact{
			Artifact: base.Artifact, DirectAttemptProfile: base.DirectAttemptProfile,
			RendezvousProfile: base.RendezvousProfile, RendezvousAssociationID: base.RendezvousAssociationID,
			LocalRole: string(role), Protocol: base.Protocol, AuthScope: base.AuthScope,
			CredentialID: base.CredentialID, PairingSecret: generatedPairingSecret(psk), AttemptID: base.AttemptID,
			ObservationGeneration:  base.ObservationGeneration,
			InitiatorParticipantID: base.InitiatorParticipantID,
			ResponderParticipantID: base.ResponderParticipantID,
			InitiatorGovernorScope: base.InitiatorGovernorScope,
			ResponderGovernorScope: base.ResponderGovernorScope,
			SecureChannelProfile:   base.SecureChannelProfile, IssuedAt: base.IssuedAt,
			ExpiresAt: base.ExpiresAt, ArtifactFingerprint: fingerprint,
		}
		defer clear(wire.PairingSecret[:])
		payload, err := json.Marshal(wire)
		if err != nil {
			return nil, ErrInvalidArtifact
		}
		parsed, err := ParseArtifact(payload, issuedAt)
		if err != nil || parsed.LocalRole != role {
			if parsed != nil {
				parsed.Close()
			}
			clear(payload)
			return nil, ErrInvalidArtifact
		}
		parsed.Close()
		return payload, nil
	}
	initiator, err = encode(RoleInitiator)
	if err != nil {
		return nil, nil, "", err
	}
	responder, err = encode(RoleResponder)
	if err != nil {
		clear(initiator)
		return nil, nil, "", err
	}
	return initiator, responder, fingerprint, nil
}
