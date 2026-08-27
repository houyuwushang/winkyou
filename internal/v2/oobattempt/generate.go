package oobattempt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"winkyou/internal/v2/pairingcontext"
)

type ArtifactMaterial struct {
	CredentialID           string
	AttemptID              string
	InitiatorParticipantID string
	ResponderParticipantID string
	OOBChannelID           string
	IssuedAt               time.Time
	ExpiresAt              time.Time
}

// ArtifactSet is the in-memory representation of the three offline files.
// Gate A deliberately performs no filesystem or clipboard I/O.
type ArtifactSet struct {
	Initiator []byte
	Responder []byte
	Manifest  []byte
}

func (set *ArtifactSet) Close() {
	if set == nil {
		return
	}
	clear(set.Initiator)
	clear(set.Responder)
	clear(set.Manifest)
	set.Initiator = nil
	set.Responder = nil
	set.Manifest = nil
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

type generatedWireArtifact struct {
	Artifact               string                 `json:"artifact"`
	DirectAttemptProfile   string                 `json:"direct_attempt_profile"`
	OOBCarrierProfile      string                 `json:"oob_carrier_profile"`
	ObservationProfile     string                 `json:"observation_profile"`
	OOBChannelID           string                 `json:"oob_channel_id"`
	LocalRole              string                 `json:"local_role"`
	InitiatorCarrierRole   string                 `json:"initiator_carrier_role"`
	ResponderCarrierRole   string                 `json:"responder_carrier_role"`
	Protocol               string                 `json:"protocol"`
	AuthScope              string                 `json:"auth_scope"`
	CredentialID           string                 `json:"credential_id"`
	PairingSecret          generatedPairingSecret `json:"pairing_secret"`
	AttemptID              string                 `json:"attempt_id"`
	ObservationGeneration  string                 `json:"observation_generation"`
	InitiatorParticipantID string                 `json:"initiator_participant_id"`
	ResponderParticipantID string                 `json:"responder_participant_id"`
	InitiatorGovernorScope string                 `json:"initiator_governor_scope"`
	ResponderGovernorScope string                 `json:"responder_governor_scope"`
	SecureChannelProfile   string                 `json:"secure_channel_profile"`
	InitiatorChannelRole   string                 `json:"initiator_channel_role"`
	ResponderChannelRole   string                 `json:"responder_channel_role"`
	EarlyData              string                 `json:"early_data"`
	Resumption             string                 `json:"resumption"`
	RuntimeFallback        string                 `json:"runtime_fallback"`
	IssuedAt               string                 `json:"issued_at"`
	ExpiresAt              string                 `json:"expires_at"`
	ArtifactFingerprint    string                 `json:"artifact_fingerprint"`
}

type Manifest struct {
	Schema               string `json:"schema"`
	ArtifactProfile      string `json:"artifact_profile"`
	DirectAttemptProfile string `json:"direct_attempt_profile"`
	OOBCarrierProfile    string `json:"oob_carrier_profile"`
	ObservationProfile   string `json:"observation_profile"`
	SecureChannelProfile string `json:"secure_channel_profile"`
	RuntimeFallback      string `json:"runtime_fallback"`
	CredentialID         string `json:"credential_id"`
	AttemptID            string `json:"attempt_id"`
	OOBChannelID         string `json:"oob_channel_id"`
	IssuedAt             string `json:"issued_at"`
	ExpiresAt            string `json:"expires_at"`
	ArtifactFingerprint  string `json:"artifact_fingerprint"`
}

func EncodeArtifactSet(material ArtifactMaterial, psk [32]byte) (set ArtifactSet, err error) {
	issuedAt := material.IssuedAt.UTC()
	expiresAt := material.ExpiresAt.UTC()
	if issuedAt.Nanosecond() != 0 || expiresAt.Nanosecond() != 0 || expiresAt.Sub(issuedAt) != pairingcontext.MaxPairingLifetime {
		return ArtifactSet{}, ErrInvalidArtifact
	}
	identifiers := []string{material.CredentialID, material.AttemptID, material.InitiatorParticipantID, material.ResponderParticipantID, material.OOBChannelID}
	seen := make(map[string]struct{}, len(identifiers))
	for _, identifier := range identifiers {
		if !validBase64URL(identifier, 16) {
			return ArtifactSet{}, ErrInvalidArtifact
		}
		if _, duplicate := seen[identifier]; duplicate {
			return ArtifactSet{}, ErrInvalidArtifact
		}
		seen[identifier] = struct{}{}
	}
	base := wireArtifact{
		Artifact: ArtifactProfile, DirectAttemptProfile: DirectAttemptProfile,
		OOBCarrierProfile: OOBCarrierProfile, ObservationProfile: ObservationProfile,
		OOBChannelID:         material.OOBChannelID,
		InitiatorCarrierRole: CarrierRoleInitiator, ResponderCarrierRole: CarrierRoleResponder,
		Protocol: pairingcontext.ProtocolVersion, AuthScope: pairingcontext.AuthScope,
		CredentialID: material.CredentialID, AttemptID: material.AttemptID,
		ObservationGeneration: "1", InitiatorParticipantID: material.InitiatorParticipantID,
		ResponderParticipantID: material.ResponderParticipantID,
		InitiatorGovernorScope: pairingcontext.GovernorScopeMachine,
		ResponderGovernorScope: pairingcontext.GovernorScopeMachine,
		SecureChannelProfile:   pairingcontext.SelectedSecureChannelProfile,
		InitiatorChannelRole:   pairingcontext.ChannelRoleInitiator,
		ResponderChannelRole:   pairingcontext.ChannelRoleResponder,
		EarlyData:              pairingcontext.FeatureDisabled, Resumption: pairingcontext.FeatureDisabled,
		RuntimeFallback: pairingcontext.FeatureDisabled,
		IssuedAt:        issuedAt.Format(time.RFC3339), ExpiresAt: expiresAt.Format(time.RFC3339),
	}
	fingerprint, fingerprintErr := artifactFingerprint(&base)
	if fingerprintErr != nil {
		return ArtifactSet{}, errors.Join(ErrInvalidArtifact, fingerprintErr)
	}
	encode := func(role Role) ([]byte, error) {
		wire := generatedWireArtifact{
			Artifact: base.Artifact, DirectAttemptProfile: base.DirectAttemptProfile,
			OOBCarrierProfile: base.OOBCarrierProfile, ObservationProfile: base.ObservationProfile,
			OOBChannelID: base.OOBChannelID, LocalRole: string(role),
			InitiatorCarrierRole: base.InitiatorCarrierRole, ResponderCarrierRole: base.ResponderCarrierRole,
			Protocol: base.Protocol, AuthScope: base.AuthScope, CredentialID: base.CredentialID,
			PairingSecret: generatedPairingSecret(psk), AttemptID: base.AttemptID,
			ObservationGeneration:  base.ObservationGeneration,
			InitiatorParticipantID: base.InitiatorParticipantID, ResponderParticipantID: base.ResponderParticipantID,
			InitiatorGovernorScope: base.InitiatorGovernorScope, ResponderGovernorScope: base.ResponderGovernorScope,
			SecureChannelProfile: base.SecureChannelProfile,
			InitiatorChannelRole: base.InitiatorChannelRole, ResponderChannelRole: base.ResponderChannelRole,
			EarlyData: base.EarlyData, Resumption: base.Resumption, RuntimeFallback: base.RuntimeFallback,
			IssuedAt: base.IssuedAt, ExpiresAt: base.ExpiresAt, ArtifactFingerprint: fingerprint,
		}
		defer clear(wire.PairingSecret[:])
		payload, marshalErr := json.Marshal(wire)
		if marshalErr != nil {
			return nil, ErrInvalidArtifact
		}
		parsed, parseErr := ParseArtifact(payload, issuedAt)
		if parseErr != nil || parsed.LocalRole != role {
			if parsed != nil {
				parsed.Close()
			}
			clear(payload)
			return nil, ErrInvalidArtifact
		}
		parsed.Close()
		return payload, nil
	}
	set.Initiator, err = encode(RoleInitiator)
	if err != nil {
		return ArtifactSet{}, err
	}
	set.Responder, err = encode(RoleResponder)
	if err != nil {
		clear(set.Initiator)
		return ArtifactSet{}, err
	}
	manifest := Manifest{
		Schema: ManifestProfile, ArtifactProfile: ArtifactProfile, DirectAttemptProfile: DirectAttemptProfile,
		OOBCarrierProfile: OOBCarrierProfile, ObservationProfile: ObservationProfile,
		SecureChannelProfile: pairingcontext.SelectedSecureChannelProfile,
		RuntimeFallback:      pairingcontext.FeatureDisabled, CredentialID: material.CredentialID,
		AttemptID: material.AttemptID, OOBChannelID: material.OOBChannelID,
		IssuedAt: base.IssuedAt, ExpiresAt: base.ExpiresAt, ArtifactFingerprint: fingerprint,
	}
	set.Manifest, err = json.Marshal(manifest)
	if err != nil {
		set.Close()
		return ArtifactSet{}, ErrInvalidManifest
	}
	if _, err = ParseManifest(set.Manifest); err != nil {
		set.Close()
		return ArtifactSet{}, err
	}
	return set, nil
}

func ParseManifest(payload []byte) (Manifest, error) {
	if len(payload) == 0 || len(payload) > MaxManifestBytes || !json.Valid(payload) || rejectDuplicateMembers(payload) != nil {
		return Manifest{}, ErrInvalidManifest
	}
	var manifest Manifest
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil || requireJSONEOF(decoder) != nil {
		return Manifest{}, ErrInvalidManifest
	}
	if manifest.Schema != ManifestProfile || manifest.ArtifactProfile != ArtifactProfile ||
		manifest.DirectAttemptProfile != DirectAttemptProfile || manifest.OOBCarrierProfile != OOBCarrierProfile ||
		manifest.ObservationProfile != ObservationProfile ||
		manifest.SecureChannelProfile != pairingcontext.SelectedSecureChannelProfile ||
		manifest.RuntimeFallback != pairingcontext.FeatureDisabled ||
		!validBase64URL(manifest.CredentialID, 16) || !validBase64URL(manifest.AttemptID, 16) ||
		!validBase64URL(manifest.OOBChannelID, 16) || !validBase64URL(manifest.ArtifactFingerprint, 32) {
		return Manifest{}, ErrInvalidManifest
	}
	seen := map[string]struct{}{}
	for _, identifier := range []string{manifest.CredentialID, manifest.AttemptID, manifest.OOBChannelID} {
		if _, duplicate := seen[identifier]; duplicate {
			return Manifest{}, ErrInvalidManifest
		}
		seen[identifier] = struct{}{}
	}
	issued, issuedErr := pairingcontext.ParseCanonicalUTCSecond(manifest.IssuedAt)
	expires, expiresErr := pairingcontext.ParseCanonicalUTCSecond(manifest.ExpiresAt)
	if issuedErr != nil || expiresErr != nil || expires.Sub(issued) != pairingcontext.MaxPairingLifetime {
		return Manifest{}, ErrInvalidManifest
	}
	return manifest, nil
}
