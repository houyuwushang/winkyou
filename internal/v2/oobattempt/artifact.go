package oobattempt

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/pairingcontext"
)

const (
	ArtifactProfile         = "winkyou-test-direct-oob-attempt/1"
	OOBCarrierProfile       = "caller-provided-bounded-stream/1"
	ObservationProfile      = "same-socket-multi-stun/1"
	ManifestProfile         = "winkyou-test-direct-oob-manifest/1"
	DirectAttemptProfile    = directattempt.OOBDirectAttemptProfile
	DirectNoiseBindingLabel = "winkyou test-only direct OOB binding v1\n"
	MaxArtifactBytes        = 4096
	MaxManifestBytes        = 4096
)

const (
	CarrierRoleInitiator = "initiator"
	CarrierRoleResponder = "responder"
)

var (
	ErrInvalidArtifact       = errors.New("oobattempt: invalid OOB artifact")
	ErrUnsupportedProfile    = errors.New("oobattempt: unsupported profile")
	ErrCredentialNotYetValid = errors.New("oobattempt: credential not yet valid")
	ErrCredentialExpired     = errors.New("oobattempt: credential expired")
	ErrSecretUnavailable     = errors.New("oobattempt: pairing secret unavailable")
	ErrInvalidManifest       = errors.New("oobattempt: invalid secret-free manifest")
)

type Role = directattempt.Role

const (
	RoleInitiator = directattempt.RoleInitiator
	RoleResponder = directattempt.RoleResponder
)

type wireArtifact struct {
	Artifact               string        `json:"artifact"`
	DirectAttemptProfile   string        `json:"direct_attempt_profile"`
	OOBCarrierProfile      string        `json:"oob_carrier_profile"`
	ObservationProfile     string        `json:"observation_profile"`
	OOBChannelID           string        `json:"oob_channel_id"`
	LocalRole              string        `json:"local_role"`
	InitiatorCarrierRole   string        `json:"initiator_carrier_role"`
	ResponderCarrierRole   string        `json:"responder_carrier_role"`
	Protocol               string        `json:"protocol"`
	AuthScope              string        `json:"auth_scope"`
	CredentialID           string        `json:"credential_id"`
	PairingSecret          pairingSecret `json:"pairing_secret"`
	AttemptID              string        `json:"attempt_id"`
	ObservationGeneration  string        `json:"observation_generation"`
	InitiatorParticipantID string        `json:"initiator_participant_id"`
	ResponderParticipantID string        `json:"responder_participant_id"`
	InitiatorGovernorScope string        `json:"initiator_governor_scope"`
	ResponderGovernorScope string        `json:"responder_governor_scope"`
	SecureChannelProfile   string        `json:"secure_channel_profile"`
	InitiatorChannelRole   string        `json:"initiator_channel_role"`
	ResponderChannelRole   string        `json:"responder_channel_role"`
	EarlyData              string        `json:"early_data"`
	Resumption             string        `json:"resumption"`
	RuntimeFallback        string        `json:"runtime_fallback"`
	IssuedAt               string        `json:"issued_at"`
	ExpiresAt              string        `json:"expires_at"`
	ArtifactFingerprint    string        `json:"artifact_fingerprint"`
}

type pairingSecret struct {
	value [32]byte
	set   bool
}

func (secret *pairingSecret) UnmarshalJSON(payload []byte) error {
	if secret == nil {
		return ErrInvalidArtifact
	}
	secret.zeroize()
	if len(payload) != 45 || payload[0] != '"' || payload[len(payload)-1] != '"' ||
		bytes.IndexByte(payload[1:len(payload)-1], '\\') >= 0 {
		return ErrInvalidArtifact
	}
	n, err := base64.RawURLEncoding.Decode(secret.value[:], payload[1:len(payload)-1])
	if err != nil || n != len(secret.value) {
		secret.zeroize()
		return ErrInvalidArtifact
	}
	var canonical [43]byte
	base64.RawURLEncoding.Encode(canonical[:], secret.value[:])
	valid := bytes.Equal(canonical[:], payload[1:len(payload)-1])
	clear(canonical[:])
	if !valid {
		secret.zeroize()
		return ErrInvalidArtifact
	}
	secret.set = true
	return nil
}

func (pairingSecret) MarshalJSON() ([]byte, error) { return nil, ErrSecretUnavailable }

func (secret *pairingSecret) zeroize() {
	if secret == nil {
		return
	}
	clear(secret.value[:])
	secret.set = false
}

// Artifact is the parsed, single-owner Gate A artifact. It deliberately has
// no endpoint, TLS, command, host, user, environment, or path member.
type Artifact struct {
	LocalRole    Role
	OOBChannelID string
	CredentialID string
	AttemptID    string
	IssuedAt     time.Time
	ExpiresAt    time.Time
	Fingerprint  string

	context       pairingcontext.PairingContext
	contextDigest [sha256.Size]byte
	secret        [32]byte
	hasSecret     bool
}

// ParseArtifact performs strict, zero-I/O validation. Unknown profiles and
// fallback values are rejected without negotiation.
func ParseArtifact(payload []byte, now time.Time) (*Artifact, error) {
	if len(payload) == 0 || len(payload) > MaxArtifactBytes || !json.Valid(payload) {
		return nil, ErrInvalidArtifact
	}
	if err := rejectDuplicateMembers(payload); err != nil {
		return nil, errors.Join(ErrInvalidArtifact, err)
	}
	var wire wireArtifact
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		wire.PairingSecret.zeroize()
		return nil, errors.Join(ErrInvalidArtifact, err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		wire.PairingSecret.zeroize()
		return nil, errors.Join(ErrInvalidArtifact, err)
	}
	artifact, err := validateWireArtifact(&wire, now.UTC())
	wire.PairingSecret.zeroize()
	return artifact, err
}

func validateWireArtifact(wire *wireArtifact, now time.Time) (*Artifact, error) {
	if wire == nil || !wire.PairingSecret.set {
		return nil, ErrInvalidArtifact
	}
	if wire.Artifact != ArtifactProfile || wire.DirectAttemptProfile != DirectAttemptProfile ||
		wire.OOBCarrierProfile != OOBCarrierProfile || wire.ObservationProfile != ObservationProfile ||
		wire.Protocol != pairingcontext.ProtocolVersion ||
		wire.SecureChannelProfile != pairingcontext.SelectedSecureChannelProfile {
		return nil, ErrUnsupportedProfile
	}
	role := Role(wire.LocalRole)
	if !role.Valid() || wire.AuthScope != pairingcontext.AuthScope || wire.ObservationGeneration != "1" ||
		wire.InitiatorGovernorScope != pairingcontext.GovernorScopeMachine ||
		wire.ResponderGovernorScope != pairingcontext.GovernorScopeMachine ||
		wire.InitiatorCarrierRole != CarrierRoleInitiator || wire.ResponderCarrierRole != CarrierRoleResponder ||
		wire.InitiatorChannelRole != pairingcontext.ChannelRoleInitiator ||
		wire.ResponderChannelRole != pairingcontext.ChannelRoleResponder ||
		wire.EarlyData != pairingcontext.FeatureDisabled || wire.Resumption != pairingcontext.FeatureDisabled ||
		wire.RuntimeFallback != pairingcontext.FeatureDisabled {
		return nil, ErrInvalidArtifact
	}
	identifiers := []string{
		wire.CredentialID,
		wire.AttemptID,
		wire.InitiatorParticipantID,
		wire.ResponderParticipantID,
		wire.OOBChannelID,
	}
	seen := make(map[string]struct{}, len(identifiers))
	for _, identifier := range identifiers {
		if !validBase64URL(identifier, 16) {
			return nil, ErrInvalidArtifact
		}
		if _, duplicate := seen[identifier]; duplicate {
			return nil, ErrInvalidArtifact
		}
		seen[identifier] = struct{}{}
	}
	if !validBase64URL(wire.ArtifactFingerprint, sha256.Size) {
		return nil, ErrInvalidArtifact
	}
	fingerprint, err := artifactFingerprint(wire)
	if err != nil || fingerprint != wire.ArtifactFingerprint {
		return nil, ErrInvalidArtifact
	}
	contextValue := pairingcontext.PairingContext{
		Artifact: pairingcontext.PairingArtifactAcceptance, Protocol: wire.Protocol, AuthScope: wire.AuthScope,
		CredentialID: wire.CredentialID, AttemptID: wire.AttemptID,
		ObservationGeneration:  wire.ObservationGeneration,
		InitiatorParticipantID: wire.InitiatorParticipantID, ResponderParticipantID: wire.ResponderParticipantID,
		InitiatorGovernorScope: wire.InitiatorGovernorScope, ResponderGovernorScope: wire.ResponderGovernorScope,
		SecureChannelProfile: wire.SecureChannelProfile, IssuedAt: wire.IssuedAt, ExpiresAt: wire.ExpiresAt,
		OfferFingerprint:     wire.ArtifactFingerprint,
		InitiatorChannelRole: wire.InitiatorChannelRole, ResponderChannelRole: wire.ResponderChannelRole,
		EarlyData: wire.EarlyData, Resumption: wire.Resumption, RuntimeFallback: wire.RuntimeFallback,
	}
	canonical, err := pairingcontext.CanonicalizePairingContext(contextValue)
	if err != nil {
		return nil, errors.Join(ErrInvalidArtifact, err)
	}
	defer clear(canonical)
	issuedAt, err := pairingcontext.ParseCanonicalUTCSecond(wire.IssuedAt)
	if err != nil {
		return nil, ErrInvalidArtifact
	}
	expiresAt, err := pairingcontext.ParseCanonicalUTCSecond(wire.ExpiresAt)
	if err != nil || expiresAt.Sub(issuedAt) != pairingcontext.MaxPairingLifetime {
		return nil, ErrInvalidArtifact
	}
	if now.Before(issuedAt) {
		return nil, errors.Join(ErrInvalidArtifact, ErrCredentialNotYetValid)
	}
	if !now.Before(expiresAt) {
		return nil, errors.Join(ErrInvalidArtifact, ErrCredentialExpired)
	}
	digest := sha256.Sum256(canonical)
	artifact := &Artifact{
		LocalRole: role, OOBChannelID: wire.OOBChannelID, CredentialID: wire.CredentialID,
		AttemptID: wire.AttemptID, IssuedAt: issuedAt, ExpiresAt: expiresAt,
		Fingerprint: wire.ArtifactFingerprint, context: contextValue, contextDigest: digest,
		secret: wire.PairingSecret.value, hasSecret: true,
	}
	clear(digest[:])
	return artifact, nil
}

func (artifact *Artifact) PairingContext() (pairingcontext.PairingContext, error) {
	if artifact == nil {
		return pairingcontext.PairingContext{}, ErrInvalidArtifact
	}
	return artifact.context, nil
}

func (artifact *Artifact) ContextDigest() ([sha256.Size]byte, error) {
	if artifact == nil {
		return [sha256.Size]byte{}, ErrInvalidArtifact
	}
	return artifact.contextDigest, nil
}

func (artifact *Artifact) TakePSK() ([32]byte, error) {
	if artifact == nil || !artifact.hasSecret {
		return [32]byte{}, ErrSecretUnavailable
	}
	secret := artifact.secret
	clear(artifact.secret[:])
	artifact.hasSecret = false
	return secret, nil
}

// NoisePrologue binds every Gate A profile, both fixed carrier roles, the
// no-fallback decision, and the one-shot OOB channel identifier.
func (artifact *Artifact) NoisePrologue() ([]byte, error) {
	if artifact == nil || !validBase64URL(artifact.OOBChannelID, 16) {
		return nil, ErrInvalidArtifact
	}
	base, err := pairingcontext.BuildNoisePrologue(artifact.context)
	if err != nil {
		return nil, err
	}
	binding := DirectNoiseBindingLabel +
		"artifact=" + ArtifactProfile + "\n" +
		"carrier=" + OOBCarrierProfile + "\n" +
		"control=" + DirectAttemptProfile + "\n" +
		"observation=" + ObservationProfile + "\n" +
		"secure_channel=" + pairingcontext.SelectedSecureChannelProfile + "\n" +
		"initiator_carrier_role=" + CarrierRoleInitiator + "\n" +
		"responder_carrier_role=" + CarrierRoleResponder + "\n" +
		"runtime_fallback=" + pairingcontext.FeatureDisabled + "\n" +
		"oob_channel_id=" + artifact.OOBChannelID + "\n"
	result := make([]byte, 0, len(base)+1+len(binding))
	result = append(result, base...)
	result = append(result, '\n')
	result = append(result, binding...)
	clear(base)
	return result, nil
}

func (artifact *Artifact) Close() {
	if artifact == nil {
		return
	}
	clear(artifact.secret[:])
	clear(artifact.contextDigest[:])
	artifact.hasSecret = false
	artifact.context = pairingcontext.PairingContext{}
}

func artifactFingerprint(wire *wireArtifact) (string, error) {
	if wire == nil {
		return "", ErrInvalidArtifact
	}
	object := map[string]any{
		"artifact": wire.Artifact, "direct_attempt_profile": wire.DirectAttemptProfile,
		"oob_carrier_profile": wire.OOBCarrierProfile, "observation_profile": wire.ObservationProfile,
		"oob_channel_id":         wire.OOBChannelID,
		"initiator_carrier_role": wire.InitiatorCarrierRole, "responder_carrier_role": wire.ResponderCarrierRole,
		"protocol": wire.Protocol, "auth_scope": wire.AuthScope, "credential_id": wire.CredentialID,
		"attempt_id": wire.AttemptID, "observation_generation": wire.ObservationGeneration,
		"initiator_participant_id": wire.InitiatorParticipantID,
		"responder_participant_id": wire.ResponderParticipantID,
		"initiator_governor_scope": wire.InitiatorGovernorScope,
		"responder_governor_scope": wire.ResponderGovernorScope,
		"secure_channel_profile":   wire.SecureChannelProfile,
		"initiator_channel_role":   wire.InitiatorChannelRole,
		"responder_channel_role":   wire.ResponderChannelRole,
		"early_data":               wire.EarlyData, "resumption": wire.Resumption,
		"runtime_fallback": wire.RuntimeFallback, "issued_at": wire.IssuedAt, "expires_at": wire.ExpiresAt,
	}
	canonical, err := pairingcontext.CanonicalizeFlatStringObject(object)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	clear(canonical)
	result := base64.RawURLEncoding.EncodeToString(digest[:])
	clear(digest[:])
	return result, nil
}

func validBase64URL(value string, size int) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	valid := err == nil && len(decoded) == size && base64.RawURLEncoding.EncodeToString(decoded) == value
	clear(decoded)
	return valid
}

func rejectDuplicateMembers(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil {
		return err
	}
	if err := scanJSONValue(decoder, first); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func scanJSONValue(decoder *json.Decoder, token json.Token) error {
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			nameToken, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := nameToken.(string)
			if !ok {
				return ErrInvalidArtifact
			}
			if _, duplicate := seen[name]; duplicate {
				return fmt.Errorf("duplicate member %q", name)
			}
			seen[name] = struct{}{}
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := scanJSONValue(decoder, value); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return ErrInvalidArtifact
		}
	case '[':
		for decoder.More() {
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := scanJSONValue(decoder, value); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return ErrInvalidArtifact
		}
	default:
		return ErrInvalidArtifact
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return ErrInvalidArtifact
		}
		return err
	}
	return nil
}
