package directattempt

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"winkyou/internal/v2/pairingcontext"
	"winkyou/internal/v2/rendezvouswire"
)

const (
	// ArtifactProfile is deliberately distinct from the loopback complete
	// bundle and contains no direct endpoint.
	ArtifactProfile           = "winkyou-test-direct-attempt-oob/1"
	DirectAttemptProfile      = "winkyou-test-direct-attempt-control/1"
	RendezvousPresenceProfile = rendezvouswire.PresenceProfile
	DirectNoiseBindingLabel   = "winkyou non-loopback direct-attempt binding v1\n"
	MaxArtifactBytes          = 4096
)

var (
	ErrInvalidArtifact       = errors.New("directattempt: invalid OOB artifact")
	ErrUnsupportedProfile    = errors.New("directattempt: unsupported profile")
	ErrCredentialNotYetValid = errors.New("directattempt: credential not yet valid")
	ErrCredentialExpired     = errors.New("directattempt: credential expired")
	ErrSecretUnavailable     = errors.New("directattempt: pairing secret unavailable")
)

type wireArtifact struct {
	Artifact                string        `json:"artifact"`
	DirectAttemptProfile    string        `json:"direct_attempt_profile"`
	RendezvousProfile       string        `json:"rendezvous_profile"`
	RendezvousAssociationID string        `json:"rendezvous_association_id"`
	LocalRole               string        `json:"local_role"`
	Protocol                string        `json:"protocol"`
	AuthScope               string        `json:"auth_scope"`
	CredentialID            string        `json:"credential_id"`
	PairingSecret           pairingSecret `json:"pairing_secret"`
	AttemptID               string        `json:"attempt_id"`
	ObservationGeneration   string        `json:"observation_generation"`
	InitiatorParticipantID  string        `json:"initiator_participant_id"`
	ResponderParticipantID  string        `json:"responder_participant_id"`
	InitiatorGovernorScope  string        `json:"initiator_governor_scope"`
	ResponderGovernorScope  string        `json:"responder_governor_scope"`
	SecureChannelProfile    string        `json:"secure_channel_profile"`
	IssuedAt                string        `json:"issued_at"`
	ExpiresAt               string        `json:"expires_at"`
	ArtifactFingerprint     string        `json:"artifact_fingerprint"`
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
	if len(payload) != 45 || payload[0] != '"' || payload[len(payload)-1] != '"' || bytes.IndexByte(payload[1:len(payload)-1], '\\') >= 0 {
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

// Artifact is the parsed, single-owner form of a direct-attempt OOB artifact.
// It intentionally has no local or peer direct endpoint.
type Artifact struct {
	LocalRole               Role
	RendezvousAssociationID string
	CredentialID            string
	AttemptID               string
	IssuedAt                time.Time
	ExpiresAt               time.Time
	Fingerprint             string

	context       pairingcontext.PairingContext
	contextDigest [sha256.Size]byte
	secret        [32]byte
	hasSecret     bool
}

// ParseArtifact performs strict, zero-I/O validation. Unknown profiles are a
// distinct stable rejection and never trigger negotiation or fallback.
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
	artifact, err := validateWireArtifact(&wire, now)
	wire.PairingSecret.zeroize()
	return artifact, err
}

func validateWireArtifact(wire *wireArtifact, now time.Time) (*Artifact, error) {
	if wire == nil || !wire.PairingSecret.set {
		return nil, ErrInvalidArtifact
	}
	if wire.Artifact != ArtifactProfile ||
		wire.DirectAttemptProfile != DirectAttemptProfile ||
		wire.RendezvousProfile != RendezvousPresenceProfile ||
		wire.Protocol != pairingcontext.ProtocolVersion ||
		wire.SecureChannelProfile != pairingcontext.SelectedSecureChannelProfile {
		return nil, ErrUnsupportedProfile
	}
	role := Role(wire.LocalRole)
	if !role.Valid() || wire.AuthScope != pairingcontext.AuthScope || wire.ObservationGeneration != "1" ||
		wire.InitiatorGovernorScope != pairingcontext.GovernorScopeMachine ||
		wire.ResponderGovernorScope != pairingcontext.GovernorScopeMachine {
		return nil, ErrInvalidArtifact
	}
	identifiers := []string{
		wire.CredentialID,
		wire.AttemptID,
		wire.InitiatorParticipantID,
		wire.ResponderParticipantID,
		wire.RendezvousAssociationID,
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

	context := pairingcontext.PairingContext{
		Artifact:               pairingcontext.PairingArtifactAcceptance,
		Protocol:               wire.Protocol,
		AuthScope:              wire.AuthScope,
		CredentialID:           wire.CredentialID,
		AttemptID:              wire.AttemptID,
		ObservationGeneration:  wire.ObservationGeneration,
		InitiatorParticipantID: wire.InitiatorParticipantID,
		ResponderParticipantID: wire.ResponderParticipantID,
		InitiatorGovernorScope: wire.InitiatorGovernorScope,
		ResponderGovernorScope: wire.ResponderGovernorScope,
		SecureChannelProfile:   wire.SecureChannelProfile,
		IssuedAt:               wire.IssuedAt,
		ExpiresAt:              wire.ExpiresAt,
		OfferFingerprint:       wire.ArtifactFingerprint,
		InitiatorChannelRole:   pairingcontext.ChannelRoleInitiator,
		ResponderChannelRole:   pairingcontext.ChannelRoleResponder,
		EarlyData:              pairingcontext.FeatureDisabled,
		Resumption:             pairingcontext.FeatureDisabled,
		RuntimeFallback:        pairingcontext.FeatureDisabled,
	}
	canonical, err := pairingcontext.CanonicalizePairingContext(context)
	if err != nil {
		return nil, errors.Join(ErrInvalidArtifact, err)
	}
	defer clear(canonical)
	issuedAt, err := pairingcontext.ParseCanonicalUTCSecond(wire.IssuedAt)
	if err != nil {
		return nil, ErrInvalidArtifact
	}
	expiresAt, err := pairingcontext.ParseCanonicalUTCSecond(wire.ExpiresAt)
	if err != nil {
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
		LocalRole:               role,
		RendezvousAssociationID: wire.RendezvousAssociationID,
		CredentialID:            wire.CredentialID,
		AttemptID:               wire.AttemptID,
		IssuedAt:                issuedAt,
		ExpiresAt:               expiresAt,
		Fingerprint:             wire.ArtifactFingerprint,
		context:                 context,
		contextDigest:           digest,
		secret:                  wire.PairingSecret.value,
		hasSecret:               true,
	}
	clear(digest[:])
	return artifact, nil
}

// PairingContext returns a secret-free value copy.
func (artifact *Artifact) PairingContext() (pairingcontext.PairingContext, error) {
	if artifact == nil {
		return pairingcontext.PairingContext{}, ErrInvalidArtifact
	}
	return artifact.context, nil
}

// ContextDigest returns SHA-256 over the restricted-JCS PairingContext.
func (artifact *Artifact) ContextDigest() ([sha256.Size]byte, error) {
	if artifact == nil {
		return [sha256.Size]byte{}, ErrInvalidArtifact
	}
	return artifact.contextDigest, nil
}

// TakePSK moves the single-use secret out of the parsed artifact exactly once.
func (artifact *Artifact) TakePSK() ([32]byte, error) {
	if artifact == nil || !artifact.hasSecret {
		return [32]byte{}, ErrSecretUnavailable
	}
	secret := artifact.secret
	clear(artifact.secret[:])
	artifact.hasSecret = false
	return secret, nil
}

// Close best-effort clears secret and secret-derived context ownership.
func (artifact *Artifact) Close() {
	if artifact == nil {
		return
	}
	clear(artifact.secret[:])
	clear(artifact.contextDigest[:])
	artifact.hasSecret = false
	artifact.context = pairingcontext.PairingContext{}
}

// BuildNoisePrologue binds the direct artifact, control profile, and
// rendezvous presence profile in addition to the existing PairingContext.
// The loopback prologue builder remains untouched.
func BuildNoisePrologue(context pairingcontext.PairingContext) ([]byte, error) {
	base, err := pairingcontext.BuildNoisePrologue(context)
	if err != nil {
		return nil, err
	}
	binding := DirectNoiseBindingLabel +
		"artifact=" + ArtifactProfile + "\n" +
		"control=" + DirectAttemptProfile + "\n" +
		"rendezvous=" + RendezvousPresenceProfile + "\n"
	result := make([]byte, 0, len(base)+1+len(binding))
	result = append(result, base...)
	result = append(result, '\n')
	result = append(result, binding...)
	clear(base)
	return result, nil
}

func artifactFingerprint(wire *wireArtifact) (string, error) {
	if wire == nil {
		return "", ErrInvalidArtifact
	}
	object := map[string]any{
		"artifact":                  wire.Artifact,
		"direct_attempt_profile":    wire.DirectAttemptProfile,
		"rendezvous_profile":        wire.RendezvousProfile,
		"rendezvous_association_id": wire.RendezvousAssociationID,
		"protocol":                  wire.Protocol,
		"auth_scope":                wire.AuthScope,
		"credential_id":             wire.CredentialID,
		"attempt_id":                wire.AttemptID,
		"observation_generation":    wire.ObservationGeneration,
		"initiator_participant_id":  wire.InitiatorParticipantID,
		"responder_participant_id":  wire.ResponderParticipantID,
		"initiator_governor_scope":  wire.InitiatorGovernorScope,
		"responder_governor_scope":  wire.ResponderGovernorScope,
		"secure_channel_profile":    wire.SecureChannelProfile,
		"issued_at":                 wire.IssuedAt,
		"expires_at":                wire.ExpiresAt,
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
