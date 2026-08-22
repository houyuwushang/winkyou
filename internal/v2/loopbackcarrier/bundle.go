package loopbackcarrier

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"

	"winkyou/internal/v2/pairingcontext"
	"winkyou/internal/v2/punchproto"
)

const MaxCompleteBundleBytes = 4096

var (
	ErrInvalidBundle         = errors.New("loopbackcarrier: invalid complete bundle")
	ErrNonLoopbackBlocked    = errors.New("loopbackcarrier: non-loopback endpoint blocked")
	ErrUserScopeBlocked      = errors.New("loopbackcarrier: user-acknowledged scope is not authorized")
	ErrSecretSerialization   = errors.New("loopbackcarrier: pairing secret cannot be serialized")
	ErrCredentialNotYetValid = errors.New("loopbackcarrier: pairing credential is not yet valid")
	ErrCredentialExpired     = errors.New("loopbackcarrier: pairing credential expired")
)

type wireOffer struct {
	Artifact               string        `json:"artifact"`
	Protocol               string        `json:"protocol"`
	AuthScope              string        `json:"auth_scope"`
	CredentialID           string        `json:"credential_id"`
	PairingSecret          pairingSecret `json:"pairing_secret"`
	AttemptID              string        `json:"attempt_id"`
	ObservationGeneration  string        `json:"observation_generation"`
	InitiatorParticipantID string        `json:"initiator_participant_id"`
	InitiatorGovernorScope string        `json:"initiator_governor_scope"`
	SecureChannelProfile   string        `json:"secure_channel_profile"`
	IssuedAt               string        `json:"issued_at"`
	ExpiresAt              string        `json:"expires_at"`
}

type wireAcceptance struct {
	Artifact               string `json:"artifact"`
	Protocol               string `json:"protocol"`
	AuthScope              string `json:"auth_scope"`
	CredentialID           string `json:"credential_id"`
	AttemptID              string `json:"attempt_id"`
	ObservationGeneration  string `json:"observation_generation"`
	InitiatorParticipantID string `json:"initiator_participant_id"`
	ResponderParticipantID string `json:"responder_participant_id"`
	InitiatorGovernorScope string `json:"initiator_governor_scope"`
	ResponderGovernorScope string `json:"responder_governor_scope"`
	SecureChannelProfile   string `json:"secure_channel_profile"`
	IssuedAt               string `json:"issued_at"`
	ExpiresAt              string `json:"expires_at"`
	OfferFingerprint       string `json:"offer_fingerprint"`
}

type wireCompleteBundle struct {
	LocalRole     string         `json:"local_role"`
	LocalEndpoint string         `json:"local_endpoint"`
	PeerEndpoint  string         `json:"peer_endpoint"`
	Offer         wireOffer      `json:"offer"`
	Acceptance    wireAcceptance `json:"acceptance"`
}

type pairingSecret struct {
	value [32]byte
	set   bool
}

func (secret *pairingSecret) UnmarshalJSON(payload []byte) error {
	if secret == nil {
		return ErrInvalidBundle
	}
	secret.zeroize()
	if len(payload) != base64.RawURLEncoding.EncodedLen(len(secret.value))+2 || payload[0] != '"' || payload[len(payload)-1] != '"' {
		return ErrInvalidBundle
	}
	encoded := payload[1 : len(payload)-1]
	if bytes.IndexByte(encoded, '\\') >= 0 {
		return ErrInvalidBundle
	}
	n, err := base64.RawURLEncoding.Decode(secret.value[:], encoded)
	if err != nil || n != len(secret.value) {
		secret.zeroize()
		return ErrInvalidBundle
	}
	var canonical [43]byte
	base64.RawURLEncoding.Encode(canonical[:], secret.value[:])
	valid := bytes.Equal(canonical[:], encoded)
	clear(canonical[:])
	if !valid {
		secret.zeroize()
		return ErrInvalidBundle
	}
	secret.set = true
	return nil
}

func (pairingSecret) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }
func (pairingSecret) String() string               { return "<redacted>" }
func (pairingSecret) GoString() string             { return "<redacted>" }

func (secret *pairingSecret) take() [32]byte {
	if secret == nil || !secret.set {
		return [32]byte{}
	}
	value := secret.value
	secret.zeroize()
	return value
}

func (secret *pairingSecret) zeroize() {
	if secret == nil {
		return
	}
	clear(secret.value[:])
	secret.set = false
}

type preparedBundle struct {
	role          punchproto.Role
	local         netip.AddrPort
	peer          netip.AddrPort
	peerID        string
	credentialID  string
	attemptID     string
	expiresAt     time.Time
	contextDigest string
	context       pairingcontext.PairingContext
	psk           [32]byte
}

func parseCompleteBundle(payload []byte, now time.Time) (*preparedBundle, error) {
	if len(payload) == 0 || len(payload) > MaxCompleteBundleBytes || !json.Valid(payload) {
		return nil, ErrInvalidBundle
	}
	if err := rejectDuplicateMembers(payload); err != nil {
		return nil, errors.Join(ErrInvalidBundle, err)
	}
	var wire wireCompleteBundle
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		wire.Offer.PairingSecret.zeroize()
		return nil, errors.Join(ErrInvalidBundle, err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		wire.Offer.PairingSecret.zeroize()
		return nil, errors.Join(ErrInvalidBundle, err)
	}
	bundle, err := validateWireBundle(&wire, now.UTC())
	wire.Offer.PairingSecret.zeroize()
	if err != nil {
		return nil, err
	}
	return bundle, nil
}

func validateWireBundle(wire *wireCompleteBundle, now time.Time) (*preparedBundle, error) {
	if wire == nil || !wire.Offer.PairingSecret.set {
		return nil, ErrInvalidBundle
	}
	role := punchproto.Role(wire.LocalRole)
	if !role.Valid() {
		return nil, ErrInvalidBundle
	}
	local, err := parseCanonicalEndpoint(wire.LocalEndpoint)
	if err != nil {
		return nil, errors.Join(ErrInvalidBundle, err)
	}
	peer, err := parseCanonicalEndpoint(wire.PeerEndpoint)
	if err != nil || peer == local {
		return nil, errors.Join(ErrInvalidBundle, err)
	}

	offer := &wire.Offer
	acceptance := &wire.Acceptance
	if offer.Artifact != "offer" || acceptance.Artifact != pairingcontext.PairingArtifactAcceptance ||
		offer.Protocol != pairingcontext.ProtocolVersion || acceptance.Protocol != offer.Protocol ||
		offer.AuthScope != pairingcontext.AuthScope || acceptance.AuthScope != offer.AuthScope ||
		offer.CredentialID != acceptance.CredentialID ||
		offer.AttemptID != acceptance.AttemptID ||
		offer.ObservationGeneration != "1" || acceptance.ObservationGeneration != offer.ObservationGeneration ||
		offer.InitiatorParticipantID != acceptance.InitiatorParticipantID ||
		offer.InitiatorGovernorScope != acceptance.InitiatorGovernorScope ||
		offer.SecureChannelProfile != pairingcontext.SelectedSecureChannelProfile || acceptance.SecureChannelProfile != offer.SecureChannelProfile ||
		offer.IssuedAt != acceptance.IssuedAt || offer.ExpiresAt != acceptance.ExpiresAt {
		return nil, ErrInvalidBundle
	}

	context := pairingcontext.PairingContext{
		Artifact:               acceptance.Artifact,
		Protocol:               acceptance.Protocol,
		AuthScope:              acceptance.AuthScope,
		CredentialID:           acceptance.CredentialID,
		AttemptID:              acceptance.AttemptID,
		ObservationGeneration:  acceptance.ObservationGeneration,
		InitiatorParticipantID: acceptance.InitiatorParticipantID,
		ResponderParticipantID: acceptance.ResponderParticipantID,
		InitiatorGovernorScope: acceptance.InitiatorGovernorScope,
		ResponderGovernorScope: acceptance.ResponderGovernorScope,
		SecureChannelProfile:   acceptance.SecureChannelProfile,
		IssuedAt:               acceptance.IssuedAt,
		ExpiresAt:              acceptance.ExpiresAt,
		OfferFingerprint:       acceptance.OfferFingerprint,
		InitiatorChannelRole:   pairingcontext.ChannelRoleInitiator,
		ResponderChannelRole:   pairingcontext.ChannelRoleResponder,
		EarlyData:              pairingcontext.FeatureDisabled,
		Resumption:             pairingcontext.FeatureDisabled,
		RuntimeFallback:        pairingcontext.FeatureDisabled,
	}
	canonicalContext, err := pairingcontext.CanonicalizePairingContext(context)
	if err != nil {
		return nil, errors.Join(ErrInvalidBundle, err)
	}
	defer clear(canonicalContext)
	issuedAt, err := pairingcontext.ParseCanonicalUTCSecond(context.IssuedAt)
	if err != nil {
		return nil, ErrInvalidBundle
	}
	expiresAt, err := pairingcontext.ParseCanonicalUTCSecond(context.ExpiresAt)
	if err != nil {
		return nil, ErrInvalidBundle
	}
	if now.Before(issuedAt) {
		return nil, errors.Join(ErrInvalidBundle, ErrCredentialNotYetValid)
	}
	if !now.Before(expiresAt) {
		return nil, errors.Join(ErrInvalidBundle, ErrCredentialExpired)
	}
	fingerprint, err := offerFingerprint(offer)
	if err != nil || fingerprint != acceptance.OfferFingerprint {
		return nil, ErrInvalidBundle
	}
	digest := sha256.Sum256(canonicalContext)
	peerID := acceptance.ResponderParticipantID
	if role == punchproto.RoleResponder {
		peerID = acceptance.InitiatorParticipantID
	}
	bundle := &preparedBundle{
		role:          role,
		local:         local,
		peer:          peer,
		peerID:        peerID,
		credentialID:  acceptance.CredentialID,
		attemptID:     acceptance.AttemptID,
		expiresAt:     expiresAt,
		contextDigest: hex.EncodeToString(digest[:]),
		context:       context,
		psk:           wire.Offer.PairingSecret.take(),
	}
	clear(digest[:])
	return bundle, nil
}

func (bundle *preparedBundle) requireLoopbackMachine() error {
	if bundle == nil {
		return ErrInvalidBundle
	}
	if !bundle.local.Addr().IsLoopback() || !bundle.peer.Addr().IsLoopback() {
		return ErrNonLoopbackBlocked
	}
	if bundle.context.InitiatorGovernorScope != pairingcontext.GovernorScopeMachine ||
		bundle.context.ResponderGovernorScope != pairingcontext.GovernorScopeMachine {
		return ErrUserScopeBlocked
	}
	return nil
}

func (bundle *preparedBundle) zeroize() {
	if bundle == nil {
		return
	}
	clear(bundle.psk[:])
	bundle.context = pairingcontext.PairingContext{}
	bundle.contextDigest = ""
	bundle.credentialID = ""
	bundle.attemptID = ""
	bundle.peerID = ""
}

func offerFingerprint(offer *wireOffer) (string, error) {
	if offer == nil {
		return "", ErrInvalidBundle
	}
	object := map[string]any{
		"artifact":                 offer.Artifact,
		"protocol":                 offer.Protocol,
		"auth_scope":               offer.AuthScope,
		"credential_id":            offer.CredentialID,
		"attempt_id":               offer.AttemptID,
		"observation_generation":   offer.ObservationGeneration,
		"initiator_participant_id": offer.InitiatorParticipantID,
		"initiator_governor_scope": offer.InitiatorGovernorScope,
		"secure_channel_profile":   offer.SecureChannelProfile,
		"issued_at":                offer.IssuedAt,
		"expires_at":               offer.ExpiresAt,
	}
	canonical, err := pairingcontext.CanonicalizeFlatStringObject(object)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	clear(canonical)
	encoded := base64.RawURLEncoding.EncodeToString(digest[:])
	clear(digest[:])
	return encoded, nil
}

func parseCanonicalEndpoint(value string) (netip.AddrPort, error) {
	endpoint, err := netip.ParseAddrPort(value)
	if err != nil || !endpoint.IsValid() || endpoint.Port() == 0 || endpoint.Addr().Zone() != "" || endpoint.Addr().Unmap() != endpoint.Addr() || endpoint.String() != value {
		return netip.AddrPort{}, ErrInvalidBundle
	}
	return endpoint, nil
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
				return ErrInvalidBundle
			}
			if _, exists := seen[name]; exists {
				return fmt.Errorf("duplicate member %q", name)
			}
			seen[name] = struct{}{}
			valueToken, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := scanJSONValue(decoder, valueToken); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return ErrInvalidBundle
		}
	case '[':
		for decoder.More() {
			valueToken, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := scanJSONValue(decoder, valueToken); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return ErrInvalidBundle
		}
	default:
		return ErrInvalidBundle
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return ErrInvalidBundle
		}
		return err
	}
	return nil
}
