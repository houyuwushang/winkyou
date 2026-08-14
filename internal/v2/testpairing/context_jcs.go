package testpairing

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	SelectedSecureChannelProfile = "noise-nnpsk0-25519-chachapoly-sha256/1"
	SelectedNoiseProtocolName    = "Noise_NNpsk0_25519_ChaChaPoly_SHA256"
	NoisePrologueLabel           = "winkyou test-only pairing Noise prologue v1\n"

	PairingArtifactAcceptance = "acceptance"
	ChannelRoleInitiator      = "initiator"
	ChannelRoleResponder      = "responder"
	FeatureDisabled           = "disabled"
)

var ErrInvalidFlatStringObject = errors.New("testpairing: restricted JCS requires a flat object with string values")

// PairingContext is the flat, secret-free object frozen by mini-spec section
// 4.4. Every field is a string by design; pairing_secret is intentionally not
// representable. This type is vector/context infrastructure, not a handshake.
type PairingContext struct {
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
	InitiatorChannelRole   string `json:"initiator_channel_role"`
	ResponderChannelRole   string `json:"responder_channel_role"`
	EarlyData              string `json:"early_data"`
	Resumption             string `json:"resumption"`
	RuntimeFallback        string `json:"runtime_fallback"`
}

// PairingContextFromAttempt projects the existing simulator context into the
// mini-spec field model without changing simulator validation or behavior. The
// simulation profile remains a sentinel that real artifact parsers reject.
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

// Validate checks the secret-free context fields needed by vector fixtures.
// It does not admit a carrier or authorize a cryptographic implementation.
func (context PairingContext) Validate() error {
	if context.Artifact != PairingArtifactAcceptance ||
		context.Protocol != ProtocolVersion ||
		context.AuthScope != AuthScope ||
		context.ObservationGeneration != "1" ||
		context.SecureChannelProfile != SelectedSecureChannelProfile ||
		context.InitiatorChannelRole != ChannelRoleInitiator ||
		context.ResponderChannelRole != ChannelRoleResponder ||
		context.EarlyData != FeatureDisabled ||
		context.Resumption != FeatureDisabled ||
		context.RuntimeFallback != FeatureDisabled {
		return ErrInvalidContext
	}
	identifiers := []string{
		context.CredentialID,
		context.AttemptID,
		context.InitiatorParticipantID,
		context.ResponderParticipantID,
	}
	seen := make(map[string]struct{}, len(identifiers))
	for _, identifier := range identifiers {
		if err := validateBase64URL(identifier, 16); err != nil {
			return ErrInvalidContext
		}
		if _, exists := seen[identifier]; exists {
			return ErrInvalidContext
		}
		seen[identifier] = struct{}{}
	}
	if err := validateBase64URL(context.OfferFingerprint, 32); err != nil {
		return ErrInvalidContext
	}
	if !GovernorScope(context.InitiatorGovernorScope).valid() || !GovernorScope(context.ResponderGovernorScope).valid() {
		return ErrInvalidContext
	}
	issuedAt, err := parseCanonicalUTCSecond(context.IssuedAt)
	if err != nil {
		return ErrInvalidContext
	}
	expiresAt, err := parseCanonicalUTCSecond(context.ExpiresAt)
	if err != nil {
		return ErrInvalidContext
	}
	lifetime := expiresAt.Sub(issuedAt)
	if lifetime <= 0 || lifetime > MaxPairingLifetime {
		return ErrInvalidContext
	}
	return nil
}

// Object returns a new map containing every context field. Callers own the
// map; no mutable value aliases PairingContext.
func (context PairingContext) Object() map[string]any {
	return map[string]any{
		"artifact":                 context.Artifact,
		"protocol":                 context.Protocol,
		"auth_scope":               context.AuthScope,
		"credential_id":            context.CredentialID,
		"attempt_id":               context.AttemptID,
		"observation_generation":   context.ObservationGeneration,
		"initiator_participant_id": context.InitiatorParticipantID,
		"responder_participant_id": context.ResponderParticipantID,
		"initiator_governor_scope": context.InitiatorGovernorScope,
		"responder_governor_scope": context.ResponderGovernorScope,
		"secure_channel_profile":   context.SecureChannelProfile,
		"issued_at":                context.IssuedAt,
		"expires_at":               context.ExpiresAt,
		"offer_fingerprint":        context.OfferFingerprint,
		"initiator_channel_role":   context.InitiatorChannelRole,
		"responder_channel_role":   context.ResponderChannelRole,
		"early_data":               context.EarlyData,
		"resumption":               context.Resumption,
		"runtime_fallback":         context.RuntimeFallback,
	}
}

// CanonicalizePairingContext validates and serializes one context with the
// restricted JCS implementation below.
func CanonicalizePairingContext(context PairingContext) ([]byte, error) {
	if err := context.Validate(); err != nil {
		return nil, err
	}
	return CanonicalizeFlatStringObject(context.Object())
}

// CanonicalizeFlatStringObject implements only the JCS subset required by
// PairingContext: one JSON object, UTF-8 string keys, and UTF-8 string values.
// Nested values, numbers, booleans, arrays, and null are rejected.
func CanonicalizeFlatStringObject(object map[string]any) ([]byte, error) {
	keys := make([]string, 0, len(object))
	for key, value := range object {
		if !utf8.ValidString(key) {
			return nil, ErrInvalidFlatStringObject
		}
		text, ok := value.(string)
		if !ok || !utf8.ValidString(text) {
			return nil, ErrInvalidFlatStringObject
		}
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return compareUTF16(keys[i], keys[j]) < 0
	})

	var result bytes.Buffer
	result.WriteByte('{')
	for index, key := range keys {
		if index > 0 {
			result.WriteByte(',')
		}
		appendJCSString(&result, key)
		result.WriteByte(':')
		appendJCSString(&result, object[key].(string))
	}
	result.WriteByte('}')
	return result.Bytes(), nil
}

// BuildNoisePrologue returns the exact ADR section 4.2 label followed by the
// restricted-JCS PairingContext. It performs no handshake or key operation.
func BuildNoisePrologue(context PairingContext) ([]byte, error) {
	canonical, err := CanonicalizePairingContext(context)
	if err != nil {
		return nil, err
	}
	prologue := make([]byte, 0, len(NoisePrologueLabel)+len(canonical))
	prologue = append(prologue, NoisePrologueLabel...)
	prologue = append(prologue, canonical...)
	return prologue, nil
}

func compareUTF16(left, right string) int {
	leftUnits := utf16.Encode([]rune(left))
	rightUnits := utf16.Encode([]rune(right))
	limit := len(leftUnits)
	if len(rightUnits) < limit {
		limit = len(rightUnits)
	}
	for i := 0; i < limit; i++ {
		if leftUnits[i] < rightUnits[i] {
			return -1
		}
		if leftUnits[i] > rightUnits[i] {
			return 1
		}
	}
	switch {
	case len(leftUnits) < len(rightUnits):
		return -1
	case len(leftUnits) > len(rightUnits):
		return 1
	default:
		return 0
	}
}

func appendJCSString(target *bytes.Buffer, value string) {
	target.WriteByte('"')
	for _, current := range value {
		switch current {
		case '"', '\\':
			target.WriteByte('\\')
			target.WriteRune(current)
		case '\b':
			target.WriteString("\\b")
		case '\t':
			target.WriteString("\\t")
		case '\n':
			target.WriteString("\\n")
		case '\f':
			target.WriteString("\\f")
		case '\r':
			target.WriteString("\\r")
		default:
			if current >= 0 && current <= 0x1f {
				fmt.Fprintf(target, "\\u%04x", current)
			} else {
				target.WriteRune(current)
			}
		}
	}
	target.WriteByte('"')
}

func validateBase64URL(value string, size int) error {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != size || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return ErrInvalidContext
	}
	return nil
}

func parseCanonicalUTCSecond(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Nanosecond() != 0 || parsed.Location() != time.UTC || parsed.Format(time.RFC3339) != value {
		return time.Time{}, ErrInvalidContext
	}
	return parsed, nil
}
