package pairingcontext

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	ProtocolVersion              = "winkyou-test-pairing/1"
	AuthScope                    = "test_only"
	SelectedSecureChannelProfile = "noise-nnpsk0-25519-chachapoly-sha256/1"
	SelectedNoiseProtocolName    = "Noise_NNpsk0_25519_ChaChaPoly_SHA256"
	NoisePrologueLabel           = "winkyou test-only pairing Noise prologue v1\n"

	PairingArtifactAcceptance = "acceptance"
	ChannelRoleInitiator      = "initiator"
	ChannelRoleResponder      = "responder"
	FeatureDisabled           = "disabled"
	GovernorScopeMachine      = "machine"
	GovernorScopeUser         = "user_acknowledged"

	MaxPairingLifetime = 10 * time.Minute
)

var (
	// ErrInvalidContext keeps the legacy testpairing text because that package
	// now aliases this sentinel while existing callers still rely on it.
	ErrInvalidContext          = errors.New("testpairing: invalid attempt context")
	ErrInvalidFlatStringObject = errors.New("pairingcontext: restricted JCS requires a flat object with string values")
)

// PairingContext is the flat, secret-free object frozen by mini-spec section
// 4.4. Every field is a string; pairing_secret is intentionally not
// representable.
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
	if !validGovernorScope(context.InitiatorGovernorScope) || !validGovernorScope(context.ResponderGovernorScope) {
		return ErrInvalidContext
	}
	issuedAt, err := ParseCanonicalUTCSecond(context.IssuedAt)
	if err != nil {
		return ErrInvalidContext
	}
	expiresAt, err := ParseCanonicalUTCSecond(context.ExpiresAt)
	if err != nil {
		return ErrInvalidContext
	}
	lifetime := expiresAt.Sub(issuedAt)
	if lifetime <= 0 || lifetime > MaxPairingLifetime {
		return ErrInvalidContext
	}
	return nil
}

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

func CanonicalizePairingContext(context PairingContext) ([]byte, error) {
	if err := context.Validate(); err != nil {
		return nil, err
	}
	return CanonicalizeFlatStringObject(context.Object())
}

// CanonicalizeFlatStringObject implements only the JCS subset required by
// PairingContext: one object with UTF-8 string keys and string values.
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

func BuildNoisePrologue(context PairingContext) ([]byte, error) {
	canonical, err := CanonicalizePairingContext(context)
	if err != nil {
		return nil, err
	}
	prologue := make([]byte, 0, len(NoisePrologueLabel)+len(canonical))
	prologue = append(prologue, NoisePrologueLabel...)
	prologue = append(prologue, canonical...)
	clear(canonical)
	return prologue, nil
}

func ParseCanonicalUTCSecond(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Nanosecond() != 0 || parsed.Location() != time.UTC || parsed.Format(time.RFC3339) != value {
		return time.Time{}, ErrInvalidContext
	}
	return parsed, nil
}

func validGovernorScope(scope string) bool {
	return scope == GovernorScopeMachine || scope == GovernorScopeUser
}

func compareUTF16(left, right string) int {
	leftUnits := utf16.Encode([]rune(left))
	rightUnits := utf16.Encode([]rune(right))
	limit := len(leftUnits)
	if len(rightUnits) < limit {
		limit = len(rightUnits)
	}
	for index := 0; index < limit; index++ {
		if leftUnits[index] < rightUnits[index] {
			return -1
		}
		if leftUnits[index] > rightUnits[index] {
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
	valid := err == nil && len(decoded) == size && base64.RawURLEncoding.EncodeToString(decoded) == value
	clear(decoded)
	if !valid {
		return ErrInvalidContext
	}
	return nil
}
