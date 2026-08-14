package testpairing

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRestrictedJCSSortsUTF16AndUsesJSONEscaping(t *testing.T) {
	canonical, err := CanonicalizeFlatStringObject(map[string]any{
		"\ue000":     "bmp",
		"\U00010000": "astral",
		"value":      "\"\\\b\t\n\f\r\x00\x1f<>&\u2028",
	})
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	want := "{\"value\":\"\\\"\\\\\\b\\t\\n\\f\\r\\u0000\\u001f<>&\u2028\",\"\U00010000\":\"astral\",\"\ue000\":\"bmp\"}"
	if string(canonical) != want {
		t.Fatalf("canonical = %q\nwant      = %q", canonical, want)
	}
	if bytes.Contains(canonical, []byte(`\u2028`)) || bytes.Contains(canonical, []byte(`\u003c`)) {
		t.Fatalf("canonical string used non-JCS escaping: %s", canonical)
	}
}

func TestRestrictedJCSMatchesRFC8785PropertyOrder(t *testing.T) {
	canonical, err := CanonicalizeFlatStringObject(map[string]any{
		"\u20ac":     "Euro Sign",
		"\r":         "Carriage Return",
		"\ufb33":     "Hebrew Letter Dalet With Dagesh",
		"1":          "One",
		"\U0001f600": "Emoji: Grinning Face",
		"\u0080":     "Control",
		"\u00f6":     "Latin Small Letter O With Diaeresis",
	})
	if err != nil {
		t.Fatalf("canonicalize RFC property sample: %v", err)
	}
	wantedKeys := []string{"\r", "1", "\u0080", "\u00f6", "\u20ac", "\U0001f600", "\ufb33"}
	previous := -1
	for _, key := range wantedKeys {
		encodedKey, err := CanonicalizeFlatStringObject(map[string]any{key: "value"})
		if err != nil {
			t.Fatalf("encode key %q: %v", key, err)
		}
		colon := bytes.IndexByte(encodedKey, ':')
		position := bytes.Index(canonical, encodedKey[1:colon])
		if position <= previous {
			t.Fatalf("RFC property order drift for %q in %s", key, canonical)
		}
		previous = position
	}
}

func TestRestrictedJCSRejectsNestedNonStringAndInvalidUTF8(t *testing.T) {
	invalidUTF8 := string([]byte{0xff})
	tests := []map[string]any{
		{"nested": map[string]any{"value": "x"}},
		{"number": 1},
		{"boolean": true},
		{"null": nil},
		{"array": []string{"x"}},
		{invalidUTF8: "value"},
		{"value": invalidUTF8},
	}
	for _, object := range tests {
		if _, err := CanonicalizeFlatStringObject(object); !errors.Is(err, ErrInvalidFlatStringObject) {
			t.Fatalf("object %#v error = %v, want restricted-JCS rejection", object, err)
		}
	}
}

func TestPairingContextProjectionAlignsSimulatorWithoutChangingIt(t *testing.T) {
	attempt := testAttempt(time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC))
	fingerprint := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32))
	context := PairingContextFromAttempt(attempt, fingerprint)

	if context.SecureChannelProfile != SimulationSecureChannelProfile ||
		context.InitiatorChannelRole != ChannelRoleInitiator ||
		context.ResponderChannelRole != ChannelRoleResponder ||
		context.EarlyData != FeatureDisabled ||
		context.Resumption != FeatureDisabled ||
		context.RuntimeFallback != FeatureDisabled {
		t.Fatalf("fixed context fields = %+v", context)
	}
	if attempt.SecureChannelProfile != SimulationSecureChannelProfile || attempt.ObservationGeneration != 1 {
		t.Fatalf("projection changed simulator input: %+v", attempt)
	}
	if err := context.Validate(); !errors.Is(err, ErrInvalidContext) {
		t.Fatalf("simulation profile validation = %v, want real-artifact rejection", err)
	}
}

func TestPairingContextAndPrologueGolden(t *testing.T) {
	context := syntheticPairingContext()
	canonical, err := CanonicalizePairingContext(context)
	if err != nil {
		t.Fatalf("canonicalize context: %v", err)
	}
	want, err := os.ReadFile("testdata/pairing_context.golden.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
	want = bytes.TrimSuffix(want, []byte("\n"))
	if !bytes.Equal(canonical, want) {
		t.Fatalf("pairing context changed\ngot:  %s\nwant: %s", canonical, want)
	}
	prologue, err := BuildNoisePrologue(context)
	if err != nil {
		t.Fatalf("build prologue: %v", err)
	}
	if !bytes.Equal(prologue, append([]byte(NoisePrologueLabel), canonical...)) {
		t.Fatalf("prologue does not equal exact label || JCS(context)")
	}
}

func TestPairingContextValidationRejectsFieldDrift(t *testing.T) {
	tests := []struct {
		name string
		edit func(*PairingContext)
	}{
		{name: "profile", edit: func(context *PairingContext) { context.SecureChannelProfile = SimulationSecureChannelProfile }},
		{name: "role", edit: func(context *PairingContext) { context.InitiatorChannelRole = "responder" }},
		{name: "feature", edit: func(context *PairingContext) { context.EarlyData = "enabled" }},
		{name: "generation", edit: func(context *PairingContext) { context.ObservationGeneration = "2" }},
		{name: "secret-shaped extra impossible", edit: func(context *PairingContext) { context.OfferFingerprint = "pairing_secret" }},
		{name: "timestamp offset", edit: func(context *PairingContext) { context.IssuedAt = "2026-08-14T08:00:00+08:00" }},
		{name: "lifetime", edit: func(context *PairingContext) { context.ExpiresAt = "2026-08-14T00:11:00Z" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			context := syntheticPairingContext()
			test.edit(&context)
			if err := context.Validate(); !errors.Is(err, ErrInvalidContext) {
				t.Fatalf("validate = %v, want invalid context", err)
			}
		})
	}
}

func syntheticPairingContext() PairingContext {
	return PairingContext{
		Artifact:               PairingArtifactAcceptance,
		Protocol:               ProtocolVersion,
		AuthScope:              AuthScope,
		CredentialID:           repeatedBase64URL(1, 16),
		AttemptID:              repeatedBase64URL(2, 16),
		ObservationGeneration:  "1",
		InitiatorParticipantID: repeatedBase64URL(3, 16),
		ResponderParticipantID: repeatedBase64URL(4, 16),
		InitiatorGovernorScope: string(GovernorScopeMachine),
		ResponderGovernorScope: string(GovernorScopeUserAcknowledged),
		SecureChannelProfile:   SelectedSecureChannelProfile,
		IssuedAt:               "2026-08-14T00:00:00Z",
		ExpiresAt:              "2026-08-14T00:05:00Z",
		OfferFingerprint:       repeatedBase64URL(5, 32),
		InitiatorChannelRole:   ChannelRoleInitiator,
		ResponderChannelRole:   ChannelRoleResponder,
		EarlyData:              FeatureDisabled,
		Resumption:             FeatureDisabled,
		RuntimeFallback:        FeatureDisabled,
	}
}

func repeatedBase64URL(value byte, size int) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{value}, size))
}

func normalizedJSON(payload []byte) []byte {
	return []byte(strings.ReplaceAll(string(payload), "\r\n", "\n"))
}
