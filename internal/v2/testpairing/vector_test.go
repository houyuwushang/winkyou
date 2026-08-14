package testpairing

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestSyntheticNoiseVectorFixtureParsesWithoutCrypto(t *testing.T) {
	payload := readSyntheticVector(t)
	vector, err := ParseNoiseVector(payload)
	if err != nil {
		t.Fatalf("parse synthetic vector: %v", err)
	}
	if vector.PairingContext != syntheticPairingContext() {
		t.Fatalf("fixture context = %+v", vector.PairingContext)
	}
	if vector.Profile != SelectedSecureChannelProfile || vector.NoiseProtocolName != SelectedNoiseProtocolName {
		t.Fatalf("fixture profile = %q / %q", vector.Profile, vector.NoiseProtocolName)
	}
	if len(vector.HandshakeFramesHex) != 2 || len(vector.TransportCases) != 1 {
		t.Fatalf("fixture shape = %+v", vector)
	}

	remarshaled, err := json.Marshal(vector)
	if err != nil {
		t.Fatalf("remarshal vector: %v", err)
	}
	if _, err := ParseNoiseVector(remarshaled); err != nil {
		t.Fatalf("parse remarshaled vector: %v", err)
	}
}

func TestNoiseVectorRejectsHexFramingAndContextDrift(t *testing.T) {
	tests := []struct {
		name string
		edit func(*NoiseVector)
	}{
		{name: "schema", edit: func(vector *NoiseVector) { vector.VectorSchema = "winkyou-test-pairing-noise-vector/2" }},
		{name: "profile", edit: func(vector *NoiseVector) { vector.Profile = SimulationSecureChannelProfile }},
		{name: "context field", edit: func(vector *NoiseVector) { vector.PairingContext.RuntimeFallback = "enabled" }},
		{name: "context hex mismatch", edit: func(vector *NoiseVector) { vector.PairingContextJCSHex = "00" + vector.PairingContextJCSHex[2:] }},
		{name: "prologue mismatch", edit: func(vector *NoiseVector) { vector.PrologueHex = "00" + vector.PrologueHex[2:] }},
		{name: "uppercase hex", edit: func(vector *NoiseVector) { vector.HandshakeHashHex = strings.ToUpper(vector.HandshakeHashHex) }},
		{name: "short psk", edit: func(vector *NoiseVector) { vector.PSKHex = vector.PSKHex[:62] }},
		{name: "short ephemeral", edit: func(vector *NoiseVector) { vector.InitiatorEphemeralPrivHex = "00" }},
		{name: "short hash", edit: func(vector *NoiseVector) { vector.HandshakeHashHex = "00" }},
		{name: "one handshake frame", edit: func(vector *NoiseVector) { vector.HandshakeFramesHex = vector.HandshakeFramesHex[:1] }},
		{name: "handshake length prefix", edit: func(vector *NoiseVector) { vector.HandshakeFramesHex[0] = "002f" + vector.HandshakeFramesHex[0][4:] }},
		{name: "transport direction", edit: func(vector *NoiseVector) { vector.TransportCases[0].Direction = "reflected" }},
		{name: "duplicate direction", edit: func(vector *NoiseVector) {
			vector.TransportCases = append(vector.TransportCases, vector.TransportCases[0])
		}},
		{name: "plaintext length prefix", edit: func(vector *NoiseVector) {
			vector.TransportCases[0].PlaintextFrameHex = "00000003" + vector.TransportCases[0].PlaintextFrameHex[8:]
		}},
		{name: "noise length prefix", edit: func(vector *NoiseVector) {
			vector.TransportCases[0].NoiseFrameHex = "0002" + vector.TransportCases[0].NoiseFrameHex[4:]
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			vector, err := ParseNoiseVector(readSyntheticVector(t))
			if err != nil {
				t.Fatalf("parse baseline: %v", err)
			}
			test.edit(&vector)
			payload, err := json.Marshal(vector)
			if err != nil {
				t.Fatalf("marshal mutation: %v", err)
			}
			if _, err := ParseNoiseVector(payload); !errors.Is(err, ErrInvalidVector) {
				t.Fatalf("parse mutation = %v, want invalid vector", err)
			}
		})
	}
}

func TestNoiseVectorStrictJSONBoundary(t *testing.T) {
	fixture := string(readSyntheticVector(t))
	profileMember := `"profile": "noise-nnpsk0-25519-chachapoly-sha256/1",`
	artifactMember := `"artifact": "acceptance",`
	tests := []struct {
		name    string
		payload []byte
	}{
		{name: "unknown top-level member", payload: []byte(strings.Replace(fixture, "{", "{\n  \"unknown\": \"value\",", 1))},
		{name: "duplicate top-level member", payload: []byte(strings.Replace(fixture, profileMember, profileMember+"\n  "+profileMember, 1))},
		{name: "duplicate nested member", payload: []byte(strings.Replace(fixture, artifactMember, artifactMember+"\n    "+artifactMember, 1))},
		{name: "nested context value", payload: []byte(strings.Replace(fixture, `"early_data": "disabled"`, `"early_data": {"value":"disabled"}`, 1))},
		{name: "non-string context value", payload: []byte(strings.Replace(fixture, `"observation_generation": "1"`, `"observation_generation": 1`, 1))},
		{name: "trailing document", payload: append(append([]byte(nil), []byte(fixture)...), []byte(" {}")...)},
		{name: "invalid UTF-8", payload: []byte{'{', '"', 0xff, '"', ':', '1', '}'}},
		{name: "over size", payload: bytes.Repeat([]byte{' '}, MaxVectorBytes+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseNoiseVector(test.payload); !errors.Is(err, ErrInvalidVector) {
				t.Fatalf("parse = %v, want invalid vector", err)
			}
		})
	}
}

func readSyntheticVector(t *testing.T) []byte {
	t.Helper()
	payload, err := os.ReadFile("testdata/noise_vector.synthetic.json")
	if err != nil {
		t.Fatalf("read synthetic vector: %v", err)
	}
	return normalizedJSON(payload)
}
