package testpairing

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	NoiseVectorSchema = "winkyou-test-pairing-noise-vector/1"
	MaxVectorBytes    = 64 * 1024
)

var ErrInvalidVector = errors.New("testpairing: invalid Noise vector fixture")

// NoiseVector is the deterministic test schema described by ADR section 6.
// Its PSK and key-shaped hex fields contain synthetic public fixture bytes;
// they are not runtime pairing material. No vector is normative before review.
type NoiseVector struct {
	VectorSchema              string               `json:"vector_schema"`
	Profile                   string               `json:"profile"`
	NoiseProtocolName         string               `json:"noise_protocol_name"`
	PairingContext            PairingContext       `json:"pairing_context"`
	PairingContextJCSHex      string               `json:"pairing_context_jcs_hex"`
	PrologueHex               string               `json:"prologue_hex"`
	PSKHex                    string               `json:"psk_hex"`
	InitiatorEphemeralPrivHex string               `json:"initiator_ephemeral_private_hex"`
	ResponderEphemeralPrivHex string               `json:"responder_ephemeral_private_hex"`
	HandshakeFramesHex        []string             `json:"handshake_frames_hex"`
	HandshakeHashHex          string               `json:"handshake_hash_hex"`
	TransportCases            []NoiseTransportCase `json:"transport_cases"`
}

type NoiseTransportCase struct {
	Direction         string `json:"direction"`
	PlaintextFrameHex string `json:"plaintext_frame_hex"`
	NoiseFrameHex     string `json:"noise_frame_hex"`
}

// ParseNoiseVector strictly parses and structurally validates one fixture. It
// verifies lengths, framing prefixes, restricted JCS, and the prologue bytes;
// it deliberately performs no Noise or other cryptographic operation.
func ParseNoiseVector(payload []byte) (NoiseVector, error) {
	var vector NoiseVector
	if len(payload) == 0 || len(payload) > MaxVectorBytes || !json.Valid(payload) {
		return vector, ErrInvalidVector
	}
	if err := rejectDuplicateJSONKeys(payload); err != nil {
		return vector, err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&vector); err != nil {
		return NoiseVector{}, fmt.Errorf("%w: %v", ErrInvalidVector, err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return NoiseVector{}, err
	}
	if err := vector.Validate(); err != nil {
		return NoiseVector{}, err
	}
	return vector, nil
}

// Validate checks the vector envelope without treating synthetic bytes as a
// successful or approved handshake.
func (vector NoiseVector) Validate() error {
	if vector.VectorSchema != NoiseVectorSchema ||
		vector.Profile != SelectedSecureChannelProfile ||
		vector.NoiseProtocolName != SelectedNoiseProtocolName {
		return ErrInvalidVector
	}
	canonical, err := CanonicalizePairingContext(vector.PairingContext)
	if err != nil {
		return fmt.Errorf("%w: pairing context", ErrInvalidVector)
	}
	contextBytes, err := decodeLowerHex("pairing_context_jcs_hex", vector.PairingContextJCSHex, -1)
	if err != nil || !bytes.Equal(contextBytes, canonical) {
		return fmt.Errorf("%w: pairing_context_jcs_hex", ErrInvalidVector)
	}
	prologue, err := BuildNoisePrologue(vector.PairingContext)
	if err != nil {
		return fmt.Errorf("%w: prologue context", ErrInvalidVector)
	}
	prologueBytes, err := decodeLowerHex("prologue_hex", vector.PrologueHex, -1)
	if err != nil || !bytes.Equal(prologueBytes, prologue) {
		return fmt.Errorf("%w: prologue_hex", ErrInvalidVector)
	}
	fixedHex := []struct {
		name  string
		value string
	}{
		{name: "psk_hex", value: vector.PSKHex},
		{name: "initiator_ephemeral_private_hex", value: vector.InitiatorEphemeralPrivHex},
		{name: "responder_ephemeral_private_hex", value: vector.ResponderEphemeralPrivHex},
		{name: "handshake_hash_hex", value: vector.HandshakeHashHex},
	}
	for _, field := range fixedHex {
		if _, err := decodeLowerHex(field.name, field.value, 32); err != nil {
			return err
		}
	}
	if len(vector.HandshakeFramesHex) != 2 {
		return fmt.Errorf("%w: handshake_frames_hex must contain two frames", ErrInvalidVector)
	}
	for _, frameHex := range vector.HandshakeFramesHex {
		frame, err := decodeLowerHex("handshake_frames_hex", frameHex, 50)
		if err != nil || int(frame[0])<<8|int(frame[1]) != 48 {
			return fmt.Errorf("%w: handshake_frames_hex", ErrInvalidVector)
		}
	}
	if len(vector.TransportCases) == 0 || len(vector.TransportCases) > 2 {
		return fmt.Errorf("%w: transport_cases count", ErrInvalidVector)
	}
	seenDirections := make(map[string]struct{}, len(vector.TransportCases))
	for _, testCase := range vector.TransportCases {
		if testCase.Direction != "initiator_to_responder" && testCase.Direction != "responder_to_initiator" {
			return fmt.Errorf("%w: transport direction", ErrInvalidVector)
		}
		if _, exists := seenDirections[testCase.Direction]; exists {
			return fmt.Errorf("%w: duplicate transport direction", ErrInvalidVector)
		}
		seenDirections[testCase.Direction] = struct{}{}
		plaintext, err := decodeLowerHex("plaintext_frame_hex", testCase.PlaintextFrameHex, -1)
		if err != nil || len(plaintext) < 4 || len(plaintext)-4 > MaxFrameBodyBytes || binary.BigEndian.Uint32(plaintext[:4]) != uint32(len(plaintext)-4) {
			return fmt.Errorf("%w: plaintext_frame_hex", ErrInvalidVector)
		}
		ciphertext, err := decodeLowerHex("noise_frame_hex", testCase.NoiseFrameHex, -1)
		if err != nil || len(ciphertext) < 2 || binary.BigEndian.Uint16(ciphertext[:2]) != uint16(len(ciphertext)-2) {
			return fmt.Errorf("%w: noise_frame_hex", ErrInvalidVector)
		}
	}
	return nil
}

func decodeLowerHex(name, value string, exactBytes int) ([]byte, error) {
	if value == "" || value != strings.ToLower(value) || len(value)%2 != 0 {
		return nil, fmt.Errorf("%w: %s must be non-empty lower-case hex", ErrInvalidVector, name)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || (exactBytes >= 0 && len(decoded) != exactBytes) {
		return nil, fmt.Errorf("%w: %s length or encoding", ErrInvalidVector, name)
	}
	return decoded, nil
}

func rejectDuplicateJSONKeys(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidVector, err)
		}
		delimiter, composite := token.(json.Delim)
		if !composite {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return fmt.Errorf("%w: %v", ErrInvalidVector, err)
				}
				key, ok := keyToken.(string)
				if !ok {
					return ErrInvalidVector
				}
				if _, exists := seen[key]; exists {
					return fmt.Errorf("%w: duplicate JSON member %q", ErrInvalidVector, key)
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
		default:
			return ErrInvalidVector
		}
		if _, err := decoder.Token(); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidVector, err)
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func requireJSONEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("%w: trailing JSON value", ErrInvalidVector)
		}
		return fmt.Errorf("%w: %v", ErrInvalidVector, err)
	}
	return nil
}
