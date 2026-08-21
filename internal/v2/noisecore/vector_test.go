package noisecore_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"winkyou/internal/v2/noisecore"
)

type cacophonyVector struct {
	SourceURL     string             `json:"source_url"`
	SourceCommit  string             `json:"source_commit"`
	SourceBlob    string             `json:"source_blob"`
	SourceLicense string             `json:"source_license"`
	ProtocolName  string             `json:"protocol_name"`
	InitPrologue  string             `json:"init_prologue"`
	InitPSKs      []string           `json:"init_psks"`
	InitEphemeral string             `json:"init_ephemeral"`
	RespPrologue  string             `json:"resp_prologue"`
	RespPSKs      []string           `json:"resp_psks"`
	RespEphemeral string             `json:"resp_ephemeral"`
	HandshakeHash string             `json:"handshake_hash"`
	Messages      []cacophonyMessage `json:"messages"`
}

type cacophonyMessage struct {
	Payload    string `json:"payload"`
	Ciphertext string `json:"ciphertext"`
}

type fixedPSKSource struct {
	key [noisecore.PSKSize]byte
}

func (source fixedPSKSource) LoadPSK() ([noisecore.PSKSize]byte, error) {
	return source.key, nil
}

func TestCacophonyNNpsk0VectorMatchesByteForByte(t *testing.T) {
	vector := loadCacophonyVector(t)
	if vector.ProtocolName != noisecore.ProtocolName ||
		vector.SourceCommit != "8ee9d41e34a1a596cfa3ab12aa4069ff87dc1247" ||
		vector.SourceBlob != "b8a271ed1aba8b4a56bf429e559d7947827123b4" ||
		vector.SourceLicense != "Unlicense" {
		t.Fatalf("unexpected vector provenance: %+v", vector)
	}
	if len(vector.InitPSKs) != 1 || len(vector.RespPSKs) != 1 || vector.InitPSKs[0] != vector.RespPSKs[0] {
		t.Fatalf("unexpected PSK vector shape")
	}
	initiatorPrologue := decodeHex(t, vector.InitPrologue)
	responderPrologue := decodeHex(t, vector.RespPrologue)
	psk := array32(t, vector.InitPSKs[0])
	initiator, err := noisecore.NewInitiator(noisecore.Config{
		Prologue: initiatorPrologue,
		PSK:      fixedPSKSource{key: psk},
		Random:   bytes.NewReader(decodeHex(t, vector.InitEphemeral)),
	})
	if err != nil {
		t.Fatalf("new initiator: %v", err)
	}
	defer initiator.Close()
	responder, err := noisecore.NewResponder(noisecore.Config{
		Prologue: responderPrologue,
		PSK:      fixedPSKSource{key: psk},
		Random:   bytes.NewReader(decodeHex(t, vector.RespEphemeral)),
	})
	if err != nil {
		t.Fatalf("new responder: %v", err)
	}
	defer responder.Close()

	for index, expected := range vector.Messages {
		payload := decodeHex(t, expected.Payload)
		wantCiphertext := decodeHex(t, expected.Ciphertext)
		var (
			ciphertext []byte
			opened     []byte
		)
		switch index {
		case 0:
			ciphertext, err = initiator.WriteMessage(payload)
			if err == nil {
				opened, err = responder.ReadMessage(ciphertext)
			}
		case 1:
			ciphertext, err = responder.WriteMessage(payload)
			if err == nil {
				opened, err = initiator.ReadMessage(ciphertext)
			}
		default:
			if index%2 == 0 {
				ciphertext, err = initiator.Encrypt(nil, payload)
				if err == nil {
					opened, err = responder.Decrypt(nil, ciphertext)
				}
			} else {
				ciphertext, err = responder.Encrypt(nil, payload)
				if err == nil {
					opened, err = initiator.Decrypt(nil, ciphertext)
				}
			}
		}
		if err != nil {
			t.Fatalf("message %d: %v", index, err)
		}
		if !bytes.Equal(ciphertext, wantCiphertext) {
			t.Fatalf("message %d ciphertext\n got %x\nwant %x", index, ciphertext, wantCiphertext)
		}
		if !bytes.Equal(opened, payload) {
			t.Fatalf("message %d payload = %x, want %x", index, opened, payload)
		}
		if index == 1 {
			assertHandshakeHash(t, initiator, vector.HandshakeHash)
			assertHandshakeHash(t, responder, vector.HandshakeHash)
		}
	}
}

func loadCacophonyVector(t *testing.T) cacophonyVector {
	t.Helper()
	payload, err := os.ReadFile("testdata/cacophony_nnpsk0_25519_chachapoly_sha256.json")
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var vector cacophonyVector
	decoder := json.NewDecoder(bytes.NewReader(bytes.ReplaceAll(payload, []byte("\r\n"), []byte("\n"))))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&vector); err != nil {
		t.Fatalf("decode vector: %v", err)
	}
	return vector
}

func assertHandshakeHash(t *testing.T, session *noisecore.Session, wantHex string) {
	t.Helper()
	got, err := session.HandshakeHash()
	if err != nil {
		t.Fatalf("handshake hash: %v", err)
	}
	want := array32(t, wantHex)
	if got != want {
		t.Fatalf("handshake hash = %x, want %x", got, want)
	}
}

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return decoded
}

func array32(t *testing.T, value string) [32]byte {
	t.Helper()
	decoded := decodeHex(t, value)
	if len(decoded) != 32 {
		t.Fatalf("decoded length = %d, want 32", len(decoded))
	}
	var result [32]byte
	copy(result[:], decoded)
	return result
}
