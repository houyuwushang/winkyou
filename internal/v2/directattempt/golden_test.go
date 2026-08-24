package directattempt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"winkyou/internal/v2/pairingcontext"
)

type goldenFrame struct {
	Sender            string `json:"sender"`
	Type              string `json:"type"`
	Sequence          uint64 `json:"sequence"`
	Domain            string `json:"domain"`
	HeaderHex         string `json:"header_hex"`
	AdditionalDataHex string `json:"additional_data_hex"`
	CiphertextHex     string `json:"ciphertext_hex"`
}

type directAttemptGolden struct {
	Schema                    string        `json:"schema"`
	IntegerByteOrder          string        `json:"integer_byte_order"`
	MaxArtifactBytes          int           `json:"max_artifact_bytes"`
	MaxFrameBytes             int           `json:"max_frame_bytes"`
	FrameHeaderBytes          int           `json:"frame_header_bytes"`
	ArtifactJSON              string        `json:"artifact_json"`
	ArtifactFingerprint       string        `json:"artifact_fingerprint"`
	PairingContextJCSSHA256   string        `json:"pairing_context_jcs_sha256"`
	DirectNoisePrologueSHA256 string        `json:"direct_noise_prologue_sha256"`
	ReadyIPv4Hex              string        `json:"ready_ipv4_hex"`
	Frames                    []goldenFrame `json:"frames"`
}

type actualGoldenFrame struct {
	sender    Role
	frameType FrameType
	frame     []byte
}

func TestDirectAttemptSyntheticGoldenIsByteStable(t *testing.T) {
	payload, err := os.ReadFile("testdata/direct_attempt.synthetic.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	payload = []byte(strings.ReplaceAll(string(payload), "\r\n", "\n"))
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var golden directAttemptGolden
	if err := decoder.Decode(&golden); err != nil {
		t.Fatalf("decode golden: %v", err)
	}
	if golden.Schema != "winkyou-test-direct-attempt-golden/1" || golden.IntegerByteOrder != "big-endian" ||
		golden.MaxArtifactBytes != MaxArtifactBytes || golden.MaxFrameBytes != MaxFrameBytes || golden.FrameHeaderBytes != FrameHeaderBytes {
		t.Fatalf("golden limits/version drifted: %+v", golden)
	}

	now := time.Date(2026, 8, 24, 9, 10, 11, 0, time.UTC)
	wantArtifact := testArtifactPayload(t, RoleInitiator, now)
	if golden.ArtifactJSON != string(wantArtifact) {
		t.Fatalf("artifact JSON changed\ngot:  %s\nwant: %s", wantArtifact, golden.ArtifactJSON)
	}
	artifact, err := ParseArtifact([]byte(golden.ArtifactJSON), now.Add(time.Second))
	if err != nil {
		t.Fatalf("parse golden artifact: %v", err)
	}
	defer artifact.Close()
	if artifact.Fingerprint != golden.ArtifactFingerprint {
		t.Fatalf("fingerprint = %s, want %s", artifact.Fingerprint, golden.ArtifactFingerprint)
	}
	context, _ := artifact.PairingContext()
	canonical, err := pairingcontext.CanonicalizePairingContext(context)
	if err != nil {
		t.Fatal(err)
	}
	canonicalHash := sha256.Sum256(canonical)
	clear(canonical)
	if got := hex.EncodeToString(canonicalHash[:]); got != golden.PairingContextJCSSHA256 {
		t.Fatalf("context JCS SHA-256 = %s, want %s", got, golden.PairingContextJCSSHA256)
	}
	prologue, err := BuildNoisePrologue(context)
	if err != nil {
		t.Fatal(err)
	}
	prologueHash := sha256.Sum256(prologue)
	clear(prologue)
	if got := hex.EncodeToString(prologueHash[:]); got != golden.DirectNoisePrologueSHA256 {
		t.Fatalf("direct prologue SHA-256 = %s, want %s", got, golden.DirectNoisePrologueSHA256)
	}

	initiator, responder, binding := testProtocolPair(t)
	defer initiator.Close()
	defer responder.Close()
	iReady, _ := NewReadyPayload(binding, RoleInitiator, netip.MustParseAddrPort("192.0.2.10:41000"))
	rReady, _ := NewReadyPayload(binding, RoleResponder, netip.MustParseAddrPort("198.51.100.20:42000"))
	readyBytes, _ := iReady.MarshalBinary()
	if got := hex.EncodeToString(readyBytes); got != golden.ReadyIPv4Hex {
		t.Fatalf("READY bytes = %s, want %s", got, golden.ReadyIPv4Hex)
	}
	clear(readyBytes)

	var actual []actualGoldenFrame
	add := func(sender Role, frameType FrameType, frame []byte) {
		actual = append(actual, actualGoldenFrame{sender: sender, frameType: frameType, frame: append([]byte(nil), frame...)})
	}
	iPrepare := mustSeal(t, initiator, FramePrepare, nil)
	add(RoleInitiator, FramePrepare, iPrepare)
	rPrepare := mustSeal(t, responder, FramePrepare, nil)
	add(RoleResponder, FramePrepare, rPrepare)
	mustOpen(t, responder, iPrepare, FramePrepare)
	mustOpen(t, initiator, rPrepare, FramePrepare)
	iReadyFrame := mustSeal(t, initiator, FrameReady, &iReady)
	add(RoleInitiator, FrameReady, iReadyFrame)
	rReadyFrame := mustSeal(t, responder, FrameReady, &rReady)
	add(RoleResponder, FrameReady, rReadyFrame)
	mustOpen(t, responder, iReadyFrame, FrameReady)
	mustOpen(t, initiator, rReadyFrame, FrameReady)
	fire := mustSeal(t, initiator, FrameFire, nil)
	add(RoleInitiator, FrameFire, fire)
	mustOpen(t, responder, fire, FrameFire)
	syn := mustSeal(t, initiator, FrameSYN, nil)
	add(RoleInitiator, FrameSYN, syn)
	synACK := mustSeal(t, responder, FrameSYNACK, nil)
	add(RoleResponder, FrameSYNACK, synACK)
	mustOpen(t, initiator, synACK, FrameSYNACK)
	ack := mustSeal(t, initiator, FrameACK, nil)
	add(RoleInitiator, FrameACK, ack)
	mustOpen(t, responder, ack, FrameACK)
	mustOpen(t, responder, syn, FrameSYN)
	iVerify := mustSeal(t, initiator, FrameVerify, nil)
	add(RoleInitiator, FrameVerify, iVerify)
	rVerify := mustSeal(t, responder, FrameVerify, nil)
	add(RoleResponder, FrameVerify, rVerify)

	cancelInitiator, cancelResponder, _ := testProtocolPair(t)
	cancel := mustSeal(t, cancelInitiator, FrameCancel, nil)
	add(RoleInitiator, FrameCancel, cancel)
	_ = cancelInitiator.Close()
	_ = cancelResponder.Close()

	if len(actual) != len(golden.Frames) {
		t.Fatalf("frame vector count = %d, want %d", len(actual), len(golden.Frames))
	}
	for index, frame := range actual {
		want := golden.Frames[index]
		sequence, _ := frame.frameType.Sequence()
		domain, _ := frame.frameType.Domain()
		additionalData, err := BuildAdditionalData(binding, frame.frame[:FrameHeaderBytes])
		if err != nil {
			t.Fatal(err)
		}
		if want.Sender != string(frame.sender) || want.Type != frame.frameType.String() || want.Sequence != sequence || want.Domain != string(domain) ||
			want.HeaderHex != hex.EncodeToString(frame.frame[:FrameHeaderBytes]) ||
			want.AdditionalDataHex != hex.EncodeToString(additionalData) ||
			want.CiphertextHex != hex.EncodeToString(frame.frame[FrameHeaderBytes:]) {
			t.Fatalf("frame vector %d (%s) changed\ngot header=%x ad=%x ciphertext=%x\nwant=%+v", index, frame.frameType, frame.frame[:FrameHeaderBytes], additionalData, frame.frame[FrameHeaderBytes:], want)
		}
		if len(frame.frame) > golden.MaxFrameBytes {
			t.Fatalf("frame %s length = %d", frame.frameType, len(frame.frame))
		}
		clear(additionalData)
		clear(frame.frame)
	}
}
