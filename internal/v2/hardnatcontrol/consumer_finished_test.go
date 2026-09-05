package hardnatcontrol

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func finishedCodecs(t *testing.T) (*ConsumerReadiness, *ConsumerReadiness) {
	t.Helper()
	left, right := readyCodecs(t)
	ready, err := left.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if err := right.Open(ready); err != nil {
		t.Fatal(err)
	}
	ack, err := right.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if err := left.Open(ack); err != nil {
		t.Fatal(err)
	}
	return left, right
}

func TestConsumerFinishedByteGoldenAndNoLegacyParser(t *testing.T) {
	left, right := finishedCodecs(t)
	frame, err := right.SealFinish()
	if err != nil {
		t.Fatal(err)
	}
	if err := left.OpenFinish(frame); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectFrame(frame); err == nil {
		t.Fatal("WYHB accepted WYCF")
	}
	if len(frame) != ConsumerFinishedFrameBytes || !left.finished || !right.finished {
		t.Fatal("completion shape/ownership changed")
	}
	vector := struct {
		Schema, Frame, AD                                                            string
		FrameBytes, InitiatorWrites, InitiatorReads, ResponderWrites, ResponderReads int
	}{
		"winkyou-gate-c-consumer-finished-vectors/1", hex.EncodeToString(frame), hex.EncodeToString(right.finishedAD(frame[:24])),
		40, 3, 3, 3, 3,
	}
	got, err := json.MarshalIndent(vector, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	want, err := os.ReadFile("testdata/consumer_finished.golden.json")
	if err != nil {
		t.Fatalf("missing golden\n%s", got)
	}
	want = []byte(strings.ReplaceAll(string(want), "\r\n", "\n"))
	if !bytes.Equal(want, got) {
		t.Fatalf("completion golden mismatch\n%s", got)
	}
}

func TestConsumerFinishedRejectsInvalidReplayAndCrossDomainTerminally(t *testing.T) {
	for _, mutation := range []string{"magic", "version", "type", "role", "reserved", "sequence", "generation", "short", "long", "tag", "attempt", "context", "handshake", "envelope", "joint", "execution", "winner", "consumer", "cross-domain", "replay"} {
		t.Run(mutation, func(t *testing.T) {
			left, right := finishedCodecs(t)
			frame, err := right.SealFinish()
			if err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "magic":
				frame[0] ^= 1
			case "version":
				frame[4]++
			case "type":
				frame[5]++
			case "role":
				frame[6]++
			case "reserved":
				frame[7]++
			case "sequence":
				frame[15]++
			case "generation":
				frame[23]++
			case "short":
				frame = frame[:39]
			case "long":
				frame = append(frame, 0)
			case "tag":
				frame[39] ^= 1
			case "attempt":
				left.binding[0] ^= 1
			case "context":
				left.binding[16] ^= 1
			case "handshake":
				left.binding[48] ^= 1
			case "envelope":
				left.binding[80] ^= 1
			case "joint":
				left.binding[112] ^= 1
			case "execution":
				left.binding[144] ^= 1
			case "winner":
				left.binding[176] ^= 1
			case "consumer":
				// Fresh original cipher, same header/bindings but a different
				// consumer suffix: authentication, not a plaintext name check.
				left, right = finishedCodecs(t)
				header := consumerFinishedHeader()
				ad := right.finishedAD(header)
				ad[len(ad)-1] ^= 1
				ciphertext, err := right.packets.Seal(10, ad, nil)
				if err != nil {
					t.Fatal(err)
				}
				frame = append(header, ciphertext...)
			case "cross-domain":
				copy(frame, "WYCR")
			case "replay":
				if err := left.OpenFinish(frame); err != nil {
					t.Fatal(err)
				}
			}
			if err := left.OpenFinish(frame); err == nil {
				t.Fatal("invalid completion accepted")
			}
			if left.packets.Ready() || !left.closed {
				t.Fatal("rejection left cipher usable")
			}
			if _, err := left.SealFinish(); err == nil {
				t.Fatal("terminal codec emitted")
			}
		})
	}
}

func TestConsumerFinishedCannotPrecedeReadinessOrChangeDirection(t *testing.T) {
	for _, mode := range []string{"before-barrier", "initiator-seal", "responder-open", "repeat-seal", "ready-parser"} {
		t.Run(mode, func(t *testing.T) {
			left, right := finishedCodecs(t)
			if mode == "before-barrier" {
				left, right = readyCodecs(t)
			}
			switch mode {
			case "before-barrier", "repeat-seal":
				if mode == "repeat-seal" {
					if _, err := right.SealFinish(); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := right.SealFinish(); err == nil {
					t.Fatal("illegal seal accepted")
				}
			case "initiator-seal":
				if _, err := left.SealFinish(); err == nil {
					t.Fatal("initiator emitted confirmation")
				}
			case "responder-open":
				if err := right.OpenFinish(make([]byte, 40)); err == nil {
					t.Fatal("responder received confirmation")
				}
			case "ready-parser":
				frame, err := right.SealFinish()
				if err != nil {
					t.Fatal(err)
				}
				if err := left.Open(frame); err == nil {
					t.Fatal("WYCR parser accepted WYCF")
				}
			}
		})
	}
}
