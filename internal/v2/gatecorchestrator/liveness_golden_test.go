package gatecorchestrator

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestLivenessWireGoldenIndependentPythonBytes(t *testing.T) {
	data, err := os.ReadFile("testdata/liveness-wire.json")
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	var vectors []struct {
		Role, Kind byte
		PacketHex  string `json:"packet_hex"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) != 4 {
		t.Fatal("missing role/kind vectors")
	}
	for _, v := range vectors {
		binding := livenessTestBinding()
		if v.Role == 2 {
			binding = oppositeLivenessBinding(binding)
		}
		message := livenessMessage{kind: livenessKind(v.Kind), sequence: 0x0102030405060708}
		for i := range message.nonce {
			message.nonce[i] = byte(i)
		}
		got, err := buildLivenessPacket(binding, message)
		if err != nil {
			t.Fatal(err)
		}
		want, err := hex.DecodeString(v.PacketHex)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("role=%d kind=%d does not match independent vector", v.Role, v.Kind)
		}
		parsed, err := parseLivenessPacket(want, oppositeLivenessBinding(binding))
		if err != nil || parsed != message {
			t.Fatal("golden parser mismatch")
		}
	}
}

func TestLivenessStableErrorGoldenAndPrivacy(t *testing.T) {
	want, err := os.ReadFile("testdata/liveness-errors.json")
	if err != nil {
		t.Fatal(err)
	}
	want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
	var compact bytes.Buffer
	if err := json.Compact(&compact, want); err != nil {
		t.Fatal(err)
	}
	var failures []*Failure
	for _, cause := range []error{errLivenessTimeout, errLivenessProtocol, errLivenessClock, errLivenessBudget, errLivenessUnavailable} {
		failures = append(failures, livenessFailure(preparedInput{}, cause, true))
	}
	failures = append(failures, livenessFailure(preparedInput{}, errLivenessUnavailable, false))
	got, err := json.Marshal(failures)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, compact.Bytes()) {
		t.Fatalf("new error golden mismatch: %s", got)
	}
	m, _ := testLivenessModel(t, 3)
	witness, err := json.Marshal(m.snapshot())
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"nonce", "sequence", "attempt", "context", "digest", m.binding.Local.String(), m.binding.Remote.String(), m.binding.AttemptID} {
		if bytes.Contains(witness, []byte(forbidden)) {
			t.Fatal("witness leaked binding or challenge material")
		}
	}
}
