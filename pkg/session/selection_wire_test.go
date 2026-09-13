package session

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestSelectionWireGolden(t *testing.T) {
	a := selectionCapability{Strategies: []string{"legacy_ice_udp", "relay_only"}, Features: []string{}, Version: selectionVersion, Epoch: strings.Repeat("01", 16)}
	b := a
	b.Epoch = strings.Repeat("02", 16)
	binding := selectionBinding{Version: selectionVersion, FromEpoch: a.Epoch, ToEpoch: b.Epoch, Ordinal: "0", SenderCapability: selectionCapabilityDigest(a.domainWire()), ReceiverCapability: selectionCapabilityDigest(b.domainWire()), PreviousClosed: true}
	pa := selectionProposal{selectionBinding: binding, Strategies: []string{"relay_only", "legacy_ice_udp"}}
	binding.FromEpoch, binding.ToEpoch = binding.ToEpoch, binding.FromEpoch
	pb := selectionProposal{selectionBinding: binding, Strategies: []string{"legacy_ice_udp", "relay_only"}}
	joint, err := jointSelection(Config{SessionID: "selection/synthetic-pair", LocalNodeID: "side-a", PeerID: "side-b", Initiator: true}, a.domainWire(), b.domainWire(), pa, pb)
	if err != nil {
		t.Fatal(err)
	}
	reversed, err := jointSelection(Config{SessionID: "selection/synthetic-pair", LocalNodeID: "side-b", PeerID: "side-a", Initiator: false}, b.domainWire(), a.domainWire(), pb, pa)
	if err != nil || selectionHash(joint) != selectionHash(reversed) {
		t.Fatal("role-separated independent recomputation differs")
	}
	wire := func(v any) string {
		encoded, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(encoded)
	}
	value := struct {
		Version       string         `json:"version"`
		CapabilityHex string         `json:"capability_utf8_hex"`
		ProposalHex   string         `json:"initiator_proposal_utf8_hex"`
		ConfirmHex    string         `json:"initiator_confirm_utf8_hex"`
		JointHex      string         `json:"joint_utf8_hex"`
		Digest        string         `json:"sha256"`
		Limits        map[string]int `json:"limits"`
		Errors        []string       `json:"errors"`
	}{selectionVersion, wire(a), wire(pa), wire(selectionConfirmation{selectionBinding: pa.selectionBinding, Strategy: joint.Order[0], Digest: selectionHash(joint)}), wire(joint), selectionHash(joint),
		map[string]int{"envelope_bytes": selectionEnvelopeLimit, "payload_bytes": selectionPayloadLimit, "strategies": selectionStrategyLimit, "features": selectionFeatureLimit, "token_bytes": selectionTokenLimit, "receive_per_slot": selectionReceiveLimit},
		[]string{"capability_missing", "selection_unsupported", "selection_invalid", "selection_conflict", "selection_timeout", "selection_closed", "selection_previous_active"},
	}
	got, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "selection_agreement_v1.golden.json"))
	if err != nil {
		t.Log("SELECTION_GOLDEN " + string(mustCompactSelectionGolden(got)))
		t.Fatal("missing selection golden")
	}
	if strings.TrimSpace(strings.ReplaceAll(string(want), "\r\n", "\n")) != string(got) {
		t.Fatal("selection golden bytes changed")
	}
}
func mustCompactSelectionGolden(data []byte) []byte {
	var value any
	_ = json.Unmarshal(data, &value)
	result, _ := json.Marshal(value)
	return result
}

func TestSelectionWireRejectsAmbiguousAndOversizeInputs(t *testing.T) {
	for _, raw := range []string{
		`{"version":"a","version":"b"}`, `{"unknown":true}`, `null null`,
		`{"strategies":[{"nested":{"too":{"deep":true}}}]}`, strings.Repeat(" ", selectionPayloadLimit+1),
	} {
		var value selectionProposal
		if decodeSelectionJSON([]byte(raw), &value) == nil {
			t.Fatalf("invalid wire input accepted case bytes=%d", len(raw))
		}
	}
	for _, ordinal := range []string{"", "00", "-1", "+1", "1.0", " 1", "18446744073709551616"} {
		if _, err := selectionOrdinal(ordinal); err == nil {
			t.Fatal("invalid ordinal accepted")
		}
	}
	for _, ordinal := range []uint64{0, 1, ^uint64(0)} {
		encoded := strconv.FormatUint(ordinal, 10)
		got, err := selectionOrdinal(encoded)
		if err != nil || got != ordinal {
			t.Fatal("valid ordinal rejected")
		}
	}
	for _, epoch := range []string{"", strings.Repeat("0", 31), strings.Repeat("0", 33), strings.Repeat("AB", 16), strings.Repeat("gh", 16)} {
		if selectionHex(epoch, 16) {
			t.Fatal("noncanonical epoch accepted")
		}
	}
	if selectionList([]string{"same", "same"}, selectionStrategyLimit, true) || selectionList([]string{""}, selectionStrategyLimit, true) || selectionList([]string{strings.Repeat("a", selectionTokenLimit+1)}, selectionStrategyLimit, true) {
		t.Fatal("ambiguous list accepted")
	}
}
