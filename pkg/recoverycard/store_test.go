package recoverycard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"
)

func TestStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "recovery-card.json")
	store, err := NewStore(path, "A")
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	want := testCard()
	if err := store.Save(want); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Load() = %#v, want %#v", got, want)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !bytes.Contains(raw, []byte(`"version": 1`)) || !bytes.HasSuffix(raw, []byte("\n")) {
		t.Fatalf("persisted card is not versioned, newline-terminated JSON:\n%s", raw)
	}
	if matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".recovery-card.json.tmp-*")); err != nil {
		t.Fatalf("Glob() error = %v", err)
	} else if len(matches) != 0 {
		t.Fatalf("temporary files remain after Save(): %v", matches)
	}
}

func TestStoreLoadMissingReturnsEmpty(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "missing.json"), "A")
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !reflect.DeepEqual(got, Card{}) {
		t.Fatalf("Load() = %#v, want empty Card", got)
	}
}

func TestStoreRejectsCorruptOrNonStrictJSON(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "truncated", data: []byte(`{"version":1`)},
		{name: "unknown field", data: appendValidCardField(t, `,"unexpected":true`)},
		{name: "multiple values", data: append(mustMarshalCard(t, testCard()), []byte("\n{}")...)},
		{name: "unsupported version", data: bytes.Replace(mustMarshalCard(t, testCard()), []byte(`"version":1`), []byte(`"version":2`), 1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "card.json")
			if err := os.WriteFile(path, tt.data, 0o600); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}
			store, err := NewStore(path, "A")
			if err != nil {
				t.Fatalf("NewStore() error = %v", err)
			}
			if _, err := store.Load(); err == nil {
				t.Fatal("Load() error = nil, want corrupt/strict-schema rejection")
			}
		})
	}
}

func TestStoreRejectsWrongNode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "card.json")
	storeA, err := NewStore(path, "A")
	if err != nil {
		t.Fatalf("NewStore(A) error = %v", err)
	}
	if err := storeA.Save(testCard()); err != nil {
		t.Fatalf("Save(A) error = %v", err)
	}
	storeB, err := NewStore(path, "B")
	if err != nil {
		t.Fatalf("NewStore(B) error = %v", err)
	}
	if _, err := storeB.Load(); !errors.Is(err, ErrWrongNode) {
		t.Fatalf("Load(B) error = %v, want ErrWrongNode", err)
	}
	card := testCard()
	card.NodeID = "B"
	if err := storeA.Save(card); !errors.Is(err, ErrWrongNode) {
		t.Fatalf("Save(wrong node) error = %v, want ErrWrongNode", err)
	}
}

func TestStoreAtomicUpdate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "card.json")
	store, err := NewStore(path, "A")
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	if err := store.Save(testCard()); err != nil {
		t.Fatalf("initial Save() error = %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(before) error = %v", err)
	}

	wantErr := errors.New("abort update")
	err = store.Update(func(card *Card) error {
		card.Peers[0].Endpoints[0].AddrPort = "203.0.113.99:49001"
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Update(abort) error = %v, want %v", err, wantErr)
	}
	afterAbort, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(after abort) error = %v", err)
	}
	if !bytes.Equal(afterAbort, before) {
		t.Fatal("aborted Update() changed the persisted card")
	}

	if err := store.Update(func(card *Card) error {
		card.Peers[0].Endpoints[0].AddrPort = "203.0.113.99:49001"
		return nil
	}); err != nil {
		t.Fatalf("Update(commit) error = %v", err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.Peers[0].Endpoints[0].AddrPort != "203.0.113.99:49001" {
		t.Fatalf("committed endpoint = %q, want updated address", got.Peers[0].Endpoints[0].AddrPort)
	}
	if bytes.Equal(before, mustReadFile(t, path)) {
		t.Fatal("committed Update() did not replace the card")
	}
}

func TestStoreUpdateMissingPrefillsIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "card.json")
	store, err := NewStore(path, "A")
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	want := testCard()
	if err := store.Update(func(card *Card) error {
		if card.Version != CurrentVersion || card.NodeID != "A" {
			t.Fatalf("new Update() card identity = version %d node %q", card.Version, card.NodeID)
		}
		*card = want
		return nil
	}); err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Load() = %#v, want %#v", got, want)
	}
}

func TestStoreConcurrentUpdates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "card.json")
	store, err := NewStore(path, "A")
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	if err := store.Save(testCard()); err != nil {
		t.Fatalf("initial Save() error = %v", err)
	}

	const workers = 32
	start := make(chan struct{})
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := store.Update(func(card *Card) error {
				succeededAt := testTime().Add(time.Duration(i+1) * time.Second)
				card.Peers = append(card.Peers, Peer{
					NodeID:                      fmt.Sprintf("peer-%02d", i),
					LastSuccessfulLocalBindPort: 42000,
					LastSuccessAt:               succeededAt,
					Endpoints: []Endpoint{{
						AddrPort:      fmt.Sprintf("198.51.100.%d:%d", i+1, 50000+i),
						ObservedAt:    succeededAt,
						Source:        "successful_path",
						NAT:           NATModel{Pattern: PortPatternUnknown, ObservedAt: succeededAt},
						LastSuccessAt: succeededAt,
					}},
				})
				if succeededAt.After(card.LastSuccessAt) {
					card.LastSuccessAt = succeededAt
				}
				card.UpdatedAt = testTime().Add(time.Hour)
				return nil
			})
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Update() error = %v", err)
		}
	}

	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(got.Peers) != workers+1 {
		t.Fatalf("len(Peers) = %d, want %d; an update was lost", len(got.Peers), workers+1)
	}
	ids := make([]string, 0, len(got.Peers))
	for _, peer := range got.Peers {
		ids = append(ids, peer.NodeID)
	}
	sort.Strings(ids)
	for i := 0; i < workers; i++ {
		want := fmt.Sprintf("peer-%02d", i)
		index := sort.SearchStrings(ids, want)
		if index == len(ids) || ids[index] != want {
			t.Fatalf("peer %q missing after concurrent updates: %v", want, ids)
		}
	}
}

func TestCardValidateRejectsInconsistentState(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Card)
	}{
		{name: "duplicate bind port", mutate: func(card *Card) { card.LocalBindPorts = []uint16{42000, 42000} }},
		{name: "invalid endpoint", mutate: func(card *Card) { card.Peers[0].Endpoints[0].AddrPort = "not-an-endpoint" }},
		{name: "unlisted endpoint bind", mutate: func(card *Card) { card.Peers[0].LastSuccessfulLocalBindPort = 42002 }},
		{name: "bad confidence", mutate: func(card *Card) { card.LocalNAT.Confidence = 1.1 }},
		{name: "delta on preserving", mutate: func(card *Card) { card.LocalNAT.Delta = 1 }},
		{name: "stale aggregate success", mutate: func(card *Card) { card.LastSuccessAt = card.LastSuccessAt.Add(-time.Second) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			card := testCard()
			tt.mutate(&card)
			if err := card.Validate(); err == nil {
				t.Fatal("Validate() error = nil, want rejection")
			}
		})
	}
}

func testCard() Card {
	now := testTime()
	return Card{
		Version:        CurrentVersion,
		NodeID:         "A",
		UpdatedAt:      now.Add(time.Second),
		LastSuccessAt:  now,
		LocalBindPorts: []uint16{42000, 42001},
		LocalNAT: NATModel{
			Pattern:    PortPatternPreserving,
			Confidence: 1,
			ObservedAt: now.Add(-time.Minute),
		},
		Peers: []Peer{{
			NodeID:                      "B",
			LastSuccessfulLocalBindPort: 42000,
			LastSuccessAt:               now,
			Endpoints: []Endpoint{{
				AddrPort:   "203.0.113.20:49000",
				ObservedAt: now.Add(-time.Second),
				Source:     "peer_observed",
				NAT: NATModel{
					Pattern:    PortPatternSequential,
					Delta:      1,
					Confidence: 0.8,
					ObservedAt: now.Add(-time.Minute),
				},
				LastSuccessAt: now,
			}},
		}},
	}
}

func testTime() time.Time {
	return time.Date(2026, time.July, 18, 12, 0, 0, 0, time.UTC)
}

func mustMarshalCard(t *testing.T, card Card) []byte {
	t.Helper()
	data, err := json.Marshal(card)
	if err != nil {
		t.Fatalf("marshal card: %v", err)
	}
	return data
}

func appendValidCardField(t *testing.T, field string) []byte {
	t.Helper()
	data := mustMarshalCard(t, testCard())
	if len(data) == 0 || data[len(data)-1] != '}' {
		t.Fatalf("unexpected JSON: %s", data)
	}
	return append(append(data[:len(data)-1], []byte(field)...), '}')
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", path, err)
	}
	return data
}
