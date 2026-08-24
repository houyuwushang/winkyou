package directsim

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"winkyou/internal/v2/directattempt"
)

func TestPresenceSchemaContainsNoPairingData(t *testing.T) {
	typeOfPresence := reflect.TypeOf(Presence{})
	want := []string{"Profile", "AssociationID", "Slot"}
	if typeOfPresence.NumField() != len(want) {
		t.Fatalf("presence fields = %d, want %d", typeOfPresence.NumField(), len(want))
	}
	for index, name := range want {
		if typeOfPresence.Field(index).Name != name {
			t.Fatalf("presence field %d = %s, want %s", index, typeOfPresence.Field(index).Name, name)
		}
	}
	for _, forbidden := range []string{"secret", "credential", "attempt", "participant", "generation", "endpoint", "payload", "role"} {
		if strings.Contains(strings.ToLower(typeOfPresence.String()), forbidden) {
			t.Fatalf("presence type contains forbidden pairing concept %q", forbidden)
		}
		for index := 0; index < typeOfPresence.NumField(); index++ {
			if strings.Contains(strings.ToLower(typeOfPresence.Field(index).Name), forbidden) {
				t.Fatalf("presence field contains forbidden pairing concept %q", forbidden)
			}
		}
	}
}

func TestMemoryRendezvousEnforcesPresenceBurnHandshakeControlOrderAndOwnership(t *testing.T) {
	association := "FRUVFRUVFRUVFRUVFRUVFQ"
	rendezvous, err := NewMemoryRendezvous(association)
	if err != nil {
		t.Fatal(err)
	}
	defer rendezvous.Close()
	if err := rendezvous.SendHandshake(directattempt.RoleInitiator, bytes.Repeat([]byte{0}, 48)); !errors.Is(err, ErrRendezvousOrder) {
		t.Fatalf("pre-burn handshake error = %v", err)
	}
	presenceA := Presence{Profile: directattempt.RendezvousPresenceProfile, AssociationID: association, Slot: PresenceSlotA}
	presenceB := Presence{Profile: directattempt.RendezvousPresenceProfile, AssociationID: association, Slot: PresenceSlotB}
	if complete, err := rendezvous.Arrive(presenceA); err != nil || complete {
		t.Fatalf("first presence = %t/%v", complete, err)
	}
	if complete, err := rendezvous.Arrive(presenceB); err != nil || !complete {
		t.Fatalf("second presence = %t/%v", complete, err)
	}
	if _, err := rendezvous.Arrive(presenceB); !errors.Is(err, ErrPresence) && !errors.Is(err, ErrRendezvousOrder) {
		t.Fatalf("duplicate presence error = %v", err)
	}
	if err := rendezvous.MarkDurablyBurned(); err != nil {
		t.Fatal(err)
	}
	first := bytes.Repeat([]byte{1}, 48)
	if err := rendezvous.SendHandshake(directattempt.RoleInitiator, first); err != nil {
		t.Fatal(err)
	}
	first[0] = 2
	opened, err := rendezvous.ReceiveHandshake(directattempt.RoleResponder)
	if err != nil || opened[0] != 1 || len(opened) != 48 {
		t.Fatalf("first handshake = %q/%v", opened, err)
	}
	if err := rendezvous.MarkHandshakeComplete(); !errors.Is(err, ErrRendezvousOrder) {
		t.Fatalf("one-sided handshake completion error = %v", err)
	}
	if err := rendezvous.SendHandshake(directattempt.RoleResponder, bytes.Repeat([]byte{2}, 48)); err != nil {
		t.Fatal(err)
	}
	if _, err := rendezvous.ReceiveHandshake(directattempt.RoleInitiator); err != nil {
		t.Fatal(err)
	}
	if err := rendezvous.MarkHandshakeComplete(); err != nil {
		t.Fatal(err)
	}
	control := bytes.Repeat([]byte{1}, directattempt.MaxFrameBytes)
	if err := rendezvous.SendControl(directattempt.RoleInitiator, control); err != nil {
		t.Fatal(err)
	}
	control[0] = 2
	opened, err = rendezvous.ReceiveControl(directattempt.RoleResponder)
	if err != nil || opened[0] != 1 {
		t.Fatalf("control ownership = %d/%v", opened[0], err)
	}
	if err := rendezvous.SendControl(directattempt.RoleInitiator, bytes.Repeat([]byte{1}, directattempt.MaxFrameBytes+1)); !errors.Is(err, ErrFrameLimit) {
		t.Fatalf("oversize error = %v", err)
	}
}
