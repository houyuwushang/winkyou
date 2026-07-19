package mesh

import (
	"bytes"
	"strings"
	"testing"
)

func TestDataFrameRoundTrip(t *testing.T) {
	want := DataFrame{
		Version:     DataFrameVersion,
		Type:        DataTypePacket,
		HopLimit:    12,
		Source:      "node-a",
		Destination: "node-c",
		FlowID:      42,
		Sequence:    7,
		Payload:     []byte("opaque-packet"),
	}
	raw, err := MarshalDataFrame(want)
	if err != nil {
		t.Fatalf("MarshalDataFrame() error = %v", err)
	}
	got, err := UnmarshalDataFrame(raw)
	if err != nil {
		t.Fatalf("UnmarshalDataFrame() error = %v", err)
	}
	if got.Version != want.Version || got.Type != want.Type || got.HopLimit != want.HopLimit ||
		got.Source != want.Source || got.Destination != want.Destination || got.FlowID != want.FlowID ||
		got.Sequence != want.Sequence || !bytes.Equal(got.Payload, want.Payload) {
		t.Fatalf("round trip = %#v, want %#v", got, want)
	}
}

func TestDataFrameValidation(t *testing.T) {
	valid := DataFrame{
		Version: DataFrameVersion, Type: DataTypePacket, HopLimit: 8,
		Source: "A", Destination: "C", FlowID: 1, Payload: []byte("x"),
	}
	tests := []struct {
		name string
		edit func(*DataFrame)
		want string
	}{
		{name: "version", edit: func(frame *DataFrame) { frame.Version++ }, want: "version"},
		{name: "type", edit: func(frame *DataFrame) { frame.Type = 99 }, want: "type"},
		{name: "hop", edit: func(frame *DataFrame) { frame.HopLimit = 0 }, want: "hop limit"},
		{name: "source", edit: func(frame *DataFrame) { frame.Source = "" }, want: "source"},
		{name: "flow", edit: func(frame *DataFrame) { frame.FlowID = 0 }, want: "flow id"},
		{name: "payload", edit: func(frame *DataFrame) { frame.Payload = nil }, want: "requires payload"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame := valid
			tt.edit(&frame)
			err := ValidateDataFrame(frame)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ValidateDataFrame() error = %v, want contains %q", err, tt.want)
			}
		})
	}
}

func TestStreamACKRoundTripAndRejectsPayload(t *testing.T) {
	ack := DataFrame{
		Version: DataFrameVersion, Type: DataTypeStreamACK, HopLimit: 8,
		Source: "B", Destination: "A", FlowID: 9, Sequence: 17,
	}
	raw, err := MarshalDataFrame(ack)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalDataFrame(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != DataTypeStreamACK || got.FlowID != ack.FlowID || got.Sequence != ack.Sequence || len(got.Payload) != 0 {
		t.Fatalf("ACK round trip = %#v, want %#v", got, ack)
	}
	ack.Payload = []byte("not allowed")
	if err := ValidateDataFrame(ack); err == nil || !strings.Contains(err.Error(), "does not accept payload") {
		t.Fatalf("ValidateDataFrame(ACK payload) error = %v", err)
	}
}

func TestUnmarshalDataFrameRejectsLengthMismatch(t *testing.T) {
	frame := DataFrame{
		Version: DataFrameVersion, Type: DataTypePacket, HopLimit: 8,
		Source: "A", Destination: "C", FlowID: 1, Payload: []byte("x"),
	}
	raw, err := MarshalDataFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	raw = raw[:len(raw)-1]
	if _, err := UnmarshalDataFrame(raw); err == nil {
		t.Fatal("UnmarshalDataFrame() accepted truncated payload")
	}
}
