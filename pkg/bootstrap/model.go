package bootstrap

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	rproto "winkyou/pkg/rendezvous/proto"
)

const EnvelopeVersion = 1

type PeerDescriptor struct {
	NodeID     string            `json:"node_id"`
	PublicKey  string            `json:"public_key"`
	VirtualIP  string            `json:"virtual_ip"`
	Capability rproto.Capability `json:"capability"`
	LastPathID string            `json:"last_path_id,omitempty"`
	Candidates []CandidateHint   `json:"candidates,omitempty"`
	UpdatedAt  time.Time         `json:"updated_at"`
	ExpiresAt  time.Time         `json:"expires_at"`
}

type CandidateHint struct {
	Strategy string `json:"strategy"`
	Type     string `json:"type"`
	Address  string `json:"address"`
	Source   string `json:"source,omitempty"`
}

type Envelope struct {
	Version int             `json:"version"`
	From    string          `json:"from"`
	To      string          `json:"to"`
	Type    string          `json:"type"`
	Seq     uint64          `json:"seq"`
	Payload json.RawMessage `json:"payload"`
	SentAt  time.Time       `json:"sent_at"`
}

func DecodePeerDescriptor(data []byte) (PeerDescriptor, error) {
	var descriptor PeerDescriptor
	if err := json.Unmarshal(data, &descriptor); err != nil {
		return PeerDescriptor{}, err
	}
	return descriptor, descriptor.Validate()
}

func DecodeEnvelope(data []byte) (Envelope, error) {
	var envelope Envelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return Envelope{}, err
	}
	return envelope, envelope.Validate()
}

func (d PeerDescriptor) Validate() error {
	if strings.TrimSpace(d.NodeID) == "" {
		return errors.New("bootstrap: peer descriptor node_id is required")
	}
	if strings.TrimSpace(d.PublicKey) == "" {
		return errors.New("bootstrap: peer descriptor public_key is required")
	}
	if strings.TrimSpace(d.VirtualIP) == "" {
		return errors.New("bootstrap: peer descriptor virtual_ip is required")
	}
	if len(d.Capability.Strategies) == 0 && len(d.Capability.Features) == 0 {
		return errors.New("bootstrap: peer descriptor capability is required")
	}
	if d.UpdatedAt.IsZero() {
		return errors.New("bootstrap: peer descriptor updated_at is required")
	}
	if d.ExpiresAt.IsZero() {
		return errors.New("bootstrap: peer descriptor expires_at is required")
	}
	if !d.ExpiresAt.After(time.Now()) {
		return errors.New("bootstrap: peer descriptor is expired")
	}
	if d.ExpiresAt.Before(d.UpdatedAt) {
		return errors.New("bootstrap: peer descriptor expires_at is before updated_at")
	}
	for i, hint := range d.Candidates {
		if err := hint.Validate(); err != nil {
			return fmt.Errorf("bootstrap: candidate hint %d: %w", i, err)
		}
	}
	return nil
}

func (h CandidateHint) Validate() error {
	if strings.TrimSpace(h.Strategy) == "" {
		return errors.New("strategy is required")
	}
	if strings.TrimSpace(h.Type) == "" {
		return errors.New("type is required")
	}
	if strings.TrimSpace(h.Address) == "" {
		return errors.New("address is required")
	}
	return nil
}

func (e Envelope) Validate() error {
	if e.Version <= 0 {
		return errors.New("bootstrap: envelope version is required")
	}
	if strings.TrimSpace(e.From) == "" {
		return errors.New("bootstrap: envelope from is required")
	}
	if strings.TrimSpace(e.To) == "" {
		return errors.New("bootstrap: envelope to is required")
	}
	if strings.TrimSpace(e.Type) == "" {
		return errors.New("bootstrap: envelope type is required")
	}
	if e.Seq == 0 {
		return errors.New("bootstrap: envelope seq is required")
	}
	if len(e.Payload) == 0 || !json.Valid(e.Payload) {
		return errors.New("bootstrap: envelope payload must be valid JSON")
	}
	if e.SentAt.IsZero() {
		return errors.New("bootstrap: envelope sent_at is required")
	}
	return nil
}
