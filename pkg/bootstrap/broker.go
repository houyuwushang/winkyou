package bootstrap

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const defaultEnvelopeTTL = 5 * time.Minute

type MemoryBroker struct {
	mu          sync.Mutex
	now         func() time.Time
	envelopeTTL time.Duration
	descriptors map[string]PeerDescriptor
	envelopes   map[string][]queuedEnvelope
}

type queuedEnvelope struct {
	envelope  Envelope
	expiresAt time.Time
}

func NewMemoryBroker(envelopeTTL time.Duration) *MemoryBroker {
	if envelopeTTL <= 0 {
		envelopeTTL = defaultEnvelopeTTL
	}
	return &MemoryBroker{
		now:         time.Now,
		envelopeTTL: envelopeTTL,
		descriptors: make(map[string]PeerDescriptor),
		envelopes:   make(map[string][]queuedEnvelope),
	}
}

func (b *MemoryBroker) PutDescriptor(peer PeerDescriptor) error {
	if b == nil {
		return errors.New("bootstrap: memory broker is nil")
	}
	if err := peer.Validate(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cleanupExpiredLocked(b.now())
	b.descriptors[peer.NodeID] = peer
	return nil
}

func (b *MemoryBroker) GetDescriptor(nodeID string) (PeerDescriptor, bool) {
	if b == nil {
		return PeerDescriptor{}, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	b.cleanupExpiredLocked(now)
	descriptor, ok := b.descriptors[strings.TrimSpace(nodeID)]
	if !ok || descriptorExpired(descriptor, now) {
		delete(b.descriptors, strings.TrimSpace(nodeID))
		return PeerDescriptor{}, false
	}
	return descriptor, true
}

func (b *MemoryBroker) QueueEnvelope(to string, env Envelope) error {
	if b == nil {
		return errors.New("bootstrap: memory broker is nil")
	}
	to = strings.TrimSpace(to)
	if to == "" {
		to = strings.TrimSpace(env.To)
	}
	if to == "" {
		return errors.New("bootstrap: envelope queue target is required")
	}
	if strings.TrimSpace(env.To) == "" {
		env.To = to
	}
	if env.To != to {
		return fmt.Errorf("bootstrap: envelope target %q does not match queue target %q", env.To, to)
	}
	if err := env.Validate(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	b.cleanupExpiredLocked(now)
	b.envelopes[to] = append(b.envelopes[to], queuedEnvelope{
		envelope:  env,
		expiresAt: now.Add(b.envelopeTTL),
	})
	return nil
}

func (b *MemoryBroker) DrainEnvelopes(nodeID string) []Envelope {
	if b == nil {
		return nil
	}
	nodeID = strings.TrimSpace(nodeID)
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	b.cleanupExpiredLocked(now)
	queued := b.envelopes[nodeID]
	delete(b.envelopes, nodeID)
	out := make([]Envelope, 0, len(queued))
	for _, item := range queued {
		if item.expiresAt.After(now) {
			out = append(out, item.envelope)
		}
	}
	return out
}

func (b *MemoryBroker) CleanupExpired() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cleanupExpiredLocked(b.now())
}

func (b *MemoryBroker) cleanupExpiredLocked(now time.Time) {
	for nodeID, descriptor := range b.descriptors {
		if descriptorExpired(descriptor, now) {
			delete(b.descriptors, nodeID)
		}
	}
	for nodeID, queued := range b.envelopes {
		filtered := queued[:0]
		for _, item := range queued {
			if item.expiresAt.After(now) {
				filtered = append(filtered, item)
			}
		}
		if len(filtered) == 0 {
			delete(b.envelopes, nodeID)
			continue
		}
		b.envelopes[nodeID] = filtered
	}
}

func descriptorExpired(descriptor PeerDescriptor, now time.Time) bool {
	return descriptor.ExpiresAt.IsZero() || !descriptor.ExpiresAt.After(now)
}
