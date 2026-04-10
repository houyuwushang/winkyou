package nat

import (
	"context"
	"net"
)

// stubICEAgent is a skeleton ICEAgent implementation that returns
// ErrNotImplemented for all methods. Used by tests that need a
// minimal agent without real network I/O.
type stubICEAgent struct {
	cfg    ICEConfig
	closed bool
}

func (s *stubICEAgent) GatherCandidates(ctx context.Context) ([]Candidate, error) {
	return nil, ErrNotImplemented
}

func (s *stubICEAgent) SetRemoteCandidates(candidates []Candidate) error {
	return ErrNotImplemented
}

func (s *stubICEAgent) Connect(ctx context.Context) (net.Conn, *CandidatePair, error) {
	return nil, nil, ErrNotImplemented
}

func (s *stubICEAgent) Close() error {
	s.closed = true
	return nil
}
