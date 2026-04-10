package nat

import (
	"context"
	"net"
)

// stubNATTraversal is a skeleton NATTraversal implementation.
type stubNATTraversal struct {
	cfg Config
}

func (s *stubNATTraversal) DetectNATType(ctx context.Context) (NATType, error) {
	return NATTypeUnknown, ErrNotImplemented
}

func (s *stubNATTraversal) NewICEAgent(cfg ICEConfig) (ICEAgent, error) {
	return &stubICEAgent{cfg: cfg}, nil
}

// stubICEAgent is a skeleton ICEAgent implementation.
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
