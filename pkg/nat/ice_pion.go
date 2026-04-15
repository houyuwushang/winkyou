package nat

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	pionice "github.com/pion/ice/v2"
	"github.com/pion/stun"
)

type icePionAgent struct {
	cfg ICEConfig

	mu               sync.RWMutex
	closed           bool
	agent            *pionice.Agent
	localUfrag       string
	localPwd         string
	remoteUfrag      string
	remotePwd        string
	localCandidates  []Candidate
	remoteCandidates map[string]struct{}
	selectedPair     *CandidatePair
	transport        SelectedTransport
	state            ConnectionState
	onPairChange     func(*CandidatePair)
}

func newICEPionAgent(cfg ICEConfig) (ICEAgent, error) {
	urls, err := buildPionURLs(cfg)
	if err != nil {
		return nil, err
	}

	failedTimeout := cfg.CheckTimeout
	if failedTimeout <= 0 {
		failedTimeout = 10 * time.Second
	}
	disconnectedTimeout := failedTimeout / 2
	if disconnectedTimeout <= 0 {
		disconnectedTimeout = 5 * time.Second
	}

	agent, err := pionice.NewAgent(&pionice.AgentConfig{
		Urls:                urls,
		NetworkTypes:        []pionice.NetworkType{pionice.NetworkTypeUDP4},
		CandidateTypes:      candidateTypesForConfig(cfg),
		MulticastDNSMode:    pionice.MulticastDNSModeDisabled,
		DisconnectedTimeout: &disconnectedTimeout,
		FailedTimeout:       &failedTimeout,
		KeepaliveInterval:   durationPtr(2 * time.Second),
	})
	if err != nil {
		return nil, fmt.Errorf("nat: create pion ice agent: %w", err)
	}

	localUfrag, localPwd, err := agent.GetLocalUserCredentials()
	if err != nil {
		_ = agent.Close()
		return nil, fmt.Errorf("nat: get local ice credentials: %w", err)
	}

	a := &icePionAgent{
		cfg:              cfg,
		agent:            agent,
		localUfrag:       localUfrag,
		localPwd:         localPwd,
		remoteCandidates: make(map[string]struct{}),
		state:            ConnectionStateNew,
	}
	if err := agent.OnConnectionStateChange(func(state pionice.ConnectionState) {
		a.mu.Lock()
		a.state = connectionStateFromPion(state)
		a.mu.Unlock()
	}); err != nil {
		_ = agent.Close()
		return nil, fmt.Errorf("nat: register connection state handler: %w", err)
	}

	if err := agent.OnSelectedCandidatePairChange(func(local, remote pionice.Candidate) {
		a.mu.Lock()
		defer a.mu.Unlock()
		if local == nil || remote == nil {
			return
		}
		localCand, err := candidateFromPion(local)
		if err != nil {
			return
		}
		remoteCand, err := candidateFromPion(remote)
		if err != nil {
			return
		}
		pair := &CandidatePair{
			Local:  &localCand,
			Remote: &remoteCand,
		}
		a.selectedPair = pair
		if a.onPairChange != nil {
			a.onPairChange(pair)
		}
	}); err != nil {
		_ = agent.Close()
		return nil, fmt.Errorf("nat: register selected pair handler: %w", err)
	}

	return a, nil
}

func (a *icePionAgent) GatherCandidates(ctx context.Context) ([]Candidate, error) {
	a.mu.RLock()
	if a.closed {
		a.mu.RUnlock()
		return nil, fmt.Errorf("nat: agent closed")
	}
	if len(a.localCandidates) > 0 {
		cached := cloneCandidates(a.localCandidates)
		a.mu.RUnlock()
		return cached, nil
	}
	a.mu.RUnlock()

	gatherTimeout := a.cfg.GatherTimeout
	if gatherTimeout <= 0 {
		gatherTimeout = 5 * time.Second
	}
	gatherCtx, cancel := context.WithTimeout(ctx, gatherTimeout)
	defer cancel()

	done := make(chan struct{})
	var doneOnce sync.Once
	if err := a.agent.OnCandidate(func(c pionice.Candidate) {
		if c == nil {
			doneOnce.Do(func() { close(done) })
		}
	}); err != nil {
		return nil, fmt.Errorf("nat: register candidate handler: %w", err)
	}

	if err := a.agent.GatherCandidates(); err != nil {
		return nil, fmt.Errorf("nat: gather candidates: %w", err)
	}

	select {
	case <-gatherCtx.Done():
		return nil, fmt.Errorf("nat: gather candidates timeout: %w", gatherCtx.Err())
	case <-done:
	}

	pionCandidates, err := a.agent.GetLocalCandidates()
	if err != nil {
		return nil, fmt.Errorf("nat: get local candidates: %w", err)
	}
	localCandidates, err := candidatesFromPion(pionCandidates)
	if err != nil {
		return nil, err
	}

	a.mu.Lock()
	a.localCandidates = cloneCandidates(localCandidates)
	a.mu.Unlock()

	return cloneCandidates(localCandidates), nil
}

func (a *icePionAgent) GetLocalCredentials() (string, string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.closed {
		return "", "", fmt.Errorf("nat: agent closed")
	}
	return a.localUfrag, a.localPwd, nil
}

func (a *icePionAgent) SetRemoteCredentials(ufrag, pwd string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return fmt.Errorf("nat: agent closed")
	}
	ufrag = strings.TrimSpace(ufrag)
	pwd = strings.TrimSpace(pwd)
	if ufrag == "" {
		return fmt.Errorf("nat: remote ufrag is required")
	}
	if pwd == "" {
		return fmt.Errorf("nat: remote pwd is required")
	}
	a.remoteUfrag = ufrag
	a.remotePwd = pwd
	return nil
}

func (a *icePionAgent) SetRemoteCandidates(candidates []Candidate) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return fmt.Errorf("nat: agent closed")
	}
	if len(candidates) == 0 {
		return fmt.Errorf("nat: no remote candidates provided")
	}
	for _, candidate := range candidates {
		key := candidateKey(candidate)
		if _, ok := a.remoteCandidates[key]; ok {
			continue
		}
		pionCandidate, err := candidateToPion(candidate)
		if err != nil {
			return err
		}
		if err := a.agent.AddRemoteCandidate(pionCandidate); err != nil {
			return fmt.Errorf("nat: add remote candidate: %w", err)
		}
		a.remoteCandidates[key] = struct{}{}
	}
	return nil
}

func (a *icePionAgent) Connect(ctx context.Context) (SelectedTransport, *CandidatePair, error) {
	a.mu.RLock()
	if a.closed {
		a.mu.RUnlock()
		return nil, nil, fmt.Errorf("nat: agent closed")
	}
	if a.transport != nil && a.selectedPair != nil {
		transport := a.transport
		pair := cloneCandidatePair(a.selectedPair)
		a.mu.RUnlock()
		return transport, pair, nil
	}
	remoteUfrag := a.remoteUfrag
	remotePwd := a.remotePwd
	controlling := a.cfg.Controlling
	a.mu.RUnlock()

	if remoteUfrag == "" || remotePwd == "" {
		return nil, nil, fmt.Errorf("nat: remote credentials not set")
	}

	connectTimeout := a.cfg.ConnectTimeout
	if connectTimeout <= 0 {
		connectTimeout = 30 * time.Second
	}
	connectCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()

	var (
		conn *pionice.Conn
		err  error
	)
	if controlling {
		conn, err = a.agent.Dial(connectCtx, remoteUfrag, remotePwd)
	} else {
		conn, err = a.agent.Accept(connectCtx, remoteUfrag, remotePwd)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("nat: ice connect failed: %w", err)
	}

	pair, err := a.GetSelectedPair()
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}

	a.mu.Lock()
	a.transport = conn
	a.selectedPair = cloneCandidatePair(pair)
	a.mu.Unlock()
	return conn, pair, nil
}

func (a *icePionAgent) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	a.closed = true
	return a.agent.Close()
}

func (a *icePionAgent) GetSelectedPair() (*CandidatePair, error) {
	a.mu.RLock()
	if a.closed {
		a.mu.RUnlock()
		return nil, fmt.Errorf("nat: agent closed")
	}
	if a.selectedPair != nil {
		pair := cloneCandidatePair(a.selectedPair)
		a.mu.RUnlock()
		return pair, nil
	}
	a.mu.RUnlock()

	pair, err := a.agent.GetSelectedCandidatePair()
	if err != nil {
		return nil, fmt.Errorf("nat: get selected candidate pair: %w", err)
	}
	if pair == nil {
		return nil, errors.New("nat: no selected pair")
	}

	converted, err := candidatePairFromPion(pair)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.selectedPair = cloneCandidatePair(converted)
	a.mu.Unlock()
	return converted, nil
}

func (a *icePionAgent) GetConnectionState() ConnectionState {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.state
}

func (a *icePionAgent) OnSelectedCandidatePairChange(handler func(*CandidatePair)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.onPairChange = handler
}

func buildPionURLs(cfg ICEConfig) ([]*stun.URI, error) {
	urls := make([]*stun.URI, 0, len(cfg.STUNServers)+len(cfg.TURNServers))
	for _, raw := range cfg.STUNServers {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if !hasURLScheme(raw) {
			raw = "stun:" + raw
		}
		uri, err := stun.ParseURI(raw)
		if err != nil {
			return nil, fmt.Errorf("nat: parse stun server %q: %w", raw, err)
		}
		urls = append(urls, uri)
	}

	for _, turnServer := range cfg.TURNServers {
		raw := strings.TrimSpace(turnServer.URL)
		if raw == "" {
			continue
		}
		if !hasURLScheme(raw) {
			raw = "turn:" + raw
		}
		if !strings.Contains(raw, "?transport=") {
			raw += "?transport=udp"
		}
		uri, err := stun.ParseURI(raw)
		if err != nil {
			return nil, fmt.Errorf("nat: parse turn server %q: %w", raw, err)
		}
		uri.Username = turnServer.Username
		uri.Password = turnServer.Password
		urls = append(urls, uri)
	}
	return urls, nil
}

func candidateTypesForConfig(cfg ICEConfig) []pionice.CandidateType {
	if cfg.relayOnly || cfg.ForceRelay {
		return []pionice.CandidateType{pionice.CandidateTypeRelay}
	}
	return []pionice.CandidateType{
		pionice.CandidateTypeHost,
		pionice.CandidateTypeServerReflexive,
		pionice.CandidateTypeRelay,
	}
}

func hasURLScheme(raw string) bool {
	lower := strings.ToLower(strings.TrimSpace(raw))
	return strings.HasPrefix(lower, "stun:") ||
		strings.HasPrefix(lower, "stuns:") ||
		strings.HasPrefix(lower, "turn:") ||
		strings.HasPrefix(lower, "turns:")
}

func durationPtr(v time.Duration) *time.Duration {
	if v <= 0 {
		return nil
	}
	return &v
}

func connectionStateFromPion(state pionice.ConnectionState) ConnectionState {
	switch state {
	case pionice.ConnectionStateChecking:
		return ConnectionStateChecking
	case pionice.ConnectionStateConnected:
		return ConnectionStateConnected
	case pionice.ConnectionStateCompleted:
		return ConnectionStateCompleted
	case pionice.ConnectionStateFailed:
		return ConnectionStateFailed
	case pionice.ConnectionStateClosed:
		return ConnectionStateClosed
	default:
		return ConnectionStateNew
	}
}

func candidateKey(candidate Candidate) string {
	address := ""
	if candidate.Address != nil {
		address = candidate.Address.String()
	}
	return fmt.Sprintf("%d|%s|%d|%s", candidate.Type, address, candidate.Priority, candidate.Foundation)
}

func candidatesFromPion(candidates []pionice.Candidate) ([]Candidate, error) {
	out := make([]Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		converted, err := candidateFromPion(candidate)
		if err != nil {
			return nil, err
		}
		out = append(out, converted)
	}
	return out, nil
}

func candidateFromPion(candidate pionice.Candidate) (Candidate, error) {
	ip := net.ParseIP(candidate.Address())
	if ip == nil {
		return Candidate{}, fmt.Errorf("nat: invalid candidate address %q", candidate.Address())
	}

	out := Candidate{
		Type:       candidateTypeFromPion(candidate.Type()),
		Address:    &net.UDPAddr{IP: append(net.IP(nil), ip...), Port: candidate.Port()},
		Priority:   candidate.Priority(),
		Foundation: candidate.Foundation(),
	}
	if related := candidate.RelatedAddress(); related != nil {
		relatedIP := net.ParseIP(related.Address)
		if relatedIP != nil {
			out.RelatedAddr = &net.UDPAddr{IP: append(net.IP(nil), relatedIP...), Port: related.Port}
		}
	}
	return out, nil
}

func candidateTypeFromPion(candidateType pionice.CandidateType) CandidateType {
	switch candidateType {
	case pionice.CandidateTypeHost:
		return CandidateTypeHost
	case pionice.CandidateTypeServerReflexive:
		return CandidateTypeSrflx
	case pionice.CandidateTypePeerReflexive:
		return CandidateTypePrflx
	case pionice.CandidateTypeRelay:
		return CandidateTypeRelay
	default:
		return CandidateTypeHost
	}
}

func candidateToPion(candidate Candidate) (pionice.Candidate, error) {
	if candidate.Address == nil || candidate.Address.IP == nil {
		return nil, fmt.Errorf("nat: candidate address is required")
	}

	network := "udp"
	component := pionice.ComponentRTP
	address := candidate.Address.IP.String()
	port := candidate.Address.Port
	foundation := candidate.Foundation
	priority := candidate.Priority

	relatedAddress := ""
	relatedPort := 0
	if candidate.RelatedAddr != nil {
		relatedAddress = candidate.RelatedAddr.IP.String()
		relatedPort = candidate.RelatedAddr.Port
	}

	switch candidate.Type {
	case CandidateTypeHost:
		return pionice.NewCandidateHost(&pionice.CandidateHostConfig{
			Network:    network,
			Address:    address,
			Port:       port,
			Component:  component,
			Priority:   priority,
			Foundation: foundation,
		})
	case CandidateTypeSrflx:
		return pionice.NewCandidateServerReflexive(&pionice.CandidateServerReflexiveConfig{
			Network:    network,
			Address:    address,
			Port:       port,
			Component:  component,
			Priority:   priority,
			Foundation: foundation,
			RelAddr:    relatedAddress,
			RelPort:    relatedPort,
		})
	case CandidateTypePrflx:
		return pionice.NewCandidatePeerReflexive(&pionice.CandidatePeerReflexiveConfig{
			Network:    network,
			Address:    address,
			Port:       port,
			Component:  component,
			Priority:   priority,
			Foundation: foundation,
			RelAddr:    relatedAddress,
			RelPort:    relatedPort,
		})
	case CandidateTypeRelay:
		return pionice.NewCandidateRelay(&pionice.CandidateRelayConfig{
			Network:       network,
			Address:       address,
			Port:          port,
			Component:     component,
			Priority:      priority,
			Foundation:    foundation,
			RelAddr:       relatedAddress,
			RelPort:       relatedPort,
			RelayProtocol: "udp",
		})
	default:
		return nil, fmt.Errorf("nat: unsupported candidate type %v", candidate.Type)
	}
}

func candidatePairFromPion(pair *pionice.CandidatePair) (*CandidatePair, error) {
	if pair == nil {
		return nil, errors.New("nat: selected pair is nil")
	}
	local, err := candidateFromPion(pair.Local)
	if err != nil {
		return nil, err
	}
	remote, err := candidateFromPion(pair.Remote)
	if err != nil {
		return nil, err
	}
	return &CandidatePair{
		Local:  cloneCandidate(local),
		Remote: cloneCandidate(remote),
	}, nil
}

func cloneCandidatePair(pair *CandidatePair) *CandidatePair {
	if pair == nil {
		return nil
	}
	out := &CandidatePair{}
	if pair.Local != nil {
		out.Local = cloneCandidate(*pair.Local)
	}
	if pair.Remote != nil {
		out.Remote = cloneCandidate(*pair.Remote)
	}
	return out
}

func cloneCandidates(candidates []Candidate) []Candidate {
	if len(candidates) == 0 {
		return nil
	}
	out := make([]Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		out = append(out, *cloneCandidate(candidate))
	}
	return out
}

func cloneCandidate(candidate Candidate) *Candidate {
	out := &Candidate{
		Type:       candidate.Type,
		Priority:   candidate.Priority,
		Foundation: candidate.Foundation,
	}
	if candidate.Address != nil {
		out.Address = &net.UDPAddr{
			IP:   append(net.IP(nil), candidate.Address.IP...),
			Port: candidate.Address.Port,
			Zone: candidate.Address.Zone,
		}
	}
	if candidate.RelatedAddr != nil {
		out.RelatedAddr = &net.UDPAddr{
			IP:   append(net.IP(nil), candidate.RelatedAddr.IP...),
			Port: candidate.RelatedAddr.Port,
			Zone: candidate.RelatedAddr.Zone,
		}
	}
	return out
}
