package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"winkyou/pkg/bootstrap/selfhosted"
	"winkyou/pkg/mesh/shortcut"
	"winkyou/pkg/solver"
)

type memberView struct {
	NodeID       string   `json:"node_id"`
	VirtualIP    string   `json:"virtual_ip,omitempty"`
	Endpoints    []string `json:"endpoints,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	NATProfile   string   `json:"nat_profile,omitempty"`
}

type routeView struct {
	Destination string   `json:"destination"`
	NextHop     string   `json:"next_hop"`
	HopCount    int      `json:"hop_count"`
	RTTMillis   int64    `json:"rtt_millis"`
	Path        []string `json:"path"`
}

type counterView struct {
	ControlForwarded uint64 `json:"control_forwarded"`
	ControlDropped   uint64 `json:"control_dropped"`
	DataForwarded    uint64 `json:"data_forwarded"`
	DataDropped      uint64 `json:"data_dropped"`
	SolverForwarded  uint64 `json:"solver_signals_forwarded"`
}

type shortcutView struct {
	AttemptID      string                  `json:"attempt_id"`
	InitiatorID    string                  `json:"initiator_id"`
	TargetID       string                  `json:"target_id"`
	CoordinatorID  string                  `json:"coordinator_id"`
	Strategy       string                  `json:"strategy"`
	LocalRole      string                  `json:"local_role"`
	Phase          shortcut.Phase          `json:"phase"`
	DirectPeerID   string                  `json:"direct_peer_id,omitempty"`
	PathID         string                  `json:"path_id,omitempty"`
	ConnectionType string                  `json:"connection_type,omitempty"`
	RemoteAddr     string                  `json:"remote_addr,omitempty"`
	PathRole       solver.PathRole         `json:"path_role,omitempty"`
	Dependencies   []solver.PathDependency `json:"dependencies,omitempty"`
	Details        map[string]string       `json:"details,omitempty"`
	Metrics        map[string]string       `json:"metrics,omitempty"`
	StartedAt      time.Time               `json:"started_at"`
	UpdatedAt      time.Time               `json:"updated_at"`
	ProbationUntil time.Time               `json:"probation_until,omitempty"`
	Failure        string                  `json:"failure,omitempty"`
}

type tcpForwardView struct {
	ID              string `json:"id"`
	Source          string `json:"source"`
	RequestedListen string `json:"requested_listen"`
	Listen          string `json:"listen"`
	RemoteID        string `json:"remote_id"`
	VirtualIP       string `json:"virtual_ip,omitempty"`
}

type tcpTargetView struct {
	Target string `json:"target"`
	Source string `json:"source,omitempty"`
}

func newShortcutView(status shortcut.Status) shortcutView {
	return shortcutView{
		AttemptID: status.AttemptID, InitiatorID: status.InitiatorID, TargetID: status.TargetID,
		CoordinatorID: status.CoordinatorID, Strategy: status.Strategy, LocalRole: status.LocalRole,
		Phase: status.Phase, DirectPeerID: status.DirectPeerID,
		PathID: status.PathSummary.PathID, ConnectionType: status.PathSummary.ConnectionType,
		RemoteAddr: addrString(status.PathSummary.RemoteAddr), PathRole: status.PathSummary.Role,
		Dependencies: append([]solver.PathDependency(nil), status.PathSummary.Dependencies...),
		Details:      status.PathSummary.Details, Metrics: status.PathSummary.Metrics,
		StartedAt: status.StartedAt, UpdatedAt: status.UpdatedAt,
		ProbationUntil: status.ProbationUntil, Failure: status.Failure,
	}
}

type statusView struct {
	NodeID           string                  `json:"node_id"`
	VirtualIP        string                  `json:"virtual_ip,omitempty"`
	StartedAt        time.Time               `json:"started_at"`
	Uptime           string                  `json:"uptime"`
	MeshListen       string                  `json:"mesh_listen,omitempty"`
	ControlListen    string                  `json:"control_listen,omitempty"`
	Neighbors        []string                `json:"neighbors"`
	DesiredPeers     map[string]string       `json:"desired_bootstrap_peers"`
	Members          []memberView            `json:"members"`
	Routes           []routeView             `json:"routes"`
	Shortcuts        []shortcutView          `json:"shortcuts"`
	MaintainedPeers  []maintainedPeerView    `json:"maintained_direct_peers,omitempty"`
	SelfBootstrap    []selfhosted.PeerStatus `json:"self_bootstrap_peers,omitempty"`
	TCPTarget        string                  `json:"tcp_target,omitempty"`
	TCPTargetSource  string                  `json:"tcp_target_source,omitempty"`
	TCPForwards      []tcpForwardView        `json:"tcp_forwards,omitempty"`
	Counters         counterView             `json:"counters"`
	InfrastructureUp bool                    `json:"infrastructure_coordinator_started"`
}

func (r *meshRuntime) status() statusView {
	tcpTarget := r.tcpTargetSnapshot()
	membersByID := r.node.Members()
	memberIDs := make([]string, 0, len(membersByID))
	for nodeID := range membersByID {
		memberIDs = append(memberIDs, nodeID)
	}
	sort.Strings(memberIDs)
	members := make([]memberView, 0, len(memberIDs))
	for _, nodeID := range memberIDs {
		record := membersByID[nodeID]
		members = append(members, memberView{
			NodeID: record.NodeID, VirtualIP: record.VirtualIP,
			Endpoints:    append([]string(nil), record.Endpoints...),
			Capabilities: append([]string(nil), record.Capabilities...), NATProfile: record.NATProfile,
		})
	}
	routesByID := r.node.Routes()
	routeIDs := make([]string, 0, len(routesByID))
	for destination := range routesByID {
		routeIDs = append(routeIDs, destination)
	}
	sort.Strings(routeIDs)
	routes := make([]routeView, 0, len(routeIDs))
	for _, destination := range routeIDs {
		route := routesByID[destination]
		routes = append(routes, routeView{
			Destination: route.Destination, NextHop: route.NextHop, HopCount: route.HopCount,
			RTTMillis: route.RTT.Milliseconds(), Path: append([]string(nil), route.Path...),
		})
	}
	shortcutStatuses := r.shortcutSnapshot()
	sort.Slice(shortcutStatuses, func(i, j int) bool { return shortcutStatuses[i].AttemptID < shortcutStatuses[j].AttemptID })
	shortcuts := make([]shortcutView, 0, len(shortcutStatuses))
	for _, status := range shortcutStatuses {
		shortcuts = append(shortcuts, newShortcutView(status))
	}
	desired := map[string]string{}
	if r.connectors != nil {
		desired = r.connectors.Snapshot()
	}
	selfBootstrap := []selfhosted.PeerStatus(nil)
	if r.selfBootstrap != nil {
		selfBootstrap = r.selfBootstrap.Snapshot()
	}
	return statusView{
		NodeID: r.cfg.NodeID, VirtualIP: r.cfg.VirtualIP, StartedAt: r.startedAt,
		Uptime:     time.Since(r.startedAt).Round(time.Millisecond).String(),
		MeshListen: r.MeshAddr(), ControlListen: r.ControlAddr(), Neighbors: r.node.Neighbors(),
		DesiredPeers: desired, Members: members, Routes: routes, Shortcuts: shortcuts,
		MaintainedPeers: r.recovery.Snapshot(), SelfBootstrap: selfBootstrap,
		TCPTarget: tcpTarget.Target, TCPTargetSource: tcpTarget.Source,
		TCPForwards: r.tcpForwardSnapshot(),
		Counters: counterView{
			ControlForwarded: r.counters.controlForwarded.Load(),
			ControlDropped:   r.counters.controlDropped.Load(),
			DataForwarded:    r.counters.dataForwarded.Load(),
			DataDropped:      r.counters.dataDropped.Load(),
			SolverForwarded:  r.counters.solverForwarded.Load(),
		},
		InfrastructureUp: false,
	}
}

func startControlServer(ctx context.Context, runtime *meshRuntime, address string) (*http.Server, error) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	server := &http.Server{
		Addr:              listener.Addr().String(),
		Handler:           runtime.controlMux(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		err := server.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			runtime.log.write("control_server_failed", map[string]any{"error": err.Error()})
		}
	}()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = server.Shutdown(shutdownCtx)
		cancel()
	}()
	return server, nil
}

func (r *meshRuntime) controlMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "node_id": r.cfg.NodeID})
	})
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, r.status())
	})
	mux.HandleFunc("POST /v1/peers", r.handleAddPeer)
	mux.HandleFunc("DELETE /v1/peers/{peerID}", r.handleRemovePeer)
	mux.HandleFunc("DELETE /v1/neighbors/{peerID}", r.handleRemoveNeighbor)
	mux.HandleFunc("POST /v1/shortcuts", r.handleStartShortcut)
	mux.HandleFunc("GET /v1/shortcuts/{attemptID}", r.handleShortcutStatus)
	mux.HandleFunc("POST /v1/ping", r.handlePing)
	mux.HandleFunc("GET /v1/tcp/target", r.handleGetTCPTarget)
	mux.HandleFunc("PUT /v1/tcp/target", r.handleSetTCPTarget)
	mux.HandleFunc("DELETE /v1/tcp/target", r.handleClearTCPTarget)
	mux.HandleFunc("GET /v1/tcp/forwards", r.handleGetTCPForwards)
	mux.HandleFunc("POST /v1/tcp/forwards", r.handleAddTCPForward)
	mux.HandleFunc("DELETE /v1/tcp/forwards/{forwardID}", r.handleRemoveTCPForward)
	return mux
}

type tcpTargetRequest struct {
	Target string `json:"target"`
}

type tcpForwardRequest struct {
	Listen   string `json:"listen"`
	RemoteID string `json:"remote_id"`
}

func (r *meshRuntime) handleGetTCPTarget(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, r.tcp.TargetSnapshot())
}

func (r *meshRuntime) handleSetTCPTarget(w http.ResponseWriter, request *http.Request) {
	var body tcpTargetRequest
	if err := decodeJSON(request, &body); err != nil {
		writeAPIError(w, http.StatusBadRequest, err)
		return
	}
	body.Target = strings.TrimSpace(body.Target)
	if err := validateTCPTarget(body.Target); err != nil {
		writeAPIError(w, http.StatusBadRequest, err)
		return
	}
	if err := r.tcp.SetTarget(body.Target); err != nil {
		writeAPIError(w, tcpAPIErrorStatus(err), err)
		return
	}
	writeJSON(w, http.StatusOK, r.tcp.TargetSnapshot())
}

func (r *meshRuntime) handleClearTCPTarget(w http.ResponseWriter, _ *http.Request) {
	if err := r.tcp.ClearTarget(); err != nil {
		writeAPIError(w, tcpAPIErrorStatus(err), err)
		return
	}
	writeJSON(w, http.StatusOK, r.tcp.TargetSnapshot())
}

func (r *meshRuntime) handleGetTCPForwards(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"forwards": r.tcp.Snapshot()})
}

func (r *meshRuntime) handleAddTCPForward(w http.ResponseWriter, request *http.Request) {
	var body tcpForwardRequest
	if err := decodeJSON(request, &body); err != nil {
		writeAPIError(w, http.StatusBadRequest, err)
		return
	}
	body.Listen = strings.TrimSpace(body.Listen)
	body.RemoteID = strings.TrimSpace(body.RemoteID)
	if err := validateTCPForward(r.cfg.NodeID, body.Listen, body.RemoteID); err != nil {
		writeAPIError(w, http.StatusBadRequest, err)
		return
	}
	view, err := r.tcp.AddForward(body.Listen, body.RemoteID, tcpForwardSourceRuntime)
	if err != nil {
		writeAPIError(w, tcpAPIErrorStatus(err), err)
		return
	}
	writeJSON(w, http.StatusCreated, view)
}

func (r *meshRuntime) handleRemoveTCPForward(w http.ResponseWriter, request *http.Request) {
	view, err := r.tcp.RemoveForward(strings.TrimSpace(request.PathValue("forwardID")))
	if err != nil {
		writeAPIError(w, tcpAPIErrorStatus(err), err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func validateTCPTarget(target string) error {
	host, _, err := net.SplitHostPort(strings.TrimSpace(target))
	if err != nil {
		return fmt.Errorf("invalid routed TCP target %q: %w", target, err)
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("invalid routed TCP target %q: host must be loopback", target)
	}
	return nil
}

func tcpAPIErrorStatus(err error) int {
	switch {
	case errors.Is(err, ErrTCPForwardNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrTCPConfigImmutable), errors.Is(err, ErrTCPForwardConflict),
		errors.Is(err, ErrTCPForwardLimit):
		return http.StatusConflict
	case errors.Is(err, ErrTCPRuntimeNotStarted), errors.Is(err, ErrTCPRuntimeClosed):
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

type peerRequest struct {
	PeerID  string `json:"peer_id"`
	Address string `json:"address"`
}

func (r *meshRuntime) handleAddPeer(w http.ResponseWriter, request *http.Request) {
	var body peerRequest
	if err := decodeJSON(request, &body); err != nil {
		writeAPIError(w, http.StatusBadRequest, err)
		return
	}
	if err := r.connectors.Add(body.PeerID, body.Address); err != nil {
		writeAPIError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"peer_id": body.PeerID, "address": body.Address, "desired": true})
}

func (r *meshRuntime) handleRemovePeer(w http.ResponseWriter, request *http.Request) {
	peerID := strings.TrimSpace(request.PathValue("peerID"))
	if !r.connectors.Remove(peerID) {
		writeAPIError(w, http.StatusNotFound, fmt.Errorf("desired bootstrap peer %q not found", peerID))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"peer_id": peerID, "desired": false})
}

func (r *meshRuntime) handleRemoveNeighbor(w http.ResponseWriter, request *http.Request) {
	peerID := strings.TrimSpace(request.PathValue("peerID"))
	if err := r.node.RemoveNeighbor(peerID); err != nil {
		writeAPIError(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"peer_id": peerID, "attached": false})
}

type shortcutRequest struct {
	TargetID      string `json:"target_id"`
	CoordinatorID string `json:"coordinator_id"`
	Wait          bool   `json:"wait,omitempty"`
	Timeout       string `json:"timeout,omitempty"`
}

func (r *meshRuntime) handleStartShortcut(w http.ResponseWriter, request *http.Request) {
	var body shortcutRequest
	if err := decodeJSON(request, &body); err != nil {
		writeAPIError(w, http.StatusBadRequest, err)
		return
	}
	waitTimeout := saturatingPositiveDurationSum(r.cfg.AttemptTimeout, time.Second)
	if body.Wait && strings.TrimSpace(body.Timeout) != "" {
		parsed, err := time.ParseDuration(body.Timeout)
		if err != nil || parsed <= 0 {
			writeAPIError(w, http.StatusBadRequest, fmt.Errorf("invalid timeout %q", body.Timeout))
			return
		}
		waitTimeout = parsed
	}
	handle, err := r.shortcuts.Start(r.ctx, body.TargetID, body.CoordinatorID)
	if err != nil {
		writeAPIError(w, http.StatusConflict, err)
		return
	}
	status, _ := handle.Status()
	if body.Wait {
		waitCtx, cancel := context.WithTimeout(request.Context(), waitTimeout)
		status, err = handle.WaitFor(waitCtx, shortcut.PhaseStable)
		cancel()
		if err != nil {
			writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "status": newShortcutView(status)})
			return
		}
		writeJSON(w, http.StatusOK, newShortcutView(status))
		return
	}
	writeJSON(w, http.StatusAccepted, newShortcutView(status))
}

func (r *meshRuntime) handleShortcutStatus(w http.ResponseWriter, request *http.Request) {
	attemptID := strings.TrimSpace(request.PathValue("attemptID"))
	status, ok := r.shortcuts.Status(attemptID)
	if !ok {
		r.shortcutMu.Lock()
		status, ok = r.shortcutStatuses[attemptID]
		r.shortcutMu.Unlock()
	}
	if !ok {
		writeAPIError(w, http.StatusNotFound, fmt.Errorf("shortcut attempt %q not found", attemptID))
		return
	}
	writeJSON(w, http.StatusOK, newShortcutView(status))
}

type pingRequest struct {
	TargetID string `json:"target_id"`
	Payload  string `json:"payload,omitempty"`
	Timeout  string `json:"timeout,omitempty"`
}

func (r *meshRuntime) handlePing(w http.ResponseWriter, request *http.Request) {
	var body pingRequest
	if err := decodeJSON(request, &body); err != nil {
		writeAPIError(w, http.StatusBadRequest, err)
		return
	}
	timeout := 5 * time.Second
	if strings.TrimSpace(body.Timeout) != "" {
		parsed, err := time.ParseDuration(body.Timeout)
		if err != nil || parsed <= 0 {
			writeAPIError(w, http.StatusBadRequest, fmt.Errorf("invalid timeout %q", body.Timeout))
			return
		}
		timeout = parsed
	}
	pingCtx, cancel := context.WithTimeout(request.Context(), timeout)
	result, err := r.echo.ping(pingCtx, strings.TrimSpace(body.TargetID), []byte(body.Payload))
	cancel()
	if err != nil {
		writeAPIError(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func decodeJSON(request *http.Request, destination any) error {
	decoder := json.NewDecoder(io.LimitReader(request.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("decode JSON: request body must contain exactly one JSON value")
		}
		return fmt.Errorf("decode trailing JSON content: %w", err)
	}
	return nil
}

func writeAPIError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]any{"error": err.Error()})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
