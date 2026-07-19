package meshruntime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"

	"winkyou/pkg/dataplane/routed"
	"winkyou/pkg/mesh"
	"winkyou/pkg/systemingress/ipalias"
)

const (
	tcpForwardSourceConfig  = "config"
	tcpForwardSourceRuntime = "runtime"
	maxDynamicTCPForwards   = 64
)

var (
	ErrTCPForwardNotFound   = errors.New("routed TCP forward not found")
	ErrTCPConfigImmutable   = errors.New("configured routed TCP state is immutable")
	ErrTCPForwardLimit      = errors.New("dynamic routed TCP forward limit reached")
	ErrTCPRuntimeNotStarted = errors.New("routed TCP runtime not started")
	ErrTCPRuntimeClosed     = errors.New("routed TCP runtime closed")
	ErrTCPForwardConflict   = errors.New("routed TCP forward conflicts with an existing listener")
)

type virtualAliasManager interface {
	Add(netip.Addr) error
	Remove(netip.Addr) error
	Close() error
}

type tcpForwardSpec struct {
	Listen   string
	RemoteID string
	// VirtualIP is set only for a system-visible virtual-address facade. A
	// zero value retains the legacy loopback-only listener behavior.
	VirtualIP netip.Addr
}

func normalizeTCPConfig(config *runtimeConfig) error {
	config.TCPTarget = strings.TrimSpace(config.TCPTarget)
	config.tcpForwardSpecs = nil
	if len(config.VirtualTCPForwards) > 0 {
		localVirtualIP, err := netip.ParseAddr(strings.TrimSpace(config.VirtualIP))
		if err != nil || !isIPv6ULA(localVirtualIP) {
			return fmt.Errorf("--virtual-tcp-forward requires this node's --virtual-ip to be a numeric IPv6 ULA address")
		}
	}
	seen := make(map[string]struct{}, len(config.TCPForwards)+len(config.VirtualTCPForwards))
	for _, raw := range config.TCPForwards {
		listen, remoteID, ok := strings.Cut(strings.TrimSpace(raw), "=")
		listen = strings.TrimSpace(listen)
		remoteID = strings.TrimSpace(remoteID)
		if !ok || listen == "" || remoteID == "" {
			return fmt.Errorf("invalid --tcp-forward %q: want LISTEN=NODE_ID", raw)
		}
		if err := validateTCPForward(config.NodeID, listen, remoteID); err != nil {
			return fmt.Errorf("invalid --tcp-forward %q: %w", raw, err)
		}
		key := listen
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate --tcp-forward %q", raw)
		}
		seen[key] = struct{}{}
		config.tcpForwardSpecs = append(config.tcpForwardSpecs, tcpForwardSpec{Listen: listen, RemoteID: remoteID})
	}
	for _, raw := range config.VirtualTCPForwards {
		listen, remoteID, ok := strings.Cut(strings.TrimSpace(raw), "=")
		listen = strings.TrimSpace(listen)
		remoteID = strings.TrimSpace(remoteID)
		if !ok || listen == "" || remoteID == "" {
			return fmt.Errorf("invalid --virtual-tcp-forward %q: want [VIRTUAL_IP]:PORT=NODE_ID", raw)
		}
		virtualIP, key, err := validateVirtualTCPForward(config.NodeID, config.VirtualIP, listen, remoteID)
		if err != nil {
			return fmt.Errorf("invalid --virtual-tcp-forward %q: %w", raw, err)
		}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate routed TCP listener %q", listen)
		}
		seen[key] = struct{}{}
		config.tcpForwardSpecs = append(config.tcpForwardSpecs, tcpForwardSpec{
			Listen: listen, RemoteID: remoteID, VirtualIP: virtualIP,
		})
	}
	return nil
}

type activeTCPForward struct {
	id              string
	source          string
	requestedListen string
	actualListen    string
	remoteID        string
	virtualIP       netip.Addr
	listener        *routed.TCPListener
}

type tcpRuntime struct {
	node      *mesh.Node
	endpoint  *routed.Endpoint
	forwarder *routed.TCPForwarder
	specs     []tcpForwardSpec

	mu                sync.Mutex
	started           bool
	ready             bool
	closed            bool
	runtimeCtx        context.Context
	runtimeCancel     context.CancelFunc
	log               *eventLog
	targetSource      string
	listeners         map[string]*activeTCPForward
	configuredIDs     map[string]struct{}
	configuredListens map[string]string
	dynamicCount      int
	nextDynamicID     uint64
	aliasManager      virtualAliasManager
}

func newTCPRuntime(config runtimeConfig, node *mesh.Node) (*tcpRuntime, error) {
	endpoint, err := routed.NewEndpoint(node)
	if err != nil {
		return nil, fmt.Errorf("create routed data endpoint: %w", err)
	}
	forwarder, err := routed.NewTCPForwarderWithConfig(endpoint, routed.TCPForwarderConfig{
		Target: config.TCPTarget, FrameTimeout: config.TCPFrameTimeout,
	})
	if err != nil {
		_ = endpoint.Close()
		return nil, fmt.Errorf("create routed TCP forwarder: %w", err)
	}
	targetSource := ""
	if strings.TrimSpace(config.TCPTarget) != "" {
		targetSource = tcpForwardSourceConfig
	}
	var aliasManager virtualAliasManager
	for _, spec := range config.tcpForwardSpecs {
		if !spec.VirtualIP.IsValid() {
			continue
		}
		aliasManager = config.virtualAliasManager
		if aliasManager == nil {
			aliasManager, err = ipalias.NewLoopbackManager()
			if err != nil {
				_ = forwarder.Close()
				_ = endpoint.Close()
				return nil, fmt.Errorf("create virtual TCP alias manager: %w", err)
			}
		}
		break
	}
	return &tcpRuntime{
		node: node, endpoint: endpoint, forwarder: forwarder,
		specs: append([]tcpForwardSpec(nil), config.tcpForwardSpecs...), targetSource: targetSource,
		listeners: make(map[string]*activeTCPForward), configuredIDs: make(map[string]struct{}),
		configuredListens: make(map[string]string), aliasManager: aliasManager,
	}, nil
}

func (r *tcpRuntime) Start(ctx context.Context, log *eventLog) error {
	if r == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return ErrTCPRuntimeClosed
	}
	if r.started {
		r.mu.Unlock()
		return fmt.Errorf("routed TCP runtime already started")
	}
	r.started = true
	r.runtimeCtx, r.runtimeCancel = context.WithCancel(ctx)
	r.log = log
	started := make([]tcpForwardView, 0, len(r.specs))
	for index, spec := range r.specs {
		id := fmt.Sprintf("config-%03d", index+1)
		if spec.VirtualIP.IsValid() {
			if r.aliasManager == nil {
				startErr := fmt.Errorf("start configured routed TCP forward %s: virtual alias manager is unavailable", id)
				r.mu.Unlock()
				return errors.Join(startErr, r.Close())
			}
			if err := r.aliasManager.Add(spec.VirtualIP); err != nil {
				startErr := fmt.Errorf("start configured routed TCP forward %s: add virtual IP %s: %w", id, spec.VirtualIP, err)
				r.mu.Unlock()
				return errors.Join(startErr, r.Close())
			}
		}
		view, err := r.addForwardLocked(id, spec.Listen, spec.RemoteID, tcpForwardSourceConfig, spec.VirtualIP)
		if err != nil {
			startErr := fmt.Errorf("start configured routed TCP forward %s: %w", id, err)
			r.mu.Unlock()
			return errors.Join(startErr, r.Close())
		}
		started = append(started, view)
	}
	r.ready = true
	r.mu.Unlock()
	for _, view := range started {
		r.logForwardEvent("tcp_forward_started", view)
	}
	return nil
}

// AddForward registers a runtime-owned listener. It intentionally accepts no
// caller context: listeners always inherit the long-lived runtime context saved
// by Start, never an HTTP request context.
func (r *tcpRuntime) AddForward(listen, remoteID, source string) (tcpForwardView, error) {
	if r == nil {
		return tcpForwardView{}, ErrTCPRuntimeClosed
	}
	listen = strings.TrimSpace(listen)
	remoteID = strings.TrimSpace(remoteID)
	source = strings.TrimSpace(source)
	if source == "" {
		source = tcpForwardSourceRuntime
	}
	if source != tcpForwardSourceRuntime {
		return tcpForwardView{}, fmt.Errorf("dynamic routed TCP forward source must be %q", tcpForwardSourceRuntime)
	}
	r.mu.Lock()
	if err := r.mutableLocked(); err != nil {
		r.mu.Unlock()
		return tcpForwardView{}, err
	}
	if r.dynamicCount >= maxDynamicTCPForwards {
		r.mu.Unlock()
		return tcpForwardView{}, fmt.Errorf("%w: maximum is %d", ErrTCPForwardLimit, maxDynamicTCPForwards)
	}
	r.nextDynamicID++
	id := fmt.Sprintf("runtime-%03d", r.nextDynamicID)
	view, err := r.addForwardLocked(id, listen, remoteID, source, netip.Addr{})
	r.mu.Unlock()
	if err != nil {
		return tcpForwardView{}, err
	}
	r.logForwardEvent("tcp_forward_started", view)
	return view, nil
}

func (r *tcpRuntime) addForwardLocked(id, listen, remoteID, source string, virtualIP netip.Addr) (tcpForwardView, error) {
	listen = strings.TrimSpace(listen)
	remoteID = strings.TrimSpace(remoteID)
	if virtualIP.IsValid() {
		if err := validateVirtualTCPListener(r.endpoint.NodeID(), listen, remoteID, virtualIP); err != nil {
			return tcpForwardView{}, err
		}
	} else {
		if err := validateTCPForward(r.endpoint.NodeID(), listen, remoteID); err != nil {
			return tcpForwardView{}, err
		}
	}
	if existing := r.conflictingForwardLocked(listen); existing != nil {
		if existing.source == tcpForwardSourceConfig && source == tcpForwardSourceRuntime {
			return tcpForwardView{}, fmt.Errorf("%w: listener %s belongs to %s", ErrTCPConfigImmutable, listen, existing.id)
		}
		return tcpForwardView{}, fmt.Errorf("%w: listener %s belongs to %s", ErrTCPForwardConflict, listen, existing.id)
	}
	var listener *routed.TCPListener
	var err error
	if virtualIP.IsValid() {
		listener, err = r.forwarder.StartListenerWithPolicy(
			r.runtimeCtx, listen, remoteID, r.virtualTCPAcceptPolicy(remoteID, virtualIP),
		)
	} else {
		listener, err = r.forwarder.StartListener(r.runtimeCtx, listen, remoteID)
	}
	if err != nil {
		return tcpForwardView{}, err
	}
	actualListen := listen
	if listener.Addr() != nil {
		actualListen = listener.Addr().String()
	}
	active := &activeTCPForward{
		id: id, source: source, requestedListen: listen, actualListen: actualListen,
		remoteID: remoteID, virtualIP: virtualIP, listener: listener,
	}
	r.listeners[id] = active
	if source == tcpForwardSourceRuntime {
		r.dynamicCount++
	} else {
		r.configuredIDs[id] = struct{}{}
		if !tcpListenUsesEphemeralPort(listen) {
			r.configuredListens[listen] = id
		}
		r.configuredListens[actualListen] = id
	}
	go r.watchForward(active)
	return active.view(), nil
}

func (r *tcpRuntime) virtualTCPAcceptPolicy(remoteID string, virtualIP netip.Addr) func() error {
	return func() error {
		if r == nil || r.node == nil {
			return ErrTCPRuntimeClosed
		}
		members := r.node.Members()
		matches := make([]string, 0, 1)
		for nodeID, member := range members {
			advertised, err := netip.ParseAddr(strings.TrimSpace(member.VirtualIP))
			if err == nil && advertised == virtualIP {
				matches = append(matches, nodeID)
			}
		}
		sort.Strings(matches)
		var err error
		switch {
		case len(matches) == 0:
			err = fmt.Errorf("virtual TCP address %s is not advertised by a current mesh member", virtualIP)
		case len(matches) > 1:
			err = fmt.Errorf("virtual TCP address %s is ambiguous across members %s", virtualIP, strings.Join(matches, ","))
		case matches[0] != remoteID:
			err = fmt.Errorf("virtual TCP address %s belongs to member %s, not configured remote %s", virtualIP, matches[0], remoteID)
		default:
			if _, ok := r.node.DataRoute(remoteID); !ok {
				err = fmt.Errorf("virtual TCP remote %s has no current mesh data route", remoteID)
			}
		}
		if err != nil {
			r.mu.Lock()
			log := r.log
			r.mu.Unlock()
			if log != nil {
				log.write("virtual_tcp_connection_rejected", map[string]any{
					"virtual_ip": virtualIP.String(), "remote_id": remoteID, "error": err.Error(),
				})
			}
		}
		return err
	}
}

func (r *tcpRuntime) conflictingForwardLocked(listen string) *activeTCPForward {
	if tcpListenUsesEphemeralPort(listen) {
		return nil
	}
	if id := r.configuredListens[listen]; id != "" {
		if active := r.listeners[id]; active != nil {
			return active
		}
		return &activeTCPForward{id: id, source: tcpForwardSourceConfig, requestedListen: listen, actualListen: listen}
	}
	for _, active := range r.listeners {
		if listen == active.requestedListen || listen == active.actualListen {
			return active
		}
	}
	return nil
}

func (r *tcpRuntime) watchForward(active *activeTCPForward) {
	if active == nil || active.listener == nil {
		return
	}
	<-active.listener.Done()
	r.mu.Lock()
	if r.listeners[active.id] != active {
		r.mu.Unlock()
		return
	}
	delete(r.listeners, active.id)
	if active.source == tcpForwardSourceRuntime && r.dynamicCount > 0 {
		r.dynamicCount--
	}
	view := active.view()
	log := r.log
	aliasManager := r.aliasManager
	virtualIP := active.virtualIP
	r.mu.Unlock()
	if virtualIP.IsValid() && aliasManager != nil {
		if err := aliasManager.Remove(virtualIP); err != nil && log != nil {
			log.write("virtual_tcp_alias_remove_failed", map[string]any{
				"virtual_ip": virtualIP.String(), "error": err.Error(),
			})
		}
	}
	if log != nil {
		log.write("tcp_forward_stopped", map[string]any{
			"id": view.ID, "source": view.Source, "requested_listen": view.RequestedListen,
			"listen": view.Listen, "remote_id": view.RemoteID, "virtual_ip": view.VirtualIP,
			"reason": "listener_ended",
		})
	}
}

func (r *tcpRuntime) RemoveForward(id string) (tcpForwardView, error) {
	if r == nil {
		return tcpForwardView{}, ErrTCPRuntimeClosed
	}
	id = strings.TrimSpace(id)
	r.mu.Lock()
	if err := r.mutableLocked(); err != nil {
		r.mu.Unlock()
		return tcpForwardView{}, err
	}
	active := r.listeners[id]
	if active == nil {
		if _, configured := r.configuredIDs[id]; configured {
			r.mu.Unlock()
			return tcpForwardView{}, fmt.Errorf("%w: forward %s", ErrTCPConfigImmutable, id)
		}
		r.mu.Unlock()
		return tcpForwardView{}, fmt.Errorf("%w: %s", ErrTCPForwardNotFound, id)
	}
	if active.source == tcpForwardSourceConfig {
		r.mu.Unlock()
		return tcpForwardView{}, fmt.Errorf("%w: forward %s", ErrTCPConfigImmutable, id)
	}
	delete(r.listeners, id)
	r.dynamicCount--
	view := active.view()
	r.mu.Unlock()
	err := active.listener.Close()
	r.logForwardEvent("tcp_forward_stopped", view)
	return view, err
}

func (r *tcpRuntime) TargetSnapshot() tcpTargetView {
	if r == nil {
		return tcpTargetView{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return tcpTargetView{Target: r.forwarder.Target(), Source: r.targetSource}
}

func (r *tcpRuntime) SetTarget(target string) error {
	if r == nil {
		return ErrTCPRuntimeClosed
	}
	target = strings.TrimSpace(target)
	r.mu.Lock()
	if err := r.mutableLocked(); err != nil {
		r.mu.Unlock()
		return err
	}
	if r.targetSource == tcpForwardSourceConfig {
		if target == r.forwarder.Target() {
			r.mu.Unlock()
			return nil
		}
		r.mu.Unlock()
		return fmt.Errorf("%w: target", ErrTCPConfigImmutable)
	}
	if err := r.forwarder.SetTarget(target); err != nil {
		r.mu.Unlock()
		return err
	}
	r.targetSource = tcpForwardSourceRuntime
	log := r.log
	r.mu.Unlock()
	if log != nil {
		log.write("tcp_target_set", map[string]any{"target": target, "source": tcpForwardSourceRuntime})
	}
	return nil
}

func (r *tcpRuntime) ClearTarget() error {
	if r == nil {
		return ErrTCPRuntimeClosed
	}
	r.mu.Lock()
	if err := r.mutableLocked(); err != nil {
		r.mu.Unlock()
		return err
	}
	if r.targetSource == tcpForwardSourceConfig {
		r.mu.Unlock()
		return fmt.Errorf("%w: target", ErrTCPConfigImmutable)
	}
	if err := r.forwarder.ClearTarget(); err != nil {
		r.mu.Unlock()
		return err
	}
	r.targetSource = ""
	log := r.log
	r.mu.Unlock()
	if log != nil {
		log.write("tcp_target_cleared", map[string]any{"source": tcpForwardSourceRuntime})
	}
	return nil
}

func (r *tcpRuntime) mutableLocked() error {
	if r.closed {
		return ErrTCPRuntimeClosed
	}
	if !r.started || !r.ready || r.runtimeCtx == nil {
		return ErrTCPRuntimeNotStarted
	}
	if r.runtimeCtx.Err() != nil {
		return ErrTCPRuntimeClosed
	}
	return nil
}

func (r *tcpRuntime) Snapshot() []tcpForwardView {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]tcpForwardView, 0, len(r.listeners))
	for _, active := range r.listeners {
		result = append(result, active.view())
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Source != result[j].Source {
			return result[i].Source < result[j].Source
		}
		return result[i].ID < result[j].ID
	})
	return result
}

func (a *activeTCPForward) view() tcpForwardView {
	if a == nil {
		return tcpForwardView{}
	}
	virtualIP := ""
	if a.virtualIP.IsValid() {
		virtualIP = a.virtualIP.String()
	}
	return tcpForwardView{
		ID: a.id, Source: a.source, RequestedListen: a.requestedListen,
		Listen: a.actualListen, RemoteID: a.remoteID, VirtualIP: virtualIP,
	}
}

func (r *tcpRuntime) logForwardEvent(kind string, view tcpForwardView) {
	r.mu.Lock()
	log := r.log
	r.mu.Unlock()
	if log == nil {
		return
	}
	log.write(kind, map[string]any{
		"id": view.ID, "source": view.Source, "requested_listen": view.RequestedListen,
		"listen": view.Listen, "remote_id": view.RemoteID, "virtual_ip": view.VirtualIP,
	})
}

func (r *tcpRuntime) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	if r.closed {
		aliasManager := r.aliasManager
		r.mu.Unlock()
		if aliasManager != nil {
			return aliasManager.Close()
		}
		return nil
	}
	r.closed = true
	r.ready = false
	cancel := r.runtimeCancel
	listeners := make([]*routed.TCPListener, 0, len(r.listeners))
	for _, active := range r.listeners {
		if active.listener != nil {
			listeners = append(listeners, active.listener)
		}
	}
	r.listeners = make(map[string]*activeTCPForward)
	r.configuredIDs = make(map[string]struct{})
	r.configuredListens = make(map[string]string)
	r.dynamicCount = 0
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	var closeErr error
	for _, listener := range listeners {
		closeErr = errors.Join(closeErr, listener.Close())
	}
	closeErr = errors.Join(closeErr, r.forwarder.Close(), r.endpoint.Close())
	if r.aliasManager != nil {
		closeErr = errors.Join(closeErr, r.aliasManager.Close())
	}
	return closeErr
}

func tcpListenUsesEphemeralPort(listen string) bool {
	_, port, err := net.SplitHostPort(listen)
	return err == nil && port == "0"
}

func (r *meshRuntime) tcpForwardSnapshot() []tcpForwardView {
	if r == nil || r.tcp == nil {
		return nil
	}
	return r.tcp.Snapshot()
}

func (r *meshRuntime) tcpTargetSnapshot() tcpTargetView {
	if r == nil || r.tcp == nil {
		return tcpTargetView{}
	}
	return r.tcp.TargetSnapshot()
}

func validateTCPForward(localID, listen, remoteID string) error {
	listen = strings.TrimSpace(listen)
	remoteID = strings.TrimSpace(remoteID)
	if remoteID == "" || remoteID == localID {
		return fmt.Errorf("invalid routed TCP remote node %q", remoteID)
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("invalid routed TCP listener %q: %w", listen, err)
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("invalid routed TCP listener %q: host must be loopback", listen)
	}
	return nil
}

func validateVirtualTCPForward(localID, localVirtualIP, listen, remoteID string) (netip.Addr, string, error) {
	remoteID = strings.TrimSpace(remoteID)
	if remoteID == "" || remoteID == localID {
		return netip.Addr{}, "", fmt.Errorf("invalid routed TCP remote node %q", remoteID)
	}
	virtualIP, port, err := parseVirtualTCPListen(listen)
	if err != nil {
		return netip.Addr{}, "", err
	}
	if local := strings.TrimSpace(localVirtualIP); local != "" {
		if localIP, parseErr := netip.ParseAddr(local); parseErr == nil && localIP == virtualIP {
			return netip.Addr{}, "", fmt.Errorf("virtual TCP listener %s is this node's own virtual IP", virtualIP)
		}
	}
	key := netip.AddrPortFrom(virtualIP, port).String()
	return virtualIP, key, nil
}

func validateVirtualTCPListener(localID, listen, remoteID string, expectedIP netip.Addr) error {
	remoteID = strings.TrimSpace(remoteID)
	if remoteID == "" || remoteID == localID {
		return fmt.Errorf("invalid routed TCP remote node %q", remoteID)
	}
	virtualIP, _, err := parseVirtualTCPListen(listen)
	if err != nil {
		return err
	}
	if !expectedIP.IsValid() || virtualIP != expectedIP {
		return fmt.Errorf("virtual TCP listener address %s does not match managed alias %s", virtualIP, expectedIP)
	}
	return nil
}

func parseVirtualTCPListen(listen string) (netip.Addr, uint16, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(listen))
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("invalid virtual TCP listener %q: %w", listen, err)
	}
	virtualIP, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil || !virtualIP.Is6() || virtualIP.Zone() != "" || !isIPv6ULA(virtualIP) {
		return netip.Addr{}, 0, fmt.Errorf("virtual TCP listener %q must use a numeric IPv6 ULA address", listen)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return netip.Addr{}, 0, fmt.Errorf("virtual TCP listener %q must use a port in 1..65535", listen)
	}
	return virtualIP, uint16(port), nil
}

func isIPv6ULA(address netip.Addr) bool {
	if !address.Is6() || address.Zone() != "" {
		return false
	}
	bits := address.As16()
	return bits[0]&0xfe == 0xfc
}
