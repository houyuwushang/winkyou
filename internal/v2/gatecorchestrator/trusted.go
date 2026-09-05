package gatecorchestrator

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"winkyou/internal/governor"
	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/gatecrequest"
	"winkyou/internal/v2/hardnatbudget"
	"winkyou/internal/v2/hardnatobserve"
	"winkyou/internal/v2/hardnatplan"
	"winkyou/pkg/config"
	"winkyou/pkg/tunnel"
)

func resolveTrustedPeer(input preparedInput) (trustedPeer, error) {
	if input.configuration == nil || input.artifact == nil ||
		input.buildVersion == "" || input.progress == nil || input.request.PeerRef == "" ||
		input.request.Role != input.artifact.LocalRole || input.request.ArtifactFile == "" {
		return trustedPeer{}, ErrRequestInvalid
	}
	if err := input.configuration.Validate(); err != nil {
		return trustedPeer{}, ErrRequestInvalid
	}
	if input.request.Role == directattempt.RoleInitiator {
		if input.request.SSH == nil || input.sshAuthority == nil || input.stream != nil || input.childInput != nil || input.childOutput != nil {
			return trustedPeer{}, ErrRequestInvalid
		}
	} else if input.request.Role == directattempt.RoleResponder {
		hasChildStream := input.childInput != nil && input.childOutput != nil
		partialChildStream := (input.childInput == nil) != (input.childOutput == nil)
		if input.request.SSH != nil || input.sshAuthority != nil || partialChildStream || (input.stream != nil) == hasChildStream {
			return trustedPeer{}, ErrRequestInvalid
		}
	} else {
		return trustedPeer{}, ErrRequestInvalid
	}
	if _, err := hardnatbudget.For(input.artifact.PlannerProfile, input.artifact.ResourceClass); err != nil {
		return trustedPeer{}, ErrRequestInvalid
	}
	privateKey, err := tunnel.ParsePrivateKey(input.configuration.WireGuard.PrivateKey)
	if err != nil {
		return trustedPeer{}, ErrRequestInvalid
	}
	var selected *config.GateCPeerConfig
	for index := range input.configuration.GateC.Peers {
		candidate := &input.configuration.GateC.Peers[index]
		if candidate.Ref != input.request.PeerRef {
			continue
		}
		if selected != nil {
			return trustedPeer{}, ErrRequestInvalid
		}
		selected = candidate
	}
	if selected == nil {
		return trustedPeer{}, ErrRequestInvalid
	}
	publicKey, err := tunnel.ParsePublicKey(selected.PublicKey)
	if err != nil || publicKey == privateKey.PublicKey() {
		return trustedPeer{}, ErrRequestInvalid
	}
	localVirtual, err := netip.ParseAddr(selected.LocalVirtualIP)
	if err != nil {
		return trustedPeer{}, ErrRequestInvalid
	}
	remoteVirtual, err := netip.ParseAddr(selected.PeerVirtualIP)
	if err != nil {
		return trustedPeer{}, ErrRequestInvalid
	}
	allowed := make([]netip.Prefix, 0, len(selected.AllowedIPs))
	for _, value := range selected.AllowedIPs {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return trustedPeer{}, ErrRequestInvalid
		}
		allowed = append(allowed, prefix)
	}
	return trustedPeer{
		ref: selected.Ref, privateKey: privateKey, publicKey: publicKey, allowedIPs: allowed,
		localVirtual: localVirtual.Unmap(), remoteVirtual: remoteVirtual.Unmap(),
		interfaceName: selected.MemoryInterfaceName, mtu: selected.MemoryMTU,
		sessionCeiling: selected.SessionCeiling,
	}, nil
}

func observerTopology(request gatecrequest.Request) (hardnatobserve.Topology, error) {
	topology := hardnatobserve.Topology{
		Primary: request.ObserverSet.Primary,
		Other:   request.ObserverSet.AlternateAddressPort,
	}
	endpoints, err := topology.Endpoints()
	if err != nil || endpoints != request.ObserverSet.Endpoints() {
		return hardnatobserve.Topology{}, ErrRequestInvalid
	}
	return topology, nil
}

func bindingPeer(peer trustedPeer) (*tunnel.PeerConfig, error) {
	allowed := make([]net.IPNet, 0, len(peer.allowedIPs))
	for _, prefix := range peer.allowedIPs {
		if !prefix.Addr().Is4() {
			return nil, ErrRequestInvalid
		}
		address := prefix.Addr().As4()
		mask := net.CIDRMask(prefix.Bits(), 32)
		allowed = append(allowed, net.IPNet{IP: net.IPv4(address[0], address[1], address[2], address[3]), Mask: mask})
	}
	return &tunnel.PeerConfig{PublicKey: peer.publicKey, AllowedIPs: allowed, Keepalive: 0}, nil
}

func acquireMachine(profile hardnatplan.Profile, resource hardnatplan.ResourceClass, buildVersion string) (*governor.Governor, *governor.PairingAdmissionLedger, error) {
	governorProfile, err := hardnatbudget.GovernorProfile(profile, resource)
	if err != nil {
		return nil, nil, ErrRequestInvalid
	}
	owner, err := governor.AcquireMachineNamespace(buildVersion)
	if err != nil {
		return nil, nil, err
	}
	ledger, err := owner.PairingLedger()
	if err != nil {
		return nil, nil, errors.Join(err, owner.Close())
	}
	machine, err := governor.New(owner, governorProfile, nil)
	if err != nil {
		return nil, nil, errors.Join(err, owner.Close())
	}
	return machine, ledger, nil
}

var localOwnership = struct {
	sync.Mutex
	keys       map[tunnel.PublicKey]struct{}
	interfaces map[string]struct{}
	routes     map[netip.Addr]struct{}
}{keys: make(map[tunnel.PublicKey]struct{}), interfaces: make(map[string]struct{}), routes: make(map[netip.Addr]struct{})}

func claimLocalOwnership(peer trustedPeer) (func(), error) {
	localKey := peer.privateKey.PublicKey()
	localOwnership.Lock()
	defer localOwnership.Unlock()
	if _, exists := localOwnership.keys[localKey]; exists {
		return nil, ErrRequestInvalid
	}
	if _, exists := localOwnership.interfaces[peer.interfaceName]; exists {
		return nil, ErrRequestInvalid
	}
	if _, exists := localOwnership.routes[peer.remoteVirtual]; exists {
		return nil, ErrRequestInvalid
	}
	localOwnership.keys[localKey] = struct{}{}
	localOwnership.interfaces[peer.interfaceName] = struct{}{}
	localOwnership.routes[peer.remoteVirtual] = struct{}{}
	var once sync.Once
	return func() {
		once.Do(func() {
			localOwnership.Lock()
			delete(localOwnership.keys, localKey)
			delete(localOwnership.interfaces, peer.interfaceName)
			delete(localOwnership.routes, peer.remoteVirtual)
			localOwnership.Unlock()
		})
	}, nil
}

func defaultConflictInspector(ctx context.Context, input preparedInput, peer trustedPeer) (conflictState, error) {
	if ctx == nil || ctx.Err() != nil {
		return conflictState{}, ErrRequestInvalid
	}
	state := conflictState{}
	localOwnership.Lock()
	_, state.PrivateKeyInUse = localOwnership.keys[peer.privateKey.PublicKey()]
	_, state.InterfaceInUse = localOwnership.interfaces[peer.interfaceName]
	_, state.RouteInUse = localOwnership.routes[peer.remoteVirtual]
	localOwnership.Unlock()

	interfaces, err := net.Interfaces()
	if err != nil {
		return conflictState{}, ErrRequestInvalid
	}
	for _, networkInterface := range interfaces {
		if networkInterface.Name == peer.interfaceName {
			state.InterfaceInUse = true
			break
		}
	}

	configPath := strings.TrimSpace(input.configPath)
	if configPath == "" {
		configPath = config.DefaultPath()
	}
	runtimePath := runtimeStatePath(configPath)
	info, statErr := os.Lstat(runtimePath)
	switch {
	case statErr == nil:
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return conflictState{}, ErrRequestInvalid
		}
		// A stale-looking runtime record is still ownership evidence. C1b never
		// removes or repairs it automatically.
		state.WinkUpRunning = true
	case !errors.Is(statErr, os.ErrNotExist):
		return conflictState{}, ErrRequestInvalid
	}
	return state, nil
}

func runtimeStatePath(configPath string) string {
	clean := strings.TrimSpace(configPath)
	if strings.HasSuffix(strings.ToLower(filepath.Base(clean)), ".runtime.json") {
		return clean
	}
	directory := filepath.Dir(clean)
	base := strings.TrimSuffix(filepath.Base(clean), filepath.Ext(clean))
	if base == "" || base == "." || base == string(filepath.Separator) {
		base = "wink"
	}
	return filepath.Join(directory, base+".runtime.json")
}

func conflictPresent(state conflictState) bool {
	return state.WinkUpRunning || state.PrivateKeyInUse || state.InterfaceInUse || state.RouteInUse
}
