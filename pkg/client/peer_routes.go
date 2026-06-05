package client

import (
	"net"

	"winkyou/pkg/logger"
	"winkyou/pkg/netif"
	"winkyou/pkg/tunnel"
)

type peerAdvertisedRouteSync struct {
	oldPeer *PeerStatus
	newPeer *PeerStatus
}

func (e *engine) applyPeerAdvertisedRoutes(peer *PeerStatus) {
	if peer == nil || len(peer.AdvertisedRoutes) == 0 {
		return
	}
	e.mu.RLock()
	ni := e.netif
	e.mu.RUnlock()
	addPeerAdvertisedRoutes(ni, peer.VirtualIP, peer.AdvertisedRoutes, e.log)
}

func (e *engine) reconcilePeerAdvertisedRoutes(sync *peerAdvertisedRouteSync) {
	if sync == nil {
		return
	}
	e.mu.RLock()
	ni := e.netif
	tun := e.tun
	e.mu.RUnlock()

	if peerAdvertisedRoutesActive(sync.oldPeer) {
		removePeerAdvertisedRoutes(ni, sync.oldPeer.AdvertisedRoutes, e.log)
	}
	if peerAdvertisedRoutesActive(sync.newPeer) {
		addPeerAdvertisedRoutes(ni, sync.newPeer.VirtualIP, sync.newPeer.AdvertisedRoutes, e.log)
		e.updateTunnelPeerAllowedIPs(tun, sync.newPeer)
	}
}

func (e *engine) updateTunnelPeerAllowedIPs(tun tunnel.Tunnel, peer *PeerStatus) {
	if tun == nil || peer == nil {
		return
	}
	updater, ok := tun.(tunnel.PeerAllowedIPsUpdater)
	if !ok {
		if len(peer.AdvertisedRoutes) > 0 && e.log != nil {
			e.log.Warn("tunnel cannot refresh advertised route allowed IPs without reconnect", logger.String("node_id", peer.NodeID))
		}
		return
	}
	publicKey, err := tunnel.ParsePublicKey(peer.PublicKey)
	if err != nil {
		if e.log != nil {
			e.log.Warn("failed to parse peer public key for advertised route update", logger.String("node_id", peer.NodeID), logger.Error(err))
		}
		return
	}
	allowedIPs, err := allowedIPsForPeer(peer)
	if err != nil {
		if e.log != nil {
			e.log.Warn("failed to build peer allowed IPs for advertised route update", logger.String("node_id", peer.NodeID), logger.Error(err))
		}
		return
	}
	if err := updater.UpdatePeerAllowedIPs(publicKey, allowedIPs); err != nil && e.log != nil {
		e.log.Warn("failed to update peer advertised route allowed IPs", logger.String("node_id", peer.NodeID), logger.Error(err))
	}
}

func shouldReconcilePeerAdvertisedRoutes(oldPeer, newPeer *PeerStatus) bool {
	if oldPeer == nil || newPeer == nil {
		return false
	}
	if !peerAdvertisedRoutesActive(oldPeer) && !peerAdvertisedRoutesActive(newPeer) {
		return false
	}
	if !oldPeer.VirtualIP.Equal(newPeer.VirtualIP) {
		return true
	}
	return !ipNetSlicesEqual(oldPeer.AdvertisedRoutes, newPeer.AdvertisedRoutes)
}

func peerAdvertisedRoutesActive(peer *PeerStatus) bool {
	if peer == nil {
		return false
	}
	return peer.State == PeerStateConnected ||
		peer.DataState == PeerDataStateBound ||
		peer.DataState == PeerDataStateAlive
}

func allowedIPsForPeer(peer *PeerStatus) ([]net.IPNet, error) {
	if peer == nil {
		return nil, ErrPeerNotFound
	}
	_, allowedIP, err := parsePeerAllowedIP(peer.VirtualIP)
	if err != nil {
		return nil, err
	}
	allowedIPs := []net.IPNet{*allowedIP}
	allowedIPs = append(allowedIPs, cloneIPNets(peer.AdvertisedRoutes)...)
	return allowedIPs, nil
}

func addPeerAdvertisedRoutes(ni netif.NetworkInterface, gateway net.IP, routes []net.IPNet, log logger.Logger) {
	if ni == nil || gateway == nil || len(routes) == 0 {
		return
	}
	for i := range routes {
		route := routes[i]
		if err := ni.AddRoute(&route, gateway); err != nil && log != nil {
			log.Warn("failed to add peer advertised route", logger.String("route", route.String()), logger.String("gateway", gateway.String()), logger.Error(err))
		}
	}
}

func removePeerAdvertisedRoutes(ni netif.NetworkInterface, routes []net.IPNet, log logger.Logger) {
	if ni == nil || len(routes) == 0 {
		return
	}
	for i := range routes {
		route := routes[i]
		if err := ni.RemoveRoute(&route); err != nil && log != nil {
			log.Debug("failed to remove peer advertised route", logger.String("route", route.String()), logger.Error(err))
		}
	}
}

func ipNetSlicesEqual(a, b []net.IPNet) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].String() != b[i].String() {
			return false
		}
	}
	return true
}

func cloneIPNets(values []net.IPNet) []net.IPNet {
	if len(values) == 0 {
		return nil
	}
	out := make([]net.IPNet, 0, len(values))
	for i := range values {
		if cloned := cloneIPNet(&values[i]); cloned != nil {
			out = append(out, *cloned)
		}
	}
	return out
}
