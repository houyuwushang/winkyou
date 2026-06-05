package client

import (
	"net"

	"winkyou/pkg/logger"
	"winkyou/pkg/netif"
)

func (e *engine) applyPeerAdvertisedRoutes(peer *PeerStatus) {
	if peer == nil || len(peer.AdvertisedRoutes) == 0 {
		return
	}
	e.mu.RLock()
	ni := e.netif
	e.mu.RUnlock()
	addPeerAdvertisedRoutes(ni, peer.VirtualIP, peer.AdvertisedRoutes, e.log)
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
