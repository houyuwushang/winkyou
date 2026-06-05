package server

import (
	"net"
	"strings"

	"winkyou/pkg/coordinator/client"
)

func toPeerInfo(node *Node) client.PeerInfo {
	return client.PeerInfo{
		NodeID:    node.NodeID,
		Name:      node.Name,
		PublicKey: node.PublicKey,
		VirtualIP: node.VirtualIP,
		Online:    node.Online,
		LastSeen:  node.LastSeen.Unix(),
		Endpoints: cloneSlice(node.Endpoints),
	}
}

func cloneNode(node *Node) *Node {
	if node == nil {
		return nil
	}
	out := *node
	out.Metadata = cloneMap(node.Metadata)
	out.Endpoints = cloneSlice(node.Endpoints)
	return &out
}

func cloneMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func cloneSlice(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func endpointsFromMetadata(metadata map[string]string) []string {
	raw := strings.TrimSpace(metadata[client.MetadataEndpointsKey])
	if raw == "" {
		return nil
	}
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t'
	})
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		value := strings.TrimSpace(field)
		if !strings.HasPrefix(value, "route:") {
			continue
		}
		_, prefix, err := net.ParseCIDR(strings.TrimSpace(strings.TrimPrefix(value, "route:")))
		if err == nil && prefix != nil {
			out = append(out, "route:"+prefix.String())
		}
	}
	return out
}

func cloneSignal(notification *client.SignalNotification) client.SignalNotification {
	out := *notification
	if len(notification.Payload) > 0 {
		out.Payload = make([]byte, len(notification.Payload))
		copy(out.Payload, notification.Payload)
	}
	return out
}
