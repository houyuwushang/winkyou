package server

import (
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

func cloneSignal(notification *client.SignalNotification) client.SignalNotification {
	out := *notification
	if len(notification.Payload) > 0 {
		out.Payload = make([]byte, len(notification.Payload))
		copy(out.Payload, notification.Payload)
	}
	return out
}
