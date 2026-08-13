package session

import (
	"fmt"
	"strings"
	"time"

	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/solver"
)

func classifyError(err error) string {
	if err == nil {
		return ""
	}
	errStr := err.Error()
	switch {
	case strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline"):
		return "timeout"
	case strings.Contains(errStr, "connection refused") || strings.Contains(errStr, "no route"):
		return "unreachable"
	case strings.Contains(errStr, "context canceled"):
		return "canceled"
	default:
		return "unknown"
	}
}

func durationMS(d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	return d.Milliseconds()
}

func addrString(addr any) string {
	switch v := addr.(type) {
	case nil:
		return ""
	case string:
		return v
	case interface{ String() string }:
		return v.String()
	default:
		return fmt.Sprint(v)
	}
}

func annotateObservationDetails(details map[string]string, sessionID, localNodeID, peerID string, initiator bool) map[string]string {
	if details == nil {
		details = make(map[string]string, 5)
	} else {
		details = cloneStringMap(details)
	}
	if sessionID != "" {
		details["session_id"] = sessionID
	}
	if localNodeID != "" {
		details["local_node_id"] = localNodeID
	}
	if peerID != "" {
		details["peer_id"] = peerID
		details["remote_node_id"] = peerID
	}
	details["initiator"] = fmt.Sprintf("%t", initiator)
	return details
}

func pathSummaryObservationDetails(summary solver.PathSummary, details map[string]string) map[string]string {
	if details == nil {
		details = map[string]string{}
	} else {
		details = cloneStringMap(details)
	}
	if len(summary.Details) > 0 {
		merged := cloneStringMap(summary.Details)
		for key, value := range details {
			merged[key] = value
		}
		details = merged
	}
	if summary.Role != "" {
		details["path_role"] = string(summary.Role)
	}
	if len(summary.Dependencies) > 0 {
		kinds := make([]string, 0, len(summary.Dependencies))
		values := make([]string, 0, len(summary.Dependencies))
		for _, dependency := range summary.Dependencies {
			if dependency.Kind == "" {
				continue
			}
			kind := string(dependency.Kind)
			kinds = append(kinds, kind)
			value := kind
			if dependency.NodeID != "" {
				value += ":" + dependency.NodeID
			}
			if dependency.Reason != "" {
				value += ":" + dependency.Reason
			}
			values = append(values, value)
		}
		if len(kinds) > 0 {
			details["path_dependency_kinds"] = strings.Join(kinds, ",")
			details["path_dependencies"] = strings.Join(values, ",")
		}
	}
	for key, value := range summary.Metrics {
		if key == "" {
			continue
		}
		details["path_metric_"+key] = value
	}
	return details
}

func cloneCapability(capability rproto.Capability) rproto.Capability {
	return rproto.Capability{
		Strategies: append([]string(nil), capability.Strategies...),
		Features:   append([]string(nil), capability.Features...),
	}
}

func normalizeCapability(capability rproto.Capability) rproto.Capability {
	return capabilityToWire(capabilityFromWire(capability))
}

func capabilityFromWire(capability rproto.Capability) solver.Capability {
	return solver.NormalizeCapability(solver.Capability{
		Strategies: append([]string(nil), capability.Strategies...),
		Features:   append([]string(nil), capability.Features...),
	})
}

func capabilityToWire(capability solver.Capability) rproto.Capability {
	normalized := solver.NormalizeCapability(capability)
	return rproto.Capability{
		Strategies: append([]string(nil), normalized.Strategies...),
		Features:   append([]string(nil), normalized.Features...),
	}
}

func clonePathCommit(pathCommit PathCommitSnapshot) PathCommitSnapshot {
	return PathCommitSnapshot{
		Strategy:       pathCommit.Strategy,
		PathID:         pathCommit.PathID,
		ConnectionType: pathCommit.ConnectionType,
	}
}

func cloneMessage(msg solver.Message) solver.Message {
	return solver.Message{
		Kind:       msg.Kind,
		Namespace:  msg.Namespace,
		Type:       msg.Type,
		Payload:    append([]byte(nil), msg.Payload...),
		ReceivedAt: msg.ReceivedAt,
	}
}

func capabilityHasFeature(capability rproto.Capability, feature string) bool {
	for _, candidate := range capability.Features {
		if candidate == feature {
			return true
		}
	}
	return false
}

func cloneProbeResult(result solver.ProbeResult) solver.ProbeResult {
	return solver.CloneProbeResult(result)
}

func cloneStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
