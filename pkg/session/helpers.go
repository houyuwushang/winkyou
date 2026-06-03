package session

import (
	"fmt"
	"slices"
	"strings"
	"time"

	pmodel "winkyou/pkg/probe/model"
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

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func annotateObservationDetails(details map[string]string, sessionID, peerID string, initiator bool) map[string]string {
	if details == nil {
		details = make(map[string]string, 3)
	} else {
		details = cloneStringMap(details)
	}
	if sessionID != "" {
		details["session_id"] = sessionID
	}
	if peerID != "" {
		details["peer_id"] = peerID
	}
	details["initiator"] = fmt.Sprintf("%t", initiator)
	return details
}

func parseIntParam(s string) int {
	if s == "" {
		return 0
	}
	var val int
	fmt.Sscanf(s, "%d", &val)
	return val
}

func cloneStringMapExcept(m map[string]string, except ...string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	excludeSet := make(map[string]struct{}, len(except))
	for _, key := range except {
		excludeSet[key] = struct{}{}
	}
	result := make(map[string]string, len(m))
	for k, v := range m {
		if _, excluded := excludeSet[k]; !excluded {
			result[k] = v
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func cloneCapability(capability rproto.Capability) rproto.Capability {
	return rproto.Capability{
		Strategies: append([]string(nil), capability.Strategies...),
		Features:   append([]string(nil), capability.Features...),
	}
}

func normalizeCapability(capability rproto.Capability) rproto.Capability {
	normalized := rproto.Capability{}
	seen := make(map[string]struct{}, len(capability.Strategies))
	strategies := make([]string, 0, len(capability.Strategies))
	for _, strategy := range capability.Strategies {
		if strategy == "" {
			continue
		}
		if _, ok := seen[strategy]; ok {
			continue
		}
		seen[strategy] = struct{}{}
		strategies = append(strategies, strategy)
	}
	slices.Sort(strategies)
	normalized.Strategies = strategies

	seen = make(map[string]struct{}, len(capability.Features))
	features := make([]string, 0, len(capability.Features))
	for _, feature := range capability.Features {
		if feature == "" {
			continue
		}
		if _, ok := seen[feature]; ok {
			continue
		}
		seen[feature] = struct{}{}
		features = append(features, feature)
	}
	slices.Sort(features)
	normalized.Features = features
	return normalized
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

func cloneProbeResult(result pmodel.Result) pmodel.Result {
	cloned := result
	cloned.Events = make([]solver.Observation, 0, len(result.Events))
	for _, obs := range result.Events {
		obs.Details = cloneStringMap(obs.Details)
		cloned.Events = append(cloned.Events, obs)
	}
	return cloned
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
