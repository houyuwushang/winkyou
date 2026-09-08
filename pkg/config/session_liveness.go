package config

import (
	"errors"
	"os"

	"gopkg.in/yaml.v3"
)

var errSessionLivenessConfig = errors.New("gate_c.session_liveness: invalid file-only policy")

// Deliberately independent of Viper's automatic environment and weak decoding.
// Missing policy is inert; malformed explicit policy is never treated as absent.
func loadFileSessionLiveness(path string, cfg *Config) error {
	for i := range cfg.GateC.Peers {
		cfg.GateC.Peers[i].SessionLiveness = nil
	}
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errSessionLivenessConfig
	}
	var doc yaml.Node
	if yaml.Unmarshal(data, &doc) != nil {
		return errSessionLivenessConfig
	}
	if len(doc.Content) == 0 {
		return nil
	}
	gate := mappingMember(doc.Content[0], "gate_c")
	peers := mappingMember(gate, "peers")
	if peers == nil || peers.Kind != yaml.SequenceNode {
		return nil
	}
	for i, peer := range peers.Content {
		policy := mappingMember(peer, "session_liveness")
		if policy == nil {
			continue
		}
		ref := mappingMember(peer, "ref")
		if i >= len(cfg.GateC.Peers) || ref == nil || ref.Value != cfg.GateC.Peers[i].Ref || policy.Kind != yaml.MappingNode {
			return errSessionLivenessConfig
		}
		value := &SessionLivenessConfig{MissedRounds: 3}
		seen := map[string]bool{}
		for j := 0; j < len(policy.Content); j += 2 {
			key, node := policy.Content[j], policy.Content[j+1]
			if key.Tag != "!!str" || seen[key.Value] {
				return errSessionLivenessConfig
			}
			seen[key.Value] = true
			switch key.Value {
			case "mode":
				if node.Kind != yaml.ScalarNode || node.Tag != "!!str" || node.Value != "challenge_v1" {
					return errSessionLivenessConfig
				}
				value.Mode = node.Value
			case "missed_rounds":
				if node.Kind != yaml.ScalarNode || node.Tag != "!!int" || (node.Value != "2" && node.Value != "3") {
					return errSessionLivenessConfig
				}
				value.MissedRounds = int(node.Value[0] - '0')
			default:
				return errSessionLivenessConfig
			}
		}
		if value.Mode == "" {
			return errSessionLivenessConfig
		}
		cfg.GateC.Peers[i].SessionLiveness = value
	}
	return nil
}

func mappingMember(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}
