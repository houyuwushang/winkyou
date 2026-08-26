package hardnatplan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const MaxRemoteIntentBytes = 4096

// RemoteIntent carries only exact identifiers. It deliberately cannot express
// candidate ports, spans, sockets, PPS, packets, or any other cost dimension.
type RemoteIntent struct {
	Profile       Profile
	ResourceClass ResourceClass
	Role          Role
	Generation    string
}

func ParseRemoteIntent(payload []byte) (RemoteIntent, error) {
	var intent RemoteIntent
	if len(payload) == 0 || len(payload) > MaxRemoteIntentBytes || !json.Valid(payload) {
		return intent, ErrRemoteControlField
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return intent, ErrRemoteControlField
	}
	seen := make(map[string]struct{}, 4)
	for decoder.More() {
		nameToken, tokenErr := decoder.Token()
		if tokenErr != nil {
			return RemoteIntent{}, ErrRemoteControlField
		}
		name, ok := nameToken.(string)
		if !ok {
			return RemoteIntent{}, ErrRemoteControlField
		}
		if _, duplicate := seen[name]; duplicate {
			return RemoteIntent{}, fmt.Errorf("%w: duplicate %s", ErrRemoteControlField, name)
		}
		seen[name] = struct{}{}
		var value string
		switch name {
		case "profile", "resource_class", "role", "generation":
			if err := decoder.Decode(&value); err != nil {
				return RemoteIntent{}, ErrRemoteControlField
			}
		default:
			// This includes candidate_list, candidate_span, packet_count,
			// socket_count, PPS, and every future unknown control field.
			return RemoteIntent{}, fmt.Errorf("%w: member %s", ErrRemoteControlField, name)
		}
		switch name {
		case "profile":
			intent.Profile = Profile(value)
		case "resource_class":
			intent.ResourceClass = ResourceClass(value)
		case "role":
			intent.Role = Role(value)
		case "generation":
			intent.Generation = value
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return RemoteIntent{}, ErrRemoteControlField
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return RemoteIntent{}, ErrRemoteControlField
	}
	if len(seen) != 4 || intent.Generation != "1" || validateRole(intent.Profile, intent.Role) != nil {
		return RemoteIntent{}, ErrUnsupportedProfile
	}
	if _, err := shapeFor(intent.Profile, intent.ResourceClass, intent.Role, StateModel{CandidateWindow: make([]uint16, PredictiveWindowPorts)}); err != nil {
		return RemoteIntent{}, ErrUnsupportedProfile
	}
	return intent, nil
}
