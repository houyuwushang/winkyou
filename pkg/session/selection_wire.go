package session

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strconv"

	rproto "winkyou/pkg/rendezvous/proto"
)

const (
	selectionVersion       = "winkyou.legacy-selection/1"
	selectionProposalType  = "selection_proposal"
	selectionConfirmType   = "selection_confirm"
	selectionEnvelopeLimit = 8192
	selectionPayloadLimit  = 4096
	selectionStrategyLimit = 8
	selectionFeatureLimit  = 32
	selectionTokenLimit    = 64
	selectionReceiveLimit  = 16
)

type selectionError struct {
	class string
	cause error
}

func (e *selectionError) Error() string   { return "session: " + e.class }
func (e *selectionError) Unwrap() error   { return e.cause }
func selectionFailure(class string) error { return &selectionError{class: class} }
func selectionDeadline(class string) error {
	return &selectionError{class: class, cause: context.DeadlineExceeded}
}

// IsSelectionError lets the product preserve an already healthy data path when
// the optional improvement's control exchange fails. It never authorizes a retry.
func IsSelectionError(err error) bool { var target *selectionError; return errors.As(err, &target) }

// Wire-only DTOs: selection metadata does not belong in solver.Capability.
type selectionCapability struct {
	Strategies []string `json:"strategies"`
	Features   []string `json:"features"`
	Version    string   `json:"selection_version"`
	Epoch      string   `json:"selection_epoch"`
}

func (c selectionCapability) domainWire() rproto.Capability {
	return rproto.Capability{Strategies: c.Strategies, Features: c.Features}
}

type selectionBinding struct {
	Version            string `json:"version"`
	FromEpoch          string `json:"from_epoch"`
	ToEpoch            string `json:"to_epoch"`
	Ordinal            string `json:"ordinal"`
	SenderCapability   string `json:"sender_capability"`
	ReceiverCapability string `json:"receiver_capability"`
	Previous           string `json:"previous"`
	PreviousClosed     bool   `json:"previous_closed"`
}
type selectionProposal struct {
	selectionBinding
	Strategies []string `json:"strategies"`
}
type selectionConfirmation struct {
	selectionBinding
	Strategy string `json:"strategy"`
	Digest   string `json:"digest"`
}

func selectionIdentifier(value string, limit int) bool {
	if len(value) == 0 || len(value) > limit {
		return false
	}
	for _, ch := range []byte(value) {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '-' || ch == '.' || ch == '/' || ch == ':') {
			return false
		}
	}
	return true
}
func selectionHex(value string, size int) bool {
	if len(value) != size*2 {
		return false
	}
	for _, ch := range []byte(value) {
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return false
		}
	}
	return true
}
func selectionList(values []string, limit int, nonempty bool) bool {
	if len(values) > limit || nonempty && len(values) == 0 {
		return false
	}
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if !selectionIdentifier(value, selectionTokenLimit) || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}
func validateSelectionCapability(value selectionCapability) error {
	if value.Version != selectionVersion {
		return selectionFailure("selection_unsupported")
	}
	if !selectionHex(value.Epoch, 16) || !selectionList(value.Strategies, selectionStrategyLimit, true) || !selectionList(value.Features, selectionFeatureLimit, false) {
		return selectionFailure("selection_invalid")
	}
	return nil
}
func selectionOrdinal(value string) (uint64, error) {
	ordinal, err := strconv.ParseUint(value, 10, 64)
	if err != nil || strconv.FormatUint(ordinal, 10) != value {
		return 0, selectionFailure("selection_invalid")
	}
	return ordinal, nil
}
func validateSelectionBinding(value selectionBinding) error {
	if value.Version != selectionVersion || !selectionHex(value.FromEpoch, 16) || !selectionHex(value.ToEpoch, 16) || !selectionHex(value.SenderCapability, 32) || !selectionHex(value.ReceiverCapability, 32) || !value.PreviousClosed {
		return selectionFailure("selection_invalid")
	}
	ordinal, err := selectionOrdinal(value.Ordinal)
	if err != nil {
		return err
	}
	if ordinal == 0 && value.Previous != "" || ordinal > 0 && !selectionHex(value.Previous, 32) {
		return selectionFailure("selection_invalid")
	}
	return nil
}

// Reject duplicate keys (including nested objects), unknown fields and trailing
// values before accepting an immutable commitment. Bound bytes before parsing.
func decodeSelectionJSON(data []byte, target any) error {
	return decodeSelectionJSONBound(data, target, selectionPayloadLimit)
}
func decodeSelectionJSONBound(data []byte, target any, limit int) error {
	if len(data) == 0 || len(data) > limit {
		return selectionFailure("selection_invalid")
	}
	check := json.NewDecoder(bytes.NewReader(data))
	var scan func(int) error
	scan = func(depth int) error {
		if depth > 4 {
			return selectionFailure("selection_invalid")
		}
		token, err := check.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for check.More() {
				keyToken, err := check.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok || seen[key] {
					return selectionFailure("selection_invalid")
				}
				seen[key] = true
				if err := scan(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for check.More() {
				if err := scan(depth + 1); err != nil {
					return err
				}
			}
		default:
			return selectionFailure("selection_invalid")
		}
		_, err = check.Token()
		return err
	}
	if err := scan(0); err != nil {
		return selectionFailure("selection_invalid")
	}
	if _, err := check.Token(); err != io.EOF {
		return selectionFailure("selection_invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return selectionFailure("selection_invalid")
	}
	return nil
}
func selectionHash(value any) string {
	encoded, _ := json.Marshal(value) // All callers supply fixed, marshalable DTOs.
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
func selectionCapabilityDigest(value rproto.Capability) string {
	return selectionHash(normalizeCapability(value))
}
func equalProposal(a, b *selectionProposal) bool {
	return a != nil && b != nil && a.selectionBinding == b.selectionBinding && slices.Equal(a.Strategies, b.Strategies)
}

type selectionJoint struct {
	Version             string            `json:"version"`
	SessionID           string            `json:"session_id"`
	InitiatorNode       string            `json:"initiator_node"`
	ResponderNode       string            `json:"responder_node"`
	InitiatorCapability rproto.Capability `json:"initiator_capability"`
	ResponderCapability rproto.Capability `json:"responder_capability"`
	Initiator           selectionProposal `json:"initiator"`
	Responder           selectionProposal `json:"responder"`
	Order               []string          `json:"order"`
}

func jointSelection(cfg Config, localCap, remoteCap rproto.Capability, local, remote selectionProposal) (selectionJoint, error) {
	joint := selectionJoint{Version: selectionVersion, SessionID: cfg.SessionID,
		InitiatorNode: cfg.LocalNodeID, ResponderNode: cfg.PeerID,
		InitiatorCapability: normalizeCapability(localCap), ResponderCapability: normalizeCapability(remoteCap), Initiator: local, Responder: remote}
	if !cfg.Initiator {
		joint.InitiatorNode, joint.ResponderNode = joint.ResponderNode, joint.InitiatorNode
		joint.InitiatorCapability, joint.ResponderCapability = joint.ResponderCapability, joint.InitiatorCapability
		joint.Initiator, joint.Responder = joint.Responder, joint.Initiator
	}
	for _, value := range joint.Initiator.Strategies {
		if slices.Contains(joint.Responder.Strategies, value) {
			joint.Order = append(joint.Order, value)
		}
	}
	if len(joint.Order) == 0 {
		return selectionJoint{}, selectionFailure("selection_conflict")
	}
	return joint, nil
}
