// Package shortcut coordinates pairwise edge solvers over an already-routed
// mesh and promotes successful protected-direct results into graph neighbors.
package shortcut

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"winkyou/pkg/solver"
)

const (
	Namespace  = "mesh.shortcut.v1"
	SignalKind = "mesh_shortcut"

	typePrepareRequest = "prepare_request"
	typePrepare        = "prepare"
	typeReady          = "ready"
	typeFire           = "fire"
	typeSolverMessage  = "solver_message"
	typeInstalled      = "installed"
	typeCommit         = "commit"
	typeStable         = "stable"
	typeFailed         = "failed"
	typeAbort          = "abort"
)

// SignalTypeSolverMessage is exported for diagnostics that need to distinguish
// routed edge-solver traffic from barrier lifecycle messages.
const SignalTypeSolverMessage = typeSolverMessage

type wireMessage struct {
	AttemptID       string          `json:"attempt_id"`
	InitiatorID     string          `json:"initiator_id"`
	TargetID        string          `json:"target_id"`
	CoordinatorID   string          `json:"coordinator_id"`
	Strategy        string          `json:"strategy"`
	ProbationMillis int64           `json:"probation_millis"`
	PathID          string          `json:"path_id,omitempty"`
	Reason          string          `json:"reason,omitempty"`
	SolverMessage   *solver.Message `json:"solver_message,omitempty"`
	SentAt          time.Time       `json:"sent_at"`
	encodedSize     int             `json:"-"`
}

func (w wireMessage) validate() error {
	if strings.TrimSpace(w.AttemptID) == "" {
		return fmt.Errorf("shortcut: attempt id is required")
	}
	if strings.TrimSpace(w.InitiatorID) == "" || strings.TrimSpace(w.TargetID) == "" || strings.TrimSpace(w.CoordinatorID) == "" {
		return fmt.Errorf("shortcut: initiator, target, and coordinator are required")
	}
	if w.InitiatorID == w.TargetID || w.InitiatorID == w.CoordinatorID || w.TargetID == w.CoordinatorID {
		return fmt.Errorf("shortcut: initiator, target, and coordinator must be distinct")
	}
	if strings.TrimSpace(w.Strategy) == "" {
		return fmt.Errorf("shortcut: strategy is required")
	}
	if w.ProbationMillis <= 0 {
		return fmt.Errorf("shortcut: probation duration is required")
	}
	if w.SentAt.IsZero() {
		return fmt.Errorf("shortcut: sent_at is required")
	}
	return nil
}

func marshalWire(w wireMessage) ([]byte, error) {
	if err := w.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(w)
}

func unmarshalWire(raw []byte) (wireMessage, error) {
	var message wireMessage
	if err := json.Unmarshal(raw, &message); err != nil {
		return wireMessage{}, fmt.Errorf("shortcut: decode signal: %w", err)
	}
	if err := message.validate(); err != nil {
		return wireMessage{}, err
	}
	message.encodedSize = len(raw)
	return message, nil
}
