//go:build fieldc1c

package gatecorchestrator

// FieldSummary is the entire public whitelist. Raw errors, local identity,
// paths, endpoints, PID and credential identifiers cannot be serialized here.
type FieldSummary struct {
	Profile        string             `json:"profile"`
	Stage          string             `json:"stage"`
	Class          string             `json:"class"`
	DurationNS     int64              `json:"duration_ns"`
	Counts         map[string]*uint64 `json:"counts"`
	EvidenceSHA256 string             `json:"evidence_sha256"`
}

func invalidFieldSummary() FieldSummary {
	return FieldSummary{Stage: StagePreflight, Class: ClassRequestInvalid}
}
