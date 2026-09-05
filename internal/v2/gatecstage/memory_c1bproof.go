//go:build c1bproof

package gatecstage

import "time"

// StageMemoryProof and ClaimMemoryProof are exact temporary-namespace seams
// for the CLI lifecycle proof. They reuse the durable slot implementation and
// are absent from ordinary binaries; they do not repair or replace a slot.
func StageMemoryProof(root, requestFile string, now time.Time) error {
	return stageAt(root, requestFile, now)
}

func ClaimMemoryProof(root string, now time.Time) (*Claimed, error) {
	return claimAt(root, now, dependencies{})
}
