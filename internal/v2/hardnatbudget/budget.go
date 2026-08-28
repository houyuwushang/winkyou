// Package hardnatbudget freezes the complete Gate B2 attempt envelopes. It
// owns no network capability and cannot acquire a governor lease.
package hardnatbudget

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/hardnatplan"
)

const (
	ActiveEnvelope  = 20 * time.Second
	DrainTimeout    = 2 * time.Second
	AttemptDuration = ActiveEnvelope + DrainTimeout

	FreshEvidencePackets = 13
	CandidateWindow      = 9 * time.Second
	EvidenceWindow       = 3 * time.Second
)

var ErrUnsupportedEnvelope = errors.New("hardnatbudget: unsupported execution envelope")

// Envelope is the immutable full-attempt authority exchanged before FIRE.
// It is deliberately distinct from hardnatplan.Cost, which describes the B1
// candidate-search slice.
type Envelope struct {
	Profile       hardnatplan.Profile
	ResourceClass hardnatplan.ResourceClass
	Cost          governor.AttemptCost
}

func For(profile hardnatplan.Profile, resource hardnatplan.ResourceClass) (Envelope, error) {
	var resources governor.Resources
	switch {
	case profile == hardnatplan.ProfilePredictiveEdm && resource == hardnatplan.ResourcePredictive:
		resources = governor.Resources{
			Sockets: 8, Targets: 64, FiveTuples: 64,
			Packets: 64, PacketsPerSecond: 32,
		}
	case profile == hardnatplan.ProfileAsymmetricBirthday && resource == hardnatplan.ResourceAsymmetric:
		resources = governor.Resources{
			Sockets: 128, Targets: 516, FiveTuples: 523,
			Packets: 526, PacketsPerSecond: 64,
		}
	default:
		return Envelope{}, ErrUnsupportedEnvelope
	}
	return Envelope{
		Profile: profile, ResourceClass: resource,
		Cost: governor.AttemptCost{Resources: resources, Duration: AttemptDuration, Heavyweight: true},
	}, nil
}

func Operation(profile hardnatplan.Profile) (governor.Operation, error) {
	switch profile {
	case hardnatplan.ProfilePredictiveEdm:
		return governor.OperationPrediction, nil
	case hardnatplan.ProfileAsymmetricBirthday:
		return governor.OperationBirthday, nil
	default:
		return "", ErrUnsupportedEnvelope
	}
}

func Exact(profile hardnatplan.Profile, resource hardnatplan.ResourceClass, operation governor.Operation, cost governor.AttemptCost) bool {
	envelope, err := For(profile, resource)
	wantOperation, operationErr := Operation(profile)
	return err == nil && operationErr == nil && operation == wantOperation && cost == envelope.Cost
}

// Digest binds the full execution envelope independently of the B1 plan cost.
func Digest(envelope Envelope) ([sha256.Size]byte, error) {
	if expected, err := For(envelope.Profile, envelope.ResourceClass); err != nil || expected != envelope {
		return [sha256.Size]byte{}, ErrUnsupportedEnvelope
	}
	var encoded bytes.Buffer
	encoded.WriteString("winkyou-hardnat-execution-envelope-v1\x00")
	appendString(&encoded, string(envelope.Profile))
	appendString(&encoded, string(envelope.ResourceClass))
	appendUint32(&encoded, uint32(envelope.Cost.Resources.Sockets))
	appendUint32(&encoded, uint32(envelope.Cost.Resources.Targets))
	appendUint32(&encoded, uint32(envelope.Cost.Resources.FiveTuples))
	appendUint32(&encoded, uint32(envelope.Cost.Resources.Packets))
	appendUint32(&encoded, uint32(envelope.Cost.Resources.PacketsPerSecond))
	appendUint64(&encoded, uint64(envelope.Cost.Duration))
	encoded.WriteByte(1)
	return sha256.Sum256(encoded.Bytes()), nil
}

func appendString(target *bytes.Buffer, value string) {
	appendUint32(target, uint32(len(value)))
	target.WriteString(value)
}

func appendUint32(target *bytes.Buffer, value uint32) {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	target.Write(encoded[:])
}

func appendUint64(target *bytes.Buffer, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	target.Write(encoded[:])
}
