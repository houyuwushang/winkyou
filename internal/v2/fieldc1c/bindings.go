//go:build fieldc1c

package fieldc1c

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"time"
)

// Binding is a copy of secret-free comparison metadata, never a capability.
type Binding struct {
	ID, Role, Profile, Resource, MappingSetRole string
	ManifestReference, ManifestSHA256           string
	InitiatorScope, ResponderScope              string
	CredentialExpiresAt                         time.Time
	SessionCeiling                              time.Duration
	MissedRounds                                int
	Deadline                                    time.Time
}

func (instance Instance) Binding() (Binding, error) {
	if instance.Check(time.Now()) != nil {
		return Binding{}, ErrInvalid
	}
	v := instance.value
	expires, _ := utcTime(v.doc.CredentialExpiresAt)
	ceiling, _ := time.ParseDuration(v.doc.AbsoluteSessionCeiling)
	result := Binding{ID: v.doc.InstanceID, Role: v.role, Profile: v.doc.Profile, Resource: v.doc.ResourceClass,
		ManifestReference: filepath.Join(v.doc.CredentialReference, "manifest.json"), ManifestSHA256: v.doc.ManifestSHA256,
		InitiatorScope: v.doc.InitiatorMachineScopeReference, ResponderScope: v.doc.ResponderMachineScopeReference,
		CredentialExpiresAt: expires, SessionCeiling: ceiling, MissedRounds: v.doc.InitiatorMissedRounds, Deadline: v.notAfter}
	if v.role == "responder" {
		result.MissedRounds = v.doc.ResponderMissedRounds
	}
	if v.doc.MappingSetRole != nil {
		result.MappingSetRole = *v.doc.MappingSetRole
	}
	return result, nil
}

func (instance Instance) CheckConfiguration(payload []byte) error {
	if instance.Check(time.Now()) != nil {
		return ErrInvalid
	}
	digest := sha256.Sum256(payload)
	if hex.EncodeToString(digest[:]) != instance.value.device.ConfigurationSHA256 {
		return ErrInvalid
	}
	return nil
}

func (instance Instance) EvidenceDirectory() (string, error) {
	if instance.value == nil {
		return "", ErrInvalid
	}
	path, err := InstancePath(instance.value.doc.InstanceID)
	if err != nil {
		return "", ErrInvalid
	}
	return filepath.Join(filepath.Dir(path), "evidence", instance.value.doc.InstanceID), nil
}
