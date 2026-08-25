// Package rendezvousadmission owns the strict, secret-free one-shot server
// admission schema shared by the offline generator and rendezvous server.
package rendezvousadmission

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"winkyou/internal/v2/rendezvouswire"
)

const MaxBytes = 4096

var ErrInvalid = errors.New("rendezvousadmission: invalid admission")

type Admission struct {
	Profile       string `json:"profile"`
	AssociationID string `json:"association_id"`
	IssuedAt      string `json:"issued_at"`
	ExpiresAt     string `json:"expires_at"`
}

type Validated struct {
	AssociationID string
	IssuedAt      time.Time
	ExpiresAt     time.Time
}

func Load(path string, now time.Time) (Validated, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > MaxBytes {
		return Validated{}, ErrInvalid
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return Validated{}, ErrInvalid
	}
	defer clear(payload)
	return Parse(payload, now)
}

func Parse(payload []byte, now time.Time) (Validated, error) {
	if len(payload) == 0 || len(payload) > MaxBytes || !json.Valid(payload) || rejectDuplicateMembers(payload) != nil {
		return Validated{}, ErrInvalid
	}
	var wire Admission
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return Validated{}, ErrInvalid
	}
	if err := requireEOF(decoder); err != nil || wire.Profile != rendezvouswire.PresenceProfile || !validAssociationID(wire.AssociationID) {
		return Validated{}, ErrInvalid
	}
	issuedAt, err := parseCanonicalUTCSecond(wire.IssuedAt)
	if err != nil {
		return Validated{}, ErrInvalid
	}
	expiresAt, err := parseCanonicalUTCSecond(wire.ExpiresAt)
	if err != nil || !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > 10*time.Minute || now.Before(issuedAt) || !now.Before(expiresAt) {
		return Validated{}, ErrInvalid
	}
	return Validated{AssociationID: wire.AssociationID, IssuedAt: issuedAt, ExpiresAt: expiresAt}, nil
}

func parseCanonicalUTCSecond(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Nanosecond() != 0 || parsed.Format(time.RFC3339) != value {
		return time.Time{}, ErrInvalid
	}
	return parsed, nil
}

func rejectDuplicateMembers(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return ErrInvalid
	}
	seen := make(map[string]struct{}, 4)
	for decoder.More() {
		nameToken, err := decoder.Token()
		if err != nil {
			return ErrInvalid
		}
		name, ok := nameToken.(string)
		if !ok {
			return ErrInvalid
		}
		if _, duplicate := seen[name]; duplicate {
			return ErrInvalid
		}
		seen[name] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return ErrInvalid
		}
		clear(value)
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return ErrInvalid
	}
	return requireEOF(decoder)
}

func requireEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}

func validAssociationID(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	valid := err == nil && len(decoded) == 16 && base64.RawURLEncoding.EncodeToString(decoded) == value
	clear(decoded)
	return valid
}
