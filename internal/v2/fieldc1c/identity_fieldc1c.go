//go:build fieldc1c

package fieldc1c

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"time"
)

// WintunIdentity returns only the secret-free, role-separated identity of an
// already validated instance. It does not issue an Instance or enable Windows
// parsing. Full Windows issuance and real adapter proof remain a B2 gate.
func (instance Instance) WintunIdentity() (name, guid string, err error) {
	if instance.Check(time.Now()) != nil {
		return "", "", ErrInvalid
	}
	return deriveWintunIdentity(instance.value.doc.InstanceID, instance.value.role)
}

func deriveWintunIdentity(id, role string) (name, guid string, err error) {
	if !attemptID(id) || (role != "initiator" && role != "responder") {
		return "", "", ErrInvalid
	}
	decoded, _ := base64.RawURLEncoding.DecodeString(id)
	input := append([]byte("winkyou-c1c-wintun-identity/1\n"), decoded...)
	input = append(input, 0)
	input = append(input, role...)
	digest := sha256.Sum256(input)
	name = "wcf" + hex.EncodeToString(digest[:6])
	h := hex.EncodeToString(digest[16:])
	return name, h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}
