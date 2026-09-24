//go:build fieldc1c

package fieldc1c

// WintunIdentity returns only the secret-free, role-separated identity of an
// already validated instance. It does not issue an Instance or enable Windows
// parsing. Full Windows issuance and real adapter proof remain a B2 gate.
func (instance Instance) WintunIdentity() (name, guid string, err error) {
	return "", "", ErrInvalid
}

func deriveWintunIdentity(id, role string) (name, guid string, err error) {
	return "", "", ErrInvalid
}
