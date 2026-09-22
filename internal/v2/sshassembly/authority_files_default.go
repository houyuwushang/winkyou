//go:build !fieldc1c

package sshassembly

// Existing loopback and isolated namespace authorities retain their reviewed
// file validation. Ordinary builds cannot contain a field scope implementation.
func validateAuthorityFiles(SSHEndpointAuthority, string, string) error { return nil }
