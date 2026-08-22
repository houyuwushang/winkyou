// Package pairingcontext owns the secret-free PairingContext validation,
// restricted JCS encoding, and fixed Noise prologue construction shared by
// reviewed test-pairing adapters.
//
// It owns no pairing secret, socket, ledger, governor capability, clock,
// goroutine, or runtime authority.
package pairingcontext
