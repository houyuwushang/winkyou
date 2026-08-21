// Package noisecore implements the exact
// Noise_NNpsk0_25519_ChaChaPoly_SHA256 handshake used by WinkYou's
// simulation-only test-pairing evidence.
//
// The package is pure in-memory cryptographic machinery. It owns no network
// capability, framing transport, credential derivation, replay ledger, or
// runtime authorization. Production paths must not import it until the pairing
// ADR and its independent review gates are accepted.
package noisecore
