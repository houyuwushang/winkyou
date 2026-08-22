// Package noisecore implements the exact
// Noise_NNpsk0_25519_ChaChaPoly_SHA256 handshake used by WinkYou's
// reviewed test-pairing evidence.
//
// The package is pure in-memory cryptographic machinery. It owns no network
// capability, framing transport, credential derivation, replay ledger, or
// runtime authorization. Architecture gates permit imports only from
// punchproto, the simulation adapter, and the exact loopback carrier package;
// this does not authorize non-loopback networking.
package noisecore
