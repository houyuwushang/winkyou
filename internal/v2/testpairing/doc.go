// Package testpairing defines the fake-only Phase 1a test pairing control
// contract.
//
// It intentionally contains no pairing secret, cryptographic handshake,
// encoder, socket, DNS lookup, or production transport adapter. Simulated
// channels enforce bounded attempt context and state transitions, but provide
// no authentication or confidentiality and must never be used across a trust
// boundary.
package testpairing
