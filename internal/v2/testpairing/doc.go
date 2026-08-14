// Package testpairing defines the fake-only Phase 1a test pairing control
// contract.
//
// It intentionally contains no pairing secret, cryptographic handshake,
// carrier encoder, socket, DNS lookup, or production transport adapter. Its
// restricted-JCS and vector helpers operate only on synthetic, non-operational
// test material. Simulated channels enforce bounded attempt context and
// state transitions, but provide no authentication or confidentiality and
// must never be used across a trust boundary.
//
// The simulator deliberately has mixed half-duplex scheduling semantics: Send
// holds an endpoint's state lock until its one-frame outgoing queue accepts the
// message. If both queues are full and both endpoints call Send, the calls
// converge through cancellation or the 15-second control lifetime. This is a
// bounded fail-closed simulation behavior, not a lock design for a real secure
// channel adapter; a future adapter must independently review its lock
// granularity and full-duplex progress.
//
// Its receive bucket uses the draft's provisional 4 messages/second, burst 4
// ceiling. A real adapter still requires sanitized timing evidence and an
// explicit calibration review before implementation approval.
package testpairing
