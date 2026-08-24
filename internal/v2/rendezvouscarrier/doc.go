// Package rendezvouscarrier provides the disconnected N2c rendezvous
// transport adapter. It is intentionally unreachable from every product
// entry point. The adapter owns one bounded stream connection but cannot
// acquire a governor lease, construct pairing material, or expose the stream.
//
// A pre-burn connection may exchange only the secret-free presence envelope.
// Handshake and authenticated control bytes remain impossible until the
// caller supplies a consumed durable admission authorization.
package rendezvouscarrier
