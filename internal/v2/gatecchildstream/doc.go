// Package gatecchildstream adapts only the SSH forced-command stdin/stdout
// pipes to the Gate C bounded-stream contract. It is not JSON-RPC framing and
// never reads, writes, or classifies stderr.
// New consumes exclusive ownership of the supplied pipe endpoints after input
// validation. Unix file endpoints are replaced with private pollable CLOEXEC
// owners and the old wrappers are closed, including on partial failure. No
// caller may retain or use an endpoint after transfer. Non-file test streams
// must implement Close that interrupts and joins their own I/O. Close failure
// is not a successful physical drain; the carrier retains the governor witness.
package gatecchildstream
