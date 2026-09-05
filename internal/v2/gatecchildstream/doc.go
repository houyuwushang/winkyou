// Package gatecchildstream adapts only the SSH forced-command stdin/stdout
// pipes to the Gate C bounded-stream contract. It is not JSON-RPC framing and
// never reads, writes, or classifies stderr.
package gatecchildstream
