// Package oobcarrier adapts one caller-provided, attempt-dedicated bounded
// stream to the reviewed WYRC control sequence used by Gate A.
//
// The package has no dial, listen, DNS, descriptor, process, SSH, Tailscale,
// retry, queue, polling, or cross-attempt reuse capability.
package oobcarrier
