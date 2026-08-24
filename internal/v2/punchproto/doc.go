// Package punchproto defines the pure message codec and transition state
// machine for one bounded direct-punch exchange.
//
// It owns no socket, goroutine, resolver, clock, admission decision, or
// retry policy. The package is approved only for the simulation package and
// the exact loopback carrier boundary enforced by internal/architecture.
package punchproto
