// Package punchsim executes the simulation-only adapter around punchproto's
// pure direct-punch state machine. It owns no socket, pairing channel,
// resolver, goroutine, or network target. Tests inject a governed
// socket-shaped adapter; production paths must not import this package.
package punchsim
