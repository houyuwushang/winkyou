// Package punchsim defines the zero-network-capability state machine used to
// simulate one bounded, synchronized direct UDP punch. It owns no socket,
// pairing channel, resolver, goroutine, or network target. Tests inject a
// governed socket-shaped adapter; production paths must not import this package.
package punchsim
