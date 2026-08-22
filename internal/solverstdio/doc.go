// Package solverstdio exposes WinkYou's bounded, local-only solver API over
// stdin/stdout. Version 1 is passive except for creating a caller-requested,
// strictly redacted report file and one explicitly requested, terminal-only
// loopback connect_test. It grants no listener or non-loopback authority.
package solverstdio
