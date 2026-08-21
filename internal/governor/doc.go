// Package governor provides the process-independent ownership and in-process
// reservation primitives for bounded connectivity attempts. Its machine-only
// pairing journal persists one-time credential burns and worst-case admission
// budgets across cooperating official processes and OS restarts.
//
// This package deliberately does not create sockets or start network work. A
// caller must first acquire one prepared safety namespace. The pairing journal
// still has no carrier integration; future active work must separately obtain
// durable admission plus peer and attempt leases before probeio can perform I/O.
package governor
