// Package governor provides the process-independent ownership and in-process
// reservation primitives for bounded connectivity attempts. Its machine-only
// pairing journal persists one-time credential burns and worst-case admission
// budgets across cooperating official processes and OS restarts.
//
// This package deliberately does not create sockets or start network work. A
// caller must first acquire one prepared safety namespace. The zero-network
// pairing gate combines a durable admission with a live attempt lease, but has
// no production carrier; probeio remains the only reviewed future I/O boundary.
package governor
