// Package governor provides the process-independent ownership and in-process
// reservation primitives for bounded connectivity attempts.
//
// This package deliberately does not create sockets or start network work. A
// caller must first acquire one prepared safety namespace, then obtain peer and
// attempt leases before a future probeio layer can perform active I/O.
package governor
