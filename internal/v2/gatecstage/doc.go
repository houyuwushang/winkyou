// Package gatecstage owns the single, private responder request slot used by
// the fixed SSH child command. Staging is local file I/O only: it never takes
// a governor owner, burns a credential, opens a socket, or starts a process.
package gatecstage
