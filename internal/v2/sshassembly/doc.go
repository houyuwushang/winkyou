// Package sshassembly turns one sealed SSH endpoint authority and one exact
// Gate B attempt reservation into a bounded OpenSSH child byte stream. The
// ordinary build can construct loopback authority only. The package owns no
// UDP, probeio, WireGuard, legacy, retry, DNS, shell, or product-entry path.
package sshassembly
