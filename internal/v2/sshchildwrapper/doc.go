// Package sshchildwrapper freezes and validates the responder forced-command
// execution domain. C1a provides validation and a pure execution plan only;
// it does not install a wrapper, edit authorized_keys/sshd, or expose the C1b
// child command.
package sshchildwrapper
