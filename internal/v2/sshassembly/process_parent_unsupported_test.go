//go:build !linux && !windows

package sshassembly

func processGoneForTest(int) bool { return true }
func killProcessForTest(int)      {}
