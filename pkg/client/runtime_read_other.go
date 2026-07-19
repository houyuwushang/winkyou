//go:build !windows

package client

func isTransientRuntimeStateReadError(error) bool { return false }
