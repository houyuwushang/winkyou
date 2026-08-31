//go:build !linux

package sshchildwrapper

func validateFixedInstallation() error { return ErrWrapperUnsupported }
