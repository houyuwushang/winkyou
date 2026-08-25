//go:build !linux && !windows

package pairgen

func protectPrivatePath(string, bool) error  { return ErrOutputUnavailable }
func validatePrivatePath(string, bool) error { return ErrOutputUnavailable }
func syncPrivateDirectory(string) error      { return ErrOutputUnavailable }
