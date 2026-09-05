//go:build !linux

package sshchildwrapper

// PrepareRootExecution does not grant a new child execution domain on Windows
// or any other platform in Gate C1b.
func PrepareRootExecution(string) (Execution, error) {
	return Execution{}, ErrWrapperUnsupported
}
