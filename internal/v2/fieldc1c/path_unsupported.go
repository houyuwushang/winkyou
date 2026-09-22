//go:build !linux && fieldc1c

package fieldc1c

func localMachineReference() (string, error) { return "", ErrInvalid }

func canonicalFieldHome() (string, error) { return "", ErrInvalid }
func safeParents(string) error            { return ErrInvalid }
