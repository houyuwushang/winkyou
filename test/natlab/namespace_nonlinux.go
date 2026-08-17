//go:build !linux

package natlab

import "errors"

var ErrNamespacesUnsupported = errors.New("natlab: Linux network namespaces are unavailable")

func RunInNamespace(string, func() error) error {
	return ErrNamespacesUnsupported
}
