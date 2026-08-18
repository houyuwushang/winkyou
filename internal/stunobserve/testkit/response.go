// Package testkit builds synthetic STUN Binding responses for isolated tests.
// It owns no socket, resolver, goroutine, or network target.
package testkit

import (
	"errors"
	"fmt"
	"net/netip"

	"winkyou/internal/stunwire"
)

var ErrInvalidBindingRequest = errors.New("stunobserve/testkit: invalid Binding request or mapped endpoint")

// BindingSuccess validates the minimal request emitted by stunobserve.Client
// and returns a matching XOR-MAPPED-ADDRESS success response.
func BindingSuccess(request []byte, mapped netip.AddrPort) ([]byte, error) {
	transaction, err := stunwire.ParseBindingRequest(request)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidBindingRequest, err)
	}
	response, err := stunwire.BindingSuccess(transaction, mapped)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidBindingRequest, err)
	}
	return response, nil
}
