package rendezvousserver

import "net"

// listenOneShot is the sole raw listener owned by the one-shot rendezvous
// binary. Serve closes it immediately after the second accepted connection.
func listenOneShot(address string) (net.Listener, error) {
	return net.Listen("tcp", address)
}
