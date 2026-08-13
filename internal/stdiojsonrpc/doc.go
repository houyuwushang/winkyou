// Package stdiojsonrpc implements the bounded JSON-RPC 2.0 transport used by
// WinkYou's local stdio API. It owns framing, admission, cancellation, and
// progress delivery only; it has no network capability and does not select
// solver strategies.
package stdiojsonrpc
