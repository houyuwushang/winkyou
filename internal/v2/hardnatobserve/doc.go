// Package hardnatobserve collects one bounded, attempt-local RFC 5780 and
// allocation-tomography evidence window through caller-owned probeio handles.
//
// The package cannot open sockets, acquire a governor lease, resolve names, or
// retry observations. It turns exactly thirteen pre-issued transactions into
// the trusted pure-function input consumed by hardnatplan.
package hardnatobserve
