// Package stunserver provides the bounded, response-only UDP loop used by
// cmd/wink-stund. It never selects a target or sends without first receiving a
// valid Binding request from that exact UDP source.
package stunserver
