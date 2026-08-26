// Package hardnatplan contains the zero-network Gate B1 state tomography and
// bounded candidate planner. It owns no socket, resolver, governor, probeio,
// carrier, executor, retry, or persistence capability. Network-shaped values
// are represented as inert fixed-width evidence values only.
//
// Every function in this package is deterministic for the same explicit
// inputs. A later reviewed gate may provide a handshake-derived PlannerKeySource
// and consume the frozen plan, but it must not widen the plan here.
package hardnatplan
