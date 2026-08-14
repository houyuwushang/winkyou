# Network Capability Gate

WinkYou v2 treats active network I/O as a reviewed capability. The repository
test in `internal/architecture` prevents a new socket opener or an indirect
Pion/QUIC dependency from appearing as an ordinary implementation detail.

## What the gate enforces

The test parses every non-test Go source file in the current checkout, across
all operating-system build tags. It records:

- standard-library TCP/UDP dial and listen functions;
- `net.Dialer`/`net.ListenConfig`-style receiver calls;
- raw socket constructors from `syscall` and `golang.org/x/sys`;
- Pion and quic-go imports, including libraries that may open sockets below the
  visible call site.

The current findings are frozen in
`internal/architecture/testdata/network_capabilities.txt`. That file is a list
of v1/legacy compatibility debt. Presence in the file is not a v2 approval and
is not evidence that the path is safe to enable.

`internal/probeio`, `internal/natsim`, every child package beneath them, and
packages beneath `internal/v2` or `pkg/v2` are governed zones. They must have
no unreviewed raw capability of their own and no transitive dependency on a
package that owns one. The only exception is the exact `openLoopbackUDP` call
in the production probeio adapter, recorded with `owner=governor`; filename,
function, package, capability, owner, or count drift fails the gate. The
adapter returns only the bounded `Datagram` interface and Phase 1a rejects
non-loopback binds and targets. `internal/natsim` is permanently pure-memory
with no exception: adding a real socket opener there fails even if the
inventory is edited. A future v2 package that imports a harmless-looking
wrapper around `pkg/nat`, for example, still fails through the dependency
graph.

Hidden worktrees, `.git`, `vendor`, and `node_modules` are excluded so ignored
copies do not become part of the current-source inventory. Non-hidden Go test
helpers with production-style `main.go` files remain inventoried deliberately.

## Reviewing a failure

Run:

```text
go test ./internal/architecture -count=1
```

The failure separates new or changed findings from stale entries and prints
the complete sorted inventory.

For a new v2 or `probeio` finding, do not update the inventory merely to make
CI pass. Route active probing through the governed capability. The production
OS adapter is the sole exact reviewed opener; callers still cannot obtain its
raw socket.

For a deliberate legacy-only change, reviewers should verify the ownership
and bounds, then update the exact sorted entry and count. Removing a legacy
capability also requires deleting its stale inventory entry; the debt list is
not allowed to grow stale.

## Limits of the check

This is a source architecture gate, not a runtime sandbox. It does not prove
that an allowlisted legacy path is safe, and it cannot reason about arbitrary
reflection, assembly, cgo, downloaded binaries, or malicious code. Dependency
and provenance review, governor limits, the persistent safety trip, fault
injection, and the live-network approval gate remain independent controls.
