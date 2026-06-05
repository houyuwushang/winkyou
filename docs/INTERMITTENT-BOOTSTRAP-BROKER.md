# Intermittent Bootstrap Broker

This document defines the A/B/C intermittent bootstrap broker design. It is not
a peer relay design and does not enable user-data forwarding through B.

## Scenario

The target topology is:

```text
T1: B can reach A and collects/caches A descriptor, capability, and candidate hints.
T2: B can reach C, forwards A descriptor to C, and collects C descriptor.
T3: B can reach A again and forwards C descriptor to A.
Final: A and C use coordinator-like session bootstrap material to build direct path.
After: B can go offline; A-C direct or multipath data plane continues.
```

In the current lab labels:

- A is the local machine, often called `local-a`.
- B is `chen-win`.
- C is `inner-gw`.

No credentials belong in this document or repository.

## Terms

### Bootstrap Broker

A bootstrap broker is a node that temporarily stores and forwards rendezvous
material for peers that are not online or mutually reachable at the same time.
It helps peers discover enough metadata to attempt session bootstrap. It is not
automatically trusted to carry user data.

### Peer Descriptor

A peer descriptor is a signed or otherwise authenticated description of one peer
for rendezvous purposes. The first model can contain:

- node ID;
- WireGuard public key;
- virtual IP;
- advertised capability;
- last successful path ID;
- candidate hints;
- update and expiry timestamps.

### Candidate Hint

A candidate hint is a compact path hint that may help another peer attempt a
future strategy. It is not a guarantee that the path is reachable. Examples:

- strategy name, such as `legacy_ice_udp` or `tcp_framed`;
- candidate type, such as host, srflx, relay, or explicit TCP;
- address string;
- source label, such as local gather, coordinator cache, or broker cache.

### Cached Rendezvous Envelope

A cached rendezvous envelope is a store-and-forward message addressed to a peer
that is not currently reachable by the broker. It should include version, sender,
recipient, message type, sequence, payload, sent time, and expiry metadata.

### Store-And-Forward Rendezvous

Store-and-forward rendezvous is the broker behavior where B persists descriptors
or envelopes temporarily, then drains them when the target peer later connects to
B. It is a bootstrap mechanism, not a continuous data path.

## Non-Goals

- B does not forward A-C user traffic by default.
- B does not join A or C's security domain unless a later feature explicitly
  authorizes that.
- B does not become a default peer relay.
- This design does not enable arbitrary virtual LAN nodes to route for one
  another.
- This design does not replace the existing coordinator RPC in the current
  production path.

## Minimal Implementation Route

1. Add a local message model for peer descriptors, candidate hints, and cached
   rendezvous envelopes.
2. Add validation and JSON roundtrip tests for the message model.
3. Add an in-memory fake broker with descriptor cache, envelope queue, drain, and
   TTL cleanup.
4. Test the A/B/C timing sequence entirely in memory.
5. Only after the model and simulator are stable, consider client runtime
   integration behind an explicit disabled-by-default gate.
6. After runtime integration exists, add real three-node validation using
   local-a, chen-win, and inner-gw.

## Boundaries

The bootstrap broker can improve first-contact resilience, but it is separate
from protected direct multipath:

- Protected direct multipath keeps a direct/P2P standby data path alive after a
  session is already established.
- Intermittent bootstrap broker helps peers exchange enough information to start
  a session when a normal coordinator-like online rendezvous is intermittent.

The two can compose, but B must not become A-C's permanent data-plane
dependency. After A and C establish a direct or multipath transport, B should be
able to disappear without breaking that established data plane.
