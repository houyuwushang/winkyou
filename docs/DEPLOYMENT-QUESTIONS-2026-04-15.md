# 2026-04-15 Deployment Questions For Expert Review

## Context

Today we attempted the documented quickstart deployment path:

- Windows client
- Linux coordinator
- Linux relay
- Linux peer

Coordinator registration works. Both peers become visible through `wink peers`. The failure is in the last data-plane mile: peers remain `connecting` and `wink ping` times out.

## Confirmed Findings

### 1. Windows TUN path is alive

- Windows `wink.exe up` reaches `wink engine started`.
- `wink0` receives the expected virtual IP, for example `10.42.0.1/24`.
- Application traffic is sourced from the overlay IP, for example:
  - `read udp4 10.42.0.1:53465->10.42.0.2:33434: i/o timeout`

This means the packet path is making it into the host stack and out through the TUN route.

### 2. Linux TUN path is alive

- Linux peer starts successfully with `backend=tun`.
- `ip addr show wink0` shows the expected virtual IP, for example `10.42.0.2/24`.
- `ip route get 10.42.0.1` resolves to `dev wink0`.

### 3. Direct-only mode does not connect in this environment

With `turn_servers: []` on both sides:

- `wink peers` shows `Conn Type: direct`
- `Endpoint: -`
- peers remain `State: connecting`

This looks consistent with an environment where direct ICE connectivity is not available across the two real networks.

### 4. Relay mode selects a TURN path but still does not complete the tunnel handshake

With TURN enabled:

- `wink peers` shows `Conn Type: relay`
- `Endpoint` becomes a relay address such as `104.168.56.67:59100`
- peers still remain `State: connecting`
- `wink ping` still times out

### 5. Embedded relay logs a repeated TURN server error

Observed on the Linux relay host:

```text
Failed to handle CreatePermission-request ... no allocation found ... :0.0.0.0:3478
```

This shows TURN permission creation is being attempted, but the server cannot find the corresponding allocation for that request.

## Changes already made in this round

- `pkg/relay/server/server.go`
  - When `relay-ip` is a local interface IP and the listener is wildcard, the server now normalizes the bind address to a concrete host IP instead of keeping `:3478` / `0.0.0.0:3478`.
- `deploy/quickstart/start-relay.sh`
  - The quickstart relay script now defaults to `--listen ${WINK_RELAY_IP}:3478`.
- `README.md`
  - Quickstart and troubleshooting now call out explicit relay binding and the need to open a high UDP relay port range, not just `3478/udp`.
- `pkg/client/*` and `cmd/wink/cmd/peers.go`
  - `wink peers` now syncs per-peer tunnel stats and shows `Handshake` timestamps from `wireguard-go`, which should make the next debugging session more concrete.
- `pkg/netif/tun_windows_wg.go`
  - Added internal `WINKYOU_TUN_NAME` override so adapter naming can be controlled during deployment/debugging without changing exported APIs.

## Open Questions

### Q1. Is the embedded `wink-relay` TURN server actually safe for this deployment path?

The quickstart currently uses the in-repo TURN server. In real cross-network deployment, we observed repeated:

```text
CreatePermission-request ... no allocation found
```

Questions:

- Is the `pion/turn` server wiring in `pkg/relay/server/server.go` sufficient for public deployment, or should we switch the documented path to `coturn` until this is proven stable?
- Is there a known issue with using a single UDP listener plus `RelayAddressGeneratorStatic` in this way for real public deployments?

### Q2. Is the selected `pion/ice` transport safe to hand directly to `wireguard-go` as a `net.Conn`?

Current design:

- `pkg/nat/ice_pion.go` returns the selected `*pion/ice.Conn`
- `pkg/client/peer_session.go` retains that transport
- `pkg/tunnel/tunnel_wggo.go` injects it into a custom WireGuard bind

Questions:

- Is passing `*pion/ice.Conn` directly into the custom `wireguard-go` bind correct for long-lived WireGuard traffic?
- Are there TURN permission/channel-binding semantics that require additional lifecycle handling beyond holding the `ICEAgent` open?
- Is there any datagram-boundary or endpoint identity issue in the current bind adapter that would prevent WireGuard handshake packets from flowing even though ICE selected the pair successfully?

### Q3. Should we add a dedicated end-to-end test for "ICE relay transport attached to wireguard-go tunnel"?

Current tests cover:

- ICE agent connection itself
- bind send/receive plumbing
- privileged Linux direct e2e

But we do not yet have a dedicated test that proves:

1. two ICE agents connect via relay candidate
2. the selected transport is attached to `wireguard-go`
3. a real WireGuard handshake completes
4. an IP packet crosses the tunnel

Question:

- Is that the right next test to add before trusting the embedded relay deployment path?

### Q4. Should quickstart prefer direct-public-IP binding for the embedded relay by default?

We changed quickstart to prefer `--listen ${WINK_RELAY_IP}:3478` when that IP is actually present on a local interface.

Question:

- Is that the right default, or should the relay binary fail fast when `--relay-ip` is set but `--listen` is wildcard, instead of trying to normalize it?

## Recommended next expert focus

1. Review the TURN allocation / permission failure around `CreatePermission-request ... no allocation found`.
2. Review whether the current `pion/ice.Conn -> custom wireguard-go bind` integration is sound for relay-selected transports.
3. Decide whether the documented deployment path should temporarily standardize on `coturn` until the in-repo relay is validated by a real relay e2e test.
