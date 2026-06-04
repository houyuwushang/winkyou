# WinkYou Release Notes

## Highlights

- Self-host coordinator + TURN relay deployment path.
- `legacy_ice_udp`, `relay_only`, and `tcp_framed` alpha strategy coverage.
- `wink doctor`, `wink logs`, and long-running client workflow docs.

## Artifacts

- `wink-windows-amd64.exe`
- `wink-linux-amd64`
- `wink-coordinator-linux-amd64`
- `wink-relay-linux-amd64`
- `SHA256SUMS`

## Verification

```bash
sha256sum -c SHA256SUMS
wink-linux-amd64 version
wink-coordinator-linux-amd64 --version
wink-relay-linux-amd64 --version
```

## Upgrade Notes

- Back up the active config file before replacing binaries.
- Stop the running client before replacing `wink`.
- Restart the coordinator before clients if coordinator and clients are upgraded together.

## Known Limits

- `tcp_framed` is alpha and requires an explicitly reachable TCP address.
- GUI, mobile clients, no-admin mode, and QUIC datagram are not part of v0.1.
- Windows service integration uses Task Scheduler or NSSM guidance rather than a native service binary.
