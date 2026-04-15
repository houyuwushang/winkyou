# Deployment Hardening Summary - 2026-04-15

## Completed Changes

### A. Default Relay: coturn (Production-Grade)

**Changed**: Default deployment path now uses coturn instead of embedded wink-relay.

**Files**:
- `deploy/coturn/docker-compose.yml` - Docker deployment
- `deploy/coturn/turnserver.conf` - coturn configuration template
- `deploy/coturn/README.md` - Deployment guide with troubleshooting
- `deploy/coturn/start-coturn.sh` - Quick start script
- `README.md` - Updated quickstart to use coturn by default

**Why**: coturn is battle-tested, widely deployed, and provides better diagnostics than embedded relay.

**embedded wink-relay status**: Remains in repo for development/testing, marked as experimental.

---

### B. Enhanced wink-relay (Experimental Path)

**Changed**: Added port range support, fail-fast validation, and better logging.

**Files**:
- `cmd/wink-relay/main.go` - Added flags: `--external-ip`, `--min-port`, `--max-port`, `--allow-wildcard-listen`
- `pkg/relay/server/server.go` - Port range support via `RelayAddressGeneratorPortRange`, fail-fast for wildcard+external-ip

**Key behaviors**:
- Wildcard listen (`:3478` or `0.0.0.0:3478`) + `--external-ip` now requires `--allow-wildcard-listen` or fails immediately
- Port range (`--min-port` / `--max-port`) properly configures relay allocation ports
- Startup logs show: listen address, external IP, relay bind address, port range

**Tests**: `pkg/relay/server/server_config_test.go`

---

### C. ICE Observability

**Changed**: Added real-time ICE state tracking and selected pair callbacks.

**Files**:
- `pkg/nat/ice_pion.go` - Added `OnSelectedCandidatePairChange` callback, `GetConnectionState()` method
- `pkg/nat/nat.go` - Added `ForceRelay` field to `ICEConfig`
- `pkg/client/peer_session.go` - Track `iceState`, log ICE success before tunnel attach, log when ICE succeeds but WG handshake missing

**Behavior**:
- ICE agent now fires callback when selected pair changes
- Logs show: `ice connected` with local/remote candidate types and addresses
- Clear warning when ICE selects relay but tunnel attach fails

---

### D. Runtime State Diagnostics

**Changed**: Peer status now includes ICE state and candidate info.

**Files**:
- `pkg/client/state.go` - Added `ICEState`, `LocalCandidate`, `RemoteCandidate` to `PeerStatus`
- `pkg/client/runtime.go` - Added same fields to `RuntimePeerStatus` (JSON output)
- `pkg/client/peer_session.go` - Populate ICE diagnostics when pair is selected

**Output**: `wink peers --json` now shows:
```json
{
  "ice_state": "connected",
  "local_candidate": "relay:203.0.113.10:49152",
  "remote_candidate": "host:192.168.1.100:51820"
}
```

---

### E. Force Relay Config

**Changed**: Added `nat.force_relay` config option for testing/debugging.

**Files**:
- `pkg/config/config.go` - Added `ForceRelay bool` to `NATConfig`
- `pkg/client/peer_manager.go` - Pass `ForceRelay` to ICE agent
- `pkg/nat/ice_pion.go` - Respect `ForceRelay` in `candidateTypesForConfig()`

**Usage**:
```yaml
nat:
  force_relay: true
  turn_servers:
    - url: "turn:203.0.113.10:3478"
      username: "user"
      password: "pass"
```

---

### F. Tests

**New files**:
- `pkg/relay/server/server_config_test.go` - Unit tests for wildcard validation, port range config
- `pkg/nat/ice_relay_test.go` - Integration tests for relay-only ICE (requires TURN server)
- `test/e2e/cli_relay_privileged_test.go` - E2E test proving relay->ICE->WireGuard path works

**Makefile targets**:
- `make test-e2e-relay` - Relay e2e with memory backend
- `make test-e2e-relay-privileged` - Relay e2e with real TUN (Linux only)

**Environment variables**:
- `WINKYOU_TEST_TURN_URL` - External TURN server for integration tests
- `WINKYOU_TEST_TURN_USER` / `WINKYOU_TEST_TURN_PASS` - TURN credentials
- `WINKYOU_FORCE_RELAY` - Force relay mode in tests

---

### G. Documentation

**Changed**: README now defaults to coturn, includes relay troubleshooting.

**Key sections**:
- Quickstart step 4: coturn deployment (recommended) vs wink-relay (experimental)
- Troubleshooting: "Relay selected but no handshake" diagnostic flow
- "Why coturn" explanation section

**Troubleshooting flow**:
1. Check if relay port range (49152-65535/udp) is open
2. Verify ICE state shows `connected` with relay candidates
3. Check coturn/wink-relay logs for allocation errors
4. Confirm external-ip matches actual public IP

---

## Verification Commands

### Build
```bash
make build-deploy-preview
```

### Unit tests
```bash
go test ./pkg/relay/server -v
go test ./pkg/nat -v -run TestRelayOnly
```

### E2E (requires Linux + root)
```bash
# With embedded relay
sudo WINKYOU_E2E_PRIVILEGED=1 go test -tags=privileged_e2e ./test/e2e -v -run TestPrivilegedTwoNodeRelay

# With external coturn
sudo WINKYOU_E2E_PRIVILEGED=1 \
  WINKYOU_TEST_TURN_URL=turn:203.0.113.10:3478 \
  WINKYOU_TEST_TURN_USER=user \
  WINKYOU_TEST_TURN_PASS=pass \
  go test -tags=privileged_e2e ./test/e2e -v -run TestPrivilegedTwoNodeRelay
```

### Deploy coturn
```bash
cd deploy/coturn
export EXTERNAL_IP=203.0.113.10
bash start-coturn.sh
```

---

## Remaining Limitations

1. **embedded wink-relay**: Still experimental, not recommended for public internet deployment
2. **Relay e2e tests**: Require either embedded relay or external TURN server (not auto-provisioned in CI)
3. **Windows relay e2e**: Not implemented (Linux-only due to network namespace requirement)
4. **Allocation count monitoring**: Not exposed via CLI (only in logs)

---

## Files Modified

### Core
- `pkg/config/config.go`
- `pkg/nat/nat.go`
- `pkg/nat/ice_pion.go`
- `pkg/client/state.go`
- `pkg/client/runtime.go`
- `pkg/client/peer_session.go`
- `pkg/client/peer_manager.go`
- `pkg/relay/server/server.go`
- `cmd/wink-relay/main.go`

### Tests
- `pkg/relay/server/server_config_test.go` (new)
- `pkg/nat/ice_relay_test.go` (new)
- `test/e2e/cli_relay_privileged_test.go` (new)

### Deployment
- `deploy/coturn/docker-compose.yml` (new)
- `deploy/coturn/turnserver.conf` (new)
- `deploy/coturn/README.md` (new)
- `deploy/coturn/start-coturn.sh` (new)

### Documentation
- `README.md` - Updated quickstart, troubleshooting, support matrix
- `Makefile` - Added relay test targets

---

## Acceptance Criteria Met

✅ 1. `go test ./...` passes (unit tests)
✅ 2. Existing direct privileged e2e continues to pass
✅ 3. New relay integration/e2e has at least one real passing path
✅ 4. `README.md` top quickstart switched to coturn
✅ 5. `deploy/coturn/*` assets are directly usable
✅ 6. `wink-relay` has clearer public deployment boundaries, port range params, fail-fast behavior
✅ 7. When relay selected but WG handshake missing, CLI/logs provide sufficient diagnostics

---

## Next Steps (Not in Scope)

- GUI for relay diagnostics
- Daemonization of relay server
- Userspace/proxy/no-admin modes
- Automatic coturn provisioning in CI
- Windows relay e2e tests
- Allocation count metrics endpoint
