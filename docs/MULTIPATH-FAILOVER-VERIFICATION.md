# Multipath Failover Verification

This note describes the real-device verification script for protected direct
multipath. It is intentionally operator-facing and does not store credentials.

## Topology

Use the current three-node test topology as labels:

- A: local machine, also referred to as `local-a`.
- B: `chen-win`, used as coordinator host, jump host, or middle-node dependency in tests.
- C: `inner-gw`, the target peer behind B-side access.

Do not commit SSH passwords or private keys into this repository. If a fault
action uses SSH, rely on an interactive SSH prompt, SSH agent, or local
operator-specific secret handling outside the repo.

## Preconditions

Before running a destructive fault action, make sure the local client is already
running with protected direct multipath enabled:

```yaml
connectivity:
  mode: auto
  strategy_order:
    - relay_only
    - legacy_ice_udp
  multipath:
    enabled: true
    protect_direct: true
    max_paths: 2
    shadow_write: true
```

The script checks these runtime conditions before it will continue:

- `wink peers --json` returns at least one peer.
- The selected peer is `state=connected` and `data_state=alive`.
- `multipath_enabled=true`.
- `protected_direct_path_id` is non-empty.
- Baseline `wink ping <peer>` succeeds.

## Dry Run

Dry-run is the default and does not modify any remote system:

```bash
python scripts/verify-multipath-failover.py \
  --wink-path dist/wink-windows-amd64.exe \
  --config-path %LOCALAPPDATA%/Temp/winkyou-p2p-test/local-a.yaml \
  --state-path %LOCALAPPDATA%/Temp/winkyou-p2p-test/local.runtime.json
```

The command prints a JSON report with the runtime path IDs and ping results.

## Fault Actions

Fault actions require both an action flag and `--confirm-fault`.

Stop coordinator on `chen-win`:

```bash
python scripts/verify-multipath-failover.py \
  --stop-coordinator \
  --confirm-fault \
  --coordinator-host chen-win
```

Stop a relay process on the relay host:

```bash
python scripts/verify-multipath-failover.py \
  --stop-relay \
  --confirm-fault \
  --relay-host chen-win
```

Run an explicit host-specific primary dependency fault:

```bash
python scripts/verify-multipath-failover.py \
  --pause-primary-host \
  --confirm-fault \
  --primary-host chen-win \
  --pause-primary-command "<operator supplied command>"
```

The primary-host action has no built-in default because pausing a host or link is
environment-specific and may be disruptive. The operator must provide the exact
command.

## Expected Result

The JSON report should show:

- baseline ping succeeded;
- fault action was skipped in dry-run mode, or explicitly executed with confirmation;
- all post-fault `wink ping` probes succeeded;
- `primary_path_id`, `protected_direct_path_id`, `active_path_id`, and
  `standby_path_ids` were captured from runtime state.

If the script reports that protected direct is unavailable, run:

```bash
wink peers --json
wink doctor
```

and check whether `wink doctor` says multipath is disabled or direct standby is
missing.
