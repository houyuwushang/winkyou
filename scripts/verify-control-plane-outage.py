#!/usr/bin/env python3
"""Verify that a bound data plane survives a coordinator process outage.

The script intentionally refuses to stop the coordinator unless the local
runtime state proves that at least one peer is connected and overlay ping works.
Remote SSH password is read from an environment variable, never from this file.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import pathlib
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any

import paramiko


DEFAULT_STATE = pathlib.Path(os.environ.get("LOCALAPPDATA", ".")) / "Temp" / "winkyou-p2p-test" / "local.runtime.json"
DEFAULT_CONFIG = pathlib.Path(os.environ.get("LOCALAPPDATA", ".")) / "Temp" / "winkyou-p2p-test" / "local-a.yaml"


@dataclass
class SSHConfig:
    host: str
    port: int
    user: str


def main() -> int:
    args = parse_args()

    print(f"Checking local data-plane precondition with {args.wink_path}...")
    before_peers = load_peers(args)
    bound_peer = require_bound_peer(before_peers)
    require_ping(args.ping_target)
    print(f"Precondition OK: peer {peer_label(bound_peer)} is connected; ping {args.ping_target} works.")

    ssh_cfg = resolve_ssh_config(args.chen_host, args.chen_user)
    password = remote_password(args.password_env)
    client = connect_ssh(ssh_cfg, password)
    try:
        print(f"Checking coordinator process on {ssh_cfg.user}@{ssh_cfg.host}:{ssh_cfg.port}...")
        print(run_remote(client, process_query(args.coordinator_process)).strip())

        try:
            print("Stopping coordinator process without touching natpierce/underlay...")
            print(run_remote(client, stop_process(args.coordinator_process)).strip())
            time.sleep(args.observe_seconds)

            print("Checking data plane during coordinator outage...")
            during_peers = load_peers(args)
            require_same_bound_peer(during_peers, bound_peer)
            require_ping(args.ping_target)
            print("Outage check OK: peer remains connected and overlay ping still works.")
        finally:
            if args.restart_task:
                print(f"Restarting coordinator task: {args.restart_task}")
                try:
                    print(run_remote(client, start_task(args.restart_task)).strip())
                except Exception as exc:  # noqa: BLE001
                    print(f"WARNING: failed to restart task {args.restart_task}: {exc}", file=sys.stderr)
    finally:
        client.close()

    print("Verification complete.")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chen-host", default="chen-win", help="SSH host alias or hostname for chen-win")
    parser.add_argument("--chen-user", default="", help="SSH user; defaults to OpenSSH config or chen")
    parser.add_argument("--password-env", default="WINKYOU_CHEN_PASSWORD", help="environment variable containing SSH password")
    parser.add_argument("--wink-path", default=str(pathlib.Path("dist") / "wink-windows-amd64.exe"))
    parser.add_argument("--config-path", default=str(DEFAULT_CONFIG))
    parser.add_argument("--state-path", default=str(DEFAULT_STATE))
    parser.add_argument("--ping-target", default="10.88.0.1")
    parser.add_argument("--coordinator-process", default="wink-coordinator")
    parser.add_argument("--restart-task", default="WinkYouCoordinator")
    parser.add_argument("--observe-seconds", type=int, default=20)
    return parser.parse_args()


def resolve_ssh_config(host_alias: str, user_override: str) -> SSHConfig:
    host = host_alias
    port = 22
    user = user_override.strip() or "chen"

    config_path = pathlib.Path.home() / ".ssh" / "config"
    if config_path.exists():
        ssh_config = paramiko.SSHConfig()
        with config_path.open("r", encoding="utf-8", errors="ignore") as fh:
            ssh_config.parse(fh)
        match = ssh_config.lookup(host_alias)
        host = match.get("hostname", host)
        port = int(match.get("port", port))
        if not user_override.strip():
            user = match.get("user", user)

    return SSHConfig(host=host, port=port, user=user)


def remote_password(env_name: str) -> str:
    value = os.environ.get(env_name, "").strip()
    if value:
        return value
    if sys.stdin.isatty():
        return getpass.getpass(f"SSH password ({env_name}): ")
    raise SystemExit(f"Set {env_name} to the chen-win SSH password or run interactively.")


def connect_ssh(cfg: SSHConfig, password: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=cfg.host,
        port=cfg.port,
        username=cfg.user,
        password=password,
        timeout=8,
        banner_timeout=8,
        auth_timeout=8,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def run_remote(client: paramiko.SSHClient, powershell: str, timeout: int = 30) -> str:
    encoded = base64.b64encode(powershell.encode("utf-16le")).decode("ascii")
    command = "powershell -NoProfile -EncodedCommand " + encoded
    _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    code = stdout.channel.recv_exit_status()
    if code != 0:
        raise RuntimeError(f"remote command failed with code {code}: {err.strip()}")
    if err.strip():
        return out + "\n" + err
    return out


def process_query(name: str) -> str:
    return f"""
$ErrorActionPreference='SilentlyContinue'
Get-Process -Name '{ps_quote(name)}' | Select-Object Id,ProcessName,Path,StartTime | Format-List
Get-NetTCPConnection -LocalPort 50051 | Select-Object LocalAddress,RemoteAddress,RemotePort,State,OwningProcess | Format-Table -AutoSize
"""


def stop_process(name: str) -> str:
    return f"""
$ErrorActionPreference='Continue'
Get-Process -Name '{ps_quote(name)}' -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2
Get-Process -Name '{ps_quote(name)}' -ErrorAction SilentlyContinue | Select-Object Id,ProcessName,Path | Format-List
"""


def start_task(name: str) -> str:
    return f"""
$ErrorActionPreference='Continue'
Start-ScheduledTask -TaskName '{ps_quote(name)}'
Start-Sleep -Seconds 5
Get-Process -Name 'wink-coordinator' -ErrorAction SilentlyContinue | Select-Object Id,ProcessName,Path,StartTime | Format-List
"""


def ps_quote(value: str) -> str:
    return value.replace("'", "''")


def load_peers(args: argparse.Namespace) -> list[dict[str, Any]]:
    command = [
        args.wink_path,
        "--config",
        args.config_path,
        "--state",
        args.state_path,
        "peers",
        "--json",
    ]
    proc = subprocess.run(command, check=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
    raw = proc.stdout.strip() or proc.stderr.strip()
    if not raw:
        raise SystemExit("wink peers --json returned no output.")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"wink peers --json returned invalid JSON: {exc}") from exc


def require_bound_peer(peers: list[dict[str, Any]]) -> dict[str, Any]:
    for peer in peers:
        if peer_is_bound(peer):
            return peer
    raise SystemExit("No connected/bound peer found in runtime state; refusing to stop coordinator.")


def require_same_bound_peer(peers: list[dict[str, Any]], before: dict[str, Any]) -> None:
    want = before.get("node_id")
    for peer in peers:
        if peer.get("node_id") == want and peer_is_bound(peer):
            return
    raise SystemExit(f"Peer {peer_label(before)} is no longer connected during coordinator outage.")


def peer_is_bound(peer: dict[str, Any]) -> bool:
    if str(peer.get("state", "")).lower() != "connected":
        return False
    data_state = str(peer.get("data_state", "")).lower()
    if data_state and data_state not in {"alive", "bound"}:
        return False
    if str(peer.get("transport_last_error", "")).strip():
        return False
    return not zero_time(peer.get("last_handshake"))


def zero_time(value: Any) -> bool:
    text = str(value or "")
    return text == "" or text.startswith("0001-01-01")


def require_ping(target: str) -> None:
    flag = "-n" if os.name == "nt" else "-c"
    command = ["ping", flag, "3", target]
    proc = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if proc.returncode != 0:
        raise SystemExit(f"Overlay ping failed for {target}; refusing coordinator outage verification.")


def peer_label(peer: dict[str, Any]) -> str:
    return str(peer.get("name") or peer.get("node_id") or "<unknown>")


if __name__ == "__main__":
    raise SystemExit(main())
