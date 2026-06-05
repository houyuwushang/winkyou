#!/usr/bin/env python3
"""Verify protected-direct multipath failover from local runtime state.

The script is intentionally dry-run by default. A destructive fault action only
runs when both an action flag and --confirm-fault are provided.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import pathlib
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any


DEFAULT_STATE = pathlib.Path(os.environ.get("LOCALAPPDATA", ".")) / "Temp" / "winkyou-p2p-test" / "local.runtime.json"
DEFAULT_CONFIG = pathlib.Path(os.environ.get("LOCALAPPDATA", ".")) / "Temp" / "winkyou-p2p-test" / "local-a.yaml"


@dataclass
class Step:
    name: str
    ok: bool
    detail: str = ""
    data: dict[str, Any] = field(default_factory=dict)


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    args = parse_args()
    report: dict[str, Any] = {
        "status": "failed",
        "started_at": utc_now(),
        "topology": {
            "local_node": args.local_node,
            "bootstrap_or_middle_node": args.bootstrap_node,
            "target_node": args.target_node,
        },
        "fault_action": selected_fault_action(args),
        "dry_run": not args.confirm_fault or selected_fault_action(args) == "dry-run",
        "steps": [],
    }

    try:
        peer = check_preconditions(args, report)
        run_baseline_ping(args, peer, report)
        run_fault_action(args, report)
        run_post_fault_pings(args, peer, report)
        report["status"] = "ok"
        return_code = 0
    except Exception as exc:  # noqa: BLE001
        report["error"] = str(exc)
        add_step(report, "failed", False, str(exc))
        return_code = 1
    finally:
        report["finished_at"] = utc_now()
        payload = json.dumps(report, indent=2, sort_keys=True)
        if args.output:
            pathlib.Path(args.output).write_text(payload + "\n", encoding="utf-8")
        print(payload)

    return return_code


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wink-path", default=str(pathlib.Path("dist") / "wink-windows-amd64.exe"))
    parser.add_argument("--config-path", default=str(DEFAULT_CONFIG))
    parser.add_argument("--state-path", default=str(DEFAULT_STATE))
    parser.add_argument("--peer-target", default="", help="peer name/node_id/virtual_ip for wink ping; defaults to protected peer")
    parser.add_argument("--local-node", default="local-a", help="topology label for this machine")
    parser.add_argument("--bootstrap-node", default="chen-win", help="topology label for B")
    parser.add_argument("--target-node", default="inner-gw", help="topology label for C")
    parser.add_argument("--post-ping-count", type=int, default=5)
    parser.add_argument("--post-ping-interval", type=float, default=2.0)
    parser.add_argument("--command-timeout", type=int, default=30)
    parser.add_argument("--confirm-fault", action="store_true", help="required before any destructive fault action runs")
    parser.add_argument("--require-failover", action="store_true", help="after a confirmed fault, require active path or failover reason to change")
    parser.add_argument("--output", default="", help="optional path for the JSON report")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("--stop-coordinator", action="store_true", help="stop wink-coordinator on --coordinator-host")
    group.add_argument("--stop-relay", action="store_true", help="stop wink-relay on --relay-host")
    group.add_argument("--pause-primary-host", action="store_true", help="run --pause-primary-command on --primary-host")

    parser.add_argument("--ssh-user", default="", help="optional SSH user for remote fault commands")
    parser.add_argument("--coordinator-host", default="chen-win")
    parser.add_argument("--relay-host", default="chen-win")
    parser.add_argument("--primary-host", default="chen-win")
    parser.add_argument("--coordinator-process", default="wink-coordinator")
    parser.add_argument("--relay-process", default="wink-relay")
    parser.add_argument("--pause-primary-command", default="", help="explicit remote command for --pause-primary-host")
    return parser.parse_args()


def check_preconditions(args: argparse.Namespace, report: dict[str, Any]) -> dict[str, Any]:
    peers = load_peers(args)
    add_step(report, "load_peers", True, f"{len(peers)} peer(s)", {"peer_count": len(peers)})
    peer = find_multipath_peer(peers)
    path_state = peer_path_state(peer)
    report["pre_fault_path_state"] = path_state
    add_step(
        report,
        "multipath_precondition",
        True,
        "protected direct standby is present",
        {"peer": peer_label(peer), **path_state},
    )
    return peer


def run_baseline_ping(args: argparse.Namespace, peer: dict[str, Any], report: dict[str, Any]) -> None:
    result = run_wink_ping(args, peer)
    add_step(report, "baseline_ping", result.returncode == 0, result_summary(result), command_data(result))
    if result.returncode != 0:
        raise RuntimeError("baseline wink ping failed")


def run_fault_action(args: argparse.Namespace, report: dict[str, Any]) -> None:
    action = selected_fault_action(args)
    if action == "dry-run":
        add_step(report, "fault_action", True, "dry-run; no remote system changed")
        return
    if not args.confirm_fault:
        raise RuntimeError(f"{action} requested without --confirm-fault")

    if action == "stop-coordinator":
        result = run_remote_powershell(args.coordinator_host, args.ssh_user, stop_process_script(args.coordinator_process), args.command_timeout)
    elif action == "stop-relay":
        result = run_remote_powershell(args.relay_host, args.ssh_user, stop_process_script(args.relay_process), args.command_timeout)
    elif action == "pause-primary-host":
        if not args.pause_primary_command.strip():
            raise RuntimeError("--pause-primary-host requires --pause-primary-command")
        result = run_remote_shell(args.primary_host, args.ssh_user, args.pause_primary_command, args.command_timeout)
    else:
        raise RuntimeError(f"unknown fault action {action}")

    add_step(report, "fault_action", result.returncode == 0, result_summary(result), command_data(result))
    if result.returncode != 0:
        raise RuntimeError(f"fault action {action} failed")


def run_post_fault_pings(args: argparse.Namespace, peer: dict[str, Any], report: dict[str, Any]) -> None:
    results: list[dict[str, Any]] = []
    ok_count = 0
    for index in range(max(args.post_ping_count, 0)):
        result = run_wink_ping(args, peer)
        ok = result.returncode == 0
        if ok:
            ok_count += 1
        results.append({"index": index + 1, "ok": ok, **command_data(result)})
        if index + 1 < args.post_ping_count:
            time.sleep(max(args.post_ping_interval, 0))
    add_step(report, "post_fault_pings", ok_count == args.post_ping_count, f"{ok_count}/{args.post_ping_count} ping(s) passed", {"results": results})
    if ok_count != args.post_ping_count:
        raise RuntimeError("one or more post-fault wink ping probes failed")
    post_peer = capture_post_fault_state(args, peer, report)
    validate_failover_requirement(args, peer, post_peer, report)


def capture_post_fault_state(args: argparse.Namespace, pre_peer: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    peers = load_peers(args)
    peer = find_same_peer(peers, pre_peer)
    path_state = peer_path_state(peer)
    report["post_fault_path_state"] = path_state
    add_step(report, "post_fault_path_state", True, "captured runtime path state after fault", {"peer": peer_label(peer), **path_state})
    return peer


def validate_failover_requirement(args: argparse.Namespace, pre_peer: dict[str, Any], post_peer: dict[str, Any], report: dict[str, Any]) -> None:
    if selected_fault_action(args) == "dry-run":
        add_step(report, "failover_requirement", True, "dry-run; failover not required")
        return
    if not args.require_failover:
        add_step(report, "failover_requirement", True, "not required; pass --require-failover to enforce active path movement")
        return

    pre_state = peer_path_state(pre_peer)
    post_state = peer_path_state(post_peer)
    active_changed = post_state["active_path_id"] and post_state["active_path_id"] != pre_state["active_path_id"]
    failover_changed = bool(post_state["last_failover_at"]) and post_state["last_failover_at"] != pre_state["last_failover_at"]
    reason_changed = bool(post_state["last_failover_why"]) and post_state["last_failover_why"] != pre_state["last_failover_why"]
    ok = active_changed or failover_changed or reason_changed
    add_step(
        report,
        "failover_requirement",
        ok,
        "failover evidence found" if ok else "no active path or failover reason changed",
        {
            "active_changed": active_changed,
            "failover_changed": failover_changed,
            "reason_changed": reason_changed,
            "pre": pre_state,
            "post": post_state,
        },
    )
    if not ok:
        raise RuntimeError("post-fault runtime state did not show multipath failover")


def load_peers(args: argparse.Namespace) -> list[dict[str, Any]]:
    command = [args.wink_path, "--config", args.config_path, "--state", args.state_path, "peers", "--json"]
    proc = run_command(command, args.command_timeout)
    raw = proc.stdout.strip() or proc.stderr.strip()
    if proc.returncode != 0:
        raise RuntimeError("wink peers --json failed: " + result_summary(proc))
    if not raw:
        raise RuntimeError("wink peers --json returned no output")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"wink peers --json returned invalid JSON: {exc}") from exc
    if not isinstance(parsed, list):
        raise RuntimeError("wink peers --json did not return a peer list")
    return parsed


def find_multipath_peer(peers: list[dict[str, Any]]) -> dict[str, Any]:
    for peer in peers:
        if str(peer.get("state", "")).lower() != "connected":
            continue
        if str(peer.get("data_state", "")).lower() != "alive":
            continue
        if not bool(peer.get("multipath_enabled")):
            continue
        if not str(peer.get("protected_direct_path_id", "")).strip():
            continue
        return peer
    raise RuntimeError("no connected peer with data_state=alive, multipath_enabled=true, and protected_direct_path_id found")


def find_same_peer(peers: list[dict[str, Any]], target: dict[str, Any]) -> dict[str, Any]:
    for key in ("node_id", "name", "virtual_ip"):
        value = str(target.get(key, "")).strip()
        if not value:
            continue
        for peer in peers:
            if str(peer.get(key, "")).strip() == value:
                return peer
    raise RuntimeError("post-fault peer state not found for " + peer_label(target))


def peer_path_state(peer: dict[str, Any]) -> dict[str, Any]:
    details = peer.get("last_path_details") if isinstance(peer.get("last_path_details"), dict) else {}
    return {
        "primary_path_id": str(peer.get("primary_path_id", "") or ""),
        "protected_direct_path_id": str(peer.get("protected_direct_path_id", "") or ""),
        "active_path_id": str(peer.get("active_path_id", "") or ""),
        "standby_path_ids": peer.get("standby_path_ids", []) if isinstance(peer.get("standby_path_ids"), list) else [],
        "last_failover_at": clean_runtime_time(str(peer.get("last_failover_at", "") or "")),
        "last_failover_why": str(peer.get("last_failover_why", "") or ""),
        "last_path_id": str(peer.get("last_path_id", "") or ""),
        "last_path_role": str(peer.get("last_path_role", "") or ""),
        "last_path_dependencies": peer.get("last_path_dependencies", []) if isinstance(peer.get("last_path_dependencies"), list) else [],
        "child_paths": str(details.get("child_paths", "") or ""),
    }


def clean_runtime_time(value: str) -> str:
    value = value.strip()
    if not value or value.startswith("0001-01-01"):
        return ""
    return value


def run_wink_ping(args: argparse.Namespace, peer: dict[str, Any]) -> subprocess.CompletedProcess[str]:
    target = args.peer_target.strip() or peer_label(peer)
    return run_command([args.wink_path, "--config", args.config_path, "--state", args.state_path, "ping", target], args.command_timeout)


def selected_fault_action(args: argparse.Namespace) -> str:
    if args.stop_coordinator:
        return "stop-coordinator"
    if args.stop_relay:
        return "stop-relay"
    if args.pause_primary_host:
        return "pause-primary-host"
    return "dry-run"


def run_remote_powershell(host: str, user: str, script: str, timeout: int) -> subprocess.CompletedProcess[str]:
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    return run_remote_shell(host, user, "powershell -NoProfile -EncodedCommand " + encoded, timeout)


def run_remote_shell(host: str, user: str, command: str, timeout: int) -> subprocess.CompletedProcess[str]:
    target = host if not user.strip() else f"{user.strip()}@{host}"
    return run_command(["ssh", target, command], timeout)


def stop_process_script(process_name: str) -> str:
    name = process_name.replace("'", "''")
    return f"""
$ProgressPreference='SilentlyContinue'
$ErrorActionPreference='SilentlyContinue'
$procs = @(Get-Process -Name '{name}' -ErrorAction SilentlyContinue)
if ($procs.Count -eq 0) {{
  'process not running: {name}'
}} else {{
  $procs | Stop-Process -Force -ErrorAction SilentlyContinue
  'stopped process count: ' + $procs.Count
}}
"""


def run_command(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)


def add_step(report: dict[str, Any], name: str, ok: bool, detail: str = "", data: dict[str, Any] | None = None) -> None:
    report["steps"].append(Step(name=name, ok=ok, detail=detail, data=data or {}).__dict__)


def command_data(result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    return {
        "returncode": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }


def result_summary(result: subprocess.CompletedProcess[str]) -> str:
    output = result.stdout.strip() or result.stderr.strip()
    if output:
        return output.replace("\n", " ")[:500]
    return f"returncode={result.returncode}"


def peer_label(peer: dict[str, Any]) -> str:
    return str(peer.get("name") or peer.get("node_id") or peer.get("virtual_ip") or "<unknown>")


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


if __name__ == "__main__":
    raise SystemExit(main())
