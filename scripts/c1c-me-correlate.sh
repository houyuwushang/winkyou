#!/bin/sh
# Read-only, bounded post-run projection. Raw evidence never goes to stdout.
set -eu
exec /usr/bin/python3 -I -B - "$@" <<'PY'
import base64
import json
import os
import re
import stat
import sys

ROOT = "/root/.winkyou-field/c1c/evidence"
ROLES = ("initiator", "responder")
MAX_BYTES = 4 * 1024 * 1024
FIELDS = ("mapping_age_at_hit_ns", "mapping_age_at_winner_ns", "mapping_idle_age_at_winner_ns",
          "hit_to_stop_ns", "stop_to_winner_ns", "winner_to_verify_ns", "stop_to_verify_ns")
CLASSES = frozenset(("success", "cancelled", "expired", "gate_c_request_invalid", "peer_address_not_authorized",
    "ssh_profile_invalid", "ssh_host_identity_rejected", "ssh_transport_unavailable", "ssh_child_terminated",
    "ssh_budget_exceeded", "wireguard_binding_failed", "post_handoff_validation_failed", "session_drain_failed",
    "hard_nat_profile_unsupported", "hard_nat_evidence_insufficient", "hard_nat_evidence_drifted",
    "hard_nat_plan_mismatch", "insufficient_authorized_search_budget", "hard_nat_candidate_exhausted",
    "hard_nat_campaign_rate_limited", "hard_nat_campaign_circuit_open", "hard_nat_packet_rejected",
    "credential_used", "pairing_admission_blocked", "oob_stream_invalid", "oob_presence_timeout",
    "oob_stream_closed", "oob_protocol_violation", "attempt_expired", "resource_budget_exceeded",
    "transport_lease_unavailable", "transport_handoff_failed", "data_plane_challenge_failed", "drain_failed"))
STAGES = frozenset(("preflight", "ssh_spawn", "oob_adopt", "present", "burned", "activated", "handshake",
    "prepare", "sockets", "evidence", "plan", "ready", "fire", "candidates", "selection", "verify",
    "transport_lease", "handoff", "data_plane_challenge", "data_plane_ready", "finish_recorded", "oob_drained", "terminal"))


def attempt(value):
    if not re.fullmatch(r"[A-Za-z0-9_-]{22}", value):
        raise ValueError("arguments_rejected")
    decoded = base64.urlsafe_b64decode(value + "==")
    if len(decoded) != 16 or base64.urlsafe_b64encode(decoded).decode().rstrip("=") != value:
        raise ValueError("arguments_rejected")
    return value


def paths(args):
    if len(args) != 3:
        raise ValueError("arguments_rejected")
    ids = []
    for index, path in enumerate(args):
        if not path.startswith(ROOT + "/") or os.path.normpath(path) != path:
            raise ValueError("arguments_rejected")
        parts = path[len(ROOT) + 1:].split("/")
        value = attempt(parts[0])
        suffix = ["endpoint-" + ROLES[index], value, "endpoint.jsonl"] if index < 2 else ["router", "router.jsonl"]
        if parts[1:] != suffix:
            raise ValueError("arguments_rejected")
        ids.append(value)
    if len(set(ids)) != 1:
        raise ValueError("arguments_rejected")
    return tuple(args)


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("evidence_invalid")
        value[key] = item
    return value


def invalid_constant(_):
    raise ValueError("evidence_invalid")


def rows(path):
    # Component-wise fd-relative opens: no symlink/hardlink escape to material.
    parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.strip("/").split("/")[:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
            info = os.fstat(parent)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError("evidence_invalid")
        fd = os.open(path.rsplit("/", 1)[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_mode & 0o022 or before.st_nlink != 1 or before.st_size > MAX_BYTES:
                raise ValueError("evidence_invalid")
            data = bytearray()
            while len(data) < before.st_size:
                chunk = os.read(fd, min(65536, before.st_size - len(data)))
                if not chunk:
                    raise ValueError("evidence_invalid")
                data.extend(chunk)
            after = os.fstat(fd)
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError("evidence_invalid")
        finally:
            os.close(fd)
    finally:
        os.close(parent)
    result = []
    for line in data.decode("utf-8", errors="strict").splitlines():
        if not line or len(line) > 65536 or len(result) >= 32768:
            raise ValueError("evidence_invalid")
        value = json.loads(line, object_pairs_hook=unique_object, parse_constant=invalid_constant)
        if not isinstance(value, dict):
            raise ValueError("evidence_invalid")
        result.append(value)
    return result


def correlate(endpoints, router):
    # Producer schema: endpoint {result,class,failure_stage,...}; router
    # {observation:{role,tuple_ref,witness_clock_ref,...},local,remote,
    # created_ns,last_ns,observed_ns}. Endpoint has NO authenticated tuple or
    # milestone field today. Router headers/progress at_ns cannot supply it.
    output = []
    for role, events in zip(ROLES, endpoints):
        terminal = next((row for row in events if "result" in row and "class" in row), None)
        observation_count = sum(1 for row in router if isinstance(row.get("observation"), dict) and row["observation"].get("role") == role)
        row = {name: None for name in FIELDS}
        row.update(role=role, authenticated_matches=0, router_observation_count=observation_count,
                   kernel_flow_observation=None, failure_stage=None, terminal_class=None,
                   missing_reason={}, measurement_source={})
        for name in FIELDS + ("kernel_flow_observation",):
            row["missing_reason"][name] = "endpoint_tuple_not_recorded" if name.startswith("mapping_") or name == "kernel_flow_observation" else "endpoint_milestones_not_recorded"
            row["measurement_source"][name] = "unavailable"
        row["missing_reason"]["clock_comparison"] = "clock_not_comparable"
        for output_key, input_key, allowed in (("terminal_class", "class", CLASSES), ("failure_stage", "failure_stage", STAGES)):
            value = terminal.get(input_key) if terminal else None
            if isinstance(value, str) and value in allowed:
                row[output_key] = value
                row["measurement_source"][output_key] = "endpoint_terminal"
            else:
                row["missing_reason"][output_key] = "endpoint_result_missing" if terminal is None else "endpoint_value_unrecognized"
                row["measurement_source"][output_key] = "unavailable"
        output.append(row)
    return {"schema": "winkyou-c1c-me-summary/1", "ok": True, "rows": output}


try:
    os.umask(0o077)
    inputs = paths(sys.argv[1:])
    if os.geteuid() != 0:
        raise ValueError("evidence_invalid")
    interpreter = os.stat("/usr/bin/python3")
    if interpreter.st_uid != 0 or interpreter.st_mode & 0o022 or not stat.S_ISREG(interpreter.st_mode):
        raise ValueError("evidence_invalid")
    result = correlate([rows(inputs[0]), rows(inputs[1])], rows(inputs[2]))
    print("C1C_ME " + json.dumps(result, sort_keys=True, separators=(",", ":")))
except Exception:
    print('C1C_ME {"ok":false,"class":"evidence_invalid"}')
    sys.exit(1)
PY
