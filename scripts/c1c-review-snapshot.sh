#!/bin/sh
# Private raw snapshot only. Never upload this output or paste it in a review.
# No arguments, file writes, user-selected executables, or configuration changes.
set -eu
if [ "$#" -ne 0 ]; then
    printf '%s\n' '{"schema":"winkyou-c1c-review-snapshot/1","ok":false,"class":"arguments_rejected"}'
    exit 64
fi
exec /usr/bin/python3 -I -B - <<'PY'
import json
import os
import stat
import subprocess
import sys

SCHEMA = "winkyou-c1c-review-snapshot/1"
NSENTER = "/usr/bin/nsenter"
PREFIX = [NSENTER, "--net=/proc/1/ns/net", "--mount=/proc/1/ns/mnt", "--"]
COMMANDS = (
    ("namespaces", ["/usr/sbin/ip", "netns", "list"], False),
    ("links", ["/usr/sbin/ip", "-j", "link", "show"], True),
    ("addresses", ["/usr/sbin/ip", "-j", "addr", "show"], True),
    ("routes", ["/usr/sbin/ip", "-j", "route", "show"], True),
    ("rules", ["/usr/sbin/ip", "-j", "rule", "show"], True),
    ("nft", ["/usr/sbin/nft", "-j", "list", "ruleset"], True),
    ("conntrack_max", ["/usr/sbin/sysctl", "-n", "net.netfilter.nf_conntrack_max"], False),
    ("conntrack_count", ["/usr/sbin/sysctl", "-n", "net.netfilter.nf_conntrack_count"], False),
    ("ip_forward", ["/usr/sbin/sysctl", "-n", "net.ipv4.ip_forward"], False),
    ("modules", ["/usr/sbin/lsmod"], False),
    ("registry", ["/usr/bin/find", "/var/run/netns", "-mindepth", "1", "-maxdepth", "1", "-printf", "%f\\n"], False),
    ("ss_udp", ["/usr/bin/ss", "-H", "-nup"], False),
    ("ss_tcp", ["/usr/bin/ss", "-H", "-ntp"], False),
)


def executable(path):
    info = os.stat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or not info.st_mode & 0o111:
        raise ValueError("command_unavailable")


def snapshot():
    if os.geteuid() != 0:
        raise ValueError("root_required")
    executable(NSENTER)
    result = {"schema": SCHEMA, "ok": True, "nonvolatile": {}, "volatile": {}}
    for name, command, decode_json in COMMANDS:
        executable(command[0])
        # All argv are constants. Each observation enters init net + mount;
        # even a reviewer in a private namespace cannot snapshot the wrong host.
        completed = subprocess.run(
            PREFIX + command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, check=True, timeout=10,
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
            encoding="utf-8", errors="strict",
        )
        value = json.loads(completed.stdout) if decode_json else completed.stdout.strip()
        if name == "modules":
            value = sorted(line for line in value.splitlines() if line.split() and (line.split()[0].startswith("nf_") or line.split()[0] == "tun"))
        elif name in ("namespaces", "registry"):
            value = sorted(value.splitlines())
        elif name in ("conntrack_max", "conntrack_count", "ip_forward"):
            value = int(value)
        bucket = "volatile" if name in ("ss_udp", "ss_tcp") else "nonvolatile"
        result[bucket][name] = value
    return result


try:
    result = snapshot()
except Exception:
    # Do not emit partial observations or exception text (which may contain
    # private values). A failed read is unknown/RED, never an empty snapshot.
    print(json.dumps({"schema": SCHEMA, "ok": False, "class": "snapshot_read_failed"}, separators=(",", ":")))
    sys.exit(1)
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
PY
