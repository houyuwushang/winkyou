#!/bin/sh
# Exact owned process only; no name matching and no signal escalation.
set -eu
exec /usr/bin/python3 -I -B - "$@" <<'PY'
import hashlib
import os
import re
import select
import signal
import stat
import sys
import time

ROLES = ("initiator", "responder")  # No role/name selection capability.
DRAIN_SECONDS = 2.0
POLL_SECONDS = 0.1


def arguments(args):
    if len(args) != 3 or not re.fullmatch(r"[1-9][0-9]{0,9}", args[0]) or not re.fullmatch(r"[1-9][0-9]{0,19}", args[1]) or not re.fullmatch(r"[0-9a-f]{64}", args[2]):
        raise ValueError("arguments_rejected")
    pid, ticks = int(args[0]), int(args[1])
    if pid <= 1 or pid > 2147483647 or ticks > 18446744073709551615:
        raise ValueError("arguments_rejected")
    return pid, ticks, args[2]


def starttime(payload, pid):
    end = payload.rfind(")")
    begin = payload.find(" (")
    if begin < 1 or end <= begin or payload[:begin] != str(pid):
        raise ValueError("identity_mismatch")
    fields = payload[end + 2:].split()
    if len(fields) < 20 or not fields[19].isdigit():
        raise ValueError("identity_mismatch")
    return int(fields[19])


def identity(pid):
    base = "/proc/" + str(pid)
    with open(base + "/stat", "rb") as source:
        first = source.read(65537)
    if len(first) > 65536:
        raise ValueError("identity_mismatch")
    ticks = starttime(first.decode("utf-8", errors="strict"), pid)
    # The proc executable link is special: read only the pinned running image.
    os.readlink(base + "/exe")
    fd = os.open(base + "/exe", os.O_RDONLY)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 512 * 1024 * 1024:
            raise ValueError("identity_mismatch")
        digest, total = hashlib.sha256(), 0
        while total < info.st_size:
            part = os.read(fd, min(65536, info.st_size - total))
            if not part:
                raise ValueError("identity_mismatch")
            total += len(part)
            digest.update(part)
        after = os.fstat(fd)
        if (info.st_size, info.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValueError("identity_mismatch")
    finally:
        os.close(fd)
    with open(base + "/stat", "rb") as source:
        last = source.read(65537)
    if len(last) > 65536 or starttime(last.decode("utf-8", errors="strict"), pid) != ticks:
        raise ValueError("identity_mismatch")
    return ticks, digest.hexdigest()


def stop(pid, ticks, digest):
    if os.geteuid() != 0:
        raise ValueError("identity_mismatch")
    interpreter = os.stat("/usr/bin/python3")
    if interpreter.st_uid != 0 or interpreter.st_mode & 0o022 or not stat.S_ISREG(interpreter.st_mode):
        raise ValueError("identity_mismatch")
    # A pidfd pins the process across identity checking and TERM, never a
    # subsequently reused PID. Unsupported kernels/Python fail closed.
    handle = os.pidfd_open(pid, 0)
    try:
        if identity(pid) != (ticks, digest):
            raise ValueError("identity_mismatch")
        started = time.monotonic()
        signal.pidfd_send_signal(handle, signal.SIGTERM, None, 0)
        poll = select.poll()
        poll.register(handle, select.POLLIN)
        while True:
            remaining = DRAIN_SECONDS - (time.monotonic() - started)
            if remaining <= 0:
                return False, int((time.monotonic() - started) * 1000)
            if poll.poll(max(1, int(min(POLL_SECONDS, remaining) * 1000))):
                return True, int((time.monotonic() - started) * 1000)
    finally:
        os.close(handle)


try:
    os.umask(0o077)
    pid, ticks, digest = arguments(sys.argv[1:])
    exited, elapsed = stop(pid, ticks, digest)
    print("C1C_STOP pid=" + str(pid) + " exited=" + str(exited).lower() + " elapsed_ms=" + str(elapsed))
    sys.exit(0 if exited else 1)
except Exception:
    print("C1C_STOP class=identity_mismatch")
    sys.exit(1)
PY
