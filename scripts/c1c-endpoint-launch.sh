#!/bin/sh
# Foreground only; never create a credential, reset state or retry an attempt.
set -eu
exec /usr/bin/python3 -I -B - "$@" <<'PY'
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time

ROOT = "/root/.winkyou-field/c1c"
ROLES = ("initiator", "responder")
WINK = "/usr/libexec/winkyou/wink"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}
STARTUP_SECONDS = 30.0
CHILD = r'''
import os, subprocess, sys
def execute():
    role_fd, registry_fd, evidence_fd, material_fd, instance_fd, barrier = map(int, sys.argv[1:7])
    attempt, anchor, payload = sys.argv[7:10]
    def bind(source, target, readonly=False):
        subprocess.run(["/usr/bin/mount", "--bind", source, target], check=True,
                       pass_fds=tuple(fd for fd in (role_fd, registry_fd, evidence_fd, material_fd, instance_fd) if fd >= 0),
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        if readonly:
            subprocess.run(["/usr/bin/mount", "-o", "remount,bind,ro", target], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    base = "/proc/self/fd/" + str(role_fd)
    for name, target in (("var-lib", "/var/lib"), ("install", "/usr/libexec"),
                         ("shadow", "/etc/shadow"), ("machine-id", "/etc/machine-id"),
                         ("home", "/root"), ("run", "/run")):
        bind(base + "/" + name, target)
    bind("/proc/self/fd/" + str(registry_fd), "/run/netns")
    evidence_parent = "/root/.winkyou-field/c1c/evidence"
    bind("/proc/self/fd/" + str(evidence_fd), evidence_parent)
    if payload == "run":
        bind("/proc/self/fd/" + str(material_fd), "/root/.winkyou-field/c1c/material/" + attempt, True)
        bind("/proc/self/fd/" + str(instance_fd), "/root/.winkyou-field/c1c/" + attempt + ".json", True)
    for fd in (role_fd, registry_fd, evidence_fd, material_fd, instance_fd):
        if fd >= 0:
            os.close(fd)
    # Do not begin the target exec unless the parent has reserved its witness.
    if os.read(barrier, 1) != b"1":
        return 70
    os.close(barrier)
    args = ["/usr/sbin/ip", "netns", "exec", anchor, "/usr/libexec/winkyou/wink"]
    args += ["version"] if payload == "version" else ["gate-c1c", "run", "--instance", "/root/.winkyou-field/c1c/" + attempt + ".json"]
    os.execv(args[0], args)
try:
    code = execute()
except BaseException:
    code = 70
os._exit(code)
'''


def arguments(args):
    if len(args) not in (3, 5) or args[0] not in ROLES or (len(args) == 5 and args[3:] != ["--payload", "version"]):
        raise ValueError("arguments_rejected")
    role, attempt, anchor = args[:3]
    if not re.fullmatch(r"[A-Za-z0-9_-]{22}", attempt):
        raise ValueError("arguments_rejected")
    raw = base64.urlsafe_b64decode(attempt + "==")
    if len(raw) != 16 or base64.urlsafe_b64encode(raw).decode().rstrip("=") != attempt:
        raise ValueError("arguments_rejected")
    expected = "wyc1c" + hashlib.sha256(("winkyou-c1c-anchor/1\n" + attempt).encode()).hexdigest()[:8] + ("-i" if role == "initiator" else "-r")
    payload = "version" if len(args) == 5 else "run"
    if anchor != expected or (payload == "run" and role != "initiator"):
        raise ValueError("arguments_rejected")
    return role, attempt, anchor, payload


def secure(path, directory=False):
    current = path
    while True:
        info = os.lstat(current)
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise ValueError("unsafe_path")
        if directory or current != path:
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError("unsafe_path")
        elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("unsafe_path")
        if current == "/":
            return
        current = os.path.dirname(current)


def protected_command(path):
    secure(os.path.dirname(path), True)
    resolved = os.path.realpath(path)
    secure(resolved)
    if not os.stat(resolved).st_mode & 0o111:
        raise ValueError("command_unavailable")


def read_fixed(path, maximum):
    secure(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise ValueError("unsafe_path")
        chunks, remaining = [], info.st_size
        while remaining:
            data = os.read(fd, min(65536, remaining))
            if not data:
                raise ValueError("file_changed")
            chunks.append(data)
            remaining -= len(data)
        return b"".join(chunks)
    finally:
        os.close(fd)


def image_hash(path):
    return hashlib.sha256(read_fixed(path, 512 * 1024 * 1024)).hexdigest()


def starttime(payload, pid):
    end, begin = payload.rfind(")"), payload.find(" (")
    if begin < 1 or end <= begin or payload[:begin] != str(pid):
        raise ValueError("witness_failed")
    fields = payload[end + 2:].split()
    if len(fields) < 20 or not fields[19].isdigit():
        raise ValueError("witness_failed")
    return int(fields[19])


def process_witness(pid):
    base = "/proc/" + str(pid)
    with open(base + "/stat", "rb") as source:
        raw = source.read(65537)
    if len(raw) > 65536:
        raise ValueError("witness_failed")
    ticks = starttime(raw.decode("utf-8", errors="strict"), pid)
    # Resolve only the proc executable link, never a caller-selected path.
    fd = os.open(base + "/exe", os.O_RDONLY)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 512 * 1024 * 1024:
            raise ValueError("witness_failed")
        digest, remaining = hashlib.sha256(), info.st_size
        while remaining:
            data = os.read(fd, min(65536, remaining))
            if not data:
                raise ValueError("witness_failed")
            digest.update(data)
            remaining -= len(data)
    finally:
        os.close(fd)
    net, mount = os.stat(base + "/ns/net").st_ino, os.stat(base + "/ns/mnt").st_ino
    with open(base + "/stat", "rb") as source:
        last = source.read(65537)
    if len(last) > 65536 or starttime(last.decode("utf-8", errors="strict"), pid) != ticks:
        raise ValueError("witness_failed")
    return {"pid": pid, "starttime": ticks, "net_ns": net, "mnt_ns": mount, "exe_sha256": digest.hexdigest()}


def exec_witness(child, expected_hash, expected_net, parent_mount):
    until = time.monotonic() + STARTUP_SECONDS
    while child.poll() is None and time.monotonic() < until:
        try:
            witness = process_witness(child.pid)
            if witness["exe_sha256"] == expected_hash and witness["net_ns"] == expected_net and witness["mnt_ns"] != parent_mount:
                return witness
        except (OSError, ValueError, UnicodeError):
            pass
        time.sleep(0.001)
    # A short version process may exit before observation: explicitly fail,
    # never report the interpreter/expected image as an observed running image.
    raise ValueError("exec_witness_unavailable")


def launch(role, attempt, anchor, payload):
    if os.geteuid() != 0 or os.stat("/proc/self/ns/net").st_ino == os.stat("/proc/1/ns/net").st_ino:
        raise ValueError("namespace_rejected")
    for executable in ("/usr/bin/python3", "/usr/bin/unshare", "/usr/bin/mount", "/usr/sbin/ip"):
        protected_command(executable)
    role_root = ROOT + "/endpoints/" + role
    secure(role_root, True)
    marker = json.loads(read_fixed(role_root + "/initialized.json", 4096))
    if set(marker) != {"schema", "role", "image_sha256"} or marker["schema"] != "winkyou-c1c-role-init/1" or marker["role"] != role:
        raise ValueError("role_not_initialized")
    expected_hash = image_hash(role_root + "/install/winkyou/wink")
    if expected_hash != marker["image_sha256"] or image_hash(role_root + "/install/winkyou/gate-c-child-wrapper") != expected_hash:
        raise ValueError("role_not_initialized")
    secure("/run/netns", True)
    anchor_path = "/var/run/netns/" + anchor
    if not os.path.ismount(anchor_path):
        raise ValueError("namespace_rejected")
    expected_net = os.stat(anchor_path).st_ino
    if expected_net == os.stat("/proc/1/ns/net").st_ino:
        raise ValueError("namespace_rejected")
    evidence = ROOT + "/evidence/" + attempt + "/endpoint-" + role
    secure(evidence, True)
    if os.path.lexists(evidence + "/" + attempt):
        raise ValueError("evidence_already_claimed")
    fds = []
    child, gate_write, witness_fd = None, None, None
    try:
        def directory(path):
            secure(path, True)
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            fds.append(fd)
            return fd
        role_fd, registry_fd, evidence_fd = directory(role_root), directory("/run/netns"), directory(evidence)
        material_fd, instance_fd = -1, -1
        if payload == "run":
            material_fd = directory(ROOT + "/material/" + attempt + "/" + role)
            instance = ROOT + "/" + attempt + ".json"
            instance_bytes = read_fixed(instance, 65536)
            instance_fd = os.open(instance, os.O_RDONLY | os.O_NOFOLLOW)
            fds.append(instance_fd)
            local = os.path.join(role_root, "home", ".winkyou-field", "c1c") + "/"
            # The persistent local copy is identical even outside the bind view.
            target = local + attempt + ".json"
            if os.path.lexists(target):
                if read_fixed(target, 65536) != instance_bytes:
                    raise ValueError("instance_copy_mismatch")
            else:
                target_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                try:
                    view = memoryview(instance_bytes)
                    while view:
                        n = os.write(target_fd, view)
                        if n <= 0:
                            raise ValueError("write_failed")
                        view = view[n:]
                    os.fsync(target_fd)
                finally:
                    os.close(target_fd)
            os.mkdir(local + "material/" + attempt, 0o700)
        witness_fd = os.open(evidence + "/launch.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        gate_read, gate_write = os.pipe()
        fds.append(gate_read)
        argv = ["/usr/bin/unshare", "-m", "--propagation", "private", "/usr/bin/python3", "-I", "-B", "-c", CHILD,
                str(role_fd), str(registry_fd), str(evidence_fd), str(material_fd), str(instance_fd), str(gate_read), attempt, anchor, payload]
        child = subprocess.Popen(argv, pass_fds=tuple(fds), env=ENV, stderr=subprocess.DEVNULL)
        os.write(gate_write, b"1")
        os.close(gate_write)
        gate_write = None
        witness = exec_witness(child, expected_hash, expected_net, os.stat("/proc/self/ns/mnt").st_ino)
        line = "C1C_LAUNCH role=" + role + " " + " ".join(key + "=" + str(witness[key]) for key in ("pid", "starttime", "net_ns", "mnt_ns", "exe_sha256"))
        data = (line + "\n").encode()
        if os.write(witness_fd, data) != len(data):
            raise ValueError("witness_failed")
        os.fsync(witness_fd)
        os.write(1, data)
        return child.wait()
    finally:
        if gate_write is not None:
            os.close(gate_write)
        for fd in fds:
            os.close(fd)
        if witness_fd is not None:
            os.close(witness_fd)
        # Never orphan a pipeline or signal a process from this script. Product
        # expiry/drain remains its own contract; containment uses owned-stop.
        if child is not None:
            code = child.wait()
            os.write(1, ("C1C_EXIT role=" + role + " code=" + str(code) + "\n").encode())


try:
    os.umask(0o077)
    code = launch(*arguments(sys.argv[1:]))
    sys.exit(code if 0 <= code <= 255 else 1)
except Exception as error:
    allowed = ("arguments_rejected", "exec_witness_unavailable", "namespace_rejected", "evidence_already_claimed")
    label = str(error) if type(error) is ValueError and str(error) in allowed else "launch_failed"
    print("C1C_LAUNCH class=" + label)
    sys.exit(1)
PY
