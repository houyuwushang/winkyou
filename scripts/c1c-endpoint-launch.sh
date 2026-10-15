#!/bin/sh
# Foreground only; never create a credential, reset state or retry an attempt.
set -eu
exec /usr/bin/python3 -I -B - "$@" <<'PY'
import base64
import hashlib
import json
import os
import re
import select
import stat
import subprocess
import sys

ROOT = "/root/.winkyou-field/c1c"
ROLES = ("initiator", "responder")
WINK = "/usr/libexec/winkyou/wink"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}
STARTUP_SECONDS = 30.0
CHILD = r'''
import os, subprocess, sys
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}
def execute():
    role_fd, var_lib, install, shadow, machine_id, registry_fd, run, home, evidence_fd, material_fd, instance_fd, wink_fd, ready_write, gate_read = map(int, sys.argv[1:15])
    wink_dev, wink_ino = map(int, sys.argv[15:17])
    attempt, anchor, payload = sys.argv[17:20]
    role_path, registry_path, evidence_path, material_path, instance_path = sys.argv[20:25]
    pins = tuple(fd for fd in (role_fd, var_lib, install, shadow, machine_id, registry_fd, run, home, evidence_fd, material_fd, instance_fd) if fd >= 0)

    def identity(pin, target):
        expected, actual = os.fstat(pin), os.stat(target)
        if (expected.st_dev, expected.st_ino) != (actual.st_dev, actual.st_ino):
            raise RuntimeError("mount_identity_mismatch")

    def bind(source, target, pin, recursive=False, readonly=False):
        option = "--rbind" if recursive else "--bind"
        subprocess.run(["/usr/bin/mount", option, source, target], check=True,
                       pass_fds=pins, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        identity(pin, target)
        if readonly:
            subprocess.run(["/usr/bin/mount", "-o", "remount,bind,ro", target], check=True,
                           pass_fds=pins, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            identity(pin, target)
    bind(role_path + "/var-lib", "/var/lib", var_lib)
    bind(role_path + "/install", "/usr/libexec", install)
    bind(role_path + "/shadow", "/etc/shadow", shadow)
    bind(role_path + "/machine-id", "/etc/machine-id", machine_id)
    bind(registry_path, role_path + "/run/netns", registry_fd, recursive=True)
    bind(role_path + "/run", "/run", run, recursive=True)
    role_home = role_path + "/home"
    role_state = role_home + "/.winkyou-field/c1c"
    evidence_parent = role_state + "/evidence"
    bind(evidence_path, evidence_parent, evidence_fd)
    if payload == "run":
        bind(material_path, role_state + "/material/" + attempt, material_fd, readonly=True)
        bind(instance_path, role_state + "/" + attempt + ".json", instance_fd, readonly=True)
    bind(role_home, "/root", home, recursive=True)
    for fd in (role_fd, var_lib, install, shadow, machine_id, registry_fd, run, home, evidence_fd, material_fd, instance_fd):
        if fd >= 0:
            os.close(fd)
    info = os.fstat(wink_fd)
    if (info.st_dev, info.st_ino) != (wink_dev, wink_ino):
        raise RuntimeError("mount_identity_mismatch")
    if os.write(ready_write, b"R") != 1:
        os._exit(70)
    os.close(ready_write)
    if os.read(gate_read, 1) != b"1":
        os._exit(70)
    os.close(gate_read)
    args = ["wink"]
    args += ["version"] if payload == "version" else ["gate-c1c", "run", "--instance", "/root/.winkyou-field/c1c/" + attempt + ".json"]
    # CPython's fd form calls fexecve; no pathname is resolved after the gate.
    os.execve(wink_fd, args, ENV)
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


def pinned_image_hash(fd):
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1 or info.st_size > 512 * 1024 * 1024:
        raise ValueError("unsafe_path")
    digest, remaining = hashlib.sha256(), info.st_size
    while remaining:
        data = os.read(fd, min(65536, remaining))
        if not data:
            raise ValueError("file_changed")
        digest.update(data)
        remaining -= len(data)
    return digest.hexdigest(), info


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
    net, mount = os.stat(base + "/ns/net").st_ino, os.stat(base + "/ns/mnt").st_ino
    return {"pid": pid, "starttime": ticks, "net_ns": net, "mnt_ns": mount}


def exec_witness(child, ready_read, expected_hash, wink_ino, expected_net, parent_mount):
    try:
        readable, _, _ = select.select([ready_read], [], [], STARTUP_SECONDS)
        if not readable or os.read(ready_read, 1) != b"R":
            raise ValueError("exec_witness_unavailable")
        witness = process_witness(child.pid)
        if witness["net_ns"] != expected_net or witness["mnt_ns"] == parent_mount:
            raise ValueError("exec_witness_unavailable")
        witness.update(exe_sha256=expected_hash, exe_ino=wink_ino)
        return witness
    except (OSError, ValueError, UnicodeError):
        raise ValueError("exec_witness_unavailable") from None


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
    child, ready_read, gate_write, witness_fd = None, None, None, None
    try:
        def source(path, directory):
            secure(path, directory)
            flags = os.O_RDONLY | os.O_NOFOLLOW
            if directory:
                flags |= os.O_DIRECTORY
            fd = os.open(path, flags)
            fds.append(fd)
            return fd
        role_fd = source(role_root, True)
        var_lib_fd = source(role_root + "/var-lib", True)
        install_fd = source(role_root + "/install", True)
        shadow_fd = source(role_root + "/shadow", False)
        machine_id_fd = source(role_root + "/machine-id", False)
        registry_fd = source("/run/netns", True)
        run_fd = source(role_root + "/run", True)
        home_fd = source(role_root + "/home", True)
        evidence_fd = source(evidence, True)
        wink_fd = source(role_root + "/install/winkyou/wink", False)
        expected_hash, wink_info = pinned_image_hash(wink_fd)
        if expected_hash != marker["image_sha256"] or image_hash(role_root + "/install/winkyou/gate-c-child-wrapper") != expected_hash:
            raise ValueError("role_not_initialized")
        material_fd, instance_fd = -1, -1
        material_path, instance_path = "", ""
        if payload == "run":
            material_path = ROOT + "/material/" + attempt + "/" + role
            material_fd = source(material_path, True)
            instance_path = ROOT + "/" + attempt + ".json"
            instance_bytes = read_fixed(instance_path, 65536)
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
            instance_fd = source(instance_path, False)
        witness_fd = os.open(evidence + "/launch.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        gate_read, gate_write = os.pipe()
        fds.append(gate_read)
        ready_read, ready_write = os.pipe()
        fds.append(ready_write)
        argv = ["/usr/sbin/ip", "netns", "exec", anchor, "/usr/bin/unshare", "-m", "--propagation", "private", "/usr/bin/python3", "-I", "-B", "-c", CHILD,
                str(role_fd), str(var_lib_fd), str(install_fd), str(shadow_fd), str(machine_id_fd), str(registry_fd),
                str(run_fd), str(home_fd), str(evidence_fd), str(material_fd), str(instance_fd), str(wink_fd), str(ready_write), str(gate_read),
                str(wink_info.st_dev), str(wink_info.st_ino),
                attempt, anchor, payload, role_root, "/run/netns", evidence, material_path, instance_path]
        child = subprocess.Popen(argv, pass_fds=tuple(fds), env=ENV, stderr=subprocess.DEVNULL)
        for fd in (ready_write, gate_read):
            os.close(fd)
            fds.remove(fd)
        witness = exec_witness(child, ready_read, expected_hash, wink_info.st_ino, expected_net, os.stat("/proc/self/ns/mnt").st_ino)
        line = "C1C_LAUNCH role=" + role + " " + " ".join(key + "=" + str(witness[key]) for key in ("pid", "starttime", "net_ns", "mnt_ns", "exe_sha256", "exe_ino"))
        data = (line + "\n").encode()
        if os.write(witness_fd, data) != len(data):
            raise ValueError("witness_failed")
        os.fsync(witness_fd)
        os.write(1, data)
        if os.write(gate_write, b"1") != 1:
            raise ValueError("witness_failed")
        os.close(gate_write)
        gate_write = None
        return child.wait()
    finally:
        if ready_read is not None:
            os.close(ready_read)
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
