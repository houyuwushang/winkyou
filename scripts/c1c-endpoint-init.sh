#!/bin/sh
# Idempotent private role initialization. Execution requires a later field window.
set -eu
exec /usr/bin/python3 -I -B - "$@" <<'PY'
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
IMAGE_LIMIT = 512 * 1024 * 1024
DIRECTORIES = ("var-lib", "home", "home/.ssh", "home/.winkyou-field",
               "home/.winkyou-field/c1c", "home/.winkyou-field/c1c/evidence",
               "home/.winkyou-field/c1c/material", "run", "run/netns", "install", "install/winkyou")
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}
SHADOW = b"root:x:19000:0:99999:7:::\n"
MARKER_SCHEMA = "winkyou-c1c-role-init/1"
MARKER_NAME = "initialized.json"
SETUP = r'''
import os, subprocess, sys
role, registry = map(int, sys.argv[1:])
def bind(source, target):
    subprocess.run(["/usr/bin/mount", "--bind", source, target], check=True,
                   pass_fds=(role, registry), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
base = "/proc/self/fd/" + str(role)
for name, target in (("var-lib", "/var/lib"), ("install", "/usr/libexec"),
                     ("shadow", "/etc/shadow"), ("machine-id", "/etc/machine-id"),
                     ("home", "/root"), ("run", "/run")):
    bind(base + "/" + name, target)
bind("/proc/self/fd/" + str(registry), "/run/netns")
os.close(role)
os.close(registry)
os.execv("/usr/libexec/winkyou/wink", ["wink", "setup-machine-scope", "--json"])
'''


def role_arg(args):
    if len(args) != 1 or args[0] not in ROLES:
        raise ValueError("arguments_rejected")
    return args[0]


def secure(path, directory=False, executable=False):
    current = path
    while True:
        info = os.lstat(current)
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise ValueError("unsafe_path")
        if current != path or directory:
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError("unsafe_path")
        elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or (executable and not info.st_mode & 0o111):
            raise ValueError("unsafe_path")
        if current == "/":
            return
        current = os.path.dirname(current)


def command(path):
    # Fixed system executable symlinks are allowed only through protected trees.
    secure(os.path.dirname(path), directory=True)
    secure(os.path.realpath(path), executable=True)


def secure_directory(path):
    secure(path, directory=True)
    info = os.lstat(path)
    if stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("identity_unsafe")


def secure_file(path, mode=0o600):
    secure(path)
    info = os.lstat(path)
    if stat.S_IMODE(info.st_mode) != mode or info.st_nlink != 1:
        raise ValueError("identity_unsafe")


def write_all(fd, data):
    while data:
        written = os.write(fd, data)
        if written <= 0:
            raise ValueError("write_failed")
        data = data[written:]


def create_file(path, data, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        info = os.fstat(fd)
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != mode or info.st_nlink != 1:
            raise ValueError("identity_unsafe")
        write_all(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def create_directory(path):
    # mkdir is atomic and exclusive for a directory; it never replaces an
    # existing path. The post-create check closes the owner/mode/link boundary.
    os.mkdir(path, 0o700)
    secure_directory(path)


def ensure_directory(path):
    if os.path.lexists(path):
        secure_directory(path)
    else:
        create_directory(path)


def read_file(path, maximum):
    secure_file(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if before.st_size > maximum:
            raise ValueError("identity_unsafe")
        chunks, remaining = [], before.st_size
        while remaining:
            part = os.read(fd, min(65536, remaining))
            if not part:
                raise ValueError("file_changed")
            chunks.append(part)
            remaining -= len(part)
        after = os.fstat(fd)
        if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_ino, len(b"".join(chunks)), after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("file_changed")
        return b"".join(chunks)
    finally:
        os.close(fd)


def digest_file(path):
    secure(path, executable=True)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if before.st_size <= 0 or before.st_size > IMAGE_LIMIT:
            raise ValueError("unsafe_path")
        digest, total = hashlib.sha256(), 0
        while True:
            part = os.read(fd, min(65536, IMAGE_LIMIT + 1 - total))
            if not part:
                break
            total += len(part)
            if total > IMAGE_LIMIT:
                raise ValueError("unsafe_path")
            digest.update(part)
        after = os.fstat(fd)
        if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_ino, total, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("file_changed")
        return digest.hexdigest()
    finally:
        os.close(fd)


def copy_image(source, target, source_hash):
    if os.path.lexists(target):
        secure_file(target, 0o700)
        if digest_file(target) != source_hash:
            raise ValueError("install_hash_mismatch")
        return
    secure(source, executable=True)
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        size = os.fstat(source_fd).st_size
        if size <= 0 or size > IMAGE_LIMIT:
            raise ValueError("unsafe_path")
        target_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
        try:
            info = os.fstat(target_fd)
            if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700 or info.st_nlink != 1:
                raise ValueError("identity_unsafe")
            remaining = size
            while remaining:
                part = os.read(source_fd, min(65536, remaining))
                if not part:
                    raise ValueError("file_changed")
                write_all(target_fd, part)
                remaining -= len(part)
            os.fsync(target_fd)
        finally:
            os.close(target_fd)
    finally:
        os.close(source_fd)
    if digest_file(target) != source_hash:
        raise ValueError("install_hash_mismatch")


def random_machine_id():
    fd = os.open("/dev/urandom", os.O_RDONLY | os.O_NOFOLLOW)
    try:
        if not stat.S_ISCHR(os.fstat(fd).st_mode):
            raise ValueError("random_failed")
        data = b""
        while len(data) < 16:
            part = os.read(fd, 16 - len(data))
            if not part:
                raise ValueError("random_failed")
            data += part
        return data.hex()
    finally:
        os.close(fd)


def parse_setup_output(payload):
    text = payload.decode("utf-8", errors="strict")
    try:
        value = json.loads(text)
        if isinstance(value, dict) and value.get("state") == "ready" and value.get("ready") is True:
            return value
    except (ValueError, UnicodeError):
        pass
    lines = text.splitlines()
    decoder = json.JSONDecoder()
    for index, line in enumerate(lines):
        if not line.lstrip().startswith("{"):
            continue
        candidate = "\n".join(lines[index:]).lstrip()
        try:
            value, _ = decoder.raw_decode(candidate)
        except (ValueError, UnicodeError):
            continue
        if isinstance(value, dict) and value.get("state") == "ready" and value.get("ready") is True:
            return value
    raise ValueError("setup_not_ready")


def setup_output_name(timestamp):
    return "setup-" + timestamp + ".json"


def utc_timestamp():
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + str(time.time_ns())


def marker_state(path, role, source_hash):
    marker_path = path + "/" + MARKER_NAME
    if not os.path.lexists(marker_path):
        return False
    try:
        marker = json.loads(read_file(marker_path, 65536).decode("utf-8"))
    except (ValueError, TypeError, UnicodeError):
        raise ValueError("identity_unsafe")
    if (not isinstance(marker, dict) or set(marker) != {"schema", "role", "image_sha256"}
            or marker.get("schema") != MARKER_SCHEMA or marker.get("role") != role
            or not isinstance(marker.get("image_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", marker["image_sha256"])):
        raise ValueError("identity_unsafe")
    if marker["image_sha256"] != source_hash:
        raise ValueError("image_changed")
    return True


def validate_machine_id(path):
    value = read_file(path, 128)
    if not re.fullmatch(rb"[0-9a-f]{32}\n", value):
        raise ValueError("identity_unsafe")
    return value[:-1].decode("ascii")


def ensure_identity(path, resumed):
    machine_path, shadow_path = path + "/machine-id", path + "/shadow"
    if os.path.lexists(machine_path):
        machine_id = validate_machine_id(machine_path)
    else:
        machine_id = random_machine_id()
        create_file(machine_path, (machine_id + "\n").encode(), 0o600)
    if os.path.lexists(shadow_path):
        secure_file(shadow_path, 0o600)
        if read_file(shadow_path, 4096) != SHADOW:
            raise ValueError("identity_unsafe")
    else:
        create_file(shadow_path, SHADOW, 0o600)
    return machine_id


def run_setup(path):
    secure_directory("/run/netns")
    role_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    registry_fd = os.open("/run/netns", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    log_path = path + "/" + setup_output_name(utc_timestamp())
    log_fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        result = subprocess.run(["/usr/bin/unshare", "-m", "--propagation", "private",
                                 "/usr/bin/python3", "-I", "-B", "-c", SETUP, str(role_fd), str(registry_fd)],
                                pass_fds=(role_fd, registry_fd), stdin=subprocess.DEVNULL,
                                stdout=log_fd, stderr=subprocess.STDOUT, env=ENV, timeout=30, check=False)
        os.fsync(log_fd)
        os.lseek(log_fd, 0, os.SEEK_SET)
        payload = os.read(log_fd, 65537)
        status = parse_setup_output(payload)
        if len(payload) > 65536:
            raise ValueError("setup_output_oversize")
        return status, result.returncode
    finally:
        os.close(log_fd)
        os.close(registry_fd)
        os.close(role_fd)


def initialize(role):
    path = ROOT + "/endpoints/" + role
    if os.geteuid() != 0:
        raise ValueError("root_required")
    secure_directory(ROOT + "/endpoints")
    for executable in ("/usr/bin/python3", "/usr/bin/unshare", "/usr/bin/mount"):
        command(executable)
    source = ROOT + "/bin/wink-field"
    source_hash = digest_file(source)
    resumed = os.path.lexists(path)
    if resumed:
        secure_directory(path)
        if marker_state(path, role, source_hash):
            raise ValueError("already_initialized")
    else:
        create_directory(path)
    machine_id = ensure_identity(path, resumed)
    for name in DIRECTORIES:
        ensure_directory(path + "/" + name)
    for name in ("wink", "gate-c-child-wrapper"):
        copy_image(source, path + "/install/winkyou/" + name, source_hash)
    status, setup_rc = run_setup(path)
    scope = hashlib.sha256(("winkyou-c1c-machine-scope/1\n" + machine_id + "\n/var/lib/winkyou-safety-v2").encode()).hexdigest()
    marker = {"schema": MARKER_SCHEMA, "role": role, "image_sha256": source_hash}
    create_file(path + "/" + MARKER_NAME, json.dumps(marker, sort_keys=True, separators=(",", ":")).encode(), 0o600)
    return "C1C_INIT role=" + role + " machine_scope=" + scope[:16] + " resumed=" + str(resumed).lower() + " setup_rc=" + str(setup_rc)


try:
    os.umask(0o077)
    print(initialize(role_arg(sys.argv[1:])))
except Exception as error:
    allowed = ("already_initialized", "image_changed", "identity_unsafe", "install_hash_mismatch", "arguments_rejected")
    label = str(error) if type(error) is ValueError and str(error) in allowed else "initialization_failed"
    print("C1C_INIT class=" + label)
    sys.exit(65 if label == "already_initialized" else 1)
PY
