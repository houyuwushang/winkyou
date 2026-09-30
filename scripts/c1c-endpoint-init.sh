#!/bin/sh
# One-shot private role initialization. Execution requires a later field window.
set -eu
exec /usr/bin/python3 -I -B - "$@" <<'PY'
import hashlib
import json
import os
import stat
import subprocess
import sys

ROOT = "/root/.winkyou-field/c1c"
ROLES = ("initiator", "responder")
IMAGE_LIMIT = 512 * 1024 * 1024
DIRECTORIES = ("var-lib", "home", "home/.ssh", "home/.winkyou-field",
               "home/.winkyou-field/c1c", "home/.winkyou-field/c1c/evidence",
               "home/.winkyou-field/c1c/material", "run", "run/netns", "install", "install/winkyou")
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}
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


def write_all(fd, data):
    while data:
        written = os.write(fd, data)
        if written <= 0:
            raise ValueError("write_failed")
        data = data[written:]


def create_file(path, data, mode, owned):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        info = os.fstat(fd)
        owned.append((path, info.st_dev, info.st_ino, False))
        write_all(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def create_directory(path, owned):
    os.mkdir(path, 0o700)
    info = os.lstat(path)
    owned.append((path, info.st_dev, info.st_ino, True))


def digest_file(path):
    secure(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > IMAGE_LIMIT:
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
        if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, total, after.st_mtime_ns):
            raise ValueError("file_changed")
        return digest.hexdigest()
    finally:
        os.close(fd)


def copy_image(source, target, owned):
    secure(source, executable=True)
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        size = os.fstat(source_fd).st_size
        if size <= 0 or size > IMAGE_LIMIT:
            raise ValueError("unsafe_path")
        target_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
        try:
            info = os.fstat(target_fd)
            owned.append((target, info.st_dev, info.st_ino, False))
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


def remove_failed_copies(root, owned):
    # Only the exact inodes just created by this invocation, in reverse order.
    if not owned or owned[0][0] != root:
        raise ValueError("cleanup_refused")
    for path, device, inode, directory in reversed(owned):
        if path != root and not path.startswith(root + "/"):
            raise ValueError("cleanup_refused")
        info = os.lstat(path)
        if (info.st_dev, info.st_ino) != (device, inode) or stat.S_ISLNK(info.st_mode):
            raise ValueError("cleanup_refused")
        if directory:
            os.rmdir(path)
        else:
            os.unlink(path)


def run_setup(path, owned):
    # Holding all sources avoids losing them when the child's /root is covered.
    secure("/run/netns", directory=True)
    role_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    registry_fd = os.open("/run/netns", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    log_path = path + "/setup.json"
    log_fd = os.open(log_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        result = subprocess.run(["/usr/bin/unshare", "-m", "--propagation", "private",
                                 "/usr/bin/python3", "-I", "-B", "-c", SETUP, str(role_fd), str(registry_fd)],
                                pass_fds=(role_fd, registry_fd), stdin=subprocess.DEVNULL,
                                stdout=log_fd, stderr=subprocess.DEVNULL, env=ENV, timeout=30, check=False)
        os.fsync(log_fd)
        os.lseek(log_fd, 0, os.SEEK_SET)
        payload = os.read(log_fd, 65537)
        status = json.loads(payload)
        if result.returncode != 0 or len(payload) > 65536 or status.get("state") != "ready" or not status.get("ready"):
            raise ValueError("setup_failed")
    finally:
        os.close(log_fd)
        os.close(registry_fd)
        os.close(role_fd)


def initialize(role):
    path = ROOT + "/endpoints/" + role
    if os.path.lexists(path):
        raise ValueError("already_initialized")
    if os.geteuid() != 0:
        raise ValueError("root_required")
    secure(ROOT + "/endpoints", directory=True)
    for executable in ("/usr/bin/python3", "/usr/bin/unshare", "/usr/bin/mount"):
        command(executable)
    source = ROOT + "/bin/wink-field"
    source_hash = digest_file(source)
    owned = []
    create_directory(path, owned)
    for name in DIRECTORIES:
        create_directory(path + "/" + name, owned)
    machine_id = random_machine_id()
    create_file(path + "/machine-id", (machine_id + "\n").encode(), 0o600, owned)
    create_file(path + "/shadow", b"root:x:19000:0:99999:7:::\n", 0o600, owned)
    for name in ("wink", "gate-c-child-wrapper"):
        copy_image(source, path + "/install/winkyou/" + name, owned)
    if any(digest_file(path + "/install/winkyou/" + name) != source_hash for name in ("wink", "gate-c-child-wrapper")) or digest_file(source) != source_hash:
        remove_failed_copies(path, owned)
        raise ValueError("install_hash_mismatch")
    run_setup(path, owned)
    scope = hashlib.sha256(("winkyou-c1c-machine-scope/1\n" + machine_id + "\n/var/lib/winkyou-safety-v2").encode()).hexdigest()
    marker = {"schema": "winkyou-c1c-role-init/1", "role": role, "image_sha256": source_hash}
    create_file(path + "/initialized.json", json.dumps(marker, sort_keys=True, separators=(",", ":")).encode(), 0o600, owned)
    return "C1C_INIT role=" + role + " machine_scope=" + scope[:16]


try:
    os.umask(0o077)
    print(initialize(role_arg(sys.argv[1:])))
except Exception as error:
    allowed = ("already_initialized", "install_hash_mismatch", "arguments_rejected")
    label = str(error) if type(error) is ValueError and str(error) in allowed else "initialization_failed"
    print("C1C_INIT class=" + label)
    sys.exit(65 if label == "already_initialized" else 1)
PY
