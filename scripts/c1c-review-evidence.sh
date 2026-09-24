#!/bin/sh
# Private raw evidence only. Never upload this output or paste it in a review.
# Fixed root, no arguments, no external commands, no writes, no symlink following.
set -eu
if [ "$#" -ne 0 ]; then
    printf '%s\n' '{"schema":"winkyou-c1c-review-evidence/1","ok":false,"class":"arguments_rejected"}'
    exit 64
fi
exec /usr/bin/python3 -I -B - <<'PY'
import hashlib
import json
import os
import stat
import sys

SCHEMA = "winkyou-c1c-review-evidence/1"
ROOT = "/root/.winkyou-field/"
TEXT_LIMIT = 4 * 1024 * 1024
TEXT_SUFFIXES = (".json", ".jsonl", ".log", ".txt")
EXCLUDED = ("c1c/material", "bin", "toolchain", "src", "tmp")


def executable(path):
    info = os.stat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or not info.st_mode & 0o111:
        raise ValueError("command_unavailable")


def same_file(before, after):
    return (before.st_dev, before.st_ino, before.st_mode, before.st_uid,
            before.st_nlink, before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (
            after.st_dev, after.st_ino, after.st_mode, after.st_uid,
            after.st_nlink, after.st_size, after.st_mtime_ns, after.st_ctime_ns)


def open_directory(parent, name, info):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY, dir_fd=parent)
    try:
        current = os.fstat(fd)
        if not stat.S_ISDIR(current.st_mode) or current.st_uid != 0 or current.st_mode & 0o022 or not same_file(info, current):
            raise ValueError("directory_changed")
        return fd
    except Exception:
        os.close(fd)
        raise


def read_file(parent, name, relative, info):
    # Reject aliases into excluded material. Never read a moving log indefinitely.
    if info.st_nlink != 1:
        raise ValueError("hardlink_rejected")
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        if not same_file(info, os.fstat(fd)):
            raise ValueError("file_changed")
        digest = hashlib.sha256()
        include_text = os.path.splitext(name)[1] in TEXT_SUFFIXES and info.st_size <= TEXT_LIMIT
        text = bytearray()
        remaining = info.st_size
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                raise ValueError("file_changed")
            digest.update(chunk)
            if include_text:
                text.extend(chunk)
            remaining -= len(chunk)
        if not same_file(info, os.fstat(fd)):
            raise ValueError("file_changed")
        record = {"path": relative, "size": info.st_size, "mode": format(stat.S_IMODE(info.st_mode), "04o"),
                  "uid": info.st_uid, "sha256": digest.hexdigest()}
        if include_text:
            record["text"] = text.decode("utf-8", errors="strict")
        return record
    finally:
        os.close(fd)


def allowed(relative, directory):
    for excluded in EXCLUDED:
        if relative == excluded or relative.startswith(excluded + "/"):
            return False
    if relative == "c1c" or relative == "log":
        return directory
    if relative == "c1c/evidence" or relative.startswith("c1c/evidence/") or relative.startswith("log/"):
        return True
    return not directory and relative.startswith("c1c/") and relative.count("/") == 1 and relative.endswith(".json")


def walk(parent, prefix, records):
    with os.scandir(parent) as entries:
        names = sorted(entry.name for entry in entries)
    for name in names:
        relative = prefix + "/" + name if prefix else name
        # Check the allowlist before inspecting excluded entries, even symlinks.
        if not allowed(relative, True) and not allowed(relative, False):
            continue
        info = os.lstat(name, dir_fd=parent)
        if stat.S_ISLNK(info.st_mode):
            records.append({"path": relative, "class": "symlink_skipped"})
        elif stat.S_ISDIR(info.st_mode) and allowed(relative, True):
            child = open_directory(parent, name, info)
            try:
                walk(child, relative, records)
            finally:
                os.close(child)
        elif stat.S_ISREG(info.st_mode) and allowed(relative, False):
            records.append(read_file(parent, name, relative, info))
        else:
            raise ValueError("file_type_rejected")


def evidence():
    if os.geteuid() != 0:
        raise ValueError("root_required")
    executable("/usr/bin/python3")
    # Resolve the fixed root component by component, without following even an
    # ancestor symlink. Every descendant is opened relative to a held directory.
    parent = os.open("/", os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY)
    try:
        for name in ROOT.strip("/").split("/"):
            info = os.lstat(name, dir_fd=parent)
            child = open_directory(parent, name, info)
            os.close(parent)
            parent = child
        records = []
        walk(parent, "", records)
        return {"schema": SCHEMA, "ok": True, "files": records}
    finally:
        os.close(parent)


try:
    result = evidence()
except Exception:
    # No partial evidence, private exception text or traceback on a failed read.
    print(json.dumps({"schema": SCHEMA, "ok": False, "class": "evidence_read_failed"}, separators=(",", ":")))
    sys.exit(1)
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
PY
