"""Synthetic-only regression: never run the privileged scripts' entry points."""
import ast
import copy
import hashlib
import io
import json
import posixpath
import stat
import sys
from types import SimpleNamespace


def check(condition, name):
    if not condition:
        raise AssertionError(name)


def definitions(source):
    code = source.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    tree = ast.parse(code)
    nodes = [n for n in tree.body if isinstance(n, (ast.Import, ast.Assign, ast.FunctionDef))]
    scope = {}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "synthetic", "exec"), scope)
    return scope, tree


def snapshot_checks(scope):
    outputs = {
        "namespaces": "synthetic-b\nsynthetic-a\n",
        "links": [{"ifname": "synthetic", "mtu": 1400, "operstate": "UP", "flags": ["UP"], "txqlen": 10,
                   "nested": {"flags": [], "kind": "veth"}}],
        "addresses": [{"addr_info": [{"label": "synthetic", "valid_life_time": 123, "preferred_life_time": 12}]}],
        "routes": [{"dst": "synthetic", "expires": 12, "nested": {"expires": 7, "protocol": "kernel"}}],
        "rules": [{"priority": 12, "flags": ["keep"], "expires": "keep"}],
        "nft": {"nftables": [{"counter": {"packets": 5, "bytes": 40, "name": "synthetic"}, "handle": 3, "flags": ["keep"]}]},
        "conntrack_max": "100", "conntrack_count": "7", "ip_forward": "0",
        "modules": "Module Size Used by\nnf_synthetic 123 4 deps\ntun 456 2 other\nignored 7 1\n",
        "registry": "synthetic-b\nsynthetic-a\n", "ss_udp": "volatile-udp", "ss_tcp": "volatile-tcp",
    }
    calls = []
    def run(argv, **kwargs):
        check(argv[:4] == scope["PREFIX"], "init_namespace_prefix")
        check(kwargs["check"] and kwargs["timeout"] == 10 and kwargs["errors"] == "strict", "bounded_read")
        name = next(name for name, args, _ in scope["COMMANDS"] if argv[4:] == args)
        calls.append(name)
        value = outputs[name]
        return SimpleNamespace(stdout=json.dumps(value) if isinstance(value, (list, dict)) else value)
    fake_os = SimpleNamespace(geteuid=lambda: 0, stat=lambda _: SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0))
    scope["os"] = fake_os
    scope["subprocess"] = SimpleNamespace(run=run, PIPE=-1, DEVNULL=-3)
    actual = scope["snapshot"]()
    stable, volatile = actual["nonvolatile"], actual["volatile"]
    check(len(calls) == 13 and len(stable) == 10 and set(volatile) == {"ss_udp", "ss_tcp", "conntrack_count"}, "snapshot_bucket_regression")
    check(stable["modules"] == ["nf_synthetic", "tun"], "module_names_only")
    check(stable["links"] == [{"ifname": "synthetic", "mtu": 1400, "nested": {"kind": "veth"}}], "link_recursive_dynamic_keys")
    check(stable["addresses"] == [{"addr_info": [{"label": "synthetic"}]}], "address_recursive_lifetimes")
    check(stable["routes"] == [{"dst": "synthetic", "nested": {"protocol": "kernel"}}], "route_expiry_only")
    check(stable["rules"] == outputs["rules"] and stable["nft"] == {"nftables": [{"counter": {"name": "synthetic"}, "handle": 3, "flags": ["keep"]}]}, "category_specific_not_global")
    original = copy.deepcopy(stable)
    outputs["conntrack_count"] = "999"
    outputs["modules"] = "tun 9999 999\nnf_synthetic 0 0\n"
    outputs["links"][0]["flags"] = ["DOWN"]
    outputs["addresses"][0]["addr_info"][0]["valid_life_time"] = 1
    outputs["routes"][0]["expires"] = 1
    outputs["nft"]["nftables"][0]["counter"]["bytes"] = 999
    check(scope["snapshot"]()["nonvolatile"] == original, "dynamic_changes_do_not_diff")
    for category, mutate in (
        ("links", lambda: outputs["links"][0].update(mtu=1300)),
        ("addresses", lambda: outputs["addresses"][0]["addr_info"][0].update(label="changed")),
        ("routes", lambda: outputs["routes"][0].update(dst="changed")),
        ("rules", lambda: outputs["rules"][0].update(priority=13)),
        ("nft", lambda: outputs["nft"]["nftables"][0].update(handle=4)),
    ):
        mutate()
        check(scope["snapshot"]()["nonvolatile"][category] != original[category], "structural_change_detected_" + category)
    fake_os.geteuid = lambda: 1
    try:
        scope["snapshot"]()
        raise AssertionError("non_root_accepted")
    except ValueError:
        pass
    fake_os.geteuid = lambda: 0
    fake_os.stat = lambda _: SimpleNamespace(st_mode=stat.S_IFREG | 0o777, st_uid=0)
    try:
        scope["snapshot"]()
        raise AssertionError("writable_executable_accepted")
    except ValueError:
        pass
    print("PASS snapshot: 13 fixed commands; 10 stable/3 volatile; recursive normalization and structural deltas; root/executable rejection; host calls=0")


class FakeOS:
    O_RDONLY, O_NOFOLLOW, O_DIRECTORY = 0, 1, 2
    path = posixpath
    def __init__(self):
        self.nodes, self.fds, self.opened, self.reads = {}, {}, [], []
        self.uid = 0
        self.race = None
        for path in ("/", "/root", "/root/.winkyou-field", "/root/.winkyou-field/c1c", "/root/.winkyou-field/c1c/evidence", "/root/.winkyou-field/log"):
            self.add(path, stat.S_IFDIR | 0o700)
    def add(self, path, mode=stat.S_IFREG | 0o600, data=b"", nlink=1):
        self.nodes[path] = SimpleNamespace(st_mode=mode, st_uid=0, st_dev=1, st_ino=len(self.nodes)+1, st_size=len(data), st_mtime_ns=1, st_ctime_ns=1, st_nlink=nlink, data=data)
    def geteuid(self):
        return self.uid
    def stat(self, path):
        check(path == "/usr/bin/python3", "only_interpreter_stat")
        return SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)
    def resolve(self, name, parent):
        return posixpath.normpath(posixpath.join(self.fds[parent][0], name)) if parent is not None else posixpath.normpath(name)
    def lstat(self, name, dir_fd=None):
        path = self.resolve(name, dir_fd)
        if path not in self.nodes:
            raise FileNotFoundError()
        return copy.copy(self.nodes[path])
    def open(self, name, flags, dir_fd=None):
        path = self.resolve(name, dir_fd)
        check(flags in (self.O_NOFOLLOW, self.O_NOFOLLOW | self.O_DIRECTORY), "read_only_nofollow_flags")
        if self.race == path:
            self.nodes[path].st_ino += 100
        node = self.nodes[path]
        if stat.S_ISLNK(node.st_mode):
            raise OSError("synthetic_symlink")
        if flags & self.O_DIRECTORY:
            check(stat.S_ISDIR(node.st_mode), "directory_type")
        fd = max(self.fds, default=0)+1
        self.fds[fd] = [path, 0]
        self.opened.append(path)
        return fd
    def fstat(self, fd):
        return copy.copy(self.nodes[self.fds[fd][0]])
    def close(self, fd):
        del self.fds[fd]
    def scandir(self, fd):
        parent = self.fds[fd][0]
        entries = [SimpleNamespace(name=posixpath.basename(path)) for path in self.nodes if path != parent and posixpath.dirname(path) == parent]
        class Entries:
            def __enter__(self): return iter(entries)
            def __exit__(self, *_): return False
        return Entries()
    def read(self, fd, count):
        path, offset = self.fds[fd]
        self.reads.append(path)
        data = self.nodes[path].data[offset:offset+count]
        self.fds[fd][1] += len(data)
        return data


def evidence_checks(scope, tree):
    check({n.names[0].name for n in tree.body if isinstance(n, ast.Import)} == {"hashlib", "json", "os", "stat", "sys"}, "read_only_import_allowlist")
    # No arbitrary import, attribute indirection, process launch, or write call.
    allowed_calls = {
        "ValueError", "FileNotFoundError", "len", "min", "sorted", "format", "print",
        "executable", "same_file", "open_directory", "read_file", "walk", "allowed", "evidence",
        "os.geteuid", "os.stat", "os.lstat", "os.fstat", "os.open", "os.close", "os.read", "os.scandir",
        "stat.S_ISREG", "stat.S_ISDIR", "stat.S_ISLNK", "stat.S_IMODE", "hashlib.sha256",
        "json.dumps", "sys.exit", "relative.startswith", "relative.endswith", "relative.count",
        "ROOT.strip", "ROOT.strip('/').split", "digest.update", "digest.hexdigest",
        "text.extend", "text.decode", "records.append", "os.path.splitext",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = ast.unparse(node.func)
            check(name in allowed_calls, "read_only_call_allowlist_" + name)
    fake = FakeOS()
    root = "/root/.winkyou-field"
    content = b'{"synthetic":true}\r\n'
    fake.add(root+"/c1c/instance.json", data=content)
    fake.add(root+"/c1c/evidence/small.txt", data=b"synthetic\n")
    fake.add(root+"/log/large.log", data=b"x"*(4*1024*1024+1))
    fake.add(root+"/log/exact.log", data=b"x"*(4*1024*1024))
    fake.add(root+"/log/raw.bin", data=b"\xff\x00")
    fake.add(root+"/log/link.json", mode=stat.S_IFLNK | 0o777)
    fake.add(root+"/c1c/evidence/linkdir", mode=stat.S_IFLNK | 0o777)
    for excluded in ("bin", "src", "tmp", "toolchain", "c1c/material", "c1c/other", "other"):
        fake.add(root+"/"+excluded, stat.S_IFDIR | 0o700)
        fake.add(root+"/"+excluded+"/secret.json", data=b"forbidden")
    fake.add(root+"/c1c/private.txt", data=b"forbidden")
    scope["os"] = fake
    result = scope["evidence"]()
    check(result["ok"] and not fake.fds, "success_closes_all_descriptors")
    records = {row["path"]: row for row in result["files"]}
    check(set(records) == {"c1c/instance.json", "c1c/evidence/small.txt", "log/large.log", "log/exact.log", "log/raw.bin", "log/link.json", "c1c/evidence/linkdir"}, "exact_evidence_allowlist")
    row = records["c1c/instance.json"]
    check(row["size"] == len(content) and row["mode"] == "0600" and row["uid"] == 0 and row["sha256"] == hashlib.sha256(content).hexdigest() and row["text"] == content.decode(), "metadata_digest_original_text")
    check("text" not in records["log/large.log"] and "text" in records["log/exact.log"] and "text" not in records["log/raw.bin"], "text_suffix_and_exact_limit")
    check(records["log/link.json"]["class"] == "symlink_skipped" and records["c1c/evidence/linkdir"]["class"] == "symlink_skipped", "symlink_skip")
    check(all("forbidden" != fake.nodes[p].data.decode(errors="replace") for p in fake.reads), "excluded_never_read")
    for mutation in ("non_root", "hardlink", "replaced", "read_error"):
        trial = FakeOS()
        trial.add(root+"/c1c/instance.json", data=content)
        if mutation == "non_root": trial.uid = 1
        if mutation == "hardlink": trial.nodes[root+"/c1c/instance.json"].st_nlink = 2
        if mutation == "replaced": trial.race = root+"/c1c/instance.json"
        if mutation == "read_error":
            def fail(*_): raise OSError("synthetic")
            trial.read = fail
        scope["os"] = trial
        try:
            scope["evidence"]()
            raise AssertionError("unsafe_evidence_accepted_"+mutation)
        except (ValueError, OSError):
            pass
        check(not trial.fds, "error_closes_all_descriptors_"+mutation)
    print("PASS evidence: fixed root/allowlist; metadata/hash/text<=4MiB; symlink/hardlink/replacement/read-error fail-closed; all descriptors drained; real filesystem reads=0")


try:
    request = json.load(sys.stdin)
    scope, tree = definitions(request["source"].replace("\r\n", "\n"))
    if request["mode"] == "snapshot":
        snapshot_checks(scope)
    else:
        evidence_checks(scope, tree)
except Exception as error:
    # Fixed assertion labels only; never publish a host traceback or path.
    print("FAIL " + (str(error) if isinstance(error, AssertionError) else type(error).__name__))
    sys.exit(1)
