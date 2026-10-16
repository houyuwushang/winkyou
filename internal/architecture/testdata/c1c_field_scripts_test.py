"""Offline definitions only: no privileged entry point or host operation."""
import ast
import base64
import copy
import hashlib
import io
import json
import posixpath
import stat
import sys
from types import SimpleNamespace

CHECKS = 0
MUTATIONS = 0


def check(value, label):
    global CHECKS
    CHECKS += 1
    if not value:
        raise AssertionError(label)


def rejected(function, label):
    try:
        function()
    except (ValueError, OSError, UnicodeError):
        check(True, label)
        return
    raise AssertionError(label)


def definitions(source):
    code = source.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    tree = ast.parse(code)
    allowed_imports = {"base64", "hashlib", "json", "os", "posixpath", "re", "select", "signal", "stat", "subprocess", "sys", "time"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            check(all(alias.name in allowed_imports for alias in node.names), "closed_import_set")
        if isinstance(node, ast.ImportFrom):
            raise AssertionError("indirect_import_rejected")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            check(node.func.id not in ("eval", "exec", "__import__", "getattr", "setattr"), "no_dynamic_capability")
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for value in ast.walk(node.value):
                if isinstance(value, ast.Call):
                    check(isinstance(value.func, ast.Name) and value.func.id == "frozenset", "no_global_effect")
    scope = {}
    nodes = [node for node in tree.body if isinstance(node, (ast.Import, ast.Assign, ast.FunctionDef))]
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "synthetic", "exec"), scope)
    return scope, tree


def mount_bind_contract(source, tree, label):
    check("/proc/self/fd/" not in source, label+"_no_fd_mount_source")
    parents = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    bind = next((node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "bind"), None)
    check(bind is not None, label+"_bind_helper")
    identity = next((node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "identity"), None)
    check(identity is not None, label+"_identity_helper")
    bind_nodes = set(ast.walk(bind))
    identity_nodes = set(ast.walk(identity))
    mount_calls = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute) or node.func.attr != "run":
            continue
        owner = node
        while owner not in bind_nodes and owner in parents:
            owner = parents[owner]
        if node.args and isinstance(node.args[0], ast.List) and any(isinstance(item, ast.Constant) and item.value == "/usr/bin/mount" for item in node.args[0].elts):
            mount_calls.append(node)
            check(owner in bind_nodes, label+"_mount_only_in_bind")
    check(len(mount_calls) >= 1, label+"_mount_call_present")
    check(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "fstat" for node in identity_nodes), label+"_pin_fstat")
    check(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "stat" for node in identity_nodes), label+"_target_stat")
    check(any(isinstance(node, ast.Raise) for node in identity_nodes), label+"_identity_failure_raises")
    identity_calls = [node for node in bind_nodes if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "identity"]
    check(len(identity_calls) >= (2 if label == "launch" else 1), label+"_bind_identity_check")


def role_view_order_contract(source, label):
    if label == "init":
        fragments = [
            'bind(role_path + "/var-lib"', 'bind(role_path + "/install"',
            'bind(role_path + "/shadow"', 'bind(role_path + "/machine-id"',
            'bind(registry_path, role_path + "/run/netns"', 'bind(role_path + "/run", "/run"',
            'bind(role_path + "/home", "/root"',
        ]
        recursive = fragments[4:]
    else:
        fragments = [
            'bind(role_path + "/var-lib"', 'bind(role_path + "/install"',
            'bind(role_path + "/shadow"', 'bind(role_path + "/machine-id"',
            'bind(registry_path, role_path + "/run/netns"', 'bind(role_path + "/run", "/run"',
            'bind(evidence_path, evidence_parent',
            'bind(material_path, role_state + "/material/" + attempt',
            'bind(instance_path, role_state + "/" + attempt',
            'bind(role_home, "/root"',
        ]
        recursive = fragments[4:6] + [fragments[-1]]
        material_start = source.index(fragments[7])
        material_end = source.find("\n", material_start)
        instance_start = source.index(fragments[8])
        instance_end = source.find("\n", instance_start)
        check("readonly=True" in source[material_start:material_end], label+"_material_readonly")
        check("readonly=True" in source[instance_start:instance_end], label+"_instance_readonly")
    positions = [source.find(fragment) for fragment in fragments]
    check(all(position >= 0 for position in positions), label+"_bind_targets_present")
    check(positions == sorted(positions), label+"_bind_order")
    for fragment in recursive:
        start = source.index(fragment)
        end = source.find("\n", start)
        check("recursive=True" in source[start:end], label+"_recursive_bind")


def mutation_rejected(source, mutate, label):
    global MUTATIONS
    changed = mutate(source)
    check(changed != source, label+"_changed")
    try:
        tree = ast.parse(changed)
        mount_bind_contract(changed, tree, "launch")
        role_view_order_contract(changed, "launch")
    except AssertionError:
        check(True, label+"_red")
        MUTATIONS += 1
        return
    raise AssertionError(label+"_escaped")


def swap_bind_lines(source, left, right):
    lines = source.splitlines()
    left_index = next(index for index, line in enumerate(lines) if left in line)
    right_index = next(index for index, line in enumerate(lines) if right in line)
    lines[left_index], lines[right_index] = lines[right_index], lines[left_index]
    return "\n".join(lines) + ("\n" if source.endswith("\n") else "")


class FakeFS:
    O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, O_EXCL, O_NOFOLLOW, O_DIRECTORY, O_NONBLOCK = 0, 1, 2, 4, 8, 16, 32, 64
    SEEK_SET = 0

    def __init__(self):
        self.nodes, self.fds, self.calls, self.next_inode, self.next_fd = {}, {}, [], 1, 10
        self.binds, self.covered = {}, set()
        self.path = SimpleNamespace(dirname=posixpath.dirname, join=posixpath.join, realpath=lambda p: p, lexists=lambda p: p in self.nodes,
                                    ismount=lambda p: p in self.mounts, normpath=posixpath.normpath)
        self.mounts, self.uid = set(), 0
        self.add("/", directory=True)
        for command in ("/usr/bin/python3", "/usr/bin/mount", "/usr/bin/unshare", "/usr/sbin/ip"):
            self.add(command, b"command", mode=0o755)
        self.add("/run/netns", directory=True)
        self.add("/dev/urandom", b"r"*16)
        self.nodes["/dev/urandom"].st_mode = stat.S_IFCHR | 0o600

    def add(self, path, data=b"", directory=False, mode=0o700):
        if path != "/" and posixpath.dirname(path) not in self.nodes:
            self.add(posixpath.dirname(path), directory=True)
        self.next_inode += 1
        self.nodes[path] = SimpleNamespace(st_mode=(stat.S_IFDIR if directory else stat.S_IFREG) | mode,
            st_uid=0, st_nlink=1, st_dev=1, st_ino=self.next_inode, st_size=len(data),
            st_mtime_ns=1, st_ctime_ns=1, data=data)

    def geteuid(self): return self.uid
    def lstat(self, path, dir_fd=None):
        path = self.resolve(path, dir_fd)
        if path not in self.nodes: raise FileNotFoundError()
        return copy.copy(self.nodes[path])
    def stat(self, path):
        path = self.resolve(path, None)
        source = self.binds.get(path, path)
        if source not in self.nodes:
            raise FileNotFoundError()
        return copy.copy(self.nodes[source])
    def resolve(self, path, parent):
        return posixpath.join(self.fds[parent][0], path) if parent is not None else path
    def mkdir(self, path, mode):
        self.calls.append(("mkdir", path, mode))
        if path in self.nodes: raise FileExistsError()
        check(posixpath.dirname(path) in self.nodes, "mkdir_parent_exists")
        self.add(path, directory=True, mode=mode)
    def open(self, path, flags, mode=0o600, dir_fd=None):
        path = self.resolve(path, dir_fd)
        self.calls.append(("open", path, flags))
        if flags & self.O_CREAT:
            check(bool(flags & self.O_EXCL), "create_exclusive")
            if path in self.nodes: raise FileExistsError()
            check(posixpath.dirname(path) in self.nodes, "file_parent_exists")
            self.add(path, mode=mode)
        if path not in self.nodes: raise FileNotFoundError()
        if flags & self.O_NOFOLLOW and stat.S_ISLNK(self.nodes[path].st_mode): raise OSError()
        if flags & self.O_DIRECTORY and not stat.S_ISDIR(self.nodes[path].st_mode): raise OSError()
        self.next_fd += 1
        self.fds[self.next_fd] = [path, 0]
        return self.next_fd
    def fstat(self, fd): return self.lstat(self.fds[fd][0])
    def close(self, fd):
        check(fd in self.fds, "owned_fd_closed_once")
        del self.fds[fd]
    def read(self, fd, length):
        path, offset = self.fds[fd]
        result = self.nodes[path].data[offset:offset+length]
        self.fds[fd][1] += len(result)
        return result
    def write(self, fd, data):
        data = bytes(data)
        self.calls.append(("write", fd, data))
        if fd == 1:
            self.calls.append(("stdout", data))
            return len(data)
        path, offset = self.fds[fd]
        old = self.nodes[path].data
        self.nodes[path].data = old[:offset] + data + old[offset+len(data):]
        self.nodes[path].st_size = len(self.nodes[path].data)
        self.fds[fd][1] += len(data)
        return len(data)
    def fsync(self, fd): self.calls.append(("sync", self.fds[fd][0]))
    def lseek(self, fd, offset, whence):
        check(whence == 0, "seek_set_only")
        self.fds[fd][1] = offset
    def rmdir(self, path):
        check(not any(p.startswith(path+"/") for p in self.nodes), "remove_empty_only")
        del self.nodes[path]
        self.calls.append(("rmdir", path))
    def unlink(self, path):
        del self.nodes[path]
        self.calls.append(("unlink", path))
    def pipe(self):
        name = "/pipe-"+str(self.next_fd)
        self.add(name)
        return self.open(name, 0), self.open(name, 1)
    def fd_text(self, path):
        check(path in self.nodes, "fake_open_only")
        return io.BytesIO(self.nodes[path].data)

    def mount(self, argv):
        if argv[1] == "-o":
            check(argv[2] == "remount,bind,ro", "readonly_remount_options")
            check(argv[3] in self.binds, "readonly_target_mounted")
            self.calls.append(("mount", argv))
            return
        check(argv[1] in ("--bind", "--rbind"), "mount_bind_only")
        source, target = argv[2], argv[3]
        if source.startswith("/proc/self/fd/"):
            parts = source.split("/", 4)
            check(len(parts) == 5 and parts[3].isdigit(), "fd_source_shape")
            base = self.fds[int(parts[3])][0]
            source = posixpath.join(base, parts[4])
        source = posixpath.normpath(source)
        if any(source == prefix or source.startswith(prefix + "/") for prefix in self.covered):
            raise OSError("source hidden by prior mount")
        if source not in self.nodes:
            raise OSError("mount source missing")
        target = posixpath.normpath(target)
        if target not in self.nodes:
            raise OSError("mount target missing")
        self.binds[target] = source
        self.covered.add(target)
        self.mounts.add(target)
        self.calls.append(("mount", argv))


def init_checks(scope):
    # The init script is deliberately tested as a pure state machine.  The
    # fake filesystem never invokes the shell entry point or any host command.
    original_os, original_subprocess, original_timestamp = scope["os"], scope["subprocess"], scope["utc_timestamp"]
    ready = scope["parse_setup_output"](b"cobra warning\n{\n  \"state\": \"ready\",\n  \"ready\": true\n}\n")
    check(ready["state"] == "ready" and ready["ready"] is True, "cobra_stderr_json_golden")
    check(scope["parse_setup_output"](b'{"state":"ready","ready":true}\n')["ready"] is True, "setup_compact_json")
    for payload in (b"{\"state\":\"missing\",\"ready\":false}\n", b"", b"{\"state\":\"ready\",\"ready\":false}\n", b"{\"state\":\"missing\"}\n{\"state\":\"ready\",\"ready\":true}\n"):
        rejected(lambda payload=payload: scope["parse_setup_output"](payload), "setup_not_ready_rejected")
    check(scope["setup_output_name"]("20261010T010203Z") == "setup-20261010T010203Z.json", "setup_unique_name")

    # Exercise the real log descriptor direction with fake I/O.  The setup
    # child writes first; run_setup must then seek and read the same file.
    setup_fs = FakeFS()
    setup_path = "/role"
    setup_fs.add(setup_path, directory=True)
    for name in ("var-lib", "install", "run", "home"):
        setup_fs.add(setup_path+"/"+name, directory=True)
    for name in ("shadow", "machine-id"):
        setup_fs.add(setup_path+"/"+name, b"x", mode=0o600)
    setup_payload = b"warning\n{\"state\":\"ready\",\"ready\":true}\n"
    setup_calls = []
    def fake_run(argv, **kwargs):
        setup_calls.append((argv, kwargs))
        setup_fs.write(kwargs["stdout"], setup_payload)
        return SimpleNamespace(returncode=0)
    scope["os"] = setup_fs
    scope["subprocess"] = SimpleNamespace(run=fake_run, STDOUT=-2, DEVNULL=-3)
    scope["utc_timestamp"] = lambda: "20261010T010203Z"
    setup_status, setup_rc = scope["run_setup"](setup_path)
    check(setup_status["ready"] is True and setup_rc == 0, "setup_log_round_trip")
    check(any(call[0] == "open" and call[1].endswith("setup-20261010T010203Z.json") and call[2] & setup_fs.O_RDWR for call in setup_fs.calls), "setup_log_readable")
    check(not setup_fs.fds and len(setup_calls) == 1, "setup_log_fds_closed")
    scope["os"], scope["subprocess"], scope["utc_timestamp"] = original_os, original_subprocess, original_timestamp

    check("remove_failed_copies" not in scope and all(token not in scope["SETUP"] for token in ("os.unlink(", "os.rmdir(", "os.remove(", "shutil")), "init_no_delete_helper")
    for args in ([], ["unknown"], ["initiator", "extra"], ["../responder"]):
        rejected(lambda args=args: scope["role_arg"](args), "init_args_rejected")
    check(scope["role_arg"](["responder"]) == "responder", "init_role")
    check("var-lib/winkyou-safety-v2" not in scope["DIRECTORIES"], "namespace_exclusive_setup")

    original_setup, original_digest, original_random = scope["run_setup"], scope["digest_file"], scope["random_machine_id"]
    root = scope["ROOT"]
    binary = b"synthetic-field"
    machine = b"72" * 16 + b"\n"

    def writes(fs):
        return [call for call in fs.calls if call[0] == "mkdir" or call[0] == "sync" or (call[0] == "open" and call[2] & fs.O_CREAT)]

    def seed(fs, role="initiator", marker=None, setup=b""):
        fs.add(root+"/endpoints", directory=True)
        fs.add(root+"/bin/wink-field", binary, mode=0o700)
        path = root+"/endpoints/"+role
        fs.add(path, directory=True)
        for name in scope["DIRECTORIES"]:
            fs.add(path+"/"+name, directory=True)
        fs.add(path+"/machine-id", machine, mode=0o600)
        fs.add(path+"/shadow", b"root:x:19000:0:99999:7:::\n", mode=0o600)
        for image in ("wink", "gate-c-child-wrapper"):
            fs.add(path+"/install/winkyou/"+image, binary, mode=0o700)
        if setup is not None:
            fs.add(path+"/setup.json", setup, mode=0o600)
        if marker is not None:
            fs.add(path+"/initialized.json", json.dumps(marker, sort_keys=True).encode(), mode=0o600)
        return path

    def fake_setup(fs, setup_calls, rc=0):
        def setup(role_path):
            setup_calls.append(role_path)
            log = role_path+"/"+scope["setup_output_name"]("20261010T010203Z")
            scope["create_file"](log, b"stderr\n{\"state\":\"ready\",\"ready\":true}\n", 0o600)
            return {"state":"ready", "ready":True}, rc
        return setup

    # Fresh initialization creates all owned state, runs setup, and commits the
    # marker last.  A non-zero setup status is retained when JSON says ready.
    for setup_rc in (0, 7):
        fs, setup_calls = FakeFS(), []
        scope["os"], scope["random_machine_id"], scope["run_setup"] = fs, lambda: "72"*16, fake_setup(fs, setup_calls, setup_rc)
        fs.add(root+"/endpoints", directory=True)
        fs.add(root+"/bin/wink-field", binary, mode=0o700)
        result = scope["initialize"]("initiator")
        check("resumed=false" in result and ("setup_rc="+str(setup_rc)) in result, "fresh_setup_status_recorded")
        path = root+"/endpoints/initiator"
        check(setup_calls == [path], "fresh_setup_once")
        check(fs.nodes[path+"/shadow"].data == b"root:x:19000:0:99999:7:::\n", "unlocked_nonpassword_shadow")
        check(fs.nodes[path+"/machine-id"].data == machine, "machine_id_entropy_shape")
        for image in ("wink", "gate-c-child-wrapper"):
            node = fs.nodes[path+"/install/winkyou/"+image]
            check(node.data == binary and stat.S_IMODE(node.st_mode) == 0o700, "exact_independent_images")
        check(fs.calls[-1][0] == "sync" and fs.calls[-1][1].endswith("initialized.json"), "marker_committed_last")
        check(not fs.fds, "init_no_fd_residue")

    # An existing partial role resumes without replacing any durable input.
    fs, setup_calls = FakeFS(), []
    scope["os"], scope["digest_file"], scope["run_setup"] = fs, original_digest, fake_setup(fs, setup_calls)
    path = seed(fs, setup=b"")
    prior_machine, prior_setup = fs.nodes[path+"/machine-id"].data, fs.nodes[path+"/setup.json"].data
    result = scope["initialize"]("initiator")
    check("resumed=true" in result and setup_calls == [path], "partial_resumed")
    check(fs.nodes[path+"/machine-id"].data == prior_machine and fs.nodes[path+"/setup.json"].data == prior_setup, "durable_inputs_unchanged")
    check(path+"/initialized.json" in fs.nodes and path+"/setup-20261010T010203Z.json" in fs.nodes, "resume_new_setup_and_marker")
    before = writes(fs)
    snapshot = {name: (node.data, node.st_mode, node.st_nlink) for name, node in fs.nodes.items()}
    rejected(lambda: scope["initialize"]("initiator"), "marker_idempotent_exit")
    check(writes(fs) == before and snapshot == {name: (node.data, node.st_mode, node.st_nlink) for name, node in fs.nodes.items()}, "marker_idempotent_zero_writes")
    check(not fs.fds, "resume_no_fd_residue")

    # A complete marker with a different source image is never silently reused.
    fs, setup_calls = FakeFS(), []
    scope["os"], scope["run_setup"] = fs, fake_setup(fs, setup_calls)
    source_hash = hashlib.sha256(binary).hexdigest()
    path = seed(fs, marker={"schema":"winkyou-c1c-role-init/1", "role":"initiator", "image_sha256":"a"*64})
    before = writes(fs)
    rejected(lambda: scope["initialize"]("initiator"), "image_change_rejected")
    check(writes(fs) == before and not setup_calls, "image_change_zero_writes")

    fs, setup_calls = FakeFS(), []
    scope["os"], scope["run_setup"] = fs, fake_setup(fs, setup_calls)
    path = seed(fs, marker=["not-a-marker"])
    before = writes(fs)
    rejected(lambda: scope["initialize"]("initiator"), "malformed_marker_rejected")
    check(writes(fs) == before and not setup_calls, "malformed_marker_zero_writes")

    # Existing identity material is validated, never repaired in place.
    for mutate in (lambda node: setattr(node, "st_mode", stat.S_IFREG | 0o644), lambda node: setattr(node, "st_nlink", 2), lambda node: setattr(node, "data", b"7"*31+b"\n")):
        fs, setup_calls = FakeFS(), []
        scope["os"], scope["run_setup"] = fs, fake_setup(fs, setup_calls)
        path = seed(fs)
        node = fs.nodes[path+"/machine-id"]
        mutate(node)
        malformed = node.data
        before = writes(fs)
        rejected(lambda: scope["initialize"]("initiator"), "unsafe_machine_id_rejected")
        check(writes(fs) == before and node.data == malformed, "unsafe_machine_id_unchanged")
        check(not setup_calls, "unsafe_identity_no_setup")

    fs, setup_calls = FakeFS(), []
    scope["os"], scope["run_setup"] = fs, fake_setup(fs, setup_calls)
    path = seed(fs)
    fs.nodes[path+"/shadow"].data = b"root:x:changed\n"
    fs.nodes[path+"/shadow"].st_size = len(fs.nodes[path+"/shadow"].data)
    before = writes(fs)
    rejected(lambda: scope["initialize"]("initiator"), "unsafe_shadow_rejected")
    check(writes(fs) == before and not setup_calls, "unsafe_shadow_unchanged")

    # A pre-existing copied image mismatch is reported, never removed.
    fs, setup_calls = FakeFS(), []
    scope["os"], scope["run_setup"] = fs, fake_setup(fs, setup_calls)
    path = seed(fs)
    fs.nodes[path+"/install/winkyou/wink"].data = b"changed"
    fs.nodes[path+"/install/winkyou/wink"].st_size = len(b"changed")
    before_nodes = set(fs.nodes)
    rejected(lambda: scope["initialize"]("initiator"), "install_hash_mismatch_rejected")
    check(set(fs.nodes) == before_nodes and not setup_calls, "install_mismatch_not_deleted")

    # Setup failure leaves a resumable partial tree and no completion marker.
    fs = FakeFS()
    scope["os"], scope["random_machine_id"] = fs, lambda: "72"*16
    fs.add(root+"/endpoints", directory=True)
    fs.add(root+"/bin/wink-field", binary, mode=0o700)
    def setup_failure(_): raise ValueError("setup_failed")
    scope["run_setup"] = setup_failure
    rejected(lambda: scope["initialize"]("initiator"), "setup_failure_rejected")
    check(root+"/endpoints/initiator" in fs.nodes and root+"/endpoints/initiator/initialized.json" not in fs.nodes, "failed_tree_retained")
    check(not fs.fds, "setup_failure_no_fd_residue")

    # Restore script functions before checking the embedded child and bind order.
    scope["run_setup"], scope["digest_file"], scope["random_machine_id"] = original_setup, original_digest, original_random
    mount_bind_contract(scope["SETUP"], ast.parse(scope["SETUP"]), "init")
    role_view_order_contract(scope["SETUP"], "init")
    fs = FakeFS()
    scope["os"] = fs
    fs.add(root+"/endpoints/initiator", directory=True)
    fs.add("/unsafe", directory=True, mode=0o777)
    rejected(lambda: scope["secure"]("/unsafe", True), "unsafe_parent_rejected")
    fs.add("/link", b"", mode=0o600)
    fs.nodes["/link"].st_mode = stat.S_IFLNK | 0o777
    rejected(lambda: scope["secure"]("/link"), "symlink_rejected")
    mount_fs = FakeFS()
    role_path = "/root/role"
    for path in (role_path, role_path+"/var-lib", role_path+"/install", role_path+"/run", role_path+"/run/netns", role_path+"/home"):
        mount_fs.add(path, directory=True)
    for path in (role_path+"/shadow", role_path+"/machine-id"):
        mount_fs.add(path, b"x")
    for path in ("/var/lib", "/usr/libexec", "/run", "/root"):
        mount_fs.add(path, directory=True)
    for path in ("/etc/shadow", "/etc/machine-id"):
        mount_fs.add(path, b"x")
    for fd, path in zip(range(10, 18), (role_path, role_path+"/var-lib", role_path+"/install", role_path+"/shadow", role_path+"/machine-id", "/run/netns", role_path+"/run", role_path+"/home")):
        mount_fs.fds[fd] = [path, 0]
    commands = []
    class ExecComplete(Exception): pass
    def mount_run(argv, **kwargs):
        if argv[0] == "/usr/bin/mount":
            mount_fs.mount(argv)
        commands.append((argv, kwargs))
    fake_os = SimpleNamespace(close=mount_fs.close, fstat=mount_fs.fstat, stat=mount_fs.stat,
                              execv=lambda *args: (_ for _ in ()).throw(ExecComplete()))
    fake_sub = SimpleNamespace(DEVNULL=-3, run=mount_run)
    env = {"os":fake_os, "subprocess":fake_sub,
           "sys":SimpleNamespace(argv=["child"]+[str(fd) for fd in range(10,18)]+[role_path, "/run/netns"])}
    tree = ast.parse(scope["SETUP"])
    try: exec(compile(ast.Module(body=[n for n in tree.body if not isinstance(n, ast.Import)], type_ignores=[]), "synthetic", "exec"), env)
    except ExecComplete: pass
    check([argv[-1] for argv,_ in commands] == ["/var/lib", "/usr/libexec", "/etc/shadow", "/etc/machine-id", role_path+"/run/netns", "/run", "/root"], "init_bind_order")
    check([argv[1] for argv,_ in commands] == ["--bind", "--bind", "--bind", "--bind", "--rbind", "--rbind", "--rbind"], "init_recursive_bind_order")
    check([options.get("pass_fds") for _,options in commands] == [(11,), (12,), (13,), (14,), (15,), (16,), (17,)], "bind_source_fd_survives_exec")
    check(not mount_fs.fds, "init_child_sources_drained")
    check(all("/proc/self/fd/" not in argv for argv,_ in commands), "init_no_fd_mount_source")


class Clock:
    def __init__(self): self.now = 0.0
    def monotonic(self): return self.now
    def sleep(self, value): self.now += value


def stop_checks(scope):
    good = ["4242", "1234", "a"*64]
    check(scope["arguments"](good) == (4242,1234,"a"*64), "stop_arguments")
    for args in ([], ["1","2","a"*64], ["4242","0","a"*64], ["4242","1234","A"*64], ["4242","1234","a"*64,"extra"]):
        rejected(lambda: scope["arguments"](args), "stop_args_rejected")
    row = "4242 (synthetic ) name) S " + " ".join(["0"]*18+["1234"]+["0"]*10)
    check(scope["starttime"](row,4242) == 1234, "paren_safe_stat_field22")
    rejected(lambda: scope["starttime"](row,4243), "wrong_stat_pid")
    rejected(lambda: scope["starttime"]("4242 (bad) S 0",4242), "short_stat")
    for mode in ("exit", "stall", "mismatch", "unsupported", "signal_error"):
        calls, closed, clock = [], [], Clock()
        def acquire(pid, flags):
            check(pid == 4242 and flags == 0, "pidfd_exact_target")
            if mode == "unsupported": raise OSError()
            return 7
        def term(fd, sig, data, flags):
            check((fd,sig,data,flags) == (7,15,None,0), "term_only")
            calls.append("term")
            if mode == "signal_error": raise ProcessLookupError()
        class Poll:
            def register(self, fd, mask): check((fd,mask) == (7,1), "owned_pidfd_poll")
            def poll(self, timeout):
                check(1 <= timeout <= 100, "poll_interval_bound")
                clock.now += timeout/1000
                return [(7,1)] if mode == "exit" else []
        scope["os"] = SimpleNamespace(geteuid=lambda:0, stat=lambda _:SimpleNamespace(st_uid=0,st_mode=stat.S_IFREG|0o755), pidfd_open=acquire, close=lambda fd:closed.append(fd))
        scope["identity"] = lambda _: (1235,"a"*64) if mode == "mismatch" else (1234,"a"*64)
        scope["signal"] = SimpleNamespace(SIGTERM=15, pidfd_send_signal=term)
        scope["select"] = SimpleNamespace(POLLIN=1, poll=Poll)
        scope["time"] = clock
        if mode in ("exit","stall"):
            exited, elapsed = scope["stop"](4242,1234,"a"*64)
            check(exited == (mode=="exit") and elapsed <= 2001, "bounded_stop_result")
            check(calls == ["term"], "one_signal_no_escalation")
        else:
            rejected(lambda:scope["stop"](4242,1234,"a"*64), "identity_or_kernel_rejection")
            if mode in ("mismatch","unsupported"): check(not calls, "mismatch_zero_signal")
        check(closed == ([] if mode=="unsupported" else [7]), "pidfd_drained")


def witness_contract(source):
    scope, parent = definitions(source)
    child = ast.parse(scope["CHILD"])
    def calls(tree, name):
        return [n for n in ast.walk(tree) if isinstance(n, ast.Call) and ast.unparse(n.func) == name]
    execs = [n for n in ast.walk(child) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr.startswith("exec")]
    check(len(execs) == 1 and ast.unparse(execs[0]) == "os.execve(wink_fd, args, ENV)", "only_pinned_fd_fexecve")
    check("os.execv(" not in scope["CHILD"], "no_path_exec")
    pins = [n for n in calls(child, "os.fstat") if ast.unparse(n.args[0]) == "wink_fd"]
    ready = [n for n in calls(child, "os.write") if ast.unparse(n.args[0]) == "ready_write"]
    gates = [n for n in calls(child, "os.read") if ast.unparse(n.args[0]) == "gate_read"]
    check(len(pins) == len(ready) == len(gates) == 1 and pins[0].lineno < ready[0].lineno < gates[0].lineno < execs[0].lineno, "child_pin_ready_gate_exec_order")
    comparisons = [n for n in ast.walk(child) if isinstance(n, ast.If) and ast.unparse(n.test) == "(info.st_dev, info.st_ino) != (wink_dev, wink_ino)"]
    check(len(comparisons) == 1 and pins[0].lineno < comparisons[0].lineno < ready[0].lineno and any(isinstance(n, ast.Raise) for n in ast.walk(comparisons[0])), "child_pin_identity_rechecked")
    for function in ("exec_witness", "process_witness"):
        node = next(n for n in parent.body if isinstance(n, ast.FunctionDef) and n.name == function)
        check(not any(isinstance(n, ast.Constant) and n.value == "/exe" for n in ast.walk(node)), "no_proc_exe_observer")
    launch = next(n for n in parent.body if isinstance(n, ast.FunctionDef) and n.name == "launch")
    witnesses = calls(launch, "exec_witness")
    releases = [n for n in calls(launch, "os.write") if ast.unparse(n) == "os.write(gate_write, b'1')"]
    emits = [n for n in calls(launch, "os.write") if ast.unparse(n) == "os.write(1, data)"]
    syncs = [n for n in calls(launch, "os.fsync") if ast.unparse(n.args[0]) == "witness_fd"]
    check(len(witnesses) == len(releases) == len(emits) == len(syncs) == 1 and witnesses[0].lineno < syncs[0].lineno < emits[0].lineno < releases[0].lineno, "durable_and_stdout_witness_before_release")


def payload_arguments(scope, ident, name):
    for role, suffix in (("initiator", "-i"), ("responder", "-r")):
        for payload in ("version", "ledger"):
            check(scope["arguments"]([role,ident,name+suffix,"--payload",payload]) == (role,ident,name+suffix,payload), "fixed_payload_both_roles")
        for payload in ("run", "status", "", "ledger --json", "--json"):
            rejected(lambda:scope["arguments"]([role,ident,name+suffix,"--payload",payload]), "unknown_payload_rejected")


def child_payload_checks(scope, ident, name, payload):
    # Execute the embedded child with a mount-aware fake.  It models source
    # path resolution and mount identity without invoking a host operation.
    child_fs, commands, execs = FakeFS(), [], []
    role_root = child_fs.path.normpath(scope["ROOT"]+"/endpoints/initiator")
    evidence = child_fs.path.normpath(scope["ROOT"]+"/evidence/"+ident+"/endpoint-initiator")
    material = child_fs.path.normpath(scope["ROOT"]+"/material/"+ident+"/initiator")
    instance = child_fs.path.normpath(scope["ROOT"]+"/"+ident+".json")
    for item in (role_root, role_root+"/var-lib", role_root+"/install", role_root+"/run", role_root+"/run/netns",
                 role_root+"/home", role_root+"/home/.winkyou-field/c1c", role_root+"/home/.winkyou-field/c1c/evidence",
                 role_root+"/home/.winkyou-field/c1c/material", role_root+"/home/.winkyou-field/c1c/material/"+ident,
                 evidence, material):
        child_fs.add(item, directory=True)
    for item in (role_root+"/shadow", role_root+"/machine-id"):
        child_fs.add(item, b"x")
    child_fs.add(instance, b'{"synthetic":true}')
    child_fs.add(role_root+"/home/.winkyou-field/c1c/"+ident+".json", b'{"synthetic":true}')
    for target in ("/var/lib", "/usr/libexec", "/run", "/root"):
        child_fs.add(target, directory=True)
    for target in ("/etc/shadow", "/etc/machine-id"):
        child_fs.add(target, b"x")
    sources = (role_root, role_root+"/var-lib", role_root+"/install", role_root+"/shadow", role_root+"/machine-id",
               "/run/netns", role_root+"/run", role_root+"/home", evidence, material, instance)
    for fd, path in zip(range(10, 21), sources):
        child_fs.fds[fd] = [path, 0]
    child_fs.add(role_root+"/install/winkyou/wink", b"synthetic-field")
    child_fs.fds[21] = [role_root+"/install/winkyou/wink",0]
    image = child_fs.fstat(21)
    child_fs.add("/ready")
    child_fs.fds[22] = ["/ready", 0]
    child_fs.add("/barrier", b"1")
    child_fs.fds[23] = ["/barrier", 0]
    closed = []
    class ExecComplete(Exception): pass
    def fexecve(fd, argv, environment):
        check(fd==21 and child_fs.fstat(fd).st_ino==image.st_ino and environment==scope["ENV"], "fd_exec_preserves_pin_and_environment")
        check(child_fs.nodes["/ready"].data==b"R", "child_announced_ready")
        execs.append((fd,argv))
        raise ExecComplete()
    def child_run(argv, **kwargs):
        if argv[0] == "/usr/bin/mount":
            if payload != "run":
                check("/material/" not in argv[-1] and not argv[-1].endswith(ident+".json"), "readonly_payload_no_material_or_instance_bind")
            child_fs.mount(argv)
        commands.append((argv,kwargs))
    def child_close(fd):
        closed.append(fd)
        child_fs.fds.pop(fd, None)
    fake_os = SimpleNamespace(close=child_close, fstat=child_fs.fstat, stat=child_fs.stat,
                              read=child_fs.read,write=child_fs.write,execve=fexecve)
    fake_sub = SimpleNamespace(DEVNULL=-3,run=child_run)
    env = {"os":fake_os,"subprocess":fake_sub,"ENV":scope["ENV"],
           "sys":SimpleNamespace(argv=["child"]+[str(-1 if payload != "run" and fd in (19,20) else fd) for fd in range(10,24)]+[str(image.st_dev),str(image.st_ino)]+[ident,name+"-i",payload,role_root,"/run/netns",evidence,material,instance])}
    tree = ast.parse(scope["CHILD"])
    exec(compile(ast.Module(body=[n for n in tree.body if isinstance(n,ast.FunctionDef)], type_ignores=[]),"synthetic","exec"),env)
    try: env["execute"]()
    except ExecComplete: pass
    binds = [argv for argv,_ in commands if argv[1] in ("--bind", "--rbind")]
    expected = ["/var/lib","/usr/libexec","/etc/shadow","/etc/machine-id",
                role_root+"/run/netns","/run",role_root+"/home/.winkyou-field/c1c/evidence"]
    if payload == "run":
        expected += [role_root+"/home/.winkyou-field/c1c/material/"+ident,role_root+"/home/.winkyou-field/c1c/"+ident+".json"]
    expected += ["/root"]
    check([argv[-1] for argv in binds] == expected, "launch_fixed_bind_order")
    options = ["--bind"]*4+["--rbind"]*2+["--bind"]+( ["--bind"]*2 if payload=="run" else [] )+["--rbind"]
    check([argv[1] for argv in binds] == options, "launch_recursive_bind_order")
    check(all(len(kw.get("pass_fds",()))==(11 if payload=="run" else 9) for _,kw in commands), "sources_inherited_by_mount")
    if payload == "run":
        check(len(commands)==12 and execs[0][1][-4:] == ["gate-c1c","run","--instance","/root/.winkyou-field/c1c/"+ident+".json"], "readonly_instance_material_and_exec")
    elif payload == "ledger":
        check(execs[0][1] == ["wink","gate-c1c","ledger","--json"], "ledger_fixed_json_argv")
    else:
        check(execs[0][1] == ["wink","version"], "version_fixed_argv")
    check(len(execs)==1, "one_pinned_payload_exec")
    expected_closed = set(range(10,24))-{21}-(set() if payload=="run" else {19,20})
    check(set(closed)==expected_closed, "only_exec_pin_retained")


def launcher_checks(scope):
    global MUTATIONS
    witness_contract(request["source"])
    mount_bind_contract(scope["CHILD"], ast.parse(scope["CHILD"]), "launch")
    role_view_order_contract(scope["CHILD"], "launch")
    ident = base64.urlsafe_b64encode(b"s"*16).decode().rstrip("=")
    name = "wyc1c"+hashlib.sha256(("winkyou-c1c-anchor/1\n"+ident).encode()).hexdigest()[:8]
    check(scope["arguments"](["initiator",ident,name+"-i"]) == ("initiator",ident,name+"-i","run"), "formal_initiator_only")
    payload_arguments(scope, ident, name)
    for args in (["responder",ident,name+"-r"], ["initiator",ident,"wrong"], ["initiator",ident,name+"-i","extra"], ["initiator","B"*22,name+"-i"], ["initiator",ident,name+"-i","--payload","run"]):
        rejected(lambda:scope["arguments"](args), "launch_args_rejected")
    row = "4242 (x ) y) S " + " ".join(["0"]*18+["1234"])
    check(scope["starttime"](row,4242) == 1234, "launch_stat_field22")
    child = SimpleNamespace(pid=4242,poll=lambda:None)
    seen = []
    def sample(pid):
        seen.append(pid)
        return {"pid":pid,"starttime":1234,"net_ns":90,"mnt_ns":91}
    scope["process_witness"] = sample
    def selected(read, write, error, seconds):
        check((read,write,error,seconds) == ([8],[],[],scope["STARTUP_SECONDS"]), "bounded_ready_select")
        return ([8],[],[])
    scope["select"] = SimpleNamespace(select=selected)
    scope["os"] = SimpleNamespace(read=lambda fd,n:b"R")
    witness = scope["exec_witness"](child,8,"a"*64,55,90,1)
    check(witness["pid"]==4242 and witness["exe_ino"]==55 and witness["exe_sha256"]=="a"*64 and seen==[4242], "one_preexec_witness")
    for signal in (b"",b"X"):
        scope["os"] = SimpleNamespace(read=lambda fd,n:signal)
        rejected(lambda:scope["exec_witness"](child,8,"a"*64,55,90,1), "early_eof_or_bad_ready_rejected")
    scope["os"] = SimpleNamespace(read=lambda fd,n:b"R")
    scope["select"] = SimpleNamespace(select=lambda *args:([],[],[]))
    rejected(lambda:scope["exec_witness"](child,8,"a"*64,55,90,1), "startup_timeout_rejected")
    scope["select"] = SimpleNamespace(select=selected)
    for net,mount in ((1,91),(90,1)):
        scope["process_witness"] = lambda _: {"net_ns":net,"mnt_ns":mount}
        rejected(lambda:scope["exec_witness"](child,8,"a"*64,55,90,1), "wrong_namespace_rejected")
    check(seen==[4242], "no_sampling_without_ready")
    for payload in ("run", "version", "ledger"):
        fs, calls = FakeFS(), []
        scope["os"] = fs
        root = scope["ROOT"]
        role_root = root+"/endpoints/initiator"
        binary = b"synthetic-field"
        digest = hashlib.sha256(binary).hexdigest()
        for item in ("/proc/self/ns/net", "/proc/1/ns/net", "/proc/self/ns/mnt"):
            fs.add(item)
        for item in ("var-lib", "install", "run", "run/netns", "home", "home/.winkyou-field/c1c",
                     "home/.winkyou-field/c1c/material", "home/.winkyou-field/c1c/evidence"):
            fs.add(role_root+"/"+item, directory=True)
        for item in ("shadow", "machine-id"):
            fs.add(role_root+"/"+item, b"x")
        for image in ("wink", "gate-c-child-wrapper"):
            fs.add(role_root+"/install/winkyou/"+image,binary)
        marker = {"schema":"winkyou-c1c-role-init/1","role":"initiator","image_sha256":digest}
        fs.add(role_root+"/initialized.json",json.dumps(marker).encode())
        evidence = root+"/evidence/"+ident+"/endpoint-initiator"
        fs.add(evidence,directory=True)
        anchor = "/var/run/netns/"+name+"-i"
        fs.add(anchor)
        fs.mounts.add(anchor)
        if payload == "run":
            fs.add(root+"/material/"+ident+"/initiator",directory=True)
            fs.add(root+"/"+ident+".json",b'{"synthetic":true}')
        def popen(argv, **kwargs):
            check(argv[:8] == ["/usr/sbin/ip","netns","exec",name+"-i","/usr/bin/unshare","-m","--propagation","private"], "private_mount_prefix")
            check(argv[-8:-5] == [ident,name+"-i",payload], "no_free_command")
            check(len(kwargs["pass_fds"]) == (14 if payload=="run" else 12), "held_sources_exact")
            calls.append(argv)
            return SimpleNamespace(pid=4242,wait=lambda:0)
        scope["subprocess"] = SimpleNamespace(Popen=popen,DEVNULL=-3)
        scope["exec_witness"] = lambda *_: {"pid":4242,"starttime":1234,"net_ns":90,"mnt_ns":91,"exe_sha256":digest,"exe_ino":fs.nodes[role_root+"/install/winkyou/wink"].st_ino}
        check(scope["launch"]("initiator",ident,name+"-i",payload) == 0, "foreground_exit")
        check(len(calls)==1 and not fs.fds, "one_pipeline_no_fd_residue")
        stored = fs.nodes[evidence+"/launch.json"].data
        emitted = [c[1] for c in fs.calls if c[0]=="stdout"]
        check(stored in emitted and stored.startswith(b"C1C_LAUNCH role=initiator"), "same_persistent_and_stdout_witness")
        released = next(i for i,c in enumerate(fs.calls) if c[0]=="write" and c[2]==b"1")
        check(next(i for i,c in enumerate(fs.calls) if c[0]=="stdout" and c[1]==stored) < released, "fake_gate_after_stdout")
        check(any(c[0]=="open" and c[1]==role_root+"/install/winkyou/wink" and c[2]&fs.O_NOFOLLOW for c in fs.calls), "wink_pin_nofollow")
        check(evidence+"/"+ident not in fs.nodes, "product_claim_directory_absent")
        if payload!="run":
            check(not any(c[0]=="open" and ("/material/" in c[1] or c[1]==root+"/"+ident+".json") for c in fs.calls), "readonly_payload_zero_material_or_instance_io")
        prior = len(calls)
        rejected(lambda:scope["launch"]("initiator",ident,name+"-i",payload), "duplicate_launch_rejected")
        check(len(calls)==prior, "duplicate_no_process")
    for payload in ("run", "version", "ledger"):
        child_payload_checks(scope, ident, name, payload)

    source = request["source"]
    for label, changed in (
        ("ledger_third_payload", source.replace('["--payload", "ledger"]))', '["--payload", "ledger"], ["--payload", "status"]))', 1)),
        ("ledger_missing_json", source.replace('["gate-c1c", "ledger", "--json"]', '["gate-c1c", "ledger"]', 1)),
        ("ledger_material_bind", source.replace('if payload == "run":', 'if payload in ("run", "ledger"):', 1)),
    ):
        check(changed != source, label+"_changed")
        changed_scope, _ = definitions(changed)
        try:
            payload_arguments(changed_scope, ident, name)
            child_payload_checks(changed_scope, ident, name, "ledger")
        except AssertionError as failure:
            MUTATIONS += 1
            check(True, label+"_red")
            print("MUTATION "+label+" RED "+str(failure))
        else:
            raise AssertionError(label+"_escaped")
    for label, changed in (
        ("release_before_witness", source.replace('        witness = exec_witness(', '        os.write(gate_write, b"1")\n        witness = exec_witness(',1).replace('        if os.write(gate_write, b"1") != 1:\n            raise ValueError("witness_failed")\n','',1)),
        ("path_exec", source.replace('os.execve(wink_fd, args, ENV)', 'os.execv(args[0], args)',1)),
        ("missing_pin_fstat", source.replace('    info = os.fstat(wink_fd)\n','',1)),
        ("missing_pin_comparison", source.replace('    if (info.st_dev, info.st_ino) != (wink_dev, wink_ino):\n        raise RuntimeError("mount_identity_mismatch")\n','',1)),
        ("proc_exe_hash", source.replace('    base = "/proc/" + str(pid)', '    os.open("/proc/" + str(pid) + "/exe", os.O_RDONLY)\n    base = "/proc/" + str(pid)',1)),
    ):
        check(changed != source, label+"_changed")
        try: witness_contract(changed)
        except AssertionError:
            MUTATIONS += 1
            check(True, label+"_red")
        else: raise AssertionError(label+"_escaped")

    mutation_rejected(scope["CHILD"], lambda source: swap_bind_lines(
        source, 'bind(role_path + "/run", "/run"', 'bind(role_home, "/root"'),
        "mutation_old_home_order")
    mutation_rejected(scope["CHILD"], lambda source: source.replace(
        'bind(role_path + "/run", "/run", run, recursive=True)',
        'bind(role_path + "/run", "/run", run, recursive=False)', 1),
        "mutation_run_nonrecursive")
    mutation_rejected(scope["CHILD"], lambda source: swap_bind_lines(
        source, 'bind(registry_path, role_path + "/run/netns"', 'bind(role_path + "/run", "/run"'),
        "mutation_registry_after_run")
    mutation_rejected(scope["CHILD"], lambda source: source.replace(
        "        identity(pin, target)\n", "", 1), "mutation_identity_removed")
    mutation_rejected(scope["CHILD"], lambda source: source.replace(
        'bind(material_path, role_state + "/material/" + attempt, material_fd, readonly=True)',
        'bind(material_path, role_state + "/material/" + attempt, material_fd)', 1),
        "mutation_material_writable")


def correlate_checks(scope):
    ident = base64.urlsafe_b64encode(b"s"*16).decode().rstrip("=")
    root = scope["ROOT"]+"/"+ident
    paths = [root+"/endpoint-"+role+"/"+ident+"/endpoint.jsonl" for role in scope["ROLES"]]+[root+"/router/router.jsonl"]
    scope["os"] = SimpleNamespace(path=posixpath)
    check(scope["paths"](paths)==tuple(paths), "fixed_same_attempt_paths")
    for change in (paths[:2], [paths[1],paths[0],paths[2]], [paths[0]+"/../endpoint.jsonl",*paths[1:]], [paths[0].replace(ident,"A"*22),*paths[1:]]):
        rejected(lambda:scope["paths"](change), "correlation_path_rejected")
    rejected(lambda:scope["attempt"]("B"*22), "canonical_base64_only")
    rejected(lambda:scope["unique_object"]([("x",1),("x",2)]), "duplicate_json_key")
    endpoints = [[{"stage":"verify","at_ns":123}, {"result":{},"class":"success","failure_stage":"terminal","private":"redacted-token"}],
                 [{"result":{},"class":"attempt_expired","failure_stage":"candidates"}]]
    router = [{"observation":{"role":"initiator","tuple_ref":"redacted-token","witness_clock_ref":"router-monotonic/1","kernel_flow_observation":"present"},
               "local":"redacted-local","remote":"redacted-remote","created_ns":1,"last_ns":20,"observed_ns":30}]
    result = scope["correlate"](endpoints,router)
    fixture = json.loads(request["golden"])
    actual_golden = scope["correlate"]([fixture["initiator"],fixture["responder"]], fixture["router"])
    check(json.dumps(actual_golden,sort_keys=True,separators=(",",":")) == json.dumps(fixture["output"],sort_keys=True,separators=(",",":")), "producer_shape_json_golden")
    for index,row in enumerate(result["rows"]):
        check(all(row[name] is None for name in scope["FIELDS"]), "no_fabricated_durations")
        check(row["authenticated_matches"]==0 and row["kernel_flow_observation"] is None, "sampling_hint_not_authenticated_hit")
        check(row["terminal_class"] == ("success" if index==0 else "attempt_expired"), "terminal_projection")
        check(row["missing_reason"]["clock_comparison"]=="clock_not_comparable", "no_cross_clock_subtraction")
    check("redacted" not in json.dumps(result), "no_tuple_address_or_private_text")
    for row in scope["correlate"]([[],[{"result":{},"class":"arbitrary-private-label","failure_stage":"arbitrary"}]],[]) ["rows"]:
        check(row["terminal_class"] is None and row["failure_stage"] is None, "missing_unknown_values_redacted")
    fs = FakeFS()
    scope["os"] = fs
    encoded = (json.dumps(endpoints[0][0])+"\r\n").encode()
    fs.add(paths[0],encoded,mode=0o600)
    check(scope["rows"](paths[0]) == [endpoints[0][0]] and not fs.fds, "bounded_nofollow_read_crlf")
    for mode in ("symlink","hardlink","oversize","bad_utf8","duplicate","nan"):
        node = fs.nodes[paths[0]]
        saved = copy.copy(node)
        if mode=="symlink": node.st_mode=stat.S_IFLNK|0o777
        if mode=="hardlink": node.st_nlink=2
        if mode=="oversize": node.st_size=scope["MAX_BYTES"]+1
        if mode=="bad_utf8": node.data=b"\xff\n";node.st_size=2
        if mode=="duplicate": node.data=b'{"x":1,"x":2}\n';node.st_size=len(node.data)
        if mode=="nan": node.data=b'{"x":NaN}\n';node.st_size=len(node.data)
        rejected(lambda:scope["rows"](paths[0]),"unsafe_evidence_rejected")
        check(not fs.fds,"correlator_error_fd_drain")
        fs.nodes[paths[0]]=saved


try:
    request = json.load(sys.stdin)
    scope, tree = definitions(request["source"])
    checks = {"endpoint-init":init_checks,"endpoint-launch":launcher_checks,"owned-stop":stop_checks,"me-correlate":correlate_checks}
    checks[request["mode"]](scope)
    print("PASS "+request["mode"]+" assertions="+str(CHECKS)+" mutations="+str(MUTATIONS)+" host_calls=0 entrypoint_calls=0")
except Exception as error:
    print("FAIL "+(str(error) if isinstance(error,AssertionError) else type(error).__name__))
    sys.exit(1)
