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


class FakeFS:
    O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, O_EXCL, O_NOFOLLOW, O_DIRECTORY, O_NONBLOCK = 0, 1, 2, 4, 8, 16, 32, 64
    SEEK_SET = 0

    def __init__(self):
        self.nodes, self.fds, self.calls, self.next_inode, self.next_fd = {}, {}, [], 1, 10
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
    def stat(self, path): return self.lstat(path)
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


def init_checks(scope):
    # The init script is deliberately tested as a pure state machine.  The
    # fake filesystem never invokes the shell entry point or any host command.
    ready = scope["parse_setup_output"](b"cobra warning\n{\n  \"state\": \"ready\",\n  \"ready\": true\n}\n")
    check(ready["state"] == "ready" and ready["ready"] is True, "cobra_stderr_json_golden")
    check(scope["parse_setup_output"](b'{"state":"ready","ready":true}\n')["ready"] is True, "setup_compact_json")
    for payload in (b"{\"state\":\"missing\",\"ready\":false}\n", b"", b"{\"state\":\"ready\",\"ready\":false}\n"):
        rejected(lambda payload=payload: scope["parse_setup_output"](payload), "setup_not_ready_rejected")
    check(scope["setup_output_name"]("20261010T010203Z") == "setup-20261010T010203Z.json", "setup_unique_name")
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
    fs = FakeFS()
    scope["os"] = fs
    fs.add(root+"/endpoints/initiator", directory=True)
    fs.add("/unsafe", directory=True, mode=0o777)
    rejected(lambda: scope["secure"]("/unsafe", True), "unsafe_parent_rejected")
    fs.add("/link", b"", mode=0o600)
    fs.nodes["/link"].st_mode = stat.S_IFLNK | 0o777
    rejected(lambda: scope["secure"]("/link"), "symlink_rejected")
    commands = []
    class ExecComplete(Exception): pass
    fake_os = SimpleNamespace(close=lambda _: None, execv=lambda *args: (_ for _ in ()).throw(ExecComplete()))
    fake_sub = SimpleNamespace(DEVNULL=-3, run=lambda argv, **kwargs: commands.append((argv, kwargs)))
    env = {"os":fake_os, "subprocess":fake_sub, "sys":SimpleNamespace(argv=["child", "10", "11"])}
    tree = ast.parse(scope["SETUP"])
    try: exec(compile(ast.Module(body=[n for n in tree.body if not isinstance(n, ast.Import)], type_ignores=[]), "synthetic", "exec"), env)
    except ExecComplete: pass
    check([argv[-1] for argv,_ in commands] == ["/var/lib", "/usr/libexec", "/etc/shadow", "/etc/machine-id", "/root", "/run", "/run/netns"], "init_bind_order")
    check(all(options.get("pass_fds") == (10,11) for _,options in commands), "bind_source_fd_survives_exec")


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


def launcher_checks(scope):
    ident = base64.urlsafe_b64encode(b"s"*16).decode().rstrip("=")
    name = "wyc1c"+hashlib.sha256(("winkyou-c1c-anchor/1\n"+ident).encode()).hexdigest()[:8]
    check(scope["arguments"](["initiator",ident,name+"-i"]) == ("initiator",ident,name+"-i","run"), "formal_initiator_only")
    check(scope["arguments"](["responder",ident,name+"-r","--payload","version"])[3] == "version", "responder_version_only")
    for args in (["responder",ident,name+"-r"], ["initiator",ident,"wrong"], ["initiator",ident,name+"-i","extra"], ["initiator","B"*22,name+"-i"], ["initiator",ident,name+"-i","--payload","run"]):
        rejected(lambda:scope["arguments"](args), "launch_args_rejected")
    row = "4242 (x ) y) S " + " ".join(["0"]*18+["1234"])
    check(scope["starttime"](row,4242) == 1234, "launch_stat_field22")
    clock = Clock()
    scope["time"] = clock
    child = SimpleNamespace(pid=4242,poll=lambda:None)
    seen = []
    def sample(pid):
        seen.append(pid)
        return {"pid":pid,"starttime":1234,"exe_sha256":"bad" if len(seen)==1 else "a"*64,"net_ns":90,"mnt_ns":91}
    scope["process_witness"] = sample
    check(scope["exec_witness"](child,"a"*64,90,1)["pid"]==4242 and len(seen)==2, "actual_exec_not_interpreter")
    exited = SimpleNamespace(pid=4242,poll=lambda:0)
    rejected(lambda:scope["exec_witness"](exited,"a"*64,90,1), "short_process_not_fabricated")
    scope["time"] = Clock()
    scope["process_witness"] = lambda _: {"exe_sha256":"bad","net_ns":90,"mnt_ns":91}
    rejected(lambda:scope["exec_witness"](child,"a"*64,90,1), "startup_observer_bounded")
    for payload in ("run", "version"):
        fs, calls = FakeFS(), []
        scope["os"] = fs
        root = scope["ROOT"]
        role_root = root+"/endpoints/initiator"
        binary = b"synthetic-field"
        digest = hashlib.sha256(binary).hexdigest()
        for item in ("/proc/self/ns/net", "/proc/1/ns/net", "/proc/self/ns/mnt"):
            fs.add(item)
        for item in ("home/.winkyou-field/c1c/material", "home/.winkyou-field/c1c/evidence", "run/netns", "var-lib"):
            fs.add(role_root+"/"+item, directory=True)
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
            check(argv[:4] == ["/usr/bin/unshare","-m","--propagation","private"], "private_mount_prefix")
            check(argv[-3:] == [ident,name+"-i",payload], "no_free_command")
            check(len(kwargs["pass_fds"]) == (6 if payload=="run" else 4), "held_sources_exact")
            calls.append(argv)
            return SimpleNamespace(pid=4242,wait=lambda:0)
        scope["subprocess"] = SimpleNamespace(Popen=popen,DEVNULL=-3)
        scope["exec_witness"] = lambda *_: {"pid":4242,"starttime":1234,"net_ns":90,"mnt_ns":91,"exe_sha256":digest}
        check(scope["launch"]("initiator",ident,name+"-i",payload) == 0, "foreground_exit")
        check(len(calls)==1 and not fs.fds, "one_pipeline_no_fd_residue")
        stored = fs.nodes[evidence+"/launch.json"].data
        emitted = [c[1] for c in fs.calls if c[0]=="stdout"]
        check(stored in emitted and stored.startswith(b"C1C_LAUNCH role=initiator"), "same_persistent_and_stdout_witness")
        check(evidence+"/"+ident not in fs.nodes, "product_claim_directory_absent")
        if payload=="version":
            check(not any(c[0]=="open" and ("/material/" in c[1] or c[1]==root+"/"+ident+".json") for c in fs.calls), "version_zero_material_or_instance_io")
        prior = len(calls)
        rejected(lambda:scope["launch"]("initiator",ident,name+"-i",payload), "duplicate_launch_rejected")
        check(len(calls)==prior, "duplicate_no_process")
    # Execute embedded child definitions with all OS/commands replaced.
    commands, execs, closed = [], [], []
    class ExecComplete(Exception): pass
    def execv(path, argv):
        execs.append((path,argv))
        raise ExecComplete()
    fake_os = SimpleNamespace(close=lambda fd:closed.append(fd),read=lambda *_:b"1",execv=execv)
    fake_sub = SimpleNamespace(DEVNULL=-3,run=lambda argv,**kw:commands.append((argv,kw)))
    env = {"os":fake_os,"subprocess":fake_sub,"sys":SimpleNamespace(argv=["child","10","11","12","13","14","15",ident,name+"-i","run"])}
    tree = ast.parse(scope["CHILD"])
    exec(compile(ast.Module(body=[n for n in tree.body if isinstance(n,ast.FunctionDef)], type_ignores=[]),"synthetic","exec"),env)
    try: env["execute"]()
    except ExecComplete: pass
    binds = [argv for argv,_ in commands if argv[1]=="--bind"]
    check([argv[-1] for argv in binds[:7]] == ["/var/lib","/usr/libexec","/etc/shadow","/etc/machine-id","/root","/run","/run/netns"], "launch_fixed_bind_order")
    check(binds[7][-1] == "/root/.winkyou-field/c1c/evidence", "evidence_parent_not_claim")
    check(all(len(kw.get("pass_fds",()))==5 for argv,kw in commands if argv[1]=="--bind"), "sources_inherited_by_mount")
    check(len(commands)==12 and execs[0][1][-3:] == ["run","--instance","/root/.winkyou-field/c1c/"+ident+".json"], "readonly_instance_material_and_exec")
    check(set(closed)==set(range(10,16)), "child_sources_drained_before_exec")


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
    print("PASS "+request["mode"]+" assertions="+str(CHECKS)+" host_calls=0 entrypoint_calls=0")
except Exception as error:
    print("FAIL "+(str(error) if isinstance(error,AssertionError) else type(error).__name__))
    sys.exit(1)
