#!/usr/bin/python3
"""Disposable CI lifecycle proof. Controller.run is replaced before any entry."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import runpy
import select
import signal
import stat
import subprocess
import time

BASE = Path(__file__).resolve().parent
ROOT = Path('/root/.winkyou-field/c1c')
MASK = (1 << (signal.SIGINT - 1)) | (1 << (signal.SIGTERM - 1))

FIXTURE = r'''
def lifecycle_fixture_run(self):
    # Only the lifecycle is exercised. No pair, launcher, router, or field
    # endpoint entry is reachable through this replacement.
    registry = self.session / 'registry'
    os.mkdir(registry, 0o700)
    subprocess.run(['/usr/bin/mount', '--bind', str(registry), '/run/netns'], check=True)
    control = self.session / 'fixture-control.fifo'
    os.mkfifo(control, 0o600)
    identity = process(os.getpid())
    jsonfile(self.session / 'fixture-identity.json', identity)
    if not hasattr(self, 'release_stopped'):
        # The accepted old bootstrap is exercised through exec/unshare --fork.
        # A cooperative private pipe ends this baseline; no HUP/KILL is used.
        fd = os.open(control, os.O_RDONLY)
        need(os.read(fd, 1) == b'1', 'fixture_gate')
        os.close(fd)
        return
    child_code = """import json,os,sys
from pathlib import Path
control,ready=sys.argv[1:]
Path(ready).write_text(json.dumps({'pid':os.getpid()}))
fd=os.open(control,os.O_RDONLY)
assert os.read(fd,1)==b'1'
os.close(fd)
worker=os.fork()
if worker==0:os._exit(0)
assert os.waitpid(worker,0)[1]==0
print('SYNTHETIC_GUARDIAN_TERMINAL code=0',flush=True)
"""
    self.spawn('fixture-guardian', ['/usr/bin/python3', '-I', '-B', '-c', child_code,
                                  str(control), str(self.session / 'fixture-child.json')])
    raise ValueError('synthetic_first_fault')

Controller.run = lifecycle_fixture_run
'''

def exclusive(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def readjson(path):
    return json.loads(path.read_bytes())

def await_condition(check, timeout=10):
    deadline = time.monotonic() + timeout
    while not check():
        assert time.monotonic() < deadline, 'lifecycle proof condition deadline'
        select.select([], [], [], 0.01)

def identity(pid):
    raw = Path('/proc', str(pid), 'stat').read_text()
    fields = raw[raw.rfind(')') + 2:].split()
    p = Path('/proc', str(pid))
    return {'pid': pid, 'starttime': int(fields[19]),
            'net_ns': (p / 'ns/net').stat().st_ino,
            'mnt_ns': (p / 'ns/mnt').stat().st_ino,
            'exe_sha256': digest(p / 'exe')}

def ignored(pid):
    line = next(line for line in Path('/proc', str(pid), 'status').read_text().splitlines()
                if line.startswith('SigIgn:'))
    return int(line.split()[1], 16)

def term(witness):
    fd = os.pidfd_open(witness['pid'])
    try:
        assert identity(witness['pid']) == witness
        signal.pidfd_send_signal(fd, signal.SIGTERM, None, 0)
    finally:
        os.close(fd)

def reaped(pid):
    result = []
    def exited():
        got, status = os.waitpid(pid, os.WNOHANG)
        if got:
            result.extend((got, status))
        return bool(got)
    await_condition(exited)
    got, status = result
    assert got == pid
    assert not Path('/proc', str(pid)).exists()
    return status

def release_pipe(path):
    fd = os.open(path, os.O_WRONLY)
    try:
        assert os.write(fd, b'1') == 1
    finally:
        os.close(fd)

def assert_no_holders(targets):
    matches = []
    for p in Path('/proc').iterdir():
        if not p.name.isdigit():
            continue
        try:
            for task in (p / 'task').iterdir():
                for kind in ('net', 'mnt'):
                    if os.readlink(task / 'ns' / kind) in targets:
                        matches.append(str(task))
                for fd in (task / 'fd').iterdir():
                    try:
                        if os.readlink(fd) in targets:
                            matches.append(str(fd))
                    except FileNotFoundError:
                        pass
        except FileNotFoundError:
            pass
    assert not matches, 'namespace holder remains'

def run_case(name):
    source = BASE / ('accepted-r4.py' if name == 'old' else 'stage3-outer.py')
    raw = source.read_text()
    assert raw.count("if __name__ == '__main__':") == 1
    assert raw.count('    def run(self):') == 1
    nonce = os.urandom(8).hex()
    prep = ROOT / 'tmp' / ('stage3-prep-' + nonce)
    prep.mkdir(mode=0o700)
    (prep / 'shared').mkdir(mode=0o700)
    preapproval = prep / 'shared/preapproval.json'
    exclusive(preapproval, b'{}\n')
    session = ROOT / 'tmp' / ('stage3-session-' + nonce)
    script = prep / 'controller-lifecycle-only.py'
    exclusive(script, raw.replace("if __name__ == '__main__':", FIXTURE + "\nif __name__ == '__main__':").encode(), 0o700)
    fifo, log = prep / 'stdin.fifo', prep / 'console.log'
    holder_file, outer_file = prep / 'holder.pid', prep / 'outer.pid'
    os.mkfifo(fifo, 0o600)
    exclusive(log, b'')
    subprocess.run(['/usr/bin/setsid', '-f', '/bin/bash', '-c',
                    'echo $$ > "$2"; exec 3>"$1"; exec /bin/sleep 7200',
                    '_', str(fifo), str(holder_file)], check=True,
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with log.open('ab', buffering=0) as output:
        subprocess.run(['/usr/bin/setsid', '-f', '/bin/bash', '-c',
                        'echo $$ > "$1"; fifo=$2; shift 2; exec "$@" <"$fifo"',
                        '_', str(outer_file), str(fifo), '/usr/bin/python3', '-I', '-B',
                        str(script), '--execute', '--prep', str(prep),
                        '--preapproval', str(preapproval), '--preapproval-sha256', digest(preapproval),
                        '--session', str(session)], check=True, stdin=subprocess.DEVNULL,
                       stdout=output, stderr=output)
    await_condition(lambda: (session / 'fixture-identity.json').exists())
    witness = readjson(session / 'fixture-identity.json')
    holder, outer_pid = int(holder_file.read_text()), int(outer_file.read_text())
    holder_witness = identity(holder)
    targets = {'net:[' + str(witness['net_ns']) + ']', 'mnt:[' + str(witness['mnt_ns']) + ']'}
    if name == 'old':
        assert outer_pid != witness['pid'], 'baseline did not fork'
        assert ignored(witness['pid']) & MASK == MASK
        assert ignored(outer_pid) & MASK == MASK
        term(witness)  # One controlled negative, followed by a pipe release.
        assert identity(witness['pid']) == witness
        release_pipe(session / 'fixture-control.fifo')
        assert reaped(outer_pid) == 0
        print('CONTROLLER_OLD fork=true parent_ignored_int_term=true child_ignored_int_term=true term_ignored=true cooperative_exit=true', flush=True)
    else:
        assert outer_pid == witness['pid'], 'candidate unexpectedly forked'
        assert ignored(witness['pid']) & MASK == 0
        await_condition(lambda: (session / 'first-stop.json').exists() and (session / 'fixture-child.json').exists())
        first_hash = digest(session / 'first-stop.json')
        child_pid = readjson(session / 'fixture-child.json')['pid']
        assert ignored(child_pid) & MASK == 0, 'controller child inherited ignored stop signals'
        term(witness)
        await_condition(lambda: 'C1C_STAGE3_RELEASE status=blocked' in log.read_text())
        assert identity(witness['pid']) == witness
        assert not (session / 'release-accepted.json').exists()
        release_pipe(session / 'fixture-control.fifo')
        await_condition(lambda: (session / 'fixture-guardian.retained-exit.json').exists())
        assert readjson(session / 'fixture-guardian.retained-exit.json') == {'code': 0}
        assert not Path('/proc', str(child_pid)).exists(), 'guardian zombie was not reaped'
        assert (session / 'fixture-guardian.stdout.log').read_bytes() == b'SYNTHETIC_GUARDIAN_TERMINAL code=0\n'
        assert digest(session / 'first-stop.json') == first_hash
        cleanup = {'synthetic': True, 'guardian_reaped': True, 'registry_empty': True}
        exclusive(session / 'fixture-cleanup.json', json.dumps(cleanup).encode())
        receipt = {'identity': witness, 'first_stop_sha256': first_hash,
                   'operator_confirmation': 'release stopped controller',
                   'reviewer_confirmation': 'release stopped controller',
                   'cleanup_evidence_sha256': digest(session / 'fixture-cleanup.json')}
        exclusive(session / 'release-stopped.json', json.dumps(receipt).encode())
        term(witness)  # A distinct, explicitly verified release request.
        assert reaped(outer_pid) == 70 << 8
        assert readjson(session / 'release-accepted.json') == receipt
        assert digest(session / 'first-stop.json') == first_hash
        print('CONTROLLER_NEW fork=false stop_signals_ignored=false child_stop_signals_ignored=false receipt_required=true guardian_reaped=true original_terminal_preserved=true first_fault_preserved=true release_exit=70', flush=True)
    term(holder_witness)
    assert reaped(holder) == signal.SIGTERM
    assert_no_holders(targets)
    print(json.dumps({'case': name, 'namespace_holders': 0, 'holder_reaped': True,
                      'source_sha256': digest(source), 'console_sha256': digest(log),
                      'synthetic_run_override': True, 'field_execution': False}, sort_keys=True), flush=True)

def main():
    assert os.geteuid() == 0
    assert os.environ.get('GITHUB_ACTIONS') == 'true'
    assert os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
    os.umask(0o077)
    assert ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=False)
    (ROOT / 'tmp').mkdir(mode=0o700)
    Path('/run/netns').mkdir(mode=0o700, exist_ok=True)
    print(subprocess.check_output(['/usr/bin/unshare', '--version'], text=True).strip(), flush=True)
    run_case('old')
    run_case('new')

if __name__ == '__main__':
    main()
