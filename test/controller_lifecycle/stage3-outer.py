#!/usr/bin/python3
"""Review draft: one gated peer-absent instance. Never run during Part B.

Linux/root only. Human receipts arrive as one JSON object per stdin line.
No gate authenticates a person; retain the actual independent responses.
After a stopped execution the controller holds its namespaces for review.
"""
import argparse
import base64
import copy
import ctypes
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import stat
import subprocess
import sys
import time

ROOT = Path('/root/.winkyou-field/c1c')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'HOME': '/root'}
FIELD_HASH = 'b878ff326b8e97ecdf558b7f69e17c5f8263ad48b04a041c70c38c2b58380f06'
ROUTER_HASH = 'bf0061aeee3486218a26037efbc62e6d7314a3195d04f53307e37e650622ad1b'
DIFF_HASH = 'e875c00b5f9e106d784f2b9f95cabb3d8da9f715c7b753757a424eaee67bc90d'
SCRIPT_HASHES = {
    'c1c-endpoint-launch.sh': 'cb74c1760922129cb157ea0ea08958297149eb8fe3521cdf3b7492bd91b82b4c',
    'c1c-owned-stop.sh': '8387015d7a761acfb0df13de409ddb6aa8de7057beec29e719410ff2cc2ff087',
    'c1c-review-evidence.sh': '897625dbeec5c5173ec4f9f0bcf87198fcaf8ff5444fef9df6d35daa29b5049c'}
HEX = re.compile(r'[0-9a-f]{64}\Z')
ROLES = ('initiator', 'transit', 'responder')

def need(ok, label):
    if not ok:
        raise ValueError(label)

def strict_json(raw):
    def pairs(items):
        value = {}
        for k, v in items:
            need(k not in value, 'duplicate_json_member')
            value[k] = v
        return value
    def reject(_):
        raise ValueError('nonfinite_json_number')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=reject)

def canonical_id(value):
    need(isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_-]{22}', value), 'attempt_shape')
    raw = base64.urlsafe_b64decode(value + '==')
    need(len(raw) == 16 and base64.urlsafe_b64encode(raw).decode().rstrip('=') == value, 'attempt_canonical')
    return value

def anchor_names(ident):
    canonical_id(ident)
    prefix = 'wyc1c' + hashlib.sha256(('winkyou-c1c-anchor/1\n' + ident).encode('ascii')).hexdigest()[:8]
    return [prefix + '-' + suffix for suffix in ('i', 't', 'r')]

def utc(value):
    need(isinstance(value, str) and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', value), 'utc_shape')
    return dt.datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=dt.timezone.utc).timestamp()

def secure(path, directory=False):
    p = Path(path)
    need(p.is_absolute(), 'absolute_path_required')
    for parent in reversed(p.parents):
        s = parent.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022, 'unsafe_parent')
    s = p.lstat()
    need(s.st_uid == 0 and not s.st_mode & 0o022 and not stat.S_ISLNK(s.st_mode), 'unsafe_path')
    need(stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode) and s.st_nlink == 1, 'unsafe_type')
    return s

def read(path, limit=65536):
    s = secure(path)
    need(s.st_size <= limit, 'read_limit')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as f:
        opened = os.fstat(f.fileno())
        need((opened.st_dev, opened.st_ino) == (s.st_dev, s.st_ino), 'read_identity')
        raw = f.read(limit + 1)
        after = os.fstat(f.fileno())
        need((opened.st_size, opened.st_mtime_ns) == (after.st_size, after.st_mtime_ns), 'read_changed')
    need(len(raw) == s.st_size, 'read_changed')
    return raw

def digest(path):
    return hashlib.sha256(read(path, 512 * 1024 * 1024)).hexdigest()

def newfile(path, raw):
    secure(Path(path).parent, True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())

def jsonfile(path, value):
    newfile(path, (json.dumps(value, sort_keys=True, ensure_ascii=False) + '\n').encode())

def rename(old, new):
    secure(Path(old).parent, True)
    secure(Path(new).parent, True)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    libc.renameat2.restype = ctypes.c_int
    need(libc.renameat2(-100, os.fsencode(old), -100, os.fsencode(new), 1) == 0, 'rename_noreplace')

def process(pid):
    raw = Path('/proc', str(pid), 'stat').read_text()
    need(raw.split(' (', 1)[0] == str(pid), 'pid_identity')
    fields = raw[raw.rfind(')') + 2:].split()
    p = Path('/proc', str(pid))
    # /proc exe is a kernel link; ordinary secure() deliberately disallows it.
    fd = os.open(p / 'exe', os.O_RDONLY)
    with os.fdopen(fd, 'rb') as f:
        st = os.fstat(f.fileno())
        need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022 and st.st_size <= 512 * 1024 * 1024, 'exe_identity')
        h = hashlib.sha256()
        for block in iter(lambda: f.read(65536), b''):
            h.update(block)
    return {'pid': pid, 'starttime': int(fields[19]), 'net_ns': (p / 'ns/net').stat().st_ino,
            'mnt_ns': (p / 'ns/mnt').stat().st_ino, 'exe_sha256': h.hexdigest()}

def ledger_ok(value, scope):
    need(value.get('ok') is True and 'class' not in value and value.get('machine_scope_reference') == scope, 'ledger_identity')
    for name in ('pending', 'claimed'):
        need(value[name]['valid'] is True and value[name]['exists'] is False, 'ledger_slot')
    need(value['trip']['state'] == 'clear' and value['trip']['blocks_active_work'] is False, 'ledger_trip')
    need(value['ledger']['pairing']['state'] == 'ready' and value['ledger']['pairing']['blocks_active_work'] is False, 'ledger_pairing')
    need(value['ledger']['campaign']['state'] == 'ready' and value['ledger']['campaign']['blocks_campaign'] is False, 'ledger_campaign')
    need(value['next_admission']['ordinary_blocked'] is False and value['next_admission']['campaign_blocked'] is False, 'ledger_admission')

def reader_state(value):
    need(value.get('ok') is True, 'reader_failed')
    files = {r['path']: r for r in value['files']}
    result = {}
    for role in ('initiator', 'responder'):
        prefix = 'c1c/endpoints/' + role + '/var-lib/winkyou-safety-v2/'
        journal = files[prefix + 'pairing-admission-v1.journal']
        trip = files[prefix + 'safety-trip.json']
        need('class' not in journal and 'class' not in trip, 'reader_alias')
        text = trip.get('text')
        need(isinstance(text, str) and text[:1] == 'C', 'reader_trip')
        try:
            envelope = strict_json(text[1:])
        except ValueError:
            need(False, 'reader_trip')
        need(isinstance(envelope, dict) and set(envelope) == {'record', 'checksum'}
             and isinstance(envelope['record'], dict) and envelope['record'].get('state') == 'clear', 'reader_trip')
        for state in ('pending', 'claimed'):
            need(prefix + 'gate-c-responder-' + state + '-v1.json' not in files, 'reader_slot')
        result[role] = {'size': journal['size'], 'sha256': journal['sha256'], 'trip_sha256': trip['sha256']}
    return result

class Controller:
    def __init__(self, args):
        self.args = args
        self.prep = Path(args.prep)
        self.session = Path(args.session)
        self.ident = None
        self.expires = None
        self.last_countdown = 0.0
        self.children = []
        self.anchors = []
        self.buffer = bytearray()
        self.stop_signal = 0
        self.outer_mnt = Path('/proc/self/ns/mnt').stat().st_ino

    def request_stop(self, number, _frame):
        # Signal handlers only request a transition. They never clean up,
        # signal children, write evidence, or interrupt an exclusive write.
        self.stop_signal = number

    def tick(self):
        need(self.stop_signal == 0, 'operator_stop_requested')
        if self.expires is not None:
            left = self.expires - time.time()
            if time.monotonic() - self.last_countdown >= 5:
                print('C1C_STAGE3_WINDOW remaining_seconds=' + str(max(0, int(left))), flush=True)
                self.last_countdown = time.monotonic()
            need(left > 0, 'credential_window_expired')

    def spawn(self, label, argv):
        self.tick()
        secure(Path(argv[0]).resolve())
        for suffix in ('stdout', 'stderr'):
            newfile(self.session / (label + '.' + suffix + '.log'), b'')
        # Append only to the two files this invocation just exclusively claimed.
        out = open(self.session / (label + '.stdout.log'), 'ab', buffering=0)
        err = open(self.session / (label + '.stderr.log'), 'ab', buffering=0)
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err, env=ENV)
        self.children.append((label, child, out, err))
        jsonfile(self.session / (label + '.started.json'), {'argv': argv, 'pid': child.pid})
        return child

    def wait(self, label, child, seconds, codes=(0,)):
        end = time.monotonic() + seconds
        while child.poll() is None:
            self.tick()
            need(time.monotonic() < end, label + '_timeout_no_signal_sent')
            for suffix in ('stdout', 'stderr'):
                need((self.session / (label + '.' + suffix + '.log')).stat().st_size <= 16 * 1024 * 1024, 'command_output_limit')
            time.sleep(0.05)
        jsonfile(self.session / (label + '.exit.json'), {'code': child.returncode})
        need(child.returncode in codes, label + '_exit')
        return read(self.session / (label + '.stdout.log'), 16 * 1024 * 1024)

    def command(self, label, argv, seconds=20, codes=(0,)):
        return self.wait(label, self.spawn(label, argv), seconds, codes)

    def gate(self, number, check):
        print('C1C_STAGE3_GATE n=' + str(number) + ' status=waiting', flush=True)
        rejected = 0
        while True:
            self.tick()
            while b'\n' not in self.buffer:
                self.tick()
                if select.select([sys.stdin.fileno()], [], [], 0.5)[0]:
                    b = os.read(sys.stdin.fileno(), 4096)
                    need(bool(b), 'gate_input_eof')
                    self.buffer.extend(b)
                    need(len(self.buffer) <= 65536, 'gate_input_limit')
            line, _, rest = self.buffer.partition(b'\n')
            self.buffer = bytearray(rest)
            self.gate_attempt = rejected + 1
            try:
                receipt = strict_json(line)
                need(isinstance(receipt, dict) and receipt.get('gate') == number and receipt.get('reviewer') == 'second-person', 'gate_receipt')
                check(receipt)
            except ValueError as error:
                if str(error) == 'credential_window_expired':
                    raise
                rejected += 1
                newfile(self.session / ('gate-' + str(number) + '.rejected-' + str(rejected) + '.log'), line + b'\n')
                reason = str(error) if re.fullmatch(r'[a-zA-Z0-9_-]+', str(error)) else type(error).__name__
                print('C1C_STAGE3_GATE n=' + str(number) + ' status=rejected class=' + reason, flush=True)
                need(rejected <= 3, 'gate_receipt_rejected_limit')
                continue
            jsonfile(self.session / ('gate-' + str(number) + '.receipt.json'), receipt)
            return receipt

    def release(self, number):
        self.tick()
        print('C1C_STAGE3_GATE n=' + str(number) + ' status=released', flush=True)

    def view_witness(self, role, payload, raw, code):
        lines = raw.decode().splitlines()
        need(len(lines) == 3 and not any(' class=' in x for x in lines), 'launcher_shape')
        pattern = r'C1C_LAUNCH role=' + role + r' pid=([1-9][0-9]*) starttime=([1-9][0-9]*) net_ns=([1-9][0-9]*) mnt_ns=([1-9][0-9]*) exe_sha256=([0-9a-f]{64}) exe_ino=([1-9][0-9]*)'
        match = re.fullmatch(pattern, lines[0])
        need(match is not None, 'launcher_witness')
        pid, start, net, mnt, sha, ino = match.groups()
        anchor = self.anchors[0 if role == 'initiator' else 2]
        need(int(net) == anchor['inode'] and int(mnt) != self.outer_mnt and sha == FIELD_HASH, 'launcher_namespace_image')
        need(int(ino) == (ROOT / 'endpoints' / role / 'install/winkyou/wink').stat().st_ino, 'launcher_image_inode')
        name = 'launch.json' if payload == 'run' else 'launch-' + payload + '.json'
        need(read(self.evidence / ('endpoint-' + role) / name) == (lines[0] + '\n').encode(), 'launcher_persisted_witness')
        need(lines[2] == 'C1C_EXIT role=' + role + ' code=' + str(code), 'launcher_exit_witness')
        print(lines[0], flush=True)
        print(lines[2], flush=True)
        return strict_json(lines[1])

    def run(self):
        need(os.geteuid() == 0 and sys.platform == 'linux', 'linux_root_required')
        need(Path('/proc/self/ns/net').stat().st_ino != Path('/proc/1/ns/net').stat().st_ino, 'outer_net')
        need(self.outer_mnt != Path('/proc/1/ns/mnt').stat().st_ino, 'outer_mount')
        secure(self.session, True)
        secure(self.prep, True)
        before_raw = read(self.args.preapproval)
        need(hashlib.sha256(before_raw).hexdigest() == self.args.preapproval_sha256, 'frozen_hash')
        before = strict_json(before_raw)
        unsigned = strict_json(read(self.prep / 'shared/instance.preapproval.json'))
        allowed = {'operator_signature', 'reviewer_signature', 'root_risk_accepted_by_operator', 'root_risk_accepted_by_reviewer'}
        need(set(before) == set(unsigned) and len(before) == 89 and all(before[k] == unsigned[k] for k in before if k not in allowed), 'preapproval_freeze_delta')
        for key, phrase in [('operator_signature', '预批 predictive_apdm_pair'), ('reviewer_signature', '复核 预批 predictive_apdm_pair')]:
            need(isinstance(before[key], str) and before[key].startswith(phrase + ' ') and '<' not in before[key], 'first_signature')
            utc(before[key][len(phrase) + 1:])
        need(all(before[k] is True for k in allowed if k.startswith('root_')), 'first_risk_acceptance')
        need(before['unused_credential_verified'] is None and before['single_invocation_verified'] is None, 'unissued_flags')
        need(before['scenario'] == 'predictive_apdm_pair' and before['expected_terminal_and_fault_stage']['terminal'] == 'oob_stream_closed' and before['expected_terminal_and_fault_stage']['stage'] == 'present', 'scenario')
        need(before['router']['allow_global_conntrack_ceiling'] is False, 'host_ceiling_forbidden')
        for name, expected in SCRIPT_HASHES.items():
            need(digest(ROOT / 'review' / name) == expected, 'script_hash')
        need(digest(ROOT / 'bin/wink-field') == FIELD_HASH and digest(ROOT / 'bin/c1crouter') == ROUTER_HASH, 'binary_hash')
        self.diff_tool = Path(__file__).resolve().with_name('instance-diff.py')
        need(digest(self.diff_tool) == DIFF_HASH, 'diff_tool_hash')
        self.command('outer-private', ['/usr/bin/mount', '--make-rprivate', '/'])
        registry = self.session / 'netns-registry'
        os.mkdir(registry, 0o700)
        need(Path('/run/netns').is_dir(), 'registry_mountpoint_missing')
        self.command('outer-registry', ['/usr/bin/mount', '--bind', str(registry), '/run/netns'])
        self.command('outer-lo', ['/usr/sbin/ip', 'link', 'set', 'lo', 'up'])
        need([x['ifname'] for x in strict_json(self.command('outer-links', ['/usr/sbin/ip', '-j', 'link', 'show']))] == ['lo'], 'outer_lo_only')
        need(Path('/run/netns').stat().st_ino == registry.stat().st_ino, 'registry_identity')
        jsonfile(self.session / 'outer.json', {'pid': os.getpid(), 'net': Path('/proc/self/ns/net').stat().st_ino, 'mnt': self.outer_mnt, 'registry_inode': registry.stat().st_ino})
        def check_gate1(receipt):
            need(receipt.get('confirmation') == '开始' and receipt.get('preapproval_sha256') == self.args.preapproval_sha256, 'gate1_confirmation')
            need(receipt.get('tool_sha256') == digest(Path(__file__).resolve()) and receipt.get('diff_sha256') == DIFF_HASH, 'reviewed_tool_hash')
            need(isinstance(receipt.get('before_file'), str), 'second_person_before')
            before_path = Path(receipt['before_file'])
            need(before_path.parent == ROOT / 'review/second-person' and digest(before_path) == receipt.get('before_sha256'), 'second_person_before')
            snap = strict_json(read(before_path, 1024 * 1024))
            need(isinstance(snap, dict) and snap.get('ok') is True and isinstance(snap.get('nonvolatile'), dict) and len(snap['nonvolatile']) == 10 and snap['nonvolatile'].get('namespaces') == [] and snap['nonvolatile'].get('registry') == [], 'before_shape')
        receipt = self.gate(1, check_gate1)
        self.release(1)
        pair = self.session / 'pair'
        self.command('pair-oob-once', [str(ROOT / 'bin/wink-field'), 'solver', 'pair', 'oob', '--profile', 'predictive', '--out-dir', str(pair)], 30)
        manifest_bytes = read(pair / 'manifest.json')
        manifest = strict_json(manifest_bytes)
        self.ident = canonical_id(manifest['attempt_id'])
        self.expires = utc(manifest['expires_at'])
        need(0 < self.expires - time.time() <= 600, 'manifest_window')
        names = anchor_names(self.ident)
        print('C1C_STAGE3_HANDSHAKE ' + json.dumps({'attempt_id': self.ident, 'anchors': names}), flush=True)
        def check_gate2(receipt):
            need(receipt.get('attempt_id') == self.ident and receipt.get('anchors') == names, 'anchor_handshake')
        receipt = self.gate(2, check_gate2)
        self.release(2)
        self.evidence = ROOT / 'evidence' / self.ident
        os.mkdir(self.evidence, 0o700)
        for role in ('initiator', 'responder'):
            os.mkdir(self.evidence / ('endpoint-' + role), 0o700)
        rename(registry, self.evidence / 'netns-registry')
        for role, name in zip(ROLES, names):
            self.command('anchor-' + role + '-add', ['/usr/sbin/ip', 'netns', 'add', name])
            inode = Path('/run/netns', name).stat().st_ino
            self.anchors.append({'role': role, 'name': name, 'inode': inode})
            need(inode != Path('/proc/1/ns/net').stat().st_ino and inode != Path('/proc/self/ns/net').stat().st_ino, 'anchor_inode')
            self.command('anchor-' + role + '-lo', ['/usr/sbin/ip', 'netns', 'exec', name, '/usr/sbin/ip', 'link', 'set', 'lo', 'up'])
            links = strict_json(self.command('anchor-' + role + '-links', ['/usr/sbin/ip', 'netns', 'exec', name, '/usr/sbin/ip', '-j', 'link', 'show']))
            need([x['ifname'] for x in links] == ['lo'], 'anchor_lo_only')
        need(len({x['inode'] for x in self.anchors}) == 3, 'anchor_inodes_unique')
        jsonfile(self.evidence / 'anchors.json', self.anchors)
        material = ROOT / 'material' / self.ident
        os.mkdir(material, 0o700)
        rename(pair, material / 'pair')
        for role in ('initiator', 'responder'):
            self.tick()
            rename(self.prep / role, material / role)
            view = material / role
            need(digest(view / (role + '.yaml')) == before['devices'][0 if role == 'initiator' else 1]['configuration_sha256'], 'config_changed')
            request = view / (role + '.request.json')
            raw = read(request)
            need(b'<ATTEMPT>' in raw, 'request_template')
            rename(request, view / (role + '.request.template.json'))
            newfile(request, raw.replace(b'<ATTEMPT>', self.ident.encode()))
            os.mkdir(view / 'pair', 0o700)
            for filename in ('manifest.json', 'initiator.artifact.json', 'responder.artifact.json'):
                newfile(view / 'pair' / filename, read(material / 'pair' / filename))
        signed = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        replacements = {'<ATTEMPT>': self.ident, '<D_MANIFEST_SHA256>': hashlib.sha256(manifest_bytes).hexdigest(),
                        '<D_EXPIRES>': manifest['expires_at'], '<H_SIGNED_AT>': signed,
                        '<H_NOT_BEFORE>': signed, '<H_NOT_AFTER>': manifest['expires_at']}
        def resolve(x):
            if isinstance(x, dict):
                return {k: resolve(v) for k, v in x.items()}
            if isinstance(x, list):
                return [resolve(v) for v in x]
            if isinstance(x, str):
                for a, b in replacements.items():
                    x = x.replace(a, b)
            return x
        final = resolve(copy.deepcopy(before))
        final['router']['anchors'] = self.anchors
        final['unused_credential_verified'] = True
        final['single_invocation_verified'] = True
        self.instance = ROOT / (self.ident + '.json')
        final_bytes = (json.dumps(final, ensure_ascii=False, indent=2) + '\n').encode()
        newfile(self.session / 'instance.final.candidate.json', final_bytes)
        newfile(self.instance, final_bytes)
        final_hash = hashlib.sha256(final_bytes).hexdigest()
        jsonfile(self.session / 'copy-status.json', {'router_sha256': final_hash, 'candidate_sha256': final_hash,
            'initiator_copy': 'launcher creates it on run; verify then', 'responder_copy': 'omitted: approved peer-absent deviation'})
        # Show the strict check's changes before gate 3. The absent human
        # verification record must still reject; it cannot authorize execution.
        preview = strict_json(self.command('diff-preview', ['/usr/bin/python3', '-I', '-B', str(self.diff_tool), self.args.preapproval, str(self.instance)], codes=(65,)))
        print('C1C_STAGE3_DIFF ' + json.dumps({'final_sha256': final_hash, 'changes': preview.get('changes'), 'authorization': 'none'}, ensure_ascii=False), flush=True)
        def check_gate3(receipt):
            # U6 spells this token ATTEMPT_FIRST_8: raw canonical ID characters,
            # distinct from the SHA-256-derived eight hex digits in anchor names.
            need(receipt.get('maintainer') == '签发 predictive_apdm_pair ' + self.ident[:8] and receipt.get('confirmation') == '复核通过', 'gate3_signatures')
            need(receipt.get('final_sha256') == final_hash, 'gate3_hash')
            need(isinstance(receipt.get('verification_record'), dict), 'derivation_diff')
            verification_path = self.session / ('verification-record-' + str(self.gate_attempt) + '.json')
            jsonfile(verification_path, receipt['verification_record'])
            checked = strict_json(self.command('diff-verified-' + str(self.gate_attempt), ['/usr/bin/python3', '-I', '-B', str(self.diff_tool), self.args.preapproval, str(self.instance), '--verification-record', str(verification_path)], codes=(0, 65)))
            need(isinstance(checked, dict) and checked.get('ok') is True and checked.get('classification') == 'only_derived_fields', 'derivation_diff')
            receipt['verification_record_file'] = verification_path.name
        receipt = self.gate(3, check_gate3)
        self.release(3)
        self.reader_before = reader_state(strict_json(self.command('reader-before-run', ['/bin/sh', str(ROOT / 'review/c1c-review-evidence.sh')], 30)))
        for role, anchor in [('initiator', self.anchors[0]), ('responder', self.anchors[2])]:
            raw = self.command('ledger-' + role, ['/bin/sh', str(ROOT / 'review/c1c-endpoint-launch.sh'), role, self.ident, anchor['name'], '--payload', 'ledger'], 35)
            ledger_ok(self.view_witness(role, 'ledger', raw, 0), before[role + '_machine_scope_reference'])
        router = self.spawn('router-run', [str(ROOT / 'bin/c1crouter'), 'run', '--instance', str(self.instance)])
        router_dir = self.evidence / 'router'
        end = time.monotonic() + 30
        while not (router_dir / 'ready.json').exists():
            self.tick()
            need(router.poll() is None and time.monotonic() < end, 'router_ready_unavailable')
            time.sleep(0.05)
        need(strict_json(read(router_dir / 'ready.json')) == {'stage': 'router_ready'}, 'router_ready')
        ownership = strict_json(read(router_dir / 'ownership.json'))
        witness = process(router.pid)
        need(ownership['schema'] == 'winkyou-router-ownership/1' and ownership['pid'] == router.pid and int(ownership['start']) == witness['starttime'] and ownership['digest'] == final_hash, 'router_ownership')
        need(witness['exe_sha256'] == ROUTER_HASH and witness['net_ns'] == Path('/proc/self/ns/net').stat().st_ino, 'router_process_identity')
        need(ownership['ceiling_original'] is None, 'router_ceiling')
        jsonfile(self.evidence / 'router-guardian-witness.json', witness)
        print('C1C_STAGE3_READY ' + json.dumps(witness), flush=True)
        def check_gate4(receipt):
            need(receipt.get('confirmation') == '复核通过' and receipt.get('ready') == {'stage': 'router_ready'} and receipt.get('guardian') == witness, 'gate4_identity')
        receipt = self.gate(4, check_gate4)
        need(process(router.pid) == witness and router.poll() is None, 'router_identity_changed')
        self.release(4)
        raw = self.command('initiator-run', ['/bin/sh', str(ROOT / 'review/c1c-endpoint-launch.sh'), 'initiator', self.ident, names[0]], 55, codes=(1,))
        summary = self.view_witness('initiator', 'run', raw, 1)
        left = self.expires - time.time()
        self.expires = None
        print('C1C_STAGE3_WINDOW phase=post_run enforcement=off remaining_seconds=' + str(max(0, int(left))), flush=True)
        need(summary['class'] == 'oob_stream_closed' and summary['stage'] == 'present', 'unexpected_terminal')
        need(all(summary['counts'][key] == 0 for key in ['evidence_packets', 'candidate_packets', 'winner_packets', 'udp_opened']), 'endpoint_udp_nonzero')
        need(digest(ROOT / 'endpoints/initiator/home/.winkyou-field/c1c' / (self.ident + '.json')) == final_hash, 'initiator_instance_copy')
        terminal_path = self.evidence / 'endpoint-initiator' / self.ident / 'endpoint.jsonl'
        terminals = [strict_json(line) for line in read(terminal_path, 4 * 1024 * 1024).splitlines()]
        terminal = [x for x in terminals if x.get('class')][-1]
        need(terminal['class'] == 'oob_stream_closed' and terminal['failure_stage'] == 'present' and terminal['result']['credential_burned'] is False and terminal['result']['finish_recorded'] is False, 'private_terminal')
        stop = self.command('router-owned-stop', ['/bin/sh', str(ROOT / 'review/c1c-owned-stop.sh'), str(witness['pid']), str(witness['starttime']), witness['exe_sha256']], 5, codes=(0, 1))
        match = re.fullmatch(rb'C1C_STOP pid=' + str(witness['pid']).encode() + rb' exited=(true|false) elapsed_ms=[0-9]+\n', stop)
        need(match is not None, 'owned_stop_identity')
        owned_stop_exited = match.group(1) == b'true'
        owned_stop_elapsed_ms = int(stop.rsplit(b'=', 1)[1])
        jsonfile(self.evidence / 'router-owned-stop.json', {'pid': witness['pid'], 'starttime': witness['starttime'], 'exe_sha256': witness['exe_sha256'], 'exited': owned_stop_exited, 'elapsed_ms': owned_stop_elapsed_ms, 'deadline_ms': 2000})
        print(stop.decode(), end='', flush=True)
        guardian = strict_json(self.wait('router-run', router, 26))
        need(guardian['class'] == 'cancelled' and guardian['stage'] == 'terminal', 'guardian_terminal')
        jsonfile(self.evidence / 'router-guardian-terminal.json', guardian)
        teardown = strict_json(self.command('router-teardown', [str(ROOT / 'bin/c1crouter'), 'teardown', '--instance', str(self.instance)], 30))
        need(teardown['class'] == 'success', 'teardown_terminal')
        after_state = reader_state(strict_json(self.command('reader-after-run', ['/bin/sh', str(ROOT / 'review/c1c-review-evidence.sh')], 30)))
        need(after_state == self.reader_before, 'post_run_journal_or_trip_changed')
        for anchor in self.anchors:
            need(Path('/run/netns', anchor['name']).stat().st_ino == anchor['inode'], 'cleanup_anchor_identity')
            need(not self.command('pids-' + anchor['role'], ['/usr/sbin/ip', 'netns', 'pids', anchor['name']]).strip(), 'anchor_has_process')
        for anchor in self.anchors:
            self.command('delete-' + anchor['role'], ['/usr/sbin/ip', 'netns', 'del', anchor['name']])
        need(list(Path('/run/netns').iterdir()) == [], 'registry_not_empty')
        jsonfile(self.evidence / 'stage3-execution.json', {'result': 'pass', 'terminal': 'oob_stream_closed', 'stage': 'present', 'burned': False, 'finish_recorded': False, 'journal_unchanged': True, 'final_sha256': final_hash, 'second_person_after': 'pending', 'owned_stop_exited': owned_stop_exited, 'owned_stop_elapsed_ms': owned_stop_elapsed_ms, 'window_remaining_at_run_exit': max(0, int(left))})
        print('C1C_STAGE3 execution=pass owned_stop_exited=' + str(owned_stop_exited).lower() + ' owned_stop_elapsed_ms=' + str(owned_stop_elapsed_ms), flush=True)
        print('CLEANUP result=pass', flush=True)

    def stopped(self, reason):
        identities = []
        for label, child, _, _ in self.children:
            if child.poll() is None:
                try:
                    identities.append({'label': label, 'identity': process(child.pid)})
                except (OSError, ValueError):
                    identities.append({'label': label, 'pid': child.pid, 'identity': 'unknown'})
        jsonfile(self.session / 'first-stop.json', {'reason': reason, 'anchors': self.anchors, 'live_children': identities, 'no_signal_sent': True})
        print('C1C_STAGE3 execution=stopped class=' + reason, flush=True)
        print('C1C_STAGE3_RETAIN ' + json.dumps({'outer_pid': os.getpid(), 'anchors': self.anchors, 'live_children': identities}), flush=True)
        if self.anchors or identities:
            # Keep the outer mount/net view available. No cleanup, signal,
            # alternate payload, anchor deletion or automatic retry on failure.
            while True:
                # poll() reaps owned zombies. Keep their original logs and
                # exit status; never rerun a child or synthesize its terminal.
                for label, child, out, err in self.children:
                    code = child.poll()
                    if code is not None and not out.closed:
                        out.close()
                        err.close()
                        jsonfile(self.session / (label + '.retained-exit.json'), {'code': code})
                if self.stop_signal:
                    self.stop_signal = 0
                    try:
                        self.release_stopped()
                    except (OSError, ValueError, KeyError, TypeError) as error:
                        reason = str(error) if type(error) is ValueError else type(error).__name__
                        print('C1C_STAGE3_RELEASE status=blocked class=' + reason, flush=True)
                    else:
                        print('C1C_STAGE3_RELEASE status=accepted no_cleanup=true', flush=True)
                        return
                time.sleep(0.1)

    def release_stopped(self):
        # This receipt is separate from run authority. After independently
        # approved cleanup, an operator sends one identity-bound TERM/INT.
        # A signal alone cannot release a namespace that still owns resources.
        receipt = strict_json(read(self.session / 'release-stopped.json'))
        need(isinstance(receipt, dict), 'release_receipt')
        identity = process(os.getpid())
        expected = {'identity': identity,
                    'first_stop_sha256': digest(self.session / 'first-stop.json'),
                    'operator_confirmation': 'release stopped controller',
                    'reviewer_confirmation': 'release stopped controller',
                    'cleanup_evidence_sha256': receipt.get('cleanup_evidence_sha256')}
        need(receipt == expected and isinstance(receipt['cleanup_evidence_sha256'], str)
             and HEX.fullmatch(receipt['cleanup_evidence_sha256']), 'release_receipt')
        need(all(child.poll() is not None for _, child, _, _ in self.children), 'release_live_child')
        secure(Path('/run/netns'), True)
        need(not list(Path('/run/netns').iterdir()), 'release_registry_not_empty')
        self.no_other_namespace_holders(identity)
        jsonfile(self.session / 'release-accepted.json', receipt)

    def no_other_namespace_holders(self, identity):
        first = strict_json(read(self.session / 'first-stop.json'))
        targets = {'net:[' + str(identity['net_ns']) + ']',
                   'mnt:[' + str(identity['mnt_ns']) + ']'}
        for anchor in first['anchors']:
            targets.add('net:[' + str(anchor['inode']) + ']')
        for child in first['live_children']:
            old = child.get('identity')
            need(isinstance(old, dict), 'release_child_identity_unknown')
            targets.update(('net:[' + str(old['net_ns']) + ']',
                            'mnt:[' + str(old['mnt_ns']) + ']'))
        for process_dir in Path('/proc').iterdir():
            if not process_dir.name.isdigit() or int(process_dir.name) == os.getpid():
                continue
            try:
                for task in (process_dir / 'task').iterdir():
                    for kind in ('net', 'mnt'):
                        need(os.readlink(task / 'ns' / kind) not in targets, 'release_namespace_thread')
                    for fd in (task / 'fd').iterdir():
                        try:
                            need(os.readlink(fd) not in targets, 'release_namespace_fd')
                        except FileNotFoundError:
                            pass  # That exact descriptor was closed.
            except FileNotFoundError:
                # A vanished process/thread cannot hold a namespace. Every
                # other read error is rejected by the stopped release gate.
                continue

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true', required=True)
    parser.add_argument('--prep', required=True)
    parser.add_argument('--preapproval', required=True)
    parser.add_argument('--preapproval-sha256', required=True)
    parser.add_argument('--session', required=True)
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    need(sys.platform == 'linux' and os.geteuid() == 0, 'linux_root_required')
    os.umask(0o077)
    prep, session = Path(args.prep), Path(args.session)
    need(prep.parent == ROOT / 'tmp' and re.fullmatch(r'stage3-prep-[0-9a-f]{16}', prep.name), 'prep_path')
    need(session.parent == ROOT / 'tmp' and re.fullmatch(r'stage3-session-[0-9a-f]{16}', session.name), 'session_path')
    need(Path(args.preapproval).parent == prep / 'shared' and HEX.fullmatch(args.preapproval_sha256), 'preapproval_path')
    secure(Path(__file__).resolve())
    if not args.inside:
        os.mkdir(session, 0o700)
        jsonfile(session / 'bootstrap.json', {'source_sha256': digest(Path(__file__).resolve()), 'preapproval_sha256': args.preapproval_sha256, 'execution_requested': True})
        # No PID namespace is used, so no fork is needed. Older unshare --fork
        # implementations ignore TERM/INT before fork and pass that disposition
        # to the child. Also reject inherited ignores from an outer shell.
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        os.execve('/usr/bin/unshare', ['/usr/bin/unshare', '--net', '--mount', '/usr/bin/python3', '-I', '-B', str(Path(__file__).resolve())] + sys.argv[1:] + ['--inside'], ENV)
    controller = Controller(args)
    signal.signal(signal.SIGINT, controller.request_stop)
    signal.signal(signal.SIGTERM, controller.request_stop)
    jsonfile(session / 'controller-identity.json', process(os.getpid()))
    try:
        controller.run()
    except (Exception, KeyboardInterrupt) as error:
        reason = str(error) if isinstance(error, ValueError) and re.fullmatch(r'[a-zA-Z0-9_-]+', str(error)) else type(error).__name__
        controller.stopped(reason)
        return 70
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
