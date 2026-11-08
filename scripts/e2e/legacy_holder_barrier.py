#!/usr/bin/env python3
"""Physical first-upgrade smoke, run ON the disposable Linux Docker host as root.

Requires locally loaded immutable --holder-image (UNCHANGED older binary) and
--tools-image (Python 3.11+ with ssl). Never pulls/builds/replaces a holder.
The tiny tool/candidate image is built only from the supplied local tools image.
No published ports, production storage, public IRC or existing holders touched.
Fixture-generated provenance is TEST EVIDENCE ONLY, never production approval.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time


def wait(predicate, label, timeout=20):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        result = predicate()
        if result:
            return result
        time.sleep(0.02)
    raise RuntimeError('event deadline: ' + label + '; last exclusion: ' + str(getattr(eligible, 'last_error', 'none')))


def exact(sock, size):
    data = b''
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise RuntimeError('unexpected physical EOF')
        data += part
    return data


def endpoint():
    root = Path('/control')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('/control/cert.pem', '/control/key.pem')
    context.set_servername_callback(lambda sock, name, _: setattr(sock, '_fixture_sni', name))
    def serve(conn, serial):
        with conn:
            conn.settimeout(30)
            version, size = exact(conn, 2)
            assert version == 5
            exact(conn, size)
            conn.sendall(b'\x05\x00')
            version, command, _, kind = exact(conn, 4)
            assert version == 5 and command == 1
            if kind == 1:
                exact(conn, 4)
            elif kind == 3:
                exact(conn, exact(conn, 1)[0])
            elif kind == 4:
                exact(conn, 16)
            else:
                raise RuntimeError('invalid SOCKS address')
            exact(conn, 2)
            conn.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x1a\x0b')
            # Peek without consuming: handshake has actually reached the peer,
            # rather than inferring progress from elapsed time or holder logs.
            assert conn.recv(1, socket.MSG_PEEK) == b'\x16'
            (root / f'hello-{serial}').write_text(json.dumps({'peer': conn.getpeername()}))
            release = root / f'release-{serial}'
            wait(release.exists, 'TLS release', 25)
            if release.read_text() == 'failure':
                return
            with context.wrap_socket(conn, server_side=True) as tls:
                tls.settimeout(None)
                assert tls._fixture_sni == 'legacy-barrier.fixture.invalid'
                (root / f'tls-{serial}').write_text('ready')
                ping = root / f'ping-{serial}'
                wait(ping.exists, 'PING event', 25)
                tls.sendall(f'PING :legacy-{serial}\r\n'.encode())
                stream = tls.makefile('rb')
                repeated = False
                while True:
                    line = stream.readline(65536)
                    if not line:
                        (root / f'closed-{serial}').write_text('EOF')
                        return
                    if b'PONG' in line and f'legacy-{serial}'.encode() in line:
                        (root / f'pong-{serial}').write_text('ok')
                        if serial == 1:
                            if repeated:
                                (root / 'repong-1').write_text('ok')
                            else:
                                wait((root / 'reping-1').exists, 'post-barrier PING event', 240)
                                tls.sendall(b'PING :legacy-1-again\r\n')
                                repeated = True
                        # Continue consuming: an upstream accidentally closed by
                        # the barrier must be observable independently of LIST.
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('0.0.0.0', 1080))
        listener.listen()
        (root / 'endpoint-ready').write_text('ready')
        serial = 0
        while True:
            conn, _ = listener.accept()
            serial += 1
            threading.Thread(target=serve, args=(conn, serial), daemon=True).start()


def client():
    root = Path('/control')
    body = {'token': (root / 'token').read_text(), 'host': '203.0.113.90', 'port': 6697,
            'tls': 'implicit', 'sni': 'legacy-barrier.fixture.invalid',
            'proxy': {'host': '203.0.113.10', 'port': 1080},
            'tag': {'networkId': os.environ['FIXTURE_NETWORK'], 'name': 'legacy-fixture'},
            'connectTimeoutMs': 20000, 'tlsTimeoutMs': 25000}
    with socket.socket(socket.AF_UNIX) as sock:
        sock.connect('/ipc/holder.sock')
        sock.sendall(('DIAL ' + json.dumps(body) + '\n').encode())
        stream = sock.makefile('rb')
        while True:
            line = stream.readline(16 << 20)
            if not line:
                return
            if line.startswith(b'CONNECTED '):
                (root / ('connected-' + os.environ['FIXTURE_NETWORK'])).write_bytes(line[10:])
            elif not line.startswith(b'EVENT '):
                (root / 'unexpected-client-reply').write_bytes(line)
                return


def candidate():
    # Not a mocked engine/holder: a physical process used only to observe that
    # the production helper's atomic start path was (or was not) reached.
    Path('/control/candidate-started').write_text('started')
    while True:
        signal.pause()


def driver():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--holder-image', required=True)
    p.add_argument('--tools-image', required=True)
    p.add_argument('--helper', default=str(Path(__file__).resolve().parents[3] / 'site/scripts/legacy-holder-barrier.py'))
    args = p.parse_args()
    assert sys.platform == 'linux' and os.geteuid() == 0, 'run on disposable Linux Docker host as root'
    assert not os.environ.get('DOCKER_HOST') and not os.environ.get('DOCKER_CONTEXT'), 'local Unix Docker only'
    for image in (args.holder_image, args.tools_image):
        assert image.startswith('sha256:') and len(image) == 71, 'exact locally loaded immutable image required'
    tag = 'legacy-barrier-' + secrets.token_hex(8)
    label = 'ircfiber.fixture.run=' + tag
    base = Path('/var/lib/ircfiber-barrier-fixture')
    base.mkdir(mode=0o700, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix=tag + '-', dir=base))
    os.chmod(root, 0o700)
    control = root / 'control'
    control.mkdir(mode=0o777)
    os.chmod(control, 0o777)  # disposable clients/holder may be non-root
    # Match the existing OVH filesystem-authenticated Unix holder, including
    # SO_PEERCRED verification by the observer. No token/config change needed.
    token = ''
    (control / 'token').write_text(token)
    token_file = root / 'token.json'
    token_file.write_text(json.dumps(token))
    os.chmod(token_file, 0o600)
    deadline = time.monotonic() + 240
    spec = importlib.util.spec_from_file_location('barrier', args.helper)
    barrier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(barrier)
    containers = []
    network = None
    volume = None
    tool_image = None
    base_image_tag = None
    def dock(*argv, check=True):
        result = subprocess.run(['docker', '--host', 'unix:///var/run/docker.sock', *argv],
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=max(1, deadline - time.monotonic()))
        if check and result.returncode:
            raise RuntimeError('fixture Docker command failed: ' + argv[0] + ': ' + result.stderr[-6000:])
        return result
    def create(name, image, options, command=()):
        result = dock('create', '--name', tag + '-' + name, '--label', label,
                      '--restart=no', *options, image, *command)
        cid = result.stdout.strip()
        containers.append(cid)
        return cid
    def start_client(name):
        cid = create(name, tool_image, ['--network', network, '--mount', f'type=volume,src={volume},dst=/ipc',
                     '--mount', f'type=bind,src={control},dst=/control', '-e', 'FIXTURE_NETWORK=' + name], ['client'])
        dock('start', cid)
        return cid
    def stop_client(cid):
        info = barrier.inspect(cid, deadline)
        gen, cg = barrier.producer_snapshot(info)
        with open(f"/proc/{gen['pid']}/ns/pid", 'rb') as pin:
            assert f"pid:[{os.fstat(pin.fileno()).st_ino}]" == gen['pidns']
            dock('stop', '--signal=SIGTERM', '--timeout', '2', cid)
            barrier.exited(gen, cg)
    def observer(pid):
        return barrier.Observer(pid, f'/proc/{pid}/root/ipc/holder.sock', 'legacy-fixture', token, deadline)
    def listener(pid):
        unix, _ = barrier.diagnostics(pid, deadline)
        return next(u for u in unix.values() if u['name'] == b'/ipc/holder.sock' and u['state'] == 10)
    def rejection(call, label):
        try:
            call()
        except (barrier.Blocked, OSError):
            return
        raise AssertionError('unsafe approval: ' + label)
    try:
        for image in (args.holder_image, args.tools_image):
            assert json.loads(dock('image', 'inspect', image).stdout)[0]['Id'] == image
        # BuildKit treats FROM sha256:... as a repository name, not a local
        # image ID. A unique owned tag pins the already-inspected local image.
        base_image_tag = tag + ':base'
        dock('tag', args.tools_image, base_image_tag)
        shutil.copyfile(__file__, root / 'fixture.py')
        (root / 'Dockerfile').write_text('FROM ' + base_image_tag + '\nLABEL com.ircfiber.routing-policy-version="1"\n'
            'LABEL ircfiber.fixture.run="' + tag + '"\n'
            'COPY fixture.py /fixture.py\nENTRYPOINT ["python3", "-u", "/fixture.py"]\nCMD ["candidate"]\n')
        dock('build', '--pull=false', '--network=none', '-t', tag + ':tools', str(root))
        tool_image = json.loads(dock('image', 'inspect', tag + ':tools').stdout)[0]['Id']
        assert json.loads(dock('image', 'inspect', base_image_tag).stdout)[0]['Id'] == args.tools_image
        network = dock('network', 'create', '--internal', '--subnet', '203.0.113.0/24', '--label', label, tag).stdout.strip()
        volume = dock('volume', 'create', '--label', label, tag + '-ipc').stdout.strip()
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=legacy-barrier.fixture.invalid', '-keyout', str(control / 'key.pem'),
                        '-out', str(control / 'cert.pem')], check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=20)
        endpoint_id = create('endpoint', tool_image, ['--network', network, '--ip', '203.0.113.10',
                             '--mount', f'type=bind,src={control},dst=/control'], ['endpoint'])
        dock('start', endpoint_id)
        wait((control / 'endpoint-ready').exists, 'endpoint startup')
        holder = create('holder', args.holder_image, ['--network', network, '--ip', '203.0.113.20',
                        '--no-healthcheck', '--mount', f'type=volume,src={volume},dst=/ipc',
                        '-e', 'IRCFIBER_SERVER_ID=legacy-fixture', '-e', 'IRCFIBER_HOLDER_ADDR=unix:///ipc/holder.sock',
                        '-e', 'IRCFIBER_HOLDER_TOKEN=' + token, '-e', 'IRCFIBER_HOLDER_DETACH_MAX_SECS=120',
                        '--entrypoint', '/app/irc-fiber-holder'])
        dock('start', holder)
        pid = barrier.inspect(holder, deadline)['State']['Pid']
        wait(lambda: Path(f'/proc/{pid}/root/ipc/holder.sock').is_socket(), 'holder startup')
        generation = barrier.proc_generation(pid)
        # 1: established socket, then engine exits. Keep socket identity and PONG.
        first = start_client('established')
        wait((control / 'hello-1').exists, 'first ClientHello')
        (control / 'release-1').write_text('success')
        connected = wait(lambda: (control / 'connected-established').exists(), 'CONNECTED')
        connected = json.loads((control / 'connected-established').read_text())
        stop_client(first)
        obs = observer(pid)
        listen = listener(pid)
        evidence = wait(lambda: eligible(barrier, pid, listen, obs, deadline), 'established relay detach')
        original_inet = evidence['inet']
        assert original_inet, 'physical upstream FD missing'
        held = obs.request('LIST', {})['connections']
        assert any(e['id'] == connected['id'] and e['connectedAtMs'] == connected['connectedAtMs'] for e in held)
        (control / 'ping-1').write_text('PING')
        wait((control / 'pong-1').exists, 'detached holder PONG')
        # 2/3: late TLS success/failure, no LIST-visible entry while pending.
        for serial, outcome in ((2, 'success'), (3, 'failure')):
            child = start_client('late-' + outcome)
            wait((control / f'hello-{serial}').exists, 'gated ClientHello')
            stop_client(child)
            before = obs.request('LIST', {})['connections']
            rejection(lambda: barrier.inventory(pid, listen, obs.inode, deadline), 'orphan pending DIAL')
            (control / f'release-{serial}').write_text(outcome)
            wait(lambda: eligible(barrier, pid, listen, obs, deadline), 'late completion cleanup')
            after = obs.request('LIST', {})['connections']
            if outcome == 'success':
                assert len(after) == len(before) + 1
                (control / f'ping-{serial}').write_text('PING')
                wait((control / f'pong-{serial}').exists, 'late-held PONG')
            else:
                assert len(after) == len(before)
        # Unknown partial/idle/authenticated streams cannot be exempted.
        for wire in (b'', b'HE', ('HELLO ' + json.dumps({'proto': 1, 'serverId': 'legacy-fixture',
                                                     'token': token}) + '\n').encode()):
            with socket.socket(socket.AF_UNIX) as unknown:
                unknown.connect(f'/proc/{pid}/root/ipc/holder.sock')
                if wire:
                    unknown.sendall(wire)
                # This newly accepted observer orders the unknown before scan.
                sentinel = observer(pid)
                obs.close()
                obs = sentinel
                rejection(lambda: barrier.inventory(pid, listen, obs.inode, deadline), 'unknown stream')
            wait(lambda: eligible(barrier, pid, listen, obs, deadline), 'unknown cleanup')
        # Queue before accept, then orphan the actual in-flight TLS handshake.
        # This older holder aborts before ClientHello if EOF precedes its first
        # EVENT write; keep the client until the peer proves handshake progress.
        with socket.socket(socket.AF_UNIX) as queued:
            os.kill(pid, signal.SIGSTOP)
            try:
                queued.connect(f'/proc/{pid}/root/ipc/holder.sock')
                queued.sendall(('DIAL ' + json.dumps({'token': token, 'host': '203.0.113.90', 'port': 6697,
                    'tls': 'implicit', 'sni': 'legacy-barrier.fixture.invalid', 'tlsTimeoutMs': 25000,
                    'proxy': {'host': '203.0.113.10', 'port': 1080}}) + '\n').encode())
            finally:
                os.kill(pid, signal.SIGCONT)
            obs.close()
            obs = observer(pid)
            wait((control / 'hello-4').exists, 'queued ClientHello')
            queued.close()
            rejection(lambda: barrier.inventory(pid, listen, obs.inode, deadline), 'queued orphan')
            (control / 'release-4').write_text('failure')
            wait(lambda: eligible(barrier, pid, listen, obs, deadline), 'queued failure cleanup')
        # Real truncated kernel dump, not mocked output or source assertions.
        with barrier.network_namespace(pid):
            request = struct.pack('=BBHIIIII', socket.AF_UNIX, 0, 0, 0xffffffff, 0, 31, 0xffffffff, 0xffffffff)
            rejection(lambda: barrier.diag_dump(request, deadline, receive_bytes=1), 'truncated dump')
        nobody = os.fork()
        if nobody == 0:
            try:
                os.setgroups([])
                os.setgid(65534)
                os.setuid(65534)
                try:
                    barrier.owned_fds(pid)
                except OSError:
                    os._exit(0)
                os._exit(1)
            except BaseException:
                os._exit(2)
        _, status = os.waitpid(nobody, 0)
        assert os.waitstatus_to_exitcode(status) == 0, 'inaccessible proc inventory did not fail closed'
        current = barrier.inventory(pid, listen, obs.inode, deadline)
        assert all(entry in current['inet'] for entry in original_inet), 'established upstream identity changed'
        assert not (control / 'closed-1').exists()
        assert barrier.proc_generation(pid) == generation
        obs.close()
        # Full CLI: unknown image rejected BEFORE old-client stop. Then exercise
        # synchronous candidate activation using a disposable fixture attestation.
        old = start_client('activation')
        wait((control / 'hello-5').exists, 'activation ClientHello')
        staged = create('candidate', tool_image, ['--network', network,
                        '--mount', f'type=volume,src={volume},dst=/ipc',
                        '--mount', f'type=bind,src={control},dst=/control'])
        manifest = root / 'provenance.json'
        manifest.write_text(json.dumps({'schema': 1, 'holders': []}))
        os.chmod(manifest, 0o600)
        command = [sys.executable, args.helper, '--holder', holder, '--engine', old,
                   '--candidate-container', staged, '--socket', '/ipc/holder.sock', '--server-id', 'legacy-fixture',
                   '--token-file', str(token_file), '--provenance', str(manifest), '--replacement-image', tool_image,
                   '--lock', str(root / 'deploy.lock'), '--deadline', '30', '--engine-stop-timeout', '2']
        refused = subprocess.run(command, capture_output=True, text=True, timeout=35)
        assert refused.returncode and barrier.inspect(old, deadline)['State']['Running']
        assert not (control / 'candidate-started').exists()
        manifest.write_text(json.dumps({'schema': 1, 'holders': [{'image': args.holder_image,
            'executableSha256': generation['exe'],
            'acceptModel': 'single-sequential-accept-fd-installed-before-callback',
            'streamLifetime': 'accepted-fd-retained-through-dial-and-relay',
            'evidenceSha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}]}))
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def source_stopped():
            if process.poll() is not None:
                raise RuntimeError('barrier exited before source closure: ' + process.stderr.read()[-6000:])
            return not barrier.inspect(old, deadline)['State']['Running']
        wait(source_stopped, 'CLI old generation exit')
        wait(lambda: any(Path(f'/proc/{pid}/root/ipc').glob('.legacy-barrier-*')), 'CLI endpoint fence')
        assert process.poll() is None and not (control / 'candidate-started').exists()
        (control / 'release-5').write_text('success')
        stdout, stderr = process.communicate(timeout=35)
        assert process.returncode == 0, stderr
        result = json.loads(stdout)
        assert result['activated'] and result['proof']['candidate'] == staged
        wait((control / 'candidate-started').exists, 'candidate activation')
        (control / 'ping-5').write_text('PING')
        wait((control / 'pong-5').exists, 'activation preserves late-held upstream')
        assert all(entry in result['proof']['sockets']['inet'] for entry in original_inet)
        (control / 'reping-1').write_text('PING after barrier')
        wait((control / 'repong-1').exists, 'original held upstream PONG after activation')
        assert barrier.proc_generation(pid) == generation
        assert not barrier.inspect(old, deadline)['State']['Running']
        assert not (control / 'closed-1').exists()
        # Generation loss is physical, at end after preservation assertions.
        dock('stop', '--timeout', '2', holder)
        rejection(lambda: barrier.require(barrier.proc_generation(pid) == generation,
                                         'holder generation changed'), 'holder generation loss')
        print(json.dumps({'passed': True, 'olderHolderImage': args.holder_image,
                          'olderHolderExeSha256': generation['exe'],
                          'productionProvenance': False, 'heldIdentityPreserved': connected['id']}))
    finally:
        for cid in reversed(containers):
            current = dock('inspect', cid, check=False)
            if current.returncode == 0:
                assert json.loads(current.stdout)[0]['Config']['Labels'].get('ircfiber.fixture.run') == tag
                dock('rm', '-f', cid)
        if volume:
            assert json.loads(dock('volume', 'inspect', volume).stdout)[0]['Labels'].get('ircfiber.fixture.run') == tag
            dock('volume', 'rm', volume)
        if network:
            assert json.loads(dock('network', 'inspect', network).stdout)[0]['Labels'].get('ircfiber.fixture.run') == tag
            dock('network', 'rm', network)
        if tool_image:
            dock('image', 'rm', tag + ':tools')
        if base_image_tag:
            assert json.loads(dock('image', 'inspect', base_image_tag).stdout)[0]['Id'] == args.tools_image
            dock('image', 'rm', base_image_tag)
        shutil.rmtree(root)


def eligible(barrier, pid, listen, observer, deadline):
    try:
        before = barrier.inventory(pid, listen, observer.inode, deadline)
        held = observer.request('LIST', {})
        after = barrier.inventory(pid, listen, observer.inode, deadline)
        barrier.require(before == after, 'socket inventory changed across fixture LIST')
        barrier.match_held_sockets(after, held)
        return after
    except barrier.Blocked as error:
        eligible.last_error = str(error)
        return None


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] in ('endpoint', 'client', 'candidate'):
        {'endpoint': endpoint, 'client': client, 'candidate': candidate}[sys.argv[1]]()
    else:
        driver()
