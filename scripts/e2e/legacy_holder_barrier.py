#!/usr/bin/env python3
"""Physical first-upgrade smoke, run ON the disposable Linux Docker host as root.

Requires locally loaded immutable --holder-image (UNCHANGED older binary) and
--tools-image (Python 3.11+ with ssl). Never pulls/builds/replaces a holder.
The tiny tool/candidate image is built only from the supplied local tools image.
No published ports, production storage, public IRC or existing holders touched.
Fixture-generated provenance is TEST EVIDENCE ONLY, never production approval.
Recovery cases always run and also require local qualified engine, Redis and Mongo
images. Resolve ambiguous/missing local dependencies explicitly (IDs, never tags):
  python3 legacy_holder_barrier.py --holder-image "$LEGACY_ID" --tools-image "$PYTHON_ID" \\
    --engine-image "$ENGINE_ID" --redis-image "$REDIS_ID" --mongo-image "$MONGO_ID" \\
    --helper /root/history-proof/legacy-holder-barrier.py
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
import uuid
import zlib


# Reviewed source/build receipt, not a fixture-generated lifecycle assertion.
# Exact source fea67fb48f89 and BuildKit attachment are in the reviewed evidence
# bundle whose manifest hash is evidenceSha256. Never broaden this image binding.
REVIEWED_LEGACY = {
    'image': 'sha256:8e7447fa51f9b2fa88fb4b88de8687af6483d8e078c147181469125bc0d82f09',
    'executableSha256': 'f0d444d4dfab2058e15e8e0f4ecc28398f854fd9fd7f344a37135b1cea72fc53',
    'acceptModel': 'single-sequential-accept-fd-installed-before-callback',
    'streamLifetime': 'accepted-fd-retained-through-dial-and-relay',
    'evidenceSha256': 'f793c9a5cb1104e626cf6e8e2fd160beab6f27264fb0b4a98752c6f7351f1c9a',
}

# Parent-reviewed exact held.d/ipc.d lifetime evidence; a separate recovery-only
# receipt extends, and links back to, the ordinary reviewed bundle above.
REVIEWED_RECOVERY = {
    **REVIEWED_LEGACY,
    'heldSocketLifetime': 'held-id-and-connectedAtMs-bind-one-upstream-until-close',
    'evidenceSha256': 'dd4fbba625839e22539f82107132a20dc8b7023feca1fa7d99ce1a291d0a5f25',
}


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


def recovery_endpoint():
    """A real private IRC peer; injection is acknowledged only after sendall."""
    root = Path('/control')
    if not os.environ.get('FIXTURE_PLAIN_ONLY'):
        threading.Thread(target=endpoint, daemon=True).start()
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('0.0.0.0', int(os.environ.get('FIXTURE_IRC_PORT', '16667'))))
        listener.listen()
        (root / 'irc-ready').write_text('ready')
        conn, peer = listener.accept()
        (root / 'irc-peer').write_text(json.dumps(peer))
        with conn:
            stream = conn.makefile('rb')
            send_lock = threading.Lock()
            def send(line):
                with send_lock:
                    conn.sendall((line + '\r\n').encode())
            def inject():
                while True:
                    target = root / 'inject'
                    if target.exists():
                        marker = target.read_text()
                        send(':peer!fixture@private PRIVMSG #proof :' + marker)
                        (root / ('sent-' + marker)).write_text(str(time.time_ns()))
                        target.unlink()
                    time.sleep(0.01)
            threading.Thread(target=inject, daemon=True).start()
            nick, user, welcomed, cap_finished = '', False, False, True
            while True:
                raw = stream.readline(65536)
                if not raw:
                    (root / 'irc-closed').write_text('EOF')
                    return
                line = raw.decode().strip()
                parts = line.split()
                if not parts:
                    continue
                verb = parts[0].upper()
                if verb == 'CAP' and 'LS' in parts:
                    cap_finished = False
                    send(':fixture CAP * LS :')
                elif verb == 'CAP' and 'REQ' in parts:
                    send(':fixture CAP * NAK :' + line.split(':', 1)[-1])
                elif verb == 'CAP' and 'END' in parts:
                    cap_finished = True
                elif verb == 'NICK':
                    nick = parts[1]
                elif verb == 'USER':
                    user = True
                elif verb == 'PING':
                    send('PONG :' + line.split(':', 1)[-1])
                elif verb == 'JOIN':
                    send(':' + nick + '!fixture@private JOIN ' + parts[1])
                    send(':fixture 366 ' + nick + ' ' + parts[1] + ' :End of NAMES')
                    (root / 'irc-joined').write_text(parts[1])
                if nick and user and cap_finished and not welcomed:
                    send(':fixture 001 ' + nick + ' :Welcome to the private physical fixture')
                    send(':fixture 376 ' + nick + ' :End of MOTD')
                    welcomed = True
                    (root / 'irc-registered').write_text(nick)


def recovery_suite(args):
    """Full CLI recovery, real application/journals/Redis and kernel witnesses."""
    assert Path(args.helper).with_name('ircfiber-history-recovery.py').is_file(), 'adjacent recovery helper required'
    assert args.holder_image == REVIEWED_LEGACY['image'], 'recovery requires the exact reviewed legacy image'
    deadline = time.monotonic() + 900
    def dock(*argv, check=True):
        result = subprocess.run(['docker', '--host', 'unix:///var/run/docker.sock', *argv],
                                capture_output=True, text=True,
                                timeout=max(1, deadline - time.monotonic()))
        if check and result.returncode:
            raise RuntimeError('recovery fixture Docker ' + argv[0] + ': ' + result.stderr[-6000:])
        return result
    def resolve(value, repository, component=None):
        if value:
            assert value.startswith('sha256:') and len(value) == 71, 'immutable recovery image ID required'
            assert json.loads(dock('image', 'inspect', value).stdout)[0]['Id'] == value
            return value
        images = [json.loads(row) for row in
                  dock('image', 'ls', '--no-trunc', '--format', '{{json .}}').stdout.splitlines()]
        ids = set()
        for image in images:
            if component:
                labels = json.loads(dock('image', 'inspect', image['ID']).stdout)[0]['Config'].get('Labels') or {}
                if (labels.get('com.ircfiber.coordinated-exclusion-version') == '1' and
                        component in labels.get('com.ircfiber.coordinated-exclusion-component', '').split(',')):
                    ids.add(image['ID'])
            elif image['Repository'] == repository:
                ids.add(image['ID'])
        assert len(ids) == 1, 'provide --' + repository + '-image: local immutable dependency is absent/ambiguous'
        return ids.pop()
    engine_image = resolve(args.engine_image, 'engine', 'engine')
    redis_image = resolve(args.redis_image, 'redis')
    mongo_image = resolve(args.mongo_image, 'mongo')
    spec = importlib.util.spec_from_file_location('recovery_barrier', args.helper)
    barrier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(barrier)
    spec = importlib.util.spec_from_file_location('fixture_maintenance',
                                                 Path(args.helper).with_name('ircfiber-holder-maintenance.py'))
    maintenance = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(maintenance)
    native_docker = maintenance.Docker()
    authority = Path(args.holder_recovery_provenance or
                     Path(args.helper).with_name('holder-recovery-provenance.json'))
    review_path = authority.with_name('holder-held-lifetime-review.json')
    bundle_path = authority.with_name('ircfiber-legacy-holder-reviewed-evidence.zip')
    authority_hashes = {
        authority: '913fe990ee55e2c0cfc81360fe4e24ce019caadb8b51ebac8e6cec04d1cc2d2d',
        review_path: REVIEWED_RECOVERY['evidenceSha256'],
        bundle_path: REVIEWED_LEGACY['evidenceSha256'],
    }
    assert barrier.trusted_json(authority) == {'schema': 1, 'holders': [REVIEWED_RECOVERY]}
    review = barrier.trusted_json(review_path)
    assert review['imageId'] == args.holder_image and review['executableSha256'] == REVIEWED_LEGACY['executableSha256']
    assert review['assertion'] == REVIEWED_RECOVERY['heldSocketLifetime']
    for path, expected in authority_hashes.items():
        st = path.lstat()
        assert not path.is_symlink() and path.is_file() and st.st_uid == 0 and st.st_nlink == 1 and not st.st_mode & 0o022
        digest = hashlib.sha256()
        with path.open('rb') as source:
            while chunk := source.read(1 << 20):
                digest.update(chunk)
        assert digest.hexdigest() == expected, 'reviewed authority file changed: ' + path.name
    results = []
    for case in ('missing-provenance', 'missing-held-lifetime', 'changed-token', 'lost-ownership',
                 'failed-graceful-drain', 'unknown-accepted', 'inflight-dial'):
        tag = 'history-physical-' + secrets.token_hex(8)
        label = 'ircfiber.fixture.run=' + tag
        base = Path('/var/lib/ircfiber-barrier-fixture')
        root = Path(tempfile.mkdtemp(prefix=tag + '-', dir=base))
        os.chmod(root, 0o700)
        control = root / 'control'
        control.mkdir(mode=0o777)
        os.chmod(control, 0o777)
        (control / 'token').write_text('')
        (root / 'token.json').write_text('""')
        os.chmod(root / 'token.json', 0o600)
        archive = root / 'archive'
        archive.mkdir(mode=0o700)
        os.chmod(archive, 0o700)
        containers, volumes = [], []
        network, process, unknown, paused = None, None, None, None
        stdout = stderr = ''
        def create(name, image, options, command=()):
            cid = dock('create', '--name', tag + '-' + name, '--label', label, '--restart=no',
                       *options, image, *command).stdout.strip()
            containers.append(cid)
            return cid
        def redis(*argv):
            return dock('exec', redis_id, 'redis-cli', '--raw', *map(str, argv)).stdout.strip()
        def mongo(script):
            return dock('exec', mongo_id, 'mongosh', '--quiet', 'ircfiber_history_physical_test',
                        '--eval', script).stdout.strip()
        def info(cid):
            return json.loads(dock('inspect', cid).stdout)[0]
        def reservation():
            return redis('HGETALL', dial_key)
        def live_marker(marker):
            return [row for row in redis('LRANGE', 'scrollback:ovh:' + healthy + ':#proof', 0, -1).splitlines()
                    if marker in row]
        def writer_gate_counts():
            return {'writerType': redis('TYPE', 'irc:holder:maintenance:writers'),
                    'writerCount': redis('SCARD', 'irc:holder:maintenance:writers'),
                    'writerTTL': redis('TTL', 'irc:holder:maintenance:writers'),
                    'globalExists': redis('EXISTS', 'irc:holder:maintenance:write-exclusion'),
                    'serverExists': redis('EXISTS', 'irc:holder:maintenance:exclusion:ovh')}
        try:
            network = dock('network', 'create', '--internal', '--subnet', '203.0.113.0/24',
                           '--label', label, tag).stdout.strip()
            volume = dock('volume', 'create', '--label', label, tag + '-ipc').stdout.strip()
            volumes.append(volume)
            for directory in ('redis-data', 'mongo-data', 'mongo-config'):
                (root / directory).mkdir(mode=0o777)
                os.chmod(root / directory, 0o777)
            redis_id = create('redis', redis_image, ['--network', network, '--ip', '203.0.113.2',
                              '--memory', '3g', '--memory-swap', '4608m',
                              '--mount', f'type=bind,src={root / "redis-data"},dst=/data'],
                              ['redis-server', '--save', '', '--appendonly', 'yes', '--appendfsync', 'everysec',
                               '--maxmemory', '512mb', '--maxmemory-policy', 'noeviction'])
            mongo_id = create('mongo', mongo_image, ['--network', network, '--ip', '203.0.113.3',
                              '--label', 'com.ircfiber.component=mongo',
                              '--mount', f'type=bind,src={root / "mongo-data"},dst=/data/db',
                              '--mount', f'type=bind,src={root / "mongo-config"},dst=/data/configdb'],
                              ['mongod', '--bind_ip_all'])
            dock('start', redis_id, mongo_id)
            wait(lambda: dock('exec', redis_id, 'redis-cli', '--raw', 'PING', check=False).stdout.strip() == 'PONG',
                 'recovery Redis')
            wait(lambda: dock('exec', mongo_id, 'mongosh', '--quiet', '--eval',
                              'print(db.runCommand({ping:1}).ok)', check=False).stdout.strip() == '1',
                 'recovery Mongo', 40)
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                            '-subj', '/CN=legacy-barrier.fixture.invalid', '-keyout', str(control / 'key.pem'),
                            '-out', str(control / 'cert.pem')], check=True, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=20)
            peer = create('peer', args.tools_image, ['--network', network, '--ip', '203.0.113.10',
                          '--mount', f'type=bind,src={control},dst=/control',
                          '--mount', f'type=bind,src={Path(__file__).resolve()},dst=/fixture.py,readonly',
                          '--entrypoint', 'python3'], ['-u', '/fixture.py', 'recovery-endpoint'])
            blocked_control = root / 'blocked-control'
            blocked_control.mkdir(mode=0o777)
            os.chmod(blocked_control, 0o777)
            blocked_peer = create('blocked-peer', args.tools_image, ['--network', 'container:' + peer,
                          '--mount', f'type=bind,src={blocked_control},dst=/control',
                          '--mount', f'type=bind,src={Path(__file__).resolve()},dst=/fixture.py,readonly',
                          '-e', 'FIXTURE_PLAIN_ONLY=1', '-e', 'FIXTURE_IRC_PORT=16668', '--entrypoint', 'python3'],
                          ['-u', '/fixture.py', 'recovery-endpoint'])
            holder = create('holder', args.holder_image, ['--network', network, '--ip', '203.0.113.20',
                            '--label', 'com.ircfiber.component=holder', '--no-healthcheck',
                            '--mount', f'type=volume,src={volume},dst=/ipc',
                            '-e', 'IRCFIBER_SERVER_ID=ovh', '-e', 'IRCFIBER_HOLDER_ADDR=unix:///ipc/holder.sock',
                            '-e', 'IRCFIBER_HOLDER_TOKEN=', '-e', 'IRCFIBER_HOLDER_DETACH_MAX_SECS=600',
                            '-e', 'IRCFIBER_HOLDER_DETACH_BUFFER_BYTES=4194304',
                            '--entrypoint', '/app/irc-fiber-holder'])
            dock('start', peer, blocked_peer, holder)
            pid = info(holder)['State']['Pid']
            wait(lambda: Path(f'/proc/{pid}/root/ipc/holder.sock').is_socket() and
                 (control / 'irc-ready').exists() and (control / 'endpoint-ready').exists() and
                 (blocked_control / 'irc-ready').exists(), 'recovery peers')
            generation = barrier.proc_generation(pid)
            healthy, blocked, owner = (str(uuid.uuid4()) for _ in range(3))
            initial_observer = barrier.Observer(pid, f'/proc/{pid}/root/ipc/holder.sock', 'ovh', '', deadline)
            try:
                holder_status = initial_observer.request('STATUS', {})
            finally:
                initial_observer.close()
            token = secrets.token_hex(16)
            dial_key = 'irc:routing:dials:ovh:' + blocked
            dial_value = 'holder_v1:legacy-pid:' + str(holder_status['pid'])
            redis('HSET', dial_key, token, dial_value)
            for ident, nick, port in ((healthy, 'PhysicalHealthy', 16667), (blocked, 'PhysicalBlocked', 16668)):
                doc = {'id': ident, 'userId': owner, 'name': nick, 'host': '203.0.113.10', 'port': port,
                       'tls': 'disabled', 'nick': nick, 'realName': 'Private physical proof', 'ident': 'fixture',
                       'disabled': False, 'ipv6Iid': 'a5' + secrets.token_hex(7), 'autoJoinChannels': ['#proof'],
                       'routing': {'order': ['direct'], 'preferredExit': ''},
                       'archiveScopeVersion': 1, 'archiveServers': ['ovh']}
                mongo('db.networks.insertOne(' + json.dumps(doc) + ')')
                redis('HSET', 'irc:assignments', ident, 'ovh')
                redis('SADD', 'irc:server-assignments:ovh', ident)
                redis('SET', 'irc:archive:owner:' + ident,
                      json.dumps({'version': 1, 'networkId': ident, 'serverId': 'ovh', 'servers': ['ovh']}))
            redis('SET', 'irc:config:fiberEnabled', '0')
            redis('SET', 'irc:config:routingSchemaVersion', '1')
            redis('SET', 'irc:config:egressRoutingPolicy', json.dumps(
                {'schema': 1, 'revision': 0, 'global': {'order': ['direct'], 'blockedRoutes': []}, 'hosts': []}))
            engine_options = ['--network', network, '--label', 'com.ircfiber.component=engine',
                              '--hostname', tag + '-engine',
                              '--mount', f'type=volume,src={volume},dst=/ipc,readonly',
                              '--mount', f'type=bind,src={archive},dst=/var/lib/ircfiber/archive',
                              '-e', 'IRCFIBER_SERVER_ID=ovh', '-e', 'IRCFIBER_HOLDER_ADDR=unix:///ipc/holder.sock',
                              '-e', 'IRCFIBER_REDIS_URL=redis://203.0.113.2:6379/0',
                              '-e', 'IRCFIBER_MONGO_URL=mongodb://203.0.113.3:27017/ircfiber_history_physical_test',
                              '-e', 'IRCFIBER_ARCHIVE_DIR=/var/lib/ircfiber/archive',
                              '-e', 'IRCFIBER_ARCHIVE_MIN_FREE_BYTES=268435456',
                              '-e', 'IRCFIBER_OTEL_ENABLED=0', '-e', 'IRCFIBER_BUGSINK_ENABLED=0',
                              '--entrypoint', '/app/irc-fiber-engine']
            engine = create('engine', engine_image, engine_options)
            dock('start', engine)
            wait((control / 'irc-registered').exists, 'real IRC peer completes CAP registration', 60)
            wait(lambda: json.loads(redis('HGET', 'irc:state:ovh:' + healthy, 'data') or '{}').get('connected') and
                 (control / 'irc-joined').exists(), 'actual engine registered and joined before initial traffic', 30)
            def real_state_initialized():
                state = archive / 'state'
                if not state.is_file() or state.stat().st_size != 8 << 20:
                    return False
                with state.open('rb') as stream:
                    first = stream.read(8)
                    stream.seek(4 << 20)
                    second = stream.read(8)
                return b'IFASv001' in (first, second)
            wait(real_state_initialized, 'actual engine initializes its durable double-slot archive state', 30)
            uid = int(next(line.split()[2] for line in
                          Path(f"/proc/{info(engine)['State']['Pid']}/status").read_text().splitlines()
                          if line.startswith('Uid:')))
            assert archive.stat().st_uid == uid and not archive.stat().st_mode & 0o022
            assert (archive / 'state').stat().st_uid == uid and not (archive / 'state').stat().st_mode & 0o077
            original_marker = 'before-' + secrets.token_hex(12)
            (control / 'inject').write_text(original_marker)
            wait(lambda: live_marker(original_marker), 'actual engine hot storage', 30)
            assert len(live_marker(original_marker)) == 1
            assert not (blocked_control / 'irc-registered').exists(), 'captured reservation did not prevent target DIAL'
            # Clone the actual source Config, not another CLI reconstruction:
            # preserve environment ordering and every image default verbatim.
            # Network intent excludes its dynamically allocated IP/MAC, since
            # the retained stopped source keeps that allocation.
            source = info(engine)
            assert source['Image'] == engine_image
            requested = dict(source['Config'])
            requested['Image'] = source['Image']
            requested['HostConfig'] = dict(source['HostConfig'])
            requested['HostConfig']['RestartPolicy'] = {'Name': 'no', 'MaximumRetryCount': 0}
            requested['NetworkingConfig'] = {'EndpointsConfig': {
                name: {key: value for key, value in endpoint.items()
                       if key in ('IPAMConfig', 'Links', 'DriverOpts', 'Aliases') and value}
                for name, endpoint in source['NetworkSettings']['Networks'].items()}}
            candidate_id = native_docker.request('POST', '/containers/create?name=' + tag + '-candidate', requested)['Id']
            containers.append(candidate_id)
            expected = maintenance.exact_create(source, source['Image'], native_docker.image(source['Image'])['Config'],
                                                required_ipc_mount='/ipc')
            expected_config = {key: value for key, value in expected.items() if key not in ('HostConfig', 'NetworkingConfig')}
            actual_config = info(candidate_id)['Config']
            differences = sorted(key for key in set(expected_config) | set(actual_config)
                                 if expected_config.get(key) != actual_config.get(key) or
                                 (key in expected_config) != (key in actual_config))
            print(json.dumps({'candidateConfigDifferingKeys': differences}), flush=True)
            assert not differences, 'exact cloned candidate Config differs from source'
            observation = barrier.Observer(pid, f'/proc/{pid}/root/ipc/holder.sock', 'ovh', '', deadline)
            original_held = observation.request('LIST', {})['connections']
            assert observation.request('STATUS', {})['pid'] == holder_status['pid']
            original_ids = {(row['id'], row['connectedAtMs']) for row in original_held if row['state'] == 'open'}
            assert len(original_ids) == 1, 'unique legacy socket/entry binding required'
            owned_inodes = set(barrier.owned_fds(pid).values())
            # An attached relay is expected at baseline; capture the physical
            # upstream denominator directly, without exempting its IPC stream.
            original_inet = {inode: row for inode, row in barrier.diagnostics(pid, deadline)[1].items()
                             if inode in owned_inodes}
            observation.close()
            manifest = {'version': 1, 'operationId': str(uuid.uuid4()), 'serverId': 'ovh',
                        'holderContainerId': holder, 'holderImageId': args.holder_image,
                        'redisContainerId': redis_id,
                        'redisRunId': next(line.split(':', 1)[1] for line in redis('INFO', 'server').splitlines()
                                           if line.startswith('run_id:')),
                        'reservations': [{'networkId': blocked, 'token': token, 'value': dial_value}], 'lineage': []}
            manifest_path = root / 'recovery.json'
            manifest_path.write_text(json.dumps(manifest))
            os.chmod(manifest_path, 0o600)
            assert generation['exe'] == REVIEWED_LEGACY['executableSha256'], 'reviewed legacy executable differs'
            authority_dir = root / 'authority'
            authority_dir.mkdir(mode=0o700)
            for path in authority_hashes:
                shutil.copyfile(path, authority_dir / path.name)
                os.chmod(authority_dir / path.name, 0o600)
            provenance = authority_dir / authority.name
            if case in ('missing-provenance', 'missing-held-lifetime'):
                provenance = root / 'provenance-negative.json'
                provenance.write_text(json.dumps({'schema': 1, 'holders':
                    [] if case == 'missing-provenance' else [REVIEWED_LEGACY]}))
                os.chmod(provenance, 0o600)
            if case == 'changed-token':
                redis('HDEL', dial_key, token)
                redis('HSET', dial_key, secrets.token_hex(16), dial_value)
            before = reservation()
            if case in ('lost-ownership', 'unknown-accepted'):
                unknown = socket.socket(socket.AF_UNIX)
                unknown.connect(f'/proc/{pid}/root/ipc/holder.sock')
                unknown.sendall(b'HE')
                # A later authenticated observer orders accept after this
                # partial stream. Kernel ownership independently proves it is
                # accepted, not merely waiting in the listener backlog.
                sentinel = barrier.Observer(pid, f'/proc/{pid}/root/ipc/holder.sock', 'ovh', '',
                                            min(deadline, time.monotonic() + 10))
                try:
                    unix, _ = barrier.diagnostics(pid, deadline)
                    owned = set(barrier.owned_fds(pid).values())
                    peer_inode = os.fstat(unknown.fileno()).st_ino
                    assert any(inode in owned and row['peer'] == peer_inode and row['state'] == 1
                               for inode, row in unix.items()), 'unknown IPC stream was not positively accepted'
                finally:
                    sentinel.close()
            if case in ('failed-graceful-drain', 'inflight-dial'):
                paused = info(engine)['State']['Pid']
                os.kill(paused, signal.SIGSTOP)
            source_started_at = info(engine)['State']['StartedAt']
            evidence_root = Path('/var/lib/ircfiber/history-recovery') / manifest['operationId']
            command = [sys.executable, args.helper, '--holder', holder, '--engine', engine,
                       '--candidate-container', candidate_id, '--socket', '/ipc/holder.sock', '--server-id', 'ovh',
                       '--token-file', str(root / 'token.json'), '--provenance', str(provenance),
                       '--replacement-image', engine_image, '--lock', str(root / 'deploy.lock'),
                       '--deadline', '45' if case == 'failed-graceful-drain' else '90',
                       '--engine-stop-timeout', '120' if case == 'failed-graceful-drain' else '15',
                       '--recovery-manifest', str(manifest_path)]
            print(json.dumps({'case': case, 'writerGateBeforeHelper': writer_gate_counts()}), flush=True)
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if case == 'inflight-dial':
                evidence = evidence_root / 'before.json'
                wait(evidence.exists, 'healthy baseline durably captured before unknown DIAL', 20)
                unknown = socket.socket(socket.AF_UNIX)
                unknown.connect(f'/proc/{pid}/root/ipc/holder.sock')
                unknown.sendall(('DIAL ' + json.dumps({'token': '', 'host': '203.0.113.90', 'port': 6697,
                    'tls': 'implicit', 'sni': 'legacy-barrier.fixture.invalid',
                    'proxy': {'host': '203.0.113.10', 'port': 1080}, 'tlsTimeoutMs': 25000,
                    'tag': {'networkId': blocked, 'name': 'pending-private'}}) + '\n').encode())
                wait((control / 'hello-1').exists, 'real unknown TLS ClientHello')
                unknown.close()
                unknown = None
                os.kill(paused, signal.SIGCONT)
                paused = None
            if case in ('lost-ownership', 'unknown-accepted', 'inflight-dial'):
                def source_exited():
                    if process.poll() is not None:
                        raise AssertionError('recovery refused before physical case: ' + process.stderr.read()[-6000:])
                    return not info(engine)['State']['Running']
                wait(source_exited, 'natural engine shutdown', 30)
                assert reservation() == before, 'reservation retired before physical exclusion'
                detach_marker = 'detached-' + secrets.token_hex(12)
                (control / 'inject').write_text(detach_marker)
                wait((control / ('sent-' + detach_marker)).exists, 'real plaintext sent during detach')
                assert not live_marker(detach_marker), 'detached traffic reached a stopped engine'
                if case == 'lost-ownership':
                    wait(lambda: redis('GET', 'irc:holder:maintenance:write-exclusion'), 'owned writer gate')
                    foreign_gate = 'foreign-' + secrets.token_hex(16)
                    redis('SET', 'irc:holder:maintenance:write-exclusion', foreign_gate)
                if unknown is not None:
                    unknown.close()
                    unknown = None
                if case == 'inflight-dial':
                    (control / 'release-1').write_text('failure')
            stdout, stderr = process.communicate(timeout=100)
            if case in ('unknown-accepted', 'inflight-dial'):
                assert process.returncode == 0, stderr[-6000:]
                result = json.loads(stdout)
                assert result.get('activated'), result
                assert not redis('HGET', dial_key, token), 'captured reservation was not retired'
                wait((blocked_control / 'irc-registered').exists, 'repaired target real IRC registration', 40)
                wait(lambda: json.loads(redis('HGET', 'irc:state:ovh:' + blocked, 'data') or '{}').get('connected'),
                     'engine confirms repaired target registration', 30)
                assert not reservation(), 'repaired target left another uncertain reservation'
                wait(lambda: len(live_marker(detach_marker)) == 1, 'buffered plaintext received after candidate reattach', 30)
                archived_query = {'serverId': 'ovh', 'networkId': healthy, 'channel': '#proof',
                                  'payload': {'$regex': detach_marker}}
                wait(lambda: mongo('print(db.messages.countDocuments(' + json.dumps(archived_query) + '))') == '1',
                     'same detached plaintext reaches actual Mongo archive', 30)
                after = barrier.Observer(pid, f'/proc/{pid}/root/ipc/holder.sock', 'ovh', '', deadline)
                try:
                    held = after.request('LIST', {})['connections']
                    current_ids = {(row['id'], row['connectedAtMs']) for row in held if row['state'] == 'open'}
                    assert original_ids < current_ids and len(current_ids) == len(original_ids) + 1
                    targets = [row for row in held if row['state'] == 'open' and
                               row.get('tag', {}).get('networkId') == blocked]
                    assert len(targets) == 1, 'repaired target has duplicate/missing holder upstream'
                    assert all(row.get('attached') is True for row in held if row['state'] == 'open')
                    assert len({(row['localIp'], row['peerIp']) for row in held if row['state'] == 'open'}) == 1, \
                        'positive case did not exercise ambiguous legacy LIST address pairs'
                    owned_inodes = set(barrier.owned_fds(pid).values())
                    physical = {inode: row for inode, row in barrier.diagnostics(pid, deadline)[1].items()
                                if inode in owned_inodes}
                    assert all(physical.get(inode) == row for inode, row in original_inet.items()), \
                        'original physical socket denominator changed'
                    added = [row for inode, row in physical.items() if inode not in original_inet]
                    assert len(added) == 1 and added[0]['peer'] == ['203.0.113.10', 16668], \
                        'unexpected extra physical target upstream'
                finally:
                    after.close()
                assert not (control / 'irc-closed').exists(), 'original private IRC connection closed'
                assert info(candidate_id)['State']['Running'] and not info(engine)['State']['Running']
                assert barrier.proc_generation(pid) == generation
            else:
                assert process.returncode != 0, 'unsafe recovery approval: ' + case
                assert reservation() == before, 'refusal mutated the full reservation: ' + case
                current_source = info(engine)['State']
                assert current_source['StartedAt'] == source_started_at, 'refusal restarted the source generation'
                assert info(candidate_id)['State']['Status'] == 'created', 'refusal started the never-started candidate'
                assert not (evidence_root / 'metadata-after.json').exists(), 'refusal reached metadata application'
                if case in ('missing-provenance', 'missing-held-lifetime'):
                    assert current_source['Running'], 'missing reviewed provenance stopped source'
                    assert not (evidence_root / 'before.json').exists(), 'provenance refusal passed source admission'
                else:
                    assert (evidence_root / 'before.json').is_file(), 'negative case did not reach its admitted boundary'
                if case == 'changed-token':
                    assert current_source['Running'] and not redis('HGET', dial_key, token)
                    assert not (evidence_root / 'journals.json').exists(), 'changed-token preflight stopped source'
                    gate = redis('GET', 'irc:holder:maintenance:write-exclusion')
                    assert gate and redis('GET', 'irc:holder:maintenance:exclusion:ovh') == gate
                if case == 'lost-ownership':
                    assert not current_source['Running'] and current_source['ExitCode'] == 0 and not current_source.get('OOMKilled')
                    assert redis('GET', 'irc:holder:maintenance:write-exclusion') == foreign_gate
                if case == 'failed-graceful-drain':
                    assert current_source['Running'] and not current_source.get('OOMKilled')
                    proc_stat = Path(f'/proc/{paused}/stat').read_text()
                    assert proc_stat[proc_stat.rindex(')') + 2] in ('T', 't'), 'drain fault did not stop the actual engine'
                    status = dict(line.split(':', 1) for line in Path(f'/proc/{paused}/status').read_text().splitlines()
                                  if ':' in line)
                    pending = int(status['SigPnd'].strip(), 16) | int(status['ShdPnd'].strip(), 16)
                    assert pending & (1 << (signal.SIGTERM - 1)), 'graceful-exit request never reached the stopped engine'
                    slots = []
                    with (archive / 'state').open('rb') as state:
                        for offset in (0, 4 << 20):
                            state.seek(offset)
                            header = state.read(24)
                            if header == bytes(24):
                                continue  # The never-written alternate slot is valid initial spool state.
                            assert header[:8] == b'IFASv001', 'actual engine state slot missing'
                            generation_s, length, checksum = struct.unpack('<QII', header[8:])
                            assert 0 < length <= (4 << 20) - 24
                            payload = state.read(length)
                            assert zlib.crc32(struct.pack('<Q', generation_s) + payload) == checksum
                            slots.append((generation_s, json.loads(payload)))
                    assert slots, 'no actual durable engine state'
                    assert max(slots, key=lambda slot: slot[0])[1]['unclean'] is True
            results.append({'case': case, 'passed': True, 'healthyDenominator': len(original_ids),
                            'holderGenerationPreserved': barrier.proc_generation(pid) == generation,
                            'detachedPlaintextReceived': case in ('unknown-accepted', 'inflight-dial'),
                            'operationId': manifest['operationId']})
            print(json.dumps({'caseAssertions': results[-1]}), flush=True)
        except BaseException:
            print('Recovery case ' + case + ' helper stderr: ' + stderr[-6000:], file=sys.stderr)
            try:
                print(json.dumps({'case': case, 'writerGateAtFailure': writer_gate_counts()}), file=sys.stderr)
            except Exception:
                print(json.dumps({'writerGateFailureDiagnosticUnavailable': True}), file=sys.stderr)
            for cid in containers:
                print(dock('logs', '--tail', '40', cid, check=False).stdout[-6000:], file=sys.stderr)
            raise
        finally:
            if unknown is not None:
                unknown.close()
            if paused is not None:
                try:
                    os.kill(paused, signal.SIGCONT)
                except ProcessLookupError:
                    pass
            if process is not None and process.poll() is None:
                process.terminate()
                process.communicate(timeout=10)
            for cid in reversed(containers):
                assert (info(cid)['Config'].get('Labels') or {}).get('ircfiber.fixture.run') == tag
                dock('rm', '-f', cid)
            for volume in volumes:
                assert json.loads(dock('volume', 'inspect', volume).stdout)[0]['Labels']['ircfiber.fixture.run'] == tag
                dock('volume', 'rm', volume)
            if network:
                assert json.loads(dock('network', 'inspect', network).stdout)[0]['Labels']['ircfiber.fixture.run'] == tag
                dock('network', 'rm', network)
            shutil.rmtree(root)
    print(json.dumps({'physicalRecovery': results, 'productionProvenance': False,
                      'engineImage': engine_image, 'redisImage': redis_image, 'mongoImage': mongo_image}))


def driver():
    source = Path(__file__).resolve()
    default_helper = source.with_name('legacy-holder-barrier.py')
    if not default_helper.is_file() and len(source.parents) > 3:
        default_helper = source.parents[3] / 'site/scripts/legacy-holder-barrier.py'
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--holder-image', required=True)
    p.add_argument('--tools-image', required=True)
    p.add_argument('--helper', default=str(default_helper))
    p.add_argument('--engine-image', help='immutable qualified engine; otherwise require one unambiguous local image')
    p.add_argument('--redis-image', help='immutable Redis; otherwise resolve the unique locally loaded redis repository')
    p.add_argument('--mongo-image', help='immutable Mongo; otherwise resolve the unique locally loaded mongo repository')
    p.add_argument('--holder-recovery-provenance', help='root-owned reviewed receipt; review and original bundle adjacent')
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
    recovery_suite(args)


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
    if len(sys.argv) > 1 and sys.argv[1] in ('endpoint', 'client', 'candidate', 'recovery-endpoint'):
        {'endpoint': endpoint, 'client': client, 'candidate': candidate,
         'recovery-endpoint': recovery_endpoint}[sys.argv[1]]()
    else:
        driver()
