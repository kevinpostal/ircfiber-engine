#!/usr/bin/env python3
"""Native Linux HOST ROOT child for the exact owned coordinated fixture.

No collector container, Docker-socket exemption, macOS emulation or synthetic
kernel evidence. All private inputs/outputs stay in a fresh root-owned host tree.
The full labelled container denominator and actual tool hashes are mandatory.
"""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import socket
import sys
import tarfile
import time
import types
import uuid

OLD = 'sha256:8e7447fa51f9b2fa88fb4b88de8687af6483d8e078c147181469125bc0d82f09'
OLD_REVISION = 'fea67fb48f891791a443367f9169ed32bc5a923e'
# OLD declares plain OLD_REVISION in its OCI revision and runtime build metadata.
# This digest is that Git revision's source, not a reproducible-binary claim.
# Reviewed source: HolderServer.onConnection -> handle -> dial -> dialUpstream
# synchronously, with the accepted control FD retained through relay. Actual
# image/executable identity and kernel accepted-FD/in-flight proof remain required.
OLD_IPC_SHA = '264822932e60e3c8200a8844a6cc21433be3c2e19635efe2ec0fca3e396b774f'
OLD_ENGINE = 'sha256:f9a5a59d2ba3ae99c002a1a6666007ecbe5bd36e032f8277622de7fbdbb06c89'
OLD_ENGINE_EXE = '44bd1b4b292e12a8c9ff63e127a9ecc64f59734f754836ff67f2b0f642c41861'
BASE = Path(os.environ['COORDINATED_ROOT_DIR'])
TOOLS = BASE / 'tools'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


m = load('coordinated_maintenance', TOOLS / 'ircfiber-holder-maintenance.py')
c = load('coordinated_collector', TOOLS / 'ircfiber-holder-coordinated.py')
k = c.load_kernel()


def require(ok, reason):
    m.require(ok, reason)


def manifest():
    require(sys.platform == 'linux' and os.geteuid() == 0 and os.uname().machine == 'x86_64' and
            Path('/sys/fs/cgroup/cgroup.controllers').exists() and not Path('/.dockerenv').exists() and
            os.readlink('/proc/self/ns/pid') == os.readlink('/proc/1/ns/pid'),
            'native Linux x86_64 HOST ROOT/PID namespace/cgroup-v2 required')
    require(BASE.is_absolute() and stat.S_ISSOCK(Path('/var/run/docker.sock').stat().st_mode),
            'exact native local Unix Docker socket required')
    for parent in (BASE, *BASE.parents):
        value = parent.lstat()
        require(value.st_uid == 0 and not value.st_mode & 0o022 and not stat.S_ISLNK(value.st_mode),
                'root evidence ancestry is writable/symlink/non-root')
    require(BASE.stat().st_mode & 0o077 == 0, 'root evidence is not private')
    spec = m.private_json(BASE / 'run.json')
    require(spec.get('version') == 1 and spec.get('sourceImageId') == OLD and
            spec.get('serverId') == 'fixture-regression' and
            re.fullmatch(r'regression-[a-zA-Z0-9_.-]+', spec.get('project', '')) and
            spec['run'] == spec['project'], 'fixture manifest scope mismatch')
    require(set(spec['toolHashes']) == {'ircfiber-holder-maintenance.py', 'ircfiber-holder-coordinated.py', 'legacy-holder-barrier.py'} and
            spec.get('fixtureRootSha256') == hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'complete actual tool/host-root fixture source hashes required')
    for name, digest in spec['toolHashes'].items():
        require(name in ('ircfiber-holder-maintenance.py', 'ircfiber-holder-coordinated.py', 'legacy-holder-barrier.py') and
                hashlib.sha256((TOOLS / name).read_bytes()).hexdigest() == digest,
                'actual collector source differs from recorded source')
    docker = m.Docker()
    info = docker.request('GET', '/info')
    require(re.fullmatch(r'colima(?:-[A-Za-z0-9_.-]+)?', info.get('Name', '')) and
            info.get('CgroupDriver') == 'systemd' and info.get('CgroupVersion') == '2' and
            not any('rootless' in option for option in info.get('SecurityOptions', [])),
            'only native owned Colima systemd/cgroup-v2 Docker daemon permitted')
    require(set(spec['containers']) == {'holder', 'engine', 'gateway', 'sysagent', 'redis', 'mongo',
                                      'mock-irc', 'egress-a', 'egress-b'},
            'complete exact fixture container manifest required')
    actual = docker.request('GET', '/containers/json?all=1')
    labelled = {item['Id'] for item in actual
                if (item.get('Labels') or {}).get('com.docker.compose.project') == spec['project']}
    allowed = {entry['id'] for entry in spec['containers'].values()}
    fence_path = BASE / 'activation/fence.json'
    if fence_path.exists():
        for service in ('holder', 'engine'):
            current_id = docker.inspect(spec['containers'][service]['name'])['Id']
            if service == 'holder' and current_id != spec['containers'][service]['id']:
                allowed.discard(spec['containers'][service]['id'])
            allowed.add(current_id)
    require(labelled == allowed, 'labelled all-container fixture denominator changed')
    for service, entry in spec['containers'].items():
        require(entry['name'].startswith(spec['project'] + '-') and 'ovh' not in entry['name'], 'production-like target forbidden')
        if service in ('holder', 'engine'):
            item = docker.inspect(entry['name'])
            if item['Id'] != entry['id']:
                fence = m.private_json(BASE / 'activation' / 'fence.json')
                expected = spec['candidateImageId'] if service == 'holder' else spec['engineImageId']
                require(fence['oldId' if service == 'holder' else 'oldEngineId'] == entry['id'] and item['Image'] == expected,
                        'unfenced fixture generation')
        else:
            item = docker.inspect(entry['id'])
        labels = item['Config'].get('Labels') or {}
        require(labels.get('ircfiber.fixture') == 'routing-regression' and
                labels.get('ircfiber.fixture.run') == spec['run'] and
                labels.get('com.docker.compose.project') == spec['project'] and
                labels.get('com.docker.compose.service') ==
                {'holder': 'ircfiber-holder', 'engine': 'ircfiber-engine', 'gateway': 'ircfiber-gateway',
                 'sysagent': 'ircfiber-sysagent'}.get(service, service), 'fixture container ownership mismatch')
        require(not any(str(BASE) == mount.get('Source') or
                        str(BASE).startswith(mount.get('Source', '').rstrip('/') + '/')
                        for mount in item.get('Mounts', []) if mount.get('Source')),
                'root-private evidence exposed to a container')
    return spec, docker


def image_binary_digest(docker, spec):
    """Hash the actual immutable-image executable without starting old code."""
    created = docker.request('POST', '/containers/create?name=' + spec['project'] + '-binary-proof', {
        'Image': OLD, 'Cmd': ['/bin/true'], 'Labels': {
            'ircfiber.fixture': 'routing-regression', 'ircfiber.fixture.run': spec['run'],
            'com.docker.compose.project': spec['project'], 'com.docker.compose.service': 'binary-proof'},
        'HostConfig': {'NetworkMode': 'none', 'RestartPolicy': {'Name': 'no'}, 'ReadonlyRootfs': True}})
    try:
        require(docker.inspect(created['Id'])['State']['Status'] == 'created', 'binary inspector unexpectedly started')
        connection = m.UnixHTTP('localhost', timeout=20)
        try:
            connection.request('GET', '/v1.41/containers/' + created['Id'] + '/archive?path=/app/irc-fiber-holder')
            response = connection.getresponse()
            require(response.status == 200, 'immutable image executable archive unavailable')
            class BoundedReader:
                count = 0
                def read(self, size):
                    data = response.read(min(size, 65536))
                    self.count += len(data)
                    require(self.count <= 256 << 20, 'image executable archive exceeds bound')
                    return data
            reader = BoundedReader()
            digest = None
            with tarfile.open(fileobj=reader, mode='r|') as archive:
                for member in archive:
                    require(member.isfile() and member.name.split('/')[-1] == 'irc-fiber-holder' and
                            member.size <= 256 << 20 and digest is None, 'unexpected executable archive member')
                    result = hashlib.sha256()
                    source = archive.extractfile(member)
                    for chunk in iter(lambda: source.read(65536), b''):
                        result.update(chunk)
                    digest = result.hexdigest()
            require(digest, 'executable archive empty')
            return digest
        finally:
            connection.close()
    finally:
        # Only this exact never-started run-owned probe and its anonymous volumes.
        require(docker.inspect(created['Id'])['State']['Status'] == 'created', 'binary inspector changed; inspect only')
        docker.request('DELETE', '/containers/' + created['Id'] + '?v=true')


def initialize(case):
    spec, docker = manifest()
    require(re.fullmatch(r'[a-z][a-z0-9-]{0,63}', case), 'invalid fixture case')
    root = BASE / case
    require(not root.exists(), 'fixture case/evidence directory is single-use')
    root.mkdir(mode=0o700)
    holder = docker.inspect(spec['containers']['holder']['id'])
    engine = docker.inspect(spec['containers']['engine']['id'])
    require(holder['Image'] == OLD and engine['Image'] == spec['oldEngineImageId'] and
            holder['State']['Running'] and engine['State']['Running'], 'exact preserved old pair required')
    require(engine['Image'] == OLD_ENGINE, 'exact physically retained f9 engine required')
    members = {int(pid) for file in (Path('/sys/fs/cgroup' + k.proc_cgroups(engine['State']['Pid']))).rglob('cgroup.procs')
               for pid in file.read_text().split()}
    binaries = [pid for pid in members if os.readlink('/proc/%d/exe' % pid) == '/app/irc-fiber-engine']
    require(len(binaries) == 1 and k.executable_sha256(binaries[0]) == OLD_ENGINE_EXE,
            'actual old engine executable differs from retained f9 binary')
    pid, _, _ = k.holder_process(holder)
    image_sha = image_binary_digest(docker, spec)
    require(k.executable_sha256(pid) == image_sha, 'running old holder binary differs from immutable image')
    receipt = m.private_json(BASE / 'reviewed-lifecycle.json')
    require(k.provenance(holder, k.proc_generation(pid), receipt), 'supplied actual lifecycle review rejected')
    m.durable(root / 'reviewed-lifecycle.json', receipt, exclusive=True)
    fixture = dict(spec, root=str(root), dockerSocket='/var/run/docker.sock')
    m.durable(root / 'fixture.json', fixture, exclusive=True)
    gateway = docker.inspect(spec['containers']['gateway']['id'])
    authority = docker.inspect(spec['containers']['sysagent']['name'])
    intent = {'version': 1, 'affinityBasis': 'current_verified', 'project': spec['project'],
              'sourceRevision': spec['sourceRevision'], 'oldEngineImage': spec['oldEngineImageId'],
              'engineImage': spec['engineImageId'], 'engineName': engine['Name'].lstrip('/'),
              'deploymentLock': str(root / 'deployment.lock'), 'provenanceFile': str(root / 'reviewed-lifecycle.json'),
              'mongoContainer': spec['containers']['mongo']['name'],
              'writerArtifactBindingsSha256': c.sha(spec['writerArtifactBindings']),
              'restartAuthorities': [{'name': authority['Name'].lstrip('/'), 'id': authority['Id'],
                                      'image': authority['Image'], 'wasRunning': authority['State']['Running']}],
              'controlOwners': [{'name': gateway['Name'].lstrip('/'), 'id': gateway['Id'], 'image': gateway['Image']}]}
    m.durable(root / 'intent.json', intent, exclusive=True)
    return {'root': str(root), 'fixture': str(root / 'fixture.json'), 'intent': str(root / 'intent.json')}


def observer(spec, docker):
    holder = docker.inspect(spec['containers']['holder']['name'])
    require(holder['Image'] in (OLD, spec['candidateImageId']), 'unexpected holder image')
    pid, _, _ = k.holder_process(holder)
    env = m.env_map(holder['Config']['Env'])
    require(env.get('IRCFIBER_SERVER_ID') == 'fixture-regression' and env.get('IRCFIBER_HOLDER_ADDR', '').startswith('unix:///'),
            'fixture requires Unix IPC')
    path = Path('/proc/%d/root' % pid) / env['IRCFIBER_HOLDER_ADDR'][7:].lstrip('/')
    return k.Observer(pid, str(path), 'fixture-regression', env.get('IRCFIBER_HOLDER_TOKEN', ''), time.monotonic() + 20)


def observe(verb):
    spec, docker = manifest()
    require(verb in ('LIST', 'STATUS'), 'only bounded fixture observations permitted')
    client = observer(spec, docker)
    try:
        value = client.request(verb, {})
        if verb == 'LIST':
            return [{key: item for key, item in row.items() if key != 'meta'} for row in value['connections']]
        return value
    finally:
        client.close()


def fault(kind):
    spec, docker = manifest()
    require(kind in ('missing-meta', 'stale-meta', 'owner-meta', 'restore-meta', 'writer-inflight',
                     'writer-release', 'route-drain', 'route-release'), 'unsupported fixture mutation')
    if kind.startswith('writer-'):
        token = 'f976b00b-3612-42f1-bb86-0699a4af1d94'
        docker.REDIS = spec['containers']['redis']['name']
        m.REDIS = spec['containers']['redis']['name']
        return {'result': docker.redis('SADD' if kind == 'writer-inflight' else 'SREM', c.WRITERS, token)}
    if kind.startswith('route-'):
        m.REDIS = spec['containers']['redis']['name']
        key = 'irc:egress:admission:north'
        if kind == 'route-release':
            return {'result': docker.redis('DEL', key)}
        return {'result': docker.redis('SET', key, json.dumps(dict(v=1, endpoint='192.0.2.30:1080', draining=True,
            drainReason='owned fixture refusal', open=False, trialToken='', updatedAtMs=m.now_ms())))}
    client = observer(spec, docker)
    try:
        backup = BASE / 'original-meta.json'
        if kind == 'restore-meta':
            saved = m.private_json(backup)
            client.request('META', {'id': saved['id'], 'meta': saved['meta']})
            backup.unlink()
            return {'restored': True}
        rows = client.request('LIST', {})['connections']
        row = next(row for row in rows if row.get('state') == 'open' and isinstance(row.get('meta'), dict))
        m.durable(backup, {'id': row['id'], 'meta': row['meta']}, exclusive=True)
        meta = dict(row['meta'])
        if kind == 'missing-meta':
            meta = None
        elif kind == 'stale-meta':
            meta['metaAtMs'] = m.now_ms() - 120000
            meta['capturedAtMs'] = meta['metaAtMs']
        else:
            meta['userId'] = str(uuid.uuid4())
        client.request('META', {'id': row['id'], 'meta': meta})
        return {'mutated': kind}
    finally:
        client.close()



def route_attempt():
    spec, docker = manifest()
    engine = docker.inspect(spec['containers']['engine']['id'])
    mount = next(mount for mount in engine['Mounts'] if mount['Destination'] == '/egress')
    path = c.host_path(mount['Source']) / 'dynamic/tailscaled.sock'
    deadline = time.monotonic() + 90
    while path.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    require(not path.exists(), 'dynamic control exclusion was never physically held')
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        try:
            client.connect(str(path))
        except FileNotFoundError:
            return {'externalRetargetConnectBlocked': True}
        raise m.Refused('external dynamic retarget producer could connect while excluded')
    finally:
        client.close()


def hold_dial():
    spec, docker = manifest()
    holder = docker.inspect(spec['containers']['holder']['name'])
    pid, _, _ = k.holder_process(holder)
    env = m.env_map(holder['Config']['Env'])
    path = Path('/proc/%d/root' % pid) / env['IRCFIBER_HOLDER_ADDR'][7:].lstrip('/')
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(40)
    network = str(uuid.uuid4())
    request = {'tag': {'networkId': network, 'userId': str(uuid.uuid4()), 'name': 'owned-inflight-fixture'},
               'host': 'mock-irc', 'port': 16669, 'tls': 'implicit', 'sni': 'mock-irc',
               'token': env.get('IRCFIBER_HOLDER_TOKEN', '')}
    held_id = None
    try:
        with k.network_namespace(pid):
            sock.connect(str(path))
        sock.sendall(('DIAL ' + json.dumps(request) + '\n').encode())
        stream = sock.makefile('rb')
        for _ in range(64):
            line = stream.readline(65536)
            if not line or line.startswith(b'FAILED '):
                break
            if line.startswith(b'CONNECTED '):
                held_id = json.loads(line[len(b'CONNECTED '):])['id']
                break
        require(held_id is not None, 'in-flight DIAL never positively reached CONNECTED')
        stream.close()
        return {'actualDialAdmitted': True, 'holderId': held_id}
    finally:
        sock.close()
        if held_id:
            control = observer(spec, docker)
            try:
                row = control.request('INFO', {'id': held_id})
                require(row['tag']['networkId'] == network, 'inflight fixture claim changed')
                control.request('CLOSE', {'id': held_id})
            finally:
                control.close()


def audit(case):
    spec, docker = manifest()
    root = BASE / case
    fence = m.private_json(root / 'fence.json')
    capture = m.private_json(root / 'capture-before-stop.json')
    receipt = m.private_json(root / 'quiesced-restart-authorities.json')
    require(fence['captureSha256'] == c.sha(capture) and receipt['fenceSha256'] == c.sha(fence) and
            receipt['captureSha256'] == c.sha(capture) and receipt['physicalAbsenceVerified'] is True,
            'real fence/capture/quiescence receipt chain broken')
    authority = receipt['restartAuthorities']
    require(len(authority) == 1 and authority[0]['container']['Id'] == spec['containers']['sysagent']['id'],
            'exact sysagent physical receipt absent')
    record = authority[0]
    collector = c.Collector(m.Maintenance(docker, root), m.private_json(root / 'intent.json'))
    collector.restart_authorities = authority
    collector.quiesced_receipt = receipt
    collector.root = root
    collector.check_restart_authorities()
    require(record['historicalNamespaceUnprovable'] is (record['generation'] is None) and
            (record['generation'] is None or record['members']), 'invented/missing source namespace proof')
    events = subprocess.run(['docker', '--host', 'unix:///var/run/docker.sock', 'events',
                             '--since', str(spec['startedAt']), '--until', str(int(time.time()) + 1),
                             '--filter', 'type=container', '--format', '{{json .}}'],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
    require(events.returncode == 0 and len(events.stdout) <= 16 << 20, 'actual Docker lifecycle event inventory unavailable')
    rows = [json.loads(line) for line in events.stdout.splitlines()]
    m.durable(root / 'docker-events.json', rows, exclusive=True)
    sid, eid = spec['containers']['sysagent']['id'], fence['oldEngineId']
    fence_ns, proof_ns = (root / 'fence.json').stat().st_mtime_ns, (root / 'quiesced-restart-authorities.json').stat().st_mtime_ns
    relevant = [row for row in rows if row.get('Actor', {}).get('ID') in (sid, eid)]
    for row in relevant:
        actor, action, at = row['Actor']['ID'], row.get('Action'), row.get('timeNano', 0)
        if actor == sid and at >= fence_ns:
            require(action not in ('start', 'restart', 'unpause'), 'sysagent implicitly restarted after fence')
        if action in ('update', 'kill') and at >= fence_ns:
            require(at >= (fence_ns if actor == sid else proof_ns),
                    'policy/TERM preceded permanent fence or positive authority absence')
    if record['generation'] is not None:
        require(any(row['Actor']['ID'] == sid and row.get('Action') == 'kill' and
                    row.get('Actor', {}).get('Attributes', {}).get('signal') in ('15', 'SIGTERM') and
                    row.get('timeNano', 0) >= fence_ns for row in relevant), 'actual post-fence sysagent SIGTERM event missing')
    else:
        require(not any(row['Actor']['ID'] == sid and row.get('Action') in ('update', 'kill', 'start', 'restart') and
                        row.get('timeNano', 0) >= fence_ns for row in relevant), 'already-stopped authority was mutated')
    return {'physicalAbsenceVerified': True, 'historicalNamespaceUnprovable': record['historicalNamespaceUnprovable'],
            'fenceSha256': c.sha(fence), 'quiescenceSha256': c.sha(receipt), 'dockerEventsSha256': c.sha(rows)}

def authority_fault(kind):
    spec, docker = manifest()
    root = BASE / 'activation'
    require(root.is_dir() and not (root / 'fence.json').exists(), 'fault must start before sole activation fence')
    actor = docker.inspect(spec['containers']['sysagent']['id'])
    require(actor['State']['Running'] and actor['Id'] == docker.inspect(actor['Name'])['Id'],
            'fault target must be exact original running sysagent')
    m.durable(root / 'physical-fault-armed.json', {'kind': kind, 'atMs': m.now_ms()}, exclusive=True)
    if kind == 'continuous-restart':
        end = time.monotonic() + 600
        while not (root / 'quiesced-restart-authorities.json').exists() and time.monotonic() < end:
            time.sleep(0.001)
        require((root / 'quiesced-restart-authorities.json').exists(), 'continuous-proof injection never reached physical quiescence')
        proof = m.private_json(root / 'quiesced-restart-authorities.json')
        require(proof['physicalAbsenceVerified'] is True and not docker.inspect(actor['Id'])['State']['Running'],
                'continuous restart fault was not after positive absence')
        docker.request('POST', '/containers/' + actor['Id'] + '/start')
        result = {'kind': kind, 'injectedAfterQuiescenceSha256': c.sha(proof), 'actual': docker.inspect(actor['Id'])}
    elif kind == 'term-refusal':
        binding = spec['writerArtifactBindings'][actor['Image']]
        collector = c.Collector(m.Maintenance(docker, root), m.private_json(root / 'intent.json'))
        _, _, members = collector.running_binary(actor, binding)
        app = next(int(pid) for pid in members if os.readlink('/proc/%s/exe' % pid) == '/app/irc-fiber')
        os.kill(app, signal.SIGSTOP)
        require(Path('/proc/%d/status' % app).read_text().split('State:', 1)[1].lstrip().startswith('T'),
                'actual sysagent SIGSTOP refusal injection not observed')
        result = {'kind': kind, 'pid': app, 'generation': k.proc_generation(app), 'actual': docker.inspect(actor['Id'])}
    elif kind == 'restart-inflight':
        docker.request('POST', '/containers/' + actor['Id'] + '/update', {'RestartPolicy': {'Name': 'always'}})
        result = None
        for _ in range(12):
            current = docker.inspect(actor['Id'])
            if current['State']['Running'] and not current['State'].get('Restarting'):
                docker.request('POST', '/containers/' + actor['Id'] + '/kill?signal=SIGKILL')
            end = time.monotonic() + 2
            while time.monotonic() < end:
                current = docker.inspect(actor['Id'])
                if current['State'].get('Restarting'):
                    result = {'kind': kind, 'actual': current}
                    break
                time.sleep(0.005)
            if result and current.get('RestartCount', 0) >= 4:
                break
            time.sleep(0.2)
        require(result and result['actual']['State']['Restarting'], 'actual Docker restart-inflight never observed')
    else:
        require(kind in ('unknown-authority', 'replacement'), 'unsupported exact authority fault')
        create = m.exact_create(actor, actor['Image'], docker.image(actor['Image'])['Config'],
                                required_ipc_mount='/var/run/docker.sock')
        for endpoint in create['NetworkingConfig']['EndpointsConfig'].values():
            endpoint.pop('IPAMConfig', None)
        if kind == 'replacement':
            docker.request('POST', '/containers/' + actor['Id'] + '/kill?signal=SIGTERM')
            end = time.monotonic() + 40
            while docker.inspect(actor['Id'])['State']['Running'] and time.monotonic() < end:
                time.sleep(0.05)
            require(not docker.inspect(actor['Id'])['State']['Running'], 'replacement injection source refused TERM')
            docker.request('POST', '/containers/' + actor['Id'] + '/rename?name=' + spec['project'] + '-superseded-sysagent')
            name = actor['Name'].lstrip('/')
        else:
            name = spec['project'] + '-unknown-authority'
        created = docker.request('POST', '/containers/create?name=' + name, create)
        docker.request('POST', '/containers/' + created['Id'] + '/start')
        result = {'kind': kind, 'original': actor, 'actual': docker.inspect(created['Id'])}
    m.durable(root / ('physical-fault-' + kind + '.json'), result, exclusive=True)
    return {'kind': kind, 'physicalInjectionObserved': True}


def settle_fault(kind):
    # Exact adversarial actor only. Never retry/start the engine or holder.
    require(kind in ('term-refusal', 'continuous-restart', 'restart-inflight', 'unknown-authority', 'replacement'),
            'unsupported exact settlement')
    docker = m.Docker()
    fault = m.private_json(BASE / 'activation' / ('physical-fault-' + kind + '.json'))
    if kind == 'term-refusal':
        require(k.proc_generation(fault['pid']) == fault['generation'], 'refusal producer generation changed')
    actor = docker.inspect(fault['actual']['Id'])
    generation = cgroup = pin = None
    if actor['State']['Running'] and not actor['State'].get('Restarting'):
        generation, cgroup = k.producer_snapshot(actor)
        pin = os.open('/proc/%d/ns/pid' % generation['pid'], os.O_RDONLY | os.O_CLOEXEC)
        require('pid:[%d]' % os.fstat(pin).st_ino == generation['pidns'], 'settlement namespace capture changed')
    if kind == 'term-refusal':
        os.kill(fault['pid'], signal.SIGCONT)
    if kind == 'restart-inflight':
        docker.request('POST', '/containers/' + actor['Id'] + '/update', {'RestartPolicy': {'Name': 'no'}})
    end, term_sent = time.monotonic() + 40, False
    while time.monotonic() < end:
        current = docker.inspect(actor['Id'])
        if not current['State']['Running'] and not current['State'].get('Restarting'):
            break
        if current['State']['Running'] and not current['State'].get('Restarting') and not term_sent:
            docker.request('POST', '/containers/' + actor['Id'] + '/kill?signal=SIGTERM')
            term_sent = True
        time.sleep(0.05)
    stopped = docker.inspect(actor['Id'])
    require(not stopped['State']['Running'] and not stopped['State'].get('Restarting'), 'adversarial authority did not settle stopped')
    if generation:
        k.exited(generation, cgroup)
        os.close(pin)
    else:
        collector = c.Collector(m.Maintenance(docker, BASE / 'activation'), {})
        collector.authority_absent({'generation': None, 'cgroup': '/system.slice/docker-' + actor['Id'] + '.scope'})
    m.durable(BASE / 'activation' / 'fault-settled.json', stopped, exclusive=True)
    return {'actualActorStopped': True}
def guard_audit(kind):
    spec = m.private_json(BASE / 'run.json')
    root = BASE / 'activation'
    docker = m.Docker()
    events = subprocess.run(['docker', '--host', 'unix:///var/run/docker.sock', 'events',
                             '--since', str(spec['startedAt']), '--until', str(int(time.time()) + 1),
                             '--filter', 'type=container', '--format', '{{json .}}'],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
    require(events.returncode == 0 and len(events.stdout) <= 16 << 20, 'actual refusal lifecycle inventory unavailable')
    rows = [json.loads(line) for line in events.stdout.splitlines()]
    m.durable(root / 'guard-docker-events.json', rows, exclusive=True)
    sid, eid = spec['containers']['sysagent']['id'], spec['containers']['engine']['id']
    if kind == 'term-refusal':
        fence_ns = (root / 'fence.json').stat().st_mtime_ns
        require(any(row.get('Actor', {}).get('ID') == sid and row.get('Action') == 'kill' and
                    row.get('Actor', {}).get('Attributes', {}).get('signal') in ('15', 'SIGTERM') and
                    row.get('timeNano', 0) >= fence_ns for row in rows), 'real bounded SIGTERM refusal was not dispatched after fence')
        require(not any(row.get('Actor', {}).get('ID') == eid and row.get('Action') in ('kill', 'update', 'stop', 'restart')
                        for row in rows), 'old engine mutated despite sysagent refusal')
        require(docker.inspect(sid)['State']['Running'], 'refusing sysagent was force-killed instead of failing closed')
    if kind == 'continuous-restart':
        proof_ns = (root / 'quiesced-restart-authorities.json').stat().st_mtime_ns
        require(any(row.get('Actor', {}).get('ID') == sid and row.get('Action') == 'start' and
                    row.get('timeNano', 0) >= proof_ns for row in rows), 'real post-proof adversarial restart event missing')
    return {'kind': kind, 'actualLifecycleSha256': c.sha(rows)}




def main():
    require(len(sys.argv) == 3, 'expected exact host-root action and argument')
    action, value = sys.argv[1:]
    if action == 'init':
        result = initialize(value)
    elif action == 'observe':
        result = observe(value)
    elif action == 'fault':
        result = fault(value)
    elif action == 'route-attempt':
        require(value == 'dynamic', 'exact owned dynamic slot required')
        result = route_attempt()
    elif action == 'hold-dial':
        require(value == 'tls', 'exact owned TLS fixture required')
        result = hold_dial()
    elif action == 'verify':
        require(value == 'host', 'exact host proof required')
        spec, docker = manifest()
        result = {'nativeHostRoot': True, 'toolHashes': spec['toolHashes']}
    elif action == 'audit':
        result = audit(value)
    elif action == 'authority-fault':
        result = authority_fault(value)
    elif action == 'settle-fault':
        result = settle_fault(value)
    elif action == 'guard-audit':
        result = guard_audit(value)
    else:
        raise m.Refused('unsupported fixture helper action')
    print(json.dumps(result, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(str(error) if isinstance(error, m.Refused) else
              'owned Linux helper refused; private evidence retained', file=sys.stderr)
        sys.exit(1)
