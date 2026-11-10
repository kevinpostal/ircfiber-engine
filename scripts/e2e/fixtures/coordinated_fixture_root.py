#!/usr/bin/env python3
"""Run-owned privileged Linux helper for coordinated qualification only.

No production name, image-source override, remote daemon, host setting changes or
arbitrary Docker command RPC. A Colima daemon plus exact project/run/image/tools
manifest is mandatory before ANY privileged operation. The ordinary driver runs
on macOS; only this helper performs kernel/proc/cgroup evidence collection.
"""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
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
BASE = Path('/evidence')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


m = load('coordinated_maintenance', '/tools/ircfiber-holder-maintenance.py')
c = load('coordinated_collector', '/tools/ircfiber-holder-coordinated.py')
k = c.load_kernel()


def require(ok, reason):
    m.require(ok, reason)


def manifest():
    require(sys.platform == 'linux' and os.geteuid() == 0 and Path('/sys/fs/cgroup/cgroup.controllers').exists(),
            'real Linux/root cgroup-v2 helper required')
    spec = m.private_json(BASE / 'run.json')
    require(spec.get('version') == 1 and spec.get('sourceImageId') == OLD and
            spec.get('serverId') == 'fixture-regression' and
            re.fullmatch(r'regression-[a-zA-Z0-9_.-]+', spec.get('project', '')) and
            spec['run'] == spec['project'], 'fixture manifest scope mismatch')
    for name, digest in spec['toolHashes'].items():
        require(name in ('ircfiber-holder-maintenance.py', 'ircfiber-holder-coordinated.py', 'legacy-holder-barrier.py') and
                hashlib.sha256((Path('/tools') / name).read_bytes()).hexdigest() == digest,
                'helper tool source differs from recorded driver source')
    docker = m.Docker()
    info = docker.request('GET', '/info')
    require(re.fullmatch(r'colima(?:-[A-Za-z0-9_.-]+)?', info.get('Name', '')), 'only owned Colima Docker daemon permitted')
    own = docker.inspect(spec['helperId'])
    labels = own['Config'].get('Labels') or {}
    require(labels.get('ircfiber.fixture') == 'routing-regression' and
            labels.get('ircfiber.fixture.run') == spec['run'] and
            labels.get('com.docker.compose.project') == spec['project'] and
            labels.get('com.docker.compose.service') == 'coordinated-helper' and
            own['HostConfig'].get('Privileged') is True and own['HostConfig'].get('PidMode') == 'host' and
            own['HostConfig'].get('CgroupnsMode') == 'host' and own['HostConfig'].get('NetworkMode') == 'none',
            'helper privilege/ownership boundary differs from declared isolated fixture')
    require({entry['Destination'] for entry in own['Mounts']} ==
            {'/var/run/docker.sock', '/sys/fs/cgroup', '/evidence'}, 'helper has undeclared host/volume mounts')
    for service, entry in spec['containers'].items():
        require(entry['name'].startswith(spec['project'] + '-') and 'ovh' not in entry['name'], 'production-like target forbidden')
        if service == 'holder':
            item = docker.inspect(entry['name'])
            if item['Id'] != entry['id']:
                fence = m.private_json(BASE / 'activation' / 'fence.json')
                require(fence['oldId'] == entry['id'] and item['Image'] == spec['candidateImageId'],
                        'unfenced fixture holder generation')
        else:
            item = docker.inspect(entry['id'])
        labels = item['Config'].get('Labels') or {}
        require(labels.get('ircfiber.fixture') == 'routing-regression' and
                labels.get('ircfiber.fixture.run') == spec['run'] and
                labels.get('com.docker.compose.project') == spec['project'], 'fixture container ownership mismatch')
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
    pid, _, _ = k.holder_process(holder)
    image_sha = image_binary_digest(docker, spec)
    require(k.executable_sha256(pid) == image_sha, 'running old holder binary differs from immutable image')
    receipt = {'schema': 1, 'holders': [{'image': OLD, 'executableSha256': image_sha,
        'acceptModel': 'single-sequential-accept-fd-installed-before-callback',
        'streamLifetime': 'accepted-fd-retained-through-dial-and-relay',
        'evidenceSha256': c.sha({'revision': OLD_REVISION, 'ipcSha256': OLD_IPC_SHA, 'imageExecutableSha256': image_sha})}]}
    m.durable(root / 'reviewed-lifecycle.json', receipt, exclusive=True)
    fixture = dict(spec, root=str(root), dockerSocket='/var/run/docker.sock')
    m.durable(root / 'fixture.json', fixture, exclusive=True)
    gateway = docker.inspect(spec['containers']['gateway']['id'])
    intent = {'version': 1, 'affinityBasis': 'current_verified', 'project': spec['project'],
              'sourceRevision': spec['sourceRevision'], 'oldEngineImage': spec['oldEngineImageId'],
              'engineImage': spec['engineImageId'], 'engineName': engine['Name'].lstrip('/'),
              'deploymentLock': str(root / 'deployment.lock'), 'provenanceFile': str(root / 'reviewed-lifecycle.json'),
              'mongoContainer': spec['containers']['mongo']['name'],
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

def main():
    require(len(sys.argv) == 3, 'expected init|observe|fault with exact argument')
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
