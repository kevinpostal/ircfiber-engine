#!/usr/bin/env python3
"""Exact old-engine stop -> one old-holder replacement -> first A physical proof.

Uses the existing owned routing stack and real IRC/TLS/001 oracle. Kernel capture
runs directly as Linux host root on Colima, never in a Docker authority/helper.
This does NOT waive the separate full 250-session memory/load gates.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time
import uuid

from holder_engine_qualification import EngineQualification, require, wait, number

OLD = 'sha256:8e7447fa51f9b2fa88fb4b88de8687af6483d8e078c147181469125bc0d82f09'
OLD_ENGINE = 'sha256:f9a5a59d2ba3ae99c002a1a6666007ecbe5bd36e032f8277622de7fbdbb06c89'
SERVICES = ('redis', 'mongo', 'ircfiber-gateway', 'ircfiber-holder', 'mock-irc', 'egress-a', 'egress-b', 'ircfiber-engine', 'ircfiber-sysagent')
TOOLS = ('ircfiber-holder-maintenance.py', 'ircfiber-holder-coordinated.py',
         'legacy-holder-barrier.py', 'ircfiber-coordination-domain.py')


class CoordinatedQualification(EngineQualification):
    def __init__(self):
        super().__init__()
        self.root_base = Path(os.environ['COORDINATED_ROOT_DIR'])
        self.root_script = Path(__file__).with_name('coordinated_fixture_root.py')
        self.case = os.environ.get('COORDINATED_CASE', 'complete')
        self.started_at = int(time.time())
        self.new_holder = os.environ['COORDINATED_HOLDER_IMAGE']
        self.new_engine = os.environ['COORDINATED_ENGINE_IMAGE']
        self.collector_source = Path(self.helper).parent
        self.phase = 'coordinated-prerequisites'

    def dc(self, *args, **kwargs):
        return self.command('compose', '--project-name', self.project, '-f', self.compose,
                            '-f', os.environ['COORDINATED_COMPOSE_FILE'], *args, **kwargs)

    def owned(self, service):
        if service in self.names:
            info = self.inspect(self.names[service])
            labels = info['Config'].get('Labels') or {}
            require(labels.get('ircfiber.fixture.run') == self.run_id and
                    labels.get('com.docker.compose.project') == self.project, 'fixture name ownership changed')
            return info
        info = super().owned(service)
        self.names[service] = info['Name'].lstrip('/')
        return info

    def root(self, action, value, timeout=90):
        result = subprocess.run([sys.executable, str(self.root_script), action, value],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        require(len(result.stdout) + len(result.stderr) <= 16 << 20, 'host child output exceeds bound')
        require(result.returncode == 0, 'host-root fixture refused: ' + result.stderr.decode()[:2000])
        return json.loads(result.stdout)

    def rpc(self, action, **kwargs):
        if (self.root_base / 'run.json').exists() and action in ('held', 'holderStatus'):
            return self.root('observe', 'LIST' if action == 'held' else 'STATUS')
        return super().rpc(action, **kwargs)

    def setup(self):
        require(os.environ['ROUTING_REGRESSION_HOLDER_IMAGE'] == OLD, 'exact old holder image required')
        require(os.environ['ROUTING_REGRESSION_ENGINE_IMAGE'] == OLD_ENGINE,
                'exact retained f9 old engine required, not a rebuilt historical-source claim')
        require(sys.platform == 'linux' and os.geteuid() == 0 and os.uname().machine == 'x86_64',
                'coordinated fixture requires native Linux x86_64 HOST ROOT; no macOS/container fallback')
        require(os.readlink('/proc/self/ns/pid') == os.readlink('/proc/1/ns/pid') and
                not Path('/.dockerenv').exists() and Path('/sys/fs/cgroup/cgroup.controllers').is_file(),
                'host PID namespace and real cgroup-v2 required')
        endpoint = json.loads(self.command('context', 'inspect', self.context))[0]['Endpoints']['docker']['Host']
        require(endpoint == 'unix:///var/run/docker.sock' and stat.S_ISSOCK(Path('/var/run/docker.sock').stat().st_mode),
                'exact native local Unix Docker daemon required')
        daemon = json.loads(self.command('info', '--format', '{{json .}}'))
        require(re.fullmatch(r'colima(?:-[A-Za-z0-9_.-]+)?', daemon.get('Name', '')) and
                daemon.get('CgroupDriver') == 'systemd' and daemon.get('CgroupVersion') == '2' and
                not any('rootless' in option for option in daemon.get('SecurityOptions', [])),
                'isolated Colima native systemd/cgroup-v2 daemon required')
        for service in SERVICES:
            info = self.owned(service)
            self.ids[service] = info['Id']
            if service not in ('ircfiber-engine', 'ircfiber-holder', 'ircfiber-sysagent'):
                self.protected[service] = self.identity(info)
        for component, expected in (('engine', os.environ['ROUTING_REGRESSION_ENGINE_IMAGE']), ('holder', OLD),
                                    ('gateway', os.environ['ROUTING_REGRESSION_GATEWAY_IMAGE'])):
            require(self.inspect(self.ids['ircfiber-' + component])['Image'] == expected, 'immutable fixture source image changed')
        gateway_image = json.loads(self.command('image', 'inspect', os.environ['ROUTING_REGRESSION_GATEWAY_IMAGE']))[0]
        require((gateway_image.get('Config', {}).get('Labels') or {}).get('com.ircfiber.coordinated-exclusion-version') == '1',
                'qualified gateway writer-exclusion image required; old gateway is not safe')
        # Root-private host storage is outside every container mount. No Docker
        # socket authority or broad inventory exemption is created for capture.
        require(self.root_base.is_absolute() and not self.root_base.exists(), 'fresh root-private host evidence required')
        for parent in self.root_base.parents:
            info = parent.lstat()
            require(info.st_uid == 0 and not info.st_mode & 0o022 and not stat.S_ISLNK(info.st_mode),
                    'evidence ancestors must be root-owned/non-writable/non-symlink (not /tmp)')
        self.root_base.mkdir(mode=0o700)
        tools = self.root_base / 'tools'
        tools.mkdir(mode=0o700)
        hashes = {}
        for name in TOOLS:
            path = self.collector_source / name
            require(path.is_file(), 'collector/kernel source absent')
            hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
            target = tools / name
            target.write_bytes(path.read_bytes())
            target.chmod(0o600)
        qualification = json.loads(Path(os.environ['COORDINATED_QUALIFICATION_FILE']).read_text())
        require(qualification.get('qualified') is False and qualification.get('checks') == [] and
                qualification.get('purpose') == 'isolatedqualification' and
                qualification.get('mode') == 'coordinated' and
                qualification.get('imageId') == self.new_holder and qualification.get('sourceImageId') == OLD and
                qualification.get('engineImageId') == self.new_engine and
                qualification.get('oldEngineImageId') == os.environ['ROUTING_REGRESSION_ENGINE_IMAGE'],
                'actual image-bound build/source/consumer scratch receipt required; no claimed physical checks')
        bindings = qualification.get('writerArtifactBindings')
        require(isinstance(bindings, dict) and bindings, 'truthful image-keyed writer receipts required')
        require(bindings.get(self.new_engine, {}).get('roles') == ['engine'] and
                {'gateway', 'sysagent'} <= set(bindings.get(os.environ['ROUTING_REGRESSION_GATEWAY_IMAGE'], {}).get('roles', [])),
                'actual candidate engine plus gateway/early-sysagent reviewed roles required')
        receipts = Path(os.environ['COORDINATED_RECEIPT_DIR'])
        retained = self.root_base / 'receipts'
        retained.mkdir(mode=0o700)
        artifacts = qualification.get('artifactBindings')
        require(isinstance(artifacts, dict) and self.new_holder in artifacts and
                all(artifacts.get(image) == binding for image, binding in bindings.items()),
                'actual holder and writer artifact evidence required')
        digests = {qualification.get('evidenceSha256')}
        for binding in artifacts.values():
            digests.update(binding.get(key) for key in
                           ('buildManifestSha256', 'sourceReviewSha256', 'behavioralEvidenceSha256'))
        lifecycle = json.loads(Path(os.environ['COORDINATED_LIFECYCLE_FILE']).read_text())
        require(lifecycle.get('schema') == 1 and lifecycle.get('holders'), 'supplied actual lifecycle review receipt required')
        digests.update(row.get('evidenceSha256') for row in lifecycle['holders'])
        for digest in digests:
            require(isinstance(digest, str) and re.fullmatch(r'[0-9a-f]{64}', digest) and len(set(digest)) > 1,
                    'missing/constant qualification evidence hash forbidden')
            source = receipts / digest
            require(source.is_file() and hashlib.sha256(source.read_bytes()).hexdigest() == digest,
                    'actual supplied build/review/behavioral receipt bytes absent or mismatched: ' + digest)
            shutil.copyfile(source, retained / digest)
            (retained / digest).chmod(0o600)
        (self.root_base / 'reviewed-lifecycle.json').write_text(json.dumps(lifecycle))
        (self.root_base / 'reviewed-lifecycle.json').chmod(0o600)
        entries = {}
        for service in SERVICES:
            short = {'ircfiber-holder': 'holder', 'ircfiber-engine': 'engine', 'ircfiber-gateway': 'gateway',
                     'ircfiber-sysagent': 'sysagent'}.get(service, service)
            info = self.owned(service)
            entries[short] = dict(id=info['Id'], name=info['Name'].lstrip('/'), image=info['Image'])
        source_revision = os.environ['COORDINATED_SOURCE_REVISION']
        require(source_revision == 'fea67fb48f891791a443367f9169ed32bc5a923e',
                'sourceRevision is the reviewed old-holder IPC lifecycle commit, never the engine base commit')
        manifest = dict(version=1, project=self.project, run=self.run_id, serverId='fixture-regression',
                        sourceImageId=OLD, candidateImageId=self.new_holder, engineImageId=self.new_engine,
                        oldEngineImageId=os.environ['ROUTING_REGRESSION_ENGINE_IMAGE'], sourceRevision=source_revision,
                        toolHashes=hashes, containers=entries, qualification=qualification,
                        bootstrapQualification=True, dockerId=daemon['ID'],
                        volumes=self.command('volume', 'ls', '--quiet').split(),
                        networks=self.command('network', 'ls', '--quiet', '--no-trunc',
                            '--filter', 'label=com.docker.compose.project=' + self.project).split(),
                        writerArtifactBindings=bindings, startedAt=self.started_at,
                        fixtureRootSha256=hashlib.sha256(self.root_script.read_bytes()).hexdigest(),
                        retainedOldEngineBinarySha256='44bd1b4b292e12a8c9ff63e127a9ecc64f59734f754836ff67f2b0f642c41861',
                        oldEngineSourceReconstructionOnly=True)
        (self.root_base / 'run.json').write_text(json.dumps(manifest))
        (self.root_base / 'run.json').chmod(0o600)
        self.save('run-manifest.json', manifest)
        self.root('verify', 'host')
        self.save('domain-native.json', self.root('domain', 'physical', timeout=300))
        wait(lambda: self.rpc('status')['subscribed'], 'real IRC event subscriber')
        user = 'coordinated' + secrets.token_hex(6)
        credentials = dict(username=user, password=secrets.token_urlsafe(24), email=user + '@fixture.invalid')
        self.api('POST', '/register', credentials, form=True)
        self.api('POST', '/login', credentials, form=True)
        for row in self.api('GET', '/api/networks'):
            self.networks[row.get('id') or row['networkId']] = row['nick']
        wait(self.registered, 'old-engine actual initial 001', 120)
        for index in range(int(os.environ.get('COORDINATED_SESSIONS', '16')) - len(self.networks)):
            route = ('direct', 'north', 'south', 'dynamic')[index % 4]
            self.create(index, route, tls=index % 2 == 1)
        wait(self.registered, 'complete pre-stop registered TCP/TLS denominator', 240)
        self.rpc('probe')
        self.save('source-manifest.json', dict(manifest, protected=self.protected,
                  scope='coordinated physical proof only; separate full 250-session load gates remain required'))

    def create(self, index, route='direct', tls=False, **kwargs):
        if route != 'dynamic':
            return super().create(index, route, tls, **kwargs)
        nick = 'co' + secrets.token_hex(5)
        result = self.api('POST', '/api/networks', dict(name='CO_' + str(index), host='mock-irc',
            port=16669 if tls else 16668, tls='enabled' if tls else 'disabled', nick=nick,
            realName='Owned coordinated physical qualification', autoJoinChannels=['#memory0'],
            routing=dict(order=['mullvad'], preferredExit='dynamic')))
        nid = result.get('id') or result.get('networkId')
        require(nid, 'dynamic fixture network identity missing')
        self.networks[nid] = nick
        return nid

    def physical(self):
        status = self.rpc('status')
        require(status['errorCount'] == 0, 'upstream oracle error')
        live = {s['nick']: s for s in status['sessions'] if not s['closed']}
        require(set(live) == set(self.networks.values()), 'physical denominator cannot shrink')
        accepts = {tuple(event['physical']): event for event in status['events'] if event['event'] == 'accept'}
        held = self.held()
        for nid, nick in self.networks.items():
            session = live[nick]
            require(session['welcomed'] and session['nickCommands'] == session['userCommands'] == 1 and
                    session['quitCommands'] == 0 and session['observed001At'] is not None, 'physical 001/one-registration proof missing')
            slot = held[nid]['tag'].get('egressLabel', '')
            if slot:
                require(accepts[tuple(session['physical'])]['source'] ==
                        {'north': '192.0.2.30', 'south': '192.0.2.31', 'dynamic': '192.0.2.30'}[slot],
                        'actual physical route differs from current concrete affinity')
        return {nid: dict(physical=live[nick]['physical'], tls=live[nick]['tls'],
                          observed001At=live[nick]['observed001At']) for nid, nick in self.networks.items()}

    def collector_command(self, operation, paths, lost=False):
        args = [sys.executable, str(self.root_base / 'tools/ircfiber-holder-maintenance.py'),
                'activate', '--mode', 'coordinated', '--operation-id', operation, '--image', self.new_holder,
                '--fixture-spec', paths['fixture'], '--coordinated-config', paths['intent']]
        if lost:
            args.append('--fixture-lost-return')
        return args

    def invoke(self, case, operation=None, lost=False, timeout=650, paths=None):
        paths = paths or self.root('init', case)
        operation = operation or str(uuid.uuid4())
        process = subprocess.Popen(self.collector_command(operation, paths, lost),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return process, operation, paths

    def finish(self, process, case, timeout=650):
        out, err = process.communicate(timeout=timeout)
        require(len(out) + len(err) <= 65536, 'helper diagnostic output exceeds bound')
        self.save(case + '-helper.json', dict(returncode=process.returncode, stdout=out.decode(), stderr=err.decode()))
        return process.returncode, out, err

    def preflight_refusals(self):
        before = self.identity(self.owned('ircfiber-engine'))
        holder = self.identity(self.owned('ircfiber-holder'))
        for case in ('writer-inflight', 'route-drain', 'missing-meta', 'stale-meta', 'owner-meta'):
            self.root('fault', case)
            process, operation, paths = self.invoke(case)
            code, _, error = self.finish(process, case)
            reasons = {
                'writer-inflight': b'continuous control exclusion unavailable or a writer is in flight',
                'route-drain': b'current exit admission blocks frozen route',
                'missing-meta': b'missing/nonregistered/owner-mismatched legacy META',
                'stale-meta': b'stale or wrong-generation legacy META',
                'owner-meta': b'missing/nonregistered/owner-mismatched legacy META',
            }
            require(code != 0 and reasons[case] in error,
                    'invalid fresh evidence did not reach its intended refusal: ' + error.decode(errors='replace')[:2000])
            # No permanent fence and no engine/holder lifecycle action.
            state = (Path(paths['root']) / 'fence.json').exists()
            require(not state and self.identity(self.owned('ircfiber-engine')) == before and
                    self.identity(self.owned('ircfiber-holder')) == holder, 'preflight refusal acted on a socket owner')
            self.root('fault', 'writer-release' if case == 'writer-inflight' else
                      'route-release' if case == 'route-drain' else 'restore-meta')
            self.record('pre-stop-refusal-' + case, operationId=operation)
        self.extra_producer_refusal(before, holder)
        self.inflight_refusal(before, holder)

    def refused_without_action(self, case, before, holder, paths=None):
        process, operation, paths = self.invoke(case, paths=paths)
        code, _, _ = self.finish(process, case)
        require(code != 0 and self.identity(self.owned('ircfiber-engine')) == before and
                self.identity(self.owned('ircfiber-holder')) == holder, 'unsafe producer refusal changed socket owners')
        require(not (Path(paths['root']) / 'fence.json').exists(),
                'unsafe producer consumed permanent transition fence')
        return operation

    def extra_producer_refusal(self, before, holder):
        paths = self.root('init', 'other-producer')
        source = next(mount['Name'] for mount in self.owned('ircfiber-holder')['Mounts']
                      if mount['Destination'] == '/run/ircfiber')
        image = self.inspect(self.ids['mock-irc'])['Image']
        args = ['create', '--name', self.project + '-unexcluded-producer', '--network=none', '--restart=no',
                '--label', 'ircfiber.fixture=routing-regression', '--label', 'ircfiber.fixture.run=' + self.run_id,
                '--label', 'com.docker.compose.project=' + self.project,
                '--label', 'com.docker.compose.service=unexcluded-producer',
                '--mount', 'type=volume,src=' + source + ',dst=/run/ircfiber,readonly', image,
                'python3', '-c', 'import socket,time;s=socket.socket(socket.AF_UNIX);'
                's.connect(\"/run/ircfiber/holder.sock\");s.sendall(' +
                repr(b'HELLO {\"proto\":1,\"serverId\":\"fixture-regression\",\"engine\":\"unexcluded\"}\n') +
                ');time.sleep(120)']
        cid = self.command(*args).strip()
        try:
            self.command('start', cid)
            operation = self.refused_without_action('other-producer', before, holder, paths)
        finally:
            self.command('rm', '-f', cid)
        self.record('real-other-producer-refused-before-stop', operationId=operation)

    def inflight_refusal(self, before, holder):
        initial = len(self.rpc('status')['accepts'])
        self.rpc('gates', phases=['TLS'])
        process = subprocess.Popen([sys.executable, str(self.root_script), 'hold-dial', 'tls'],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            wait(lambda: len(self.rpc('status')['accepts']) > initial, 'actual in-flight TLS DIAL accepted upstream', 20)
            operation = self.refused_without_action('inflight-dial', before, holder)
        finally:
            self.rpc('gates', phases=[])
            out, err = process.communicate(timeout=45)
            require(process.returncode == 0, 'owned in-flight DIAL cleanup did not positively finish')
        self.record('actual-inflight-DIAL-refused-before-stop', operationId=operation)

    def validate_actual_admission(self):
        from datetime import datetime
        admitted = self.diagnostics_for('registration_admitted')
        require(admitted and max(number(event['inFlight']) for event in admitted) == 8 and
                all(1 <= number(event['inFlight']) <= 8 for event in admitted),
                'full-attempt admission never established exactly eight bounded permits')
        holder = self.owned('ircfiber-holder')
        logs = self.command('logs', '--since', holder['State']['StartedAt'], holder['Id'],
                            include_stderr=True, max_bytes=8 << 20)
        starts, by_route = [], {}
        for line in logs.splitlines():
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if event.get('event') not in ('dial_ok', 'dial_fail') or 'tookMs' not in event:
                continue
            start = datetime.fromisoformat(event['ts'].replace('Z', '+00:00')).timestamp() - number(event['tookMs']) / 1000
            key = (event['host'].lower().rstrip('.'), str(event['port']), event.get('egress', ''), event.get('proxy', ''))
            starts.append(dict(start=start, route=key, networkId=event['networkId']))
        require(starts, 'actual holder DIAL timing evidence unavailable')
        for event in sorted(starts, key=lambda value: value['start']):
            key = tuple(event['route'])
            if key in by_route:
                # Each tookMs truncation contributes at most one millisecond.
                require(event['start'] - by_route[key] >= 0.998, 'actual concrete-route DIAL spacing below one second')
            by_route[key] = event['start']
        self.record('actual-eight-full-attempts-and-concrete-DIAL-spacing', starts=starts,
                    maximumPermits=max(number(event['inFlight']) for event in admitted))

    def maintenance(self):
        before_held, before_physical = self.held(), self.physical()
        preferences = {row.get('id') or row.get('networkId'): row['routing'] for row in self.api('GET', '/api/networks')}
        direct = [nid for nid, row in before_held.items() if not row['tag'].get('egressLabel')]
        require(direct, 'explicit external refusal requires a direct route row')
        refused = direct[0]
        self.rpc('targetRules', silent=[], refused=[self.networks[refused]])
        lost = os.environ.get('COORDINATED_CASE', 'complete') == 'ambiguous'
        if self.case == 'already-stopped':
            self.command('kill', '--signal', 'SIGTERM', self.ids['ircfiber-sysagent'])
            wait(lambda: not self.owned('ircfiber-sysagent')['State']['Running'], 'source already-stopped actual sysagent')
        accepts_before = len(self.rpc('status')['accepts'])
        if not lost:
            require(self.redis('ACL', 'SETUSER', 'default', '-sadd') == 'OK',
                    'selective registration-only Redis ACL stall failed')
        self.rpc('gates', phases=['001'])
        route_proof = subprocess.Popen([sys.executable, str(self.root_script), 'route-attempt', 'dynamic'],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process, operation, paths = self.invoke('activation', lost=lost)
        if not lost:
            wait(lambda: self.owned('ircfiber-engine')['Image'] == self.new_engine and
                 self.owned('ircfiber-engine')['State']['Running'], 'first A running after sole holder replacement', 120)
            self.ids['ircfiber-engine'] = self.owned('ircfiber-engine')['Id']
            self.start_diagnostics()
            # Deny ONLY SADD: registerServer cannot complete, but BLPOP,
            # canonical config reads and the control consumer remain live.
            # This witnesses the startup latch, not a whole-Redis freeze.
            target = next(iter(before_held))
            marker = dict(action='addNetwork', networkId=target,
                          userId=before_held[target]['tag']['userId'], timestampMs=int(time.time() * 1000))
            self.redis('LPUSH', 'irc:control:fixture-regression', json.dumps(marker))
            def consumed():
                logs = self.command('logs', '--since', self.owned('ircfiber-engine')['State']['StartedAt'],
                                    self.ids['ircfiber-engine'], include_stderr=True, max_bytes=8 << 20)
                return (self.redis('LLEN', 'irc:control:fixture-regression') == '0' and
                        ('addNetwork network=' + target) in logs)
            try:
                wait(consumed, 'owned addNetwork consumed while registration SADD alone is denied', 30)
                time.sleep(3)
                require(len(self.rpc('status')['accepts']) == accepts_before and not self.rpc('held'),
                        'fresh upstream DIAL occurred before any maintenance manifest restoration')
                self.record('startup-control-live-registration-stalled-no-fresh-DIAL', networkId=target)
            finally:
                require(self.redis('ACL', 'SETUSER', 'default', '+sadd') == 'OK', 'fixture registration ACL cleanup failed')
            def pending():
                live = [row for row in self.rpc('status')['sessions'] if not row['closed']]
                require(len(live) <= 8, 'more than eight physical full registration attempts')
                return len(live) == 8 and all(not row['welcomed'] for row in live)
            wait(pending, 'eight real attempts retained through gated numeric 001', 60)
            time.sleep(2)
            require(pending(), 'attempt permits released before actual numeric 001')
            self.rpc('gates', phases=[])
        code, out, err = self.finish(process, 'activation')
        route_out, route_err = route_proof.communicate(timeout=10)
        require(route_proof.returncode == 0 and json.loads(route_out)['externalRetargetConnectBlocked'],
                'continuous dynamic retarget socket exclusion was not physically observed')
        if lost:
            require(code != 0 and b'single attempt failed/ambiguous' in err, 'ambiguous-return injection did not reach sole activation')
            proof = self.root('audit', 'activation')
            require(not self.owned('ircfiber-sysagent')['State']['Running'] and
                    not self.inspect(self.ids['ircfiber-engine'])['State']['Running'], 'ambiguous return restarted an old actor')
            self.reject_second_uuid(operation, paths, ambiguous=True)
            self.record('ambiguous-return-no-retry', operationId=operation, physicalProof=proof)
            return dict(state='passed', scope='ambiguous sole holder attempt only; no recovery qualification',
                        coordinatedQualified=False, ambiguousReturnQualified=True, qualified=False)
        require(code == 0, 'real coordinated collector failed; root-private host evidence retained')
        result = json.loads(out)
        require(result['state'] == 'classified' and result['unresolvedCount'] == 0 and result['refusedCount'] >= 1,
                'every frozen row must classify; refusal is not recovery')
        self.ids['ircfiber-holder'] = self.owned('ircfiber-holder')['Id']
        self.ids['ircfiber-engine'] = self.owned('ircfiber-engine')['Id']
        completed = json.loads(self.redis('GET', 'irc:holder:maintenance:fixture-regression:' + operation))
        require({row['networkId'] for row in completed['rows']} == set(before_held), 'classified denominator changed')
        require(completed['affinityBasis'] == 'current_verified' and completed['mode'] == 'coordinated', 'affinity basis not disclosed')
        dynamic = [row for row in completed['rows'] if row['route']['slot'] == 'dynamic']
        require(dynamic and all(row['historicalExitUnprovable'] is True for row in dynamic), 'dynamic historical uncertainty hidden')
        live = {s['nick']: s for s in self.rpc('status')['sessions'] if not s['closed'] and s['welcomed']}
        recovered = {row['networkId'] for row in completed['rows'] if row['state'] == 'recovered'}
        for nid in recovered:
            sessions = [s for s in self.rpc('status')['sessions'] if s['nick'] == self.networks[nid] and
                        s['physical'] != before_physical[nid]['physical']]
            require(len(sessions) == 1 and sessions[0]['nickCommands'] == sessions[0]['userCommands'] == 1 and
                    sessions[0]['observed001At'] is not None and live[self.networks[nid]] == sessions[0],
                    'recovered row lacks exactly one new physical actual 001')
        require(preferences == {row.get('id') or row.get('networkId'): row['routing'] for row in self.api('GET', '/api/networks')},
                'coordinated transition changed saved preferences')
        self.reject_second_uuid(operation, paths)
        proof = self.root('audit', 'activation')
        self.record('one-stop-one-holder-first-A-complete-denominator', classification=completed, physicalProof=proof)
        self.validate_actual_admission()
        require(any(row['route']['slot'] == 'north' and row['state'] == 'recovered' for row in completed['rows']),
                'draining retained-ATTACH case requires a recovered north route')
        self.root('fault', 'route-drain')
        try:
            self.hot_swap_after_maintenance(recovered, completed, self.identity(self.owned('ircfiber-holder')))
        finally:
            self.root('fault', 'route-release')
        self.record('retained-ATTACH-through-draining-without-fresh-DIAL')
        return dict(state='passed', coordinatedQualified=True, affinityBasis='current_verified',
                    historicalExitUnprovableCount=len(dynamic), classification={key: completed.get(key) for key in
                    ('recoveredCount', 'refusedCount', 'unresolvedCount')}, separateFull250LoadGateRequired=True,
                    nativeIpv6='not configured; no native IPv6 claim', providerControl='explicit tailscaled LocalAPI emulator')

    def reject_second_uuid(self, operation, paths, ambiguous=False):
        before = {service: self.identity(self.owned(service)) for service in ('ircfiber-holder', 'ircfiber-engine', 'ircfiber-sysagent')}
        for new_operation, success in ((operation, True), (str(uuid.uuid4()), False)):
            result = subprocess.run(self.collector_command(new_operation, paths),
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
            require((result.returncode == 0) == success, 'permanent paired-transition fence violated')
            if success and ambiguous:
                require(json.loads(result.stdout)['state'] == 'ambiguous', 'ambiguity was falsely classified')
        require(before == {service: self.identity(self.owned(service)) for service in before},
                'read-only resume/second UUID changed an actor')

    def authority_guard(self):
        paths = self.root('init', 'activation')
        operation = str(uuid.uuid4())
        before = {service: self.identity(self.owned(service)) for service in ('ircfiber-engine', 'ircfiber-holder')}
        watcher = None
        if self.case == 'continuous-restart':
            watcher = subprocess.Popen([sys.executable, str(self.root_script), 'authority-fault', self.case],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            wait(lambda: (Path(paths['root']) / 'physical-fault-armed.json').exists(),
                 'real authority fault watcher armed', 30)
        else:
            self.root('authority-fault', self.case, timeout=120)
        invoked_at = time.monotonic()
        process = subprocess.Popen(self.collector_command(operation, paths), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        code, out, err = self.finish(process, self.case)
        if watcher:
            self.finish(watcher, self.case + '-injector', timeout=30)
            require(watcher.returncode == 0, 'physical continuous-proof fault did not execute')
        require(code != 0, 'actual unsafe authority case accepted')
        fault = json.loads((Path(paths['root']) / ('physical-fault-' + self.case + '.json')).read_text())
        require(fault['kind'] == self.case, 'actual physical fault receipt missing')
        fence = Path(paths['root']) / 'fence.json'
        if self.case in ('unknown-authority', 'replacement', 'restart-inflight'):
            require(not fence.exists() and before == {service: self.identity(self.owned(service)) for service in before},
                    'preflight authority refusal changed old engine/holder')
        else:
            require(fence.exists() and self.identity(self.owned('ircfiber-holder')) == before['ircfiber-holder'],
                    'post-fence authority refusal replaced holder or lost permanent fence')
            if self.case == 'term-refusal':
                require(b'single attempt failed/ambiguous' in err and time.monotonic() - invoked_at >= 39 and
                        not (Path(paths['root']) / 'quiesced-restart-authorities.json').exists() and
                        self.identity(self.owned('ircfiber-engine')) == before['ircfiber-engine'],
                        'SIGTERM refusal did not stop before old-engine mutation')
            else:
                require('injectedAfterQuiescenceSha256' in fault and
                        b'single attempt failed/ambiguous' in err, 'continuous physical revalidation did not reject restart')
        physical_audit = self.root('guard-audit', self.case)
        self.root('settle-fault', self.case)
        if fence.exists():
            for identity in (operation, str(uuid.uuid4())):
                result = subprocess.run(self.collector_command(identity, paths),
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
                require(result.returncode != 0, 'ambiguous authority failure resumed/retried a cut')
            require(self.identity(self.owned('ircfiber-holder')) == before['ircfiber-holder'],
                    'post-fence retry changed holder')
        self.record('physical-authority-refusal-' + self.case, operationId=operation,
                    physicalAudit=physical_audit,
                    physicalFaultSha256=hashlib.sha256(json.dumps(fault, sort_keys=True).encode()).hexdigest())
        return dict(state='passed', qualified=False, coordinatedQualified=False,
                    authorityGuardQualified=True, guardCase=self.case, actualPhysicalFaultObserved=True,
                    scope='one real unsafe-authority refusal only; not complete coordinated recovery')

    def run(self):
        self.setup()
        self.preflight_refusals()
        if self.case in ('unknown-authority', 'replacement', 'restart-inflight', 'term-refusal', 'continuous-restart'):
            return self.authority_guard()
        return self.maintenance()


def main():
    qualification = None
    result = dict(state='failed', coordinatedQualified=False)
    try:
        qualification = CoordinatedQualification()
        result = qualification.run()
    except BaseException as error:
        result = dict(state='failed', coordinatedQualified=False, reason=(type(error).__name__ + ': ' + str(error))[:2000])
    finally:
        if qualification:
            qualification.stop_diagnostics()
            # Private env/META/provenance and all failure artifacts remain in the
            # root-owned host tree; no automatic container or evidence cleanup.
            qualification.save('coordinated-result.json', result)
    print(json.dumps(result), flush=True)
    return 0 if result['state'] == 'passed' else 1


if __name__ == '__main__':
    sys.exit(main())
