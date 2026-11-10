#!/usr/bin/env python3
"""Exact old-engine stop -> one old-holder replacement -> first A physical proof.

Uses the existing owned routing stack and real IRC/TLS/001 oracle. Kernel capture
runs in a strict run-owned privileged helper on Colima, never in macOS HTTP code.
This does NOT waive the separate full 250-session memory/load gates.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import uuid

from holder_engine_qualification import EngineQualification, require, wait, number

OLD = 'sha256:8e7447fa51f9b2fa88fb4b88de8687af6483d8e078c147181469125bc0d82f09'
SERVICES = ('redis', 'mongo', 'ircfiber-gateway', 'ircfiber-holder', 'mock-irc', 'egress-a', 'egress-b', 'ircfiber-engine')
TOOLS = ('ircfiber-holder-maintenance.py', 'ircfiber-holder-coordinated.py', 'legacy-holder-barrier.py')


class CoordinatedQualification(EngineQualification):
    def __init__(self):
        super().__init__()
        self.helper_name = self.project + '-coordinated-helper'
        self.helper_id = None
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
        return json.loads(self.command('exec', self.helper_id, 'python3', '/fixture/coordinated_fixture_root.py',
                                       action, value, timeout=timeout, max_bytes=16 << 20))

    def rpc(self, action, **kwargs):
        if self.helper_id and action in ('held', 'holderStatus'):
            return self.root('observe', 'LIST' if action == 'held' else 'STATUS')
        return super().rpc(action, **kwargs)

    def setup(self):
        require(os.environ['ROUTING_REGRESSION_HOLDER_IMAGE'] == OLD, 'exact old holder image required')
        daemon = json.loads(self.command('info', '--format', '{{json .}}'))
        require(str(daemon.get('Name', '')).startswith('colima'), 'only isolated local Colima daemon allowed')
        for service in SERVICES:
            info = self.owned(service)
            self.ids[service] = info['Id']
            if service not in ('ircfiber-engine', 'ircfiber-holder'):
                self.protected[service] = self.identity(info)
        for component, expected in (('engine', os.environ['ROUTING_REGRESSION_ENGINE_IMAGE']), ('holder', OLD),
                                    ('gateway', os.environ['ROUTING_REGRESSION_GATEWAY_IMAGE'])):
            require(self.inspect(self.ids['ircfiber-' + component])['Image'] == expected, 'immutable fixture source image changed')
        gateway_image = json.loads(self.command('image', 'inspect', os.environ['ROUTING_REGRESSION_GATEWAY_IMAGE']))[0]
        require((gateway_image.get('Config', {}).get('Labels') or {}).get('com.ircfiber.coordinated-exclusion-version') == '1',
                'qualified gateway writer-exclusion image required; old gateway is not safe')
        # The helper image is this run's already-built Python fixture image;
        # application OLD/A/holder images are immutable inputs, never built here.
        endpoint_image = self.inspect(self.ids['mock-irc'])['Image']
        volume = self.project + '-coordinated-evidence'
        labels = {'ircfiber.fixture': 'routing-regression', 'ircfiber.fixture.run': self.run_id,
                  'com.docker.compose.project': self.project}
        self.command('volume', 'create', *sum((['--label', key + '=' + value] for key, value in labels.items()), []), volume)
        labels['com.docker.compose.service'] = 'coordinated-helper'
        args = ['create', '--name', self.helper_name, '--privileged', '--pid=host', '--cgroupns=host', '--network=none',
                '--restart=no', '--mount', 'type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock',
                '--mount', 'type=bind,src=/sys/fs/cgroup,dst=/sys/fs/cgroup,readonly',
                '--mount', 'type=volume,src=' + volume + ',dst=/evidence']
        for key, value in labels.items():
            args += ['--label', key + '=' + value]
        args += [endpoint_image, 'python3', '-c', 'import time;time.sleep(7200)']
        self.helper_id = self.command(*args).strip()
        self.command('start', self.helper_id)
        self.command('exec', self.helper_id, 'mkdir', '-m', '700', '/tools')
        hashes = {}
        for name in TOOLS:
            path = self.collector_source / name
            require(path.is_file(), 'collector/kernel source absent')
            hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
            self.command('cp', str(path), self.helper_id + ':/tools/' + name)
        entries = {}
        for service, short in (('ircfiber-holder', 'holder'), ('ircfiber-engine', 'engine'), ('ircfiber-gateway', 'gateway'),
                               ('redis', 'redis'), ('mongo', 'mongo'), ('mock-irc', 'mock-irc'), ('egress-a', 'egress-a'), ('egress-b', 'egress-b')):
            info = self.owned(service)
            entries[short] = dict(id=info['Id'], name=info['Name'].lstrip('/'))
        source_revision = os.environ['COORDINATED_SOURCE_REVISION']
        require(len(source_revision) == 40 and all(char in '0123456789abcdef' for char in source_revision), 'exact source revision required')
        manifest = dict(version=1, project=self.project, run=self.run_id, serverId='fixture-regression',
                        sourceImageId=OLD, candidateImageId=self.new_holder, engineImageId=self.new_engine,
                        oldEngineImageId=os.environ['ROUTING_REGRESSION_ENGINE_IMAGE'], sourceRevision=source_revision,
                        helperId=self.helper_id, toolHashes=hashes, containers=entries)
        # The manifest contains identities only. Tool/env/META capture remains
        # root-private on the Linux named volume, never a workstation bind.
        manifest_path = self.output / 'run-manifest.json'
        manifest_path.write_text(json.dumps(manifest))
        self.command('cp', str(manifest_path), self.helper_id + ':/evidence/run.json')
        self.command('exec', self.helper_id, 'chmod', '700', '/evidence')
        self.command('exec', self.helper_id, 'chmod', '600', '/evidence/run.json')
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

    def invoke(self, case, operation=None, lost=False, timeout=650):
        paths = self.root('init', case)
        operation = operation or str(uuid.uuid4())
        args = ['docker', '--context', self.context, 'exec', self.helper_id, 'python3',
                '/tools/ircfiber-holder-maintenance.py', 'activate', '--mode', 'coordinated',
                '--operation-id', operation, '--image', self.new_holder, '--fixture-spec', paths['fixture'],
                '--coordinated-config', paths['intent']]
        if lost:
            args.append('--fixture-lost-return')
        process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
            code, _, _ = self.finish(process, case)
            require(code != 0, 'invalid/missing fresh evidence was accepted')
            # No permanent fence and no engine/holder lifecycle action.
            state = self.command('exec', self.helper_id, 'python3', '-c',
                'from pathlib import Path;print(Path(' + repr(paths['root'] + '/fence.json') + ').exists())').strip()
            require(state == 'False' and self.identity(self.owned('ircfiber-engine')) == before and
                    self.identity(self.owned('ircfiber-holder')) == holder, 'preflight refusal acted on a socket owner')
            self.root('fault', 'writer-release' if case == 'writer-inflight' else
                      'route-release' if case == 'route-drain' else 'restore-meta')
            self.record('pre-stop-refusal-' + case, operationId=operation)

    def maintenance(self):
        before_held, before_physical = self.held(), self.physical()
        preferences = {row.get('id') or row.get('networkId'): row['routing'] for row in self.api('GET', '/api/networks')}
        direct = [nid for nid, row in before_held.items() if not row['tag'].get('egressLabel')]
        require(direct, 'explicit external refusal requires a direct route row')
        refused = direct[0]
        self.rpc('targetRules', silent=[], refused=[self.networks[refused]])
        lost = os.environ.get('COORDINATED_CASE', 'complete') == 'ambiguous'
        process, operation, paths = self.invoke('activation', lost=lost)
        code, out, err = self.finish(process, 'activation')
        if lost:
            require(code != 0 and b'single attempt failed/ambiguous' in err, 'ambiguous-return injection did not reach sole activation')
            self.record('ambiguous-return-no-retry', operationId=operation)
            return dict(state='passed', scope='ambiguous sole holder attempt only; no recovery qualification',
                        coordinatedQualified=False, ambiguousReturnQualified=True)
        require(code == 0, 'real coordinated collector failed; inspect private evidence on helper volume')
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
        # Repeat SAME operation through the real helper: observation only. A new
        # UUID must fail; no second replacement or automatic rollback exists.
        for new_operation, expected in ((operation, 0), (str(uuid.uuid4()), 1)):
            result = subprocess.run(['docker', '--context', self.context, 'exec', self.helper_id, 'python3',
                '/tools/ircfiber-holder-maintenance.py', 'activate', '--mode', 'coordinated',
                '--operation-id', new_operation, '--image', self.new_holder, '--fixture-spec', paths['fixture'],
                '--coordinated-config', paths['intent']], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
            require((result.returncode == 0) == (expected == 0), 'permanent paired-transition fence violated')
        self.record('one-stop-one-holder-first-A-complete-denominator', classification=completed)
        self.start_diagnostics()
        self.hot_swap_after_maintenance(recovered, completed, self.identity(self.owned('ircfiber-holder')))
        return dict(state='passed', coordinatedQualified=True, affinityBasis='current_verified',
                    historicalExitUnprovableCount=len(dynamic), classification={key: completed.get(key) for key in
                    ('recoveredCount', 'refusedCount', 'unresolvedCount')}, separateFull250LoadGateRequired=True,
                    nativeIpv6='not configured; no native IPv6 claim', providerControl='explicit tailscaled LocalAPI emulator')

    def run(self):
        self.setup()
        self.preflight_refusals()
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
            # Private env/META/provenance remains inside the root-owned volume.
            # Export only allowlisted bounded public results and tool hashes.
            qualification.save('coordinated-result.json', result)
    print(json.dumps(result), flush=True)
    return 0 if result['state'] == 'passed' else 1


if __name__ == '__main__':
    sys.exit(main())
