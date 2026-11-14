# ircfiber-engine — IRC Daemon

**D daemon that holds IRC TCP/TLS for IRC Fiber.** Always-on, rejoins, replays via `CHATHISTORY`. Portfolio analog for **Celery workers + Python daemons** at scale.

<p align="center">
  <a href="https://github.com/kevinpostal/irc-fiber">
    <img src="https://github.com/kevinpostal/irc-fiber/releases/download/v0.3.0-demo/irc-fiber-final-minimal.gif" width="800" alt="IRC Fiber demo — #zod typing" />
  </a>
</p>

![D LDC 1.41](https://img.shields.io/badge/D-LDC%201.41-8B0000)
![vibe.d](https://img.shields.io/badge/vibe.d-0.10-8B0000)
![Redis](https://img.shields.io/badge/Redis-7-DC382D)
![Ansible](https://img.shields.io/badge/Ansible-decoupled-E00)
[![Hits](https://hits.dwyl.com/kevinpostal/ircfiber-engine.svg)](https://hits.dwyl.com/kevinpostal/ircfiber-engine)

<p align="center"><a href="https://skillicons.dev"><img src="https://skillicons.dev/icons?i=d,redis,py&perline=5" alt="Skills" /></a></p>

## Why this matters for hiring

At **Rabl** I ran `Celery` + `RabbitMQ` (10K+ jobs/day) and at **National Services Group** I fixed memory leaks via profiling/caching. This daemon is the same — but for IRC:

* **Holds connections:** `engine/source/ircfiber/irc/{connection,manager,parser}.d` — per-network `ConnectionServer`, `SASL`/`CAP`/`CHATHISTORY`, exponential backoff, `TLS` soft-reconnect.
* **Sharded + resilient:** `ServerRegistry` shards networks across `engine` hosts, `EngineJanitor` TTL (Redis `EXPIRE 600s`), `NetworkStateSnapshot` survives `docker restart` / host reboot — same patterns as `Celery` + `Redis` + `Mongo` I shipped.
* **Ops:** `Containerfile.engine` (`base` → `builder-common` → `builder-engine` → `runtime-engine`) **never compiles `frontend/`/`backend/`** — `make ship-engine` (ircfiber-infra) builds on the prod host and hot-swaps `ircfiber-engine-*` only, gateway stays up.

Server ban/throttle classification ignores IRC colour/style codes and letter
spacing, including Super Nets' decorated `ENTER THE VOID` refusal. A rejected
exit is host-banned by the existing routing policy; the next attempt uses another
eligible exit within the network's selected provider rather than retrying that IP.

## IRCv3 recovery

Replay ancestry is resolved before current-state handlers. Historical state
events stay in their enclosing conversation's timeline without changing the
current roster, identity, topic, metadata or automatic actions. Nested multiline
and valid open batches survive retained-socket adoption; malformed ancestry is
quarantined rather than reclassified as live.

Known gaps paginate from a frozen committed boundary; short nonempty pages do
not imply completion. TARGETS discovery also finds missed conversations.
`irc:history:recovery:<networkId>` stores committed per-target progress and
`*targets` discovery state without a TTL. Ordered processor acknowledgement
advances a page only after Redis append/dedup acceptance under current ownership.
Acknowledgement must only update recovery state and enqueue follow-up work; it
must not send IRC commands or publish into the bounded event ring drained by
that same ordered processor. Sending can publish flood-pacing logs and block
the processor on its own full ring, stopping event consumption and checkpoint
progress. The connection reader's next recovery tick dispatches queued work,
including work left pending after a rejected acknowledgement.
This preserves, rather than strengthens, existing asynchronous MongoDB durability.
Crash adoption merges committed Redis cursors with unresolved holder-META intent:
a complete pre-gap seed must not erase a stalled failed-storage page's retry.
Unresolvable timestamp-only boundaries remain explicitly stalled.

Part of [kevinpostal/irc-fiber](https://github.com/kevinpostal/irc-fiber) superproject.

## Quick start

```bash
git clone https://github.com/kevinpostal/ircfiber-engine.git
cd ircfiber-engine
./scripts/generate-version.sh
dub --root=common build && dub --root=engine build
./engine/irc-fiber-engine --config config/dev.conf
```

### Docker

```bash
docker compose up -d  # Containerfile.engine --target runtime-engine
docker compose logs -f engine
```

## Structure

```
ircfiber-engine/
 engine/source/app_engine.d
 engine/source/ircfiber/{irc/{connection,manager,parser,sasl},engine/{bootstrap,consumer,processor,state}}
 common/source/ircfiber/{redis,models,db,storage} # duplicated from ircfiber-common
 backend/dub.sdl + dub.selections.json           # stub for dub validation
 Containerfile.engine + Makefile.engine + docker-compose.yml
 (deploys: `make ship-engine` from ircfiber-infra — site/deploy/playbooks/engine-deploy.yml)
```

## Configuration

```bash
cp deploy/inventories/production/group_vars/vault.example.yml deploy/inventories/production/group_vars/vault.yml
op inject -i vault.example.yml -o vault.yml  # 1Password, or Codespaces secret
ansible-vault edit deploy/inventories/production/group_vars/vault.yml
```

No hardcoded `ircfiber_admin_password` — via `vault_ircfiber_admin_password`.

## Deployment

```bash
make -C .. ship-engine        # from ircfiber-infra: build on the prod host, deploy by image id
# hot-swaps the engine container only (IRC sockets held by the holder; gateway untouched)
```

Release container builds schedule compiler instances serially to bound peak memory. Build on a healthy non-production Linux builder when production lacks headroom; transfer immutable images rather than compiling on the live host. Engine, holder and migration binaries are all built from the same committed checkout with hash-checked pinned dependency patches.

The engine can hot-attach to legacy protocol-v1 holders through genuine streaming `LIST`; newer holders advertise bounded `INVENTORY` and gap-acknowledgement capabilities. A holder replacement cannot preserve its TCP/TLS sockets. `make ship-holder` deliberately refuses: use only the directly scoped `site/deploy/playbooks/holder-deploy.yml` with an immutable qualified image, preserved live configuration, maintenance UUID and fresh collector evidence. This is a single-attempt fenced operation, not a retry/rollback loop.

Durable archive ingress uses `/var/lib/ircfiber/archive` by default. Mount persistent per-engine storage across swaps; the defaults cap spool storage at 512 MiB and require 2 GiB free disk. `IRCFIBER_ARCHIVE_DIR`, `IRCFIBER_ARCHIVE_MAX_BYTES` and `IRCFIBER_ARCHIVE_MIN_FREE_BYTES` configure that storage. Unknown/failed archival acknowledgement remains pending or explicitly degraded; it is not reported as a successful archive.

## Testing

```bash
dub --root=engine test && dub --root=common test
# site/common is the source of truth — edits flow site -> engine via
# site/scripts/sync-common.sh, so this side only checks:
./scripts/check-common-drift.sh --fetch  # common in sync?
python3 -m pytest tests/irc_parity -v  # against mock ircd
```

### Reaction history regression

With an isolated Redis listening on `127.0.0.1:6379`:

```bash
dub --root=engine build --config=buffer-dedup-test
./engine/buffer-dedup-test
```

The Redis round trip checks reply targets and ordered reaction add/remove rows through the actual scrollback writer and filtered reader, including tag aliases, preferred-tag precedence, legacy/namespaced storage and typing-noise exclusion.

### VPN egress reliability

Saved networks use `routing: {order: null | [...], preferredExit: ""}`.
An explicit order is the complete permitted route list; `["nordvpn"]` uses
only configured NordVPN SOCKS exits, without Mullvad or shared-direct fallback.
`null` currently inherits `["mullvad","nordvpn","direct"]` (the first-party
network remains direct-only). An empty order or malformed stored preferences
starts no dial. `preferredExit` biases an eligible exit within its provider
tier and cannot enable an omitted provider.
After a registered session survives 60 seconds, an upstream socket loss makes
that client prefer another exit for five minutes. Correlated losses on two
distinct IRC hostnames within 90 seconds exclude their shared static exit
from new connections. This is a precautionary correlation, not proof that
the VPN provider caused the losses. Existing sockets stay open.

Admission lives in Redis at `irc:egress:admission:<label>`, bound to the
configured proxy endpoint. Quarantine survives engine hot swaps and applies
to every engine; neither a preferred exit nor route memory bypasses it.
After the minimum five-minute cooldown, one atomically claimed recovery
session may try the exit after healthy candidates within its permitted tier. It must stay
registered for at least 60 seconds and answer a matching keepalive sent
after that window before the exit admits ordinary connections again.
Failed or expired trials double the cooldown up to one hour. Fresh
correlated loss during a trial invalidates its claim; stale callbacks cannot
undo a drain or reopen the circuit. A hot-swapped trial needs a fresh
keepalive from the new engine, not an inferred success from reattachment.

Admin's Mullvad and NordVPN tables distinguish the SOCKS probe from
`healthy`, `quarantined`, `recovering`, `draining`, or `unavailable` admission.
Drain/resume affects new connections only and never queues reconnects.
Resume does not clear quarantine. Malformed, changed-endpoint, or unreadable
records fail closed; an acknowledged replacement endpoint must recover.
A refused quarantine write leaves the exit locally excluded while the
engine retries persistence. All exits sharing one NordVPN account remain a
provider-wide failure domain; this does not buy independent provider capacity.

Run `bash scripts/e2e/egress_failover.sh` only against a disposable local
Docker stack to exercise failover, drain, recovery, silent blackholing, and
no-direct fallback; `bash scripts/e2e/hot_swap.sh` checks holder continuity.
The shared package's `egress-admission-redis-test` configuration exercises
atomic claims and fencing. It requires a dedicated disposable Redis and
`EGRESS_ADMISSION_ALLOW_CONFIG_TEST=1`: its write-failure case temporarily
changes server-wide `min-replicas-to-write`, then restores it.
On a quarantine transition the engine queues one `notice` in
`irc:logs:outbox`; FiberEye delivers it to `#staff`. Notice delivery is
best-effort; it is not the source of the admission decision.

### Ordered route selection and IPv6

Routing remembers completed TCP+TLS/STARTTLS dials per host, port, and TLS mode:
successful exits lead within their configured provider tier for 30 minutes,
and failed exits go last in that tier for five minutes. Neither remembered
success nor a preferred exit can change the saved provider order. Memory is
process-local and bounded to 512 endpoints with 32 concrete routes each;
retargeting an exit starts fresh. Host-specific TLS failures do not trip an
exit's global circuit breaker. Host bans, SASL gates, client avoidance and
durable admission still apply.

The `ipv6` route tier requires a valid routed pool prefix, the saved immutable
IID and a holder advertising IPv6-only dial capability. It binds the reserved
source address and never substitutes shared-direct or a dual-stack dial.
Legacy holders withdraw this capability; missing prerequisites skip the tier
within the existing saved provider order.

Direct TLS/STARTTLS tries the remaining vetted DNS addresses if the first
TCP winner fails negotiation. Each address gets at most one protocol attempt,
with the existing timeouts, original SNI, and no plaintext downgrade.
The timeline can therefore contain multiple TCP-open and TLS-attempt events
within one direct dial.

For a provider-assigned **shared /128**, set `ircfiber_public_ipv6_address`,
`ircfiber_public_ipv6_gateway`, and `ircfiber_public_ipv6_interface` in host
inventory. The engine role persists a netplan overlay and adds the address
and routes without restarting networking or containers. This is separate from
`ircfiber_ipv6_prefix`, which accepts only an aligned global-unicast routed
`/64`. Each saved connection has an immutable random `ipv6Iid`, allocated
atomically in Mongo with a unique partial index. Its address reservation uses
that IID and the serving node's pool, never the owner's UUID, nick or host.
Missing/invalid IIDs or prefixes produce no reservation; the engine never
generates a transient replacement. Different saved connections have different
IIDs; reconnects and hot swaps retain them.

A reservation alone is not evidence of an active source. Native route status
uses the holder-observed `localIp`/`peerIp`; shared-direct retains no pool bind,
including its plaintext fallback. Restoring a legacy shared IPv6 socket does
not relabel it as a native reservation.
The obsolete per-owner rDNS pool setting has been removed.
An assigned IPv6 route does not override a remote server's access policy.

```bash
cd engine
dub test --compiler=ldc2
dub run :holder --config=dial-fallback-test --compiler=ldc2
```

The real-socket harness requires IPv6 loopback and `openssl`; it checks TLS
fallback, bounded silent-peer timeouts with scheduler progress, cleanup,
STARTTLS, unchanged plaintext behavior, original SNI, and destination policy.
Installing holder-side functionality disconnects every socket that holder owns;
an engine hot swap alone cannot install it. Use the qualified, guarded maintenance
entry described above, not an unqualified holder recreation.

### Bounded memory and archive qualification

The engine exposes `memory-reliability-test`, `archive-buffer-test` and
`archive-storage-test` DUB configurations; the storage fixture requires explicit
credential-free loopback Mongo isolation and failpoint opt-in. Shell launchers in
`scripts/e2e/` enforce disposable Docker fixtures and immutable candidate images.
`legacy_holder_continuity.sh` covers old-holder engine transfer;
`holder_engine_qualification.sh` and `holder_memory_reliability.sh` cover the
candidate holder. `archive_reliability.sh` is the candidate-only archive proof.
The memory harness treats asynchronous producer-preparation exceptions as a
failed check, while satisfying vibe's non-throwing task callback contract.
Smoke-duration runs are not the full warm-up/soak qualification receipts.

Scrollback is not a prerequisite for live publication: a failed Redis buffer
write is reported separately, while nonhistorical messages still enter the
durable journal and live/user-stream paths. Confirmed duplicates remain
suppressed; failed historical pages never advance their storage checkpoint.
Scope preparation parses UUIDs through a local cursor, preserving the original
network identifier for ownership checks and majority catalog registration.
This does not make Redis sequencing/pubsub outages or rejected journal
admission lossless.

An expiring lineage companion whose locator disappeared receives a fresh
incarnation on append, preserving surviving rows and dedup. The old locator is
never reconstructed, so an old frozen purge cannot acquire replacement
history. Persistent companions, wrong types and existing mismatches fail
closed. Redis must use `noeviction`: paired lineage, dedup and scrollback keys
are one logical dataset, not independently disposable cache entries.

Recent, cursor and unread reads select by message time across bounded hot
history, not by backfill arrival order. A terminal journal failure keeps the
existing native disk owner available for fresh diagnostic snapshots until
shutdown, without reopening archival admission or retrying the failed journal.
Failed archive runs capture bounded wire status, exact container generations,
registry and logs before Mongo resume or launcher teardown. Evidence/cleanup
errors are retained separately without replacing the original failure reason;
constructor failures cannot provide observations from an uncreated fixture.

The coordinated fixture's legacy IPC source digest comes from the plain
`fea67fb4` revision declared by the immutable `8e7447fa` holder image and its
runtime build metadata. This associates reviewed synchronous accept/dispatch
source with the declared revision; it does not assert a reproducible binary
build. Exact image/executable and fresh kernel stream-lifetime checks remain
independent prerequisites.
Its in-flight DIAL fixture sends a real LF delimiter and requires an actual
`CONNECTED` reply before claiming admission; a literal backslash-n is not framing.

Queued configuration, connection lifecycle, migration and provider retarget
effects acquire the existing Common logical writer at execution, not merely at
queue insertion. One admission spans canonical Mongo writes, Redis assignment/
lease evidence, commands and external retarget completion. Ambiguous replies
retain non-expiring writer evidence; maintenance refuses a cut while it remains.
Ordinary IRC, heartbeats, matching-owner lease renewal and held-session restoration
remain available. Restoration validates the canonical owner and held claim before
starting its reader; it does not bypass the canonical write exclusion.

During exclusion, validated existing owners may durably journal RAW records with
pending catalog provenance. Replay must prove the current canonical owner and
catalog before history persistence or checkpoint advancement. Transferred/deleted
owners are quarantined visibly rather than silently discarded or replayed under
an unverified owner.

`dub build --config=consumer-write-test` builds the real logical-writer regression
driver. Run it with `IRCFIBER_CONSUMER_TEST_ISOLATED=1`, explicit loopback
`IRCFIBER_HISTORY_TEST_REDIS_URL` (initially empty) and
`IRCFIBER_HISTORY_TEST_MONGO_URL`, plus a run-owned holder endpoint/token in
`IRCFIBER_CONSUMER_TEST_HOLDER_ADDR`/`IRCFIBER_CONSUMER_TEST_HOLDER_TOKEN`.
`IRCFIBER_CONSUMER_TEST_EGRESS_LABEL` and
`IRCFIBER_CONSUMER_TEST_EGRESS_LOCATION` must identify a disposable real
controllable tailscaled slot configured through the usual pool/control-directory
settings. Missing fixtures fail, never skip. This executes queued effects,
held-reader journal restart/replay and real provider completion/lost-ACK races.

The coordinated regression collector runs as a native Linux x86_64 host-root
child, not a privileged Docker helper. Its full owned-daemon inventory, actual
kernel process/cgroup/executable evidence and immutable receipt inputs remain
mandatory. Failed fixtures retain evidence and owned containers for diagnosis;
remove only that fixture's exact containers and volumes before another run.
Scratch maintenance admission is explicitly `qualified=false`,
`purpose=isolatedqualification`, `checks=[]`. It is available only on the
native root-owned disposable Colima host after complete container/image,
volume/network and exact tool-byte checks, with retained hash-named real
build/source/consumer receipts (`artifactBindings`, including the holder, plus
the writer receipt subset). It never authorizes production maintenance.
Supply `COORDINATED_QUALIFICATION_FILE`/`COORDINATED_RECEIPT_DIR` to the coordinated
fixture, or `HOLDER_QUALIFICATION_FILE`/`HOLDER_RECEIPT_DIR` to online maintenance
qualification. Production still requires a completed `qualified=true` receipt
containing every physical check. Mongo's config volume is explicitly owned;
unlabelled anonymous volumes are not exempted from the fixture denominator.
The coordinated native domain cases exercise the actual Site executable and
owner network namespace against real Redis: unique alias/DB0/nonce success,
another real Redis domain, an actual owner `/1` configuration, live Docker alias
collision, fresh inventory after restoration, and nonce replacement. Each
specific refusal and source/binary identity is retained before deleting only
the exact temporary domain containers. These cases are not a coordinated cut
or a full-load qualification receipt.

The selected rollout is the atomic old `f9a5` engine + `8e7447` holder to the
new engine + new holder. No interim or fallback new-engine/old-holder start is
authorized. `legacy_holder_continuity` is therefore inapplicable to this order,
not waived or passed. Exact old-source/kernel provenance, snapshot compatibility,
positive producer absence and the physical paired cut remain mandatory.




## Links

* Superproject: [kevinpostal/irc-fiber](https://github.com/kevinpostal/irc-fiber)
* Site: [kevinpostal/ircfiber-site](https://github.com/kevinpostal/ircfiber-site)
* Common: [kevinpostal/ircfiber-common](https://github.com/kevinpostal/ircfiber-common)

## License

MIT