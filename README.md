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

## Testing

```bash
dub --root=engine test && dub --root=common test
# site/common is the source of truth — edits flow site -> engine via
# site/scripts/sync-common.sh, so this side only checks:
./scripts/check-common-drift.sh --fetch  # common in sync?
python3 -m pytest tests/irc_parity -v  # against mock ircd
```

### VPN egress reliability

The `nordvpn` network pin uses **static SOCKS exits only**; if none can dial,
the engine retries with backoff rather than connecting directly or via Mullvad.
After a registered session survives 60 seconds, an upstream socket loss makes
that client prefer another exit for five minutes. Losses on two distinct IRC
hostnames within 90 seconds quarantine their shared static exit for five
minutes, without closing other live sockets. Avoided/quarantined exits remain
last-resort VPN candidates. All exits sharing one NordVPN account remain a
provider-wide failure domain.

Run `bash scripts/e2e/egress_failover.sh` against the local Docker stack to
prove correlated failover and the no-direct fallback; run
`bash scripts/e2e/hot_swap.sh` to prove holder sockets survive engine restarts.
On a quarantine transition the engine queues one `notice` in
`irc:logs:outbox`; FiberEye delivers it to `#staff`. Redis delivery is
best-effort and does not block reconnect decisions if unavailable.

### Automatic route selection and IPv6

Automatic routing remembers completed TCP+TLS/STARTTLS dials per host, port,
and TLS mode: successful routes lead for 30 minutes, failed routes go last
for five minutes but remain last resorts. Memory is process-local and bounded
to 512 endpoints with 32 concrete routes each; retargeting an exit starts fresh.
Host-specific TLS failures do not trip an exit's global circuit breaker.
Host bans, SASL gates, and client avoidance still take precedence. Direct pins
stay direct; NordVPN pins stay on NordVPN; location pins may use another VPN
exit but never fall back to direct.

Direct TLS/STARTTLS tries the remaining vetted DNS addresses if the first
TCP winner fails negotiation. Each address gets at most one protocol attempt,
with the existing timeouts, original SNI, and no plaintext downgrade.
The timeline can therefore contain multiple TCP-open and TLS-attempt events
within one direct dial.

For a provider-assigned **shared /128**, set `ircfiber_public_ipv6_address`,
`ircfiber_public_ipv6_gateway`, and `ircfiber_public_ipv6_interface` in host
inventory. The engine role persists a netplan overlay and adds the address
and routes without restarting networking or containers. This is separate from
`ircfiber_ipv6_prefix`, which requires an actually routed per-user prefix.
An assigned IPv6 route does not override a remote server's access policy.

```bash
cd engine
dub test --compiler=ldc2
dub run :holder --config=dial-fallback-test --compiler=ldc2
```

The real-socket harness requires IPv6 loopback and `openssl`; it checks TLS
fallback, bounded silent-peer timeouts with scheduler progress, cleanup,
STARTTLS, unchanged plaintext behavior, original SNI, and destination policy.
Deploying the holder (`make ship-holder`) disconnects **every IRC session**;
an engine hot swap alone cannot install holder-side address fallback.


## Links

* Superproject: [kevinpostal/irc-fiber](https://github.com/kevinpostal/irc-fiber)
* Site: [kevinpostal/ircfiber-site](https://github.com/kevinpostal/ircfiber-site)
* Common: [kevinpostal/ircfiber-common](https://github.com/kevinpostal/ircfiber-common)

## License

MIT