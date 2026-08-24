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

## Why this matters for hiring

At **Rabl** I ran `Celery` + `RabbitMQ` (10K+ jobs/day) and at **National Services Group** I fixed memory leaks via profiling/caching. This daemon is the same — but for IRC:

* **Holds connections:** `engine/source/ircfiber/irc/{connection,manager,parser}.d` — per-network `ConnectionServer`, `SASL`/`CAP`/`CHATHISTORY`, exponential backoff, `TLS` soft-reconnect.
* **Sharded + resilient:** `ServerRegistry` shards networks across `engine` hosts, `EngineJanitor` TTL (Redis `EXPIRE 600s`), `NetworkStateSnapshot` survives `docker restart` / host reboot — same patterns as `Celery` + `Redis` + `Mongo` I shipped.
* **Ops:** `Containerfile.engine` (`base` → `builder-common` → `builder-engine` → `runtime-engine`) **never compiles `frontend/`/`backend/`** — `ansible-playbook deploy-engine.yml` hard-restarts `ircfiber-engine-*` only, gateway stays up.

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
 deploy/playbooks/deploy-engine.yml               # src_root=/opt/ircfiber-engine
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
ansible-playbook deploy/playbooks/deploy-engine.yml -l vps-efb4b52d
# BuildKit --target runtime-engine, hard-restarts engine only
```

## Testing

```bash
dub --root=engine test && dub --root=common test
./scripts/check-common-drift.sh --fetch
python3 -m pytest tests/irc_parity -v  # against mock ircd
```

## Links

* Superproject: [kevinpostal/irc-fiber](https://github.com/kevinpostal/irc-fiber)
* Site: [kevinpostal/ircfiber-site](https://github.com/kevinpostal/ircfiber-site)
* Common: [kevinpostal/ircfiber-common](https://github.com/kevinpostal/ircfiber-common)

## License

MIT
