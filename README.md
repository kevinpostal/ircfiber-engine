# ircfiber-engine — IRC Daemon

Persistent IRC engine for IRC Fiber. Holds TCP/TLS connections, rejoins, replays history. Part of the IRC Fiber superproject.

![D LDC 1.41](https://img.shields.io/badge/D-LDC%201.41-8B0000)
![vibe.d](https://img.shields.io/badge/vibe.d-0.10-8B0000)

## What this is

- Maintains IRC connections per network, handles CAP/SASL/CHATHISTORY, reconnect backoff
- Stores state in Redis (`NetworkStateSnapshot`, `irc:stream`), fans events to gateway
- `EngineJanitor` TTL + `ServerRegistry` sharding

Gateway is separate: `kevinpostal/ircfiber-site`.

## Quick start

```bash
git clone https://github.com/kevinpostal/ircfiber-engine.git
cd ircfiber-engine
./scripts/generate-version.sh
dub --root=common build
dub --root=engine build
./engine/irc-fiber-engine --config config/dev.conf
```

### Docker

```bash
docker compose up -d  # uses Containerfile.engine --target runtime-engine
docker compose logs -f engine
```

`Containerfile.engine` stages: `base` → `builder-common` → `builder-engine` → `runtime-engine`. Never compiles `frontend/` or `backend/source`.

## Project structure

```
ircfiber-engine/
 engine/source/ircfiber/{irc,engine}  # connection.d, manager.d, parser.d, bootstrap.d
 engine/source/app_engine.d
 common/source/ircfiber/{redis,models,db} # duplicated from ircfiber-common
 backend/dub.sdl + dub.selections.json   # stub for dub validation only
 Containerfile.engine + Makefile.engine + docker-compose.yml
 deploy/playbooks/deploy-engine.yml       # src_root=/opt/ircfiber-engine
```

## Configuration

```bash
cp deploy/inventories/production/group_vars/vault.example.yml deploy/inventories/production/group_vars/vault.yml
ansible-vault edit deploy/inventories/production/group_vars/vault.yml
```

No hardcoded `ircfiber_admin_password` — set via `vault_ircfiber_admin_password`.

## Deployment

```bash
ansible-playbook deploy/playbooks/deploy-engine.yml -l vps-efb4b52d
# builds Containerfile.engine --target runtime-engine, hard-restarts ircfiber-engine-* only
```

## Testing

```bash
dub --root=engine test
dub --root=common test
./scripts/check-common-drift.sh --fetch
# parity tests (against mock ircd)
python3 -m pytest tests/irc_parity -v
```

## License

MIT
