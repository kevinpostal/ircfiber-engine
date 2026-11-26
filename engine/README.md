# Engine — IRC Fiber D Backend

Enterprise-grade D service that maintains persistent IRC connections and serves the gateway API.

## Layout
```
engine/
├── source/              D sources (app.d, app_engine.d, ircfiber/*)
│   ├── ircfiber/
│   │   ├── api/         REST + WebSocket
│   │   ├── db/          Mongo models
│   │   ├── engine/      Consumer / processor
│   │   ├── irc/         IRC client, registry, SASL, CHATHISTORY
│   │   ├── web/         HTTP routes
│   │   └── ...
│   └── tools/           Migrators, loadtest
├── views/               Diet-NG templates (index.dt, login.dt, admin/*)
├── dub.sdl              D build manifest (vibe-d, diet-ng)
├── dub.selections.json  Locked dependencies
└── genhash.d            Helper for password hashing
```

## Build
```bash
dub build --root=engine          # debug
dub build --root=engine --build=release
make build        # via top-level Makefile (uses --root=engine internally)
make build-engine # engine binary only
```

## Config
- `../config/dev.conf` and `../config/prod.conf` (shared)
- `../public/` served as static assets (Vite output in public/dist)

## Notes
- Diet templates are compiled via `stringImportPaths` resolved relative to `engine/` when built with `--root=engine`.
- All `find source` / `find views` references in the top-level Makefile now point to `engine/source` and `engine/views`.

## Shared dependency and process-state ownership

`common/` is a real git submodule pinned to one immutable commit of
`kevinpostal/ircfiber-common`. Existing clones should run
`git submodule update --init --recursive`. Do not restore an inline mirror or
edit common sources in this repository. The local deployment stack is the
sibling `../site/deploy/local` tree, configurable through `LOCAL_STACK_DIR`.

The architecture extraction confines state behind module APIs, not eliminates
all process globals:

- `ircfiber.irc.host_breaker` owns one process-shared table and its eagerly
  initialized lock. Failure, success, admission and reconnect-delay access all
  take that lock. The unused manager-local duplicate was removed. The original
  window, thresholds and distinct cooldown-expiry paths are preserved.
- `ircfiber.irc.webirc_suppress` owns the process-wide suppression table and an
  independent eagerly initialized lock. It does not acquire `gMullvadLock`.
  Ban-policy and registration call sites already invoke suppression separately
  from egress-pool operations, so there is no compound pool-table transaction
  being split. Every suppression read, insertion and expiry removal takes the
  same module lock.
- `ircfiber.irc.ipv6_config` owns the prefix cache, loaded flag and lock. First
  environment read and all later reads are serialized. Existing holder-family,
  physical-routing and saved-IID gates remain in the connection path.

Run native extraction and transport gates from `engine/engine`:

```sh
dub run --config=architecture-test
dub run --config=startup-test
dub run --config=unittest -b unittest
dub run --config=services-test
dub run --config=connection-registration-test
dub run --config=dial-guard-test
dub run :holder --config=dial-fallback-test
dub build --config=engine
dub build :holder
```

`dial-guard-test` requires an isolated Redis on `127.0.0.1:6379`.
Set `IRCFIBER_HISTORY_TEST_REDIS_URL=redis://127.0.0.1:6379/0` to include
registration's full writer-ledger regression, using only an isolated empty
fixture. Do not point these tests at production or a shared development DB.
The architecture gate exercises cross-thread breaker visibility, shared
WEBIRC inserts/read/expiry under concurrency and concurrent IPv6 initialization.
The module unittest runner explicitly enumerates all three extracted modules.

The canonical common library also requires atomic strict reporter configuration
and process-owner handling of `HolderStartupException`. The narrow
`ircfiber.engine.startup` adapter configures reporting before holder bootstrap,
honors an authoritative DSN file, reports a typed startup failure once, waits
for its bounded report and preserves process status 75/78. Other exceptions
retain their prior propagation. `startup-test` checks the status boundary in
subprocesses with reporting disabled, plus configuration state transitions
without sending reports. From the repository root,
`python3 test/test_engine_startup.py` runs the same status boundary with a
loopback-only synthetic HTTP ingest and checks exactly one private report for
each bootstrap/terminal failure before process exit. No production ingest or
credentials are used.

## Anope services compatibility

Anope 2.0/2.1 VERSION families select candidate reply decoders; an unknown
build hash does not by itself disable integration. Complete, target-bound
read replies establish readable state. Non-exact builds also need compatible,
command-specific HELP syntax before a control becomes requestable or a
mutation is sent. Missing or incompatible evidence disables only affected
controls; it never grants authority or fabricates an empty list.

Approved endpoint pins, account/channel authorization, reviewed revisions,
paced-write guards and mutation-result verification remain independent.
HELP evidence is private to one transaction and bound to the actual endpoint,
raw VERSION and authority generation. Other products/version families remain
unsupported. This does not change service identities or deploy an engine.

Run the focused parser, real-adapter and localhost socket regressions from
`engine/engine`:

```sh
dub run --config=services-test
```
