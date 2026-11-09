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
