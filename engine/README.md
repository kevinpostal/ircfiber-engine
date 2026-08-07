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
