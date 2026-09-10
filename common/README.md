# common — mirror of ircfiber-common

This `common/` is a mirror of `site/common` (source of truth) and the canonical `kevinpostal/ircfiber-common` repo (dub package `irc-fiber-common`, tagged `common-v0.3.x`).
Do not edit here — edit `site/common/`, then run `site/scripts/sync-common.sh` (copies `source/` + `dub.sdl` only). Guards: `site/scripts/check-common-drift.sh --fetch` fails CI on drift; `site/scripts/check-common-version.sh` checks version + dep strings (`~>0.3.1`).
