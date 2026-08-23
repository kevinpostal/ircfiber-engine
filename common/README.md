# common — duplicated until ircfiber-common package

This `common/` is duplicated in `ircfiber-site` and `ircfiber-engine` (Option A).
Keep in sync via cherry-pick. Drift check: `scripts/check-common-drift.sh` fails PR if drift >0.
Follow-up: extract `kevinpostal/ircfiber-common` as dub package `irc-fiber-common` version `~>0.3.0`.
