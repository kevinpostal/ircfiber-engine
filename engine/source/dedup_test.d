/// Standalone regression test for the /irc/<net>/channel/<chan> duplicate-
/// message-on-refresh bug. See `source/ircfiber/api/rest.d` for the dedup
/// helper that this exercises. Pinned at a binary `dedup-test` so it can
/// run in CI without booting Redis/Mongo (which the full unittest build
/// needs and which is currently broken on macOS — see dub.sdl `unittest`
/// config).
///
/// Run with: `dub build --config=dedup-test && ./dedup-test`.
module dedup_test;

import std.conv : to;
import std.json : JSONValue;
import std.stdio : stderr, writeln;

import vibe.data.json : Json;

static import ircfiber.api.rest;

// Reach into the package-static dedupMessages helper via the class.
import ircfiber.api.rest : RESTAPI;

/// Tracks the number of passing checks.
int passed;
/// Tracks the number of failing checks.
int failed;

/// Records the outcome of a single named check.
void check(string name)(bool cond, string msg = "") {
    if (cond) {
        ++passed;
        stderr.writeln("  PASS  ", name);
    } else {
        ++failed;
        stderr.writeln("  FAIL  ", name, "  ", msg);
    }
}

void main() {
    stderr.writeln("dedupMessages regression suite");

    // The real bug: #zod had 9-16 Redis messages; MongoDB returned 200;
    // each Redis msg appeared twice in the response.
    {
        auto existing = [
            Json(["m": Json("msg-a"), "eid": Json(100)]),
            Json(["m": Json("msg-b"), "eid": Json(101)]),
        ];
        auto older = [
            Json(["m": Json("msg-a"), "eid": Json(100)]),
            Json(["m": Json("msg-c"), "eid": Json(102)]),
            Json(["m": Json("msg-b"), "eid": Json(101)]),
        ];
        auto deduped = RESTAPI.dedupMessages(existing, older);
        check!"drops MongoDB msgids already in Redis"(deduped.length == 1);
        check!"keeps the genuinely new message"(
            deduped.length > 0 && deduped[0]["m"].get!string == "msg-c");
    }

    // Legacy MongoDB entries lack msgid — eid fallback must catch them.
    {
        auto existing = [Json(["eid": Json(42), "x": Json("hello")])];
        auto older = [
            Json(["eid": Json(42), "x": Json("hello")]),
            Json(["eid": Json(43), "x": Json("world")]),
        ];
        auto deduped = RESTAPI.dedupMessages(existing, older);
        check!"falls back to eid when msgid missing"(deduped.length == 1);
        check!"eid fallback keeps the new eid"(
            deduped.length > 0 && deduped[0]["eid"].get!long == 43);
    }

    // No overlap → older passes through unchanged.
    {
        auto existing = [Json(["m": Json("a"), "eid": Json(1)])];
        auto older = [
            Json(["m": Json("b"), "eid": Json(2)]),
            Json(["m": Json("c"), "eid": Json(3)]),
        ];
        auto deduped = RESTAPI.dedupMessages(existing, older);
        check!"no overlap returns full older slice"(deduped.length == 2);
    }

    // Empty inputs are no-ops.
    {
        auto existing = [Json(["m": Json("a"), "eid": Json(1)])];
        auto deduped = RESTAPI.dedupMessages(existing, []);
        check!"empty older yields empty deduped"(deduped.length == 0);

        auto older2 = [Json(["m": Json("a"), "eid": Json(1)])];
        auto deduped2 = RESTAPI.dedupMessages([], older2);
        check!"empty existing passes older through"(deduped2.length == 1);
    }

    writeln("\n", passed, " passed, ", failed, " failed");
    import core.stdc.stdlib : exit;
    if (failed > 0) exit(1);
}