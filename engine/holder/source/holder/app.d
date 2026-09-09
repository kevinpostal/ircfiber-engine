/**
 * irc-fiber-holder — owns every IRC TCP/SOCKS5/TLS socket for one engine
 * and relays plaintext IRC bytes to it over unix/TCP streams, so the
 * engine can be hot-swapped without the IRC server noticing.
 *
 * Daemon: `irc-fiber-holder` (env `IRCFIBER_SERVER_ID` required,
 * `IRCFIBER_HOLDER_ADDR`, `IRCFIBER_HOLDER_TOKEN`, …; see protocol.d).
 * Client: `--check` (HELLO+STATUS, exit 0/1 — healthcheck), `--status`,
 * `--list` — dial `IRCFIBER_HOLDER_ADDR` with a 3 s timeout.
 */
module holder.app;

import core.stdc.stdlib : exit;
import core.time : msecs, seconds;
import std.stdio : stderr, stdout, writeln;
import vibe.core.core : exitEventLoop, runApplication, runEventLoop, sleep;
import vibe.core.net : TCPConnection;
import vibe.data.json : Json;
import ircfiber.async : safeFiberRun;
import ircfiber.logging : logJsonMap;
import ircfiber.term_signal : installTermSignalFlag, termSignal;
import holder.ipc : HolderConfig, HolderServer, configFromEnv, connectHolderAddr;
import holder.protocol;

/// EX_CONFIG: misconfiguration the operator must fix.
private enum EXIT_CONFIG = 78;
/// Client-side timeout for `--check` / `--status` / `--list`.
private enum CLIENT_TIMEOUT = 3.seconds;

int main(string[] args) {
    string mode;
    if (args.length > 1) mode = args[1];
    switch (mode) {
        case "":
            return runDaemon();
        case "--check":
        case "--status":
            return runClient("STATUS", mode == "--check");
        case "--list":
            return runClient("LIST", false);
        default:
            stderr.writeln("usage: irc-fiber-holder [--check|--status|--list]");
            return 64;
    }
}

private HolderConfig loadConfigOrExit() {
    HolderConfig cfg;
    try cfg = configFromEnv();
    catch (Exception e) {
        stderr.writeln("irc-fiber-holder: ", e.msg);
        exit(EXIT_CONFIG);
    }
    return cfg;
}

private int runDaemon() {
    auto cfg = loadConfigOrExit();
    if (cfg.serverId.length == 0) {
        stderr.writeln("irc-fiber-holder: ", ENV_SERVER_ID, " is required");
        return EXIT_CONFIG;
    }
    if (cfg.tokenRequired && cfg.token.length == 0) {
        stderr.writeln("irc-fiber-holder: ", ENV_TOKEN, " is required for a tcp:// address");
        return EXIT_CONFIG;
    }
    auto server = new HolderServer(cfg);
    installTermSignalFlag();
    int rc = 0;
    safeFiberRun("holder_main", "", {
        try server.start();
        catch (Exception e) {
            logJsonMap("error", "holder", "Cannot listen", ["addr": cfg.addrText, "error": e.msg, "event": "listen_fail"]);
            rc = 1;
            exitEventLoop();
            return;
        }
        while (termSignal() == 0) sleep(100.msecs);
        // In-loop shutdown: QUIT every open session, give the servers a
        // moment to close, then leave. This is a full reconnect event for
        // the engine — holder restarts are planned maintenance only.
        logJsonMap("warn", "holder", "Holder stopping — quitting every held connection",
            ["signal": termSignal() == 15 ? "SIGTERM" : "SIGINT", "event": "shutdown"]);
        server.quitAll();
        sleep(1.seconds);
        server.stop();
        exitEventLoop();
    });
    runApplication();
    return rc;
}

/// Sends `HELLO` then `request` over one control session and prints the
/// `OK` payload. Returns the process exit code.
private int runClient(string request, bool check) {
    auto cfg = loadConfigOrExit();
    int rc = 1;
    safeFiberRun("holder_main", "", {
        scope (exit) exitEventLoop();
        try {
            auto conn = connectHolderAddr(cfg.addr.toNetworkAddress(true), CLIENT_TIMEOUT);
            scope (exit) conn.close();
            conn.readTimeout = CLIENT_TIMEOUT;
            auto hello = HelloRequest(PROTO_VERSION, cfg.serverId, "cli-" ~ cfg.buildShort, cfg.token);
            auto reply = roundTrip(conn, "HELLO " ~ hello.toJson().toString());
            if (reply.type != Json.Type.object) return;
            reply = roundTrip(conn, request);
            if (reply.type != Json.Type.object) return;
            writeln(reply.toString());
            stdout.flush();
            rc = 0;
        } catch (Exception e) {
            stderr.writeln("irc-fiber-holder: ", e.msg);
        }
    });
    runEventLoop();
    return rc;
}

/// Writes one request line, reads one response line; returns the `OK`
/// payload or `Json(null)` after printing an `ERR` to stderr.
private Json roundTrip(ref TCPConnection conn, string line) {
    import vibe.data.json : parseJsonString;
    import vibe.stream.operations : readLine;
    conn.write(cast(const(ubyte)[]) (line ~ "\n"));
    conn.flush();
    auto resp = cast(string) readLine(conn, MAX_LINE, "\n");
    if (resp.length >= 3 && resp[0 .. 3] == "OK ") return parseJsonString(resp[3 .. $]);
    stderr.writeln("irc-fiber-holder: ", resp);
    return Json(null);
}
