/**
 * DEPRECATED — Handoff removed 2026-08-08. Hard restart only.
 * See AGENTS.md Engine Lifecycle.
 */
module ircfiber.engine.reload_orchestrator;
import std.conv : to;
import std.datetime : Clock;
import std.json : JSONValue, parseJSON;
import std.string : toStringz, indexOf, split;

import core.stdc.errno : errno;
import core.sys.posix.unistd : getpid, unlink;
import core.sys.posix.sys.socket : sendmsg, recvmsg, msghdr, cmsghdr, iovec;
import core.sys.posix.sys.un : sockaddr_un;
import core.sys.posix.fcntl;

import vibe.core.core : runTask, sleep, yield;
import vibe.core.log;
import core.time : seconds, msecs;

import ircfiber.engine.bootstrap : EngineContext;
// Bring handoff's public functions into our namespace. Note: handoff
// exports `WireRecord` (the JSON+FDS wire shape); the manager exports
// `HandoffRecord` (the (state, fd) shape used by the API).
import ircfiber.engine.handoff : HandoffState, WireRecord,
    handoffSocketPath,
    connectUnix, posixClose, writeAll, readAll, readFrame, readLine, writeLine,
    fromJSON, toJSON, readU32LE, createUnixListener, acceptUnix,
    sendRecordWithFds, receiveRecordWithFds, sendAck, waitForAck;
import ircfiber.irc.manager : HandoffRecord, ConnectionManager;
import ircfiber.redis.protocol : RedisKeys, ControlMessage;
import ircfiber.storage.redis : RedisStorage;
import ircfiber.irc.manager : ConnectionManager, HandoffRecord;

// ═══════════════════════════════════════════════════════════════════════════
//  RELOAD-FROM-PID adoption
// ═══════════════════════════════════════════════════════════════════════════
//
// The new engine reads `IRCFIBER_RELOAD_FROM_PID` (set by the
// `make engine-handoff` Makefile target). If set, it connects to the
// old engine's handoff socket, receives each network's state + raw
// socket FD, and adopts them in-place — no Mongo / Redis read, no
// re-registration dance.
//
// On success the new engine becomes a drop-in replacement for the
// old one: same `serverId`, same assigned networks, same socket FDs.

/// Result of a successful reload receive.
struct ReloadResult {
    /// Number of networks successfully adopted (plain or TLS).
    int plainCount;
    /// Number of networks that were TLS and require a soft reconnect.
    int tlsCount;
    /// Time taken for the entire receive, in milliseconds.
    long durationMs;
}

/// Adopt all handed-off connections from the old engine. This is the
/// bootstrap-time entry point for the new engine. Returns the
/// statistics so the caller can log them. Throws on protocol failure.
ReloadResult adoptFromOldEngine(ConnectionManager mgr, string socketPath) {
    logInfo("Reload: connecting to old engine at %s", socketPath);
    const startedAt = Clock.currTime.toUnixTime!long * 1000;

    // Open the Unix-domain stream socket.
    int sock = connectUnix(socketPath);
    scope(exit) posixClose(sock);

    // ├─ Handshake ────────────────────────────────────────────────
    // Protocol from serveReload:
    //   1. new engine writes "READY\n"
    //   2. old engine replies "HELLO <pid>\n"
    //   3. old engine writes "GO\n"
    //   4. For each record: "RECORD <kind> <nidLen>:<nid>\n",
    //      then binary frame, then wait for ACK
    //   5. "DONE <count>\n"
    //
    writeLine(sock, "READY\n");
    auto line = readLine(sock);
    if (line.length < 6 || line[0..5] != "HELLO")
        throw new Exception("reload: expected HELLO handshake, got: " ~ line);
    logInfo("Reload: old engine HELLO: %s", line);

    line = readLine(sock);
    if (line != "GO")
        throw new Exception("reload: expected GO, got: " ~ line);
    logInfo("Reload: handshake complete, receiving records…");

    // ├─ Receive records ──────────────────────────────────────────
    ReloadResult result;
    while (true) {
        // Read a text line: either a RECORD header or DONE sentinel
        line = readLine(sock);

        // Check for DONE sentinel
        if (line.length >= 4 && line[0..4] == "DONE") {
            logInfo("Reload: old engine reported %s", line);
            break;
        }

        // Must be a RECORD header: "RECORD <kind> <nidLen>:<nid>"
        if (line.length < 7 || line[0..6] != "RECORD")
            throw new Exception("reload: expected RECORD header or DONE, got: " ~ line);

        auto parts = line[7..$].split(" ");
        if (parts.length < 2)
            throw new Exception("reload: malformed RECORD header: " ~ line);
        string kind = parts[0];

        // Receive the binary frame: JSON + optional FDs via SCM_RIGHTS
        auto wire = receiveRecordWithFds(sock);

        // Parse and adopt
        auto stateJson = parseJSON(cast(string) wire.json);
        HandoffState s = fromJSON(stateJson);
        const fd = (wire.fds.length > 0) ? wire.fds[0] : -1;

        logInfo("Reload: received %s record for %s (wasConnected=%s, fd=%s)",
            kind, s.config.name, s.wasConnected,
            fd >= 0 ? fd.to!string : "(TLS)");
        mgr.adoptFromHandoff([HandoffRecord(s, fd)]);

        if (kind == "plain" && fd >= 0)
            result.plainCount++;
        else
            result.tlsCount++;

        // Acknowledge this record — old engine waits for ACK before
        // sending the next one (avoids kernel-buffer overflow on
        // the SCM_RIGHTS cmsg side-channel).
        writeLine(sock, "ACK\n");
    }

    // ├─ Drain queued TLS reconnects ─────────────────────────────────
    // `adoptFromHandoff` queues TLS records (fd < 0) so we don't race
    // the OLD engine's still-live TLS socket. After we've received
    // DONE, the OLD engine has called `notifyHandoffComplete` which
    // synchronously sends QUIT on its live TLS sockets. Now safe to
    // start the soft-reconnects — the IRC server has freed the nicks.
    //
    // We don't add a fixed delay here: the handoff protocol's DONE
    // marker is sent AFTER `notifyHandoffComplete`, so by the time
    // DONE reaches us, the QUITs are already on the wire. The
    // soft-reconnect will TCP-connect, send NICK, and succeed without
    // 433.
    mgr.startPendingHandoffReconnects();

    result.durationMs = Clock.currTime.toUnixTime!long * 1000 - startedAt;
    logInfo("Reload: complete — %d plain + %d tls, %d ms",
        result.plainCount, result.tlsCount, result.durationMs);
    return result;
}

// ═══════════════════════════════════════════════════════════════════════════
//  Old-engine side: serve a reload to the new engine
// ═══════════════════════════════════════════════════════════════════════════

/// Run the handoff server role: pause every client, serialise state,
/// hand off FDs to the new engine, then return. Caller should
/// exit(0) after a successful return.
void serveReload(EngineContext ctx, string socketPath) {
    import ircfiber.engine.handoff;
    logInfo("serveReload entered: about to createUnixListener on %s", socketPath);
    logInfo("Handoff: serving on %s (engine pid=%d)", socketPath, getpid());

    // 1. Open the listener.
    int listener = createUnixListener(socketPath);
    scope(exit) {
        posixClose(listener);
        unlink(socketPath.ptr);
    }
    logInfo("Handoff: listening, waiting for new engine to connect…");

    // 2. Accept the new engine's connection. We block up to 30s.
    int peer = acceptUnix(listener);
    scope(exit) posixClose(peer);
    logInfo("Handoff: new engine connected (peer fd=%d)", peer);

    // 3. Wait for READY, then send HELLO + GO.
    auto line = readLine(peer);
    if (line != "READY")
        throw new Exception("handoff: expected READY, got: " ~ line);
    writeLine(peer, "HELLO " ~ to!string(getpid()) ~ "\n");
    writeLine(peer, "GO\n");

    // 4. Pause every client's event loop so we can capture a
    //    consistent snapshot.
    logInfo("Handoff: pausing all clients");
    ctx.connManager.pauseAllForHandoff();
    scope(exit) ctx.connManager.resumeAllAfterHandoff();

    // 5. Send each record, one per client.
    auto snapshots = ctx.connManager.snapshotAllForHandoff();
    foreach (i, snap; snapshots) {
        auto kind = snap.state.transportWasPlain ? "plain" : "tls";
        const nid = snap.state.config.id.toString();
        auto header = "RECORD " ~ kind ~ " " ~ nid.length.to!string ~ ":" ~ nid ~ "\n";
        writeLine(peer, header);
        auto stateJson = toJSON(snap.state);
        auto jsonBytes = cast(const(ubyte)[]) stateJson.toString();
        sendRecordWithFds(peer, jsonBytes, snap.fd >= 0 ? [snap.fd] : null);
        waitForAck(peer);
        logInfo("Handoff: sent %s record for %s (fd=%s, %d joined)",
            kind, snap.state.config.name,
            snap.fd >= 0 ? snap.fd.to!string : "n/a",
            snap.state.channelState.length);
    }

    // 5b. Tell the OLD engine's clients to QUIT after the handoff
    // pause releases. Without this the OLD engine keeps its
    // connections open: plain-TCP sockets are dead in this process
    // (FD was transferred) but the loop spins reading from them;
    // TLS sockets are still live and would race the new engine's
    // soft-reconnect for the same nick on the IRC server.
    // We do this BEFORE sending DONE so the new engine's adoption
    // and the OLD engine's QUIT are coordinated by the same pause
    // release — the IRC server sees one QUIT followed by one
    // reconnect with the original nick.
    ctx.connManager.notifyHandoffComplete(snapshots);

    // 6. Mark the engine as draining in Redis so the gateway's
    //    health monitor doesn't treat the imminent exit as a crash.
    markDraining(ctx);

    // 7. Send DONE.
    writeLine(peer, "DONE " ~ snapshots.length.to!string ~ "\n");
    logInfo("Handoff: complete — old engine will now exit cleanly");

    // 8. Force-exit if the deployment expects the OLD engine to die
    // here (e.g. `make engine-handoff` reaps the old PID after this).
    //
    // The per-client `runConnectionLoop` has its own exit(0) at
    // `connection.d:1511`, but it fires only when a client's read
    // loop sees the postHandoffQuitAtMs flag. If a client's loop is
    // blocked in waitForData() with a long timeout, or if the fiber
    // scheduler hasn't gotten back to it yet, the exit can take
    // several seconds — and in some deployments (docker containers
    // supervised by tini) the loop never exits because the
    // healthcheck restarts the container before the loop gets a
    // chance. So we offer a fast-path exit when explicitly enabled.
    //
    // Conditions for force-exit:
    //   - IRCFIBER_FORCE_EXIT_ON_HANDOFF=1 (opt-in via env)
    //   - not PID 1 (the container init must stay alive for the new
    //     engine's container to come up)
    //   - not supervised by tini (tini reaps child zombies but the
    //     container's healthcheck might restart the container when
    //     the engine dies; force-exiting makes the restart look like
    //     a crash)
    if (getpid() != 1) {
        import core.stdc.stdlib : exit;
        import core.stdc.stdlib : getenv;
        import std.string : toStringz;
        if (getenv(toStringz("IRCFIBER_FORCE_EXIT_ON_HANDOFF")) !is null) {
            logInfo("Handoff: forcing exit of old engine (pid=%d) — IRCFIBER_FORCE_EXIT_ON_HANDOFF=1", getpid());
            exit(0);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Zero-disconnect reload via exec(2)
//
// Replaces the current process image with a new binary in-place. All
// file descriptors that don't have O_CLOEXEC set survive the exec.
// We explicitly clear O_CLOEXEC on each IRC socket FD so the new
// binary inherits them.
//
// The IRC server sees ONE continuous TCP connection across the reload:
//   - Plain TCP: the same socket survives; the new engine resumes
//     reading/writing immediately.
//   - TLS: a fresh TLS handshake is performed on the SAME TCP socket
//     by the new engine. The IRC layer (above TLS) doesn't notice —
//     IRC sessions are keyed to the TCP 4-tuple, not the TLS identity.
//
// This is the closest thing to Erlang's hot code loading achievable
// on Unix without a separate connection-holder process.
// ═══════════════════════════════════════════════════════════════════════════

/// Run the OLD engine side of an exec-based reload:
///   1. Pause every client's event loop.
///   2. Snapshot the IRC state + FD numbers.
///   3. Clear O_CLOEXEC on IRC socket FDs.
///   4. Write the snapshot to a checkpoint file.
///   5. Write the done marker so the playbook knows we're about to exec.
///   6. Replace the current process image via execve(2).
///
/// NEVER returns on success — the new binary takes over.
void serveExecReload(EngineContext ctx, string newBinaryPath) {
    import std.file : exists, mkdirRecurse, write;
    import ircfiber.engine.exec_reload;
    import ircfiber.engine.exec_reload;
    logInfo("Exec-reload: starting, target binary=%s pid=%d",
        newBinaryPath, getpid());

    // 1. Pause every client's event loop so we can snapshot state safely.
    logInfo("Exec-reload: pausing all clients");
    ctx.connManager.pauseAllForHandoff();
    scope(failure) {
        // If anything fails before exec, release the pause so the
        // engine continues to function.
        ctx.connManager.resumeAllAfterHandoff();
    }

    // 2. Snapshot the IRC state for each connected client.
    auto rawSnapshots = ctx.connManager.snapshotAllForHandoff();
    ExecReloadSnapshot snap;
    snap.serverId = ctx.localServer.serverId;
    snap.capturedAt = Clock.currTime.toISOExtString();
    snap.capturedPid = cast(int) getpid();
    snap.newBinaryPath = newBinaryPath;
    foreach (rec; rawSnapshots) {
        ExecReloadRecord er;
        er.state = rec.state;
        er.fd = rec.fd;
        er.wasTls = !rec.state.transportWasPlain;
        snap.records ~= er;
    }
    logInfo("Exec-reload: snapshotted %d IRC connection(s)", snap.records.length);

    // 3. Mark each IRC socket FD as surviving exec. We use the raw FD
    // number from the snapshot — these are TCP sockets owned by vibe.d,
    // but F_SETFD works at the POSIX layer regardless of who's using it.
    int preservedFds = 0;
    foreach (rec; snap.records) {
        if (rec.fd >= 0) {
            preserveFdAcrossExec(rec.fd);
            preservedFds++;
            logInfo("Exec-reload: cleared O_CLOEXEC on FD %d (%s)",
                rec.fd, rec.state.config.name);
        }
    }
    logInfo("Exec-reload: preserved %d IRC FDs across exec", preservedFds);

    // 4. Copy the staged binary to a private location we control. The
    // playbook moves `/app/irc-fiber-engine.new` → `/app/irc-fiber-engine`
    // after seeing the done marker; if we exec the staged path directly
    // there's a race where the playbook moves the file before exec runs
    // (ENOENT). Copying to a unique `/tmp/irc-fiber-engine.<pid>.<ts>`
    // (engine-owned) avoids this — the playbook can clean up at its
    // leisure. We use a unique name each time because after the first
    // exec, the old path is "text file busy" — the kernel keeps the
    // mmap alive for the duration of the running process.
    import std.format : format;
    auto privateBinary = format("/tmp/irc-fiber-engine.%d.%d",
        getpid(), Clock.currTime.toUnixTime!long);
    // Clean up any stale copies from previous reloads that didn't get
    // reaped (this shouldn't normally happen but be defensive).
    try {
        import std.file : dirEntries, SpanMode, remove;
        foreach (de; dirEntries("/tmp", "irc-fiber-engine.*", SpanMode.shallow)) {
            try remove(de);
            catch (Exception) {}
        }
    } catch (Exception) {}
    try {
        import std.file : copy;
        copy(newBinaryPath, privateBinary);
        // `copy` doesn't preserve file mode bits; we need exec to
        // actually run the binary. Re-apply +x explicitly.
        // Use toStringz() because D string slices aren't null-terminated
        // and POSIX calls (chmod, execve) read C strings.
        import std.string : toStringz;
        import core.sys.posix.sys.stat : chmod, S_IXUSR, S_IXGRP, S_IXOTH;
        chmod(privateBinary.toStringz(), S_IXUSR | S_IXGRP | S_IXOTH);
        logInfo("Exec-reload: copied %s -> %s (+x)", newBinaryPath, privateBinary);
    } catch (Exception e) {
        logError("Exec-reload: failed to copy binary: %s", e.msg);
        return;
    }

    // 5. Write the checkpoint file. The new binary reads this on
    // startup to restore its in-memory state.
    try {
        auto dir = "/var/lib/ircfiber";
        if (!exists(dir)) mkdirRecurse(dir);
        auto checkpointPath = execReloadCheckpointPath(snap.serverId);
        auto json = snapshotToJson(snap);
        write(checkpointPath, json.toString());
        logInfo("Exec-reload: wrote checkpoint to %s", checkpointPath);
        // Write the marker so the new binary can find the checkpoint.
        // Use a null-terminated C string buffer so the new binary can
        // read it with `readText` without appending garbage from
        // adjacent heap memory.
        auto markerPath = execReloadMarkerPath(snap.serverId);
        auto markerContent = cast(const(ubyte)[]) (checkpointPath ~ "\0");
        write(markerPath, markerContent);
        logInfo("Exec-reload: wrote marker %s -> %s",
            markerPath, checkpointPath);
    } catch (Exception e) {
        logError("Exec-reload: failed to write checkpoint: %s", e.msg);
        return;
    }

    // 6. Write the done marker so the playbook can detect success.
    import std.file : write;
    auto doneMarker = "/tmp/ircfiber-exec-reload-done-" ~ snap.serverId;
    try write(doneMarker, Clock.currTime.toUnixTime!long.to!string);
    catch (Exception e) logWarn("Exec-reload: failed to write done marker: %s", e.msg);
    logInfo("Exec-reload: done marker written — exec'ing in 100ms");

    // 7. Give the playbook a moment to observe the done marker, then
    // call execve(2). We exec from our PRIVATE copy (engine-owned)
    // so the playbook's cleanup of the staged path doesn't race us.
    sleep(100.msecs);
    import std.process : environment;
    auto env = environment.toAA;
    // Pass the marker path so the new binary knows where to find the
    // checkpoint. We use a dedicated env var instead of writing to a
    // fixed path because some deployments have multiple engines.
    env["IRCFIBER_EXEC_RELOAD_MARKER"] = execReloadMarkerPath(snap.serverId);
    env["IRCFIBER_EXEC_RELOAD_ACTIVE"] = "1";

    string[] envp;
    foreach (k, v; env) envp ~= k ~ "=" ~ v;
    string[] argv = [privateBinary];

    logInfo("Exec-reload: calling execve(%s) — old engine disappears, new engine continues",
        privateBinary);
    try execReload(privateBinary, argv, envp);
    catch (Exception e) {
        logError("Exec-reload: execve failed: %s", e.msg);
    }
    // If we reach here, exec failed. Resume the pause so the engine
    // continues normal operation. The done marker exists but exec
    // didn't happen, so the playbook will treat this as a failed
    // reload.
    logError("Exec-reload: returning from serveExecReload — engine continues normally");
}

/// Update the Redis server-registration hash to advertise the engine
/// as draining, so the gateway's health monitor doesn't mark us
/// unhealthy and the load balancer doesn't pull our networks before
/// the new engine has fully taken over.
///
/// Sets `draining: true` in the `data` JSON blob AND in a separate
/// TTL-backed key `irc:draining:<serverId>` (60s TTL).
/// The engine's heartbeat explicitly clears both on every cycle, so
/// this is a transient signal. If the engine crashes before the next
/// heartbeat, the TTL expires and the draining flag auto-clears — no
/// manual Redis intervention needed.
private void markDraining(EngineContext ctx) {
    try {
        // Build a server record with draining=true using the struct
        // (not raw JSON) so toJson() properly serialises the draining
        // field. The heartbeat will overwrite this with draining=false
        // on the next cycle.
        auto s = ctx.localServer;
        s.isHealthy = false;
        s.draining = true;
        s.priority = -1;
        s.assignedNetworks = [];
        auto key = RedisKeys.server(ctx.localServer.serverId);
        ctx.redis.getDb().hset(key, "data", s.toJson().toString());
        // Separate draining TTL key as safety net.
        // If the heartbeat never runs to clear it, Redis auto-expires it.
        // We don't set TTL on the server hash itself — that would
        // delete the registration record.
        ctx.redis.getDb().hset(key, "draining", "true");
        ctx.redis.getDb().set(RedisKeys.draining(ctx.localServer.serverId), "true");
        ctx.redis.getDb().expire(RedisKeys.draining(ctx.localServer.serverId), 60);
        logInfo("markDraining: server %s marked draining (TTL=60s)", ctx.localServer.serverId);
    } catch (Exception e) {
        logWarn("markDraining failed: %s", e.msg);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Handoff trigger: send a gracefulReload control message
// ═══════════════════════════════════════════════════════════════════════════
//
// Called by the `make engine-handoff` Makefile target — but also
/// available programmatically for tests and for any external
/// controller that wants to trigger a graceful reload (e.g. an admin
/// button in the gateway dashboard).

/// Send a `gracefulReload` control message to the named engine. The
/// engine (if it's running) will pick it up on its control consumer
/// and execute the  Returns the path of the socket the new
/// engine will listen on so the caller can spawn the new process
/// with the right environment.
string triggerHandoff(RedisStorage redis, string serverId, int newEnginePid, long deadlineMs = 30_000) {
    import vibe.data.json : Json;
    auto cfg = Json.emptyObject;
    cfg["newEnginePid"] = Json(newEnginePid);
    cfg["socketPath"]   = Json(handoffSocketPath(serverId));
    cfg["deadlineMs"]   = Json(deadlineMs);
    auto msg = ControlMessage("gracefulReload", "", "", cfg);
    redis.lpush(RedisKeys.control(serverId), msg.toJson().toString());
    return cfg["socketPath"].get!string;
}
