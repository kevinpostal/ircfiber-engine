/// Isolated, test-build-only real engine failure-owner qualification.
module bugsink_coverage_test;

version (BugsinkEngineCoverage) {
import core.exception : AssertError;
import core.time : MonoTime, Duration, seconds, msecs;
import std.conv : to;
import std.exception : enforce;
import std.file : tempDir, mkdir, rmdirRecurse;
import std.path : buildPath;
import std.process : environment;
import std.stdio : stderr;
import std.string : startsWith, indexOf, toStringz;
import std.uuid : randomUUID;
import core.sys.posix.sys.stat : chmod;
import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import vibe.core.net : listenTCP, TCPConnection;
import vibe.stream.operations : readLine;
import vibe.data.json : Json;
import ircfiber.build_info : buildInfo;
import ircfiber.errors : configureErrorReporting, isErrorReportingEnabled;
import ircfiber.holder_client : HolderClient, HolderUnavailableException, HolderErrorException;
import ircfiber.engine.bootstrap : runBugsinkNetworkLoadFixture;
import ircfiber.engine.archive_spool : ArchiveSpool, ArchiveSpoolConfig,
    ArchiveSpoolProgress, ArchiveAdmission, ArchiveRecord;
import ircfiber.engine.archive_worker : ArchiveWorker, ArchiveApply, ArchiveApplyResult;

private void awaitCondition(bool delegate() condition, string failure, Duration timeout = 5.seconds) {
    const deadline = MonoTime.currTime + timeout;
    while (!condition() && MonoTime.currTime < deadline) sleep(10.msecs);
    enforce(condition(), failure);
}

private string privateDetail() {
    return environment.get("FIXTURE_PRIVATE_DETAIL", "private-engine-fixture-detail");
}

private void configureReporter() {
    const dsn = environment.get("IRCFIBER_BUGSINK_DSN", "");
    const release = buildInfo().describe;
    enforce(environment.get("IRCFIBER_BUGSINK_ENVIRONMENT", "") == "test"
        && environment.get("IRCFIBER_BUGSINK_ENABLED", "") == "1"
        && release.startsWith("fixture-") && dsn.startsWith("http://")
        && (dsn.indexOf("@relay:8000/") >= 0 || dsn.indexOf("@127.0.0.1:") >= 0),
        "explicit private fixture reporting configuration required");
    configureErrorReporting(true, dsn, "ircfiber-engine", release, "test");
    enforce(isErrorReportingEnabled(), "fixture reporter did not initialize");
}

private void closePeer(TCPConnection peer) {
    try peer.close(); catch (Exception) {}
}

private void holderLifecycle(string mode) {
    bool available = true;
    size_t handshakes, activePeers;
    TCPConnection[] peers;
    auto listener = listenTCP(environment.get("FIXTURE_HOLDER_PORT", "0").to!ushort, (TCPConnection peer) {
        ++activePeers;
        scope(exit) {
            --activePeers;
            closePeer(peer);
        }
        peers ~= peer;
        try {
            const hello = readLine(peer, 4096, "\n");
            enforce(hello.startsWith("HELLO "), "fixture expected real HELLO");
            ++handshakes;
            if (!available) return;
            peer.write("OK {\"proto\":1,\"instance\":\"fixture-holder\"}\n");
            peer.flush();
            while (true) {
                const line = readLine(peer, 4096, "\n");
                if (line == "STATUS") {
                    peer.write("OK {\"proto\":1,\"instance\":\"fixture-holder\",\"open\":0}\n");
                } else if (line == "LIST") {
                    auto response = Json.emptyObject;
                    Json[] entries;
                    foreach (i; 0 .. 16) {
                        auto entry = Json.emptyObject;
                        entry["id"] = "fixture-network-" ~ i.to!string;
                        entry["state"] = "closed";
                        entry["error"] = privateDetail();
                        entries ~= entry;
                    }
                    response["connections"] = entries;
                    peer.write("OK " ~ response.toString() ~ "\n");
                } else if (line.startsWith("INFO ")) {
                    auto error = Json.emptyObject;
                    error["code"] = "not_found";
                    error["msg"] = privateDetail();
                    peer.write("ERR " ~ error.toString() ~ "\n");
                } else throw new Exception("unexpected holder fixture verb");
                peer.flush();
            }
        } catch (Exception) {}
    }, "127.0.0.1");
    scope(exit) {
        listener.stopListening();
        foreach (peer; peers) closePeer(peer);
        awaitCondition(() => activePeers == 0, "holder fixture peers did not close");
    }

    auto client = new HolderClient("fixture-engine", "tcp://127.0.0.1:" ~ listener.bindAddress.port.to!string);
    client.connectControl();
    client.status();
    enforce(client.controlAlive && handshakes == 1, "holder did not establish control");

    void networkDisconnects() {
        auto entries = client.list();
        enforce(entries.length == 16, "closed network fixture missing");
        foreach (entry; entries) {
            enforce(entry.state == "closed", "fixture network not disconnected");
            bool refused;
            try client.info(entry.id);
            catch (HolderErrorException e) { refused = e.code == "not_found"; }
            enforce(refused && client.controlAlive, "network error damaged holder control");
        }
        client.status();
    }
    networkDisconnects();
    if (mode == "holder-network-disconnects") {
        // A negative assertion must allow an accidentally queued report to
        // finish too; immediate process exit must not hide a regression.
        sleep(6.seconds);
        return;
    }

    const episodes = mode == "holder-control-recovery" ? 2 : 1;
    foreach (episode; 0 .. episodes) {
        const previousHandshakes = handshakes;
        available = false;
        foreach (peer; peers) try peer.close(); catch (Exception) {}
        bool unavailable;
        try client.status();
        catch (HolderUnavailableException) { unavailable = true; }
        enforce(unavailable && !client.controlAlive, "real control loss was not detected");
        // Calls for multiple logical networks and reconnect attempts must not
        // turn one up-to-down transition into multiple incidents.
        foreach (i; 0 .. 16) {
            unavailable = false;
            try client.info("fixture-network-" ~ i.to!string);
            catch (HolderUnavailableException) { unavailable = true; }
            enforce(unavailable && !client.controlAlive, "outage was not retained");
        }
        awaitCondition(() => handshakes >= previousHandshakes + 3,
            "holder reconnect retry loop did not run");
        // Let the bounded sender finish before a second independent episode,
        // so single-flight admission cannot hide a missing recovery rearm.
        sleep(6.seconds);
        enforce(!client.controlAlive, "unavailable holder recovered unexpectedly");
        available = true;
        awaitCondition(delegate bool() { return client.controlAlive; }, "holder did not recover");
        client.status();
        networkDisconnects();
    }
}

private void archiveLifecycle(bool terminal) {
    const root = buildPath(tempDir(), "bugsink-archive-" ~ randomUUID().toString());
    mkdir(root);
    enforce(chmod(root.toStringz, 448) == 0, "cannot protect private archive root");
    ArchiveSpool spool;
    ArchiveWorker worker;
    scope(exit) {
        if (worker !is null) {
            worker.requestStop();
            awaitCondition(() => worker.isStopped(), "archive consumer did not stop");
        }
        if (spool !is null) {
            spool.requestShutdown(2.seconds);
            awaitCondition(() {
                ArchiveSpoolProgress progress;
                return spool.tryProgress(progress) && progress.stopped;
            }, "native archive owner did not stop");
        }
        rmdirRecurse(root);
    }
    ArchiveSpoolConfig config;
    config.directory = buildPath(root, "journal");
    mkdir(config.directory);
    enforce(chmod(config.directory.toStringz, 448) == 0, "cannot protect private journal");
    config.maxBytes = 64 * 1024 * 1024;
    config.minFreeBytes = 0;
    config.diagnosticPath = "";
    spool = new ArchiveSpool(config);
    awaitCondition(() {
        ArchiveSpoolProgress progress;
        return spool.tryProgress(progress) && progress.ready && !progress.failed;
    }, "native archive journal did not recover");

    size_t calls;
    ArchiveApply apply = (ref const ArchiveRecord record) {
        ++calls;
        if (terminal) throw new AssertError(privateDetail());
        return ArchiveApplyResult.retry;
    };
    worker = new ArchiveWorker(spool, apply);
    auto payload = Json.emptyObject;
    payload["eid"] = 1L;
    payload["t"] = 1_700_000_000_000L;
    payload["body"] = privateDetail();
    enforce(spool.tryAppend("fixture-engine", randomUUID().toString(), "#private-fixture", 1,
        payload.toString(), randomUUID().toString()) == ArchiveAdmission.queued,
        "real archive ingress refused fixture record");
    worker.start();
    if (terminal) {
        awaitCondition(() => worker.isStopped(), "terminal archive consumer did not exit");
        enforce(calls == 1 && worker.activeConsumerFibers() == 0,
            "terminal archive failure retried or retained its fiber");
        awaitCondition(() {
            ArchiveSpoolProgress progress;
            return spool.tryProgress(progress) && progress.failed;
        }, "terminal archive failure did not retain its failure signal");
        sleep(6.seconds);
    } else {
        awaitCondition(() => calls >= 3, "ordinary archive retries did not occur");
        worker.requestStop();
        awaitCondition(() => worker.isStopped(), "ordinary archive stop did not complete");
        ArchiveSpoolProgress progress;
        awaitCondition(() => spool.tryProgress(progress), "archive progress unavailable");
        enforce(!progress.failed && worker.activeConsumerFibers() == 0,
            "ordinary archive retry/stop became a terminal failure");
        sleep(6.seconds);
    }
}

int main(string[] args) {
    enforce(args.length == 2, "one engine fixture scenario required");
    configureReporter();
    int result = 1;
    bool completed;
    runTask(() nothrow {
        try {
            switch (args[1]) {
                case "network-load-exhaustion": runBugsinkNetworkLoadFixture(); break;
                case "holder-network-disconnects":
                case "holder-control-outage":
                case "holder-control-recovery": holderLifecycle(args[1]); break;
                case "archive-terminal": archiveLifecycle(true); break;
                case "archive-retry-stop": archiveLifecycle(false); break;
                default: throw new Exception("unknown engine fixture scenario");
            }
            result = 0;
            stderr.writeln("engine owner fixture passed");
        } catch (Throwable error) {
            // Harness assertion failures are not application reports or evidence.
            try stderr.writeln("engine owner fixture failed: ", error.classinfo.name,
                " at line ", error.line); catch (Throwable) {}
        }
        completed = true;
        exitEventLoop();
    });
    runEventLoop();
    return completed ? result : 1;
}
}
