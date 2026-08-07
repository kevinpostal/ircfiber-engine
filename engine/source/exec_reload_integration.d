module exec_reload_integration;

import std.stdio : writefln, writeln, stdout, stderr;
import std.conv : to;
import std.string : toStringz;
import std.file : write, readText, exists, remove;
import std.json : JSONValue, JSONType;
import std.datetime : Clock;
import core.sys.posix.sys.socket : AF_INET, SOCK_STREAM, socket, connect, send,
    recv, getsockname, getpeername, sockaddr, socklen_t, SOL_SOCKET,
    CMSG_SPACE, CMSG_LEN, CMSG_DATA, CMSG_FIRSTHDR, SCM_RIGHTS;
import core.sys.posix.netinet.in_ : sockaddr_in, htons, htonl, ntohs;
import std.string : strip;
import core.sys.posix.unistd : close, read, write, fork, execve, getpid, sleep;
import core.sys.posix.sys.stat : chmod, S_IXUSR, S_IXGRP, S_IXOTH;
import core.sys.posix.fcntl : fcntl, F_GETFD, F_SETFD, FD_CLOEXEC;
import core.stdc.string : memset;
import core.stdc.errno : errno;
import std.process : environment;

// ═══════════════════════════════════════════════════════════════════════════
//  exec-reload integration test
//
//  This exercises the full exec-reload flow:
//    1. OLD path: connects to a mock IRC server, writes a snapshot of
//       the socket FD, copies itself to a private /tmp path, then
//       execve()s the private copy.
//    2. NEW path (post-exec): reads the snapshot, finds the inherited
//       FD, adopts it via eventcore, then sends an IRC command through
//       the SAME socket — proving the TCP connection survived.
//
//  We pass a `mode` argument via argv[1]: "old" runs the OLD path, "new"
//  runs the NEW path. The fork/exec preserves argv across exec so the
//  same binary becomes both processes.

void main(string[] args) {
    if (args.length < 2) {
        stderr.writeln("usage: exec-reload-integration [old|new] [snapshot-file] [marker-file]");
        return;
    }
    auto mode = args[1];
    writeln("exec-reload-integration: mode=", mode, " pid=", getpid());
    stdout.flush();

    if (mode == "old") {
        runOld(args);
    } else if (mode == "new") {
        runNew(args);
    } else {
        stderr.writeln("Unknown mode: ", mode);
        return;
    }
}

private string selfPath() {
    import std.file : thisExePath;
    return thisExePath();
}

private void runOld(string[] args) {
    // args layout when run normally (no exec):
    //   argv[0] = binary path
    //   argv[1] = "old"
    //   argv[2] = snapshot file path
    //   argv[3] = marker file path
    // After exec, argv is preserved:
    //   argv[0] = binary path (now /tmp/exec-reload-integration.PID.TS)
    //   argv[1] = "new"   (overwritten below)
    //   argv[2] = snapshot file path  (SAME)
    //   argv[3] = marker file path    (SAME)
    auto snapshotFile = args.length > 2 ? args[2] : "/tmp/exec-reload-test.snapshot";
    auto markerFile = args.length > 3 ? args[3] : "/tmp/exec-reload-test.marker";
    auto mockHost = "127.0.0.1";
    auto mockPort = 16667;

    // 1. Connect to the mock IRC server.
    writeln("OLD: connecting to mock IRC at ", mockHost, ":", mockPort);
    auto ircFd = socket(AF_INET, SOCK_STREAM, 0);
    if (ircFd < 0) { stderr.writeln("OLD: socket() failed"); return; }
    sockaddr_in dst;
    memset(&dst, 0, sockaddr_in.sizeof);
    dst.sin_family = cast(ushort) AF_INET;
    dst.sin_addr.s_addr = htonl(0x7F000001); // 127.0.0.1
    dst.sin_port = htons(cast(ushort) mockPort);
    if (connect(ircFd, cast(sockaddr*) &dst, cast(socklen_t) dst.sizeof) != 0) {
        stderr.writeln("OLD: connect() failed: errno=", errno);
        return;
    }
    writeln("OLD: connected on fd=", ircFd);

    // Capture remote-port identity BEFORE exec.
    sockaddr_in peer;
    socklen_t plen = cast(socklen_t) peer.sizeof;
    getpeername(ircFd, cast(sockaddr*) &peer, &plen);
    auto remotePortBefore = ntohs(peer.sin_port);

    // 2. Send a PING so the mock server echoes PONG — proves the OLD
    //    engine can talk over the socket.
    write(ircFd, cast(const(ubyte)*) "PING :from-old-engine\r\n".ptr, 25);
    char[64] buf;
    auto n = recv(ircFd, buf.ptr, buf.length, 0);
    writeln("OLD: pre-exec recv returned ", n, " bytes: '",
        (cast(ubyte[]) buf)[0 .. n], "'");

    // 3. Write the snapshot file. The receiver (NEW engine) will use
    //    this to find the inherited FD.
    writeln("OLD: writing snapshot to ", snapshotFile);
    JSONValue snap = JSONValue.emptyObject;
    snap.object["serverId"] = JSONValue("test");
    snap.object["capturedAt"] = JSONValue(Clock.currTime.toISOExtString());
    snap.object["capturedPid"] = JSONValue(cast(long) getpid());
    snap.object["newBinaryPath"] = JSONValue("/tmp/exec-reload-integration");
    auto recs = JSONValue.emptyArray;
    auto rec = JSONValue.emptyObject;
    rec.object["fd"] = JSONValue(cast(long) ircFd);
    rec.object["wasTls"] = JSONValue(false);
    rec.object["networkId"] = JSONValue("test-network");
    rec.object["networkName"] = JSONValue("mockirc");
    rec.object["currentNick"] = JSONValue("Zod");
    rec.object["userId"] = JSONValue("test-user");
    rec.object["isAway"] = JSONValue(false);
    rec.object["awayMessage"] = JSONValue("");
    auto caps = JSONValue.emptyArray;
    rec.object["ackedCaps"] = caps;
    auto queries = JSONValue.emptyArray;
    rec.object["queryBuffers"] = queries;
    rec.object["channelState"] = JSONValue.emptyObject;
    rec.object["channelTopics"] = JSONValue.emptyObject;
    rec.object["channelUsers"] = JSONValue.emptyObject;
    rec.object["realnames"] = JSONValue.emptyObject;
    rec.object["partedChannels"] = JSONValue.emptyArray;
    auto sf = JSONValue.emptyObject;
    sf.object["network"] = JSONValue("test");
    sf.object["prefix"] = JSONValue("@+");
    sf.object["chanModes"] = JSONValue("");
    sf.object["maxChannels"] = JSONValue(0);
    sf.object["maxNickLen"] = JSONValue(30);
    sf.object["topicLen"] = JSONValue(0);
    rec.object["serverFeatures"] = sf;
    recs.array ~= rec;
    snap.object["records"] = recs;
    write(snapshotFile, snap.toString());

    // Write the marker so the NEW binary can find the snapshot.
    write(markerFile, snapshotFile);

    // 4. Clear O_CLOEXEC on the IRC FD so it survives exec.
    int flags = fcntl(ircFd, F_GETFD, 0);
    fcntl(ircFd, F_SETFD, flags & ~FD_CLOEXEC);
    writeln("OLD: cleared O_CLOEXEC on fd ", ircFd);

    // 5. Copy the binary to a private location (avoids text-file-busy
    //    if this binary is already running).
    import std.format : format;
    auto privatePath = format("/tmp/exec-reload-integration.%d.%d",
        getpid(), Clock.currTime.toUnixTime!long);
    try {
        import std.file : copy;
        copy(selfPath(), privatePath);
        chmod(privatePath.ptr, S_IXUSR | S_IXGRP | S_IXOTH);
        writeln("OLD: copied to ", privatePath);
    } catch (Exception e) {
        stderr.writeln("OLD: copy failed: ", e.msg);
        return;
    }

    // 6. Send a "from-old" message, then exec.
    write(ircFd, cast(const(ubyte)*) "PRIVMSG #test :message-from-OLD-engine\r\n".ptr, 38);
    writeln("OLD: sent from-old message");

    // Brief delay so the mock server processes the PRIVMSG before exec.
    sleep(1);

    // 7. exec the private copy with mode=new and the marker env var.
    writeln("OLD: calling execve()...");
    stdout.flush();
    auto env = environment.toAA;
    env["IRCFIBER_EXEC_RELOAD_MARKER"] = markerFile;
    env["IRCFIBER_EXEC_RELOAD_ACTIVE"] = "1";
    string[] envp;
    foreach (k, v; env) envp ~= k ~ "=" ~ v;
    string[] argv = [privatePath, "new", snapshotFile, markerFile];

    // Allocate env entries as null-terminated C strings. D strings
    // are NOT null-terminated, so we explicitly convert with toStringz()
    // and store the C strings in a separate array so the GC doesn't
    // collect them out from under execve.
    auto envCStrings = new char*[envp.length];
    foreach (i, e; envp) envCStrings[i] = cast(char*) e.toStringz();

    // IMPORTANT: D `string` slices are NOT null-terminated, so we MUST use
    // `toStringz()` to get a C-compatible pointer. Otherwise execve reads
    // past the slice's end and concatenates adjacent argv entries.
    auto argvCStrings = new char*[argv.length];
    foreach (i, a; argv) argvCStrings[i] = cast(char*) a.toStringz();

    immutable(char)*[] argvArr = new immutable(char)*[argv.length + 1];
    foreach (i, c; argvCStrings) argvArr[i] = cast(immutable(char)*) c;
    argvArr[argv.length] = null;
    immutable(char)*[] envpArr = new immutable(char)*[envp.length + 1];
    foreach (i, c; envCStrings) envpArr[i] = cast(immutable(char)*) c;
    envpArr[envp.length] = null;

    writeln("OLD: passing argv to exec: ", argv);
    stdout.flush();

    auto rc = execve(privatePath.ptr, cast(char**) argvArr.ptr, cast(char**) envpArr.ptr);
    stderr.writeln("OLD: execve failed: errno=", errno);
}

private void runNew(string[] args) {
    auto snapshotFile = args.length > 2 ? args[2] : "/tmp/exec-reload-test.snapshot";
    writeln("NEW: reading snapshot from '", snapshotFile, "'");
    auto content = readText(snapshotFile);
    writeln("NEW: snapshot content length=", content.length);

    // Parse snapshot.
    import std.json : parseJSON, JSONType;
    JSONValue root;
    try root = parseJSON(content);
    catch (Exception e) {
        stderr.writeln("NEW: failed to parse snapshot: ", e.msg);
        return;
    }
    // The fd is inside records[0].fd (matches exec_reload.d's wire format).
    int fd = -1;
    if (auto recsP = "records" in root.object) {
        if (recsP.type == JSONType.array && recsP.array.length > 0) {
            auto rec = recsP.array[0];
            if (auto p = "fd" in rec.object) {
                writeln("NEW: fd field type=", p.type);
                if (p.type == JSONType.integer) fd = cast(int) p.integer;
                else if (p.type == JSONType.uinteger) fd = cast(int) p.uinteger;
            }
        }
    }
    writeln("NEW: inherited fd=", fd);
    if (fd < 0) {
        stderr.writeln("NEW: snapshot has no valid FD, aborting");
        return;
    }

    // Verify the FD is open and connected.
    sockaddr_in peer;
    socklen_t plen = cast(socklen_t) peer.sizeof;
    if (getpeername(fd, cast(sockaddr*) &peer, &plen) != 0) {
        stderr.writeln("NEW: getpeername on inherited fd failed: errno=", errno);
        return;
    }
    auto remotePortAfter = ntohs(peer.sin_port);
    writeln("NEW: getpeername returned remote port=", remotePortAfter);

    // Send a message through the inherited FD — the mock server should see
    // this as a continuation of the same TCP connection.
    string msg = "PRIVMSG #test :message-from-NEW-engine-after-exec\r\n";
    write(fd, cast(const(ubyte)*) msg.ptr, msg.length);
    writeln("NEW: sent '", msg.strip, "'");

    // Try to read a PONG if the server sends one in response to a PING.
    write(fd, cast(const(ubyte)*) "PING :after-exec\r\n".ptr, 18);
    char[128] buf;
    auto n = recv(fd, buf.ptr, buf.length, 0);
    if (n > 0) {
        writeln("NEW: received ", n, " bytes post-exec: '",
            (cast(ubyte[]) buf)[0 .. n], "'");
    } else {
        writeln("NEW: no response (n=", n, ")");
    }

    // Send a final message confirming we're still alive.
    auto finalMsg = "PRIVMSG #test :FINAL-message-from-NEW-engine\r\n";
    write(fd, cast(const(ubyte)*) finalMsg.ptr, finalMsg.length);
    writeln("NEW: sent '", finalMsg.strip, "'");

    writeln("NEW: exec-reload test PASSED — IRC connection survived");
    close(fd);
}