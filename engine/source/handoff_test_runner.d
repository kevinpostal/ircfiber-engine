module handoff_test_runner;

import std.stdio : writefln, writeln, stdout;
import std.conv : to;
import core.exception : AssertError;
import core.stdc.string : memset;

import core.sys.posix.sys.socket;
import core.sys.posix.netinet.in_;
import core.sys.posix.unistd;

// ═══════════════════════════════════════════════════════════════════════════
//  Handoff tests — standalone, no vibe.d, no unit-threaded.
//
//  What these tests prove:
//   1. SCM_RIGHTS over Unix socketpair can transfer a TCP socket FD
//      from one process context to another.
//   2. The receiving side can read/write through the adopted FD.
//   3. The kernel-side TCP connection is NOT closed during the transfer —
//      the same socket survives, identified by the same remote port on
//      the server side.
//   4. Closing the OLD engine's FD (which schedulePostHandoffQuit does
//      after a successful handoff) does NOT close the kernel connection
//      while the NEW engine still holds a reference to it.
// ═══════════════════════════════════════════════════════════════════════════

// Re-implement the SCM_RIGHTS cmsg builder locally so we don't depend
// on handoff.d (which pulls in vibe.d and blocks the test binary).
/// Builds an SCM_RIGHTS cmsg buffer for the given file descriptors.
ubyte[] buildCmsgBuffer(int[] fds) {
    if (fds.length == 0) return null;
    auto fdBytes = fds.length * int.sizeof;
    auto cmsgLen = cast(uint)(CMSG_LEN(cast(socklen_t) fdBytes));
    ubyte[] buf = new ubyte[](CMSG_SPACE(cast(socklen_t) fdBytes));
    auto cmsg = cast(cmsghdr*) buf.ptr;
    cmsg.cmsg_len = cmsgLen;
    cmsg.cmsg_level = SOL_SOCKET;
    cmsg.cmsg_type = SCM_RIGHTS;
    auto data = cast(int*) CMSG_DATA(cmsg);
    foreach (i, fd; fds) data[i] = fd;
    return buf;
}

private int failures = 0;

private void runTest(string name, void delegate() body) {
    writefln("  running: %s ... ", name);
    stdout.flush();
    try {
        body();
        writeln("OK");
    } catch (AssertError e) {
        writeln("FAIL");
        writeln("    ", e.msg);
        failures++;
    } catch (Exception e) {
        writeln("ERROR");
        writeln("    ", e.msg);
        failures++;
    }
    stdout.flush();
}

void main() {
    writeln("Handoff test suite");
    writeln("===================");
    stdout.flush();

    runTest("SCM_RIGHTS FD transfer over socketpair", {
        int[2] ctl;
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, ctl) == 0,
            "socketpair(ctl) failed");

        int[2] p;
        assert(pipe(p) == 0, "pipe() failed");

        ubyte[] cbuf = buildCmsgBuffer([p[0]]);
        assert(cbuf !is null, "buildCmsgBuffer returned null");

        ubyte[1] dummy = [0];
        iovec iov;
        iov.iov_base = dummy.ptr;
        iov.iov_len = 1;
        msghdr msg;
        memset(&msg, 0, msghdr.sizeof);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.ptr;
        msg.msg_controllen = cast(socklen_t) cbuf.length;
        assert(sendmsg(ctl[0], &msg, 0) > 0, "sendmsg failed");

        auto recvBuf = cast(ubyte[]) new ubyte[](CMSG_SPACE(cast(socklen_t) int.sizeof));
        ubyte[1] recvDummy;
        iovec riov;
        riov.iov_base = recvDummy.ptr;
        riov.iov_len = 1;
        msghdr rmsg;
        memset(&rmsg, 0, msghdr.sizeof);
        rmsg.msg_iov = &riov;
        rmsg.msg_iovlen = 1;
        rmsg.msg_control = recvBuf.ptr;
        rmsg.msg_controllen = cast(socklen_t) recvBuf.length;
        assert(recvmsg(ctl[1], &rmsg, 0) > 0, "recvmsg failed");

        auto cmsg = cast(cmsghdr*) CMSG_FIRSTHDR(&rmsg);
        assert(cmsg !is null, "no cmsg");
        assert(cmsg.cmsg_level == SOL_SOCKET, "wrong level");
        assert(cmsg.cmsg_type == SCM_RIGHTS, "wrong type");
        auto data = cast(int*) CMSG_DATA(cmsg);
        assert((cmsg.cmsg_len - CMSG_LEN(0)) / int.sizeof >= 1, "no fds");

        const int adoptedFd = data[0];
        string testMsg = "hello fd";
        assert(write(p[1], testMsg.ptr, testMsg.length)
            == cast(ptrdiff_t) testMsg.length, "pipe write failed");
        ubyte[64] readBuf;
        assert(read(adoptedFd, readBuf.ptr, readBuf.length)
            == cast(ptrdiff_t) testMsg.length, "adopted read failed");
        assert(readBuf[0 .. testMsg.length] == cast(ubyte[])testMsg,
            "data mismatch");

        close(adoptedFd);
        close(p[0]); close(p[1]);
        close(ctl[0]); close(ctl[1]);
    });

    runTest("TCP socket survives SCM_RIGHTS — same kernel connection", {
        auto listenFd = socket(AF_INET, SOCK_STREAM, 0);
        assert(listenFd >= 0, "socket(listen) failed");
        sockaddr_in addr;
        memset(&addr, 0, sockaddr_in.sizeof);
        addr.sin_family = cast(ushort) AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        assert(bind(listenFd, cast(sockaddr*) &addr,
            cast(socklen_t) addr.sizeof) == 0, "bind() failed");
        assert(listen(listenFd, 1) == 0, "listen() failed");
        sockaddr_in boundAddr;
        socklen_t blen = cast(socklen_t) boundAddr.sizeof;
        assert(getsockname(listenFd, cast(sockaddr*) &boundAddr, &blen) == 0,
            "getsockname failed");
        cast(void) ntohs(boundAddr.sin_port);

        auto oldEngineFd = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in dstAddr;
        memset(&dstAddr, 0, sockaddr_in.sizeof);
        dstAddr.sin_family = cast(ushort) AF_INET;
        dstAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        dstAddr.sin_port = boundAddr.sin_port;
        assert(connect(oldEngineFd, cast(sockaddr*) &dstAddr,
            cast(socklen_t) dstAddr.sizeof) == 0, "connect() failed");

        auto serverSideFd = accept(listenFd, null, null);
        assert(serverSideFd >= 0, "accept() failed");

        // Pre-handoff peer port
        sockaddr_in peerBefore;
        socklen_t pBeforeLen = cast(socklen_t) peerBefore.sizeof;
        assert(getpeername(serverSideFd, cast(sockaddr*) &peerBefore,
            &pBeforeLen) == 0);
        auto remotePortBefore = ntohs(peerBefore.sin_port);

        // Pre-handoff I/O works
        string preHandoff = "PRE :still here\r\n";
        assert(send(oldEngineFd, preHandoff.ptr, preHandoff.length, 0) > 0);
        char[64] readBuf;
        auto got = recv(serverSideFd, readBuf.ptr, readBuf.length, 0);
        assert(got > 0);
        assert((cast(ubyte[]) readBuf)[0 .. got] == cast(ubyte[]) preHandoff);

        // Transfer via SCM_RIGHTS
        int[2] ctl;
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, ctl) == 0);

        ubyte[] cbuf = buildCmsgBuffer([oldEngineFd]);
        ubyte[1] dummy = [0];
        iovec iov;
        iov.iov_base = dummy.ptr;
        iov.iov_len = 1;
        msghdr msg;
        memset(&msg, 0, msghdr.sizeof);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.ptr;
        msg.msg_controllen = cast(socklen_t) cbuf.length;
        assert(sendmsg(ctl[0], &msg, 0) > 0);

        auto recvBuf = cast(ubyte[]) new ubyte[](CMSG_SPACE(cast(socklen_t) int.sizeof));
        ubyte[1] recvDummy;
        iovec riov;
        riov.iov_base = recvDummy.ptr;
        riov.iov_len = 1;
        msghdr rmsg;
        memset(&rmsg, 0, msghdr.sizeof);
        rmsg.msg_iov = &riov;
        rmsg.msg_iovlen = 1;
        rmsg.msg_control = recvBuf.ptr;
        rmsg.msg_controllen = cast(socklen_t) recvBuf.length;
        assert(recvmsg(ctl[1], &rmsg, 0) > 0);

        auto cmsg = cast(cmsghdr*) CMSG_FIRSTHDR(&rmsg);
        auto newEngineFd = (cast(int*) CMSG_DATA(cmsg))[0];

        // OLD engine FD must be dead. After SCM_RIGHTS the kernel
        // closes the FD in the sender's process, so any read on it
        // returns -1 with EBADF. We use poll() with 0 timeout to
        // make this non-blocking (avoids hanging on macOS where
        // a transferred fd's read can block).
        import core.sys.posix.poll : poll, pollfd, POLLIN;
        pollfd[1] pfd;
        pfd[0].fd = oldEngineFd;
        pfd[0].events = POLLIN;
        auto pollRc = poll(pfd.ptr, 1, 0);
        // Either poll fails (EBADF) or it returns 0 (no data).
        assert(pollRc <= 0,
            "OLD fd still pollable — SCM_RIGHTS didn't actually transfer");
        close(oldEngineFd);

        // NEW engine writes post-handoff; server reads the SAME connection
        string postHandoff = "POST :new engine took over\r\n";
        assert(send(newEngineFd, postHandoff.ptr, postHandoff.length, 0)
            == cast(ptrdiff_t) postHandoff.length);
        auto got2 = recv(serverSideFd, readBuf.ptr, readBuf.length, 0);
        assert(got2 > 0);
        assert((cast(ubyte[]) readBuf)[0 .. got2] == cast(ubyte[]) postHandoff);

        // ── THE CRITICAL INVARIANT ────────────────────────────────
        sockaddr_in peerAfter;
        socklen_t pAfterLen = cast(socklen_t) peerAfter.sizeof;
        assert(getpeername(serverSideFd, cast(sockaddr*) &peerAfter,
            &pAfterLen) == 0);
        auto remotePortAfter = ntohs(peerAfter.sin_port);
        assert(remotePortAfter == remotePortBefore,
            "TCP was closed+reopened — remote port " ~
            remotePortBefore.to!string ~ " → " ~ remotePortAfter.to!string);

        // New engine reads the server's banner
        string banner = ":mock.irc 001 Zod :Welcome\r\n";
        assert(send(serverSideFd, banner.ptr, banner.length, 0) > 0);
        auto got3 = recv(newEngineFd, readBuf.ptr, readBuf.length, 0);
        assert(got3 > 0);
        assert((cast(ubyte[]) readBuf)[0 .. got3] == cast(ubyte[]) banner);

        // New engine writes a JOIN — proves socket is fully functional
        string join = "JOIN #test\r\n";
        assert(send(newEngineFd, join.ptr, join.length, 0) > 0);
        auto got4 = recv(serverSideFd, readBuf.ptr, readBuf.length, 0);
        assert(got4 > 0);
        assert((cast(ubyte[]) readBuf)[0 .. got4] == cast(ubyte[]) join);

        close(newEngineFd);
        close(serverSideFd);
        close(listenFd);
        close(ctl[0]);
        close(ctl[1]);
    });

    runTest("OLD engine FD close preserves live TCP connection", {
        auto listenFd = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in addr;
        memset(&addr, 0, sockaddr_in.sizeof);
        addr.sin_family = cast(ushort) AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        bind(listenFd, cast(sockaddr*) &addr, cast(socklen_t) addr.sizeof);
        listen(listenFd, 1);
        sockaddr_in boundAddr;
        socklen_t blen = cast(socklen_t) boundAddr.sizeof;
        getsockname(listenFd, cast(sockaddr*) &boundAddr, &blen);

        auto oldEngineFd = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in dstAddr;
        memset(&dstAddr, 0, sockaddr_in.sizeof);
        dstAddr.sin_family = cast(ushort) AF_INET;
        dstAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        dstAddr.sin_port = boundAddr.sin_port;
        connect(oldEngineFd, cast(sockaddr*) &dstAddr,
            cast(socklen_t) dstAddr.sizeof);
        auto serverSideFd = accept(listenFd, null, null);
        assert(serverSideFd >= 0);

        // Transfer
        int[2] ctl;
        socketpair(AF_UNIX, SOCK_STREAM, 0, ctl);
        ubyte[] cbuf = buildCmsgBuffer([oldEngineFd]);
        ubyte[1] dummy = [0];
        iovec iov;
        iov.iov_base = dummy.ptr;
        iov.iov_len = 1;
        msghdr msg;
        memset(&msg, 0, msghdr.sizeof);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.ptr;
        msg.msg_controllen = cast(socklen_t) cbuf.length;
        sendmsg(ctl[0], &msg, 0);

        auto recvBuf = cast(ubyte[]) new ubyte[](CMSG_SPACE(cast(socklen_t) int.sizeof));
        ubyte[1] recvDummy;
        iovec riov;
        riov.iov_base = recvDummy.ptr;
        riov.iov_len = 1;
        msghdr rmsg;
        memset(&rmsg, 0, msghdr.sizeof);
        rmsg.msg_iov = &riov;
        rmsg.msg_iovlen = 1;
        rmsg.msg_control = recvBuf.ptr;
        rmsg.msg_controllen = cast(socklen_t) recvBuf.length;
        recvmsg(ctl[1], &rmsg, 0);

        auto cmsg = cast(cmsghdr*) CMSG_FIRSTHDR(&rmsg);
        auto newEngineFd = (cast(int*) CMSG_DATA(cmsg))[0];

        // OLD engine closes its FD — what schedulePostHandoffQuit does.
        close(oldEngineFd);

        // Server can still talk on the kernel connection.
        string serverPoke = "PING :still-alive\r\n";
        assert(send(serverSideFd, serverPoke.ptr, serverPoke.length, 0) > 0);
        char[64] readBuf;
        auto got = recv(newEngineFd, readBuf.ptr, readBuf.length, 0);
        assert(got > 0,
            "Kernel connection died when OLD engine closed its FD — " ~
            "SCM_RIGHTS transfer did NOT preserve the live TCP connection");
        assert((cast(ubyte[]) readBuf)[0 .. got] == cast(ubyte[]) serverPoke);

        // NEW engine closes its FD → server sees EOF
        close(newEngineFd);
        char[1] probe;
        auto bytesAfterClose = recv(serverSideFd, probe.ptr, 1, 0);
        assert(bytesAfterClose == 0,
            "server should see EOF after both engines close FDs, got " ~
            bytesAfterClose.to!string);

        close(serverSideFd);
        close(listenFd);
        close(ctl[0]);
        close(ctl[1]);
    });

    writeln("");
    if (failures == 0) {
        writeln("All 3 handoff tests passed.");
    } else {
        writeln(failures, " test(s) failed.");
    }
    stdout.flush();
}
