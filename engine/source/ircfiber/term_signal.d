/**
 * Shared SIGTERM/SIGINT capture for the engine and the connection holder.
 *
 * vibe's default handler exits the event loop immediately, and I/O issued
 * after `runApplication()` returns is not reliable. Both binaries need
 * their shutdown work (engine: hot-swap detach or decommission QUIT;
 * holder: QUIT every held connection) to run *inside* the loop, so the
 * handler here only records which signal fired; a watcher fiber polls
 * `termSignal()` and performs the in-loop shutdown before `exitEventLoop()`.
 *
 * Usage (before `runApplication()`):
 * ---
 * installTermSignalFlag();
 * runTask({ while (termSignal() == 0) sleep(100.msecs); shutdownInLoop(); exitEventLoop(); });
 * runApplication();
 * ---
 */
module ircfiber.term_signal;

import core.atomic : atomicLoad, atomicStore;
import core.sys.posix.signal : sigaction, sigaction_t, sigemptyset, SIGTERM, SIGINT;

private shared int g_termSignal = 0;

/// Signal number recorded by the handler: 0 = none yet, else `SIGTERM` or `SIGINT`.
int termSignal() nothrow @nogc @trusted {
    return atomicLoad(g_termSignal);
}

private extern (C) void onTermSignal(int signo) nothrow @nogc @system {
    // First signal wins; a second SIGTERM during a slow detach must not
    // flip a hot swap into a decommission (or vice versa).
    if (atomicLoad(g_termSignal) == 0) atomicStore(g_termSignal, signo);
}

/// Disables vibe's default SIGTERM/SIGINT handlers and installs the flag-only
/// handler for both signals. Call once, before `runApplication()`.
void installTermSignalFlag() @trusted {
    import vibe.core.core : disableDefaultSignalHandlers;
    disableDefaultSignalHandlers();
    foreach (signo; [SIGTERM, SIGINT]) {
        sigaction_t sa;
        sa.sa_handler = &onTermSignal;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction(signo, &sa, null);
    }
}
