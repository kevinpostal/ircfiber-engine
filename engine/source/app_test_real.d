/// Real D-unit test runner — replaces `unit_threaded.light.runTestsMain`.
///
/// The previous runner was a no-op that always printed "All tests passed"
/// without executing anything. CI ran green-by-default. This driver
/// enumerates each module's `@("name") unittest` blocks via
/// `__traits(getUnitTests, mod)` (which requires `-b unittest` at build
/// time) and runs them through a single try/catch wrapping so a single
/// failure doesn't abort the rest of the suite.
///
/// `runAllTests!(modA, modB, ...)()` accepts *symbol* modules (not
/// strings) because `getUnitTests` only resolves at template
/// instantiation time. The caller must `import` every listed module so
/// the compiler sees it.
module app_test_real;

import core.stdc.stdlib : exit;
import std.stdio : stderr, writefln;
import std.traits : moduleName;

// unit-threaded's `disableDefaultRunner` mixin installs a `shared
// static this()` that swaps D's runtime unittest loop with
// unit-threaded's own runner. With this installed, the D runtime no
// longer auto-executes every `unittest {}` block before main() — our
// explicit `__traits(getUnitTests)` enumeration below becomes the
// authoritative test executor and the process no longer hangs at
// startup on leaked fibers from third-party unittests.
import unit_threaded.runner.runner : disableDefaultRunner;

mixin disableDefaultRunner;

pragma(msg, "[app_test_real] module loaded");

// Each module's unittests must be reachable via static import so D's
// runtime registers them in ModuleInfo when `-b unittest` is on. The
// `__traits(getUnitTests, mod)` walk enumerates them.
import ircfiber.auth;
import ircfiber.models.user;
import ircfiber.models.network;
import ircfiber.models.irc_event;
import ircfiber.models.message;
import ircfiber.models.ircchannel;
import ircfiber.irc.chathistory;
import ircfiber.irc.parser;
import ircfiber.irc.tls_safe;
import ircfiber.irc.server;
import ircfiber.irc.sasl;
import ircfiber.irc.connection;
import ircfiber.default_network;

private uint g_passed;
private uint g_failed;

/// Runs every `@("name") unittest {}` in module `M`. Returns `true` iff
/// every test passed.
private bool runModuleTests(M...)() if (M.length > 0) {
    static foreach (mod; M) {{
        enum modName = moduleName!mod;
        writefln("\n[%s]", modName);
        static foreach (unitTest; __traits(getUnitTests, mod)) {
            () {
                try {
                    unitTest();
                    ++g_passed;
                    writefln("  \u2713 %s",
                        __traits(identifier, unitTest));
                } catch (Throwable t) {
                    ++g_failed;
                    writefln("  \u2717 %s\n        %s",
                        __traits(identifier, unitTest), t.msg);
                }
            }();
        }
    }}
    return g_failed == 0;
}

int main() {
    writefln("IRC Fiber real-unittest suite (run with -b unittest)");
    runModuleTests!(
        ircfiber.auth,
        ircfiber.models.user,
        ircfiber.models.network,
        ircfiber.models.irc_event,
        ircfiber.models.message,
        ircfiber.models.ircchannel,
        ircfiber.irc.chathistory,
        ircfiber.irc.parser,
        ircfiber.irc.tls_safe,
        ircfiber.irc.server,
        ircfiber.irc.sasl,
        ircfiber.irc.connection,
        ircfiber.default_network
    )();
    writefln("\n%d passed, %d failed", g_passed, g_failed);
    // Force-exit because vibe-d's event loop keeps the process alive
    // past main() under `-b unittest`; C exit() is the only way to
    // terminate without dragging eventcore's leaked drivers through
    // every teardown hook.
    exit(g_failed == 0 ? 0 : 1);
}
