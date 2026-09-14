/// Test runner — replaces the previous no-op stub that hung on vibe-d's leaked
/// eventcore handles. Uses unit-threaded's disableDefaultRunner so D's
/// default unittest auto-run doesn't hang before main(), then explicitly
/// enumerates each module's unittests via __traits(getUnitTests) and
/// force-exits via C exit() to avoid the vibe-core linger that made
/// `make test` / `dub test` appear to hang for ~6s after printing results.
module app_test;

import core.stdc.stdlib : exit;
import std.stdio : writefln;
import std.traits : moduleName;

import unit_threaded.runner.runner : disableDefaultRunner;

mixin disableDefaultRunner;

pragma(msg, "[app_test] module loaded");

// Engine-LOCAL modules only, and that is load-bearing twice over:
//
//  * `ircfiber.auth` lived here from when one repo held gateway and engine.
//    After the split `engine/backend/` is a dub stub with no sources, so the
//    import failed the whole config ("unable to read module `auth`") and the
//    engine had no runnable unittest target at all.
//  * `ircfiber.models.*` come from the irc-fiber-common DEPENDENCY, which dub
//    builds without `-unittest`. Enumerating their unittests here emitted
//    references to symbols that were never compiled, so the link failed with
//    dozens of "__unittest_L…FZv, symbol(s) not found".
//
// Both are covered where they live: `dub test --root=common` (site/common)
// and the backend's own narrow `*-test` configs.
import ircfiber.irc.chathistory;
import ircfiber.irc.connection;
import ircfiber.irc.parser;
import ircfiber.irc.sasl;
import ircfiber.irc.pacer;
import ircfiber.irc.reconnect;

private uint g_passed;
private uint g_failed;

private bool runModuleTests(M...)() if (M.length > 0) {
    static foreach (mod; M) {{
        enum modName = moduleName!mod;
        writefln("\n[%s]", modName);
        static foreach (unitTest; __traits(getUnitTests, mod)) {
            () {
                try {
                    unitTest();
                    ++g_passed;
                    writefln("  \u2713 %s", __traits(identifier, unitTest));
                } catch (Throwable t) {
                    ++g_failed;
                    writefln("  \u2717 %s\n        %s", __traits(identifier, unitTest), t.msg);
                }
            }();
        }
    }}
    return g_failed == 0;
}

int main() {
    writefln("IRC Fiber unittest suite (run with -b unittest)");
    cast(void) runModuleTests!(
        ircfiber.irc.connection,
        ircfiber.irc.parser,
        ircfiber.irc.sasl,
        ircfiber.irc.pacer,
        ircfiber.irc.reconnect,
        ircfiber.irc.chathistory
    )();
    writefln("\n%d passed, %d failed", g_passed, g_failed);
    exit(g_failed == 0 ? 0 : 1);
    return 0;
}
