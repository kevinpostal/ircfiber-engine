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

import ircfiber.auth;
import ircfiber.models.user;
import ircfiber.models.network;
import ircfiber.models.irc_event;
import ircfiber.models.message;
import ircfiber.models.ircchannel;
import ircfiber.irc.chathistory;

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
        ircfiber.auth,
        ircfiber.models.user,
        ircfiber.models.network,
        ircfiber.models.irc_event,
        ircfiber.models.message,
        ircfiber.models.ircchannel,
        ircfiber.irc.chathistory
    )();
    writefln("\n%d passed, %d failed", g_passed, g_failed);
    exit(g_failed == 0 ? 0 : 1);
    return 0;
}
