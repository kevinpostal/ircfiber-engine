module history_storage_test;

import std.process : environment;
import std.stdio : writeln;
import vibe.core.core : runTask, runEventLoop, exitEventLoop;
import ircfiber.db.redis_pool : initRedisPool, shutdownRedisPool;
import ircfiber.testing.isolated_db : isolatedTestRedis;
import ircfiber.storage.buffer : historyAtomicStorageRegressionChecks;
import ircfiber.irc.bnc_ownership : runBncMonitorProtocolChecks, runBncOwnershipProtocolChecks;

int main() {
    if (!environment.get("IRCFIBER_HISTORY_TEST_REDIS_URL", "").length) {
        writeln("history atomic storage: explicit isolated IRCFIBER_HISTORY_TEST_REDIS_URL is required");
        return 1;
    }
    initRedisPool();
    scope (exit) shutdownRedisPool();
    int result;
    runTask(() nothrow {
        try {
            auto redis = isolatedTestRedis("history atomic storage");
            assert(redis !is null);
            historyAtomicStorageRegressionChecks(redis);
            runBncOwnershipProtocolChecks();
            runBncMonitorProtocolChecks(redis, "history-storage-fixture");
            writeln("history monitor storage: PASS isolated ownership, capacity, waiters and lease expiry");
            writeln("history atomic storage: PASS append/dedup WRONGTYPE atomicity and retry");
        } catch (Throwable error) {
            result = 1;
            try writeln("history atomic storage: FAIL: ", error.toString());
            catch (Exception) {}
        }
        exitEventLoop();
    });
    runEventLoop();
    return result;
}
