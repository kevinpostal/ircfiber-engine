module ircfiber.build_info;

/// Build identity of the running binary. Sourced from the environment the
/// runtime image sets (see the `ENV IRCFIBER_BUILD_*` layer in the
/// Containerfile) rather than compiled in, so a commit that changes no
/// sources produces a byte-identical binary and the build cache holds.
struct BuildInfo {
    string version_;
    string commit;
    string shortHash;
    string describe;
    string branch;
    string builtAt;
    string builtHost;
    string message;
    string commitUrl;
}

/// Read once from the environment. Absent → "dev".
ref const(BuildInfo) buildInfo() @trusted {
    __gshared BuildInfo info;
    __gshared bool loaded;
    if (!loaded) {
        import std.process : environment;
        info.version_  = environment.get("IRCFIBER_VERSION", "0.3.0");
        info.commit    = environment.get("IRCFIBER_BUILD_COMMIT", "dev");
        info.shortHash = environment.get("IRCFIBER_BUILD_SHORT", "dev");
        info.describe  = environment.get("IRCFIBER_BUILD_DESCRIBE", "dev");
        info.branch    = environment.get("IRCFIBER_BUILD_BRANCH", "dev");
        info.builtAt   = environment.get("IRCFIBER_BUILD_TIME", "dev");
        info.builtHost = environment.get("IRCFIBER_BUILD_HOST", "dev");
        info.message   = environment.get("IRCFIBER_BUILD_MESSAGE", "");
        info.commitUrl = environment.get("IRCFIBER_BUILD_COMMIT_URL", "");
        loaded = true;
    }
    return info;
}
