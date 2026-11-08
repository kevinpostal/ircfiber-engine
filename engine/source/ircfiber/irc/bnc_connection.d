module ircfiber.irc.bnc_connection;

mixin template BncConnectionMixin() {
    import ircfiber.irc.bnc_ownership : BncEngineState, BncEngineHooks, BncCommandOwner, BncPendingWrite;
    import ircfiber.redis.protocol : IRCCommand;
    import std.string : indexOf, strip, startsWith;
    import std.algorithm : canFind;
    import std.uuid : randomUUID;

    private BncEngineState bncOwnership;

    private BncEngineState bncState() {
        if (bncOwnership !is null) return bncOwnership;
        BncEngineHooks hooks;
        hooks.epoch = () => connectionEpoch;
        hooks.connected = () => state == ConnectionState.connected && !detachedForHotSwap;
        hooks.labeled = () => hasCap("labeled-response");
        hooks.monitorSupported = () => monitorSupported();
        hooks.monitorLimit = () => monitorLimit();
        hooks.ownNick = () => sessionNick.length ? sessionNick : "*";
        hooks.fold = (string nick) => foldNick(nick);
        hooks.webNicks = () => config.monitoredNicks;
        hooks.monitorLines = (string verb, const string[] nicks, size_t limit) {
            return monitorLines(verb, nicks, limit);
        };
        hooks.write = (string line) { writeRaw(line); };
        hooks.emit = (IRCRawEvent event) { eventChannel.put(event); };
        hooks.warning = (string text) { emitLog("monitor", text); };
        bncOwnership = new BncEngineState(redis, config.name, config.id.toString(), ownerId.toString(), serverId, hooks);
        return bncOwnership;
    }

    public void handleBncMonitor(IRCCommand command, long nowMs) {
        bncState().handleBncMonitor(command, nowMs);
    }
    public void expireBncMonitorSessions(long nowMs) { bncState().expireBncMonitorSessions(nowMs); }
    public void reconcileMonitorUnion() { bncState().reconcileMonitorUnion(); }
    public bool observeMonitorNumeric(ref IRCRawEvent event) { return bncState().observeMonitorNumeric(event); }

    private bool preflightBncWrite(BncCommandOwner owner, string wireLabel, string epoch) {
        string code, text;
        if (epoch != connectionEpoch) { code = "STALE_EPOCH"; text = "Upstream connection changed"; }
        else if (state != ConnectionState.connected || detachedForHotSwap) {
            code = "UPSTREAM_UNAVAILABLE"; text = "No connected upstream";
        } else if (!hasCap("labeled-response")) {
            code = "LABELED_RESPONSE_UNAVAILABLE"; text = "Upstream does not support labeled responses";
        } else if (owner.deadlineMs <= unixMsNow()) { code = "RESPONSE_TIMEOUT"; text = "Upstream response timed out"; }
        if (!code.length) return true;
        bncState().reject(owner, code, text, wireLabel, epoch);
        return false;
    }

    public void submitBncRaw(string line, string wireLabel, BncCommandOwner owner,
            string[string] clientTags = null) {
        const epoch = connectionEpoch;
        if (!preflightBncWrite(owner, wireLabel, epoch)) return;
        // Client-only tags have already been validated by the gateway. In particular,
        // downstream labels never change command recognition or security admission.
        if (line.startsWith("@")) {
            const space = line.indexOf(' ');
            line = space < 0 ? "" : line[space + 1 .. $].strip;
        }
        if (!line.length || line.startsWith(":")) {
            bncState().reject(owner, "COMMAND_REJECTED", "Upstream command was rejected", wireLabel, epoch);
            return;
        }
        sendRawAdmitted(line, true, owner, wireLabel, epoch, clientTags);
    }

    public void submitBncMessage(string target, string text, string wireLabel,
            BncCommandOwner owner, string[string] clientTags = null) {
        const epoch = connectionEpoch;
        if (!preflightBncWrite(owner, wireLabel, epoch)) return;
        sendUserMessage("PRIVMSG", target, text, "", clientTags, owner, wireLabel, epoch);
    }

    private void publishBncPresence(ref IRCRawEvent event) {
        if (event.command != "AWAY" && event.command != "ACCOUNT"
            && event.command != "CHGHOST" && event.command != "SETNAME") return;
        string[] sharedChannels;
        foreach (channel, users; channelUsers) {
            foreach (nick; users) {
                if (sameNick(nick, event.nick)) { sharedChannels ~= channel; break; }
            }
        }
        bncState().publishPresence(event, sharedChannels, false);
    }
}
