module ircfiber.irc.query_restore;

/// Which private conversations to re-open from history when a session starts
/// without its query tabs. The tabs live in engine memory and the holder's META
/// snapshot only; a holder restart (OOM kill) or a fresh dial loses them while
/// the messages stay in Mongo. `MessageRepository.recentDirectBuffers` names
/// the conversations, this module decides which of them become tabs.
import std.string : toLower;

/// Look this far back for conversations to re-open (ms).
enum long QUERY_RESTORE_WINDOW_MS = 90L * 24 * 3600 * 1000;
/// Re-open at most this many conversations per network (newest first).
enum size_t QUERY_RESTORE_LIMIT = 100;

/// Network services whose private replies are server-log material, not a
/// conversation the user opened. MemoServ is not listed: it has its own
/// conversation view.
private immutable string[] SERVICES_NICKS = [
    "nickserv", "chanserv", "operserv", "hostserv", "botserv", "helpserv", "global",
    "statserv", "saslserv", "alis", "authserv", "userserv", "chanfix",
];

/// Whether `nick` is one of the network services above (case-insensitive).
bool isServicesNick(string nick) @safe pure {
    const folded = nick.toLower;
    foreach (services; SERVICES_NICKS)
        if (folded == services) return true;
    return false;
}

/// The names in `history` that are not services and not already in `open`
/// (compared with `same`, the connection's casemapping), keeping history order
/// and dropping repeats.
string[] queriesToReopen(const(string)[] open, const(string)[] history, scope bool delegate(string, string) same) {
    string[] fresh;
    foreach (name; history) {
        if (name.length == 0 || isServicesNick(name)) continue;
        bool known;
        foreach (existing; open) if (same(existing, name)) { known = true; break; }
        if (!known) foreach (existing; fresh) if (same(existing, name)) { known = true; break; }
        if (!known) fresh ~= name;
    }
    return fresh;
}

@("queriesToReopen: skips open tabs, repeats and services; keeps history order")
unittest {
    bool same(string a, string b) { return a.toLower == b.toLower; }
    const open = ["alice", "Bob"];
    const history = ["carol", "BOB", "NickServ", "dave", "Carol", "", "ChanServ", "MemoServ"];
    assert(queriesToReopen(open, history, &same) == ["carol", "dave", "MemoServ"]);
    assert(queriesToReopen(open, [], &same).length == 0);
    assert(queriesToReopen([], ["x"], &same) == ["x"]);
}
