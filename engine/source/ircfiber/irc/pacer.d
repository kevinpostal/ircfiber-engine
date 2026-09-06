module ircfiber.irc.pacer;

import std.algorithm : canFind, max, min;
import std.array : appender, split;
import std.ascii : isDigit;
import std.conv : to;
import std.string : indexOf, startsWith, strip, toLower;
import std.utf : stride;

/// Outbound flood pacing.
///
/// IRC servers never advertise their flood *rates*: UnrealIRCd's
/// `set::anti-flood` block (lag-penalty, lag-penalty-bytes, target-flood,
/// connect-flood) is server-side configuration and is not exposed to
/// clients in CAP or ISUPPORT. What *is* machine-readable is:
///
///   * the `draft/multiline` CAP value (`max-lines`, `max-bytes`) — see
///     `parseMultilineCap`; UnrealIRCd re-sends it via CAP DEL/NEW when a
///     user moves between the known-users and unknown-users groups,
///   * the channel's `+f` mode parameter — see `parseChannelFloodLines`,
///   * ISUPPORT `LINELEN` — see `payloadBudget`.
///
/// Everything else has to be *modelled*. Fortunately UnrealIRCd documents
/// its fake-lag formula exactly (Anti-flood settings, "lag-penalty &
/// lag-penalty-bytes"):
///
///   penalty_ms = (1 + floor(cmd_bytes / lag-penalty-bytes)) * lag-penalty
///
/// Accrued fake lag drains at 1000 ms per second. Once it exceeds 10 000 ms
/// the server stops processing the client's commands and buffers them in
/// `recvq`; overflowing `class::recvq` is what produces
/// `ERROR :Closing Link: … (Excess Flood)`.
///
/// `FakeLagPacer` runs that same formula locally and refuses to write a line
/// until the server would accept it, so the ceiling is never reached. It is
/// deliberately pessimistic: it starts on the *unknown-users* defaults (the
/// strictest published values) and is only promoted once we know we are
/// identified to services.

/// One server-side flood group's published parameters.
struct FloodLimits {
    /// `set::anti-flood::<group>::lag-penalty`, milliseconds per command.
    int penaltyMs = 1000;
    /// `set::anti-flood::<group>::lag-penalty-bytes`; every whole multiple
    /// of this in a command costs another `penaltyMs`.
    int penaltyBytes = 90;
    /// Fake lag at which the server stops *processing* commands. Reaching
    /// this is harmless on its own — it only delays our lines.
    int ceilingMs = 10_000;
    /// `class::recvq` in bytes: the amount of RECEIVED-BUT-UNPROCESSED data
    /// the server tolerates before `exit_client(… "Excess Flood")`.
    /// UnrealIRCd's example.conf ships `recvq 8000;` for the client class
    /// and this is what almost every network runs.
    int recvqBytes = 8_000;
    /// Fraction of `recvqBytes` we are willing to occupy, in percent. The
    /// rest absorbs traffic we do not control from here: our own WHO/WHOIS
    /// probes, a JOIN burst, a NICK, and any bouncer client attached to the
    /// same IRC session.
    int recvqUsePct = 60;
}

/// UnrealIRCd 6 defaults for users who are NOT identified to services and
/// have not been connected for two hours. The strictest published values,
/// and therefore our starting assumption.
enum FloodLimits UNKNOWN_USER_LIMITS = FloodLimits(1000, 90, 10_000, 8_000, 60);

/// UnrealIRCd 6 defaults for users identified to services (or connected
/// > 2 h). Only adopted once SASL succeeded.
enum FloodLimits KNOWN_USER_LIMITS = FloodLimits(750, 180, 10_000, 8_000, 60);

/// Hard cap on how far `tighten()` may stretch the per-command penalty.
private enum int MAX_PENALTY_MS = 8_000;

/// UnrealIRCd's documented fake-lag cost of one command of `cmdBytes` bytes.
long lagCostMs(size_t cmdBytes, const FloodLimits lim) pure nothrow @safe {
    const bytes = lim.penaltyBytes <= 0 ? 1 : lim.penaltyBytes;
    return (1 + cast(long)(cmdBytes / bytes)) * lim.penaltyMs;
}

/// Hard clamp UnrealIRCd applies to a multiline batch's fake-lag lump
/// (`multiline.c: calculate_multiline_fakelag`).
enum long MULTILINE_MAX_FAKELAG_MS = 15_000;

/// Fake-lag cost of one `draft/multiline` batch, per UnrealIRCd's
/// `calculate_multiline_fakelag`: one `lag-penalty` floor ("1 extra line")
/// plus the ordinary per-line cost of every line, clamped to 15 s.
///
/// Only the message payloads count — the server measures `strlen(l->text)`,
/// not the wire line — so pass the payloads, not the full protocol lines.
long multilineBatchCostMs(const string[] lines, const FloodLimits lim)
        pure nothrow @safe {
    if (lines.length == 0) return 0;
    const bytes = lim.penaltyBytes <= 0 ? 1 : lim.penaltyBytes;
    long lag = lim.penaltyMs;                       // floor: 1 extra line
    foreach (l; lines)
        lag += (1 + cast(long)(l.length / bytes)) * lim.penaltyMs;
    return lag > MULTILINE_MAX_FAKELAG_MS ? MULTILINE_MAX_FAKELAG_MS : lag;
}

/// Bytes a batch consumes against the advertised `max-bytes`, per
/// UnrealIRCd's `multiline_calc_add_bytes` and the IRCv3 spec: every
/// payload byte, plus one byte for each line feed — i.e. for every line
/// after the first that is NOT a `draft/multiline-concat` continuation.
size_t multilineByteCount(const string[] lines, const bool[] concat)
        pure nothrow @safe {
    size_t total = 0;
    foreach (i, l; lines) {
        total += l.length;
        const isConcat = i < concat.length ? concat[i] : false;
        if (i > 0 && !isConcat) total += 1;
    }
    return total;
}

/// Local model of the server's *receive queue*, driven by its fake-lag clock.
///
/// The thing that kills you is NOT fake lag. `src/parse.c`:
///
///   while (DBufLength(&recvQ) && !client_lagged_up(client)) { … }
///   if (IsUser(client) && DBufLength(&recvQ) > get_recvq(client))
///       exit_client(client, NULL, "Excess Flood");
///
/// Fake lag only stops the server *processing* our queued commands; the
/// bytes then sit in `recvQ`, and only overflowing `class::recvq` (8000 by
/// default) disconnects us. So the correct gate is "will this line fit in
/// the server's receive queue", not "has our fake lag run out".
///
/// IRCCloud reaches the same conclusion by doing nothing: its web client has
/// no send-side throttle whatsoever (the only `_.throttle` in its bundle
/// caps *typing notifications* at 3 s), and it merely reacts to the
/// server's `*** Message to #x throttled due to flooding` notice.
///
/// Consequence: with 8000 bytes of recvq and ~60-byte chat lines, ~80 lines
/// can be in flight at once. Interactive typing is never delayed, a normal
/// paste goes out at wire speed, and only a genuinely huge dump gets paced —
/// and then only as fast as the server drains it.
struct FakeLagPacer {
    private {
        FloodLimits lim = UNKNOWN_USER_LIMITS;
        /// Modelled fake lag, in ms, as of `lastTickMs`.
        long accruedMs;
        /// Sizes of commands the server has received but not yet processed,
        /// oldest first — our model of its `recvQ`.
        size_t[] pending;
        /// Minimum gap between writes imposed after a server complaint.
        /// Zero in the normal case: bursts are free.
        long minIntervalMs;
        long lastSendMs;
        long lastTickMs;
        /// Consecutive server flood complaints; each one doubles the modelled
        /// penalty until a clean period relaxes it again.
        int tightenSteps;
        /// True when the server exempts us from fake lag entirely.
        ///
        /// UnrealIRCd `src/parse.c`: both `parse_addlag()` and
        /// `client_lagged_up()` short-circuit on
        /// `ValidatePermissionsForPath("immune:lag", …)`, which every IRCOp
        /// holds by default. It is a *privilege* though, so an oper block
        /// can withhold it — hence `tighten()` revokes this on the first
        /// complaint rather than trusting oper status forever.
        bool immune;
    }

    /// Current parameters (for logging and tests).
    FloodLimits limits() const pure nothrow @safe { return lim; }

    /// Modelled fake lag as of the last `drain`/`charge` (for logging).
    long accrued() const pure nothrow @safe { return accruedMs; }

    /// Number of times `tighten()` has fired without an intervening `relax`.
    int penaltySteps() const pure nothrow @safe { return tightenSteps; }

    /// Whether the server currently exempts us from fake lag.
    bool isImmune() const pure nothrow @safe { return immune; }

    /// Grants or withdraws the fake-lag exemption (oper gained/lost).
    /// Granting also zeroes the accrual: the server stops counting for us.
    void setImmune(bool v) pure nothrow @safe {
        immune = v;
        if (v) accruedMs = 0;
    }

    /// Adopts a flood group's parameters, preserving any tightening.
    void adopt(FloodLimits base) pure nothrow @safe {
        lim = base;
        foreach (_; 0 .. tightenSteps)
            lim.penaltyMs = min(lim.penaltyMs * 2, MAX_PENALTY_MS);
    }

    /// Fake lag drains at 1000 ms per elapsed second.
    private void drain(long nowMs) pure nothrow @safe {
        if (lastTickMs == 0) {
            lastTickMs = nowMs;
            return;
        }
        if (nowMs <= lastTickMs) return;
        accruedMs -= (nowMs - lastTickMs);
        if (accruedMs < 0) accruedMs = 0;
        lastTickMs = nowMs;
    }

    /// Modelled bytes the server has received but not yet processed.
    long backlogBytes() const pure nothrow @safe {
        long n = 0;
        foreach (b; pending) n += b;
        return n;
    }

    /// Bytes of recvq we allow ourselves to occupy.
    private long recvqBudget() const pure nothrow @safe {
        const pct = lim.recvqUsePct <= 0 ? 60 : lim.recvqUsePct;
        auto b = cast(long)lim.recvqBytes * pct / 100;
        return b < 512 ? 512 : b;
    }

    /// Advances the model of the server's processing loop.
    ///
    /// The server drains `recvQ` while it is not lagged up, so each
    /// iteration processes one command and adds its penalty. Fake lag falls
    /// 1 ms per elapsed ms, which is what lets the queue move at all.
    private void advance(long nowMs) pure nothrow @safe {
        drain(nowMs);
        // `client_lagged_up()` tests the accrual BEFORE the next command's
        // penalty is added, so a single huge command may push far past the
        // ceiling — exactly as the server behaves.
        while (pending.length > 0 && accruedMs < lim.ceilingMs) {
            accruedMs += lagCostMs(pending[0], lim);
            pending = pending[1 .. $];
        }
    }

    /// 0 when a `cmdBytes`-byte command may be written now, otherwise the
    /// number of milliseconds to wait before asking again.
    long waitMs(size_t cmdBytes, long nowMs) pure nothrow @safe {
        if (immune) return 0;
        advance(nowMs);

        // A server complaint imposes a real minimum interval. The recvq gate
        // alone cannot express "slow down" — with an empty queue it would
        // happily let the next line straight through — but a 439/707/flood
        // NOTICE means the server is already dropping or deferring us.
        if (minIntervalMs > 0 && lastSendMs > 0) {
            const since = nowMs - lastSendMs;
            if (since < minIntervalMs) return minIntervalMs - since;
        }

        const budget = recvqBudget();
        // A single command larger than the whole budget could never be sent;
        // let it through rather than deadlocking (the server's own 512-byte
        // line limit makes this unreachable in practice).
        if (cast(long)cmdBytes >= budget) return 0;
        if (backlogBytes() + cast(long)cmdBytes <= budget) return 0;
        // The queue only moves once fake lag drops back under the ceiling.
        const shortfall = accruedMs - lim.ceilingMs + 1;
        return shortfall > 0 ? shortfall : 1;
    }

    /// Records that a `cmdBytes`-byte command was written.
    void charge(size_t cmdBytes, long nowMs) pure nothrow @safe {
        if (immune) return;
        advance(nowMs);
        pending ~= cmdBytes;
        lastSendMs = nowMs;
    }

    /// Whether a `draft/multiline` BATCH may be started now.
    ///
    /// A batch is charged ONE lump penalty when it closes, not per line
    /// (UnrealIRCd `multiline.c`: `add_fake_lag(client,
    /// calculate_multiline_fakelag(client, batch))` after the last line),
    /// and that lump is clamped to 15 s. So the only precondition is that
    /// the server is currently processing our commands at all — the lump
    /// lands afterwards and delays whatever comes next.
    ///
    /// The batch itself must NOT be paced internally: `set::multiline::
    /// batch-timeout` (default 15 s) aborts a batch that takes too long.
    bool canStartBatch(long nowMs) pure nothrow @safe {
        return waitMs(0, nowMs) == 0;
    }

    /// Charges a completed batch its single clamped penalty.
    void chargeBatch(const string[] lines, long nowMs) pure nothrow @safe {
        if (immune) return;
        drain(nowMs);
        accruedMs += multilineBatchCostMs(lines, lim);
    }

    /// The server complained (263 / 439 / 707 / a flood NOTICE / a FAIL /
    /// an Excess Flood kill): double the modelled per-command penalty and
    /// assume we are already at the ceiling, so the next line waits.
    void tighten(long nowMs) pure nothrow @safe {
        // An exemption we assumed from oper status is disproved the moment
        // the server rate-limits us: `immune:lag` can be withheld from an
        // oper block, and other ircds grant opers nothing at all.
        immune = false;
        if (tightenSteps < 4) {
            tightenSteps++;
            lim.penaltyMs = min(lim.penaltyMs * 2, MAX_PENALTY_MS);
            // A complaint means our recvq estimate was too generous for
            // this server: shrink the share we are willing to occupy.
            lim.recvqUsePct = max(lim.recvqUsePct / 2, 10);
            // Impose a real floor on our send rate, doubling per complaint.
            minIntervalMs = minIntervalMs > 0
                ? min(minIntervalMs * 2, 4_000)
                : lim.penaltyMs;
        }
        drain(nowMs);
        // The cooldown runs from the complaint itself, not from our last
        // write — otherwise a complaint arriving during an idle moment would
        // impose nothing at all.
        lastSendMs = nowMs;
        // Assume the queue is as full as we are willing to let it get, so
        // the next line waits for real drain rather than our estimate.
        accruedMs = max(accruedMs, cast(long)lim.ceilingMs);
    }

    /// Undoes one tightening step (called after a long quiet period).
    void relax() pure nothrow @safe {
        if (tightenSteps == 0) return;
        tightenSteps--;
        lim.penaltyMs = max(lim.penaltyMs / 2, 1);
        lim.recvqUsePct = min(lim.recvqUsePct * 2, 60);
        minIntervalMs = minIntervalMs > 1 ? minIntervalMs / 2 : 0;
    }

    /// New TCP connection: the server's recvq and fake lag both start empty.
    void resetAccrual() pure nothrow @safe {
        accruedMs = 0;
        lastTickMs = 0;
        pending = null;
        lastSendMs = 0;
    }
}

/// A channel's `+f` line-rate ceiling: `lines` per `seconds`.
struct ChannelLineLimit {
    int lines;
    int seconds;

    bool valid() const pure nothrow @safe { return lines > 0 && seconds > 0; }
}

/// `set::anti-flood::everyone::target-flood`, the one limit that applies to
/// literally every user on UnrealIRCd and cannot be escaped by opering up
/// (only `immune:target-flood` does that). Over it the server silently
/// DROPS the message — no kick, no error — which the user experiences as
/// messages vanishing. Documented defaults:
///
///   channel-privmsg 45:5    private-privmsg 30:5
///   channel-notice  15:5    private-notice  10:5
///
/// The limit is per TARGET across all senders, so leaving a margin is not
/// optional: someone else talking in the channel consumes the same budget.
enum ChannelLineLimit TARGET_FLOOD_CHANNEL_PRIVMSG = ChannelLineLimit(36, 5);
/// ditto
enum ChannelLineLimit TARGET_FLOOD_PRIVATE_PRIVMSG = ChannelLineLimit(24, 5);
/// ditto
enum ChannelLineLimit TARGET_FLOOD_CHANNEL_NOTICE = ChannelLineLimit(12, 5);
/// ditto
enum ChannelLineLimit TARGET_FLOOD_PRIVATE_NOTICE = ChannelLineLimit(8, 5);

/// The applicable target-flood ceiling for a send.
ChannelLineLimit targetFloodLimit(bool isChannel, bool isNotice) pure nothrow @safe {
    if (isNotice)
        return isChannel ? TARGET_FLOOD_CHANNEL_NOTICE : TARGET_FLOOD_PRIVATE_NOTICE;
    return isChannel ? TARGET_FLOOD_CHANNEL_PRIVMSG : TARGET_FLOOD_PRIVATE_PRIVMSG;
}

/// Parses the line-rate part of a UnrealIRCd channel `+f` parameter.
///
/// Accepts both the modern grouped form and the legacy simple form:
///
///   `[7t,4j,15m#b]:15`  → the `t` (text) or `m` (moderate) entry, 7 per 15 s
///   `4:15`              → 4 lines per 15 s
///
/// Only the `t` and `m` subtypes bound message rate — UnrealIRCd applies the
/// lower of `+f` and `multiline::max-lines` to a multiline batch, so this is
/// also the ceiling for batched sends. Returns an invalid limit when the
/// parameter carries no line-rate entry.
ChannelLineLimit parseChannelFloodLines(string param) pure nothrow @safe {
    ChannelLineLimit none;
    try {
        auto p = param.strip();
        if (p.length == 0) return none;

        const colon = p.lastIndexOf(':');
        if (colon <= 0 || colon + 1 >= p.length) return none;
        const secsPart = p[colon + 1 .. $].strip();
        int secs = 0;
        foreach (c; secsPart) {
            if (!isDigit(c)) return none;
            secs = secs * 10 + (c - '0');
        }
        if (secs <= 0) return none;

        auto body_ = p[0 .. colon].strip();
        if (body_.length == 0) return none;

        // Legacy `<lines>:<secs>` — no brackets, no subtype letters.
        if (body_[0] != '[') {
            int lines = 0;
            foreach (c; body_) {
                if (!isDigit(c)) return none;
                lines = lines * 10 + (c - '0');
            }
            return lines > 0 ? ChannelLineLimit(lines, secs) : none;
        }

        // Grouped `[<num><type>[<action>][<duration>], …]`.
        if (body_[$ - 1] != ']') return none;
        auto inner = body_[1 .. $ - 1];
        foreach (entry; inner.split(",")) {
            auto e = entry.strip();
            size_t i = 0;
            int num = 0;
            while (i < e.length && isDigit(e[i])) {
                num = num * 10 + (e[i] - '0');
                i++;
            }
            if (i == 0 || i >= e.length) continue;
            const type = e[i];
            if (num > 0 && (type == 't' || type == 'm'))
                return ChannelLineLimit(num, secs);
        }
        return none;
    } catch (Exception) {
        return none;
    }
}

/// std.string.lastIndexOf without the Unicode machinery (params are ASCII).
private ptrdiff_t lastIndexOf(string s, char c) pure nothrow @safe @nogc {
    for (ptrdiff_t i = cast(ptrdiff_t)s.length - 1; i >= 0; i--)
        if (s[i] == c) return i;
    return -1;
}

/// Sliding-window counter enforcing a `ChannelLineLimit`.
struct LineRateWindow {
    private long[] stamps;

    /// Drops stamps older than the window.
    private void prune(long nowMs, int seconds) pure nothrow @safe {
        const cutoff = nowMs - cast(long)seconds * 1000;
        size_t keep = 0;
        while (keep < stamps.length && stamps[keep] <= cutoff) keep++;
        if (keep > 0) stamps = stamps[keep .. $];
    }

    /// 0 when another line fits in the window, otherwise the wait in ms.
    long waitMs(long nowMs, ChannelLineLimit lim) pure nothrow @safe {
        if (!lim.valid()) return 0;
        prune(nowMs, lim.seconds);
        if (cast(int)stamps.length < lim.lines) return 0;
        // The oldest stamp has to age out of the window.
        const expiresAt = stamps[0] + cast(long)lim.seconds * 1000;
        return expiresAt > nowMs ? expiresAt - nowMs : 0;
    }

    /// Records a line.
    void record(long nowMs) pure nothrow @safe { stamps ~= nowMs; }

    /// Forgets all history (new connection, or channel re-joined).
    void clear() pure nothrow @safe { stamps = null; }
}

/// `draft/multiline` CAP value.
struct MultilineLimits {
    /// Maximum PRIVMSG/NOTICE lines in one batch. 0 = not advertised.
    int maxLines;
    /// Maximum total payload bytes across the batch. 0 = not advertised.
    int maxBytes;

    bool usable() const pure nothrow @safe { return maxBytes > 0; }
}

/// Parses the REQUIRED value of the `draft/multiline` capability, e.g.
/// `max-bytes=5250,max-lines=15`. Unknown keys are ignored per the spec.
MultilineLimits parseMultilineCap(string value) pure nothrow @safe {
    MultilineLimits out_;
    try {
        foreach (tok; value.split(",")) {
            auto t = tok.strip();
            const eq = t.indexOf('=');
            if (eq <= 0) continue;
            const key = t[0 .. eq].strip().toLower();
            const val = t[eq + 1 .. $].strip();
            int n = 0;
            bool ok = val.length > 0;
            foreach (c; val) {
                if (!isDigit(c)) { ok = false; break; }
                n = n * 10 + (c - '0');
            }
            if (!ok) continue;
            if (key == "max-bytes") out_.maxBytes = n;
            else if (key == "max-lines") out_.maxLines = n;
        }
    } catch (Exception) {
        return MultilineLimits.init;
    }
    return out_;
}

/// Bytes of message payload that fit in one protocol line.
///
/// The 512-byte limit (or ISUPPORT `LINELEN`) covers the whole line as the
/// *server re-emits it to other clients*, which is where truncation bites:
///
///   `:` + `nick!user@host` + ` ` + `PRIVMSG` + ` ` + `#target` + ` :` + msg + `\r\n`
///
/// `hostmask` is our own `nick!user@host` (from `396 RPL_VISIBLEHOST`, or
/// the echo of our own JOIN). When it is unknown the IRCv3 multiline spec's
/// recommended worst case is assumed: nick 20 + `!` + user 20 + `@` + host 63.
size_t payloadBudget(int linelen, string hostmask, string command,
                     string target, size_t safety = 16) pure nothrow @safe {
    enum size_t WORST_CASE_HOSTMASK = 20 + 1 + 20 + 1 + 63;
    const size_t len = linelen > 0 ? cast(size_t)linelen : 512;
    const size_t mask = hostmask.length > 0 ? hostmask.length : WORST_CASE_HOSTMASK;
    const size_t overhead =
        1 +                 // leading ':'
        mask +              // nick!user@host
        1 +                 // ' '
        command.length +    // PRIVMSG / NOTICE
        1 +                 // ' '
        target.length +     // #channel or nick
        2 +                 // " :"
        2 +                 // CRLF
        safety;
    return len > overhead + 80 ? len - overhead : 80;
}

// ── Flood-permission detection ───────────────────────────────────────────────
//
// Nothing here guesses. Each helper decodes one thing the server actually
// tells us, and the exemptions mirror UnrealIRCd's own checks:
//
//   fake lag  : parse.c        !ValidatePermissionsForPath("immune:lag", …)
//   channel +f: floodprot.c    check_channel_access(client, channel, "hoaq")
//                              || is_floodprot_exempt() via ~F:/~flood: in +e

/// Channel status modes that exempt a member from `+f`: halfop, op, admin,
/// owner. Voice (`v`) deliberately absent — floodprot's access string is
/// exactly `"hoaq"`.
enum string FLOOD_EXEMPT_STATUS_MODES = "hoaq";

/// True when a user-mode string grants IRCOp status (`o`, or `O` for a
/// local/services oper on ircds that distinguish them).
///
/// Accepts both the `221 RPL_UMODEIS` form (`+iwo`) and a bare `MODE`
/// change fragment (`+o`). Only additive segments count, so `+i-o` is not
/// oper.
bool userModesGrantOper(string modes) pure nothrow @safe {
    bool adding = true;
    foreach (c; modes) {
        if (c == '+') { adding = true; continue; }
        if (c == '-') { adding = false; continue; }
        if (adding && (c == 'o' || c == 'O')) return true;
    }
    return false;
}

/// Maps the status-prefix characters on a NAMES entry to their mode letters
/// using the ISUPPORT `PREFIX` token, e.g. `(qaohv)~&@%+` plus `@%nick` →
/// `"oh"`. Unknown prefixes are skipped.
string statusModesOf(string namesEntry, string prefixToken) pure nothrow @safe {
    // PREFIX=(modes)prefixes
    if (prefixToken.length < 3 || prefixToken[0] != '(') return "";
    const close = prefixToken.indexOf(')');
    if (close <= 1) return "";
    const modes = prefixToken[1 .. close];
    const chars = prefixToken[close + 1 .. $];
    if (modes.length != chars.length) return "";

    auto out_ = appender!string();
    foreach (c; namesEntry) {
        bool matched = false;
        foreach (i, pc; chars) {
            if (pc == c) {
                out_ ~= modes[i];
                matched = true;
                break;
            }
        }
        if (!matched) break;   // first non-prefix char ends the run
    }
    return out_.data;
}

/// True when the status modes we hold on a channel exempt us from `+f`.
bool statusExemptsFromFlood(string statusModes) pure nothrow @safe {
    foreach (m; statusModes)
        foreach (e; FLOOD_EXEMPT_STATUS_MODES)
            if (m == e) return true;
    return false;
}

/// Extracts the effective `+f` line limit from UnrealIRCd's reply to a
/// `MODE <channel> f` *query*.
///
/// That query is the only way a plain client can read the numbers behind
/// `+F <profile>` — the profile name is public but its limits are
/// server-side config (`floodprot_override_mode` in floodprot.c answers
/// with notices like `Channel '#x' has effective flood setting
/// '[30j#R10,40m#M10,…]:15' (flood profile 'normal')`).
///
/// Every single-quoted run is tried and the STRICTEST valid line limit
/// wins, because `+f` and `+F` can both be set and the reply then lists
/// them on separate lines.
ChannelLineLimit parseEffectiveFloodNotice(string text) pure nothrow @safe {
    ChannelLineLimit best;
    try {
        if (text.canFind("No channel mode +f")) return best;
        size_t i = 0;
        while (i < text.length) {
            const open = text[i .. $].indexOf('\'');
            if (open < 0) break;
            const start = i + open + 1;
            if (start >= text.length) break;
            const close = text[start .. $].indexOf('\'');
            if (close < 0) break;
            auto candidate = text[start .. start + close];
            i = start + close + 1;
            auto lim = parseChannelFloodLines(candidate);
            if (!lim.valid()) continue;
            if (!best.valid() || stricter(lim, best)) best = lim;
        }
    } catch (Exception) {
        return ChannelLineLimit.init;
    }
    return best;
}

/// `a` allows fewer lines per second than `b`.
private bool stricter(ChannelLineLimit a, ChannelLineLimit b) pure nothrow @safe {
    // a.lines/a.seconds < b.lines/b.seconds, integer-safe.
    return cast(long)a.lines * b.seconds < cast(long)b.lines * a.seconds;
}

/// Case-insensitive IRC mask match supporting `*` and `?`.
bool maskMatches(string mask, string target) pure nothrow @safe {
    size_t m = 0, t = 0, starM = size_t.max, starT = 0;
    static char fold(char c) pure nothrow @safe @nogc {
        return (c >= 'A' && c <= 'Z') ? cast(char)(c + 32) : c;
    }
    while (t < target.length) {
        if (m < mask.length && (mask[m] == '?' || fold(mask[m]) == fold(target[t]))) {
            m++; t++;
        } else if (m < mask.length && mask[m] == '*') {
            starM = m++; starT = t;
        } else if (starM != size_t.max) {
            m = starM + 1;
            t = ++starT;
        } else {
            return false;
        }
    }
    while (m < mask.length && mask[m] == '*') m++;
    return m == mask.length;
}

/// True when a channel `+e` exception entry exempts `hostmask` from the
/// given flood type.
///
/// UnrealIRCd `is_floodprot_exempt()` recognises `~F:<types>:<mask>` and
/// `~flood:<types>:<mask>`, where `<types>` is `*` or a set of flood-type
/// letters (`t`/`m` being the message-rate ones).
bool floodExceptionExempts(string exceptEntry, string hostmask, char floodType)
        pure nothrow @safe {
    try {
        string rest;
        if (exceptEntry.startsWith("~F:")) rest = exceptEntry[3 .. $];
        else if (exceptEntry.startsWith("~flood:")) rest = exceptEntry[7 .. $];
        else return false;

        const sep = rest.indexOf(':');
        if (sep <= 0 || sep + 1 >= rest.length) return false;
        const types = rest[0 .. sep];
        const mask = rest[sep + 1 .. $];
        bool typeOk = types == "*";
        if (!typeOk)
            foreach (c; types)
                if (c == floodType) { typeOk = true; break; }
        if (!typeOk) return false;
        return maskMatches(mask, hostmask);
    } catch (Exception) {
        return false;
    }
}

/// Removes everything that could terminate or forge a protocol line.
///
/// A user-supplied message body reaches the wire as
/// `PRIVMSG <target> :<text>`, so an embedded CR or LF would inject an
/// arbitrary command; NUL truncates the line in some servers.
string sanitizeLine(string s) pure nothrow @safe {
    bool dirty = false;
    foreach (c; s) {
        if (c == '\r' || c == '\n' || c == '\0') { dirty = true; break; }
    }
    if (!dirty) return s;
    auto buf = appender!string();
    foreach (c; s) {
        if (c == '\r' || c == '\n' || c == '\0') continue;
        buf ~= c;
    }
    return buf.data;
}

/// Splits `text` into chunks of at most `maxBytes` UTF-8 bytes, never
/// splitting a code point.
///
/// Prefers breaking after the last space that fits, and keeps that space at
/// the end of the chunk — the IRCv3 multiline recommendation, so a
/// `draft/multiline-concat` rejoin and the non-multiline fallback both read
/// correctly. A single word longer than the budget is hard-broken.
string[] splitUtf8(string text, size_t maxBytes) pure nothrow @safe {
    if (maxBytes == 0) maxBytes = 1;
    if (text.length <= maxBytes) return text.length ? [text] : [""];

    auto out_ = appender!(string[]);
    size_t start = 0;
    while (start < text.length) {
        if (text.length - start <= maxBytes) {
            out_ ~= text[start .. $];
            break;
        }
        size_t i = start;
        size_t lastSpaceEnd = 0;
        while (i < text.length) {
            size_t n = 1;
            try n = stride(text, i);
            catch (Exception) n = 1;             // invalid UTF-8: byte-wise
            if (i + n - start > maxBytes) break;
            i += n;
            if (text[i - 1] == ' ') lastSpaceEnd = i;
        }
        // A single code point wider than the budget still has to advance.
        if (i == start) {
            size_t n = 1;
            try n = stride(text, start);
            catch (Exception) n = 1;
            i = start + n;
        }
        const end = (lastSpaceEnd > start) ? lastSpaceEnd : i;
        out_ ~= text[start .. end];
        start = end;
    }
    return out_.data;
}

/// Splits a logical message into protocol-ready lines: newline-separated
/// first (blank lines preserved — multiline batches carry them), then each
/// line byte-split to `maxBytes`.
///
/// `concatFlags[i]` is true when line `i` continues line `i-1` because it was
/// byte-split rather than newline-separated, i.e. exactly when the
/// `draft/multiline-concat` tag must be set.
string[] splitMessage(string text, size_t maxBytes, out bool[] concatFlags)
        pure nothrow @safe {
    auto lines = appender!(string[]);
    auto flags = appender!(bool[]);
    size_t lineStart = 0;
    void emitLogicalLine(string logical) {
        auto parts = splitUtf8(sanitizeLine(logical), maxBytes);
        foreach (idx, p; parts) {
            lines ~= p;
            flags ~= idx > 0;
        }
    }
    foreach (i, c; text) {
        if (c == '\n') {
            emitLogicalLine(text[lineStart .. i]);
            lineStart = i + 1;
        }
    }
    emitLogicalLine(text[lineStart .. $]);
    concatFlags = flags.data;
    return lines.data;
}

@safe unittest {
    // ── UnrealIRCd's documented fake-lag arithmetic ───────────────────────
    // "JOIN #test" is 10 bytes, unknown-users: (1+floor(10/90))*1000 = 1000.
    assert(lagCostMs(10, UNKNOWN_USER_LIMITS) == 1000);
    // A 200-byte command: (1+floor(200/90))*1000 = 3000.
    assert(lagCostMs(200, UNKNOWN_USER_LIMITS) == 3000);
    // Known-users, 400-byte PRIVMSG: (1+floor(400/180))*750 = 2250.
    assert(lagCostMs(400, KNOWN_USER_LIMITS) == 2250);
}

@safe unittest {
    // The gate is the server's recvq, not its patience. Budget is
    // 8000 * 60% = 4800 bytes, so ~60-byte chat lines go out in a burst of
    // 80 queued — plus the ~10 the server processes outright before fake
    // lag reaches its 10 s ceiling, which free their recvq bytes again.
    // 90 lines with zero delay is what "as fast as I can type" needs.
    FakeLagPacer p;
    long t = 1_000_000;
    int sent = 0;
    while (p.waitMs(60, t) == 0 && sent < 500) {
        p.charge(60, t);
        sent++;
    }
    assert(sent == 90, "burst size " ~ sent.to!string);
    assert(p.waitMs(60, t) > 0, "the 91st line has to wait for drain");

    // Sustained throughput is whatever the server drains, and that IS the
    // fake-lag rate: ~10 commands per 10 s ceiling-cycle for small lines.
    // Bursts are free; only a sustained dump is rate-limited, by the server.
    const before = p.backlogBytes();
    t += 11_000;
    assert(p.waitMs(60, t) == 0, "drain must free room");
    assert(p.backlogBytes() < before, "backlog must shrink");
    int more = 0;
    while (p.waitMs(60, t) == 0 && more < 100) { p.charge(60, t); more++; }
    assert(more == 10, "freed slots " ~ more.to!string);
}

@safe unittest {
    // A 40-line paste of ordinary lines never waits — the whole point.
    FakeLagPacer p;
    long t = 500_000;
    foreach (i; 0 .. 40) {
        assert(p.waitMs(70, t) == 0, "line " ~ i.to!string ~ " must not wait");
        p.charge(70, t);
    }
}

@safe unittest {
    // A command bigger than the whole budget is let through rather than
    // deadlocking (unreachable in practice: lines are <= 512 bytes).
    FakeLagPacer p;
    assert(p.waitMs(100_000, 5_000) == 0);
}

@safe unittest {
    // A complaint doubles the penalty AND halves the recvq share we claim.
    FakeLagPacer p;
    assert(p.limits().penaltyMs == 1000 && p.limits().recvqUsePct == 60);
    p.tighten(1000);
    assert(p.limits().penaltyMs == 2000 && p.limits().recvqUsePct == 30);
    assert(p.waitMs(60, 1000) > 0, "must back off immediately");
    p.tighten(1000);
    p.tighten(1000);
    p.tighten(1000);
    p.tighten(1000);                       // capped at 4 steps
    assert(p.penaltySteps() == 4);
    assert(p.limits().penaltyMs == 8000);
    assert(p.limits().recvqUsePct == 10, "floor at 10%");
    p.relax();
    assert(p.limits().penaltyMs == 4000 && p.limits().recvqUsePct == 20);
    // Promotion keeps the tightening multiplier.
    FakeLagPacer q;
    q.tighten(0);
    q.adopt(KNOWN_USER_LIMITS);
    assert(q.limits().penaltyMs == 1500 && q.limits().penaltyBytes == 180);
}

@safe unittest {
    // target-flood is the limit nobody escapes, and it DROPS messages
    // silently rather than kicking — so it must cap our rate too.
    assert(targetFloodLimit(true, false) == TARGET_FLOOD_CHANNEL_PRIVMSG);
    assert(targetFloodLimit(false, false) == TARGET_FLOOD_PRIVATE_PRIVMSG);
    assert(targetFloodLimit(true, true) == TARGET_FLOOD_CHANNEL_NOTICE);
    assert(targetFloodLimit(false, true) == TARGET_FLOOD_PRIVATE_NOTICE);
    // Every default leaves headroom under the server's documented figure.
    assert(TARGET_FLOOD_CHANNEL_PRIVMSG.lines < 45);
    assert(TARGET_FLOOD_PRIVATE_PRIVMSG.lines < 30);
    // ~7 messages/second sustained to a channel is the ceiling this implies.
    assert(TARGET_FLOOD_CHANNEL_PRIVMSG.lines / TARGET_FLOOD_CHANNEL_PRIVMSG.seconds == 7);
}

@safe unittest {
    // Channel +f line-rate parsing.
    auto a = parseChannelFloodLines("[7t,4j,15m#b]:15");
    assert(a.valid() && a.lines == 7 && a.seconds == 15);
    auto b = parseChannelFloodLines("[5t]:15");
    assert(b.valid() && b.lines == 5 && b.seconds == 15);
    auto c = parseChannelFloodLines("4:15");
    assert(c.valid() && c.lines == 4 && c.seconds == 15);
    // Kick action and duration suffixes must not confuse the subtype.
    auto d = parseChannelFloodLines("[10t#b10]:20");
    assert(d.valid() && d.lines == 10 && d.seconds == 20);
    // No line-rate entry at all.
    assert(!parseChannelFloodLines("[4j,3n]:60").valid());
    assert(!parseChannelFloodLines("").valid());
    assert(!parseChannelFloodLines("garbage").valid());
    assert(!parseChannelFloodLines("[5t]:0").valid());
}

@safe unittest {
    // Sliding window: 5 lines per 15 s.
    auto lim = ChannelLineLimit(5, 15);
    LineRateWindow w;
    long t = 500_000;
    foreach (i; 0 .. 5) {
        assert(w.waitMs(t, lim) == 0);
        w.record(t);
    }
    const wait = w.waitMs(t, lim);
    assert(wait == 15_000, "wait " ~ wait.to!string);
    // After the oldest stamp ages out, one more fits.
    assert(w.waitMs(t + 15_000, lim) == 0);
    // No limit configured → never blocks.
    LineRateWindow u;
    foreach (i; 0 .. 50) { assert(u.waitMs(t, ChannelLineLimit(0, 0)) == 0); u.record(t); }
}

@safe unittest {
    // draft/multiline CAP value.
    auto m = parseMultilineCap("max-bytes=5250,max-lines=15");
    assert(m.usable() && m.maxBytes == 5250 && m.maxLines == 15);
    // Order and unknown keys per spec.
    auto m2 = parseMultilineCap("max-lines=7,something=x,max-bytes=1500");
    assert(m2.maxLines == 7 && m2.maxBytes == 1500);
    // max-lines is only RECOMMENDED, max-bytes REQUIRED.
    auto m3 = parseMultilineCap("max-bytes=4096");
    assert(m3.usable() && m3.maxLines == 0);
    assert(!parseMultilineCap("").usable());
    assert(!parseMultilineCap("max-bytes=abc").usable());
}

@safe unittest {
    // Multiline batch fake lag, against UnrealIRCd's calculate_multiline_fakelag:
    //   lag = lag_penalty + Σ (1 + len/lag_penalty_bytes) * lag_penalty,  clamp 15s
    string[] three = ["hello", "world", "again"];
    // known-users: 750 floor + 3 * (1 + 0) * 750 = 3000
    assert(multilineBatchCostMs(three, KNOWN_USER_LIMITS) == 3000);
    // unknown-users: 1000 + 3 * 1000 = 4000
    assert(multilineBatchCostMs(three, UNKNOWN_USER_LIMITS) == 4000);
    assert(multilineBatchCostMs([], KNOWN_USER_LIMITS) == 0);

    // A full 15-line / 350-byte-a-line batch blows past the clamp.
    string[] big;
    string line350;
    foreach (i; 0 .. 350) line350 ~= "x";
    foreach (i; 0 .. 15) big ~= line350;
    // Uncapped this would be 750 + 15*(1+1)*750 = 23 250.
    assert(multilineBatchCostMs(big, KNOWN_USER_LIMITS) == MULTILINE_MAX_FAKELAG_MS);

    // The batch is admitted whenever recvq has room. Its lump penalty stops
    // the server *processing* for ~15 s, so anything sent after it simply
    // queues — which is fine until recvq fills, and then we wait.
    FakeLagPacer p;
    assert(p.canStartBatch(1000));
    p.chargeBatch(big, 1000);
    assert(p.waitMs(50, 1000) == 0, "recvq is empty, one more line is fine");
    int queued = 0;
    while (p.waitMs(60, 1000) == 0 && queued < 500) { p.charge(60, 1000); queued++; }
    assert(queued == 80, "queued " ~ queued.to!string);
    // 15 s of drain lets the server work through it again.
    assert(p.waitMs(60, 1000 + 16_000) == 0);
}

@safe unittest {
    // max-bytes accounting: payload bytes + 1 per line feed, and a
    // multiline-concat continuation contributes NO line feed
    // (UnrealIRCd multiline_calc_add_bytes).
    assert(multilineByteCount(["abc"], [false]) == 3);
    // "abc" + LF + "de" = 6
    assert(multilineByteCount(["abc", "de"], [false, false]) == 6);
    // concat continuation: no separator byte → 5
    assert(multilineByteCount(["abc", "de"], [false, true]) == 5);
    // Blank line still costs its separator.
    assert(multilineByteCount(["a", "", "b"], [false, false, false]) == 4);
}

@safe unittest {
    // payloadBudget mirrors the documented line accounting.
    const mask = "nick!~user@host.example.com";      // 27 bytes
    const got = payloadBudget(512, mask, "PRIVMSG", "#channel");
    // 1 + 27 + 1 + 7 + 1 + 8 + 2 + 2 + 16 = 65
    assert(got == 512 - 65, "budget " ~ got.to!string);
    // Unknown hostmask → IRCv3 worst case of 105 bytes.
    const worst = payloadBudget(512, "", "PRIVMSG", "#channel");
    assert(worst == 512 - (1 + 105 + 1 + 7 + 1 + 8 + 2 + 2 + 16));
    // A larger LINELEN is honoured.
    assert(payloadBudget(1024, mask, "PRIVMSG", "#channel") == 1024 - 65);
    // Absurd LINELEN clamps to a usable floor rather than underflowing.
    assert(payloadBudget(40, mask, "PRIVMSG", "#channel") == 80);
}

@safe unittest {
    // Oper detection from user modes: additive `o`/`O` only.
    assert(userModesGrantOper("+iwo"));
    assert(userModesGrantOper("+o"));
    assert(userModesGrantOper("iwxzo"));     // 221 without a leading sign
    assert(userModesGrantOper("+O"));        // local oper on some ircds
    assert(!userModesGrantOper("+iwx"));
    assert(!userModesGrantOper("-o"));
    assert(!userModesGrantOper("+i-o"));
    assert(!userModesGrantOper(""));
}

@safe unittest {
    // An oper is exempt from fake lag entirely, and a complaint revokes it.
    FakeLagPacer p;
    long t = 2_000_000;
    // 400-byte lines against a 4800-byte budget: a plain user gets a
    // sizeable burst (12 queued + the handful the server processes at once)
    // and is then paced by the server's own drain rate.
    int admitted = 0;
    while (p.waitMs(400, t) == 0 && admitted < 500) { p.charge(400, t); admitted++; }
    assert(admitted > 8 && admitted < 40, "burst " ~ admitted.to!string);
    assert(p.waitMs(400, t) > 0, "non-oper is eventually paced");

    FakeLagPacer o;
    o.setImmune(true);
    assert(o.isImmune());
    foreach (i; 0 .. 500) { assert(o.waitMs(400, t) == 0); o.charge(400, t); }
    assert(o.canStartBatch(t));
    // The server disagreed with us — immunity is only ever an assumption.
    o.tighten(t);
    assert(!o.isImmune());
    assert(o.waitMs(400, t) > 0, "must fall back to pacing after a complaint");
}

@safe unittest {
    // Status prefixes → mode letters via ISUPPORT PREFIX, and the "hoaq"
    // exemption (voice must NOT count).
    enum P = "(qaohv)~&@%+";
    assert(statusModesOf("@nick", P) == "o");
    assert(statusModesOf("~&nick!u@h", P) == "qa");
    assert(statusModesOf("%nick", P) == "h");
    assert(statusModesOf("+nick", P) == "v");
    assert(statusModesOf("nick", P) == "");
    assert(statusModesOf("@nick", "garbage") == "");

    assert(statusExemptsFromFlood("o"));
    assert(statusExemptsFromFlood("h"));
    assert(statusExemptsFromFlood("qa"));
    assert(statusExemptsFromFlood("ov"));
    assert(!statusExemptsFromFlood("v"), "voice is not in floodprot's \"hoaq\"");
    assert(!statusExemptsFromFlood(""));
}

@safe unittest {
    // `MODE #chan f` query replies (floodprot_override_mode).
    auto a = parseEffectiveFloodNotice(
        "Channel '#x' has effective flood setting '[30j#R10,40m#M10,7c#C15]:15' (flood profile 'normal')");
    assert(a.valid() && a.lines == 40 && a.seconds == 15);

    // floodprot sends the +f line as its own notice.
    auto b = parseEffectiveFloodNotice("Plus flood setting via +f: '[5t]:15'");
    assert(b.valid() && b.lines == 5 && b.seconds == 15);

    // Custom-only channel.
    auto d = parseEffectiveFloodNotice(
        "Channel '#x' has effective flood setting '[7t#b10]:15' (custom settings via +f)");
    assert(d.valid() && d.lines == 7 && d.seconds == 15);

    // Strictest of several quoted runs wins regardless of order.
    auto c = parseEffectiveFloodNotice("'[40m]:15' then '[5t]:15' then '[60m]:15'");
    assert(c.valid() && c.lines == 5);

    // No flood protection at all → no limit.
    assert(!parseEffectiveFloodNotice("No channel mode +f/+F is active on #x").valid());
    assert(!parseEffectiveFloodNotice("nothing quoted here").valid());
}

@safe unittest {
    // Wildcard mask matching for +e flood exceptions.
    assert(maskMatches("*!*@*", "nick!user@host"));
    assert(maskMatches("nick!*@*", "NICK!user@host"), "IRC masks fold case");
    assert(maskMatches("*@trusted.example.com", "nick!user@trusted.example.com"));
    assert(maskMatches("ni?k!*@*", "nick!user@host"));
    assert(!maskMatches("other!*@*", "nick!user@host"));
    assert(maskMatches("*", "anything"));
    assert(!maskMatches("", "x"));

    // ~F: / ~flood: exception entries.
    const me = "nick!user@trusted.example.com";
    assert(floodExceptionExempts("~F:t:*!*@trusted.example.com", me, 't'));
    assert(floodExceptionExempts("~flood:*:*!*@trusted.example.com", me, 'm'));
    assert(floodExceptionExempts("~F:tm:nick!*@*", me, 'm'));
    // Wrong flood type.
    assert(!floodExceptionExempts("~F:j:*!*@*", me, 't'));
    // Wrong mask.
    assert(!floodExceptionExempts("~F:t:*!*@other.example.com", me, 't'));
    // Not a flood exception at all (a plain ban exception).
    assert(!floodExceptionExempts("*!*@trusted.example.com", me, 't'));
    assert(!floodExceptionExempts("~F:t", me, 't'));
}

@safe unittest {
    // CR/LF/NUL stripping — the command-injection guard.
    assert(sanitizeLine("hello") == "hello");
    assert(sanitizeLine("a\r\nJOIN #evil") == "aJOIN #evil");
    assert(sanitizeLine("a\0b") == "ab");
}

@safe unittest {
    // Byte-correct splitting: 4-byte emoji must never be cut apart.
    string emoji;
    foreach (i; 0 .. 50) emoji ~= "\U0001F600";      // 200 bytes
    auto parts = splitUtf8(emoji, 30);
    string rejoined;
    foreach (p; parts) {
        assert(p.length <= 30, "chunk " ~ p.length.to!string);
        assert(p.length % 4 == 0, "cut a code point apart");
        rejoined ~= p;
    }
    assert(rejoined == emoji);

    // 3-byte CJK.
    string cjk;
    foreach (i; 0 .. 40) cjk ~= "\u4F60";
    auto cparts = splitUtf8(cjk, 10);
    string cjoined;
    foreach (p; cparts) {
        assert(p.length <= 10 && p.length % 3 == 0);
        cjoined ~= p;
    }
    assert(cjoined == cjk);

    // Word-boundary preference keeps the space at the end of the chunk.
    auto w = splitUtf8("aaa bbb ccc", 8);
    assert(w[0] == "aaa bbb ", w[0]);
    assert(w[1] == "ccc");

    // A single word wider than the budget is hard-broken, never dropped.
    auto hard = splitUtf8("aaaaaaaaaaaa", 5);
    assert(hard.length == 3 && hard[0] == "aaaaa" && hard[2] == "aa");

    // One code point wider than the whole budget still advances.
    auto tiny = splitUtf8("\U0001F600\U0001F600", 2);
    assert(tiny.length == 2 && tiny[0] == "\U0001F600");
}

@safe unittest {
    // splitMessage: newlines are logical breaks, byte splits are concats.
    bool[] flags;
    auto lines = splitMessage("hello\nworld", 400, flags);
    assert(lines == ["hello", "world"]);
    assert(flags == [false, false]);

    // Blank interior lines survive (multiline fidelity).
    auto blank = splitMessage("a\n\nb", 400, flags);
    assert(blank == ["a", "", "b"]);

    // A long logical line becomes concat continuations.
    auto longLine = splitMessage("aaa bbb ccc", 8, flags);
    assert(longLine == ["aaa bbb ", "ccc"]);
    assert(flags == [false, true], "second chunk must carry multiline-concat");

    // Injection attempt inside a logical line is stripped, not split.
    auto inj = splitMessage("safe\rQUIT :bye", 400, flags);
    assert(inj == ["safeQUIT :bye"]);
    assert(flags == [false]);
}
