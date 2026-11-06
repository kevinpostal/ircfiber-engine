/// Actual-user services transport regression runner.
///
/// Two layers, every check named and printed:
///  1. `ServicesTransport` behaviour against a scripted host with a
///     controllable clock: admission, pin revalidation, fences, `+reply`
///     correlation, deadlines, asynchronous authentication ambiguity,
///     lifecycle cancellation, dedup, the epoch-bound write queue, effects
///     and the history/privacy interception rules.
///  2. The real `PersistentIRCClient` over a localhost fake ircd that
///     answers like an Anope pseudoclient (`servicesTransportWireChecks`):
///     typed request → live socket → fenced private frame → result.
///
/// Run with: `dub run --config=services-test` (from engine/engine).
module services_test;

import std.algorithm : any, canFind, startsWith;
import std.conv : to;
import std.stdio : stderr, writeln;
import std.string : indexOf;
import std.uni : icmp;
import std.uuid : randomUUID;

import vibe.data.json : Json, parseJsonString;

import ircfiber.irc.parser : parseIRCLineNamed;
import ircfiber.irc.services;
import ircfiber.irc.connection : servicesTransportWireChecks;
import ircfiber.irc.services_grammar : servicesGrammarChecks;
import ircfiber.irc.services_operation : servicesOperationChecks;
import ircfiber.irc.services_channel : channelServicesChecks;
import ircfiber.irc.services_staff : staffServicesChecks;
import ircfiber.models.irc_event : IRCRawEvent;
import ircfiber.services.config : ServicesConfig, ServicePin, ServiceId, ServicesProvider, managedServicesConfig;
import ircfiber.services.privacy : sensitiveServiceLine;
import ircfiber.services.protocol : ServicesRequest, ServicesResult, ServiceAction, ServiceStatus;

int passed;
int failed;

void ok(string name, bool cond) {
    if (cond) {
        ++passed;
        stderr.writeln("  ✓ ", name);
    } else {
        ++failed;
        stderr.writeln("  ✗ ", name);
    }
}

enum NET = "22222222-2222-4222-8222-222222222222";
enum SVC = ":NickServ!services@services.test ";

/// Scripted connection: clock, epoch, actor and the write side.
final class FakeHost : ServicesHost {
    long now = 1_700_000_000_000;
    string epoch = "11111111-1111-4111-8111-111111111111";
    string nick = "me";
    ServicesActor who = ServicesActor(ServicesActorState.account, "acct");
    ServicesConfig cfg;
    string[] written;
    ServicesTransport t;
    bool paced;
    string adopted;
    int markers;

    long nowMs() { return now; }
    string liveEpoch() { return epoch; }
    string ownNick() { return nick; }
    bool isOwnNick(string n) { return icmp(n, nick) == 0; }
    bool sameNick(string a, string b) { return icmp(a, b) == 0; }
    ServicesActor actor() { return who; }
    ServicesConfig servicesConfig() { return cfg; }
    string isupport(string) { return ""; }
    size_t lineLimit() { return 512; }
    size_t ownPrefixBytes() { return 30; }
    bool manualLinePending(string) { return false; }
    void wake() { if (!paced) drain(); }
    void drain() {
        for (;;) {
            auto l = t.nextWrite();
            if (!l.length) break;
            t.popWrite();
            written ~= l;
        }
    }
    void markerChanged() { ++markers; }
    void adoptOwnAccount(string a) { adopted = a; who = ServicesActor(ServicesActorState.account, a); }
    bool ownChannelStatus(string, out string p) { p = "@"; return true; }
}

/// Scriptable adapter: runs `specs` frames in order, then `finish`.
final class ScriptOp : ServicesOperation {
    ServiceFrameSpec[] specs;
    ServiceFrame[] frames;
    void delegate(ServicesTransaction, ServiceFrame[]) finish;
    bool throwOnRun;
    bool supports(const ref ServicesEndpoint ep) { return true; }
    void run(ServicesTransaction txn) {
        if (throwOnRun) throw new Exception("adapter bug");
        frames = null;
        next(txn, 0);
    }
    private void next(ServicesTransaction txn, size_t i) {
        if (i >= specs.length) {
            if (finish !is null) finish(txn, frames);
            return;
        }
        txn.frame(specs[i], (ServiceFrame f) {
            frames ~= f;
            next(txn, i + 1);
        });
    }
}

/// Primary HostServ/BotServ operation that reads NickServ through `frameOn`.
final class PeerOp : ServicesOperation {
    ServiceFrame got;
    bool supports(const ref ServicesEndpoint ep) { return true; }
    void run(ServicesTransaction txn) {
        txn.frameOn(ServiceId.nickServ, ServiceFrameSpec(["INFO me"]), (ServiceFrame f) {
            got = f;
            const ok_ = f.outcome == ServiceFrameOutcome.completed && f.lines.length > 0;
            txn.complete(ok_ ? ServiceStatus.confirmed : ServiceStatus.unconfirmed, ok_ ? "" : f.reason);
        });
    }
}

struct Rig {
    FakeHost host;
    ServicesTransport t;
    ServicesResult[] results;

    static Rig make(bool trusted = true) {
        Rig r;
        r.host = new FakeHost;
        if (trusted) {
            r.host.cfg = managedServicesConfig("services.test");
        }
        r.t = new ServicesTransport(r.host);
        r.host.t = r.t;
        return r;
    }

    ServicesRequest request(ServiceAction action, string params, string actor = "acct") {
        auto j = parseJsonString(`{"params":` ~ params ~ `}`);
        j["requestId"] = randomUUID().toString();
        j["action"] = action.to!string;
        j["expectedConnectionEpoch"] = host.epoch;
        j["expectedActorAccount"] = actor;
        return ServicesRequest.fromJson(j);
    }

    void run(ServicesRequest req) {
        t.execute(req, (ServicesResult r) { results ~= r; });
    }

    bool feed(string line, bool historical = false) {
        auto ev = parseIRCLineNamed(line, "net", NET);
        return t.intercept(ev, historical);
    }

    /// Answers the pending pin WHOIS and VERSION like a healthy NickServ.
    void verify(string host_ = "services.test", string server = "services.test", string nick = "NickServ") {
        feed(":s 311 me " ~ nick ~ " services " ~ host_ ~ " * :Services");
        feed(":s 312 me " ~ nick ~ " " ~ server ~ " :Anope");
        feed(":s 318 me " ~ nick ~ " :End of /WHOIS list.");
        feed(":" ~ nick ~ "!services@" ~ host_ ~ " NOTICE me :\x01VERSION Anope-2.1.0 services.test\x01");
    }

    /// Token of the n-th fence written (0-based), "" if none.
    string fence(size_t n) {
        size_t seen;
        foreach (l; host.written) {
            const at = l.indexOf("\x01PING ");
            if (at < 0) continue;
            if (seen++ == n) return l[at + 6 .. $ - 1];
        }
        return "";
    }

    void fenceReply(size_t n, string from = SVC, string to_ = "me") {
        feed(from ~ "NOTICE " ~ to_ ~ " :\x01PING " ~ fence(n) ~ "\x01");
    }

    ServicesResult last() { return results.length ? results[$ - 1] : ServicesResult.init; }
}

void transportChecks() {
    stderr.writeln("\n[services.transport] admission, trust, frames, lifecycle, privacy");
    auto op = new ScriptOp;
    registerServicesOperation(ServiceAction.accountInfo, op);
    registerServicesOperation(ServiceAction.accountIdentify, op);
    scope (exit) clearServicesOperations();
    void confirmIfReplied() {
        op.finish = (ServicesTransaction txn, ServiceFrame[] fs) {
            const replied = fs.length && fs[$ - 1].lines.length > 0;
            txn.complete(replied ? ServiceStatus.confirmed : ServiceStatus.unconfirmed, replied ? "" : "no_reply");
        };
    }
    confirmIfReplied();
    op.specs = [ServiceFrameSpec(["INFO acct"])];

    // ── admission ────────────────────────────────────────────────────
    {
        auto r = Rig.make();
        auto q = r.request(ServiceAction.accountInfo, `{"account":"acct"}`);
        r.host.epoch = "";
        r.run(q);
        ok("no live epoch answers unavailable/offline",
            r.last.status == ServiceStatus.unavailable && r.last.reasonCode == "offline");
    }
    {
        auto r = Rig.make(false);
        r.run(r.request(ServiceAction.accountInfo, `{"account":"acct"}`));
        ok("an external network with no approved pins is untrusted_endpoint, nothing written",
            r.last.reasonCode == "untrusted_endpoint" && r.host.written.length == 0);
        r.run(r.request(ServiceAction.memoList, `{}`));
        ok("an action without a registered adapter is adapter_unavailable", r.last.reasonCode == "adapter_unavailable");
        auto d = r.request(ServiceAction.discover, `{}`);
        r.run(d);
        ok("discovery WHOISes the seven conventional nicks",
            r.host.written.length == 7 && r.host.written[0] == "WHOIS NickServ" && r.host.written[6] == "WHOIS Global");
        r.feed(":s 311 me NickServ svc svc.example * :Nickname Services");
        r.feed(":s 312 me NickServ svc.example :Anope");
        ok("discovery WHOIS numerics are intercepted", r.feed(":s 318 me NickServ :End of /WHOIS list."));
        foreach (n; ["ChanServ", "BotServ", "MemoServ", "HostServ", "OperServ", "Global"]) {
            r.feed(":s 401 me " ~ n ~ " :No such nick");
            r.feed(":s 318 me " ~ n ~ " :End of /WHOIS list.");
        }
        r.feed(":NickServ!svc@svc.example NOTICE me :\x01VERSION Anope-2.0.20 svc.example\x01");
        ok("discovery returns WHOIS candidates as unpinned on an untrusted network",
            r.last.requestId == d.requestId && r.last.status == ServiceStatus.confirmed
            && r.last.data["services"]["nickserv"]["pin"].get!string == "unpinned"
            && r.last.data["services"]["nickserv"]["host"].get!string == "svc.example"
            && r.last.data["services"]["nickserv"]["version"].get!string == "Anope-2.0.20 svc.example"
            && r.last.data["services"]["global"]["pin"].get!string == "absent");
    }
    {
        auto r = Rig.make();
        r.host.who = ServicesActor(ServicesActorState.unknown, "");
        r.run(r.request(ServiceAction.accountInfo, `{"account":"acct"}`, ""));
        ok("an unknown actor triggers a suppressed self-WHOIS", r.host.written == ["WHOIS me"]);
        r.feed(":s 311 me me ~m host * :Me");
        ok("the self-WHOIS 330 is intercepted", r.feed(":s 330 me me acct :is logged in as"));
        r.feed(":s 318 me me :End of /WHOIS list.");
        ok("a 330 account is adopted as the observed login", r.host.adopted == "acct");
        r.verify();
        ok("then the request proceeds to its own frame", r.fence(0).length > 0);
    }
    {
        auto r = Rig.make();
        r.host.who = ServicesActor(ServicesActorState.unknown, "");
        r.run(r.request(ServiceAction.accountInfo, `{"account":"acct"}`, ""));
        r.feed(":s 311 me me ~m host * :Me");
        r.feed(":s 318 me me :End of /WHOIS list.");
        ok("no 330 leaves the actor unknown; the review still proceeds for a public read",
            r.host.adopted == "" && r.host.who.state == ServicesActorState.unknown
            && r.host.written.canFind("WHOIS NickServ"));
    }
    {
        auto r = Rig.make();
        auto q = r.request(ServiceAction.accountInfo, `{"account":"acct"}`, "other");
        r.run(q);
        ok("a review for another account is stale/actor_changed", r.last.reasonCode == "actor_changed");
        auto e = r.request(ServiceAction.accountInfo, `{"account":"acct"}`);
        e.expectedConnectionEpoch = randomUUID().toString();
        r.run(e);
        ok("a review from another epoch is stale/epoch_stale",
            r.last.status == ServiceStatus.stale && r.last.reasonCode == "epoch_stale");
    }

    // ── pins ─────────────────────────────────────────────────────────
    {
        auto r = Rig.make();
        r.run(r.request(ServiceAction.accountInfo, `{"account":"acct"}`));
        r.verify("evil.example");
        ok("a WHOIS host differing from the pin is pin_mismatch, no command sent",
            r.last.reasonCode == "pin_mismatch" && !r.host.written.any!(l => l.canFind("INFO")));
        r.run(r.request(ServiceAction.accountInfo, `{"account":"acct"}`));
        ok("the mismatch blocks the service until review or reconnect", r.last.reasonCode == "pin_mismatch");
    }

    // ── a full frame with +reply correlation ─────────────────────────
    {
        auto r = Rig.make();
        // The adapter positively recognises one unsolicited notice.
        op.specs = [ServiceFrameSpec(["INFO acct"], ServiceFrameKind.ordinary, null,
            delegate (const ref ServiceReplyLine l) => l.plain.startsWith("You have a new memo"))];
        scope (exit) op.specs = [ServiceFrameSpec(["INFO acct"])];
        auto q = r.request(ServiceAction.accountInfo, `{"account":"acct"}`);
        r.run(q);
        r.verify();
        const start = r.fence(0);
        ok("the start fence goes to Nick@server with an ifsvc token",
            r.host.written[$ - 1] == "PRIVMSG NickServ@services.test :\x01PING " ~ start ~ "\x01");
        r.fenceReply(0, ":NickServ!evil@elsewhere ");
        r.fenceReply(0, SVC, "bob");
        ok("a fence reply from another prefix or to another recipient opens nothing",
            !r.host.written.canFind("PRIVMSG NickServ@services.test :INFO acct"));
        ok("the verified fence reply is intercepted", r.feed(SVC ~ "NOTICE me :\x01PING " ~ start ~ "\x01"));
        ok("then the command and the end fence leave, in order",
            r.host.written[$ - 2] == "PRIVMSG NickServ@services.test :INFO acct"
            && r.host.written[$ - 1].canFind("\x01PING " ~ r.fence(1)));
        ok("our own echo of the command is intercepted",
            r.feed("@msgid=m1 :me!~m@host PRIVMSG NickServ@services.test :INFO acct"));
        ok("a +reply to our msgid is claimed", r.feed("@+reply=m1;msgid=r1 " ~ SVC ~ "NOTICE me :acct is me"));
        ok("a +reply to another message is ordinary traffic",
            !r.feed("@+reply=zz;msgid=r2 " ~ SVC ~ "NOTICE me :about your manual command"));
        ok("an unknown untagged line from the verified service is quarantined by default",
            r.feed("@msgid=r4 " ~ SVC ~ "NOTICE me :Ihr Passwort hunter2 ist ungültig"));
        ok("only a line the adapter recognises as unrelated is released as ordinary traffic",
            !r.feed("@msgid=r3 " ~ SVC ~ "PRIVMSG me :You have a new memo from bob"));
        r.fenceReply(1);
        ok("the end fence completes the frame and the request",
            r.last.requestId == q.requestId && r.last.status == ServiceStatus.confirmed);
        ok("the frame keeps every verified line, marking which were private",
            op.frames.length == 1 && op.frames[0].replyCorrelated && op.frames[0].lines.length == 3
            && op.frames[0].lines[0].claimed && op.frames[0].lines[1].claimed && !op.frames[0].lines[2].claimed);
        ok("a CHATHISTORY replay of a claimed reply is suppressed",
            r.feed("@batch=h;msgid=r1 " ~ SVC ~ "NOTICE me :acct is me", true));
        ok("a fence replayed from history is swallowed",
            r.feed("@batch=h " ~ SVC ~ "NOTICE me :\x01PING " ~ start ~ "\x01", true));
        ok("older private service replies are never history, even ones this engine never saw",
            r.feed("@batch=h;msgid=old " ~ SVC ~ "NOTICE me :Your confirmation code is X1", true));
        ok("historical service lines in a channel stay ordinary history",
            !r.feed("@batch=h;msgid=old2 :ChanServ!services@services.test PRIVMSG #c :Channel registered", true));
        auto again = q;
        r.run(again);
        ok("a duplicate request id is not re-executed",
            r.last.reasonCode == "duplicate_request" && r.last.data.type == Json.Type.undefined
            && r.fence(2).length == 0);
        r.host.now += 5 * 60_000 + 1;
        r.run(again);
        ok("the dedup record expires after five minutes and the id executes again", r.fence(2).length > 0);
    }

    // ── 2.0 style: no msgids, fence window attribution ───────────────
    {
        auto r = Rig.make();
        r.run(r.request(ServiceAction.accountInfo, `{"account":"acct"}`));
        r.verify();
        r.fenceReply(0);
        ok("without msgid correlation the verified window line is claimed (NOTICE)",
            r.feed(SVC ~ "NOTICE me :acct is me"));
        ok("and PRIVMSG replies too", r.feed(SVC ~ "PRIVMSG me :Registered: today"));
        ok("another sender inside the window is never attributed",
            !r.feed(":Bob!b@h NOTICE me :hi"));
        ok("a TOPIC inside the window is recorded as an effect, not intercepted",
            !r.feed(":ChanServ!services@services.test TOPIC #c :new topic"));
        r.fenceReply(1);
        ok("effects and lines ride on the finished frame",
            op.frames[0].lines.length == 2 && op.frames[0].effects.length == 1
            && op.frames[0].effects[0].command == "TOPIC");
    }

    // ── silence, deadlines, downgrades ───────────────────────────────
    {
        auto r = Rig.make();
        r.run(r.request(ServiceAction.accountInfo, `{"account":"acct"}`));
        r.verify();
        r.fenceReply(0);
        r.fenceReply(1);
        ok("fences without a command reply are never success",
            r.last.status == ServiceStatus.unconfirmed && r.last.reasonCode == "no_reply");
    }
    {
        auto r = Rig.make();
        op.finish = (ServicesTransaction txn, ServiceFrame[] fs) { txn.complete(ServiceStatus.confirmed); };
        r.run(r.request(ServiceAction.accountInfo, `{"account":"acct"}`));
        r.verify();
        r.host.now += SERVICES_ORDINARY_DEADLINE_MS;
        r.t.tick();
        ok("a missing start fence ends in a deadline; an adapter's confirmed becomes unconfirmed",
            r.last.status == ServiceStatus.unconfirmed && r.last.reasonCode == "frame_incomplete"
            && op.frames.length == 1 && op.frames[0].outcome == ServiceFrameOutcome.deadline);
        auto saved = op.specs;
        op.specs = null;
        r.run(r.request(ServiceAction.accountInfo, `{"account":"acct"}`));
        ok("confirmed without any frame is downgraded", r.last.reasonCode == "frame_incomplete");
        op.specs = saved;
        op.throwOnRun = true;
        r.run(r.request(ServiceAction.accountInfo, `{"account":"acct"}`));
        ok("an adapter exception before dispatch is unavailable/adapter_error, never success",
            r.last.status == ServiceStatus.unavailable && r.last.reasonCode == "adapter_error");
        op.throwOnRun = false;
        confirmIfReplied();
    }

    // ── asynchronous authentication ─────────────────────────────────
    {
        auto r = Rig.make();
        r.host.who = ServicesActor(ServicesActorState.none, "");
        op.specs = [ServiceFrameSpec(["IDENTIFY acct hunter2"], ServiceFrameKind.asyncAuth,
            delegate (const ref ServiceFrame f) => f.accountChanges.length > 0)];
        op.finish = (ServicesTransaction txn, ServiceFrame[] fs) {
            const f = fs[$ - 1];
            txn.complete(f.outcome == ServiceFrameOutcome.completed ? ServiceStatus.confirmed
                : ServiceStatus.unconfirmed, f.reason);
        };
        auto q = r.request(ServiceAction.accountIdentify, `{"account":"acct","password":"hunter2"}`, "");
        r.run(q);
        r.verify();
        r.fenceReply(0);
        ok("the IDENTIFY echo is intercepted",
            r.feed(":me!~m@h PRIVMSG NickServ@services.test :IDENTIFY acct hunter2"));
        r.fenceReply(1);
        ok("after the end fence an authentication keeps waiting for the verdict", r.last.requestId != q.requestId);
        r.t.onOwnAccount(ServicesActor(ServicesActorState.account, "acct"));
        ok("a stated login completes it", r.last.requestId == q.requestId && r.last.status == ServiceStatus.confirmed);

        r.host.who = ServicesActor(ServicesActorState.account, "acct");
        auto q2 = r.request(ServiceAction.accountIdentify, `{"account":"acct","password":"hunter2"}`, "acct");
        r.run(q2);
        r.fenceReply(2);
        r.fenceReply(3);
        r.host.now += SERVICES_ASYNC_DEADLINE_MS;
        r.t.tick();
        ok("an authentication with no verdict in 30 s is unconfirmed",
            r.last.requestId == q2.requestId && r.last.status == ServiceStatus.unconfirmed
            && r.last.reasonCode == "async_deadline");
        r.run(r.request(ServiceAction.accountIdentify, `{"account":"acct","password":"x"}`, "acct"));
        ok("and blocks the next authentication on that service", r.last.reasonCode == "auth_pending_ambiguous");
        r.t.onOwnAccount(ServicesActor(ServicesActorState.account, "acct"));
        const answered = r.results.length;
        auto q3 = r.request(ServiceAction.accountIdentify, `{"account":"acct","password":"x"}`, "acct");
        r.run(q3);
        // Admitted: no immediate answer, and its own start fence is on the wire.
        ok("until the server states a login",
            r.results.length == answered && r.fence(4).length > 0
            && r.host.written[$ - 1].canFind("\x01PING " ~ r.fence(4)));
        r.t.onDisconnect();
        op.specs = [ServiceFrameSpec(["INFO acct"])];
        confirmIfReplied();
    }

    // ── lifecycle ────────────────────────────────────────────────────
    {
        auto r = Rig.make();
        auto q = r.request(ServiceAction.accountInfo, `{"account":"acct"}`);
        r.run(q);
        r.verify();
        r.t.onDisconnect();
        ok("a disconnect before the command left is stale",
            r.last.requestId == q.requestId && r.last.status == ServiceStatus.stale
            && r.last.reasonCode == "cancelled_disconnect");
        r.host.epoch = "33333333-3333-4333-8333-333333333333";
        auto q2 = r.request(ServiceAction.accountInfo, `{"account":"acct"}`);
        r.run(q2);
        r.verify();
        r.fenceReply(1);
        r.host.epoch = "44444444-4444-4444-8444-444444444444";
        r.t.tick();
        ok("an epoch change after the command left is unconfirmed, never confirmed",
            r.last.requestId == q2.requestId && r.last.status == ServiceStatus.unconfirmed);
        const writtenBefore = r.host.written.length;
        r.host.drain();
        ok("lines queued for the old epoch are never written", r.host.written.length == writtenBefore);
    }
    {
        auto r = Rig.make();
        auto q = r.request(ServiceAction.accountInfo, `{"account":"acct"}`);
        r.run(q);
        r.verify();
        r.fenceReply(0);
        r.t.onOwnAccount(ServicesActor(ServicesActorState.none, ""));
        ok("a logout cancels a non-authentication transaction",
            r.last.requestId == q.requestId && r.last.reasonCode == "actor_changed"
            && r.last.status == ServiceStatus.unconfirmed);
    }
    {
        auto r = Rig.make();
        auto q = r.request(ServiceAction.accountInfo, `{"account":"acct"}`);
        r.run(q);
        r.verify();
        r.fenceReply(0);
        ok("a line from the pinned nick with another user@host is not attributed",
            !r.feed(":NickServ!evil@elsewhere NOTICE me :acct is me"));
        ok("and stops the transaction for review",
            r.last.requestId == q.requestId && r.last.reasonCode == "pin_changed");
        r.run(r.request(ServiceAction.accountInfo, `{"account":"acct"}`));
        ok("further requests see pin_mismatch", r.last.reasonCode == "pin_mismatch");
    }
    {
        auto r = Rig.make();
        auto q = r.request(ServiceAction.accountInfo, `{"account":"acct"}`);
        r.run(q);
        r.verify();
        r.feed(SVC ~ "QUIT :Services shutting down");
        ok("a service QUIT cancels its transaction", r.last.requestId == q.requestId
            && r.last.reasonCode == "service_changed");
    }

    // ── secondary-service frames (frameOn) ───────────────────────────
    {
        auto peerOp = new PeerOp;
        registerServicesOperation(ServiceAction.hostInfo, peerOp);
        registerServicesOperation(ServiceAction.botInfo, peerOp);
        auto r = Rig.make();
        auto q = r.request(ServiceAction.hostInfo, `{}`);
        r.run(q);
        r.verify("services.test", "services.test", "HostServ");
        ok("a HostServ transaction resolves NickServ as its peer before any command",
            r.host.written[$ - 1] == "WHOIS NickServ");
        ok("the peer lock covers manual NickServ lines too",
            r.t.lockedServiceFor("PRIVMSG NickServ :INFO me") == "NickServ"
            && r.t.lockedServiceFor("PRIVMSG HostServ :ON") == "HostServ");
        r.verify();
        ok("the peer frame is fenced on the peer endpoint",
            r.host.written[$ - 1] == "PRIVMSG NickServ@services.test :\x01PING " ~ r.fence(0) ~ "\x01");
        r.fenceReply(0);
        ok("its reply is attributed to the peer frame", r.feed(SVC ~ "NOTICE me :vhost: me.example"));
        r.fenceReply(1);
        ok("and the transaction completes holding both locks until then",
            r.last.requestId == q.requestId && r.last.status == ServiceStatus.confirmed
            && peerOp.got.service == ServiceId.nickServ && peerOp.got.lines.length == 1);
        ok("both locks are released together",
            r.t.lockedServiceFor("PRIVMSG NickServ :x") == "" && r.t.lockedServiceFor("PRIVMSG HostServ :x") == "");

        r.run(r.request(ServiceAction.accountInfo, `{"account":"acct"}`));
        r.run(r.request(ServiceAction.hostInfo, `{}`));
        ok("a busy peer answers the frame unavailable at once, no queue or retry",
            r.last.reasonCode == "peer_busy" && peerOp.got.outcome == ServiceFrameOutcome.unavailable);
        r.t.onDisconnect();

        auto b = Rig.make();
        b.run(b.request(ServiceAction.botInfo, `{"channel":"#c"}`));
        b.verify("services.test", "services.test", "BotServ");
        ok("edges outside HostServ→NickServ / BotServ→ChanServ are refused",
            b.last.reasonCode == "peer_not_allowed");
    }

    // ── busy / locks / queue ─────────────────────────────────────────
    {
        auto r = Rig.make();
        auto q = r.request(ServiceAction.accountInfo, `{"account":"acct"}`);
        r.run(q);
        r.verify();
        r.run(r.request(ServiceAction.accountIdentify, `{"account":"acct","password":"x"}`));
        ok("a second request for the busy service is refused, not queued", r.last.reasonCode == "service_busy");
        ok("manual NickServ lines (msg, alias, Nick@server) see the lock",
            r.t.lockedServiceFor("PRIVMSG NickServ :INFO x") == "NickServ"
            && r.t.lockedServiceFor("NS INFO x") == "NickServ"
            && r.t.lockedServiceFor("@l=1 privmsg nickserv@services.test :x") == "NickServ"
            && r.t.lockedServiceFor("IDENTIFY pw") == "NickServ");
        ok("the managed ircd's ID alias and a smuggled second line see the NickServ lock",
            r.t.lockedServiceFor("ID canary") == "NickServ"
            && r.t.lockedServiceFor("JOIN #c\nPRIVMSG NickServ :IDENTIFY canary") == "NickServ"
            && r.t.lockedServiceFor("PRIVMSG NickServ :hi\nIDENTIFY canary") == "NickServ");
        ok("a formatted IDENTIFY echo to NickServ is swallowed, not attributed or stored",
            r.feed(":me!~m@h PRIVMSG NickServ :\x02IDENTIFY\x02 canary"));
        ok("other services and ordinary chat are not locked",
            r.t.lockedServiceFor("PRIVMSG ChanServ :INFO #c") == ""
            && r.t.lockedServiceFor("PRIVMSG #c :NickServ") == "");
        const m = r.t.marker();
        ok("the holder marker names the pseudoclient and a deadline only",
            m.prefixes == ["NickServ!services@services.test"] && m.untilMs > r.host.now);
        r.t.onDisconnect();
    }
    {
        auto r = Rig.make();
        r.host.paced = true;
        r.run(r.request(ServiceAction.accountInfo, `{"account":"acct"}`));
        ok("while the pacer holds, lines wait in the bounded service queue",
            r.t.queued == 1 && r.host.written.length == 0);
        r.host.paced = false;
        r.host.drain();
        ok("and are written once it admits them", r.host.written == ["WHOIS NickServ"]);
    }

    // ── late replies of a dead frame ─────────────────────────────────
    {
        auto r = Rig.make();
        r.run(r.request(ServiceAction.accountInfo, `{"account":"acct"}`));
        r.verify();
        r.fenceReply(0); // the command leaves
        r.host.now += SERVICES_ORDINARY_DEADLINE_MS;
        r.t.tick();
        ok("a frame that timed out after its command left is unconfirmed",
            r.last.status == ServiceStatus.unconfirmed);
        ok("its late reply (a memo body) is still private, never history",
            r.feed("@msgid=late1 " ~ SVC ~ "NOTICE me :memo body canary"));
        ok("the late reply's msgid is remembered for CHATHISTORY replays",
            r.feed("@batch=h;msgid=late1 " ~ SVC ~ "NOTICE me :memo body canary", true));
        ok("the holder marker covers the quarantined pseudoclient",
            r.t.marker().prefixes == ["NickServ!services@services.test"]);
        r.fenceReply(1); // the dead frame's end fence finally returns
        ok("its verified end fence ends the quarantine", !r.feed(SVC ~ "NOTICE me :You have a new memo"));
    }
    {
        auto r = Rig.make();
        r.run(r.request(ServiceAction.accountInfo, `{"account":"acct"}`));
        r.verify();
        r.fenceReply(0);
        r.t.onOwnAccount(ServicesActor(ServicesActorState.none, ""));
        ok("a transaction cancelled by an actor change after dispatch keeps late replies private",
            r.last.reasonCode == "actor_changed" && r.feed(SVC ~ "NOTICE me :memo body canary"));
        r.host.now += SERVICES_LATE_QUARANTINE_MS + 1;
        r.t.tick();
        ok("the quarantine is bounded", !r.feed(SVC ~ "NOTICE me :hello"));
    }
    {
        auto r = Rig.make();
        ok("a replayed private service reply to an old nick is never history",
            r.feed("@batch=h " ~ SVC ~ "NOTICE me_ :memo body canary", true));
        ok("a replayed sensitive command sent under an old nick is never history",
            r.feed("@batch=h :me_!~m@h PRIVMSG NickServ :IDENTIFY canary", true));
        ok("replayed non-sensitive service chat stays history",
            !r.feed("@batch=h :me_!~m@h PRIVMSG NickServ :HELP", true));
    }

    // ── issue-time bound ─────────────────────────────────────────────
    {
        auto r = Rig.make();
        auto q = r.request(ServiceAction.accountInfo, `{"account":"acct"}`);
        r.t.execute(q, (ServicesResult x) { r.results ~= x; }, r.host.now - SERVICES_TRANSACTION_CAP_MS);
        ok("a request already past its issue-time cap is stale/request_expired, nothing sent",
            r.last.reasonCode == "request_expired" && r.host.written.length == 0);
        auto q2 = r.request(ServiceAction.accountInfo, `{"account":"acct"}`);
        r.t.execute(q2, (ServicesResult x) { r.results ~= x; }, r.host.now - 20_000);
        r.verify();
        r.host.now += SERVICES_TRANSACTION_CAP_MS - 20_000;
        r.t.tick();
        ok("the transaction cap counts from issue, not admission",
            r.last.requestId == q2.requestId && r.last.status != ServiceStatus.confirmed);
    }

    // ── history and privacy ──────────────────────────────────────────
    {
        auto r = Rig.make();
        r.t.restoreQuiet(["NickServ!services@services.test"], r.host.now + 10_000);
        ok("after a takeover, backlog replies from the in-flight pseudoclient are suppressed",
            r.feed(SVC ~ "NOTICE me :Password accepted", true));
        ok("live private replies inside the marker window stay private too (late replies after a takeover)",
            r.feed(SVC ~ "NOTICE me :Password accepted"));
        ok("live channel lines are not affected by the marker",
            !r.feed(":NickServ!services@services.test PRIVMSG #c :hello"));
        r.host.now += 10_001;
        r.t.tick();
        ok("live channel service lines are untouched by the marker",
            !r.feed(":ChanServ!services@services.test PRIVMSG #c :hello"));
        ok("own sensitive echoes are swallowed live",
            r.feed(":me!~m@h PRIVMSG NickServ :IDENTIFY hunter2"));
        ok("and when replayed", r.feed("@batch=x :me!~m@h PRIVMSG NickServ :GHOST me pw", true));
        ok("own non-sensitive service chat stays visible", !r.feed(":me!~m@h PRIVMSG NickServ :HELP"));
        ok("chat to ordinary users is never touched", !r.feed(":me!~m@h PRIVMSG bob :IDENTIFY hunter2"));
    }
    ok("details strip formatting and redact the request's password",
        sanitizeServiceDetail("Unknown command \x02IDENTIFY acct hunter2\x02", ["hunter2"])
            == "Unknown command IDENTIFY acct [redacted]");
    {
        ServicesConfig cfg;
        ok("the shared classifier marks credentials and memo sends, not chat",
            sensitiveServiceLine("PRIVMSG NickServ :IDENTIFY pw", cfg)
            && sensitiveServiceLine("PRIVMSG MemoServ :SEND bob hi", cfg)
            && !sensitiveServiceLine("PRIVMSG bob :IDENTIFY pw", cfg));
    }
}

void mutationPreflightChecks() {
    stderr.writeln("\n[services.preflight] paced mutation reviews");
    enum body = "HOP #c ADD targetacct";
    enum params = `{"channel":"#c","account":"targetacct","targetNick":"target","provider":"xop","value":"HOP"}`;
    enum chanServ = ":ChanServ!services@services.test ";
    auto op = new ScriptOp;
    registerServicesOperation(ServiceAction.channelAccessSet, op);
    scope (exit) clearServicesOperations();
    auto spec = ServiceFrameSpec([body]);
    spec.mutating = true;
    op.specs = [spec];
    foreach (line; [":s MODE me :-o", ":target!u@h ACCOUNT another",
            ":target!u@h NICK replacement", ":s MODE #c -o me"]) {
        auto r = Rig.make();
        r.run(r.request(ServiceAction.channelAccessSet, params));
        r.verify("services.test", "services.test", "ChanServ");
        r.host.paced = true;
        r.fenceReply(0, chanServ);
        r.feed(line);
        r.host.paced = false;
        r.host.drain();
        ok("a queued mutation is stale after live authority/target change: " ~ line,
            r.last.status == ServiceStatus.stale && r.last.reasonCode == "capabilities_changed"
                && !r.host.written.any!(l => l.canFind(body)));
    }
    {
        auto r = Rig.make();
        r.run(r.request(ServiceAction.channelAccessSet, params));
        r.verify("services.test", "services.test", "ChanServ");
        r.host.paced = true;
        r.fenceReply(0, chanServ);
        r.feed("@batch=history :target!u@h ACCOUNT another", true);
        r.feed(":bob!u@h PRIVMSG #c :hello");
        r.feed(":s MODE #unrelated -o someone");
        r.feed(":other!u@h ACCOUNT another");
        r.host.paced = false;
        r.host.drain();
        ok("history, ordinary chat, unrelated targets and other channels do not stale a live review",
            r.host.written.any!(l => l.canFind(body)));
    }
    {
        bool allowed = true;
        spec.preflight = () => allowed;
        op.specs = [spec];
        auto r = Rig.make();
        r.run(r.request(ServiceAction.channelAccessSet, params));
        r.verify("services.test", "services.test", "ChanServ");
        r.host.paced = true;
        r.fenceReply(0, chanServ);
        const offered = r.t.nextWrite();
        allowed = false;
        r.host.paced = false;
        r.host.drain();
        ok("a final guard is rechecked after a pacer deferral, not cached on the first offer",
            offered.canFind(body) && r.last.status == ServiceStatus.stale
                && !r.host.written.any!(l => l.canFind(body)));
    }
}

void frameBoundsChecks() {
    import std.array : replicate;
    stderr.writeln("\n[services.bounds] complete native lists and private overflow");
    auto op = new ScriptOp;
    op.specs = [ServiceFrameSpec(["INFO acct"])];
    op.finish = (ServicesTransaction txn, ServiceFrame[] frames) {
        txn.complete(ServiceStatus.confirmed);
    };
    registerServicesOperation(ServiceAction.accountInfo, op);
    scope (exit) clearServicesOperations();
    {
        auto r = Rig.make();
        r.run(r.request(ServiceAction.accountInfo, `{"account":"acct"}`));
        r.verify();
        r.fenceReply(0);
        foreach (i; 0 .. 1000) r.feed(SVC ~ "NOTICE me :entry " ~ i.to!string);
        r.fenceReply(1);
        ok("a native default-size access list is retained without truncating",
            r.last.status == ServiceStatus.confirmed && op.frames.length == 1
                && !op.frames[0].truncated && op.frames[0].lines.length == 1000);
    }
    {
        auto r = Rig.make();
        r.run(r.request(ServiceAction.accountInfo, `{"account":"acct"}`));
        r.verify();
        r.fenceReply(0);
        const oversizedLine = SVC ~ "NOTICE me :" ~ "private".replicate(500);
        bool allPrivate = true;
        foreach (i; 0 .. 200) allPrivate = r.feed(oversizedLine) && allPrivate;
        r.fenceReply(1);
        ok("a byte-bounded frame cannot confirm, and overflow remains private",
            allPrivate && r.last.status == ServiceStatus.unconfirmed
                && r.last.reasonCode == "frame_incomplete" && op.frames[0].truncated);
    }
    {
        auto r = Rig.make();
        r.run(r.request(ServiceAction.accountInfo, `{"account":"acct"}`));
        r.verify();
        r.fenceReply(0);
        foreach (i; 0 .. SERVICES_FRAME_MAX_LINES + 1) r.feed(SVC ~ "NOTICE me :x");
        r.fenceReply(1);
        ok("many small replies also cannot turn a truncated frame into success",
            r.last.status == ServiceStatus.unconfirmed && op.frames[0].truncated);
    }
}

void credentialDetailsChecks() {
    import std.array : replicate;
    stderr.writeln("\n[services.credentials] wrapped secret echoes");
    enum first = "password-fragment-A";
    enum last = "password-fragment-Z";
    const password = first ~ "x".replicate(110) ~ last;
    auto op = new ScriptOp;
    op.specs = [ServiceFrameSpec(["IDENTIFY acct " ~ password])];
    op.finish = (ServicesTransaction txn, ServiceFrame[] frames) {
        txn.complete(ServiceStatus.unconfirmed, "unrecognized_reply", Json.undefined, "",
            Json.undefined, txn.details(frames[0].lines));
    };
    registerServicesOperation(ServiceAction.accountIdentify, op);
    scope (exit) clearServicesOperations();
    auto r = Rig.make();
    auto params = Json(["account": Json("acct"), "password": Json(password)]);
    r.run(r.request(ServiceAction.accountIdentify, params.toString()));
    r.verify();
    r.fenceReply(0);
    const a = r.feed(SVC ~ "NOTICE me :Unknown command IDENTIFY acct " ~ first ~ "x".replicate(100));
    const b = r.feed(SVC ~ "NOTICE me :" ~ "x".replicate(10) ~ last);
    r.fenceReply(1);
    const wire = r.last.toJson().toString();
    ok("separately wrapped password fragments reach neither history nor the private receipt",
        a && b && r.last.status == ServiceStatus.unconfirmed
            && !wire.canFind(first) && !wire.canFind(last));
}

void wireChecks() {
    stderr.writeln("\n[services.wire] PersistentIRCClient over a localhost fake Anope");
    string[] wire;
    foreach (c; servicesTransportWireChecks(wire)) ok(c.name, c.passed);
    stderr.writeln("  wire (", wire.length, " lines):");
    foreach (l; wire) {
        string shown;
        foreach (ch; l) shown ~= ch == '\x01' ? "\\x01" : [ch];
        stderr.writeln("    > ", shown);
    }
}

int main() {
    transportChecks();
    mutationPreflightChecks();
    frameBoundsChecks();
    servicesGrammarChecks((n, c) => ok(n, c));
    servicesOperationChecks((n, c) => ok(n, c));
    channelServicesChecks((n, c) => ok(n, c));
    staffServicesChecks((n, c) => ok(n, c));
    credentialDetailsChecks();
    wireChecks();
    stderr.writeln("\n", passed, " passed, ", failed, " failed");
    return failed ? 1 : 0;
}
