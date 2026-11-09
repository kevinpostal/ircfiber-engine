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
import ircfiber.irc.connection : servicesTransportWireChecks, servicesLegacyMetaChecks;
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
    string socketId = "fake-socket";
    string[string] caps;
    ServicesActor who = ServicesActor(ServicesActorState.account, "acct");
    ServicesConfig cfg;
    string[] written;
    ServicesTransport t;
    bool paced;
    string adopted;
    int markers;

    long nowMs() { return now; }
    string liveEpoch() { return epoch; }
    bool hasCapability(string name) { return (name in caps) !is null; }
    string capabilityValue(string name) { auto p = name in caps; return p is null ? "" : *p; }
    string socketIdentity() { return socketId; }
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
    void verify(string host_ = "services.test", string server = "services.test", string nick = "NickServ",
            string versionText = "Anope-2.1.0 services.test") {
        feed(":s 311 me " ~ nick ~ " services " ~ host_ ~ " * :Services");
        feed(":s 312 me " ~ nick ~ " " ~ server ~ " :Anope");
        feed(":s 318 me " ~ nick ~ " :End of /WHOIS list.");
        feed(":" ~ nick ~ "!services@" ~ host_ ~ " NOTICE me :\x01VERSION " ~ versionText ~ "\x01");
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
        auto marker = ServicesQuietMarker(["NickServ!services@services.test"], r.host.now + 10_000);
        r.t.restoreQuiet(marker);
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

void nativeIdentityChecks() {
    import ircfiber.irc.services_identity : registerIdentityServicesOperations;
    import ircfiber.irc.services_grammar : ANOPE_21_VERSION;
    stderr.writeln("\n[services.native.identity] self evidence versus public NickServ INFO");
    registerIdentityServicesOperations();
    scope (exit) {
        clearServicesOperations();
        setLegacyAuthTerminalClassifier(null);
    }
    Rig nativeRig(bool trusted = true) {
        auto r = Rig.make(trusted);
        r.host.caps["draft/account-registration"] = "min-password-length=4,max-password-length=32";
        return r;
    }
    void answerInfo(ref Rig r) {
        r.feed(SVC ~ "NOTICE me :Information about nick \x02other\x02:");
        r.feed(SVC ~ "NOTICE me :Account: other (ID: 8)");
        r.fenceReply(1);
    }
    {
        auto r = nativeRig();
        r.host.cfg.provider = ServicesProvider.disabled;
        r.run(r.request(ServiceAction.accountInfo, `{"account":"ACCT"}`));
        ok("own account view returns observed native identity even with NickServ disabled",
            r.last.status == ServiceStatus.confirmed
            && r.last.data["nick"].get!string == "me"
            && r.last.data["account"].get!string == "acct"
            && r.last.data["identified"].get!bool
            && r.last.capabilities["accountRegister"]["registration"]["protocol"].get!string == "native"
            && !r.host.written.length);
        r.host.who = ServicesActor(ServicesActorState.none, "");
        foreach (params; [`{"account":"ME"}`, `{"targetNick":"ME"}`]) {
            r.run(r.request(ServiceAction.accountInfo, params, ""));
            ok("unidentified self view exposes registration but never invents an account",
                r.last.status == ServiceStatus.confirmed
                && r.last.data["nick"].get!string == "me"
                && r.last.data["account"].get!string == ""
                && !r.last.data["identified"].get!bool
                && r.last.capabilities["accountRegister"]["registration"]["protocol"].get!string == "native"
                && !r.host.written.length);
        }
    }
    {
        auto r = nativeRig();
        r.host.cfg.provider = ServicesProvider.disabled;
        foreach (params; [`{"account":"other"}`, `{"targetNick":"other"}`,
                `{"account":"acct","targetNick":"other"}`, `{"account":"other","targetNick":"me"}`]) {
            r.run(r.request(ServiceAction.accountInfo, params));
            ok("foreign INFO cannot masquerade as self when legacy services are disabled",
                r.last.status == ServiceStatus.unavailable
                && r.last.reasonCode == "services_disabled"
                && r.last.data.type == Json.Type.undefined && !r.host.written.length);
        }
    }
    {
        auto r = nativeRig();
        r.run(r.request(ServiceAction.accountInfo, `{"account":"other"}`));
        ok("native capability does not bypass public INFO endpoint discovery",
            !r.results.length && r.host.written == ["WHOIS NickServ"]);
        r.verify("services.test", "services.test", "NickServ", ANOPE_21_VERSION ~ " services.test");
        r.fenceReply(0);
        ok("approved public INFO uses the real legacy adapter and requested account",
            !r.results.length && r.host.written.canFind("PRIVMSG NickServ@services.test :INFO other"));
        answerInfo(r);
        ok("public INFO returns the queried account rather than our native identity",
            r.last.status == ServiceStatus.confirmed
            && r.last.data["registered"].get!bool
            && r.last.data["nick"].get!string == "other"
            && r.last.data["account"].get!string == "other"
            && r.last.data["identified"].type == Json.Type.undefined
            && r.last.capabilities.type == Json.Type.undefined);
    }
    {
        auto r = nativeRig();
        r.run(r.request(ServiceAction.accountInfo, `{"targetNick":"guest"}`));
        r.verify("services.test", "services.test", "NickServ", ANOPE_21_VERSION ~ " services.test");
        ok("foreign nickname lookup still waits for fresh account evidence",
            !r.results.length && r.host.written.canFind("WHOIS guest")
            && !r.host.written.any!(line => line.canFind("INFO ")));
        r.feed(":s 311 me guest user host * :Guest");
        r.feed(":s 330 me guest other :is logged in as");
        r.feed(":s 318 me guest :End of /WHOIS list.");
        r.fenceReply(0);
        answerInfo(r);
        ok("foreign grouped nickname resolves and reports its actual public account",
            r.last.status == ServiceStatus.confirmed
            && r.last.data["targetNick"].get!string == "guest"
            && r.last.data["targetAccount"].get!string == "other"
            && r.last.data["account"].get!string == "other");
    }
    {
        auto r = nativeRig(false);
        r.run(r.request(ServiceAction.accountInfo, `{"account":"other"}`));
        ok("native registration never authorizes an untrusted public INFO endpoint",
            r.last.status == ServiceStatus.unavailable
            && r.last.reasonCode == "untrusted_endpoint" && !r.host.written.length);
    }
    {
        auto r = nativeRig();
        r.run(r.request(ServiceAction.accountInfo, `{"account":"other"}`));
        r.verify("evil.example");
        ok("public INFO still rejects a NickServ pin mismatch with native registration active",
            r.last.status == ServiceStatus.unavailable && r.last.reasonCode == "pin_mismatch"
            && !r.host.written.any!(line => line.canFind("INFO ")));
    }
    {
        auto r = nativeRig();
        r.run(r.request(ServiceAction.accountInfo, `{"account":"other"}`));
        r.feed(":s 311 me NickServ services services.test * :Services");
        r.feed(":s 312 me NickServ services.test :Anope");
        r.feed(":s 318 me NickServ :End of /WHOIS list.");
        r.feed(SVC ~ "NOTICE me :\x01VERSION Anope-9.0.0 services.test\x01");
        ok("native registration does not make an uncertified public INFO grammar usable",
            r.last.status == ServiceStatus.unavailable && r.last.reasonCode == "version_unsupported"
            && !r.host.written.any!(line => line.canFind("INFO ")));
    }
}

/// Candidate fingerprints must constrain real adapters, not just recognize a banner.
void fingerprintChecks() {
    import ircfiber.irc.services_identity : registerIdentityServicesOperations;
    import ircfiber.irc.services_channel : registerChannelServicesOperations;
    import ircfiber.irc.services_staff : registerStaffServicesOperations;
    import ircfiber.irc.services_operation : servicesRevisionFor;

    stderr.writeln("\n[services.fingerprint] real candidate adapters and command evidence");
    enum netcrave = "Anope-2.1.27-git (1947276) build #1, compiled Mon Sep 28 2026 08:19:33 UTC, flags DG -- InspIRCd 4+ -- enc_sha2";
    registerIdentityServicesOperations();
    registerChannelServicesOperations();
    registerStaffServicesOperations();
    scope (exit) {
        clearServicesOperations();
        setLegacyAuthTerminalClassifier(null);
    }

    // Consume the actual Rig wire in order, including each real fence. A script
    // supplies only service replies; it cannot bypass discovery or frame parsing.
    void answer(ref Rig r, ref size_t cursor, string[] delegate(string, string) reply,
            string peerVersion = netcrave, bool badNickServPin = false, string primaryVersion = netcrave) {
        size_t guard;
        while (cursor < r.host.written.length && guard++ < 500) {
            const line = r.host.written[cursor++];
            if (line.startsWith("WHOIS ")) {
                const nick = line[6 .. $];
                if (nick == "me") {
                    r.feed(":s 311 me me user real.example * :Me");
                    r.feed(":s 330 me me acct :is logged in as");
                    r.feed(":s 318 me me :End of /WHOIS list.");
                } else {
                    r.verify(badNickServPin && nick == "NickServ" ? "evil.example" : "services.test",
                        "services.test", nick, nick == "NickServ" ? peerVersion : primaryVersion);
                }
                continue;
            }
            if (!line.startsWith("PRIVMSG ")) continue;
            const at = line.indexOf(" :");
            if (at < 0) continue;
            const target = line[8 .. at];
            const serverAt = target.indexOf('@');
            const nick = serverAt < 0 ? target : target[0 .. serverAt];
            const body = line[at + 2 .. $];
            const prefix = ":" ~ nick ~ "!services@services.test NOTICE me :";
            if (body.startsWith("\x01PING ")) {
                r.feed(prefix ~ body);
            } else if (body != "\x01VERSION\x01") {
                foreach (text; reply(nick, body)) r.feed(prefix ~ text);
            }
        }
    }
    size_t countBody(ref Rig r, string body) {
        size_t n;
        foreach (line; r.host.written) {
            const at = line.indexOf(" :");
            if (at >= 0 && line[at + 2 .. $] == body) ++n;
        }
        return n;
    }
    bool requestable(Json caps, ServiceAction action) {
        if (caps.type != Json.Type.object) return false;
        auto cap = caps[action.to!string];
        if (cap.type != Json.Type.object) return false;
        const state = cap["state"].get!string;
        return state == "allowed" || state == "service_checked";
    }
    bool allProof = true;
    bool numericAdd = true;
    bool keepProof = true;
    bool founder = true;
    string[] channelReply(string service, string body) {
        if (body == "HELP ACCESS") {
            string[] rows = ["Syntax: ACCESS channel ADD mask level [description]"];
            if (!numericAdd) rows = ["This command requires the permission chanserv/access."];
            if (allProof) rows ~= "Syntax: ACCESS channel LIST [mask | list] [ALL]";
            return rows;
        }
        if (body == "HELP SET KEEPTOPIC")
            return keepProof ? ["Syntax: SET KEEPTOPIC channel {ON | OFF}"]
                : ["This command requires the permission chanserv/set."];
        if (body == "HELP TOPIC") return ["Syntax: TOPIC channel unexpected-argument"];
        if (body == "INFO #c")
            return ["Information about channel \x02#c\x02:", "Founder: " ~ (founder ? "acct" : "other"),
                "Description: Candidate fixture"];
        if (body == "STATUS #c") return ["Unknown command STATUS. Type /msg ChanServ HELP for help."];
        if (body == "LEVELS #c LIST") return ["Unknown command LEVELS. Type /msg ChanServ HELP for help."];
        if (body == "ACCESS #c LIST * ALL")
            return ["Access list for #c:", "Number  Level  Mask", "1       10     bob", "End of access list"];
        if (body == "FLAGS #c LIST") return ["Unknown command FLAGS. Type /msg ChanServ HELP for help."];
        if (body.startsWith("HELP "))
            return ["Unknown command " ~ body[5 .. $] ~ ". Type /msg ChanServ HELP for help."];
        return ["Unexpected command"];
    }
    {
        auto r = Rig.make();
        size_t cursor;
        r.run(r.request(ServiceAction.channelInfo, `{"channel":"#c"}`));
        answer(r, cursor, &channelReply);
        ok("Netcrave target-bound INFO survives absent optional STATUS/LEVELS/FLAGS",
            r.last.status == ServiceStatus.confirmed && r.last.data["registered"].get!bool
            && r.last.data["channel"].get!string == "#c" && r.last.data["founder"].get!string == "acct");
        ok("founder authority intersects syntax, leaving unrelated verified KEEPTOPIC enabled",
            requestable(r.last.capabilities, ServiceAction.channelKeepTopic)
            && !requestable(r.last.capabilities, ServiceAction.channelTopicSet)
            && !requestable(r.last.capabilities, ServiceAction.channelTopicLock));
        const revision = r.last.revision;
        auto mutation = r.request(ServiceAction.channelTopicLock, `{"channel":"#c","enabled":true}`);
        mutation.expectedRevision = revision;
        r.run(mutation);
        answer(r, cursor, &channelReply);
        ok("direct founder mutation with incompatible HELP never dispatches a write",
            r.last.status != ServiceStatus.confirmed && countBody(r, "TOPIC #c LOCK") == 0);
    }
    {
        auto r = Rig.make();
        size_t cursor;
        r.run(r.request(ServiceAction.channelAccessList, `{"channel":"#c"}`));
        answer(r, cursor, &channelReply);
        ok("optional missing modules preserve independently parsed numeric access",
            r.last.status == ServiceStatus.confirmed && r.last.data["entries"].length == 1
            && r.last.data["entries"][0]["provider"].get!string == "access"
            && r.last.data["entries"][0]["account"].get!string == "bob");
        ok("one cached ACCESS HELP proves ADD but not DEL or FLAGS",
            requestable(r.last.capabilities, ServiceAction.channelAccessSet)
            && !requestable(r.last.capabilities, ServiceAction.channelAccessRemove)
            && countBody(r, "HELP ACCESS") == 1);
        ok("shared provider editing requires removal proof as well as ADD",
            !requestable(Json(["channelAccessSet": r.last.data["providerCapabilities"]["access"]]),
                ServiceAction.channelAccessSet));
        const accessRevision = r.last.revision;
        auto removal = r.request(ServiceAction.channelAccessRemove,
            `{"channel":"#c","account":"bob","provider":"access","value":""}`);
        removal.expectedRevision = accessRevision;
        r.run(removal);
        answer(r, cursor, &channelReply);
        ok("compatible numeric ADD cannot authorize a direct ACCESS DEL mutation",
            r.last.status != ServiceStatus.confirmed && countBody(r, "ACCESS #c DEL bob") == 0);
        const before = countBody(r, "HELP ACCESS");
        r.run(r.request(ServiceAction.channelAccessList, `{"channel":"#c"}`));
        answer(r, cursor, &channelReply);
        ok("another transaction cannot reuse a completed transaction's HELP",
            r.last.status == ServiceStatus.confirmed && countBody(r, "HELP ACCESS") == before + 1);
    }
    {
        allProof = false;
        scope (exit) allProof = true;
        auto r = Rig.make();
        size_t cursor;
        r.run(r.request(ServiceAction.channelAccessList, `{"channel":"#c"}`));
        answer(r, cursor, &channelReply);
        ok("missing ALL syntax sends no provider-only substitute and never reports complete",
            countBody(r, "ACCESS #c LIST * ALL") == 0 && countBody(r, "ACCESS #c LIST") == 0
            && (r.last.data.type != Json.Type.object || !r.last.data["complete"].get!bool));
    }
    {
        keepProof = numericAdd = false;
        scope (exit) { keepProof = numericAdd = true; }
        auto r = Rig.make();
        size_t cursor;
        r.run(r.request(ServiceAction.channelInfo, `{"channel":"#c"}`));
        answer(r, cursor, &channelReply);
        ok("permission-only HELP cannot turn founder authority into any requestable channel mutation",
            r.last.status == ServiceStatus.confirmed
            && !requestable(r.last.capabilities, ServiceAction.channelKeepTopic)
            && !requestable(r.last.capabilities, ServiceAction.channelTopicSet)
            && !requestable(r.last.capabilities, ServiceAction.channelTopicLock)
            && !requestable(r.last.capabilities, ServiceAction.channelRegister));
        auto write = r.request(ServiceAction.channelKeepTopic, `{"channel":"#c","enabled":true}`);
        write.expectedRevision = r.last.revision;
        r.run(write);
        answer(r, cursor, &channelReply);
        ok("direct founder KEEPTOPIC with permission prose sends no mutation body",
            r.last.status != ServiceStatus.confirmed && countBody(r, "SET KEEPTOPIC #c ON") == 0);
    }
    {
        founder = false;
        scope (exit) founder = true;
        auto r = Rig.make();
        size_t cursor;
        r.run(r.request(ServiceAction.channelInfo, `{"channel":"#c"}`));
        answer(r, cursor, &channelReply);
        ok("compatible HELP cannot elevate an actor with unverified channel authority",
            r.last.status == ServiceStatus.confirmed
            && !requestable(r.last.capabilities, ServiceAction.channelKeepTopic));
    }
    foreach (recognized; [true, false]) {
        auto r = Rig.make();
        size_t cursor;
        string[] memoReply(string service, string body) {
            if (body == "HELP SEND") return ["Syntax: SEND {nick | channel} memo-text"];
            if (body == "SEND bob candidate-message")
                return [recognized ? "Memo sent to \x02bob\x02." : "Your memo was probably queued."];
            return ["Unknown command"];
        }
        r.run(r.request(ServiceAction.memoSend, `{"recipient":"bob","text":"candidate-message"}`));
        answer(r, cursor, &memoReply);
        ok(recognized ? "candidate memo mutation confirms its exact acknowledgement with one send"
                : "unknown candidate mutation acknowledgement stays unconfirmed with no retry",
            r.last.status == (recognized ? ServiceStatus.confirmed : ServiceStatus.unconfirmed)
            && countBody(r, "SEND bob candidate-message") == 1 && countBody(r, "HELP SEND") == 1);
    }
    {
        auto r = Rig.make();
        size_t cursor;
        bool compatibleRead;
        bool readSent;
        string[] memoReply(string service, string body) {
            if (body == "LIST")
                return ["Memos for acct:", "Number  Sender  Date/Time",
                    (readSent ? "  1" : "* 1") ~ "     bob     Nov 06 2026"];
            if (body == "HELP READ") return compatibleRead
                ? ["Syntax: READ [channel] {num | list | LAST | NEW | ALL}"]
                : ["This command requires the permission memoserv/read."];
            if (body == "HELP SEND") return ["Syntax: SEND {nick | channel} memo-text"];
            if (body == "HELP DEL") return ["Syntax: DEL [channel] {num | list | LAST | ALL}"];
            if (body == "READ 1") {
                readSent = true;
                return ["Memo 1 from bob (Nov 06 2026).", "candidate memo body"];
            }
            return ["Unknown command"];
        }
        r.run(r.request(ServiceAction.memoList, `{}`));
        answer(r, cursor, &memoReply);
        ok("memo discovery lists without reading and cannot infer READ syntax from permission prose",
            r.last.status == ServiceStatus.confirmed && countBody(r, "READ 1") == 0
            && !requestable(r.last.capabilities, ServiceAction.memoRead)
            && requestable(r.last.capabilities, ServiceAction.memoSend));
        const reviewedInbox = r.last.revision;
        auto read = r.request(ServiceAction.memoRead, `{"selection":"1"}`);
        read.expectedRevision = r.last.revision;
        r.run(read);
        answer(r, cursor, &memoReply);
        ok("explicit memo READ still needs its own strict mutation proof",
            r.last.status != ServiceStatus.confirmed && countBody(r, "READ 1") == 0
            && countBody(r, "HELP READ") == 2);
        compatibleRead = true;
        read = r.request(ServiceAction.memoRead, `{"selection":"1"}`);
        read.expectedRevision = reviewedInbox;
        r.run(read);
        answer(r, cursor, &memoReply);
        ok("explicit candidate READ makes one write and confirms only after the fresh LIST marks it read",
            r.last.status == ServiceStatus.confirmed && countBody(r, "READ 1") == 1
            && countBody(r, "LIST") == 3 && r.last.data["text"].get!string == "candidate memo body");
        ok("memo body remains private rather than appearing in generic result details",
            !r.last.details.canFind("candidate memo body"));
    }
    {
        auto r = Rig.make();
        size_t cursor;
        string[] statsReply(string service, string body) {
            if (body == "HELP STATS")
                return ["Syntax: STATS [AKILL | HASH | PASSWORD | UPLINK | UPTIME | ALL | RESET]"];
            if (body == "STATS") return ["Current users: \x0210\x02 (\x021\x02 ops)", "Services up 1 day."];
            if (body == "STATS AKILL") return ["Current number of AKILLs: \x020\x02"];
            return ["Unknown command"];
        }
        r.run(r.request(ServiceAction.operStats, `{}`));
        answer(r, cursor, &statsReply);
        ok("registered staff adapter consumes candidate literal STATS syntax and real statistics",
            r.last.status == ServiceStatus.confirmed && r.last.data["fields"].length >= 3
            && requestable(r.last.capabilities, ServiceAction.operStats));
    }
    foreach (peerVersion; ["Anope-2.1.28-git (differenthash)", "Anope-2.0.20", "Anope-9.0.0"]) {
        auto r = Rig.make();
        size_t cursor;
        string[] hostReply(string service, string body) {
            if (service == "NickServ" && body.startsWith("INFO "))
                return ["Information about nick \x02me\x02:", "Account: acct (ID: 8)", "VHost: cloak.example"];
            if (body == "HELP REQUEST") return ["Syntax: REQUEST vhost"];
            if (body == "HELP ON") return ["Syntax: ON"];
            if (body == "HELP OFF") return ["Syntax: OFF"];
            return ["Unknown command"];
        }
        r.run(r.request(ServiceAction.hostInfo, `{}`));
        answer(r, cursor, &hostReply, peerVersion);
        const sameProfile = peerVersion.startsWith("Anope-2.1.");
        ok("peer decoder baseline binding: " ~ peerVersion,
            sameProfile ? r.last.status == ServiceStatus.confirmed && countBody(r, "INFO me") == 1
                : r.last.status != ServiceStatus.confirmed && countBody(r, "INFO me") == 0);
    }
    {
        auto r = Rig.make();
        size_t cursor;
        r.run(r.request(ServiceAction.accountIdentify, `{"account":"acct","password":"candidate-secret"}`));
        // A mismatched pin must reject before even a sensitive HELP/write.
        answer(r, cursor, &channelReply, netcrave, true);
        ok("candidate syntax never bypasses an untrusted NickServ pin",
            r.last.reasonCode == "pin_mismatch"
            && !r.host.written.any!(l => l.canFind(" :IDENTIFY")));
    }
    {
        ServicesEndpoint ep;
        ep.service = ServiceId.chanServ;
        ep.nick = "ChanServ"; ep.ident = "services"; ep.host = ep.server = "services.test";
        ep.version_ = netcrave;
        auto basis = Json(["kind": Json("channel"), "channel": Json("#c")]);
        const revision = servicesRevisionFor(ep, ServicesActor(ServicesActorState.account, "acct"), NET, basis);
        ep.version_ = "Anope-2.1.28-git (differenthash)";
        ok("review revision binds the observed VERSION even within one candidate family",
            revision != servicesRevisionFor(ep, ServicesActor(ServicesActorState.account, "acct"), NET, basis));
    }
    {
        auto r = Rig.make();
        size_t cursor;
        r.run(r.request(ServiceAction.channelInfo, `{"channel":"#c"}`));
        answer(r, cursor, &channelReply);
        const reviewed = r.last.revision;
        r.t.onConfigChanged(); // Force a fresh endpoint VERSION, retaining channel state.
        auto write = r.request(ServiceAction.channelKeepTopic, `{"channel":"#c","enabled":true}`);
        write.expectedRevision = reviewed;
        r.run(write);
        answer(r, cursor, &channelReply, netcrave, false, "Anope-2.1.28-git (changedbuild)");
        ok("a changed observed VERSION rejects the stale review before any native write",
            r.last.status == ServiceStatus.stale && r.last.reasonCode == "revision_changed"
            && countBody(r, "SET KEEPTOPIC #c ON") == 0);
    }
}

void nativeChecks() {
    stderr.writeln("\n[services.native] protected unlabelled socket lane");
    Rig nativeRig() {
        auto r = Rig.make(false);
        r.host.who = ServicesActor(ServicesActorState.none, "");
        r.host.cfg.provider = ServicesProvider.disabled;
        r.host.caps["draft/account-registration"] = "min-password-length=4,max-password-length=32";
        return r;
    }
    bool verdict(ref Rig r, string line, bool historical = false, bool backlog = false) {
        auto event = parseIRCLineNamed(line, "net", NET);
        return r.t.interceptNative(event, historical, backlog);
    }
    {
        auto r = nativeRig();
        r.run(r.request(ServiceAction.accountInfo, `{"targetNick":"me"}`, ""));
        ok("native identity capabilities work with legacy services disabled",
            r.last.status == ServiceStatus.confirmed
            && r.last.capabilities["accountRegister"]["registration"]["protocol"].get!string == "native"
            && !r.host.written.length);
        r.run(r.request(ServiceAction.accountRegister, `{"password":"é pw"}`, ""));
        ok("native UTF8 password with spaces uses trailing parameter and no label",
            r.host.written == ["REGISTER * * :é pw"] && r.results.length == 1);
        ok("ACK is not a native verdict", !verdict(r, ":irc.test ACK") && r.results.length == 1);
        verdict(r, ":evil!user@host REGISTER SUCCESS me :forged");
        verdict(r, ":irc.test REGISTER SUCCESS other :wrong account");
        verdict(r, ":irc.test REGISTER SUCCESS me :archive", true);
        verdict(r, ":irc.test REGISTER SUCCESS me :backlog", false, true);
        ok("forged history backlog and other-account verdicts never settle",
            r.results.length == 1 && !r.host.adopted.length);
        verdict(r, ":irc.test REGISTER VERIFICATION_REQUIRED me :Use your private code");
        ok("verification instructions are private and are not identity evidence",
            r.results.length == 2 && r.last.status == ServiceStatus.confirmed
            && r.last.data["state"].get!string == "verification_required"
            && r.last.data["instructions"].get!string == "Use your private code"
            && !r.host.adopted.length);
        r.run(r.request(ServiceAction.accountConfirm, `{"code":"wrong code"}`, ""));
        verdict(r, ":irc.test FAIL VERIFY INVALID_CODE me :A safe refusal");
        ok("definitive VERIFY failure permits correction", r.last.status == ServiceStatus.rejected);
        r.run(r.request(ServiceAction.accountConfirm, `{"code":"right code"}`, ""));
        verdict(r, ":irc.test VERIFY SUCCESS me :Verified");
        ok("authentic native SUCCESS adopts only its requested account",
            r.last.status == ServiceStatus.confirmed && r.host.adopted == "me"
            && r.host.written[$ - 1] == "VERIFY * :right code");
    }
    {
        auto r = nativeRig();
        r.run(r.request(ServiceAction.accountRegister, `{"password":"valid pw"}`, ""));
        r.host.now += SERVICES_TRANSACTION_CAP_MS;
        r.t.tick();
        const marker = r.t.marker();
        ok("timeout retains only a nonsecret unresolved socket marker",
            r.last.status == ServiceStatus.unconfirmed && marker.native.unresolved
            && marker.native.account == "me" && marker.native.command == "REGISTER"
            && marker.native.mode == "unlabelled" && marker.native.socketId == r.host.socketId);
        r.run(r.request(ServiceAction.accountConfirm, `{"code":"next"}`, ""));
        ok("timeout never unlocks an indistinguishable successor",
            r.last.reasonCode == "native_auth_unresolved" && r.host.written.length == 1);
        verdict(r, ":irc.test REGISTER SUCCESS me :Late");
        ok("late terminal drain does not authenticate or deliver another result",
            !r.host.adopted.length && !r.t.marker().native.unresolved && r.results.length == 2);
        r.run(r.request(ServiceAction.accountConfirm, `{"code":"next"}`, ""));
        ok("authentic drain releases lane", r.host.written.length == 2);
        r.t.onRegistrationCapabilityChanged();
        ok("capability changes retire dispatched work without losing quarantine",
            r.last.status == ServiceStatus.unconfirmed && r.t.marker().native.unresolved);
        r.host.socketId = "replacement-socket";
        r.t.tick();
        ok("replacement socket discards unresolved old ownership", !r.t.marker().native.unresolved);
    }
    {
        auto r = nativeRig();
        r.host.paced = true;
        r.run(r.request(ServiceAction.accountRegister, `{"password":"valid pw"}`, ""));
        r.host.caps["draft/account-registration"] = "email-required";
        ok("native write revalidates capability options before dispatch",
            !r.t.nextWrite().length && r.last.status == ServiceStatus.stale
            && !r.host.written.length && !r.t.marker().native.unresolved);
        r.host.paced = false;
        r.run(r.request(ServiceAction.accountRegister, `{"password":"valid pw"}`, ""));
        ok("email-required is enforced before write", r.last.reasonCode == "email_required");
        r.host.caps["draft/account-registration"] = "min-password-length=6";
        r.run(r.request(ServiceAction.accountRegister, `{"password":"éé"}`, ""));
        ok("native minimum counts UTF8 bytes", r.last.reasonCode == "password_length");
        r.run(r.request(ServiceAction.accountRegister, `{"password":"abcdef","account":"other"}`, ""));
        ok("custom account requires advertised support", r.last.reasonCode == "custom_account_name_unsupported");
        ServicesQuietMarker marker;
        marker.native = NativeQuietMarker("", "", "", "invalid", true);
        r.t.restoreQuiet(marker);
        r.run(r.request(ServiceAction.accountConfirm, `{"code":"next"}`, ""));
        verdict(r, ":irc.test VERIFY SUCCESS me :Cannot drain malformed ownership");
        ok("malformed transferred marker fails closed until socket replacement",
            r.last.reasonCode == "native_auth_unresolved" && r.t.marker().native.unresolved);
    }
    {
        auto r = nativeRig();
        r.run(r.request(ServiceAction.accountRegister, `{"password":"valid pw"}`, ""));
        auto marker = r.t.marker();
        r.t.onDetach();
        auto adopted = nativeRig();
        adopted.t.restoreQuiet(marker);
        verdict(adopted, ":irc.test REGISTER VERIFICATION_REQUIRED me :Old private instructions", false, true);
        ok("holder terminal drains transferred ownership without delivering private instructions",
            !adopted.t.marker().native.unresolved && !adopted.results.length && !adopted.host.adopted.length);
        ok("tagged and prefixed native manual commands are sensitive",
            sensitiveServiceLine("@label=x :me!u@h REGISTER * * :canary pw", r.host.cfg)
            && sensitiveServiceLine("VERIFY * :canary code", r.host.cfg));
    }
    {
        auto r = nativeRig();
        ok("manual native raw uses the same protected unlabelled lane",
            r.t.submitManualNative("@label=client REGISTER * * :manual pw", r.host.epoch)
            && r.host.written == ["REGISTER * * :manual pw"] && !r.results.length);
        r.host.epoch = randomUUID().toString;
        r.t.onEpoch();
        r.run(r.request(ServiceAction.accountConfirm, `{"code":"next"}`, ""));
        ok("epoch replacement on retained socket never clears native uncertainty",
            r.last.reasonCode == "native_auth_unresolved" && r.host.written.length == 1);
        verdict(r, ":irc.test REGISTER SUCCESS me :Drain old manual work");
        ok("manual late drain cannot fabricate identity", !r.host.adopted.length);
    }
    {
        import std.array : replicate;
        auto r = nativeRig();
        r.host.caps.remove("draft/account-registration");
        r.run(r.request(ServiceAction.accountRegister, `{"password":"valid pw"}`, ""));
        ok("unACKed native capability uses the real legacy unsupported path",
            r.last.reasonCode == "services_disabled" && !r.host.written.length);
        r.host.caps["draft/account-registration"] = "";
        r.run(r.request(ServiceAction.accountRegister, Json(["password": Json("p".replicate(500))]).toString, ""));
        ok("actual IRC line budget is enforced without splitting native secrets",
            r.last.reasonCode == "line_too_long" && !r.host.written.length);
        r.host.caps["draft/account-registration"] = "before-connect,custom-account-name,email-required";
        r.run(r.request(ServiceAction.accountRegister,
            `{"password":"valid pw","account":"custom","email":"scratch@example.test"}`, ""));
        ok("advertised custom account and email survive native wire admission",
            r.host.written == ["REGISTER custom scratch@example.test :valid pw"]);
        verdict(r, ":irc.test REGISTER SUCCESS CUSTOM :Created");
        ok("server-returned account spelling is retained as identity evidence", r.host.adopted == "CUSTOM");
    }
    {
        auto r = nativeRig();
        r.host.paced = true;
        r.run(r.request(ServiceAction.accountRegister, `{"password":"valid pw"}`, ""));
        r.t.prepareNativeDetach();
        ok("graceful handoff never quarantines a native command that was not dispatched",
            r.last.status == ServiceStatus.stale && !r.t.marker().native.unresolved && !r.t.queued);
        r.run(r.request(ServiceAction.accountConfirm, `{"code":"next"}`, ""));
        r.t.failClosedMeta();
        ok("failed holder marker write drops unsent native secret and releases lane",
            r.last.reasonCode == "meta_unavailable" && !r.t.marker().native.unresolved && !r.t.queued);
    }
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
    nativeChecks();
    transportChecks();
    mutationPreflightChecks();
    frameBoundsChecks();
    nativeIdentityChecks();
    fingerprintChecks();
    foreach (c; servicesLegacyAuthChecks()) ok(c.name, c.passed);
    foreach (c; servicesLegacyMetaChecks()) ok(c.name, c.passed);
    servicesGrammarChecks((n, c) => ok(n, c));
    servicesOperationChecks((n, c) => ok(n, c));
    channelServicesChecks((n, c) => ok(n, c));
    staffServicesChecks((n, c) => ok(n, c));
    credentialDetailsChecks();
    wireChecks();
    stderr.writeln("\n", passed, " passed, ", failed, " failed");
    return failed ? 1 : 0;
}
