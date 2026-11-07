/**
 * Actual-user IRC services transport (Anope NickServ, ChanServ, BotServ,
 * MemoServ, HostServ, OperServ, Global).
 *
 * Every service operation runs over the network owner's own live IRC
 * connection, addressed to `ServiceNick@verified.services.server`, as that
 * user. There is no privileged RPC fallback here.
 *
 * What this module owns:
 *  - request admission: live epoch, observed actor, per-request dedup
 *    (bounded, five minutes, sanitized outcomes only), connection/service
 *    concurrency bounds;
 *  - endpoint trust: WHOIS (+ CTCP VERSION) discovery and per-epoch pin
 *    revalidation against `ServicesConfig`, casemapped through the host;
 *  - framing: random CTCP PING start/end fences from a verified pseudoclient
 *    to our own nick, `+reply`/echo-msgid correlation where the network has
 *    it, NOTICE and PRIVMSG replies, ordinary (15 s) and asynchronous
 *    authentication (30 s) deadlines, and the ambiguity block an unresolved
 *    authentication leaves behind;
 *  - one in-flight transaction per service (manual service traffic is
 *    refused while one runs, never interleaved);
 *  - a dedicated bounded write queue bound to the live epoch, which the
 *    connection drains through its real pacer and socket write — never
 *    through `outboundQueue`/`pacedQueue`, so nothing here is replayed or
 *    written into a holder snapshot;
 *  - inbound interception ahead of normal CTCP/history/persistence/bouncer
 *    fan-out: fences, correlated private replies, discovery WHOIS/VERSION,
 *    own echoes of frame commands and of sensitive service commands, and
 *    backlog replies a previous engine's transaction left in the holder.
 *
 * What it deliberately does not do: interpret service text. Success is
 * never inferred from quiet time, a fence, an IRC ACK or unknown text.
 * Operation adapters (`ServicesOperation`, registered per action) parse the
 * collected frame and decide; until one is registered for an action the
 * request is answered `unavailable`/`adapter_unavailable`. A `confirmed`
 * result from an adapter is downgraded to `unconfirmed` unless every frame
 * it ran completed between verified fences.
 */
module ircfiber.irc.services;

import std.algorithm : canFind, countUntil;
import std.conv : to;
import std.exception : enforce;
import std.uni : icmp;
import std.uuid : randomUUID;

import vibe.data.json : Json;

import ircfiber.models.irc_event : IRCRawEvent;
import ircfiber.services.config : ServiceId, ServicesConfig, ServicesProvider, ServicePin,
    SERVICE_COUNT, SERVICE_KEYS, SERVICE_DEFAULT_NICKS, isServiceTrusted, providerName;
import ircfiber.services.protocol : ServicesRequest, ServicesResult, ServiceAction, ServiceStatus,
    ServicesKeys, serviceFor, isAuthentication, permitsUnauthenticated, enforceServiceWireLimit;
import ircfiber.services.privacy : serviceTarget, sensitiveServiceMessage;

// ── Limits ─────────────────────────────────────────────────────────────────

/// Ordinary command: dispatch → verdict.
enum long SERVICES_ORDINARY_DEADLINE_MS = 15_000;
/// IDENTIFY/GROUP/RECOVER may finish after the end fence (SQL/LDAP auth).
enum long SERVICES_ASYNC_DEADLINE_MS = 30_000;
/// A whole transaction (revalidation + every frame) ends inside the
/// gateway's 35 s reply wait.
enum long SERVICES_TRANSACTION_CAP_MS = 32_000;
/// WHOIS probe (discovery, revalidation, adapter target resolution).
enum long SERVICES_WHOIS_DEADLINE_MS = 15_000;
/// CTCP VERSION wait after a WHOIS proved the pseudoclient present.
enum long SERVICES_VERSION_WAIT_MS = 5_000;
/// After 401 some servers never send 318; wait this long for it.
enum long SERVICES_WHOIS_ABSENT_GRACE_MS = 2_000;
/// Duplicate-request memory.
enum long SERVICES_DEDUP_MS = ServicesKeys.dedupTTLSeconds * 1000L;
enum size_t SERVICES_DEDUP_MAX = 512;
/// Dedicated write queue (fences, bodies, probes) for one connection.
enum size_t SERVICES_QUEUE_MAX = 64;
/// Command lines one frame may carry.
enum size_t SERVICES_FRAME_MAX_BODIES = 16;
/// Reply lines one frame records; later lines are still intercepted.
enum size_t SERVICES_FRAME_MAX_LINES = 4096;
/// Retained lines and observed effects share this byte budget, independently
/// of the server's advertised LINELEN. Supports native 1000-entry lists.
enum size_t SERVICES_FRAME_MAX_BYTES = 1024 * 1024;
/// Msgids of intercepted private replies, so a CHATHISTORY replay of the
/// same message is suppressed too.
enum size_t SERVICES_PRIVATE_MSGIDS_MAX = 512;
enum long SERVICES_PRIVATE_MSGID_MS = 5 * 60_000;
/// How long a dead frame's (timed out / cancelled after its command left)
/// late replies stay private when its end fence never comes back.
enum long SERVICES_LATE_QUARANTINE_MS = 60_000;
/// Fence tokens are `ifsvc` + 32 hex: alphanumeric, as 2.0's PING handler
/// (`NormalizeBuffer`) requires, and recognisably ours in any replay.
enum string SERVICES_FENCE_PREFIX = "ifsvc";
/// Legacy (manual, automatic, bouncer) NickServ authentication commands
/// remembered per socket while their verdict is outstanding. More than this
/// saturates the ledger: structured authentication then waits for a new
/// socket rather than guess which verdict belonged to which request.
enum size_t SERVICES_LEGACY_AUTH_MAX = 8;
/// Unresolved `+reply` lines one frame keeps while its own echo is pending.
enum size_t SERVICES_FRAME_MAX_UNRESOLVED = 64;

/// Pure classifier for UNTAGGED legacy-auth verdicts (Anope 2.0, no
/// echo-message, ircd aliases such as `ID <pass>`): given the NickServ
/// endpoint's CTCP VERSION text ("" unknown) and one formatting-stripped
/// NickServ→us line, true iff it is the terminal reply (acknowledgement or
/// any refusal) of IDENTIFY/GROUP/RECOVER/GHOST/RELEASE/REGISTER/CONFIRM in
/// any shipped locale. Supplied by the identity adapters; without it an
/// untagged legacy request stays pending until the socket is replaced.
alias LegacyAuthTerminal = bool function(string versionText, string plainLine);

private LegacyAuthTerminal gLegacyAuthTerminal;

/// Installs (or, with null, removes) the untagged legacy-auth classifier.
void setLegacyAuthTerminalClassifier(LegacyAuthTerminal fn) {
    gLegacyAuthTerminal = fn;
}

// ── Host contract ──────────────────────────────────────────────────────────

/// Own services login as the server stated it (mirrors the connection's
/// `ServicesAccountState`; this module does not import the connection).
enum ServicesActorState : ubyte { unknown, none, account }

/// Observed actor: state + account ("" unless `account`).
struct ServicesActor {
    ServicesActorState state;
    string account;
}

/// What the transport needs from its IRC connection.
interface ServicesHost {
    /// Unix ms.
    long nowMs();
    /// Live connection epoch; "" when no live, attached, registered socket.
    string liveEpoch();
    /// Current own nick.
    string ownNick();
    /// `nick` is us (current, optimistic previous, verified prefix).
    bool isOwnNick(string nick);
    /// Nick/account equality under the network's ISUPPORT CASEMAPPING.
    bool sameNick(string a, string b);
    /// Server-observed own login.
    ServicesActor actor();
    /// Effective (managed or stored) trust configuration.
    ServicesConfig servicesConfig();
    /// One ISUPPORT value ("" if absent).
    string isupport(string key);
    /// ISUPPORT LINELEN (512 default).
    size_t lineLimit();
    /// Bytes the server adds when relaying our line (`:nick!user@host `).
    size_t ownPrefixBytes();
    /// A manual line to `serviceNick` is still waiting in a normal queue.
    bool manualLinePending(string serviceNick);
    /// Lines were queued: drain the service queue now (paced).
    void wake();
    /// The non-secret holder marker changed (transaction start/end).
    void markerChanged();
    /// A suppressed WHOIS of our own current nick returned a 330 account:
    /// record it as the server-stated login (never configuration).
    void adoptOwnAccount(string account);
    /// Our live status prefixes on `channel` from the server-fed roster
    /// (`"@"`, `"~@"`, `""` = member without status). False when we are
    /// not a member as far as NAMES/JOIN told us.
    bool ownChannelStatus(string channel, out string prefixes);
}

// ── Frames ─────────────────────────────────────────────────────────────────

/// How long a frame may wait for its verdict.
enum ServiceFrameKind {
    /// Synchronous command: replies arrive before the end fence; 15 s.
    ordinary,
    /// IDENTIFY/GROUP/RECOVER: the verdict may follow the end fence; 30 s.
    /// A deadline after the command was written leaves the service's
    /// authentication ambiguous (see `ServicesTransport.onOwnAccount`).
    asyncAuth,
    /// No-ack commands (TOPIC SET, GLOBAL, HostServ ON): after the end
    /// fence keep observing effects until `terminal` holds; 15 s, no
    /// authentication ambiguity.
    observe
}

/// How a frame ended.
enum ServiceFrameOutcome {
    /// Start and end fences both observed from the verified pseudoclient
    /// (and, for `asyncAuth` with a terminal predicate, it was satisfied).
    completed,
    /// The deadline passed first. Nothing about the effect is known.
    deadline,
    /// The transport refused or lost the frame (queue full, invalid line).
    unavailable
}

/// Why a reply line belongs to a frame.
enum ServiceReplyAttribution {
    /// `+reply` names one of this frame's own command msgids.
    reply,
    /// Inside the fence window from the verified pseudoclient, untagged.
    window,
    /// After the end fence (asynchronous authentication only).
    late
}

/// One service line collected by a frame.
struct ServiceReplyLine {
    /// NOTICE or PRIVMSG.
    string command;
    /// Text exactly as received (formatting retained).
    string text;
    /// Text with IRC formatting removed, for parsing.
    string plain;
    string msgid;
    /// `+reply` / `+draft/reply` value, "" when absent.
    string replyTo;
    ServiceReplyAttribution attribution;
    /// The line was hidden from ordinary processing (history, bouncers).
    bool claimed;
    long atMs;
}

/// A finished frame, handed to the adapter.
struct ServiceFrame {
    ServiceId service;
    /// `Nick@server` the commands were addressed to.
    string target;
    ServiceFrameKind kind;
    ServiceFrameOutcome outcome;
    /// Machine reason for a non-completed outcome.
    string reason;
    bool startFenced;
    bool endFenced;
    /// Own command msgids were learned from echoes: `+reply` decides.
    bool replyCorrelated;
    /// A line-count or retained-byte bound was reached; never a full read.
    bool truncated;
    /// A `+reply`-tagged line named a message this frame could not prove
    /// was its own or someone else's (our echo still pending, or never
    /// coming): kept private and OUT of `lines`. Such a frame never
    /// confirms anything (`ServicesTransaction.complete` downgrades).
    bool ambiguous;
    ServiceReplyLine[] lines;
    /// Own-login changes the server stated while the frame was open.
    ServicesActor[] accountChanges;
    /// IRC effects observed while the frame was open (see `ServiceEffect`).
    ServiceEffect[] effects;
    long dispatchedAtMs;
    long closedAtMs;
}

/// A live IRC event seen while a frame was open: TOPIC, MODE, KICK, NICK,
/// CHGHOST, 332/333/396 numerics, and PRIVMSG/NOTICE from the transaction's
/// verified pseudoclient to a non-private target (`$*`, a channel). It is
/// evidence for an adapter to match exactly; it never implies the request
/// caused it.
struct ServiceEffect {
    string command;
    /// Full source prefix (`nick!user@host` or a server name).
    string prefix;
    string[] params;
    string msgid;
    long atMs;
}

/// Asynchronous frames: true once the collected evidence is terminal.
alias ServiceFrameTerminal = bool delegate(const ref ServiceFrame frame);
/// Privacy contract for adapters: every line from the verified pseudoclient
/// to us while a frame is open (fence window, or after the end fence for
/// lingering frames) is PRIVATE by default — quarantined from history,
/// notifications and bouncers and kept on the frame — because unknown or
/// translated text can echo a password or carry a memo body. `release`
/// may return true ONLY for a line the adapter positively recognises as an
/// unrelated unsolicited notice (memo arrival, ...), which then continues
/// as ordinary traffic. "Not my command's grammar" is never a reason to
/// release: unknown text stays private and the adapter answers
/// unconfirmed. A `+reply` naming our command is always private; one
/// naming another message (a manual command) is ordinary traffic.
/// Request secrets are redacted from details by `ServicesTransaction.details`;
/// generated secrets (confirmation codes, channel keys) must be omitted by
/// the adapter itself.
alias ServiceLineRelease = bool delegate(const ref ServiceReplyLine line);
/// Frame completion.
alias ServiceFrameDone = void delegate(ServiceFrame frame);

/// What an adapter asks the transport to send.
struct ServiceFrameSpec {
    /// Command bodies, each sent as `PRIVMSG Nick@server :<body>`. Never
    /// split; each must fit the line budget (`ServicesTransaction.fits`).
    string[] bodies;
    ServiceFrameKind kind;
    ServiceFrameTerminal terminal;
    ServiceLineRelease release;
    /// Only the command that changes state; read/HELP frames stay false.
    bool mutating;
    /// Pure final guard, evaluated again whenever the paced body is offered
    /// for writing. False/exception fails closed without sending the body.
    bool delegate() preflight;
}

/// A verified pseudoclient.
struct ServicesEndpoint {
    ServiceId service;
    string nick;
    string ident;
    string host;
    string server;
    /// CTCP VERSION text ("" when the pseudoclient did not answer).
    string version_;

    /// `Nick@server`: addresses the services server explicitly.
    string target() const @safe pure nothrow { return nick ~ "@" ~ server; }
}

/// A suppressed WHOIS answer.
struct ServicesWhois {
    /// 318 (or the 401 grace) arrived before the deadline.
    bool complete;
    /// 311 seen; false after 401.
    bool present;
    string nick;
    string ident;
    string host;
    string server;
    /// 330 account ("" when not logged in or not reported).
    string account;
    bool bot;
}

// ── Operation adapters (unit 3) ────────────────────────────────────────────

/// One action's versioned adapter: command builder, parser, read-back.
interface ServicesOperation {
    /// Whether this adapter's grammar covers the endpoint's version.
    bool supports(const ref ServicesEndpoint endpoint);
    /// Runs the operation. Must end with exactly one `txn.complete`.
    /// An exception completes the request as unavailable/unconfirmed.
    void run(ServicesTransaction txn);
}

private ServicesOperation[ServiceAction] gServicesOperations;

/// Registers the adapter for `action` (not `discover`, which is built in).
void registerServicesOperation(ServiceAction action, ServicesOperation op) {
    enforce(action != ServiceAction.discover, "discover is built into the transport");
    enforce(op !is null, "null services operation");
    gServicesOperations[action] = op;
}

/// Removes every registered adapter (tests).
void clearServicesOperations() {
    gServicesOperations = null;
}

// ── Transaction ────────────────────────────────────────────────────────────

/// One request holding one service's lock on one epoch.
final class ServicesTransaction {
    private ServicesTransport transport;
    private ServicesRequest req;
    private ServicesEndpoint ep;
    private ServicesActor startActor;
    private string epochValue;
    private long startedAt;
    private long capAt;
    private bool finished;
    private bool bodiesWritten;
    private bool frameIncomplete;
    private size_t framesCompleted;
    private ulong targetGeneration;
    private string[] secrets;
    private PendingFrame* frameState;
    private void delegate(ServicesResult) deliver;

    /// `capAt`: the request's absolute deadline, anchored at the gateway's
    /// issue time so a command can never reach services after the gateway
    /// stopped waiting.
    private this(ServicesTransport t, ServicesRequest r, ServiceId service, string epoch,
            ServicesActor actor, void delegate(ServicesResult) cb, long capAt_) {
        transport = t;
        req = r;
        ep.service = service;
        epochValue = epoch;
        startActor = actor;
        startedAt = t.host.nowMs();
        capAt = capAt_;
        deliver = cb;
        secrets = requestSecrets(r);
    }

    /// The validated request (includes `expectedRevision`).
    @property ref const(ServicesRequest) request() const { return req; }
    /// The verified pseudoclient for this epoch.
    @property ServicesEndpoint endpoint() const { return ep; }
    /// Connection epoch the transaction is bound to.
    @property string epoch() const { return epochValue; }
    /// Own login when the transaction started.
    @property ServicesActor actor() const { return startActor; }
    /// Still running on the live epoch.
    bool live() { return !finished && transport.host.liveEpoch() == epochValue; }
    /// A command body has reached the socket (an effect may exist).
    @property bool dispatched() const { return bodiesWritten; }
    /// ISUPPORT value (CHANMODES, PREFIX, CASEMAPPING ...).
    string isupport(string key) { return transport.host.isupport(key); }
    /// Live own authority plus this request's channel state, not unrelated
    /// channel traffic. Reviewed nick ownership is guarded separately.
    ulong capabilityGeneration() { return transport.generationFor(req); }
    /// Casemapped nick/account comparison.
    bool sameNick(string a, string b) { return transport.host.sameNick(a, b); }
    /// Current own nick (personal HostServ/GLIST read-backs).
    string ownNick() { return transport.host.ownNick(); }
    /// Live own status prefixes on `channel` (roster, not configuration).
    bool ownChannelStatus(string channel, out string prefixes) {
        return transport.host.ownChannelStatus(channel, prefixes);
    }

    /// Whether `body` fits one line to the primary endpoint (no splitting
    /// ever; never a CTCP, so it cannot pose as a fence).
    bool fits(string body) { return transport.fitsTo(ep, body); }

    /// Sends one fenced frame to the primary service. `done` runs exactly
    /// once unless the transaction is cancelled by the connection lifecycle
    /// first (then the request has already been answered and the adapter
    /// is not called back).
    void frame(ServiceFrameSpec spec, ServiceFrameDone done) {
        enforce(!finished, "services transaction already finished");
        enforce(frameState is null, "one frame at a time per transaction");
        transport.startFrame(this, ep, spec, done);
    }

    /// Sends one ordinary, non-sensitive (read) frame to a secondary
    /// service whose state the primary operation depends on. Allowed
    /// edges only (`peerAllowed`): HostServ → NickServ (own vhost via INFO),
    /// BotServ → ChanServ (STATUS/LEVELS/ACCESS policy) and ChanServ →
    /// BotServ (assigned bot INFO for TOPIC). Peer locks never wait, so two
    /// transactions cannot deadlock. The peer's lock is taken for the rest
    /// of the transaction (manual lines to it are refused too) and its pin
    /// is revalidated like the primary's. A busy, untrusted, absent or
    /// mismatched peer answers `done` at once with outcome `unavailable`
    /// and `reason` peer_busy / peer_not_allowed / untrusted_endpoint /
    /// service_absent / pin_mismatch / revalidation_timeout — no queueing,
    /// no retry.
    void frameOn(ServiceId peer, ServiceFrameSpec spec, ServiceFrameDone done) {
        enforce(!finished, "services transaction already finished");
        enforce(frameState is null, "one frame at a time per transaction");
        if (peer == ep.service) return frame(spec, done);
        transport.startPeerFrame(this, peer, spec, done);
    }

    /// Suppressed WHOIS for target resolution (nick → account).
    void whois(string nick, void delegate(ServicesWhois) done) {
        enforce(!finished, "services transaction already finished");
        transport.requestWhois(nick, capAt, (ServicesWhois w) {
            if (!finished) done(w);
        });
    }

    /// Bounded formatting/control-free details. Credential operations omit
    /// raw replies entirely: Anope may wrap an echoed password/code across
    /// lines, where whole-string redaction cannot remove every fragment.
    string[] details(const ServiceReplyLine[] lines) const {
        if (secrets.length) return null;
        string[] result;
        foreach (l; lines) {
            if (result.length >= 200) break;
            result ~= sanitizeServiceDetail(l.text, secrets);
        }
        return result;
    }

    /// Answers the request. The first call wins; later ones are ignored.
    /// `confirmed` requires every frame to have completed between
    /// verified fences; otherwise it is reported `unconfirmed`.
    void complete(ServiceStatus status, string reasonCode = "", Json data = Json.undefined,
            string revision = "", Json capabilities = Json.undefined, string[] details = null) {
        if (finished) return;
        if (status == ServiceStatus.confirmed && (frameIncomplete || framesCompleted == 0)) {
            status = ServiceStatus.unconfirmed;
            reasonCode = "frame_incomplete";
        }
        ServicesResult r;
        r.requestId = req.requestId;
        r.connectionEpoch = epochValue;
        r.action = req.action;
        r.status = status;
        r.data = data;
        r.capabilities = capabilities;
        r.revision = revision;
        r.reasonCode = reasonCode;
        r.details = details;
        transport.finishTransaction(this, r);
    }
}

// ── Transport ──────────────────────────────────────────────────────────────

private enum FramePhase { awaitStart, collecting, lingering }

private struct PendingFrame {
    ServicesTransaction txn;
    ServiceFrameSpec spec;
    ServiceFrameDone done;
    /// The verified pseudoclient this frame talks to (primary or peer).
    ServicesEndpoint ep;
    ServiceFrame frame;
    string startToken;
    string endToken;
    FramePhase phase;
    long deadlineMs;
    /// Bodies written but not yet echoed (echo-message correlation).
    string[] unechoed;
    string[] ownMsgids;
    /// A command body of this frame reached the socket.
    bool bodySent;
    /// `+reply` lines naming a msgid not (yet) known as ours or foreign,
    /// kept private and out of `frame.lines` until our echo decides.
    ServiceReplyLine[] unresolved;
    ulong capabilityGeneration;
    ulong targetGeneration;
    size_t retainedBytes;
}

/// One legacy NickServ authentication command awaiting its verdict.
private struct LegacyAuth {
    /// Sent as a PRIVMSG, so echo-message returns it with a msgid.
    bool expectEcho;
    bool echoed;
    /// Msgid of our echo ("" when untagged): 2.1 tags the verdict with it.
    string msgid;
    long sentAtMs;
}

/// Opaque copy of the legacy-auth ledger (`legacyAuthState`): no text, no
/// secret — only what is needed to put a tentative note back.
struct LegacyAuthLedger {
    private LegacyAuth[] entries;
    private bool saturated;

    /// Same count `legacyAuthPending` reports.
    size_t pending() const @safe pure nothrow @nogc {
        return saturated ? SERVICES_LEGACY_AUTH_MAX + 1 : entries.length;
    }
}

private struct LateQuarantine {
    ServicesEndpoint ep;
    /// The dead frame's end fence ("" when it already came back).
    string endToken;
    long untilMs;
}

private enum PinState : ubyte { unknown, verified, mismatch, absent, unpinned }

private struct ServiceSlot {
    PinState pin;
    ServicesEndpoint endpoint;
    bool authAmbiguous;
    ServicesTransaction txn;
    /// Late replies of a dead frame on this service stay private.
    LateQuarantine late;
}

private struct QueuedLine {
    string line;
    string epoch;
    long deadlineMs;
    /// Owning transaction ("" for probes).
    ServicesTransaction txn;
    bool isBody;
}

private struct WhoisProbe {
    string nick;
    long deadlineMs;
    ServicesWhois result;
    void delegate(ServicesWhois)[] waiters;
    /// A client asked for the same WHOIS: let its numerics through.
    bool shared_;
}

private struct VersionProbe {
    ServicesEndpoint endpoint;
    long deadlineMs;
    void delegate(string)[] waiters;
}

private struct DedupEntry {
    ServicesResult result;
    long expiresAt;
}

private final class DiscoveryRun {
    ServicesRequest req;
    void delegate(ServicesResult) deliver;
    string epoch;
    long deadlineMs;
    ServicesConfig cfg;
    ServicesWhois[SERVICE_COUNT] whois;
    string[SERVICE_COUNT] versions;
    bool[SERVICE_COUNT] whoisDone;
    bool[SERVICE_COUNT] versionDone;
    bool finished;
}

/// Non-secret holder marker: service prefixes an in-flight transaction is
/// talking to and until when their backlog lines belong to it.
struct ServicesQuietMarker {
    string[] prefixes;
    long untilMs;
}

/// Per-connection services transport.
final class ServicesTransport {
    private ServicesHost host;
    private string stateEpoch;
    private ServiceSlot[SERVICE_COUNT] slots;
    private DiscoveryRun discovery;
    private QueuedLine[] queue;
    private WhoisProbe[] whoisProbes;
    private VersionProbe[] versionProbes;
    private DedupEntry[string] dedup;
    private string[] dedupOrder;
    private long[string] privateMsgids;
    private string[] privateMsgidOrder;
    private ServicesQuietMarker quiet;
    /// Requests waiting for the self-WHOIS before admission.
    private string[] pendingAdmission;
    /// Legacy NickServ authentication commands on THIS socket whose verdict
    /// is still outstanding (no text, no secret: only how to recognise the
    /// verdict). Survives epoch changes on the same socket; ends with it.
    private LegacyAuth[] legacyAuth;
    /// More legacy auth commands than SERVICES_LEGACY_AUTH_MAX were sent.
    private bool legacyAuthSaturated;
    /// Msgids of our own non-frame lines to services (manual commands), so
    /// a `+reply` naming one is provably someone else's than a frame's.
    private bool[string] foreignMsgids;
    private string[] foreignMsgidOrder;
    private ulong generation = 1;
    private ulong[string] channelGenerations;
    private ulong invalidationSerial = 1;
    private string invalidatedChannel;
    private string invalidatedTarget;

    @property ulong capabilityGeneration() const @safe pure nothrow @nogc { return generation; }
    @property ulong invalidationGeneration() const @safe pure nothrow @nogc { return invalidationSerial; }
    @property string lastInvalidationChannel() const @safe pure nothrow @nogc { return invalidatedChannel; }
    @property string lastInvalidationTarget() const @safe pure nothrow @nogc { return invalidatedTarget; }

    private ulong generationFor(const ref ServicesRequest req) {
        // Keep authority and channel counters separate: evicting channel
        // state must never recreate an earlier review's generation by sum.
        ulong value = generation << 32;
        auto channel = req.params["channel"];
        if (channel.type == Json.Type.string)
            foreach (key, count; channelGenerations)
                if (host.sameNick(key, channel.get!string)) return value | count;
        return value;
    }

    private void noteInvalidation(string channel = "", string target = "") {
        ++invalidationSerial;
        invalidatedChannel = channel;
        invalidatedTarget = target;
    }

    private void invalidateChannel(string channel) {
        foreach (key, ref count; channelGenerations)
            if (host.sameNick(key, channel)) {
                if (count == uint.max) {
                    count = 0;
                    invalidateCapabilities();
                    return;
                }
                ++count;
                noteInvalidation(key);
                return;
            }
        if (channelGenerations.length >= 256) {
            // Bounded state; forget channel counters only behind a new
            // authority generation so no old review can become current.
            channelGenerations = null;
            invalidateCapabilities();
            return;
        }
        channelGenerations[channel] = 1;
        noteInvalidation(channel);
    }

    private void invalidateTarget(string nick) {
        foreach (ref slot; slots) {
            auto txn = slot.txn;
            if (txn is null) continue;
            auto target = txn.req.params["targetNick"];
            if (target.type == Json.Type.string && target.get!string.length
                    && host.sameNick(target.get!string, nick))
                ++txn.targetGeneration;
        }
        noteInvalidation("", nick);
    }

    private void invalidateCapabilities() {
        noteInvalidation();
        ++generation;
        if (!generation) ++generation;
    }

    this(ServicesHost host) {
        this.host = host;
    }

    // ── Request admission ─────────────────────────────────────────────

    /// Runs one validated request on the live connection. `complete` is
    /// called exactly once (possibly synchronously). `issuedMs` is the
    /// gateway's issue time (0 = now): every bound — the admission WHOIS,
    /// queued lines, the whole transaction — ends SERVICES_TRANSACTION_CAP_MS
    /// after it, inside the gateway's reply wait, and a request already past
    /// it is stale.
    void execute(ServicesRequest req, void delegate(ServicesResult) complete, long issuedMs = 0) {
        const now = host.nowMs();
        expire(now);
        const epoch = host.liveEpoch();
        const capAt = (issuedMs > 0 && issuedMs < now ? issuedMs : now) + SERVICES_TRANSACTION_CAP_MS;

        if (auto d = req.requestId in dedup) {
            auto r = d.result;
            r.reasonCode = "duplicate_request";
            deliverSafely(complete, r);
            return;
        }
        if (inFlight(req.requestId)) {
            ServicesResult r;
            r.requestId = req.requestId;
            r.connectionEpoch = epoch;
            r.action = req.action;
            r.status = ServiceStatus.unconfirmed;
            r.reasonCode = "duplicate_in_flight";
            deliverSafely(complete, r);
            return;
        }
        if (!epoch.length) return answerRequest(req, complete, epoch, ServiceStatus.unavailable, "offline");
        if (req.expectedConnectionEpoch != epoch)
            return answerRequest(req, complete, epoch, ServiceStatus.stale, "epoch_stale");
        syncEpoch(epoch);
        if (now >= capAt) return answerRequest(req, complete, epoch, ServiceStatus.stale, "request_expired");

        // No server statement about our login yet (no 900, no WHOX): ask
        // with a standard, suppressed WHOIS of our own nick. A non-empty
        // 330 is a statement of the account; its absence proves nothing
        // (not every server reports accounts), so the state stays unknown.
        if (host.actor().state == ServicesActorState.unknown) {
            pendingAdmission ~= req.requestId;
            requestWhois(host.ownNick(), capAt, (ServicesWhois w) {
                pendingAdmission = removeValue(pendingAdmission, req.requestId);
                if (host.liveEpoch() != epoch)
                    return answerRequest(req, complete, epoch, ServiceStatus.stale, "epoch_stale");
                if (host.nowMs() >= capAt)
                    return answerRequest(req, complete, epoch, ServiceStatus.stale, "request_expired");
                bool adopted;
                if (w.complete && w.present && w.account.length && host.sameNick(w.nick, host.ownNick())
                        && host.actor().state == ServicesActorState.unknown) {
                    host.adoptOwnAccount(w.account);
                    adopted = true;
                }
                admit(req, complete, epoch, capAt, adopted);
            });
            return;
        }
        admit(req, complete, epoch, capAt);
    }

    private void answerRequest(ServicesRequest req, void delegate(ServicesResult) complete, string epoch,
            ServiceStatus status, string reason) {
        ServicesResult r;
        r.requestId = req.requestId;
        r.connectionEpoch = epoch;
        r.action = req.action;
        r.status = status;
        r.reasonCode = reason;
        remember(r);
        deliverSafely(complete, r);
    }

    /// Actor, trust and concurrency admission on the live epoch.
    /// `adopted`: the login was only just learned from our own WHOIS, so a
    /// review made while it was unknown ("") still stands for actions that
    /// do not depend on an account.
    private void admit(ServicesRequest req, void delegate(ServicesResult) complete, string epoch,
            long capAt, bool adopted = false) {
        void answer(ServiceStatus status, string reason) {
            answerRequest(req, complete, epoch, status, reason);
        }
        const actor = host.actor();
        final switch (actor.state) {
            case ServicesActorState.unknown:
                if (req.expectedActorAccount.length || !permitsUnauthenticated(req.action))
                    return answer(ServiceStatus.stale, "actor_unknown");
                break;
            case ServicesActorState.none:
                if (req.expectedActorAccount.length) return answer(ServiceStatus.stale, "actor_changed");
                break;
            case ServicesActorState.account:
                if (!req.expectedActorAccount.length && adopted && permitsUnauthenticated(req.action))
                    break;
                if (!req.expectedActorAccount.length || !host.sameNick(req.expectedActorAccount, actor.account))
                    return answer(ServiceStatus.stale, "actor_changed");
                break;
        }

        const cfg = host.servicesConfig();
        if (cfg.provider == ServicesProvider.disabled) return answer(ServiceStatus.unavailable, "services_disabled");
        if (activeCount() >= ServicesKeys.maxActivePerConnection)
            return answer(ServiceStatus.unavailable, "connection_busy");

        if (req.action == ServiceAction.discover) {
            if (discovery !is null) return answer(ServiceStatus.unavailable, "service_busy");
            startDiscovery(req, complete, epoch, cfg, capAt);
            return;
        }

        auto op = req.action in gServicesOperations;
        if (op is null) return answer(ServiceStatus.unavailable, "adapter_unavailable");
        const service = serviceFor(req.action);
        auto slot = &slots[service];
        if (slot.txn !is null) return answer(ServiceStatus.unavailable, "service_busy");
        if (isAuthentication(req.action) && slot.authAmbiguous)
            return answer(ServiceStatus.unavailable, "auth_pending_ambiguous");
        // An earlier manual/automatic NickServ authentication on this socket
        // has no verdict yet: its asynchronous reply and 900 would land in
        // this frame.
        if (isAuthentication(req.action) && legacyAuthPending() > 0)
            return answer(ServiceStatus.unavailable, "legacy_auth_pending");
        if (!isServiceTrusted(cfg, service)) return answer(ServiceStatus.unavailable, "untrusted_endpoint");
        if (slot.pin == PinState.mismatch) return answer(ServiceStatus.unavailable, "pin_mismatch");
        if (slot.pin == PinState.absent) return answer(ServiceStatus.unavailable, "service_absent");
        if (host.manualLinePending(cfg.pins[service].nick)) return answer(ServiceStatus.unavailable, "service_busy");

        auto txn = new ServicesTransaction(this, req, service, epoch, actor, complete, capAt);
        slot.txn = txn;
        host.markerChanged();
        auto operation = *op;
        resolveEndpoint(txn, service, cfg, (bool ok, string reason, ServicesEndpoint endpoint) {
            if (txn.finished) return;
            if (!ok) return txn.complete(ServiceStatus.unavailable, reason);
            txn.ep = endpoint;
            if (!operation.supports(endpoint)) return txn.complete(ServiceStatus.unavailable, "version_unsupported");
            try operation.run(txn);
            catch (Exception) {
                txn.complete(txn.bodiesWritten ? ServiceStatus.unconfirmed : ServiceStatus.unavailable,
                    "adapter_error");
            }
        });
    }

    /// A manual (raw/alias/msg/bouncer/auto) line targets a service whose
    /// transaction is in flight: the caller must refuse it, not queue it.
    /// Returns the conventional nick of the busy service, or "".
    string lockedServiceFor(string line) {
        bool any;
        foreach (ref s; slots) if (s.txn !is null) { any = true; break; }
        if (!any) return "";
        const cfg = host.servicesConfig();
        foreach (id; lineServiceTargets(line, cfg))
            if (slots[id].txn !is null) return SERVICE_DEFAULT_NICKS[id];
        return "";
    }

    /// `lockedServiceFor` for a chat message: only its target list counts
    /// (a multi-line body is several messages to the same targets).
    string lockedServiceForTargets(string targets) {
        bool any;
        foreach (ref s; slots) if (s.txn !is null) { any = true; break; }
        if (!any) return "";
        const cfg = host.servicesConfig();
        ServiceId id;
        foreach (t; splitTargets(targets))
            if (serviceTarget(t, cfg, id) && slots[id].txn !is null) return SERVICE_DEFAULT_NICKS[id];
        return "";
    }

    /// A client sent its own WHOIS for these nicks: let the numerics of a
    /// matching engine probe through to it.
    void noteClientWhois(string nicks) {
        foreach (ref p; whoisProbes)
            foreach (n; splitTargets(nicks))
                if (host.sameNick(n, p.nick)) p.shared_ = true;
    }

    // ── Lifecycle ─────────────────────────────────────────────────────

    /// Socket gone or a new connection attempt: everything bound to the old
    /// transport ends. Dedup memory survives (request ids are global).
    void onDisconnect() {
        cancelAll("cancelled_disconnect");
        resetEpochState("");
        resetLegacyAuth();
    }

    /// Hot-swap detach: the next engine sees the marker in META.
    void onDetach() {
        cancelAll("cancelled_detach");
        resetEpochState("");
        resetLegacyAuth();
    }

    // ── Legacy (manual / automatic / bouncer) NickServ authentication ──
    //
    // A structured IDENTIFY/GROUP/RECOVER/REGISTER/CONFIRM must not start
    // while an earlier NickServ authentication command sent outside the
    // transport on this socket still awaits its verdict: an asynchronous
    // (SQL/LDAP) verdict for the old command — and its 900 — would land in
    // the new frame. Each Anope auth command ends with exactly one
    // CommandSource reply (sync refusal/ack, or IdentifyRequest
    // OnSuccess/OnFail), which 2.1 tags `+reply=<msgid of the command>`;
    // that tagged reply resolves the entry whose echo carried the msgid.
    // Untagged (2.0, no echo-message, ircd aliases) entries are resolved
    // only by a verdict the identity grammar recognises. A 900 alone
    // never resolves anything; nothing expires by quiet time; a new socket
    // clears the ledger.

    /// A raw line the connection is sending live (manual `/raw`, ircd alias,
    /// bouncer, automatic IDENTIFY/GHOST). Records each NickServ
    /// authentication command it carries, physical line by line.
    void noteManualLine(string line) {
        import std.string : indexOf, stripLeft;
        size_t start;
        foreach (i; 0 .. line.length + 1) {
            if (i < line.length && line[i] != '\r' && line[i] != '\n') continue;
            string seg = line[start .. i].stripLeft;
            start = i + 1;
            if (seg.length && seg[0] == '@') {
                const sp = seg.indexOf(' ');
                seg = sp < 0 ? "" : seg[sp + 1 .. $].stripLeft;
            }
            const sp1 = seg.indexOf(' ');
            const verb = sp1 < 0 ? seg : seg[0 .. sp1];
            string rest = sp1 < 0 ? "" : seg[sp1 + 1 .. $].stripLeft;
            const privmsg = icmp(verb, "PRIVMSG") == 0;
            if (privmsg || icmp(verb, "SQUERY") == 0) {
                const sp2 = rest.indexOf(' ');
                if (sp2 < 0 || !targetsNickServ(rest[0 .. sp2], host.servicesConfig())) continue;
                auto text = rest[sp2 + 1 .. $].stripLeft;
                if (text.length && text[0] == ':') text = text[1 .. $];
                // Only a PRIVMSG is echoed back with its msgid.
                if (isLegacyAuthCommand(text)) addLegacyAuth(privmsg);
            } else if (icmp(verb, "NS") == 0 || icmp(verb, "NICKSERV") == 0) {
                if (rest.length && rest[0] == ':') rest = rest[1 .. $];
                if (isLegacyAuthCommand(rest)) addLegacyAuth(false);
            } else if (icmp(verb, "IDENTIFY") == 0 || icmp(verb, "ID") == 0 || icmp(verb, "LOGIN") == 0) {
                addLegacyAuth(false);
            }
        }
    }

    /// A PRIVMSG chat message (body possibly multi-line: one message per
    /// line) being sent live to `targets`.
    void noteManualMessage(string targets, string text) {
        if (!targetsNickServ(targets, host.servicesConfig())) return;
        size_t start;
        foreach (i; 0 .. text.length + 1) {
            if (i < text.length && text[i] != '\r' && text[i] != '\n') continue;
            if (i > start && isLegacyAuthCommand(text[start .. i])) addLegacyAuth(true);
            start = i + 1;
        }
    }

    /// Outstanding legacy auth commands on this socket (a non-secret count
    /// for the holder META); saturation reports SERVICES_LEGACY_AUTH_MAX + 1.
    size_t legacyAuthPending() const {
        return legacyAuthSaturated ? SERVICES_LEGACY_AUTH_MAX + 1 : legacyAuth.length;
    }

    /// Attach to a held socket whose previous engine had `count` legacy
    /// auth commands outstanding: their msgids are unknown here, so only a
    /// recognised untagged verdict or a new socket resolves them.
    void restoreLegacyAuth(size_t count) {
        resetLegacyAuth();
        foreach (_; 0 .. count) addLegacyAuth(false);
    }

    /// What the holder META must carry so a next engine on this socket
    /// blocks structured authentication: the legacy ledger, plus a
    /// structured authentication in flight or left ambiguous (its verdict
    /// can still arrive on the retained socket).
    size_t handoffAuthPending() const {
        size_t n = legacyAuthPending();
        const ns = &slots[ServiceId.nickServ];
        if (ns.authAmbiguous) ++n;
        if (ns.txn !is null && isAuthentication(ns.txn.req.action)) ++n;
        return n;
    }

    /// Current ledger, to undo a tentative note when its META write fails.
    LegacyAuthLedger legacyAuthState() const {
        return LegacyAuthLedger(legacyAuth.dup, legacyAuthSaturated);
    }

    /// Puts back a ledger saved by `legacyAuthState`.
    void restoreLegacyAuthState(const LegacyAuthLedger saved) {
        legacyAuth = saved.entries.dup;
        legacyAuthSaturated = saved.saturated;
        host.markerChanged();
    }

    /// The holder META could not be written before a transaction's first
    /// line: every transaction that has not sent a command ends stale
    /// (`meta_unavailable`) and its queued lines are dropped. Transactions
    /// already dispatched had their marker published before their first
    /// line and continue.
    void failClosedMeta() {
        foreach (ref s; slots)
            if (s.txn !is null && !s.txn.bodiesWritten) cancelTransaction(s.txn, "meta_unavailable");
    }

    private void resetLegacyAuth() {
        legacyAuth = null;
        legacyAuthSaturated = false;
    }

    private void addLegacyAuth(bool expectEcho) {
        if (legacyAuth.length >= SERVICES_LEGACY_AUTH_MAX) {
            legacyAuthSaturated = true;
            return;
        }
        legacyAuth ~= LegacyAuth(expectEcho, false, "", host.nowMs());
        host.markerChanged(); // the count rides in the holder META
    }

    private bool targetsNickServ(string targets, const ServicesConfig cfg) {
        ServiceId id;
        foreach (t; splitTargets(targets))
            if (serviceTarget(t, cfg, id) && id == ServiceId.nickServ) return true;
        return false;
    }

    /// Our own echo of a non-frame line to NickServ: the oldest legacy auth
    /// command still waiting for its echo learns its msgid (echoes come back
    /// in send order).
    private void legacyAuthEchoed(string text, string msgid) {
        size_t start;
        foreach (i; 0 .. text.length + 1) {
            if (i < text.length && text[i] != '\r' && text[i] != '\n') continue;
            if (i > start && isLegacyAuthCommand(text[start .. i]))
                foreach (ref e; legacyAuth)
                    if (e.expectEcho && !e.echoed) {
                        e.echoed = true;
                        e.msgid = msgid;
                        break;
                    }
            start = i + 1;
        }
    }

    /// A live NickServ→us line (verified endpoint, or the conventional nick
    /// before verification). Observation only: never consumes the line.
    private void observeLegacyAuthReply(ref IRCRawEvent ev, string text, const ServicesEndpoint ep) {
        if (!legacyAuth.length) return;
        auto replyTo = ev.getTag("+reply");
        if (!replyTo.length) replyTo = ev.getTag("+draft/reply");
        if (replyTo.length) {
            foreach (i, ref e; legacyAuth)
                if (e.msgid.length && e.msgid == replyTo) {
                    legacyAuth = legacyAuth[0 .. i] ~ legacyAuth[i + 1 .. $];
                    host.markerChanged();
                    return;
                }
            // A further tagged line for a message we already know (a
            // multi-line verdict, a manual non-auth command, a frame of our
            // own): never a second verdict.
            if ((replyTo in foreignMsgids) !is null) return;
            foreach (ref s; slots)
                if (s.txn !is null && s.txn.frameState !is null && s.txn.frameState.ownMsgids.canFind(replyTo))
                    return;
        }
        // Untagged, or tagged for a message whose echo we never saw (ircd
        // alias): only a verdict the grammar recognises closes the oldest
        // entry that has no msgid.
        if (gLegacyAuthTerminal is null) return;
        bool terminal;
        try terminal = gLegacyAuthTerminal(ep.version_, stripIrcFormatting(text));
        catch (Exception) terminal = false;
        if (!terminal) return;
        foreach (i, ref e; legacyAuth)
            if (!e.msgid.length) {
                legacyAuth = legacyAuth[0 .. i] ~ legacyAuth[i + 1 .. $];
                host.markerChanged();
                return;
            }
    }

    private void rememberForeignMsgid(string msgid) {
        if (!msgid.length || (msgid in foreignMsgids) !is null) return;
        if (foreignMsgidOrder.length >= SERVICES_PRIVATE_MSGIDS_MAX) {
            foreignMsgids.remove(foreignMsgidOrder[0]);
            foreignMsgidOrder = foreignMsgidOrder[1 .. $];
        }
        foreignMsgids[msgid] = true;
        foreignMsgidOrder ~= msgid;
    }

    /// The live epoch changed (attach, re-registration).
    void onEpoch() { syncEpoch(host.liveEpoch()); }

    /// Trust configuration changed: pins are re-checked before next use.
    void onConfigChanged() {
        invalidateCapabilities();
        cancelAll("config_changed");
        foreach (ref s; slots) s.pin = PinState.unknown;
    }

    /// Authoritative own operator transition (MODE, 381 or 221).
    void onOwnAuthorityChanged() { invalidateCapabilities(); }

    /// The server stated our login (900/901/ACCOUNT/WHOX).
    void onOwnAccount(ServicesActor actor) {
        invalidateCapabilities();
        foreach (ref s; slots) s.authAmbiguous = false;
        foreach (ref s; slots) {
            auto txn = s.txn;
            if (txn is null) continue;
            if (isAuthentication(txn.req.action)) {
                if (auto f = txn.frameState) {
                    if (f.frame.accountChanges.length < SERVICES_FRAME_MAX_LINES
                            && retainFrameBytes(f, ServicesActor.sizeof + actor.account.length))
                        f.frame.accountChanges ~= actor;
                    else f.frame.truncated = true;
                    evaluateTerminal(f);
                }
            } else if (actor.state != txn.startActor.state
                    || !host.sameNick(actor.account, txn.startActor.account)) {
                cancelTransaction(txn, "actor_changed");
            }
        }
    }

    /// Restores the previous engine's marker on attach.
    void restoreQuiet(string[] prefixes, long untilMs) {
        if (untilMs <= host.nowMs() || prefixes.length == 0) return;
        quiet = ServicesQuietMarker(prefixes.dup, untilMs);
    }

    /// Marker for the holder META: prefixes of in-flight transactions.
    ServicesQuietMarker marker() {
        ServicesQuietMarker m;
        foreach (ref s; slots) {
            if (s.txn is null || !s.endpoint.ident.length) continue;
            const p = s.endpoint.nick ~ "!" ~ s.endpoint.ident ~ "@" ~ s.endpoint.host;
            if (!m.prefixes.canFind(p)) m.prefixes ~= p;
            // Late replies can trail the transaction's own cap.
            const until = host.nowMs() + SERVICES_LATE_QUARANTINE_MS;
            if (until > m.untilMs) m.untilMs = until;
        }
        foreach (ref s; slots) {
            if (s.late.untilMs <= host.nowMs() || !s.late.ep.ident.length) continue;
            const p = s.late.ep.nick ~ "!" ~ s.late.ep.ident ~ "@" ~ s.late.ep.host;
            if (!m.prefixes.canFind(p)) m.prefixes ~= p;
            if (s.late.untilMs > m.untilMs) m.untilMs = s.late.untilMs;
        }
        return m;
    }

    /// Deadlines; call from the connection loop.
    void tick() {
        const now = host.nowMs();
        expire(now);
        const epoch = host.liveEpoch();
        if (epoch != stateEpoch && (epoch.length || hasActiveWork())) syncEpoch(epoch);
        foreach (ref s; slots) {
            auto txn = s.txn;
            if (txn is null) continue;
            if (auto f = txn.frameState) {
                if (now >= f.deadlineMs) frameDeadline(f);
            }
            if (s.txn is txn && !txn.finished && now >= txn.capAt)
                cancelTransaction(txn, "deadline");
        }
        for (size_t i = 0; i < whoisProbes.length;) {
            if (now >= whoisProbes[i].deadlineMs) finishWhois(i);
            else ++i;
        }
        for (size_t i = 0; i < versionProbes.length;) {
            if (now >= versionProbes[i].deadlineMs) finishVersion(i, "");
            else ++i;
        }
        if (discovery !is null && !discovery.finished && now >= discovery.deadlineMs)
            finishDiscovery(ServiceStatus.unconfirmed, "deadline");
    }

    // ── Write queue (drained by the connection's pacer) ──────────────

    /// Next line to write on `epoch`, or "" (stale lines are dropped).
    string nextWrite() {
        const epoch = host.liveEpoch();
        const now = host.nowMs();
        while (queue.length) {
            if (!epoch.length || queue[0].epoch != epoch) {
                syncEpoch(epoch);
                queue = null;
                return "";
            }
            if (now >= queue[0].deadlineMs || (queue[0].txn !is null && queue[0].txn.finished)) {
                queue = queue[1 .. $];
                continue;
            }
            if (queue[0].isBody && queue[0].txn !is null) {
                auto txn = queue[0].txn;
                auto f = txn.frameState;
                if (f !is null && f.spec.mutating) {
                    const actor = host.actor();
                    bool valid = f.capabilityGeneration == txn.capabilityGeneration()
                        && f.targetGeneration == txn.targetGeneration
                        && actor.state == txn.startActor.state
                        && host.sameNick(actor.account, txn.startActor.account);
                    if (valid && f.spec.preflight !is null) {
                        try valid = f.spec.preflight();
                        catch (Exception) { valid = false; }
                    }
                    if (!valid) {
                        txn.complete(ServiceStatus.stale, "capabilities_changed");
                        continue;
                    }
                }
            }
            return queue[0].line;
        }
        return "";
    }

    /// The line `nextWrite` returned was written to the socket.
    void popWrite() {
        if (!queue.length) return;
        auto q = queue[0];
        queue = queue[1 .. $];
        if (q.isBody && q.txn !is null) {
            q.txn.bodiesWritten = true;
            if (auto f = q.txn.frameState) f.bodySent = true;
        }
    }

    /// Lines waiting for the pacer.
    @property size_t queued() const { return queue.length; }

    // ── Inbound interception ──────────────────────────────────────────

    /// Called before any normal processing. True = consumed: the line must
    /// not reach CTCP handling, buffers, history, persistence or bouncers.
    bool intercept(ref IRCRawEvent ev, bool historical) {
        const cmd = ev.command;
        if (!historical) recordEffect(ev);
        if (!historical) observeCapabilityEvent(ev);
        if (cmd.length == 3 && cmd[0] >= '0' && cmd[0] <= '9')
            return historical ? false : interceptNumeric(ev);
        if (cmd == "QUIT" || cmd == "NICK" || cmd == "CHGHOST") {
            if (!historical) observePresence(ev);
            return false;
        }
        if (cmd != "PRIVMSG" && cmd != "NOTICE") return false;
        const text = ev.text;
        // Fences are ours in any context: live, backlog or CHATHISTORY.
        string token;
        if (isFenceReply(text, token)) {
            if (!historical && !host.isOwnNick(ev.nick)) fenceObserved(ev, token);
            return true;
        }
        if (ev.nick.length == 0) return false;
        const cfg = host.servicesConfig();
        auto params = ev.getParams();
        const target = params.length ? params[0] : "";
        // A replayed direct message to a service can only be one of ours,
        // whatever nick we held then (GHOST reclaim, renames): judge the
        // command itself, not the sender.
        if (historical) {
            ServiceId to;
            if (serviceTarget(target, cfg, to) && sensitiveServiceMessage(target, text, cfg))
                return true;
        }
        if (host.isOwnNick(ev.nick)) return interceptOwnEcho(ev, target, text, cfg, historical);

        ServiceId id;
        if (!serviceTarget(ev.nick, cfg, id)) return false;
        if (historical) return historicalServiceLine(ev, target);
        if (text == "\x01VERSION\x01") return false;
        if (versionReply(ev, text)) return true;
        auto slot = &slots[id];
        // Legacy auth verdicts are observed (never consumed) before any
        // frame or quarantine handling sees the line: from the verified
        // NickServ, or by nick before this epoch verified it.
        if (id == ServiceId.nickServ && host.isOwnNick(target)
                && (slot.pin != PinState.verified || matchesEndpoint(ev, slot.endpoint)))
            observeLegacyAuthReply(ev, text, slot.endpoint);
        // Late private replies of a frame that timed out or was cancelled
        // after its command left, or of a previous engine's in-flight
        // transaction (holder marker): private until bounded expiry.
        if (host.isOwnNick(target) && (lateQuarantined(*slot, ev) || quietPrefix(ev))) {
            rememberPrivateMsgid(ev.getMsgid());
            return true;
        }
        if (slot.pin == PinState.verified && !matchesEndpoint(ev, slot.endpoint)) {
            if (host.sameNick(ev.nick, slot.endpoint.nick)) pinChanged(id);
            return false;
        }
        auto txn = slot.txn;
        if (txn is null || txn.frameState is null) return false;
        auto f = txn.frameState;
        if (f.ep.service != id || f.phase == FramePhase.awaitStart || !matchesEndpoint(ev, f.ep)) return false;
        if (!host.isOwnNick(target)) return false;
        return collect(f, ev);
    }

    private bool lateQuarantined(const ref ServiceSlot slot, ref IRCRawEvent ev) {
        return slot.late.untilMs > host.nowMs() && matchesEndpoint(ev, slot.late.ep);
    }

    private bool quietPrefix(ref IRCRawEvent ev) {
        if (quiet.untilMs <= host.nowMs()) return false;
        const full = ev.nick ~ "!" ~ ev.hostmask;
        foreach (p; quiet.prefixes)
            if (icmp(p, full) == 0) return true;
        return false;
    }

    /// Keeps a dead frame's late replies private: until its end fence comes
    /// back from the verified endpoint, a new frame on that service starts,
    /// or SERVICES_LATE_QUARANTINE_MS passes.
    private void quarantineLate(PendingFrame* f) {
        if (!f.bodySent) return;
        auto slot = &slots[f.ep.service];
        slot.late = LateQuarantine(f.ep, f.phase == FramePhase.lingering ? "" : f.endToken,
            host.nowMs() + SERVICES_LATE_QUARANTINE_MS);
        host.markerChanged();
    }

    /// IRC effects observed while a frame is open, for adapters whose
    /// service gives no acknowledgement (TOPIC SET, GLOBAL) or whose effect
    /// is the proof (HostServ ON, RECOVER). Observation only: the event
    /// continues through ordinary processing and nothing is concluded here.
    private void recordEffect(ref IRCRawEvent ev) {
        bool open;
        foreach (ref s; slots)
            if (s.txn !is null && s.txn.frameState !is null && s.txn.frameState.phase != FramePhase.awaitStart) {
                open = true;
                break;
            }
        if (!open) return;
        const cmd = ev.command;
        const isMessage = cmd == "PRIVMSG" || cmd == "NOTICE";
        if (!isMessage && !isEffectCommand(cmd)) return;
        ServiceEffect effect;
        effect.command = cmd;
        effect.prefix = ev.prefix;
        effect.params = ev.getParams();
        effect.msgid = ev.getMsgid();
        effect.atMs = host.nowMs();
        foreach (i, ref s; slots) {
            auto txn = s.txn;
            // A transaction holding a peer slot too is visited once.
            if (txn !is null && i != txn.ep.service) continue;
            if (txn is null || txn.frameState is null) continue;
            auto f = txn.frameState;
            if (f.phase == FramePhase.awaitStart) continue;
            // Messages count only from this transaction's pseudoclient to a
            // non-private target (a `$mask` or channel broadcast).
            if (isMessage && (!matchesEndpoint(ev, f.ep) || !effect.params.length
                    || host.isOwnNick(effect.params[0])))
                continue;
            size_t bytes = ServiceEffect.sizeof + effect.command.length
                + effect.prefix.length + effect.msgid.length;
            foreach (p; effect.params) bytes += p.length + string.sizeof;
            if (f.frame.effects.length < SERVICES_FRAME_MAX_LINES && retainFrameBytes(f, bytes))
                f.frame.effects ~= effect;
            else f.frame.truncated = true;
            evaluateTerminal(f);
        }
    }

    // ── Internals: admission and endpoint ────────────────────────────

    private void deliverSafely(void delegate(ServicesResult) cb, ServicesResult r) {
        try cb(r);
        catch (Exception) {}
    }

    private bool inFlight(string requestId) {
        foreach (ref s; slots) if (s.txn !is null && s.txn.req.requestId == requestId) return true;
        return pendingAdmission.canFind(requestId)
            || (discovery !is null && discovery.req.requestId == requestId);
    }

    private size_t activeCount() {
        size_t n = discovery !is null ? 1 : 0;
        foreach (ref s; slots) if (s.txn !is null) ++n;
        return n;
    }

    private bool hasActiveWork() {
        return activeCount() > 0 || queue.length > 0 || whoisProbes.length > 0 || versionProbes.length > 0;
    }

    private void syncEpoch(string epoch) {
        if (epoch == stateEpoch) return;
        cancelAll("epoch_changed");
        resetEpochState(epoch);
    }

    private void resetEpochState(string epoch) {
        invalidateCapabilities();
        stateEpoch = epoch;
        foreach (ref s; slots) {
            s.pin = PinState.unknown;
            s.endpoint = ServicesEndpoint.init;
            s.authAmbiguous = false;
            // A new socket carries no late replies of the old one.
            s.late = LateQuarantine.init;
        }
        queue = null;
        // Fail outstanding probes so every waiter (a request still being
        // admitted) is answered; finished transactions ignore the call.
        auto whois = whoisProbes;
        auto versions = versionProbes;
        whoisProbes = null;
        versionProbes = null;
        foreach (p; whois)
            foreach (w; p.waiters) {
                try w(ServicesWhois.init);
                catch (Exception) {}
            }
        foreach (p; versions)
            foreach (w; p.waiters) {
                try w("");
                catch (Exception) {}
            }
    }

    /// Resolves the verified endpoint of service `id` for `txn` on this
    /// epoch: WHOIS against the pin (+ VERSION) unless already verified.
    private void resolveEndpoint(ServicesTransaction txn, ServiceId id, const ServicesConfig cfg,
            void delegate(bool, string, ServicesEndpoint) then) {
        auto slot = &slots[id];
        if (!isServiceTrusted(cfg, id)) return then(false, "untrusted_endpoint", ServicesEndpoint.init);
        if (slot.pin == PinState.mismatch) return then(false, "pin_mismatch", ServicesEndpoint.init);
        if (slot.pin == PinState.absent) return then(false, "service_absent", ServicesEndpoint.init);
        if (slot.pin == PinState.verified) return then(true, "", slot.endpoint);
        const pin = cfg.pins[id];
        const server = cfg.server;
        const epoch = txn.epochValue;
        requestWhois(pin.nick, txn.capAt, (ServicesWhois w) {
            // Pin state is per epoch; a callback from an older one says nothing.
            if (host.liveEpoch() != epoch) return;
            if (!w.complete) {
                if (!txn.finished) then(false, "revalidation_timeout", ServicesEndpoint.init);
                return;
            }
            const state = evaluatePin(w, pin, server);
            // The verified endpoint is stored together with the verdict, so a
            // `verified` pin can never stand without its endpoint.
            slots[id].pin = state;
            slots[id].endpoint = state == PinState.verified
                ? ServicesEndpoint(id, w.nick, w.ident, w.host, w.server) : ServicesEndpoint.init;
            if (txn.finished) return;
            if (state == PinState.absent) return then(false, "service_absent", ServicesEndpoint.init);
            if (state != PinState.verified) return then(false, state == PinState.unpinned
                ? "untrusted_endpoint" : "pin_mismatch", ServicesEndpoint.init);
            const ep = slots[id].endpoint;
            requestVersion(ep, txn.capAt, (string version_) {
                // Cache the version only for the same epoch and the very
                // endpoint still verified — never re-trust after a reconnect
                // or a pin change — even when this request already ended.
                if (host.liveEpoch() != epoch) return;
                if (slots[id].pin == PinState.verified && sameEndpoint(slots[id].endpoint, ep))
                    slots[id].endpoint.version_ = version_;
                if (txn.finished) return;
                ServicesEndpoint resolved = ep;
                resolved.version_ = version_;
                then(true, "", resolved);
            });
        });
    }

    private bool sameEndpoint(const ServicesEndpoint a, const ServicesEndpoint b) {
        return a.service == b.service && host.sameNick(a.nick, b.nick) && icmp(a.ident, b.ident) == 0
            && icmp(a.host, b.host) == 0 && icmp(a.server, b.server) == 0;
    }

    /// Opens a frame on a secondary service for `txn` (see
    /// `ServicesTransaction.frameOn`): acquires that service's lock for the
    /// rest of the transaction, or answers the frame unavailable at once.
    private void startPeerFrame(ServicesTransaction txn, ServiceId peer, ServiceFrameSpec spec,
            ServiceFrameDone done) {
        void refuse(string reason) {
            ServiceFrame f;
            f.service = peer;
            f.kind = spec.kind;
            f.outcome = ServiceFrameOutcome.unavailable;
            f.reason = reason;
            f.dispatchedAtMs = f.closedAtMs = host.nowMs();
            txn.frameIncomplete = true;
            done(f);
        }
        if (!peerAllowed(txn.ep.service, peer)) return refuse("peer_not_allowed");
        if (spec.kind != ServiceFrameKind.ordinary) return refuse("peer_not_allowed");
        const cfg = host.servicesConfig();
        foreach (b; spec.bodies)
            if (sensitiveServiceMessage(SERVICE_DEFAULT_NICKS[peer], b, cfg))
                return refuse("peer_not_allowed");
        auto slot = &slots[peer];
        if (slot.txn !is null && slot.txn !is txn) return refuse("peer_busy");
        if (slot.txn is null && host.manualLinePending(cfg.pins[peer].nick)) return refuse("peer_busy");
        slot.txn = txn;
        host.markerChanged();
        resolveEndpoint(txn, peer, cfg, (bool ok, string reason, ServicesEndpoint ep) {
            if (txn.finished) return;
            if (!ok) return refuse(reason);
            startFrame(txn, ep, spec, done);
        });
    }

    private PinState evaluatePin(const ServicesWhois w, const ServicePin pin, string server) {
        if (!w.present) return PinState.absent;
        if (!server.length || !pin.isComplete) return PinState.unpinned;
        if (host.sameNick(w.nick, pin.nick) && icmp(w.ident, pin.ident) == 0
                && icmp(w.host, pin.host) == 0 && icmp(w.server, server) == 0)
            return PinState.verified;
        return PinState.mismatch;
    }

    /// Scope changes to the authority, channel or reviewed nick they affect.
    /// A busy unrelated channel must not invalidate a staff review.
    private void observeCapabilityEvent(ref IRCRawEvent ev) {
        auto params = ev.getParams();
        switch (ev.command) {
            case "MODE":
                if (params.length && host.isOwnNick(params[0])) invalidateCapabilities();
                else if (params.length && params[0].length && "#&+!".canFind(params[0][0]))
                    invalidateChannel(params[0]);
                break;
            case "ACCOUNT": case "NICK": case "QUIT": case "CHGHOST":
                if (host.isOwnNick(ev.nick)) invalidateCapabilities();
                else invalidateTarget(ev.nick);
                break;
            case "TOPIC":
                if (params.length && params[0].length) invalidateChannel(params[0]);
                break;
            case "PART": case "JOIN":
                if (host.isOwnNick(ev.nick) && params.length && params[0].length)
                    invalidateChannel(params[0]);
                break;
            case "KICK":
                if (params.length >= 2 && host.isOwnNick(params[1]))
                    invalidateChannel(params[0]);
                break;
            default: break;
        }
    }

    private bool matchesEndpoint(ref IRCRawEvent ev, const ServicesEndpoint ep) {
        if (!ep.ident.length || !host.sameNick(ev.nick, ep.nick)) return false;
        const at = ev.hostmask.countUntil('@');
        if (at < 0) return false;
        return icmp(ev.hostmask[0 .. at], ep.ident) == 0 && icmp(ev.hostmask[at + 1 .. $], ep.host) == 0;
    }

    /// A pinned pseudoclient spoke with another user@host, quit or was
    /// renamed: stop and require review / revalidation.
    private void pinChanged(ServiceId id) {
        invalidateCapabilities();
        slots[id].pin = PinState.mismatch;
        if (auto txn = slots[id].txn) cancelTransaction(txn, "pin_changed");
    }

    private void observePresence(ref IRCRawEvent ev) {
        const cfg = host.servicesConfig();
        ServiceId id;
        bool affected = serviceTarget(ev.nick, cfg, id);
        if (!affected && ev.command == "NICK") {
            auto p = ev.getParams();
            const newNick = p.length ? p[$ - 1] : ev.text;
            affected = serviceTarget(newNick, cfg, id);
        }
        if (!affected) return;
        invalidateCapabilities();
        slots[id].pin = PinState.unknown;
        slots[id].endpoint = ServicesEndpoint.init;
        if (auto txn = slots[id].txn) cancelTransaction(txn, "service_changed");
    }

    // ── Internals: frames ─────────────────────────────────────────────

    private void startFrame(ServicesTransaction txn, ServicesEndpoint ep, ServiceFrameSpec spec,
            ServiceFrameDone done) {
        auto f = new PendingFrame;
        f.txn = txn;
        f.ep = ep;
        f.spec = spec;
        f.done = done;
        f.capabilityGeneration = txn.capabilityGeneration();
        f.targetGeneration = txn.targetGeneration;
        f.frame.service = ep.service;
        f.frame.target = ep.target();
        f.frame.kind = spec.kind;
        f.frame.dispatchedAtMs = host.nowMs();
        f.startToken = fenceToken();
        f.endToken = fenceToken();
        f.deadlineMs = f.frame.dispatchedAtMs + (spec.kind == ServiceFrameKind.asyncAuth
            ? SERVICES_ASYNC_DEADLINE_MS : SERVICES_ORDINARY_DEADLINE_MS);
        if (f.deadlineMs > txn.capAt) f.deadlineMs = txn.capAt;
        txn.frameState = f;
        string reason;
        if (!spec.bodies.length || spec.bodies.length > SERVICES_FRAME_MAX_BODIES) reason = "invalid_command";
        if (spec.mutating && spec.bodies.length != 1) reason = "invalid_command";
        foreach (b; spec.bodies) if (!fitsTo(ep, b)) reason = "invalid_command";
        if (!reason.length && !enqueue(fenceLine(ep, f.startToken), txn, false, f.deadlineMs))
            reason = "queue_full";
        if (reason.length) {
            closeFrame(f, ServiceFrameOutcome.unavailable, reason);
            return;
        }
        host.wake();
    }

    private string fenceLine(const ServicesEndpoint ep, string token) {
        return "PRIVMSG " ~ ep.target() ~ " :\x01PING " ~ token ~ "\x01";
    }

    /// One command body fits one line to `ep` (never split, never a CTCP).
    package bool fitsTo(const ServicesEndpoint ep, string body) {
        if (!body.length || body[0] == '\x01') return false;
        try {
            enforceServiceWireLimit(ep.target(), body, host.lineLimit(), host.ownPrefixBytes());
            return true;
        } catch (Exception) {
            return false;
        }
    }

    private bool enqueue(string line, ServicesTransaction txn, bool isBody, long deadline) {
        if (queue.length >= SERVICES_QUEUE_MAX) return false;
        queue ~= QueuedLine(line, stateEpoch, deadline, txn, isBody);
        return true;
    }

    private void fenceObserved(ref IRCRawEvent ev, string token) {
        // A dead frame's end fence from its verified endpoint: nothing more
        // of that frame follows, its quarantine ends.
        foreach (ref s; slots)
            if (s.late.endToken.length && token == s.late.endToken && matchesEndpoint(ev, s.late.ep)) {
                s.late = LateQuarantine.init;
                return;
            }
        foreach (ref s; slots) {
            auto txn = s.txn;
            if (txn is null || txn.frameState is null) continue;
            auto f = txn.frameState;
            const isStart = token == f.startToken && f.phase == FramePhase.awaitStart;
            const isEnd = token == f.endToken && f.phase == FramePhase.collecting;
            if (!isStart && !isEnd) continue;
            // Only the verified pseudoclient, to us, closes a fence.
            auto p = ev.getParams();
            if (!matchesEndpoint(ev, f.ep) || !p.length || !host.isOwnNick(p[0])) return;
            if (isStart) {
                // Services answer in order: everything of an older frame on
                // this service came before this fence.
                slots[f.ep.service].late = LateQuarantine.init;
                f.frame.startFenced = true;
                f.phase = FramePhase.collecting;
                foreach (b; f.spec.bodies) {
                    if (!enqueue("PRIVMSG " ~ f.frame.target ~ " :" ~ b, txn, true, f.deadlineMs)) {
                        closeFrame(f, ServiceFrameOutcome.unavailable, "queue_full");
                        return;
                    }
                    f.unechoed ~= b;
                }
                if (!enqueue(fenceLine(f.ep, f.endToken), txn, false, f.deadlineMs)) {
                    closeFrame(f, ServiceFrameOutcome.unavailable, "queue_full");
                    return;
                }
                host.wake();
            } else {
                f.frame.endFenced = true;
                if (f.spec.kind != ServiceFrameKind.ordinary && f.spec.terminal !is null) {
                    f.phase = FramePhase.lingering;
                    evaluateTerminal(f);
                } else {
                    closeFrame(f, ServiceFrameOutcome.completed, "");
                }
            }
            return;
        }
    }

    /// Account retained data without trusting the server's line length.
    private bool retainFrameBytes(PendingFrame* f, size_t bytes) {
        if (bytes > SERVICES_FRAME_MAX_BYTES - f.retainedBytes) {
            f.frame.truncated = true;
            return false;
        }
        f.retainedBytes += bytes;
        return true;
    }

    /// One reply from the verified endpoint to us while a frame is open.
    private bool collect(PendingFrame* f, ref IRCRawEvent ev) {
        ServiceReplyLine line;
        line.command = ev.command;
        line.text = ev.text;
        line.plain = stripIrcFormatting(ev.text);
        line.msgid = ev.getTag("msgid");
        line.replyTo = ev.getTag("+reply");
        if (!line.replyTo.length) line.replyTo = ev.getTag("+draft/reply");
        line.atMs = host.nowMs();
        if (line.replyTo.length) {
            if (f.ownMsgids.canFind(line.replyTo)) {
                line.attribution = ServiceReplyAttribution.reply;
                line.claimed = true;
            } else if ((line.replyTo in foreignMsgids) !is null
                    || (!f.unechoed.length && f.ownMsgids.length >= f.spec.bodies.length)) {
                // Provably a reply to another message of ours (a manual
                // command): ordinary traffic, as it always was.
                return false;
            } else {
                // Names a message we cannot place yet (our echo pending, or
                // never coming): private, never attributed. Our echo may
                // still claim it (`resolveUnresolved`); otherwise the frame
                // closes ambiguous and cannot confirm.
                line.attribution = ServiceReplyAttribution.reply;
                line.claimed = true;
                const ubytes = ServiceReplyLine.sizeof + line.command.length + line.text.length
                    + line.plain.length + line.msgid.length + line.replyTo.length;
                if (f.unresolved.length < SERVICES_FRAME_MAX_UNRESOLVED && retainFrameBytes(f, ubytes))
                    f.unresolved ~= line;
                else f.frame.ambiguous = true;
                rememberPrivateMsgid(line.msgid);
                return true;
            }
        } else {
            line.attribution = f.phase == FramePhase.collecting
                ? ServiceReplyAttribution.window : ServiceReplyAttribution.late;
            bool released;
            if (f.spec.release !is null) {
                try released = f.spec.release(line);
                catch (Exception) released = false;
            }
            line.claimed = !released;
        }
        const bytes = ServiceReplyLine.sizeof + line.command.length + line.text.length
            + line.plain.length + line.msgid.length + line.replyTo.length;
        if (f.frame.lines.length < SERVICES_FRAME_MAX_LINES && retainFrameBytes(f, bytes))
            f.frame.lines ~= line;
        else f.frame.truncated = true;
        if (line.claimed) rememberPrivateMsgid(line.msgid);
        if (f.phase == FramePhase.lingering) evaluateTerminal(f);
        return line.claimed;
    }

    private void evaluateTerminal(PendingFrame* f) {
        if (f.phase != FramePhase.lingering || f.spec.terminal is null) return;
        bool terminal;
        try terminal = f.spec.terminal(f.frame);
        catch (Exception) terminal = false;
        if (terminal) closeFrame(f, ServiceFrameOutcome.completed, "");
    }

    private void frameDeadline(PendingFrame* f) {
        auto txn = f.txn;
        // An authentication whose verdict never arrived leaves the service
        // ambiguous: no further authentication until a stated login or a
        // reconnect resolves it.
        if (isAuthentication(txn.req.action) && txn.bodiesWritten)
            slots[txn.ep.service].authAmbiguous = true;
        closeFrame(f, ServiceFrameOutcome.deadline, f.phase == FramePhase.lingering ? "async_deadline" : "deadline");
    }

    private void closeFrame(PendingFrame* f, ServiceFrameOutcome outcome, string reason) {
        auto txn = f.txn;
        if (txn.frameState !is f) return;
        txn.frameState = null;
        f.frame.outcome = outcome;
        f.frame.reason = reason;
        f.frame.closedAtMs = host.nowMs();
        f.unechoed = null;
        // Replies we could not place keep the frame from confirming anything.
        if (f.unresolved.length) f.frame.ambiguous = true;
        f.unresolved = null;
        if (outcome == ServiceFrameOutcome.completed && !f.frame.truncated && !f.frame.ambiguous)
            ++txn.framesCompleted;
        else txn.frameIncomplete = true;
        if (outcome != ServiceFrameOutcome.completed) quarantineLate(f);
        // Drop this frame's unwritten lines (fences, bodies).
        QueuedLine[] keep;
        foreach (q; queue) if (q.txn !is txn) keep ~= q;
        queue = keep;
        if (txn.finished) return;
        try f.done(f.frame);
        catch (Exception) {
            txn.complete(txn.bodiesWritten ? ServiceStatus.unconfirmed : ServiceStatus.unavailable, "adapter_error");
        }
    }

    // ── Internals: own echoes and history ────────────────────────────

    private bool interceptOwnEcho(ref IRCRawEvent ev, string target, string text, const ServicesConfig cfg,
            bool historical) {
        ServiceId id;
        if (!serviceTarget(target, cfg, id)) return false;
        if (!historical) {
            if (auto txn = slots[id].txn) {
                if (auto f = txn.frameState) if (f.ep.service == id) {
                    const i = f.unechoed.countUntil(text);
                    if (i >= 0) {
                        f.unechoed = f.unechoed[0 .. i] ~ f.unechoed[i + 1 .. $];
                        const msgid = ev.getMsgid();
                        if (msgid.length) {
                            f.ownMsgids ~= msgid;
                            f.frame.replyCorrelated = true;
                        }
                        resolveUnresolved(f, msgid);
                        return true;
                    }
                }
            }
            // Our own line to a service outside any frame (manual, alias,
            // bouncer, automatic): its msgid is provably not a frame's, and
            // a NickServ auth command learns the msgid its verdict will name.
            const echoMsgid = ev.getMsgid();
            rememberForeignMsgid(echoMsgid);
            if (id == ServiceId.nickServ) legacyAuthEchoed(text, echoMsgid);
        }
        if (text == "\x01VERSION\x01") return true;
        // Sensitive own service commands (manual or automatic) never become
        // a chat row, live or replayed.
        return sensitiveServiceMessage(target, text, cfg);
    }

    /// Our echo for one of a frame's bodies arrived: `+reply` lines naming
    /// its msgid become ours. Once every body has echoed, the remaining
    /// unresolved lines are provably someone else's — they stay private
    /// (already hidden) but no longer make the frame ambiguous.
    private void resolveUnresolved(PendingFrame* f, string msgid) {
        if (!f.unresolved.length) return;
        ServiceReplyLine[] still;
        foreach (l; f.unresolved) {
            if (msgid.length && l.replyTo == msgid) {
                auto ours = l;
                ours.attribution = ServiceReplyAttribution.reply;
                ours.claimed = true;
                if (f.frame.lines.length < SERVICES_FRAME_MAX_LINES) f.frame.lines ~= ours;
                else f.frame.truncated = true;
            } else {
                still ~= l;
            }
        }
        // Every body echoed with a msgid: whatever is left named a message
        // that is provably not ours.
        const allKnown = !f.unechoed.length && f.ownMsgids.length >= f.spec.bodies.length;
        f.unresolved = allKnown ? null : still;
        if (f.phase == FramePhase.lingering) evaluateTerminal(f);
    }

    /// Backlog / CHATHISTORY lines from a service. Private replies (to our
    /// own nick) are never history: an older reply can hold a confirmation
    /// code, a 2.0 REGISTER echo or a memo body whose msgid this engine
    /// never saw. Service lines in channels stay ordinary history.
    private bool historicalServiceLine(ref IRCRawEvent ev, string target) {
        // Any direct (non-channel, non-`$mask`) service line, to whichever
        // nick we held then.
        if (target.length && target[0] != '#' && target[0] != '&' && target[0] != '!'
                && target[0] != '+' && target[0] != '$')
            return true;
        const msgid = ev.getMsgid();
        if (msgid.length && (msgid in privateMsgids) !is null) return true;
        return quietPrefix(ev);
    }

    private void rememberPrivateMsgid(string msgid) {
        if (!msgid.length) return;
        if (privateMsgidOrder.length >= SERVICES_PRIVATE_MSGIDS_MAX) {
            privateMsgids.remove(privateMsgidOrder[0]);
            privateMsgidOrder = privateMsgidOrder[1 .. $];
        }
        privateMsgids[msgid] = host.nowMs() + SERVICES_PRIVATE_MSGID_MS;
        privateMsgidOrder ~= msgid;
    }

    // ── Internals: WHOIS / VERSION probes ────────────────────────────

    /// Suppressed WHOIS; joins an outstanding probe for the same nick.
    package void requestWhois(string nick, long notAfter, void delegate(ServicesWhois) done) {
        const now = host.nowMs();
        foreach (ref p; whoisProbes)
            if (host.sameNick(p.nick, nick)) {
                p.waiters ~= done;
                return;
            }
        long deadline = now + SERVICES_WHOIS_DEADLINE_MS;
        if (notAfter > 0 && deadline > notAfter) deadline = notAfter;
        WhoisProbe p;
        p.nick = nick;
        p.deadlineMs = deadline;
        p.result.nick = nick;
        p.waiters ~= done;
        if (!enqueue("WHOIS " ~ nick, null, false, deadline)) {
            done(ServicesWhois.init);
            return;
        }
        whoisProbes ~= p;
        host.wake();
    }

    private bool interceptNumeric(ref IRCRawEvent ev) {
        if (!whoisProbes.length) return false;
        const code = ev.command;
        if (!isWhoisNumeric(code)) return false;
        auto p = ev.getParams();
        if (p.length < 2) return false;
        foreach (i, ref probe; whoisProbes) {
            if (!host.sameNick(p[1], probe.nick)) continue;
            auto r = &probe.result;
            switch (code) {
                case "311":
                    if (p.length >= 4) {
                        r.present = true;
                        r.nick = p[1];
                        r.ident = p[2];
                        r.host = p[3];
                    }
                    break;
                case "312":
                    if (p.length >= 3) r.server = p[2];
                    break;
                case "330":
                    if (p.length >= 3) r.account = p[2];
                    break;
                case "335":
                    r.bot = true;
                    break;
                case "401": {
                    r.present = false;
                    const grace = host.nowMs() + SERVICES_WHOIS_ABSENT_GRACE_MS;
                    if (probe.deadlineMs > grace) probe.deadlineMs = grace;
                    r.complete = true;
                    break;
                }
                case "318": {
                    r.complete = true;
                    const shared_ = probe.shared_;
                    finishWhois(i);
                    return !shared_;
                }
                default:
                    break;
            }
            return !probe.shared_;
        }
        return false;
    }

    private void finishWhois(size_t i) {
        auto probe = whoisProbes[i];
        whoisProbes = whoisProbes[0 .. i] ~ whoisProbes[i + 1 .. $];
        foreach (w; probe.waiters) {
            try w(probe.result);
            catch (Exception) {}
        }
    }

    private void requestVersion(ServicesEndpoint ep, long notAfter, void delegate(string) done) {
        foreach (ref p; versionProbes)
            if (host.sameNick(p.endpoint.nick, ep.nick)) {
                p.waiters ~= done;
                return;
            }
        long deadline = host.nowMs() + SERVICES_VERSION_WAIT_MS;
        if (notAfter > 0 && deadline > notAfter) deadline = notAfter;
        if (!enqueue("PRIVMSG " ~ ep.target() ~ " :\x01VERSION\x01", null, false, deadline)) {
            done("");
            return;
        }
        versionProbes ~= VersionProbe(ep, deadline, [done]);
        host.wake();
    }

    private bool versionReply(ref IRCRawEvent ev, string text) {
        enum head = "\x01VERSION ";
        if (ev.command != "NOTICE" || text.length < head.length + 1 || text[0 .. head.length] != head
                || text[$ - 1] != '\x01')
            return false;
        foreach (i, ref p; versionProbes) {
            if (!matchesEndpoint(ev, p.endpoint)) continue;
            auto params = ev.getParams();
            if (!params.length || !host.isOwnNick(params[0])) return false;
            finishVersion(i, stripIrcFormatting(text[head.length .. $ - 1]));
            return true;
        }
        return false;
    }

    private void finishVersion(size_t i, string version_) {
        auto probe = versionProbes[i];
        versionProbes = versionProbes[0 .. i] ~ versionProbes[i + 1 .. $];
        foreach (w; probe.waiters) {
            try w(version_);
            catch (Exception) {}
        }
    }

    // ── Internals: discovery ─────────────────────────────────────────

    private void startDiscovery(ServicesRequest req, void delegate(ServicesResult) deliver, string epoch,
            const ServicesConfig cfg, long capAt) {
        auto d = new DiscoveryRun;
        d.req = req;
        d.deliver = deliver;
        d.epoch = epoch;
        d.cfg = cfg;
        d.deadlineMs = host.nowMs() + SERVICES_ORDINARY_DEADLINE_MS;
        if (d.deadlineMs > capAt) d.deadlineMs = capAt;
        discovery = d;
        foreach (i; 0 .. SERVICE_COUNT) {
            const nick = cfg.pins[i].nick.length ? cfg.pins[i].nick : SERVICE_DEFAULT_NICKS[i];
            // One closure frame per service: a delegate literal in the loop
            // body would share the loop's frame (and its last index).
            requestWhois(nick, d.deadlineMs, discoveryWhoisDone(d, cast(ServiceId) i));
            if (d.finished) return;
        }
    }

    private void delegate(ServicesWhois) discoveryWhoisDone(DiscoveryRun d, ServiceId idx) {
        return (ServicesWhois w) {
            if (d.finished) return;
            d.whois[idx] = w;
            d.whoisDone[idx] = true;
            if (!w.complete) {
                finishDiscovery(ServiceStatus.unconfirmed, "deadline");
                return;
            }
            if (w.present && w.server.length && w.ident.length) {
                requestVersion(ServicesEndpoint(idx, w.nick, w.ident, w.host, w.server), d.deadlineMs, (string v) {
                    if (d.finished) return;
                    d.versions[idx] = v;
                    d.versionDone[idx] = true;
                    discoveryProgress();
                });
            } else {
                d.versionDone[idx] = true;
            }
            discoveryProgress();
        };
    }

    private void discoveryProgress() {
        auto d = discovery;
        if (d is null || d.finished) return;
        foreach (i; 0 .. SERVICE_COUNT) if (!d.whoisDone[i] || !d.versionDone[i]) return;
        auto services = Json.emptyObject;
        foreach (i; 0 .. SERVICE_COUNT) {
            const w = d.whois[i];
            const pin = d.cfg.pins[i];
            const state = evaluatePin(w, pin, d.cfg.server);
            slots[i].pin = state;
            if (state == PinState.verified)
                slots[i].endpoint = ServicesEndpoint(cast(ServiceId) i, w.nick, w.ident, w.host, w.server,
                    d.versions[i]);
            auto s = Json.emptyObject;
            s["nick"] = Json(w.present ? w.nick : (pin.nick.length ? pin.nick : SERVICE_DEFAULT_NICKS[i]));
            s["present"] = Json(w.present);
            s["ident"] = Json(w.present ? w.ident : "");
            s["host"] = Json(w.present ? w.host : "");
            s["server"] = Json(w.present ? w.server : "");
            s["version"] = Json(d.versions[i]);
            s["pin"] = Json(pinStateName(state));
            services[SERVICE_KEYS[i]] = s;
        }
        auto data = Json.emptyObject;
        data["provider"] = Json(providerName(d.cfg.provider));
        data["approvedServer"] = Json(d.cfg.server);
        data["services"] = services;
        finishDiscovery(ServiceStatus.confirmed, "", data);
    }

    private void finishDiscovery(ServiceStatus status, string reason, Json data = Json.undefined) {
        auto d = discovery;
        if (d is null || d.finished) return;
        d.finished = true;
        discovery = null;
        ServicesResult r;
        r.requestId = d.req.requestId;
        r.connectionEpoch = d.epoch;
        r.action = ServiceAction.discover;
        r.status = status;
        r.reasonCode = reason;
        r.data = data;
        remember(r);
        deliverSafely(d.deliver, r);
    }

    // ── Internals: completion / cancellation / dedup ─────────────────

    package void finishTransaction(ServicesTransaction txn, ServicesResult r) {
        if (txn.finished) return;
        txn.finished = true;
        if (auto f = txn.frameState) {
            // Finished (cancelled, or answered by its adapter) mid-frame:
            // late replies of a command already sent stay private.
            quarantineLate(f);
            txn.frameState = null;
            QueuedLine[] keep;
            foreach (q; queue) if (q.txn !is txn) keep ~= q;
            queue = keep;
        }
        foreach (ref s; slots)
            if (s.txn is txn) s.txn = null;
        remember(r);
        host.markerChanged();
        deliverSafely(txn.deliver, r);
    }

    private void cancelTransaction(ServicesTransaction txn, string reason) {
        if (txn.finished) return;
        // A command that may have reached services is uncertain, never stale.
        txn.frameIncomplete = true;
        txn.complete(txn.bodiesWritten ? ServiceStatus.unconfirmed : ServiceStatus.stale, reason);
    }

    private void cancelAll(string reason) {
        foreach (ref s; slots)
            if (s.txn !is null) cancelTransaction(s.txn, reason);
        if (discovery !is null) finishDiscovery(ServiceStatus.stale, reason);
    }

    /// Dedup keeps outcomes only: no data, details or capabilities.
    private void remember(ServicesResult r) {
        if (!r.requestId.length) return;
        ServicesResult s;
        s.requestId = r.requestId;
        s.connectionEpoch = r.connectionEpoch;
        s.action = r.action;
        s.status = r.status;
        s.revision = r.revision;
        s.reasonCode = r.reasonCode;
        if ((r.requestId in dedup) is null) {
            if (dedupOrder.length >= SERVICES_DEDUP_MAX) {
                dedup.remove(dedupOrder[0]);
                dedupOrder = dedupOrder[1 .. $];
            }
            dedupOrder ~= r.requestId;
        }
        dedup[r.requestId] = DedupEntry(s, host.nowMs() + SERVICES_DEDUP_MS);
    }

    private void expire(long now) {
        while (dedupOrder.length) {
            auto e = dedupOrder[0] in dedup;
            if (e !is null && e.expiresAt > now) break;
            if (e !is null) dedup.remove(dedupOrder[0]);
            dedupOrder = dedupOrder[1 .. $];
        }
        while (privateMsgidOrder.length) {
            auto e = privateMsgidOrder[0] in privateMsgids;
            if (e !is null && *e > now) break;
            if (e !is null) privateMsgids.remove(privateMsgidOrder[0]);
            privateMsgidOrder = privateMsgidOrder[1 .. $];
        }
        if (quiet.untilMs && quiet.untilMs <= now) quiet = ServicesQuietMarker.init;
        foreach (ref s; slots)
            if (s.late.untilMs && s.late.untilMs <= now) s.late = LateQuarantine.init;
    }
}

// ── Pure helpers ───────────────────────────────────────────────────────────

/// Wire name of a pin state in discovery data.
private string pinStateName(PinState s) @safe pure nothrow {
    final switch (s) {
        case PinState.unknown:  return "unknown";
        case PinState.verified: return "verified";
        case PinState.mismatch: return "mismatch";
        case PinState.absent:   return "absent";
        case PinState.unpinned: return "unpinned";
    }
}

/// `ifsvc` + 32 random hex digits.
private string fenceToken() {
    import std.array : replace;
    return SERVICES_FENCE_PREFIX ~ randomUUID().toString().replace("-", "");
}

/// `\x01PING ifsvc<hex>\x01`: one of our fence replies (or echoes).
bool isFenceReply(string text, out string token) @safe pure nothrow {
    enum head = "\x01PING " ~ SERVICES_FENCE_PREFIX;
    if (text.length < head.length + 2 || text[0 .. head.length] != head || text[$ - 1] != '\x01') return false;
    const body_ = text[6 .. $ - 1];
    foreach (c; body_[SERVICES_FENCE_PREFIX.length .. $])
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    token = body_;
    return true;
}

/// Secondary-service edges a transaction may add (`frameOn`): HostServ →
/// NickServ (own vhost via INFO), BotServ → ChanServ (channel policy) and
/// ChanServ → BotServ (the assigned bot that relays TOPIC). A peer lock is
/// taken without waiting — a busy peer refuses the frame at once — so two
/// transactions holding each other's primary can never wait on each other.
bool peerAllowed(ServiceId primary, ServiceId peer) @safe pure nothrow @nogc {
    return (primary == ServiceId.hostServ && peer == ServiceId.nickServ)
        || (primary == ServiceId.botServ && peer == ServiceId.chanServ)
        || (primary == ServiceId.chanServ && peer == ServiceId.botServ);
}

/// One line of NickServ text is an authentication command whose verdict
/// can log this session in or out, or arrive asynchronously (formatting
/// ignored, as services tokenise the raw body).
bool isLegacyAuthCommand(string text) @safe pure nothrow {
    import std.ascii : toUpper;
    const plain = stripIrcFormatting(text);
    size_t i;
    while (i < plain.length && plain[i] == ' ') ++i;
    if (i < plain.length && plain[i] == '/') ++i;
    size_t j = i;
    while (j < plain.length && plain[j] != ' ') ++j;
    char[16] buf;
    if (j - i == 0 || j - i > buf.length) return false;
    foreach (k, c; plain[i .. j]) buf[k] = toUpper(c);
    switch (buf[0 .. j - i]) {
        case "IDENTIFY": case "ID": case "LOGIN": case "GROUP": case "RECOVER": case "GHOST":
        case "RELEASE": case "REGISTER": case "CONFIRM":
            return true;
        default:
            return false;
    }
}

private string[] removeValue(string[] list, string value) @safe pure nothrow {
    string[] result;
    foreach (v; list) if (v != value) result ~= v;
    return result;
}

private bool isEffectCommand(string cmd) @safe pure nothrow {
    switch (cmd) {
        case "TOPIC": case "MODE": case "KICK": case "NICK": case "CHGHOST":
        case "332": case "333": case "396":
            return true;
        default:
            return false;
    }
}

private bool isWhoisNumeric(string code) @safe pure nothrow {
    switch (code) {
        case "276": case "301": case "307": case "310": case "311": case "312": case "313":
        case "317": case "318": case "319": case "320": case "330": case "335": case "338":
        case "378": case "379": case "401": case "671":
            return true;
        default:
            return false;
    }
}

/// Services a manual line addresses: PRIVMSG/NOTICE/SQUERY targets
/// (comma lists, `Nick@server`) and the usual alias commands, including the
/// managed ircd's `ID <pass>` and `GLOBAL <message>`. A block carrying
/// CR/LF is the union over its physical lines, so a second command line
/// cannot slip past a service lock.
ServiceId[] lineServiceTargets(string line, const ServicesConfig cfg) @safe pure {
    ServiceId[] ids;
    size_t start;
    foreach (i; 0 .. line.length + 1) {
        if (i < line.length && line[i] != '\r' && line[i] != '\n') continue;
        if (i > start)
            foreach (id; lineServiceTargetsOne(line[start .. i], cfg))
                if (!ids.canFind(id)) ids ~= id;
        start = i + 1;
    }
    return ids;
}

private ServiceId[] lineServiceTargetsOne(string line, const ServicesConfig cfg) @safe pure {
    import std.string : indexOf, toUpper, stripLeft;
    string rest = line.stripLeft;
    if (rest.length && rest[0] == '@') {
        const sp = rest.indexOf(' ');
        rest = sp < 0 ? "" : rest[sp + 1 .. $].stripLeft;
    }
    const sp1 = rest.indexOf(' ');
    const verb = (sp1 < 0 ? rest : rest[0 .. sp1]).toUpper;
    ServiceId[] ids;
    switch (verb) {
        case "PRIVMSG": case "NOTICE": case "SQUERY": {
            if (sp1 < 0) return null;
            auto args = rest[sp1 + 1 .. $].stripLeft;
            const sp2 = args.indexOf(' ');
            ServiceId id;
            foreach (t; splitTargets(sp2 < 0 ? args : args[0 .. sp2]))
                if (serviceTarget(t, cfg, id)) ids ~= id;
            return ids;
        }
        case "NS": case "NICKSERV": case "IDENTIFY": case "ID": case "LOGIN": return [ServiceId.nickServ];
        case "CS": case "CHANSERV": return [ServiceId.chanServ];
        case "BS": case "BOTSERV": return [ServiceId.botServ];
        case "MS": case "MEMOSERV": return [ServiceId.memoServ];
        case "HS": case "HOSTSERV": return [ServiceId.hostServ];
        case "OS": case "OPERSERV": return [ServiceId.operServ];
        case "GS": case "GLOBAL": return [ServiceId.global];
        default: return null;
    }
}

private string[] splitTargets(string s) @safe pure nothrow {
    string[] result;
    size_t start;
    foreach (i; 0 .. s.length + 1) {
        if (i < s.length && s[i] != ',') continue;
        if (i > start) result ~= s[start .. i];
        start = i + 1;
    }
    return result;
}

/// IRC formatting (bold, colour, italics, underline, reverse, strike,
/// monospace, reset) removed; Anope's `\x1B` no-break marker becomes a space.
string stripIrcFormatting(string s) @safe pure nothrow {
    char[] o;
    o.reserve(s.length);
    for (size_t i = 0; i < s.length; ++i) {
        const c = s[i];
        switch (c) {
            case '\x02': case '\x0F': case '\x11': case '\x16': case '\x1D': case '\x1E': case '\x1F':
                break;
            case '\x1B':
                o ~= ' ';
                break;
            case '\x03': {
                // \x03[N[N]][,N[N]]
                size_t n;
                while (n < 2 && i + 1 < s.length && s[i + 1] >= '0' && s[i + 1] <= '9') { ++i; ++n; }
                if (n && i + 2 < s.length && s[i + 1] == ',' && s[i + 2] >= '0' && s[i + 2] <= '9') {
                    ++i;
                    n = 0;
                    while (n < 2 && i + 1 < s.length && s[i + 1] >= '0' && s[i + 1] <= '9') { ++i; ++n; }
                }
                break;
            }
            case '\x04': {
                // \x04[RRGGBB[,RRGGBB]]
                static bool hex6(string t) @safe pure nothrow {
                    if (t.length < 6) return false;
                    foreach (h; t[0 .. 6])
                        if (!((h >= '0' && h <= '9') || (h >= 'a' && h <= 'f') || (h >= 'A' && h <= 'F'))) return false;
                    return true;
                }
                if (hex6(s[i + 1 .. $])) {
                    i += 6;
                    if (i + 1 < s.length && s[i + 1] == ',' && hex6(s[i + 2 .. $])) i += 7;
                }
                break;
            }
            default:
                o ~= c;
        }
    }
    return () @trusted { return cast(string) o; }();
}

/// One detail line safe to hand to the initiating browser session.
string sanitizeServiceDetail(string text, const string[] secrets) @safe {
    import std.array : replace;
    auto plain = stripIrcFormatting(text);
    char[] o;
    foreach (char c; plain) o ~= (c < 32 || c == 127) ? ' ' : c;
    string s = () @trusted { return cast(string) o; }();
    foreach (secret; secrets)
        if (secret.length >= 1) s = s.replace(secret, "[redacted]");
    if (s.length > 512) {
        size_t cut = 512;
        while (cut > 0 && (s[cut] & 0xC0) == 0x80) --cut;
        s = s[0 .. cut];
    }
    return s;
}

/// Request values that must never appear in a detail line.
private string[] requestSecrets(ServicesRequest r) {
    string[] out_;
    if (r.params.type != Json.Type.object) return out_;
    foreach (key; ["password", "code"]) {
        auto v = r.params[key];
        if (v.type == Json.Type.string && v.get!string.length) out_ ~= v.get!string;
    }
    return out_;
}

@("services: fence tokens are recognised only in our alphanumeric format")
unittest {
    string tok;
    const t = fenceToken();
    assert(t.length == SERVICES_FENCE_PREFIX.length + 32);
    assert(isFenceReply("\x01PING " ~ t ~ "\x01", tok) && tok == t);
    assert(!isFenceReply("\x01PING 12345\x01", tok));
    assert(!isFenceReply("\x01PING " ~ t ~ "x\x01", tok));
    assert(!isFenceReply("PING " ~ t, tok));
}

@("services: formatting is stripped and secrets redacted from details")
unittest {
    assert(stripIrcFormatting("\x02Bold\x02 \x0304,12red\x03 \x1Fu\x1F\x1Bx") == "Bold red u x");
    assert(stripIrcFormatting("\x04FF0000hex\x04") == "hex");
    assert(sanitizeServiceDetail("Unknown command \x02IDENTIFY hunter2\x02.", ["hunter2"])
        == "Unknown command IDENTIFY [redacted].");
}

@("services: manual lines map to the services they address")
unittest {
    ServicesConfig cfg;
    assert(lineServiceTargets("PRIVMSG NickServ :INFO", cfg) == [ServiceId.nickServ]);
    assert(lineServiceTargets("privmsg bob,MemoServ@x.y :LIST", cfg) == [ServiceId.memoServ]);
    assert(lineServiceTargets("NS IDENTIFY x", cfg) == [ServiceId.nickServ]);
    assert(lineServiceTargets("@a=b CS ACCESS #c LIST", cfg) == [ServiceId.chanServ]);
    assert(lineServiceTargets("PRIVMSG #chan :hi", cfg).length == 0);
    assert(lineServiceTargets("JOIN #c", cfg).length == 0);
}

version (ServicesWireHarness) {

import ircfiber.irc.parser : parseIRCLineNamed;
import ircfiber.services.config : managedServicesConfig;

/// One named legacy-auth / reply-correlation check, printed and counted by
/// the `services-test` runner (`servicesLegacyAuthChecks`).
struct ServicesLedgerCheck {
    string name;
    bool passed;
}

private enum LEDGER_NET = "22222222-2222-4222-8222-222222222222";
private enum LEDGER_NS = ":NickServ!services@services.test ";

private final class LedgerHost : ServicesHost {
    long now = 1_700_000_000_000;
    string epoch = "11111111-1111-4111-8111-111111111111";
    ServicesActor who = ServicesActor(ServicesActorState.none, "");
    ServicesConfig cfg;
    string[] written;
    ServicesTransport t;
    long nowMs() { return now; }
    string liveEpoch() { return epoch; }
    string ownNick() { return "me"; }
    bool isOwnNick(string n) { return icmp(n, "me") == 0; }
    bool sameNick(string a, string b) { return icmp(a, b) == 0; }
    ServicesActor actor() { return who; }
    ServicesConfig servicesConfig() { return cfg; }
    string isupport(string) { return ""; }
    size_t lineLimit() { return 512; }
    size_t ownPrefixBytes() { return 30; }
    bool manualLinePending(string) { return false; }
    void wake() {
        for (;;) {
            auto l = t.nextWrite();
            if (!l.length) break;
            t.popWrite();
            written ~= l;
        }
    }
    void markerChanged() {}
    void adoptOwnAccount(string) {}
    bool ownChannelStatus(string, out string p) { return false; }
}

/// A deliberately naive adapter: "confirmed" whenever its frame completed
/// with any line. The transport must still never let a foreign reply make
/// that true.
private final class LedgerOp : ServicesOperation {
    ServiceFrame got;
    bool asyncKind;
    bool supports(const ref ServicesEndpoint) { return true; }
    void run(ServicesTransaction txn) {
        ServiceFrameSpec spec;
        spec.bodies = [asyncKind ? "IDENTIFY acct wrongpw" : "INFO acct"];
        spec.kind = asyncKind ? ServiceFrameKind.asyncAuth : ServiceFrameKind.ordinary;
        if (asyncKind)
            spec.terminal = delegate (const ref ServiceFrame f) => f.lines.length > 0 && f.accountChanges.length > 0;
        txn.frame(spec, (ServiceFrame f) {
            got = f;
            const ok_ = f.outcome == ServiceFrameOutcome.completed && f.lines.length > 0;
            txn.complete(ok_ ? ServiceStatus.confirmed : ServiceStatus.unconfirmed, ok_ ? "" : f.reason);
        });
    }
}

private final class LedgerRig {
    LedgerHost host;
    ServicesTransport t;
    ServicesResult[] results;

    this() {
        host = new LedgerHost;
        host.cfg = managedServicesConfig("services.test");
        t = new ServicesTransport(host);
        host.t = t;
    }

    ServicesRequest request(ServiceAction action, string params, string actor) {
        import vibe.data.json : parseJsonString;
        auto j = parseJsonString(`{"params":` ~ params ~ `}`);
        j["requestId"] = randomUUID().toString();
        j["action"] = action.to!string;
        j["expectedConnectionEpoch"] = host.epoch;
        j["expectedActorAccount"] = actor;
        return ServicesRequest.fromJson(j);
    }

    void run(ServicesRequest q) { t.execute(q, (ServicesResult r) { results ~= r; }); }

    bool feed(string line, bool historical = false) {
        auto ev = parseIRCLineNamed(line, "net", LEDGER_NET);
        return t.intercept(ev, historical);
    }

    void verify() {
        feed(":s 311 me NickServ services services.test * :Services");
        feed(":s 312 me NickServ services.test :Anope");
        feed(":s 318 me NickServ :End of /WHOIS list.");
        feed(LEDGER_NS ~ "NOTICE me :\x01VERSION Anope-2.1.0 services.test\x01");
    }

    string fence(size_t n) {
        size_t seen;
        foreach (l; host.written) {
            const at = l.countUntil("\x01PING ");
            if (at < 0) continue;
            if (seen++ == n) return l[at + 6 .. $ - 1];
        }
        return "";
    }

    void fenceReply(size_t n) { feed(LEDGER_NS ~ "NOTICE me :\x01PING " ~ fence(n) ~ "\x01"); }

    ServicesResult last() { return results.length ? results[$ - 1] : ServicesResult.init; }

    bool wrote(string needle) {
        foreach (l; host.written) if (l.countUntil(needle) >= 0) return true;
        return false;
    }
}

/// Legacy NickServ auth serialization and `+reply` correlation, scripted.
ServicesLedgerCheck[] servicesLegacyAuthChecks() {
    ServicesLedgerCheck[] results;
    void check(string name, bool passed) { results ~= ServicesLedgerCheck(name, passed); }
    auto savedOps = gServicesOperations.dup;
    auto savedClassifier = gLegacyAuthTerminal;
    scope (exit) {
        gServicesOperations = savedOps;
        gLegacyAuthTerminal = savedClassifier;
    }
    gServicesOperations = null;
    auto op = new LedgerOp;
    registerServicesOperation(ServiceAction.accountIdentify, op);
    registerServicesOperation(ServiceAction.accountInfo, op);
    static bool passwordVerdict(string, string plain) @safe pure nothrow {
        return plain.length >= 8 && plain[0 .. 8] == "Password";
    }
    setLegacyAuthTerminalClassifier(&passwordVerdict);

    // ── 2.1 tagged: an old manual IDENTIFY (right password, held by an
    // async SQL/LDAP backend) still pending when the UI sends a wrong one.
    {
        auto r = new LedgerRig;
        op.asyncKind = true;
        r.t.noteManualMessage("NickServ", "IDENTIFY acct rightpw");
        check("our echo of the manual IDENTIFY is swallowed",
            r.feed("@msgid=m0 :me!~m@h PRIVMSG NickServ :IDENTIFY acct rightpw"));
        r.run(r.request(ServiceAction.accountIdentify, `{"account":"acct","password":"wrongpw"}`, ""));
        check("a structured IDENTIFY is refused while a manual IDENTIFY awaits its verdict",
            r.last.reasonCode == "legacy_auth_pending" && !r.wrote("wrongpw"));
        r.t.onOwnAccount(ServicesActor(ServicesActorState.account, "acct"));
        r.host.who = ServicesActor(ServicesActorState.account, "acct");
        r.run(r.request(ServiceAction.accountIdentify, `{"account":"acct","password":"wrongpw"}`, "acct"));
        check("a 900 alone does not resolve the manual command",
            r.last.reasonCode == "legacy_auth_pending" && r.t.legacyAuthPending() == 1);
        check("the verdict tagged with the manual command's msgid stays ordinary traffic",
            !r.feed("@+reply=m0;msgid=r0 " ~ LEDGER_NS ~ "NOTICE me :Password accepted - you are now recognized."));
        check("and resolves it", r.t.legacyAuthPending() == 0);
        const answered = r.results.length;
        r.run(r.request(ServiceAction.accountIdentify, `{"account":"acct","password":"wrongpw"}`, "acct"));
        check("then the structured IDENTIFY is admitted",
            r.results.length == answered && r.wrote("WHOIS NickServ"));
        r.t.onDisconnect();
    }

    // ── a foreign +reply inside our frame, before / without our echo ────
    {
        auto r = new LedgerRig;
        op.asyncKind = false;
        r.run(r.request(ServiceAction.accountInfo, `{"account":"acct"}`, ""));
        r.verify();
        r.fenceReply(0);
        check("a +reply naming a message we cannot place yet is private",
            r.feed("@+reply=m1;msgid=x1 " ~ LEDGER_NS ~ "NOTICE me :acct is me"));
        r.feed("@msgid=m1 :me!~m@h PRIVMSG NickServ@services.test :INFO acct");
        r.fenceReply(1);
        check("our later echo claims it as ours",
            op.got.lines.length == 1 && op.got.lines[0].replyTo == "m1" && !op.got.ambiguous
            && r.last.status == ServiceStatus.confirmed);
    }
    {
        auto r = new LedgerRig;
        op.asyncKind = false;
        r.run(r.request(ServiceAction.accountInfo, `{"account":"acct"}`, ""));
        r.verify();
        r.fenceReply(0);
        check("a manual command's tagged verdict arriving before our echo is private, not attributed",
            r.feed("@+reply=mX;msgid=x2 " ~ LEDGER_NS ~ "NOTICE me :Password accepted - you are now recognized."));
        r.feed("@msgid=m1 :me!~m@h PRIVMSG NickServ@services.test :INFO acct");
        r.feed("@+reply=m1;msgid=x3 " ~ LEDGER_NS ~ "NOTICE me :acct is me");
        r.fenceReply(1);
        check("once every echo is known it is provably foreign: never in the frame",
            op.got.lines.length == 1 && op.got.lines[0].text == "acct is me" && !op.got.ambiguous);
        check("a CHATHISTORY replay of that private line is suppressed",
            r.feed("@batch=h;msgid=x2 " ~ LEDGER_NS ~ "NOTICE me :Password accepted - you are now recognized.", true));
    }
    {
        auto r = new LedgerRig;
        op.asyncKind = false;
        r.run(r.request(ServiceAction.accountInfo, `{"account":"acct"}`, ""));
        r.verify();
        r.fenceReply(0);
        r.feed("@+reply=mX;msgid=x4 " ~ LEDGER_NS ~ "NOTICE me :Password accepted - you are now recognized.");
        r.feed(LEDGER_NS ~ "NOTICE me :acct is me");
        r.fenceReply(1);
        check("with no echo ever, an unplaceable tagged reply makes the frame ambiguous",
            op.got.ambiguous && op.got.lines.length == 1);
        check("and an adapter's confirmed is reported unconfirmed",
            r.last.status == ServiceStatus.unconfirmed && r.last.reasonCode == "frame_incomplete");
    }

    // ── 2.0 / alias: untagged verdicts need the grammar classifier ───────
    {
        auto r = new LedgerRig;
        r.t.noteManualLine("ID rightpw");
        r.run(r.request(ServiceAction.accountIdentify, `{"account":"acct","password":"wrongpw"}`, ""));
        check("an ircd-alias IDENTIFY blocks structured authentication",
            r.last.reasonCode == "legacy_auth_pending");
        check("an unrelated untagged notice does not resolve it",
            !r.feed(LEDGER_NS ~ "NOTICE me :This nickname is registered and protected.")
            && r.t.legacyAuthPending() == 1);
        check("a recognised untagged verdict does (and stays ordinary traffic)",
            !r.feed(LEDGER_NS ~ "NOTICE me :Password incorrect.") && r.t.legacyAuthPending() == 0);
    }
    {
        auto r = new LedgerRig;
        setLegacyAuthTerminalClassifier(null);
        r.t.noteManualLine("PRIVMSG NickServ :IDENTIFY rightpw");
        r.feed(LEDGER_NS ~ "NOTICE me :Password incorrect.");
        check("without a classifier an untagged verdict cannot be placed: still pending",
            r.t.legacyAuthPending() == 1);
        r.t.onDisconnect();
        check("a new socket clears the ledger", r.t.legacyAuthPending() == 0);
        setLegacyAuthTerminalClassifier(&passwordVerdict);
    }
    {
        auto r = new LedgerRig;
        r.t.noteManualLine("PRIVMSG NickServ :IDENTIFY rightpw");
        r.t.noteManualLine("ID otherpw");
        r.feed("@msgid=m5 :me!~m@h PRIVMSG NickServ :IDENTIFY rightpw");
        r.feed("@+reply=m5 " ~ LEDGER_NS ~ "NOTICE me :Password incorrect.");
        r.feed("@+reply=m5 " ~ LEDGER_NS ~ "NOTICE me :Password incorrect (continued).");
        check("a second tagged line of one verdict never closes another command",
            r.t.legacyAuthPending() == 1);
    }

    // ── automatic GHOST → IDENTIFY keeps its observable behaviour ────────
    {
        auto r = new LedgerRig;
        r.t.noteManualLine("PRIVMSG NickServ :GHOST me pw");
        r.t.noteManualLine("PRIVMSG NickServ :IDENTIFY pw");
        const echoes = r.feed("@msgid=g1 :me!~m@h PRIVMSG NickServ :GHOST me pw")
            && r.feed("@msgid=g2 :me!~m@h PRIVMSG NickServ :IDENTIFY pw");
        const replies = !r.feed("@+reply=g1 " ~ LEDGER_NS ~ "NOTICE me :Ghost with your nick has been killed.")
            && !r.feed("@+reply=g2 " ~ LEDGER_NS ~ "NOTICE me :Password accepted - you are now recognized.");
        check("automatic GHOST then IDENTIFY: echoes hidden, verdicts ordinary, ledger resolved in order",
            echoes && replies && r.t.legacyAuthPending() == 0);
    }

    // ── hand-off and bounds ──────────────────────────────────────────────
    {
        auto r = new LedgerRig;
        r.t.restoreLegacyAuth(1);
        r.run(r.request(ServiceAction.accountIdentify, `{"account":"acct","password":"x"}`, ""));
        check("a pending count handed over by the previous engine blocks structured auth",
            r.last.reasonCode == "legacy_auth_pending");
        r.feed(LEDGER_NS ~ "NOTICE me :Password incorrect.");
        check("until a recognised verdict arrives on the retained socket", r.t.legacyAuthPending() == 0);
        foreach (_; 0 .. SERVICES_LEGACY_AUTH_MAX + 1) r.t.noteManualLine("ID pw");
        r.feed(LEDGER_NS ~ "NOTICE me :Password incorrect.");
        check("a saturated ledger stays blocked until the socket is replaced",
            r.t.legacyAuthPending() == SERVICES_LEGACY_AUTH_MAX + 1);
        r.t.onDisconnect();
        check("and a new socket clears it", r.t.legacyAuthPending() == 0);
    }
    return results;
}

} // version (ServicesWireHarness)
