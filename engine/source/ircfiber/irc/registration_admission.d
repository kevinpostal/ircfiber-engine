module ircfiber.irc.registration_admission;

/// Event-loop-owned admission, shared by every client on this engine. A route
/// waiter owns no full-attempt permit. No callbacks/yields occur in tryStart.
final class RegistrationAdmission {
    enum MAX_IN_FLIGHT = 8;
    enum MAX_ROUTES = 4096;
    private struct RouteStart { string key; long atMs; bool writing; }
    private RouteStart[MAX_ROUTES] routes;
    private size_t active;
    private size_t unproven;
    private ulong generation = 1;
    private string incarnation;
    /// Detached terminal claims retain only proof coordinates, never clients,
    /// streams, callbacks or snapshots. Each record owns one active permit.
    struct TerminalClaim {
        string id;
        string incarnation;
        long connectedAtMs;
        ulong token;
        ulong epoch;
    }
    private TerminalClaim[MAX_IN_FLIGHT] terminalClaims;
    private ulong nextTerminalToken;

    /// Only a fresh, different holder incarnation proves all earlier in-flight
    /// operations gone. Keep route spacing across this reset.
    void observeIncarnation(string identity) {
        assert(identity.length);
        if (!incarnation.length) { incarnation = identity; return; }
        if (identity == incarnation) return;
        incarnation = identity;
        generation++;
        active = unproven = 0;
        foreach (ref route; routes) route.writing = false;
        terminalClaims[] = TerminalClaim.init;
    }

    void retainUnproven(ulong issuedGeneration) nothrow {
        if (issuedGeneration == generation) {
            assert(unproven < active);
            unproven++;
        }
    }

    /// A retained claim may later obtain authoritative terminal evidence.
    /// The client clears its own uncertainty flag before releasing once.
    void resolveUnproven(ulong issuedGeneration) nothrow {
        if (issuedGeneration == generation) {
            assert(unproven > 0);
            unproven--;
        }
    }

    /// Transfers an unresolved known claim out of a stopping client before
    /// its actor/object can be reaped. Unknown-ID DIALs use retainUnproven.
    void retainTerminalClaim(ref bool owned, ref bool uncertain, ulong issuedGeneration,
            string id, string instance, long connectedAtMs) nothrow {
        if (!owned) return;
        if (issuedGeneration != generation) {
            owned = uncertain = false;
            return;
        }
        assert(id.length);
        foreach (ref claim; terminalClaims) if (!claim.token) {
            if (!uncertain) retainUnproven(issuedGeneration);
            assert(nextTerminalToken < ulong.max);
            claim = TerminalClaim(id, instance, connectedAtMs, ++nextTerminalToken, generation);
            owned = uncertain = false;
            return;
        }
        assert(0, "every known terminal claim must own one of the eight permits");
    }

    TerminalClaim terminalClaimAt(size_t slot) const nothrow {
        return terminalClaims[slot];
    }

    /// INFO can yield across incarnation changes or slot reuse. Match the
    /// captured record before consuming its permit; duplicate proof is inert.
    bool resolveTerminalClaim(size_t slot, ulong token, ulong issuedGeneration) nothrow {
        if (!token || issuedGeneration != generation
                || terminalClaims[slot].token != token) return false;
        assert(active > 0 && unproven > 0);
        terminalClaims[slot] = TerminalClaim.init;
        active--;
        unproven--;
        return true;
    }

    @property size_t terminalClaimCount() const nothrow {
        size_t count;
        foreach (ref claim; terminalClaims) if (claim.token) count++;
        return count;
    }
    @property size_t unprovenCount() const nothrow { return unproven; }
    @property ulong epoch() const nothrow { return generation; }

    bool tryStart(string key, long nowMs) {
        if (active >= MAX_IN_FLIGHT) return false;
        size_t slot = MAX_ROUTES;
        foreach (i, ref route; routes) {
            if (route.key == key) {
                if (route.writing || nowMs < route.atMs || nowMs - route.atMs < 1000) return false;
                slot = i;
                break;
            }
            if (slot == MAX_ROUTES && !route.writing && (!route.key.length
                    || (nowMs >= route.atMs && nowMs - route.atMs >= 1000))) slot = i;
        }
        if (slot == MAX_ROUTES) return false;
        routes[slot] = RouteStart(key, nowMs);
        active++;
        return true;
    }

    /// Called without yielding after tryStart. Hold the route across durable
    /// policy checks until the holder responds; neither reservation nor local
    /// IPC write completion proves when the remote DIAL was processed.
    void reserveStart(string key) nothrow {
        foreach (ref route; routes) if (route.key == key) {
            assert(!route.writing);
            route.writing = true;
            return;
        }
        assert(0, "registration route was not reserved");
    }

    /// Completion/cancellation closes only this incarnation's route lease.
    /// The next DIAL starts a full second after positive remote observation.
    void completeStart(string key, ulong issuedGeneration, long nowMs) nothrow {
        if (issuedGeneration != generation) return;
        foreach (ref route; routes) if (route.key == key) {
            assert(route.writing);
            route.writing = false;
            if (nowMs > route.atMs) route.atMs = nowMs;
            return;
        }
        assert(0, "pending registration route disappeared");
    }

    void release(ref bool owned, ulong issuedGeneration = 0) nothrow {
        if (!owned) return;
        if (issuedGeneration != 0 && issuedGeneration != generation) {
            owned = false;
            return;
        }
        assert(active > 0);
        owned = false;
        active--;
    }
    @property size_t inFlight() const nothrow { return active; }
}

@("registration admission bounds global full attempts and concrete-route starts")
unittest {
    auto admission = new RegistrationAdmission;
    bool[8] permits;
    foreach (i; 0 .. 8) {
        import std.conv : to;
        assert(admission.tryStart("irc.example:6697|slot-" ~ i.to!string, 10000));
        permits[i] = true;
    }
    assert(!admission.tryStart("other.example:6697|direct", 20000));
    assert(admission.inFlight == 8);
    admission.release(permits[0]);
    admission.release(permits[0]); // cancellation is idempotent
    assert(admission.inFlight == 7);
    assert(admission.tryStart("other.example:6697|direct", 20000));
    bool extra = true;
    admission.release(extra);
    assert(!admission.tryStart("other.example:6697|direct", 20999));
    assert(admission.inFlight == 7); // route waiters consume no global permit
    assert(admission.tryStart("other.example:6697|direct", 21000));
    extra = true;
    admission.release(extra);
    assert(admission.tryStart("other.example:6697|different-exit", 21000));
}

@("ambiguous DIAL retains its permit until a new incarnation; stale releases cannot free new permits")
unittest {
    auto admission = new RegistrationAdmission;
    admission.observeIncarnation("first");
    bool oldPermit = admission.tryStart("same-route", 10000);
    const oldEpoch = admission.epoch;
    admission.retainUnproven(oldEpoch);
    admission.observeIncarnation("first");
    assert(admission.inFlight == 1 && admission.unprovenCount == 1);
    admission.observeIncarnation("second");
    assert(admission.inFlight == 0 && admission.unprovenCount == 0);
    bool newPermit = admission.tryStart("same-route", 11000);
    admission.release(oldPermit, oldEpoch);
    assert(!oldPermit && newPermit && admission.inFlight == 1);
    admission.release(newPermit, admission.epoch);
    assert(admission.inFlight == 0);
}
