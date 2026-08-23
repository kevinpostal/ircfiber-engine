/// In-memory LRU cache for UserPreferences with bounded size and TTL.
///
/// Eliminates redundant Redis reads when the same session's prefs are
/// loaded repeatedly (sync, buffer switch, etc.) within a short window.
/// Active sessions hit memory; inactive sessions evict naturally via TTL.
///
/// Thread safety: NOT synchronized. Intended for use within a single
/// vibe.d event-loop thread (the gateway's worker fiber). The natural
/// cooperative concurrency of fibers means no locking is needed — only
/// one fiber runs at a time within a thread.
module ircfiber.db.prefs_cache;

import std.uuid;
import std.datetime;
import std.typecons : Nullable;
import ircfiber.db.preferences : UserPreferences;

/// Number of entries before LRU eviction kicks in.
private enum DEFAULT_MAX_ENTRIES = 1000;

/// How long an entry lives without a cache hit before being dropped.
private enum DEFAULT_TTL_SECONDS = 30;

/// Single node in the doubly-linked LRU list.
private final class LruNode {
    UUID key;
    UserPreferences prefs;
    MonoTime lastAccess;
    LruNode prev;
    LruNode next;
}

/// In-memory LRU cache for UserPreferences.
///
/// Typical usage is via `PreferencesRepository` which owns a singleton
/// instance and plumbs get/set/remove into its load/save paths.
///
/// The cache is intentionally simple — no sharding, no async expiry sweep.
/// TTL is checked on every `get()`; expired entries are removed lazily.
/// Eviction (when full) removes the single least-recently-used entry.
final class PrefsCache {
    private {
        size_t maxEntries_;
        Duration ttl_;

        /// Doubly-linked list: head = most recently used, tail = LRU.
        LruNode head_;
        LruNode tail_;
        /// O(1) lookup from key to node.
        LruNode[UUID] map_;
        size_t count_;
    }

    /// Create a cache with the given capacity and entry TTL.
    this(size_t maxEntries = DEFAULT_MAX_ENTRIES,
         Duration ttl = dur!"seconds"(DEFAULT_TTL_SECONDS)) {
        maxEntries_ = maxEntries;
        ttl_ = ttl;
    }

    /// Retrieve cached prefs. Returns `Nullable!UserPreferences.init`
    /// (i.e. `.isNull == true`) on miss or expired entry.
    Nullable!UserPreferences get(UUID userId) {
        auto pp = userId in map_;
        if (pp is null)
            return Nullable!UserPreferences.init;

        auto node = *pp;

        // Lazy TTL check — expired entries are dropped on read.
        if (MonoTime.currTime - node.lastAccess >= ttl_) {
            removeNode(node);
            return Nullable!UserPreferences.init;
        }

        // Promote to head (most recently used).
        if (node !is head_)
            moveToHead(node);

        return Nullable!UserPreferences(node.prefs);
    }

    /// Store prefs in the cache, marking them as most recently used.
    /// If the cache is full (>= maxEntries), the LRU entry is evicted.
    void set(UUID userId, UserPreferences prefs) {
        LruNode node;

        // Update in place if already present.
        if (auto pp = userId in map_) {
            node = *pp;
            node.prefs = prefs;
            node.lastAccess = MonoTime.currTime;
            if (node !is head_)
                moveToHead(node);
            return;
        }

        // Evict the least-recently-used entry when at capacity.
        while (count_ >= maxEntries_)
            evictOne();

        // Create a fresh node at the head.
        node = new LruNode();
        node.key = userId;
        node.prefs = prefs;
        node.lastAccess = MonoTime.currTime;
        node.prev = null;
        node.next = head_;
        if (head_ !is null)
            head_.prev = node;
        head_ = node;
        if (tail_ is null)
            tail_ = node;

        map_[userId] = node;
        ++count_;
    }

    /// Remove a single entry from the cache (called when prefs are saved).
    void remove(UUID userId) {
        auto pp = userId in map_;
        if (pp !is null)
            removeNode(*pp);
    }

    /// Drop every entry. Exposed for testing and emergency reset.
    void clear() {
        head_ = null;
        tail_ = null;
        map_ = null;
        count_ = 0;
    }

    /// Current number of entries (public for testing).
    @property size_t length() const { return count_; }

    // ── internal helpers ──────────────────────────────────────────────

    /// Move an existing node to the head of the list.
    private void moveToHead(LruNode n) {
        // Already at head — no-op.
        if (n is head_)
            return;

        // Unlink from current position.
        if (n is tail_)
            tail_ = n.prev;
        if (n.prev !is null)
            n.prev.next = n.next;
        if (n.next !is null)
            n.next.prev = n.prev;

        // Splice in at head.
        n.prev = null;
        n.next = head_;
        if (head_ !is null)
            head_.prev = n;
        head_ = n;
        // If tail_ was null (single-node case after unlink), this handles it.
        if (tail_ is null)
            tail_ = n;
    }

    /// Fully remove a node from both the linked list and the map.
    private void removeNode(LruNode n) {
        if (n is head_)
            head_ = n.next;
        if (n is tail_)
            tail_ = n.prev;
        if (n.prev !is null)
            n.prev.next = n.next;
        if (n.next !is null)
            n.next.prev = n.prev;

        map_.remove(n.key);
        --count_;
    }

    /// Evict the least-recently-used entry (tail of the list).
    private void evictOne() {
        if (tail_ !is null)
            removeNode(tail_);
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────

@("PrefsCache: basic get/set round-trip")
unittest {
    auto cache = new PrefsCache(5, dur!"seconds"(30));
    auto uid = randomUUID();

    // Miss on empty cache.
    auto got = cache.get(uid);
    assert(got.isNull, "fresh cache must return null");

    // Set and retrieve.
    UserPreferences p;
    p.pinnedChannels = ["net1:#a"];
    p.prefVersion = 42;
    cache.set(uid, p);

    got = cache.get(uid);
    assert(!got.isNull, "must find entry after set");
    assert(got.get.prefVersion == 42);
    assert(got.get.pinnedChannels == ["net1:#a"]);
}

@("PrefsCache: update in place preserves cache position")
unittest {
    auto cache = new PrefsCache(5, dur!"seconds"(30));
    auto uid = randomUUID();

    UserPreferences p1;
    p1.prefVersion = 1;
    cache.set(uid, p1);

    UserPreferences p2;
    p2.prefVersion = 2;
    cache.set(uid, p2); // same key → in-place update

    const got = cache.get(uid);
    assert(!got.isNull);
    assert(got.get.prefVersion == 2, "update must replace value");
    assert(cache.length == 1, "update must not increase count");
}

@("PrefsCache: remove deletes entry")
unittest {
    auto cache = new PrefsCache(5, dur!"seconds"(30));
    auto uid = randomUUID();

    cache.set(uid, UserPreferences.init);
    assert(!cache.get(uid).isNull);

    cache.remove(uid);
    assert(cache.get(uid).isNull, "removed entry must be gone");
    assert(cache.length == 0);
}

@("PrefsCache: LRU eviction evicts least recently accessed")
unittest {
    auto cache = new PrefsCache(3, dur!"seconds"(30));
    auto u1 = randomUUID();
    auto u2 = randomUUID();
    auto u3 = randomUUID();
    auto u4 = randomUUID();

    cache.set(u1, UserPreferences.init);
    cache.set(u2, UserPreferences.init);
    cache.set(u3, UserPreferences.init);
    assert(cache.length == 3, "three entries fit");

    // Access u1 to make it most recently used.
    assert(!cache.get(u1).isNull);

    // Insert fourth entry — should evict u2 (the LRU after promotion).
    cache.set(u4, UserPreferences.init);
    assert(cache.length == 3, "must stay at max after eviction");

    // u2 should be evicted.
    assert(cache.get(u2).isNull, "LRU entry (u2) must be evicted");
    // u1, u3, u4 should still be present.
    assert(!cache.get(u1).isNull);
    assert(!cache.get(u3).isNull);
    assert(!cache.get(u4).isNull);
}

@("PrefsCache: clear empties everything")
unittest {
    auto cache = new PrefsCache(5, dur!"seconds"(30));
    cache.set(randomUUID(), UserPreferences.init);
    cache.set(randomUUID(), UserPreferences.init);
    assert(cache.length == 2);

    cache.clear();
    assert(cache.length == 0);
    assert(cache.get(randomUUID()).isNull);
}

@("PrefsCache: TTL is applied per-entry (not global)")
unittest {
    // Use 1-day TTL — entries should survive a quick get.
    auto cache = new PrefsCache(5, dur!"seconds"(86_400));
    auto uid = randomUUID();

    cache.set(uid, UserPreferences.init);
    // Immediate re-read must hit.
    const got = cache.get(uid);
    assert(!got.isNull, "entry with 1-day TTL must be accessible immediately");
    assert(cache.length == 1, "count after get must remain 1");
}
