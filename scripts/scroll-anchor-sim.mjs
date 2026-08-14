#!/usr/bin/env node
/**
 * Deterministic simulation of IRC Fiber's reverse-infinite-scroll anchoring
 * math (docs/SCROLL_ANCHORING_MATH.md §2–§6), faithful to the real code
 * paths in MessageList.svelte:
 *
 *   • history prepends (revealBacklogFromMemory / anchoredMutate) —
 *     compensation s := oldS + (H′ − oldH), same synchronous flush;
 *   • trim (maybeTrim) — ONLY while pinned at the bottom;
 *   • realtime appends while scrolled up — DOM frozen (renderEndKey), i.e.
 *     zero geometry change, so the reader cannot move;
 *   • returning to the bottom — snap s := H − V.
 *
 * Model: content height H, viewport height V, scrollTop s with the browser
 * invariant 0 ≤ s ≤ max(0, H−V). The reader's row sits at document offset y;
 * screen offset y − s. "No visual jump" ⇔ y − s unchanged.
 *
 * Invariants checked on every op (exact, ε = 1e-6):
 *   A. browser invariant;
 *   B. pinned ⇒ s = max(0, H−V);
 *   C. scrolled-up history load ⇒ reader screen offset AND anchor (H−s)
 *      preserved exactly;
 *   D. scrolled-up realtime ⇒ geometry frozen (H and s unchanged).
 */
const V = 400;            // viewport height (px)
const SEED = 0xC0FFEE;

function mulberry32(a) {
  return function () {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rnd = mulberry32(SEED);
const ri = (lo, hi) => lo + Math.floor(rnd() * (hi - lo + 1));

/** Mixed row heights: most rows 18–40px, 15% are ANSI-art rows 60–160px. */
function rowHeight() { return rnd() < 0.15 ? ri(60, 160) : ri(18, 40); }

class Model {
  constructor(V) {
    this.V = V;
    this.H = 0;
    this.s = 0;
    this.readerDocOffset = 0;
    this.pinned = true;
  }
  clamp() { this.s = Math.min(Math.max(this.s, 0), Math.max(0, this.H - this.V)); }
  /** The code's anchoredMutate: measure, mutate, compensate, one flush. */
  anchored(mutate) {
    const oldH = this.H, oldS = this.s;
    mutate();
    this.clamp();
    const delta = this.H - oldH;
    if (delta !== 0) this.s = oldS + delta;
    this.clamp();
  }
  /** History prepend above the viewport (the compensated load-more). */
  prepend(heights) {
    const d = heights.reduce((a, b) => a + b, 0);
    this.anchored(() => { this.H += d; });
    this.readerDocOffset += d;        // inserted above the reader
  }
  /** Trim while pinned: drops rows above the viewport; view stays pinned. */
  trimWhilePinned(heights) {
    const t = heights.reduce((a, b) => a + b, 0);
    this.anchored(() => { this.H -= t; });
  }
  /** Realtime while scrolled up: renderEndKey freeze — no geometry change. */
  realtimeWhileReading(heights) {
    const a = heights.reduce((a, b) => a + b, 0);
    void a; // frozen: the DOM is NOT touched (ChatInfinite.frozenRenderEndWhileScrolledUp)
  }
  appendPinned(heights) {
    const a = heights.reduce((a, b) => a + b, 0);
    this.anchored(() => { this.H += a; });
    this.snapToBottom();
  }
  snapToBottom() { this.s = Math.max(0, this.H - this.V); }
  screenOffsetOfReader() { return this.readerDocOffset - this.s; }
}

const m = new Model(V);
let violations = 0, ops = 0, historyLoads = 0, frozenAppends = 0, trims = 0, pinnedAppends = 0;
const MAX_OPS = 20000;

// Open a channel: 600 rows, at the bottom.
const initial = Array.from({ length: 600 }, rowHeight);
m.H = initial.reduce((a, b) => a + b, 0);
m.snapToBottom();

for (let i = 0; i < MAX_OPS; i++) {
  const roll = rnd();

  // 1. Position: scroll up into history, pick the reader's row (real scroll).
  if (roll < 0.45) {
    m.s = Math.max(0, m.H - m.V) * rnd();
    m.pinned = m.H - m.s <= m.V + 1e-9;
    m.readerDocOffset = m.s + ri(10, m.V - 30);
  }

  // 2. Baseline for THIS reader, immediately before the mutation.
  const H0 = m.H, s0 = m.s;
  const readerBefore = m.screenOffsetOfReader();
  const anchorBefore = m.H - m.s;

  // 3. Mutate, following the real code's rules.
  if (roll < 0.45) {
    m.prepend(Array.from({ length: ri(100, 250) }, rowHeight));   // C: history load
    historyLoads++;
  } else if (roll < 0.6) {
    m.snapToBottom(); m.pinned = true;                            // B: trim while pinned
    m.trimWhilePinned(Array.from({ length: ri(100, 200) }, rowHeight));
    trims++;
  } else if (roll < 0.8) {
    m.realtimeWhileReading(Array.from({ length: ri(1, 30) }, rowHeight)); // D: frozen
    frozenAppends++;
  } else if (roll < 0.9) {
    m.snapToBottom(); m.pinned = true;                            // B: pinned prepend+trim
    m.prepend(Array.from({ length: ri(100, 200) }, rowHeight));
    const t = ri(0, 120);
    if (t > 0) m.trimWhilePinned(Array.from({ length: t }, rowHeight));
    historyLoads++;
  } else {
    m.appendPinned(Array.from({ length: ri(1, 5) }, rowHeight));  // B: pinned realtime
    pinnedAppends++;
  }
  ops++;

  // 4. Invariants.
  if (!(m.s >= 0 && m.s <= Math.max(0, m.H - m.V) + 1e-9)) {
    console.error('VIOLATION A (browser invariant)', { s: m.s, H: m.H, V: m.V }); violations++;
  }
  if (m.pinned) {
    if (Math.abs(m.s - Math.max(0, m.H - m.V)) > 1e-6) {
      console.error('VIOLATION B (pinned, not at bottom)', { s: m.s, H: m.H, V: m.V }); violations++;
    }
  } else {
    if (roll < 0.45) {
      // C: history loaded under a reading viewport.
      if (Math.abs(m.screenOffsetOfReader() - readerBefore) > 1e-6) {
        console.error('VIOLATION C (reader moved on history load)', { before: readerBefore, after: m.screenOffsetOfReader(), s: m.s, H: m.H }); violations++;
      }
      if (Math.abs((m.H - m.s) - anchorBefore) > 1e-6) {
        console.error('VIOLATION C (anchor moved on history load)', { before: anchorBefore, after: m.H - m.s }); violations++;
      }
    } else if (roll < 0.8) {
      // D: realtime while reading must be a geometry no-op.
      if (m.H !== H0 || m.s !== s0) {
        console.error('VIOLATION D (geometry moved under reader)', { H0, H1: m.H, s0, s1: m.s }); violations++;
      }
    }
  }
  if (violations > 5) break;
}

console.log('────────────────────────────────────────────────────────────');
console.log('Scroll-anchor simulation (viewport 400px, seeded RNG)');
console.log('────────────────────────────────────────────────────────────');
console.log(`  ops executed        : ${ops} (history ${historyLoads}, trim ${trims}, frozen-appends ${frozenAppends}, pinned-appends ${pinnedAppends})`);
console.log(`  content height      : ${m.H.toFixed(1)}px (${(m.H / m.V).toFixed(1)} viewports)`);
console.log(`  anchor (H − s)      : ${(m.H - m.s).toFixed(1)}px`);
console.log(`  violations          : ${violations}`);
console.log(`  result              : ${violations === 0 ? 'PASS — reading position preserved exactly across every history load; pinned stays pinned; frozen realtime moves nothing' : 'FAIL'}`);
process.exit(violations === 0 ? 0 : 1);
