# GlyphSmart — Aristotle one-time derivation for Smart detail glyph selection + 512B compression

## Objective
Derive the offline deterministic algorithm for IRC Fiber Smart detail mode that:
- Selects the optimal glyph alphabet K (12..18 glyphs) covering luma thresholds from image histogram
- Ranks glyphs by `glyphDominatedByByteGap` Pareto frontier at viterbiW sweet spot
- Proves `∃ alphabet K, ∀ cell, cellCost minimal ∧ Σ bytes ≤ 512`

## Hard constants (MUST appear literally)
- `IRC_HARD_LIMIT=512` (frontend/src/lib/img2irc.ts:154) — RFC 2812 hard limit 512 incl. prefix+CRLF
- `IRC_SAFE_PAYLOAD=400` (frontend/src/lib/img2irc.ts:157) — leaves ~112 for PRIVMSG prefix/tags
- `GLYPH_COVERAGES=[0,121/1000,254/1000,273/1000,4945/10000,5055/10000,727/1000,746/1000,879/1000,1]` (img2irc.ts:480)
- `GLYPH_BYTES_SPACE=1` (img2irc.ts:561) — space costs 1 byte
- `GLYPH_BYTES_HALF=3` (img2irc.ts:561) — half-block costs 3 bytes
- `glyphCellCost` at img2irc.ts:476: `|tTop - blend(ct,fg,bg)| + |tBot - blend(cb,fg,bg)| + w*bytes`
- `glyphDominatedByByteGap` at img2irc.ts:482-488: `(|Δct|+|Δcb|)*contrast ≤ w*Δbytes → dominated`
- `LambdaPareto.lean` monotonicity: `fits_upward_closed` — feasible set {λ | longest(λ) ≤ 512} upward-closed because B antitone in λ
- `viterbiW ∈ [0,6] step 0.5` — bisection range (4 iterations, start w=2 sweet spot)

## Theorems to prove (no sorry)
- `optimal_block_coverage r* = (1 + cmax)/3 ≈ 0.4243` — band error minimized
- `bandError cmax r = max(r-cmax, 1-2r)/2` — quantifies 32% improvement of r* over measured ▒ (0.494)
- `dominatedByByteGap` — glyph with higher bytes dominated when Δcoverage*contrast ≤ w*Δbytes
- `fits_512` — after glyph pruning → bisection → width shrink (MIN_IRC_WIDTH=10) → palette downgrade, Σ bytes ≤ 512
- `pareto_optimal` — at viterbiW ∈ [2,4], no alphabet with fewer bytes achieves lower cellCost

## Compression order to prove (deterministic, offline)
1. Glyph pruning first: if alphabet.length > 14, remove most expensive glyphs with minimal Δerror (dominance order)
2. Viterbi bisection: 0..6 with fits_upward_closed, start w=2, 4 iterations
3. Width shrink: pickFitStep shrinks width by 4 down to MIN_IRC_WIDTH=10
4. Palette downgrade: smart → xterm256 → 16
5. Final guard: if still >512 at width=10, viterbiW=6, 16 colors, minimal glyphs ([' ','▀']), emit "Image too detailed for 512B at 10 cols"

## Deliverable
- Deterministic JS ranking + compression order (glyph pruning → bisection → width → palette)
- Constants: optimal_block_coverage=(1+cmax)/3≈0.4243, bandError thresholds
- No runtime Aristotle calls — algorithm baked into frontend/src/lib/aristotleGlyphs.ts as pure function

## Verification
- `grep "theorem fits_512" frontend/wasm-img2irc/lean/GlyphSmart.lean` shows no `sorry`
- `ls /tmp/glyph-smart-result.tar.gz` exists after Aristotle run
