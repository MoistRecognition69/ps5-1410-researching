# GLM_Findings.md — WebKit log analysis (2026-11-12 beacons) + V681 assessment

**Date:** 2026-11-12 (evening session)
**Inputs analyzed:** `HANDOFF.md`, `AGENTIC-FINDINGS.md`, `tools/remote-loader/host-beacons.log` (267,816 lines, 13:50–19:54), `host-console.log` (mirror), V681 beacon sample (20:38:54)

---

## 1. What the log actually contains (vs. what the docs said)

| Metric | Value |
|---|---|
| Sessions (`P691-*`, distinct `u=`) | **447** (14:36–19:54, ~30s cadence) |
| `FORGED-1` (write primitive) | **445/447** — routine, near-deterministic |
| `WALK-ok=true` (full chain + VP leak) | **419** |
| Full vtable dumps (`VT-s*`) | 1257 = 419 × 3 beacon groups — exactly consistent |
| Distinct VP samples | ~440 |

The docs describe the primitives as "confirmed once"; the log shows they are **routine** — the entire chain (leak → templating → forge → arbitrary read → vtable leak) lands nearly every session.

## 2. ASLR structure (new, not in the docs)

- All ~440 VP values lie in `0x8033f9b28 … 0x8438ddb28` — a **~1.01GB span** (~14 bits of slide entropy).
- **Every VP ≡ `0x1b28 (mod 0x4000)`** — the slide is **16KB page-granular** (correction of my earlier 32KB statement). Mod 0x8000 there are exactly two phases (0x1b28 / 0x5b28, one 16KB page apart).
- Vtable deltas constant in **every** session: `VP−s0 = 0x170_0B78`, `VP−s3 = 0x170_0478`. Same binary confirmed across all landings.
- HANDOFF's "confirmed addresses" are one-session examples, not constants: heap geometry slides slightly (e.g. session 1PRG3Y: SELF=`0x1000384b40`, FO=`0x10003eb110` vs the common `0x1000380b40` / `0x10003e7110`).

## 3. Option B (DYN / `.dynamic` scan) — effectively failed, and the islands are foreign

- One mapped island at **VP+0x202610** (16:42:47, session 1PRG3Y, stride 0x10000 landing). Fine scan died almost immediately; subsequent sessions hopped from +0x202620 to **+26.8MB** (`off 0x1a82620`) with zero further mapped hits. No `.dynamic` ever found.
- **Proof the island is not module memory:** 1PRG3Y (VP=0x837535b28) read it fine; the very next session 12XE8B (VP=0x836331b28, slide moved −0x1204000) **crashed on its first read at the same offset**. Module pages sit at fixed offsets from VP; foreign mappings re-slide per session. Same 16KB module-relative page mapped in one session and fatal in the next ⇒ the island is foreign.
- Consequence: **islands are one-shot**. Each landing must be fully exploited within its own ~30s session; it will never be at that offset again.

## 4. Option A (SCAN / ELF-magic scan) — did the stride miss the base? Yes, with evidence

### 4.1 Coverage reality (from the beacon cursor history)

- **Dense negative (solid):** every 16KB page from VP down to **−0x97c000 (~9.9MB)** was read exactly once. The in-log history shows cursor `0x0 → 0x770000` swept in one session at 14:51 (~475 mapped pages, all read), the frozen-at-0x770000 resume-loop bug (14:51:56–14:54:34), then page-per-crash to 0x97c000. No ELF magic anywhere, including the island's bottom page at −0x770000.
- **Hop zone:** offs 0x998000–0x3b78000 (~50MB) sampled at **53 candidates ≈ 1 page per MB**. All crashed.
- **The landing:** 19:49:28, session L6E6XO, off 0x3c78000 → abs page **0x8377e8000** (~60.4MB below VP). ≥640KB mapped (36 fine pages verified downward), **no ELF magic** on any checked page including its bottom.
- **Post-island:** stride re-doubled 0x4000→0x100000 in 6 crashes (~3 min); ~8 samples covered the last 3.4MB before the 0x4000000 cap → `BASE-NOTFOUND-0` at 19:54:25.

Total actual coverage of the 64MB range: ≈ 10MB dense + ~60 sparse samples + 36 landing pages ≈ **~4–5% of the 16,384 pages**. `BASE-NOTFOUND-0` is a *sampling* negative, not an exhaustive one. The AGENTIC-FINDINGS claim "the module base is not within 64MB below the vtable" is **not supported at the achieved density**.

### 4.2 The four hints

1. **Islands exist inside the "empty" gap.** The −60.4MB landing proves the 53-crash "unmapped gap" contained a ≥640KB mapping the whole time. It became visible only when a 1MB grid point landed inside it — i.e., sub-1MB mappings can be invisible to the grid.
2. **Grid-phase lock.** All VPs ≡ 0x1b28 (mod 0x4000) and all hop offs are multiples of 0x4000 ⇒ candidate = VP − off always reads the **same module-relative page**. The 1MB hop samples a **fixed 1-in-64 subset** of module pages forever. If the header mapping doesn't intersect that sublattice, re-runs can never find it — the stride didn't cost time, it cost the result. (Foreign islands re-slide, so only *module* pages are phase-locked — but the header is what we're hunting.)
3. **Worst coverage where the base most plausibly is.** Directly below the only island found all day (off 0x3d08000→0x4000000), sampled at ~8 quickly-coarsening strides. If the found island is a code/rodata segment, the header segment is the next island down — a 64–256KB header mapping there had ~25–50% hit odds before failure was declared.
4. **No ≥1MB mapping exists between −9.9MB and −60.4MB** (53 straight 1MB-grid crashes prove this — big text cannot hide from 1MB hops). Combined with the dense negative: the base is not in the vtable's own ~9MB island, not in any ≥1MB island below −60.4MB… it is in a **sub-1MB island** in the hop zone, below the found island, past the cap — or **above VP, which was never ELF-scanned** (upward was only `.dynamic`-hunted).

### 4.3 Also in-log: the RIP attempt
`P691-READD-PRE` at 14:38:47 (session 2XMSDQ) — the V677 lay-forge death at the face re-add, matching the docs. SCAN went live 14:46 with cursor 0x0.

## 5. Fixes for the strided ELF scan

1. **Per-session phase jitter** — random `jitter ∈ {0, 0x4000, …, stride−0x4000}` added to hop candidates (0x4000-aligned so reads stay on page starts). Coverage then accumulates: at 1MB stride, ~64 sessions ≈ 63% odds of hitting the header page, ~130 ≈ 87% — vs 0% forever for the fixed grid.
2. **Landing handler** — on MAPPED: hexdump the first page (beacon raw bytes), walk **up** to the island's top edge as well as down, check magic both ways. ~30s at ~30ms/read ≈ hundreds of reads is enough to sweep a whole island in-session (islands are one-shot).
3. **Finer re-sweep** — stride 0x10000 (64KB) over the hop zone + the 3.4MB below the island guarantees catching any island ≥64KB (~800 crashes ≈ 7h overnight); 0x40000 ≈ 200 crashes ≈ 2h.
4. **Upward ELF scan** — never attempted; same probe pointed up from VP.

## 6. V681 (20:38:54 sample) — parsed

- The HIT hexdump is a reclaimed 192B buffer: byte 0 = `0x01`, **+0x58 = `0x100088c970` (T58)**, +0x60 = 0, **+0x68 = `0x10007e2220` (W68)**, rest zero (b34 and b35 identical).
- Both pointers are **heap-family (`0x1000_`)** — W68 is the WeakPtr seed ("IM") for the walk chain. **No module-side anchor; no direct help for the ELF scan.**
- Useful takeaway: the full-192B hexdump instrumentation should be kept — a `0x8x`-family qword in any reclaimed buffer would be a direct code-segment leak that makes the ELF scan unnecessary. This landing contained none (the freed FontFace structures carry only heap pointers).
- Recommended extension: hexdump ~256B around **FO and IM** via the arbitrary read — those engine objects almost certainly contain multiple vtable/function pointers beyond FO+0; each distinct `0x8x` pointer is an extra code anchor, and distinct vtables at distinct RVAs enable base triangulation without the ELF header at all.

## 7. Bottom line (afternoon analysis)

The full primitive chain is routine (445/447 forges, 419/447 walks). The base-finding problem is not that the base is unreachable — it is that the scan's *sampling design* was structurally blind: a phase-locked 1MB grid over a layout that provably contains sub-1MB foreign islands, with the most promising zone (below the one island found) blitzed at coarsening strides until a cap declared failure. Fix the sampling (jitter + landing handler + finer sweep + upward direction), or sidestep it entirely by leaking more code pointers from engine objects and triangulating the base from vtable deltas.

---

# EVENING SESSION (V678V2 + V683) — 2026-11-12, ~21:00–23:15

## E1. The reclaim died and was revived (V681 recipe)

At ~19:54 the p691 reclaim pattern (32×192B single-size spray, one 80ms window, wrapper GC'd) stopped landing **for every probe family**: V680 NOLEAK'd from 20:21 onward (even after adopting ladders/checks), V678V2 NOLEAK'd 6× consecutively, and a **console restart did not fix it**. Bare diagnostic V681 still leaked at 20:38 — the only post-19:54 success. Ported V681's exact recipe into V678V2 Step 0/1 (size-ladder spray as pressure, `document.fonts.check('1em v1')` consumption in the getter, `__alive` wrapper retention, multi-timing retry at 60/140/400/700ms with `fired`/`sp` diagnostics): **100% leak+walk rate restored for the rest of the night.** The reclaim pattern is boot-state-sensitive, not probe-code-sensitive.

## E2. V678V2 pass 0 rewrote the map below VP

Built v678-v2 (fresh keys/prefix, per-pass random phase, landing hexdump, ISL up-sweep, zone mode, upward dir, 128MB cap). Sim-verified first (caught an up-sweep that scanned *down* — wrong half of the island). Pass 0 results (module-relative offsets below VP):

| Region (off below VP) | Finding |
|---|---|
| 0 → 0x770000 | data/rodata island: fine-swept, all mapped, no ELF |
| 0x770000 → 0x41d4000 | ~58MB "gap": 1MB-grid hop crashes, no landings — *see E5: this is execute-only text* |
| **0x41d4000 → ~0x52e0000** | **readable "text island"** — landing dump = ARM64 opcodes (0x60xxxxxx pattern), 17.5MB fine-swept, top edge mapped by ISL up-sweep. **V678's 64MB cap missed this by 1.9MB** — the old "definitive negative" was wrong by a hair |
| 0x52e0000 → 0x5318000 | 224KB gap — **page-verified empty** (zone sweep: 14/14 pages crash, `ZONE-EXHAUSTED-NOTFOUND`) |
| **0x5318000 → 0x5424000** | **zero island** — ~1MB all zeros, top page all-zeros where seg0/ehdr would sit |
| 0x6320000 | fill-pattern island — `0xfff81675` repeating ×4 (poison/fill), landed at 97.6MB |

**Verdict: no `\x7fELF` exists anywhere below VP — the loader wipes header pages.** The magic-scan route is dead by Sony's design, not ours. Best remaining candidate under the seg0 hypothesis: **BASE = VP_page − 0x5424000** (zero-island bottom), pending verification.

## E3. Old-island verdict

Pass 0 sailed through the old −60.4MB island offset with no landing → that island was foreign/session-specific, consistent with the +0x202610 island (which vanished in the next session after its landing — islands re-slide per boot).

## E4. V683 pointer-sift (current probe)

Built v683 (chain identical, V683 keys/prefix; Step 9 = RTTI probe, function-page probes, data-island sift for 16KB-aligned self-pointers with `__dso_handle` direct-hit check). Sim-verified against extracted code — caught two on-device-fatal bugs pre-flight: family range `LO/HI` off by 16× (10 hex digits vs the real 9-digit module family), and a `{32}`-char regex guard on a 64-char read that would have silently killed the RTTI deref.

**First on-device results (23:08):**
- `RTTI-hex = ffffffffffffffe0 0000000000000000` → vtable[-2] = −32 (secondary-vtable offset-to-top), vtable[-1] = **0** → **WebKit built -fno-rtti** — typeinfo identity closed cleanly (guard worked, no crash).
- `FPROBE-s0` printed its pre-crash marker, **then crashed reading the function entry** → see E5.

## E5. Execute-only text — the gap was never empty

The FPROBE crash at s0 (a live dispatch target the engine calls constantly) means text pages are **PROT_EXEC-only: reads fault, execution doesn't**. All four leaked vtable function pointers live inside the "58MB gap" (s0 at VP−0x1710B78, s2 at VP−0x324C3D8, s6 at VP−0x2ABC728): **the gap is the vtable-module's execute-only text segment.** The entire evening's "unmapped gap" was a readability artifact — we mapped readability, not presence. Consequences:
- No code bytes are obtainable via the data-read primitive (FPROBE s2/s3/s6 will each burn one session confirming; exp list persists).
- The readable "text island" at −65MB is therefore a *different* module's readable text (explains the never-quite-one-image layout).
- The module's true span: data/rodata island + exec-only text; base is at/below the text — the sift's `__dso_handle` (a *data* symbol, readable) is the definitive base oracle, unaffected by exec-only text.

## E6. Tooling built this evening (all in tools/remote-loader unless noted)

| Tool | Purpose |
|---|---|
| `scan-watch.ps1` | colored live watcher (V678V2/V678V2Z/V683): gray ticks, yellow landings/HITs, cyan RTTI/FPROBE, green BASE/DSOHIT |
| `dismiss_dialog.py` (PS5-14.10-Research/tools) | focus Chiaki + PostMessage Enter=X — the *proven* dialog press |
| `auto_continue.py` | beacon-driven dialog dismiss: silence >12s = crash → press X **immediately** (the ~40s is session-start→dialog, not crash→dialog); retries only if no new BOOT |
| `v683.html` | pointer-sift probe (dispatcher current) |
| `v678-v2.html` / `v678-v2-wide.html` / `v678-v2z.html` | wide build live/parked; wide cursor preserved at 0x63bc000 under v678v2_* keys |

**PS5 guide-cache doctrine learned the hard way:** OK-click reloads re-use the current page URL and *never* re-fetch the dispatcher; close/reopen follows the dispatcher but can serve cached pages; **only a fresh filename reliably busts the cache** (v678-v2z/v683 worked first try; cb= params did not).

**Session protocol refinements:** post-crash, OK-click (or auto_continue) suffices — the dead process is replaced automatically (3-second gap between crash and next BOOT proved it; the NOLEAK streak was reloads into a *live* process). Full close/reopen is only required after non-crash session ends (spent UAF in a live process).

## E7. Standing next steps

1. V683 sift: ~2h of loop sessions over the data island; watch for green `DSOHIT` / yellow `HIT-` clusters.
2. If sift yields the base: cross-check against the seg0 hypothesis (VP−0x5424000); compute VT-RVA; RIP landing becomes computable (though gadget hunting needs readable text — the exec-only discovery means RIP work may need the readable text island's module instead, or an exec-only-tolerant technique).
3. Parked wide scan (cursor 0x63bc000) can resume anytime for the census below 100MB→128MB.

## E8. Sift status & discoveries (00:05, 2026-11-13)

**FPROBE complete — exec-only quadruple-confirmed.** All four probes (s0/s2/s3/s6, 23:08–23:13) printed their pre-crash marker and faulted on read. The readable-data primitive cannot touch any of the vtable's function entries; every "unmapped" result inside the exec-only gap is a readability artifact.

**V683b session self-termination works.** 12+ clean unattended cycles: sift budget (1600 reads) → `SIFT-SUICIDE` (deliberate fault at 0x414100000000) → memory dialog → auto_continue presses X → fresh session (BOOT gaps 14–40s). No stall observed. The suicide is sequenced strictly after cursor persistence — verified it cannot truncate sweep work.

**Read-rate discovery.** Warm style-reads run at **~2ms, not the ~30ms estimated from beacon cadence** (beacon overhead inflated the estimate). Each session's 1600-read budget exhausts in ~3 seconds; the sweep is **session-cycle-bound** (walk ~25s + dialog ~40s), not read-bound. The whole down-pass is ~3.6 minutes of pure read time. The 1600 budget is the throttle — a candidate for v683c.

**Sift tally at 00:05** (~61% of down-pass, off ≈ 0x4653e8 of 0x760000): 44 sessions, **94 hits, 28 distinct deltas, one stable candidate**:

| delta | sessions | shape | status |
|---|---|---|---|
| **−0x1928000** | 2 | 24× strided (0x8C0) table in one session | leading `__dso_handle` candidate |
| all others (27) | 1 each | varied | foreign-slid (other modules' segments) |

Cross-session delta repetition is the discriminator: foreign pointers would need two independent ~1GB-entropy slides to coincide at 16KB granularity (~1/65,000 odds), so ×2 is effectively proof of module-relativity. No `DSOHIT` yet — the seg0 hypothesis (VP−0x5424000) remains unsupported by any data pointer.

**The confirm-pass endgame (v683c, planned).** The sweep is one-pass, so a module self-pointer observed once gains a second observation only from a *different* qword holding the same value. A second sweep of the same ground under fresh slides would flip every true self-pointer to ×2 while foreign ones scatter — yielding the module's complete self-pointer inventory. Cheap variant: re-read just the ~94 recorded hit addresses (one session at 2ms/read); v683c will do this with a raised budget. Survivors = candidate set for base + `__dso_handle`.

## E9. Confirm-pass results (00:35, 2026-11-13) — the module's landmark map

`SIFT-DONE-ALL` at 00:31:20 (both passes: 80 sessions, 102 hits, 35 deltas). v683c confirm-pass deployed (all 102 hit addresses baked in as module-relative offsets; one 80-byte neighborhood read each): **`CONFIRM-DONE-n=102` at 00:35:19** — the entire confirmation in one session, ~3 seconds of reads.

**Verdict: 58 of 102 hits are module self-pointers — 24 stable module-relative landmarks.**

| landmark | refs | reading |
|---|---|---|
| **−0x1928000** | **×32** | dominant anchor ~25.5MB below vtable: strided 0x8C0-byte table whose entries hold it plus deep code pointers (−0x301dd40, −0x3246470 — the latter within bytes of s2's known −0x324C3D8) and a six-pointer cluster into the −0x192xxxx region |
| −0x974000 | ×3 | aligned target |
| −0x11f8000 | ×2 | aligned target |
| 21 more (−0x820000 … −0x2ee8000) | ×1 each | **a ladder of 16KB-aligned segment starts — the exec-only text's internal segmentation map** |

**Conclusions:**
1. The "empty gap" is a chain of exec-only segments whose boundaries are now mapped by the ladder (deepest aligned: −0x2ee8000; deepest known code: s2's −0x324C3D8 region).
2. **No qword names the image base** — no `__dso_handle` exists in the swept data island; base is bounded below s2's region (≥51MB below the vtable). The seg0 hypothesis and the simple handle hunt are both closed, conclusively.
3. **Strategic reframing: exec-only text caps what BASE would buy for this module** — its code can never be read, so no gadget mining regardless of base. The RIP path runs through the **readable text island** (other module's 17.5MB at −0x41d4000..−0x52e0000), which the primitive CAN dump (~250k reads ≈ minutes of read time across ~10 sessions).

**Three ranked next moves:**
- **(a) Gadget-mine the readable text island** — **→ V684 built and deployed (00:45, 2026-11-13)**. Dumps the full 17.5MB in 80-byte reads, 32-batch beacons (`Z`-compressed zeros), 6000 reads/session, suicide-cycle, `DUMP-DONE` halts. ~150 sessions / ~60–75 min. Offline pipeline ready: `decode_dump.py` reconstructs the binary → `text-island.bin` → ARM64 gadget scan.
- **(b) Decode one full 0x8C0 table entry** — read 2240 bytes at the strided table (28 reads) to identify the structure owning the 32× −0x1928000 anchor (font/WebKit metadata? registration table?).
- **(c) Probe the −0x1928000 region's readability** — the old 1MB grids sampled only phase-locked pages; sub-islands between grid points may be readable data. If readable, dump the anchor page and its cluster (the most-referenced page in the module).

## E10. Overnight scan results (2026-11-13, 01:10–08:15)

**624 sessions, 5 complete passes** (pass 5 active at 08:15, cursor 0x2878000, phase 0xf0000). The rollover-suicide fix worked perfectly — all 5 `PASS-ROLLOVER` events were followed by `SCAN-SUICIDE` and auto-resumed unattended. 42 `SCAN-MAPPED` landings, 393 `ISLDUMP` batches (16B/4KB samples from fine sweeps).

**Key discovery: the text island is STILL at `−0x41d8000`.** The scan re-landed on it during the overnight passes, dumping the exact same ARM64 bytes (`4e1a0060 341c0160…`) as the original ELF-scan landing. The D6 diagnostic's crash was a single-session fluke, not a moved island.

**Complete overnight island map** (22 unique module-relative landing deltas):

| delta | landings | content |
|---|---|---|
| **−0x3268000** | **×5 (stable)** | ASCII strings ("edlegitimatesubs…") — multi-pass confirmed |
| **−0x41d8000** | ×1 | **ARM64 code** (same bytes as original landing) |
| −0x51d0000 | ×1 | ARM64-typed (`0b4e7280…`) |
| −0x5330000 | ×1 | ARM64-typed (`0105a86b…`) |
| −0x3284000 | ×1 | binary (`011b033b…`) |
| 17 more | ×1 each | data: UTF-16 strings, tables, zeros, fill patterns |

**Architecture note:** the ISLDUMP dump-along-the-way design (added mid-night at user's suggestion) — 16 bytes per fine-swept page, batched 32/beacon, zero-compressed — proved the right overnight strategy: the scan never stalls, every island gets sampled, and the morning analysis has complete content for island identification.

**The read-length question is now open:** last night's "80-byte reads kill the serializer" was actually an unmapped-address crash. A proper length test (16/32/48/72/80 bytes at a verified island address) determines the full dump's throughput — 80B = 4× faster than 16B.

## E11. VP_RVA found from source analysis (2026-11-13, ~09:00) — BASE COMPUTABLE

**The other agent's commit c3584c5** (`ZigZagBoi1/PS5-14.10-Research`) contains a full COOP analysis from WebKit source code (`docs/COOP_ANALYSIS.md`, now on disk at `PS5-14.10-Research/docs/COOP_ANALYSIS.md`):

**`VP_RVA = 0x724DB28`** — the CSSFontFace secondary vtable's static offset from the module base. This is the number the ELF scan, pointer sift, and confirm pass were all hunting for. With it:

```
WebProcess_base = VP − 0x724DB28
```

**Everything the source analysis provides:**

| Item | Value | Match to our device data |
|---|---|---|
| **VP_RVA** | **0x724DB28** | → BASE = VP − 0x724DB28 (computable per session) |
| PV_RVA | 0x724DAC0 | Primary vtable (ActiveDOMObject, 11 slots) |
| offset_to_top | −32 (0xFFFFFFFFFFFFFFE0) | ✓ matches our RTTI probe exactly |
| s3 = fontStateChanged | `m_loadedPromise->resolve(*this)` on Success | ✓ matches our method identification |
| FontFace layout | +0x30 = m_backing, +0x38 = m_loadedPromise | The write-chain targets |
| PS5 vtable check | `cmp [rdi], rax; jnz fail` at reclaim | Explains why reclaim needs matching vtable |
| Gigacage/IsoHeaps | disabled on PS5 | JS Butterfly in same heap as C++ objects |
| **Path B** | addrof via read → DataView → one COOP write → ARW | **Recommended next step** |

**Strategic pivot: the text island dump is obsolete.** The exec-only text of the vtable's module can't be read — but we don't need to read it. We need to compute `BASE + gadget_RVA` and execute through it. The other agent's `p810-gadget-scan.html` already has gadget RVAs from source.

**Next step: verify VP_RVA on-device** — read at the computed base address to confirm the module is where the formula says it is. If verified: compute BASE, derive gadget addresses, begin the Path B addrof chain.

## E12. VP_RVA VERIFIED ON-DEVICE (2026-11-13, 08:47) — BASE SOLVED

Session 5YMTE1 (v687 `?v=3`) — all five tests passed:

| Test | Result |
|---|---|
| T5 (vtable at VP) | 9 slots, all deltas exact: **s3 = −0x1710478** (corrected fontStateChanged) |
| T3 (PV at BASE+0x724DAC0) | 176 bytes readable, slot0 = 0x8319b4450 (function ptr) |
| **LM1 (BASE+0x6FA5A5C)** | **`"Function\0TDZFail"` — byte-exact** |
| **LM2 (BASE+0x6FB1E17)** | **`"JSGlobalProxy\0JS"` — byte-exact** |
| T1 (BASE) | fired at 0x82d888000 (base page mapped) |

**WebProcess_base = VP − 0x724DB28 is confirmed with string-level certainty.**

Per-session from the walk chain alone:
```
BASE            = VP − 0x724DB28
fontStateChanged = BASE + 0x5B3D6B0
noop            = BASE + 0x4001750
destructor      = BASE + 0x5B3CFB0
```

**The base-finding mission is SOLVED.** Not by scanning, not by dumping — by the other agent's source analysis (COOP_ANALYSIS.md) + our on-device verification chain working together.

**Correction from other agent (accepted):** s3 delta is `0x1710478`, not `0x1700478` — the original AGENTIC-FINDINGS.md had a digit-grouping error. All our on-device measurements consistently showed `0x1710478`; the source doc propagated the wrong grouping.

**Next: Path B addrof chain** — use the arbitrary read to find JS objects (JSCell → Butterfly → element pointers), locate a DataView's buffer pointer, then one COOP fontStateChanged write through the forged vtable → arbitrary R/W → RIP control.

## E13. PATH B IDENTITY CERTIFIED — FACE-IDENTITY-OK (2026-11-13, 09:34)

Session 3B00VR (v688 v10): the full chain green in 28s, crash-free:
```
LEAK → A-DEAD → v9 full-b1 scan → SELF → VTAB → WALK-ok → BASE=VP−0x724DB28 →
L2 → FB (wrapper) → vtable00===VP ✓ weak08===L2 ✓ backing10===SELF ✓ →
FACE-IDENTITY-OK → promise chase → PATHB-DONE
```

### The debugging war (09:07-09:34) — four wrong fixes before the real one
- **v3 cross-session cursor resume** → cursor was boot-poisoned; post-reboot the resumed address was unmapped → instant crash loop → OOM boot storm (A89LND)
- **v5 scan-from-0** → sessions scanned 448K clean then died at a "wall" (distance-110 band) — walls are unmapped heap-slice edges; console tolerates ~1 crash/boot post-reboot
- **v7 crash-tunneling** → mechanism worked (PH3-ADVANCE) but the wall is multi-window — can't tunnel within the crash budget
- **v8 tail-first** → tail is entirely unmapped (N29867 instant death)
- **v9 THE REAL FIX: the scan grid covered b1 ∈ [0,0x7E] only — HALF the byte.** Morning SELF had b1=0x00 (lucky page-start chunk); every failed boot's SELF had b1 > 0x7E (e.g. 0x100037c180, b1=0xC1) — structurally invisible. Full grid: 256 b1 × 16 b0 = 4096/window; ~905K over the mapped band ≈ 9s at post-reboot scan speed (~100K/s, 6× the morning boot's rate)
- Console fragility law: post-reboot, ~1 WebProcess crash → system degrades to instant-death boot storm; memory warnings follow. Sessions that complete cleanly (PATHB-DONE + RTT reload) are sustainable; crash churn is not.

### Wrapper layout MEASURED (corrects COOP_ANALYSIS.md estimate)
```
+0x00 vtable = VP (0x724DB28 RVA)     +0x08 impl-backptr = L2 (mutual)
+0x10 m_backing = SELF ✓              +0x18 m_loadedPromise candidate
+0x20 0                              +0x28 epoch (shared w/ impl+0x20)
```
The wrapper and reclaimed CSSFontFace form a closed 2-object cycle; the walk's client IS the wrapper.

### COOP write-target map (real addresses, session 3B00VR)
- wrapper FB, promise obj (e.g. 0x1000871200), resolve-callback wrapper (e.g. 0x10007a84e0) with module vtables (BASE+0x72AB340 family) and JSC-side pointers (0x7ef28b5b5/5b7/5b6) — the addrof leads
- PROMISE-CALLBACK-OWNER-FAIL (expected): the callback links to JSC cells, not the raw C++ FB — the "deterministic carrier" is the next research question

### Tooling/protocol notes
- PS5 reboots don't clear guide-app localStorage (cursors/caches persist across boots — this caused the v3 storm; v9+ uses pattern-verified caches and namespace-bumped resume keys 'dead3')
- v688_self caching works: cache miss → clean fall-through → scan re-finds (~24s)
- scan-watch green lines: FACE-IDENTITY-OK / PATHB-DONE / SELF-0x / CLIENT-0x

**Next: addrof** — chase the JSC pointers from the callback wrapper (0x7ef28b5bX family), or scan the bmalloc band for the marker DataView's unique qwords (0xDEADBEEFCAFEBABE at buffer+0x00), → JSDataView cell → certify via the ?dv= flow → then design the single COOP write.

## E14. ADDROF-CERTIFIED — READ CHAIN COMPLETE (2026-11-13, 09:59)

Session TFR4OD (v688 v15): the full pipeline certified end-to-end in ~10s, all cached:
```
UAF leak → walk (VP) → BASE → wrapper identity (3 gates) →
marker buffer → calibrated cell scan → JSDataView cell → 6-marker verification →
ADDROF-CERTIFIED-cell=0x1000880140-vectorFieldAddr=0x1000880150
```

### The oracle — fully decoded (v12→v15 calibration campaign)
- **`chk(c) = TRUE iff A ≤ c ≤ B`** where (A,B) = the two uint32s at the probe address (inclusive); inverted pair (A>B) → always FALSE; test codepoints must be ≤ 0x10FFFF (fromCodePoint throws → null)
- Calibrations (device-measured): PH3 (0x1000,0x2000)→(T,F,T,F); CAL1 (0x100,0x40)→FFFF; CALA (0,0x200000)→Tnnn (n = out-of-range cps); v14 primary (0x10,0x40)→FTTF ✓ predicted & confirmed
- The cell's probeable windows: +0x14=(band byte-4, 0x40) both edges pinned; +0x1C=(0,0x20) B-edge pinned; +0x18=(0x40,0) inverted filter

### The v12-v14 walk-failure root cause (self-inflicted alias)
- Marker spray PATs at +0x88 aliased the SELF scan's +0x38 probe (0x88−0x38=0x50, 16-aligned → on-grid)
- New boot + cache miss → PH3 scan hit the marker pattern at b2-distance 1 (real spray at ~87) → fake SELF=marker+0x50 → VTAB-NONE → walk dead → fake cached
- **v15 fix: PATs at +0x90/+0xC0 — alias targets (marker+0x58/+0x88) are mod-16=8 → permanently off-grid.** Stale fake caches self-heal (verify hits zeros → cleared)

### JSDataView cell layout — VERIFIED on-device (was ?dv= assumption)
```
+0x08 butterfly = 0        +0x10 m_vector → buffer+0x20    (THE COOP WRITE TARGET)
+0x18 m_length = 0x40      +0x20 m_byteOffset = 0x20
```
Certified via 6 independent marker reads (C/A/B/D/E/F all exact). Write target beaconed per session: `vectorFieldAddr = cell+0x10`.

### Status after E14
| Info leak | Arb read | Module base | Wrapper identity | **addrof** | COOP write → ARW | RIP |
|---|---|---|---|---|---|---|
| ✅ | ✅ | ✅ | ✅ | ✅ | ⏳ **next** | ⏳ |

**Next: the COOP write** — forge client table → fake impl → fake client → fake vtable → fontStateChanged → one write to cell+0x10 → retarget vector → full ARW.

## E15. FIRST ENGINE WRITE INTO FORGED STRUCTURE — WITNESSED (2026-11-13, 10:25)

Session B4VLTA (v688 v16g): the engine's addClient INSERT into our forged client table — witnessed via JS-diff of our own buffer:
```
WIT-insert-WRITE:
  @MBUF+0x18 (metadata qword): 0x100000000 → 0x200000000   = keyCount 1→2
  @MBUF+0x38 (bucket[2]):      0 → 0x10007e0b40            = the SET's WeakPtrImpl inserted
V16F-TBL58-after: unchanged (no rehash at 50% load) → our table stays authoritative
→ V16-DONE → ADDROF-CERTIFIED (the full flow completes with the write test embedded)
```

### The v16 campaign ledger (all empirical)
| Probe | Trigger | Result |
|---|---|---|
| v16b | fonts.load(v1) / status / loaded-getter / new-face-add / **faces[zi].load()** | T1-T4 nowrite; **T5 crashed synchronously** (the load walks +0x58) |
| v16c | load() control, REAL table | **still crashed** — the load machinery faults on our face bytes, not our chain |
| v16d | broad face-clean (+0x08-0x57, +0x70-0xB0) | the `.loaded` getter crashed — the clean broke followed fields (+0x82=3 is load-bearing) |
| v16e | surgical clean + `.loaded.then()` witness | the **witness itself crashed** pre-clean — 3 promise-adjacent crashes → the load/promise FIELD MAP is a source-lane question |
| v16f | document.fonts.add(faces[zi]) re-add, 1-bucket table | **HUNG** — mask=0 makes the hash probe structurally infinite (every probe → slot 0) |
| v16g | same, 4-bucket table (mask=3, size=4) | **INSERT WITNESSED** ✓ — the write lands, the session survives |

### State after E15
- The fake chain format is PROVEN: 4-bucket table, fake impl {L2-copy, m_ptr patched}, fake client {FB-copy, vtable+promise patched}, noop vtable slots, neutered promise
- The SET is a live client in OUR table — any face status transition now dispatches to our fake vtable (slot 3 = fontStateChanged gadget → resolve(*this) → a fully-controlled value at a positioned destination)
- **Open: the transition trigger** — faces[zi].load() crashes on 3 different field subsets (sources? status? the promise path) — the exact CSSFontFace::load()/fontLoaded/setStatus field-read map goes to the source lane
- The insert proves the table machinery; the dispatch needs only the transition

**Next: the dispatch trigger** — with the source lane's field map (what load() reads before the notify), craft the face bytes so the transition completes; OR find a non-load transition path. Then: the gadget's resolve write → aimed at cell+0x10 → ARW.

## E16. THE LOAD-PATH WALL (2026-11-13, 10:29) — SOURCE-LANE HANDOFF

v17a (session LD5IJZ): the +0x38 pattern-kill theory was wrong — the control load crashed even with the PH3 qword zeroed. Combined with v16b/c/d/e, the picture is final:

**`CSSFontFace::load()` cannot run on our forged face** — it dereferences the `+0x28-0x48` band (sources, file) which must contain REAL object pointers. Zeroing any subset crashes on a different field; garbage crashes; the original values died with the freed face (only the face object was freed — the field objects live, but their addresses are unrecoverable through any known reference chain). This matches ng643's poisoning law verbatim ("+0x28-0x48 are followed/dereferenced — kill even with valid heap pointer").

**The certified base is unaffected**: the read chain, the insert-witness (the engine write into our forged table), the SET as a live client — all stable. Only the TRANSITION TRIGGER is blocked.

### Handoff to the source lane (the other agent, WebKit 605.1.15 source)
1. **CSSFontFace::load() preconditions**: the exact field-read order before any status change — which offsets must hold valid pointers (sources Vector? file? the +0x18/+0x20 obfuscation fields?), and what minimum values let the call complete or fail GRACEFULLY
2. **Alternative transition paths**: is there ANY status-changing path on a CSSFontFace that doesn't dereference +0x28-0x48? (fontLoaded() callers besides load(); the FontFaceSet's family-merge interactions; the source-completion path that fired the original .then continuation)
3. **LoadedPromise::resolve semantics**: the value-offset in the promise (what resolve(*this) writes and where) — needed to aim the eventual write at cell+0x10
4. **The status byte**: confirm +0x82's encoding (3 = ?; 0 = ?) and what value starts a transition

### Meanwhile (probe lane)
- v17.html keeps cycling: the certified chain + the insert-witness (the SET joining our table every session) — a stable, crash-free pipeline
- If the source lane finds a safe transition path → v17b adds it → the dispatch → the witnessed resolve write → v17c aims at cell+0x10 → ARW

## E18. THE DISPATCH CAMPAIGN COMPLETE LEDGER (2026-11-13, 11:00-11:26) — HANG LOCALIZED

**The load-path dispatch (`faces[zi].load()` → pump → setStatus → iterateClients) hangs BEFORE any client vtable dispatch** — proven by crash-bisection (v17q: garbage at the ref() slot → NO crash → the engine never called it). The hang is in the WeakHashSet's `computeSize()` → `removeNullReferences()` → `removeIf()` — the unconditional pre-dispatch cleanup — on our forged m_clients.

### Every hypothesis tested (v17b→v17r, on-device)
| # | Hypothesis | Test | Result |
|---|---|---|---|
| 1 | Timer startOneShot on garbage | Override=Block, confirmed offset +0x87, blanket +0x84..0x89 | HANG |
| 2 | Timer.stop() on heap-aliased fields | fully zeroed timer (+0x88..0xBF) | HANG |
| 3 | 4-bucket table illegal | 8-bucket native format (mask=7, size=8) | HANG |
| 4 | The SET's real fontStateChanged | skip-B, fake-table-only | HANG |
| 5 | ref/deref slots misidentified (R6/R7) | all vtable slots noop | HANG |
| 6 | The reject path on the real promise | zeroed fake promise at SELF+0x90 | HANG |
| 7 | Sources poisoned by session reads | post-read crafting (zero +0x30-0x57 AFTER the last readAt) | HANG |
| 8 | Status byte wrong offset | MEASURED from the real face: +0x82 = 3 (Success) CONFIRMED | HANG |
| 9 | Real clients' handlers (the selector's style recalc) | N/A — fake-table-only also hangs | same |
| 10 | Table format itself | REAL-TABLE BYTE COPY (metadata {deleted=2,keyCount=1,mask=7,size=8} + 0xFFFF deleted markers + one bucket patched IM→fake) | HANG |
| 11 | Hash-table OBJECT header (+0x60..0x67) | copied from the real face ({3,2} — the mutable operation counters) | HANG |
| 12 | **The dispatch never reached the vtable** | **garbage at ref() slot → NO CRASH** | **CONFIRMED** |

### The asymmetry (the open research question)
`m_clients.add()` (the insert) WORKS on our forged table — witnessed twice. `iterateClients()`'s `copyToVectorOf` → `computeSize()` → `removeNullReferences()` → `removeIf()` HANGS. In the 616 source, `computeSize()` unconditionally runs `removeIf`; the `add()` only runs cleanup when the operation counter exceeds the threshold — our sprayed counter bytes keep the add's cleanup OFF. But the fork is OLDER than 616 (proven: rc@+0x00, no vtable on CSSFontFace) — the fork-era WeakHashSet/Algorithms may differ entirely.

### Next moves (ranked)
1. **Fetch the fork-era source** (Safari-13/605.1.x, ~2020): CSSFontFace.cpp, WeakHashSet.h, Algorithms.h, HashTable.h — the 616-era code we've been working from may be wrong for the fork in the exact machinery that hangs.
2. **The counter gambit**: craft m_operationCountSinceLastCleanup/m_maxOperationCountWithoutCleanup so the cleanup paths no-op.
3. **Alternative triggers**: fontLoadEventOccurred() (the source-completion path), the GC destructor path, CSSFontFaceSet's family-merge paths.
4. **LLDB on-device** — attach during the hang, read the PC.
