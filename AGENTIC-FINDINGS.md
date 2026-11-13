# AGENTIC-FINDINGS — PS5 14.10 WebKit Research

> **⚠ RESUME STATE 2026-11-13 11:30 — read §10.14 first.** Read-chain COMPLETE (leak/walk/identity/addrof all certified ~10s/session). Engine write into forged table WITNESSED (the insert). The dispatch trigger BLOCKED: the load-path dispatch hangs in the WeakHashSet's computeSize/removeIf BEFORE any vtable call (crash-bisection proven, ~12 hypotheses eliminated — full ledger in GLM E18). The PS5's fork is OLDER than 616 (rc@+0x00, no vtable). Next: fetch the 605.1.x-era sources, craft the operation counters, or try alternative triggers (fontLoadEventOccurred, GC destructor, family-merge). Current probe: v17.html (harmless ~30s cycles). Tooling: auto_continue.py + scan-watch.ps1 (V17-aware).

> **⚠ LATE UPDATE 2026-11-12 ~23:15 — read §10 at the bottom first.** Short version: the ELF-magic-scan route is **dead** (loader wipes header pages — proven, not inferred); the "unmapped gap" below the vtable is **execute-only text** (all 4 vtable function pointers live in it; reads fault, execution doesn't); the current probe is **V683 pointer-sift** (RTTI probe done: WebKit is -fno-rtti; data-island `__dso_handle` hunt in progress). Reclaim recipe note: the old single-size spray died mid-evening for all probes; V681's size-ladder + `fonts.check` consumption recipe is now in V678V2/V683 and restored 100% leak rate.

**Date:** 2026-11-12 (session state as of ~20:35)
**Target:** PlayStation 5 firmware **14.10** — owner's retail console (`10.100.102.14`)
**Companion doc:** `AGENTIC-FINDINGS.md` (full run history and probe-by-probe changes)

---

## 1. The mission in plain terms

Get the PS5's built-in browser to run our own instructions, then use that to reach the kernel and (eventually) bypass the hypervisor — i.e., a full jailbreak on 14.10. The browser is the entry point; the current stage is building the pieces that let us compute where the browser's code lives so we can run it.

## 2. Where we are on that path

| Stage | What it means | Status |
|---|---|---|
| Browser entry | Serve probes to the PS5 via `host.py` DNS-spoof of `manuals.playstation.net` → *Settings → User's Guide* | ✅ Working |
| Info leak | FontFace UAF → engine writes two live heap pointers (`+0x58`/`+0x68`) into a reclaimed 192B ArrayBuffer | ✅ Confirmed (multiple landings) |
| Process survival | p564 buffer templating (write leaked pointers back into all 192B buffers) | ✅ Confirmed |
| Write primitive | Two-phase FontFace addClient forge — engine inserts into a hash table at an address *we* choose | ✅ **FORGE CONFIRMED** |
| Arbitrary read | 4-step walk chain (`forgeRead` + `face.style`) reads any address in the WebProcess | ✅ Confirmed (`WALK-ok=true`) |
| Self-address | Our own spray buffer's VA (`SELF = 0x1000380b40`) | ✅ Found |
| Text base leak | CSSFontFaceSet vtable pointer (`VP = 0x81c979b28`) + all 9 vtable slots leaked from the code segment | ✅ Found |
| **Module base + vtable RVA** | The WebProcess module's base address and the vtable's static offset in the binary | ⏳ Still needed for full gadget set (ELF scan + metadata method both failed) |
| **RIP control** | Make the browser dispatch through a forged vtable to run our code | 🔄 **V680 staged** — lane-relative forge using leaked vtable slots, no absolute base needed |
| Kernel R/W | Browser RCE → kernel memory access | ⏳ Later |
| Hypervisor bypass | Full jailbreak | ⏳ End goal |

**In short:** info leak → write primitive → arbitrary read → text base leak are all **confirmed working on this console**. The current objective is **RIP control via the lane-relative forge (V680)**, which uses the leaked vtable slots as code-reuse targets without needing the absolute base.

## 3. The current objective (and why it matters)

**V680 — lane-relative RIP-control forge (method 3).** Instead of finding the absolute module base (which failed on both ELF scan and metadata method), V680 uses the **leaked vtable slots as code-reuse targets directly**. The forge builds a 5-dereference chain from the reclaimed CSSFontFace to a fake vtable where all slots point to `0x4141414141414141` (poison) or a real gadget address.

The chain:
```
CSSFontFace+0x58 → HashTable.m_table → entry[0] (WeakPtrImpl)
→ WeakPtrImpl+0x10 (m_ptr) → Client vtable → vtable[3] fontStateChanged
```

**Proof of RIP control:** crash at RIP=`0x4141414141414141` = the virtual dispatch chain reached RIP with our controlled value. Then replace poison with a real gadget address from the leaked slots.

**Why this avoids the base-finding problem:** the leaked vtable slots (`0x81b268fb0`, `0x81b268fe0`, etc.) are already valid code addresses in the WebProcess. We don't need to know the module base to use them as code-reuse targets — we just point the forged vtable at them.

## 3b. Base-finding (still needed for full gadget set)

The absolute module base is still needed for a full ROP chain beyond the leaked slots. Both methods are still in play:
- **V678 ELF scan:** exhausted 64MB below VP (`BASE-NOTFOUND-0`) — cursor preserved, can be retried with different range or direction
- **V679 metadata method:** hopped through a large unmapped gap, no mapped candidate yet — stride-hop still progressing, can be retried with bigger cap or different start offset

The lane-relative approach may bypass this need entirely for the initial RIP control proof, but the base is still needed for a full ROP chain.

## 4. Confirmed addresses on this bench

| Name | Value | What it is |
|---|---|---|
| SELF (spray buffer VA) | `0x1000380b40` | Our own memory's address |
| VTAB (adjacent buffer) | `0x1000380100-j0` | Forged-vtable landing site |
| IM (client WeakPtr) | `0x10007eac90` | From the hash table bucket |
| FO (CSSFontFaceSet) | `0x10003e70c8` | From IM+8 dereference |
| **VP (CSSFontFaceSet vtable ptr)** | **`0x81c979b28`** | **Code-segment / text base leak** |
| Vtable slots s0–s8 | `0x81b268fb0`, `0x81b268fe0`, `0x81972d750`, `0x81b2696b0`, `0x81972d750`, `0x81972d750`, `0x81aebf400`, `0x81b269810`, `0x0` | All 9 slots leaked; deltas match repo 2's bench exactly (same binary) |

## 5. Probe inventory (all in `PS5-14.10-Jailbreak-Research/probes/`)

| Probe | What it does | Outcome on this bench |
|---|---|---|
| `canvas-uaf/v675-fontface-canvas-combo.html` | Repo 2's FontFace leak + repo 1's Canvas UAF + V650 forged read | Leak + alias confirmed; V650 forged read **dead** (5+ crashes, also dead on repo 2's P682) |
| `canvas-uaf/v676-two-phase-fontface-forge.html` | p656 two-phase addClient forge + p564 templating + early-P2 instrumentation | **FORGE CONFIRMED** (write primitive) |
| `escalation/v677-walk-forge.html` | p691 full walk chain (self-address + arbitrary read + text base leak) | **Full success** (SELF/VTAB/VP/all slots) |
| `escalation/v678-elf-base-scan.html` | ELF magic scan below VP with loop-proof resume cursor | Exhausted 64MB below VP (`BASE-NOTFOUND-0`) — cursor preserved, retry with different range/direction |
| `escalation/v679-dynamic-linkmap-base.html` | `.dynamic`/`link_map` metadata method with stride-hop | Hopping through large unmapped gap, no mapped candidate yet — stride-hop still progressing |
| `escalation/v680-lane-relative-rip-forge.html` | **CURRENT VER-5.** V55/V65 lane-relative RIP-control forge with V681's complete spray geometry and 60/140/400 ms scans | Staged; awaiting fresh guide load. VER-4 produced six completed NOLEAK outcomes; no LAY/READD/RIP2 evidence |
| `escalation/v681-fontface-reclaim-diagnostic.html` | Isolated FontFace reclaim; explicit sheet cleanup + `check()` + three scans | **LEAK OK** 20:38:54: `T58=0x100088c970`, `W68=0x10007e2220`; first scan had `resolved=0` |

Staged copies live in `tools/remote-loader/` (`v675.html` … `v681.html`); the dispatcher is `tools/remote-loader/index.html` → `v680.html?cb=1794510960` (repo-root `index.html` untouched per the repo's DEPLOY.lock convention). VER-4's fixed 60 ms scan still returned NOLEAK, so VER-5 reproduces V681's successful trigger as one unit: exact 13-size/eight-per-size allocations, eight 192B downstream buffers, original-face keep-alive, zero-filled allocations through `check()`, and all three fixed scans. Metadata is restored only after a hit; `WAITFACES` preserves early-hit continuation. The rest of the chain and V681 are unchanged. Source/staged SHA-256 is `41F4027FCBBABBCECE4A482135C92745DB38BDE808C1F4E741EA50B5E780CDC1`; both pass syntax checks and the expanded stub harness passes 42/42 assertions.

## 6. Session protocol (how to run any of these)

1. **host.py** (on the PC, elevated PowerShell):
   ```powershell
   cd D:\ps5\PS5-14.10-Jailbreak-Research\tools\remote-loader
   $env:PYTHONIOENCODING="utf-8"   # required: the banner is Unicode and crashes cp1252
   python host.py *> host-console.log
   ```
   Redirecting output to a file also prevents the Windows select/mark-mode console hang. `openssl` (from Git's `usr/bin`) must be on PATH for the TLS cert.
2. **PS5:** Settings → Network → DNS: Manual → Primary = PC's LAN IP (currently `10.100.102.2`). Then **Settings → User's Guide** to run the probe. Restore DNS to Automatic afterward.
3. **Beacons:** sync-XHR POST to `/beacon/` → `tools/remote-loader/host-beacons.log`. That's the result record; the console screen only shows the final verdict banner because the main thread is blocked during scans.
4. **After any hit/crash:** close the guide app and reopen (one FontFace UAF hit per WebProcess). Watchdog dialog → Continue. OOM error → restart the console (clears it) and reopen (cursor persists).
5. **HALT breaker:** 5 crashed runs per 2 min → a 2-minute pause page (not a crash, just a pause). Clears after 2 min or with `?reset=1` in the dispatcher URL.

## 7. Known dead ends (do not retry)

- **V650 forged-stateStack read (Canvas UAF → AB(768) reclaim → forged m_stateBuffer):** crashed 5+ times on this bench; repo 2's P682 hit the identical crash on both firmwares. The mechanism is dead on 14.10.
- The RIP lay-forge trigger (V677's Step 9/10) crashed at the face re-add — that's the open landing-mechanism blocker on 14.10, to be revisited once the base is known.

## 8. What's next concretely

1. **Close and reopen User’s Guide once** — this runs V680 VER-5 with V681's complete allocation geometry and 60/140/400 ms scan schedule. Keep the host running and leave the result on screen for beacon inspection. VER-4 produced six completed NOLEAK outcomes and never reached FORGED/LAY/RIP2.
2. **Once reclaim lands** (you'll see `L1-0x10008...` and `L2-0x10007...` instead of `0x0`), the full chain proceeds: SELF → CLIENT → VTAB → IHT → WALK → LAY → RIP2.
3. **RIP control proof:** if the crash is at RIP=`0x4141414141414141`, the virtual dispatch chain reached RIP with a controlled value — **RIP control confirmed**.
4. **Replace poison with a real gadget address** from the leaked vtable slots (e.g. `?pk=3&poison=81b2696b0` to use s3 as the target).
5. **Base-finding (parallel track):** if the lane-relative approach needs a full ROP chain, retry V678's ELF scan with a different range (e.g. scan UPWARD from VP) or V679's metadata method with a bigger cap. Both cursors are preserved.
6. After RIP control: ROP chain → kernel R/W → hypervisor bypass (the end goal).

---

## 10. LATE UPDATE — evening session 2026-11-12 (~21:00–23:15)

**Supersedes §3's objective framing.** Full details in `GLM_Findings.md` (evening sections E1–E7).

### 10.1 What changed
- **ELF-magic route: definitively dead.** V678V2 (sampling-fixed rebuild of V678: fresh cursor keys, per-pass random phase, landing hexdump, island up-sweep, zone mode, upward scan, 128MB cap) swept pass 0 to ~100MB. No `\x7fELF` anywhere below VP. The 64MB cap of the old V678 missed a **readable 17.5MB text island at VP−0x41d4000 by 1.9MB**. The header page is wiped by the loader (zero island at VP−0x5318000..0x5424000 is all zeros exactly where seg0/ehdr belongs).
- **Execute-only text discovered.** V683's FPROBE at leaked function entry s0 **crashed the process** — s0 is a live dispatch target. All four vtable function pointers (s0=VP−0x1710B78, s2=VP−0x324C3D8, s6=VP−0x2ABC728) point into the "58MB unmapped gap" → the gap is the module's **PROT_EXEC-only text**. Reads fault, execution works. Every "unmapped" result inside [0x770000, 0x41d4000] is a readability artifact, not absence.
- **RTTI: WebKit is -fno-rtti.** vtable[-2] = −32 (secondary-vtable offset-to-top), vtable[-1] = 0. Module identity via typeinfo is closed.
- **Reclaim died and was revived.** At ~19:54 the p691 single-size 192B reclaim stopped landing for **all** probes (V680, V678V2; console restart did not help). V681's recipe (size ladder 12 sizes ×8 as pressure, `document.fonts.check('1em v1')` consumption in the getter, `__alive` wrapper retention, multi-timing retry 60/140/400/700ms) was ported into V678V2/V683 Steps 0/1 → **100% leak+walk restored for the rest of the night**.

### 10.2 Module-relative map below VP (pageStart = VP & ~0x3FFF)

| off | what |
|---|---|
| 0 → 0x770000 | data/rodata island (vtable's module), readable, dense-verified |
| 0x770000 → 0x41d4000 | **execute-only text** of the same module (s0/s2/s3/s6 live here) |
| 0x41d4000 → ~0x52e0000 | readable text island — **different module** (17.5MB ARM64) |
| 0x52e0000 → 0x5318000 | 224KB gap, page-verified empty |
| 0x5318000 → 0x5424000 | zero island (~1MB) — wiped seg0; **BASE candidate = VP_page − 0x5424000** |
| 0x6320000 | fill-pattern island (0xfff81675 ×4) |

### 10.3 Current objective
**V683 pointer-sift** (dispatcher live on `v683.html`): sift the readable data island [VP−0x760000, VP+0x140000] for 16KB-aligned self-pointers; green `DSOHIT` = a data qword equal to the seg0-hypothesis base (near-conclusive); any `HIT` cluster = base candidates to verify. ~2h of normal loop sessions; persists across sessions. FPROBE s2/s3/s6 will each burn one session (exec-only confirmations) before the sift settles in — expected, not a fault.

### 10.4 Session protocol updates
- **Post-crash: OK-click suffices** (dead process replaced automatically; auto_continue.py presses X for you — silence >12s → press immediately; the ~40s dialog latency is session-start→dialog, not crash→dialog).
- **Full close/reopen only after non-crash ends** (spent UAF in a live process → NOLEAK on reload).
- **PS5 guide cache: only fresh filenames bust it.** OK-reloads never re-fetch the dispatcher; cb= params don't either; close/reopen follows the dispatcher but may serve cached pages. Deploy new probes under new filenames.
- Wide-scan census is **parked, not dead**: cursor at 0x63bc000 preserved under `v678v2_*` keys; flip dispatcher to `v678-v2.html` to resume.

### 10.14 DISPATCH HANG LOCALIZED (2026-11-13, 11:26)
- **v17b-r campaign (~12 hypotheses)**: the load-path dispatch hangs BEFORE any vtable dispatch (crash-bisection: garbage at ref() → NO crash). The hang is in the WeakHashSet's computeSize/removeNullReferences/removeIf on our forged m_clients. Every table/timer/promise/status/vtable variation eliminated. The INSERT still works (the add path skips the cleanup). Full ledger in GLM E18.
- **The fork is OLDER than 616** (rc@+0x00, non-virtual CSSFontFace) — the 616-era source assumptions may be wrong for the machinery that hangs. Next: fetch the Safari-13-era (605.1.x) sources; craft the operation counters; alternative triggers (fontLoadEventOccurred, GC destructor, family-merge).

### 10.13 THE LOAD-PATH WALL — SOURCE-LANE HANDOFF (2026-11-13, 10:29)
- v17a: the control load crashed even with the +0x38 pattern zeroed — the wild-pointer theory dead. `CSSFontFace::load()` requires REAL object pointers in the +0x28-0x48 band (ng643's law); unrecoverable after the free.
- **Certified base unaffected**: read chain ✓, insert-witness ✓, the SET as live client in our table ✓ (v17.html cycles it every session, crash-free).
- **Source-lane tasks**: (1) CSSFontFace::load() field-read preconditions; (2) alternative status-transition paths that avoid +0x28-0x48; (3) LoadedPromise::resolve value-offset; (4) the +0x82 status encoding.
- **Probe lane meanwhile**: v17.html runs the certified pipeline; when a safe transition path arrives → the dispatch → the witnessed resolve → aimed at cell+0x10 → ARW.

### 10.12 FIRST ENGINE WRITE INTO FORGED STRUCTURE (2026-11-13, 10:25)
- **Session B4VLTA (v16g)**: addClient INSERT into our forged 4-bucket table WITNESSED — keyCount 1→2 + the SET's WeakPtrImpl (0x10007e0b40) inserted at bucket[2]. T58 unchanged (our table authoritative). The session then completed ADDROF-CERTIFIED — the full flow runs with the write test embedded.
- **The write primitive is half-proven**: engine-chosen pointer at our-chosen slot (the insert). The dispatch adds the other half: fully-controlled `this` at a positioned promise destination (fontStateChanged → resolve(*this)).
- **The SET is now a live client in our table** — any face status transition dispatches to our fake vtable (slot 3 = the gadget).
- **The v16 ledger**: T1-T4 (fonts.load/status/loaded/add-new) don't walk the table; faces[zi].load() crashes on 3 different face-byte subsets (the load/promise field map = SOURCE-LANE question); mask=0 hangs (probe-infinite), mask=3 fixed.
- **Next: the transition trigger** (source lane: CSSFontFace::load()/fontLoaded/setStatus field reads) → the dispatch → the resolve write aimed at cell+0x10 → ARW.

### 10.11 ADDROF-CERTIFIED — READ CHAIN COMPLETE (2026-11-13, 09:59)
- **Session TFR4OD (v688 v15)**: full pipeline certified in ~10s — UAF leak → walk → BASE → wrapper identity (3 gates) → marker buffer → calibrated cell scan → **JSDataView cell verified via 6 markers → ADDROF-CERTIFIED**. All cached (SELF/MBUF/CELL); every session re-certifies in ~10s.
- **Write target**: `vectorFieldAddr = cell+0x10` (the JSDataView m_vector field, beaconed per session). Cell layout verified on-device: {butterfly=0@+0x08, m_vector@+0x10, length=0x40@+0x18, byteOffset=0x20@+0x20}.
- **Oracle fully decoded**: chk(c)=T iff A≤c≤B (inclusive; inverted=all-F; cps ≤0x10FFFF). Calibrated triple-window cell signature: +0x14 (0x10,0x40)→FTTF primary.
- **v12-v14 walk-failure root cause**: marker-spray PATs at +0x88 aliased the SELF scan's +0x38 probe (Δ=0x50 on-grid) → fake SELF=marker+0x50 → VTAB-NONE → walk dead. v15: PATs at +0x90/+0xC0 (alias targets off-grid) — fixed + self-healing caches.
- **Next: the COOP write** — forge client table → fake impl → fake client → fake vtable → fontStateChanged → one write to cell+0x10 → retarget vector → full ARW.

### 10.10 PATH B IDENTITY CERTIFIED (2026-11-13, 09:34)
- **FACE-IDENTITY-OK** (session 3B00VR, v688 v10): wrapper vtable===VP, impl-backptr===L2, m_backing===SELF — all exact. Full chain green in 28s, crash-free, repeatable (SELF cache + v9 full-b1 grid).
- **Root cause of all scan failures found**: the grid covered b1 ∈ [0,0x7E] only — half the byte. SELF at b1>0x7E was invisible on every post-reboot boot. v9 full grid (4096/window) finds SELF in ~9-24s.
- **Wrapper layout MEASURED** (corrects COOP_ANALYSIS.md): {vtable=VP@+0x00, impl-backptr@+0x08, m_backing@+0x10, promise@+0x18}. Closed 2-object cycle CSSFontFace⟷wrapper; walk's client IS the wrapper.
- **COOP write targets mapped**: promise obj at FB+0x18 → resolve-callback wrapper → JSC pointers (0x7ef28b5bX) — addrof leads.
- Console fragility: ~1 crash post-reboot → OOM boot storm; clean-completing sessions (PATHB-DONE + RTT reload) are sustainable.
- **Next: addrof** — chase JSC pointers / scan for marker DataView qwords → JSDataView cell → ?dv= certification → design the single COOP write.

### 10.9 VP_RVA VERIFIED — BASE SOLVED (2026-11-13, 08:47)
- **On-device verification complete** (session 5YMTE1, v687 `?v=3`): ASCII landmarks `"Function\0TDZFail"` at BASE+0x6FA5A5C and `"JSGlobalProxy\0JS"` at BASE+0x6FB1E17 — **byte-exact**. Primary vtable readable at BASE+0x724DAC0. All 9 vtable slots with correct deltas (s3 = −0x1710478).
- **`WebProcess_base = VP − 0x724DB28`** — computable per session from the walk chain alone.
- **Gadget addresses per session:** fontStateChanged = BASE+0x5B3D6B0, noop = BASE+0x4001750, destructor = BASE+0x5B3CFB0.
- **Base-finding mission SOLVED.** Next: Path B addrof chain → DataView → one COOP write → ARW → RIP.
- s3 delta correction accepted: `0x1710478` (not `0x1700478`).

### 10.8 VP_RVA found from source — BASE COMPUTABLE (2026-11-13, ~09:00)
- **Other agent's commit c3584c5** contains full COOP analysis: **VP_RVA = 0x724DB28** → `WebProcess_base = VP − 0x724DB28` per session. All 19 vtable slots identified; FontFace layout mapped; Path B (addrof → DataView → one COOP fontStateChanged write → ARW) recommended.
- **Text island dump is obsolete** — we don't need to read exec-only text, just compute `BASE + gadget_RVA` and execute.
- Files on disk: `PS5-14.10-Research/docs/COOP_ANALYSIS.md`, `probes/phase13_webkit/p809-p816`.
- **Next: on-device VP_RVA verification probe** (read at computed base address).

### 10.7 Morning status (2026-11-13, 08:20) — OVERNIGHT SCAN COMPLETE
- **624 sessions, 5 full passes** of 128MB below VP. Rollover suicide worked perfectly (5/5 unattended). 42 island landings, 393 ISLDUMP batches.
- **The text island is STILL at −0x41d8000** — the overnight scan re-landed on it with the same ARM64 bytes. The D6 diagnostic's crash was a fluke.
- **22 unique island deltas mapped** with content samples. One stable island (−0x3268000, ×5 passes, ASCII strings). Three ARM64-typed candidates beyond the known island (−0x51d0000, −0x5330000, −0x3284000).
- **Next step:** read-length test at the island (16/32/48/72/80 bytes) → then full v684 dump at max verified length → ARM64 gadget inventory. The "80-byte crash" was actually an unmapped-address crash, so longer reads may work (4× throughput).

### 10.6 Status addendum (2026-11-13 00:40) — CONFIRM-PASS COMPLETE
- **Sift complete** (`SIFT-DONE-ALL` 00:31:20): 80 sessions, 102 hits, 35 deltas. **v683c confirm-pass ran in one session** (`CONFIRM-DONE-n=102`, 00:35:19): 58/102 confirmed module self-pointers, **24 stable module-relative landmarks**.
- **Headline landmark:** `−0x1928000` ×32 — a heavily-referenced anchor page ~25.5MB below the vtable, held by a strided 0x8C0 table alongside deep code pointers. The other 23 form a **ladder of 16KB-aligned exec-only segment starts** (−0x820000 … −0x2ee8000): the "gap" is segmented text, now mapped.
- **No `__dso_handle` / no base pointer exists in the swept data island.** Base bounded below s2's region (≥51MB below vtable). Seg0 hypothesis closed.
- **Strategic reframing:** exec-only text means the vtable module's code is unreadable — base wouldn't enable gadget mining for it anyway. The RIP path runs through the **readable text island** (−0x41d4000..−0x52e0000, 17.5MB, different module, dumpable in minutes).
- **Three ranked next options:** (a) gadget-mine the readable text island — **V684 deployed (00:45):** full 17.5MB dump, 32-read batch beacons, ~150 suicide-cycles ≈ 60–75 min unattended, `DUMP-DONE` halts, offline decode → `text-island.bin` → ARM64 gadget scan. (b) decode one 0x8C0 table entry to identify the 32×-anchor owner; (c) probe the −0x1928000 region's sub-island readability.
- Dispatched probes: v678-v2 (ELF scan, parked), v678-v2z (zone), v683/v683b (sift, complete), v683c (confirm, complete). All session protocol/tooling notes in §10.4-10.5 still apply.

### 10.6 Status addendum (2026-11-13 00:05)
- **FPROBE complete:** all four function probes (s0/s2/s3/s6) faulted on read → exec-only text quadruple-confirmed.
- **V683b** (self-terminating sift sessions) deployed and running unattended: ~75s cycle (walk→sift→SUICIDE→dialog→auto-X→fresh session), 12+ clean cycles, no stalls.
- **Sift tally:** 44 sessions, 94 hits, 28 deltas, **one stable candidate: −0x1928000 (×2 sessions, 24× strided cluster)** = leading `__dso_handle` candidate. No DSOHIT (seg0 hypothesis still unsupported). ~61% of the down-pass complete.
- **Read rate:** warm style-reads are ~2ms (not 30ms) — the sweep is session-cycle-bound; v683c (confirm-pass, planned) will re-read the recorded hit addresses under fresh slides with a bigger budget: survivors = the module's self-pointer inventory = base candidates.

### 10.5 Tooling added (tools/remote-loader unless noted)
`scan-watch.ps1` (colored live watcher), `auto_continue.py` (beacon-driven dialog dismiss), `dismiss_dialog.py` (manual X press; in PS5-14.10-Research/tools), `v683.html` (pointer-sift), `v678-v2-wide.html`/`v678-v2z.html` (parked builds).

---

*All results above are device-measured on the owner's console via the beacon log. Nothing is inferred from source alone; the RVA work is being done in-memory on-device because no 14.10 WebProcess binary exists publicly.*
