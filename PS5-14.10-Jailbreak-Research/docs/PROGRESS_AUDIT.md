# Progress Audit

Status of the PS5 14.10 WebKit exploitation research as of November 15, 2026 (the council breakthrough, session 50).

## Timeline

| Session | Date | Focus |
|---------|------|-------|
| 1-6 | Oct 15-16 | Bug discovery, stride correction, heap groom, JSString corruption |
| 7-8 | Oct 17 | Extraction attempts, RAB inversion, Relapse testing |
| 9 | Oct 17-18 | Sweep survival testing, MetadataTable declared BLOCKED/DEAD |
| 10 | Oct 18 | Pivot to new surfaces. Font/image recon. 17+ audit agents deployed |
| 11-13 | Oct 18-19 | CSSFontFace UAF (DoS-only), tee() type confusion (contained), WK-1400 audit |
| 14-16 | Oct 19-20 | IsoHeap OFF discovery, CVE-2026-43720 reopened, first reclaim attempts |
| 17-19 | Oct 20-21 | Same-type reclaim V573 CONFIRMED, full R/W via alias V562/V630 |
| 20-21 | Oct 21-22 | Crash oracle development, heap topology mapping V650-V655 |
| 22-23 | Oct 22-23 | Info leak hunting, APNG overread (V674), ASLR defeat work |
| 24+ (V-series) | Nov 12 | THE V-SERIES: the FontFace chain — V17-V39 UAF+reclaim+COOP, V40-V54 the 64MB OOB DataView (absolute in-cage R/W), V55-V65 module rodata + PC redirection (V63) → arbitrary PC (V65, no icall CFI) |
| V66-V99 | Nov 12-13 | Victim ID (the RVA anchor), REALBODY witness, VM calibration, THE R2 GATE (RDI controlled), out-of-cage write, the import hunt (GOT/dynstr dead: pure-vtable RELRO), the V61 read gate |
| V100-V119 | Nov 13-14 | Deterministic auxv (AT_BASE/AT_ENTRY every boot), the ld.so layout fully mapped (text-only island), the 16KB-page rules, the JSFunction/Thread-band gates |
| The shell era | Nov 14-15 | THE INTERACTIVE SHELL (XHR poll mode) — sessions 1-23: the module registry found, the call primitive proven (−1 verified), the binding-class lesson (WebCore C++ implementations crash on the fake-scope RDI), the mem-warning crash-dialog reclassified (generic WebProcess-crash text), the e2shot instrument (v5-v12: sparse anchors, TWO canary-confirmed bases, the harvest boundary calibrated to 0x390000, the empty-chunk exit, the full-census mode) |
| The console crash | Nov 15 | Session 47: the rawcall sweep's first target was the constant band (unmapped) + unknown garbage-arg calls; the CONSOLE died (unclean shutdown, repair screen); recovered via Rebuild Database, everything intact. POSTURE: no blind sweeps, identified targets only |
| The council | Nov 15 | Sessions 48-50: the full-band census (940 values, 13 clusters), THE COUNCIL convened — delivered gettimeofday=lk+0xB50 (14.10 named-import-proven; my 0x1B840 was FSTATFS mislabeled), thr_self (single-arg TID write), the pthread-backlink route — LIVE-PROVEN in one session: registry → thread record → struct pthread → backlink (residue 0x218 exact) → lk_base 0x83BC88000 → THE THIRD CANARY (0x5453e725171b5aa7). The export table at lk+0x48000 decoded (magic 0x3b031b01; hi-words = self-relative text RVAs incl. the verified stub 0x410). The rawcall at the identified target died at the call moment (no beacons) → v13 e2witness: the whole chain, one command, blocking sync beacons |

## Exploit Chain Progress (FontFace — the leading chain)

| Stage | Status | Notes |
|-------|--------|-------|
| Bug + reclaim + COOP + ARW + PC control | **DONE** | V17–V65 |
| Controlled arguments (fake scope) + return decode | **DONE** | V82, V84+ — 35+ consecutive boots |
| Out-of-cage R/W | **DONE** | V86+ |
| Deterministic auxv (AT_BASE/AT_ENTRY per boot) | **DONE** | V105 — every boot since |
| The interactive shell | **DONE** | XHR poll mode; the V61 gate at the CLI; sync beacons; session evidence logging |
| The call primitive (interactive PC + RDI + verified restore) | **DONE** | the −1 A/B witness at the CLI; rawcall (decode-immune: return discarded untouched, memory side-effects read instead) |
| **libkernel base derivation (per-session)** | **DONE (live-proven)** | THE PTHREAD BACKLINK: registry entry (boot-stable) → thread record → struct pthread (the 0x88-band, readable) → the `_thread_list` backlink at +0x40 (residue 0x218 gate) → base; confirmed by the canary at +0x751D0 (THREE canaries across three sessions: 0x4b0fffa9f9b6c7b7, 0xcd3d5b7f41eb2dc6, 0x5453e725171b5aa7). Three reads + two gates, non-stochastic |
| The export table | **READ + DECODED** | lk+0x48000: magic 0x3b031b01, 0x82C entries; hi = self-relative text RVA (ladder 0xD0, 0x130… incl. the game-lane-verified stub 0x410); lo = NID/name offset (names not ASCII, not SHA1-of-name — encoding unresolved; the gettimeofday anchor validation pending the entries-512+ dump) |
| **E2: the benign syscall witness** | **ONE COMMAND AWAY** | The identified target: **gettimeofday @ lk+0xB50** (14.10 named-import-proven; the 13.60 map's 0x1B840 was fstatfs — the "drift" deaths were wrong-function calls). v13 `e2witness`: the full chain in one command with blocking sync beacons — a death at the call moment still banks the derivation and the scope bytes. Safety: tv copies before tz (witness-first in every RSI outcome); the tz copyout is kernel-validated userland — no panic path |
| Kernel leg (M2/D2) | **PRE-ANALYZED, BLOCKED ON E2** | External corpus banked (677-entry syscall table, per-boot kernel addresses, libkernel syscall-stub mechanics); begins after E2 |

## The Key Instrument

`e2shot` / `e2witness` — one-command campaign stages, in-page, every step on a **blocking sync beacon** (evidence survives any death). The retired-methods ledger (all evidence-backed): low-14 wrapper matching (dense residues), derived-guard probes (15% lottery), cluster density (no module identity), blind sweeps (console crash), the timing theory (stochastic tables).

## What We Know About the Target

- Firmware 14.10 (UA-confirmed), WebKit-1400, LLInt-only; **16KB pages**; FreeBSD r230171, Zen 2
- Gigacage disabled, IsoHeap OFF; **module text execute-only**; ld.so a text-only island; the classic GOT dead (pure-vtable RELRO); no /proc, no debugger
- **The mem-warning dialog is the generic WebProcess-crash text** — deaths are our faults or the stochastic session end; the console survives everything except (once) the blind-sweep class — blind calls are banned
- Every guide re-entry = fresh WebProcess = fresh ASLR; **the registry page, thread records, auxv anchors, and module file layouts are the boot-stable invariants**; the pthread backlink + canary derive the libkernel base in three reads

## The Runbook

- host.py (443 + DNS + dispatcher) untouched; the shell server: `PORT=8443 node server.js` (full-path invocation avoids the CWD trap); dispatcher cache-busted (`?v=e2shot1`); server restarts are session-survived; the busy-guard (one command in flight) + the 409 rejection are live
- The per-session ground truth: `info` (BASE, cfr, fakeScope, neEntry); the pipeline beacons in shell-beacons.log
- **The E2 witness: `node shell-cmd.js e2witness`** — the one command; the sync beacons carry the trail; green banner + ~1 min settle before firing

## Probe Count

~800+ probes across 24+ sessions (pre-V + V119 + 50 shell sessions). The council: 4 members, 3 rounds, the breakthrough intelligence.
