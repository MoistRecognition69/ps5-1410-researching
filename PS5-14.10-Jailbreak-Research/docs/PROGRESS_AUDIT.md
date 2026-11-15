# Progress Audit

Status of the PS5 14.10 WebKit exploitation research as of November 15, 2026.

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
| 24+ (V-series) | Nov 12-15 | **The FontFace chain to WebProcess control** — see below |

## The V-Series (Nov 12–15, the current campaign)

The probe numbering restarted at V1 for the FontFace chain's active exploitation
phase. Every probe is an HTML page deployed via the guide DNS spoofer, emits
beacons to a host logger, and runs on-device with no debugger.

| Probes | Milestone |
|--------|-----------|
| V17–V36 | UAF + reclaim + COOP dispatch (the address-validation wall discovered at V36) |
| V38–V39 | The COOP write station: multi-shot arbitrary writes |
| V40–V49 | AB expansion → 64MB OOB DataView (V49 self-repair) |
| V54 | **Absolute in-cage R/W** (m_vector rewrite) |
| V55 | Module rodata reads; text read-fatal mapped |
| V56–V62 | NE census (6 iterations, 3 crashes — each a diagnosed fix) |
| V63 | **PC redirection** (round→sign via battery diff) |
| V65 | **Arbitrary PC** (cross-signature to folded-empty; no icall CFI) |
| V66–V72 | Victim identification (RVA anchor 0x4057848; three-route hunt) |
| V73–V75 | JSFunction hunt (up-walk; corrected layout: scope@+0x10, exec@+0x18) |
| V76–V78 | Scope → globalObject (member run confirmed; fallback-G gate added) |
| V79–V81 | **VM calibration** (window-differential; topCallFrame at VM+0x9ce8) |
| V82 | **THE R2 GATE PASSED** — the fake scope works; RDI under control |
| V83–V84 | **REALBODY witness** — `Math.round(-5.7)` through forged scope = exactly −6 |
| V85–V86 | **Out-of-cage write** — sentinel in the 0x7ef stack band |
| V87–V90 | GOT/dynstr hunt (module band mapped: pure vtables, no import tables) |
| V91–V94 | Foreign-pointer hunt (band-prior route closed by the V94 decisive negative) |
| V95–V96 | Deref hunt depth 1 (V61 gate; Thread-structure lead found) |
| V97–V98 | **Depth-2 deref: first foreign-band pointers found** (hi32=1 band) |
| V99+ | The read-around validation (ELF-magic check → module base → import library) |

## Exploit Chain Progress (FontFace — the leading chain)

| Stage | Status | Notes |
|-------|--------|-------|
| Bug identification | **DONE** | CSSFontFace freed during FontFace load promise resolution |
| Source audit (WK-1400) | **DONE** | LLInt-only confirmed; JSCallee extends JSNonFinalObject directly |
| UAF + reclaim | **DONE** | V17–V36; COOP-only (CFI wall at V36) |
| COOP write station | **DONE** | V38–V39; multi-shot, arbitrary address, fixed pattern |
| Absolute in-cage R/W | **DONE** | V54; m_vector rewrite; identity caging (GIGACAGE_ENABLED=0) |
| Module rodata reads | **DONE** | V55-A; the vtable band readable |
| NE census | **DONE** | V56–V62; ~300 raw function pointers |
| PC redirection (same-sig) | **DONE** | V63; round→sign, battery-diff identified |
| Arbitrary PC | **DONE** | V65; cross-signature survived; no icall CFI |
| Victim identification (deterministic) | **DONE** | V68–V72; RVA anchor 0x4057848; three-route hunt |
| JSFunction hunt | **DONE** | V73–V78; corrected layout; type-byte check; 10th layout family handled |
| VM calibration | **DONE** | V79–V81; topCallFrame at VM+0x9ce8 (window-differential) |
| Fake scope (R2 gate) | **DONE** | V82; RDI controlled; 15 consecutive clean gates |
| Controlled-return real-body call | **DONE** | V84+; `Math.round(-5.7)` = exactly −6 through forged scope; 13 consecutive boots |
| Out-of-cage write | **DONE** | V86+; sentinel in the 0x7ef stack band; 11 consecutive boots |
| Foreign-module pointer discovery | **DONE** | V98; depth-2 deref; first foreign-band hits |
| Import resolution / module identification | **IN PROGRESS** | V99: the read-around (ELF-magic check at the foreign candidates) |
| strlen quartet (E1 completion) | **BLOCKED** | Needs import resolution |
| Benign syscall (E2 completion) | **BLOCKED** | Needs import resolution |
| Kernel candidate selection (D2) | **PRE-ANALYZED** | External corpus banked; 677-entry syscall table; dead routes eliminated |
| Kernel trigger | **NOT STARTED** | Begins after E2 |
| Privilege escalation | **NOT STARTED** | |

## What We Know About the Target

- Firmware 14.10 (UA-confirmed), WebKit-1400 (616-era internal fork)
- LLInt-only execution (all JIT tiers OFF — ENABLE_JIT/DFG/FTL/B3/WASM all 0)
- FreeBSD r230171, AMD Zen 2, 16KB pages
- Gigacage disabled (GIGACAGE_ENABLED=0 — identity caged(), stored pointers used as-is)
- IsoHeap OFF (bmalloc/libpas, not IsoHeap free lists)
- Module text is **execute-only** (PKU on Zen 2 — not a page-table property)
- Module rodata readable; the full readable RELRO segment [~0x71x, 0x7392000) is 1.25MB of pure vtables — no classic GOT, no dynstr
- ELF header page unmapped (V52); cage floor at cage+0x100000 (V70/V71)
- PS5 thread stacks at ~0x7exxxxxxx (not the classic 0x7fff... range)
- Game-process module bands do NOT describe the WebProcess (V94)
- WebProcess foreign module pointers found at depth-2 through GC-thread structures (V98)

## Probe Count

~800+ probes across 24+ sessions (including the pre-V series). The current V-series: 99 probes in 3 days.
