# Progress Audit

Status of the PS5 14.10 WebKit exploitation research as of November 15, 2026 (the shell era).

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
| 24+ (V-series) | Nov 12-15 | **The FontFace chain to WebProcess control + the interactive shell** — see below |

## The V-Series (Nov 12–15, the current campaign)

| Probes | Milestone |
|--------|-----------|
| V17–V39 | UAF + reclaim + COOP write station (the address-validation wall discovered at V36) |
| V40–V54 | AB expansion → 64MB OOB DataView → **absolute in-cage R/W** |
| V55–V65 | Module rodata reads; NE census; **PC redirection (V63) → arbitrary PC (V65, no icall CFI)** |
| V66–V72 | Victim identification: the RVA anchor (0x4057848), the three-route hunt, the corrected JSFunction layout |
| V73–V82 | JSFunction hunt; scope → globalObject; **VM calibrated (VM+0x9ce8 topCallFrame)**; **THE R2 GATE PASSED — RDI controlled** |
| V83–V86 | **REALBODY witness** (−6, exact); **out-of-cage write** (the 0x7ef stack band) |
| V87–V94 | GOT/dynstr hunt (the vtable band is pure rodata — no classic GOT); band-prior foreign scan closed by the V94 decisive negative |
| V95–V99 | The deref hunt: the V61 gate, the first readable foreign region, the read-around design |
| V100–V105 | The deterministic stack walk (cfr-upward); **THE ANCHORED AUXV DECODE** — AT_BASE/AT_ENTRY deterministically, every boot |
| V106–V112 | The reorder (safe treasure banks first); the ld.so header gamble (DEAD — the SELF-loader treatment); the low-32 rule; 0x101000000 answered (a constant, not a pointer) |
| V113–V119 | The ld.so layout completed (dead zone + text cluster); the T2 chase proven; the clustering rule; the Thread-band gate; the k=210 past-text-end death |
| **The shell era** | Nov 15 | **The WS shell** (audited, 14+6 fixes; XHR poll mode after the WS 1006); the ld.so body and the executable route both CLOSED IN ONE COMMAND; **THE MODULE REGISTRY FOUND** (the heap string scan: path strings, registry entries, native-heap pointers, resolved foreign-pointer bands) |

## Exploit Chain Progress (FontFace — the leading chain)

| Stage | Status | Notes |
|-------|--------|-------|
| Bug + reclaim + COOP + ARW + PC control | **DONE** | V17–V65 |
| Controlled arguments (fake scope) + return decoding | **DONE** | V82, V84+ — 35+ consecutive boots |
| Out-of-cage R/W | **DONE** | V86+ — 24+ consecutive boots |
| Deterministic auxv (AT_BASE/AT_ENTRY per boot) | **DONE** | V100–V105 — 14 consecutive clean decodes |
| Direct module-read routes (ld.so / executable) | **CLOSED** | Measured XO — one interactive command each |
| **Module registry located** | **DONE** | Shell session 3 — the loader's malloc'd registry in the heap |
| **Import resolution (module bases by name)** | **IN PROGRESS** | The registry walk: read the entry structures → native-heap targets (0x8310exxxx) → module bases → the .got → strlen + syscall wrappers |
| strlen quartet (E1 completion) | **BLOCKED on imports** | |
| Benign syscall (E2 completion) | **BLOCKED on imports** | |
| Kernel candidate selection (D2) | **PRE-ANALYZED** | External corpus banked; 677-entry syscall table; dead routes eliminated |
| Kernel trigger | **NOT STARTED** | Begins after E2 |

## What We Know About the Target

- Firmware 14.10 (UA-confirmed), WebKit-1400 (616-era internal fork), LLInt-only execution
- **16KB pages** (AT_PAGESZ=0x4000, auxv-confirmed); FreeBSD r230171, AMD Zen 2
- Gigacage disabled (identity caged()); IsoHeap OFF
- **Module text is execute-only in this WebProcess — OUR module, ld.so, AND the NKWebProcess executable** (each closed by measurement, the last two interactively)
- The ld.so layout, fully mapped: header dead, body dead, gap dead, text `[+0x304000,+0x348000)` XO (non-contiguous, ~3.2MB above AT_BASE)
- The auxv sits at the main-thread stack top (the execve setup zone), deterministic from cfr
- The readable universe: the heap [lowB, jfuTop), the stack setup pages, our module's vtable band, the native heap (0x831xxxxxx-class) — and the JS heap moves under GC
- **The module registry is malloc'd IN THE HEAP**: path strings carry the per-boot mount prefix; registry entries carry native-heap pointers; resolved foreign pointers appear in unseen bands (0x802715af0, 0x80100a030, 0x80040f888)
- The guide webview's secure WebSocket is transport-dead (1006); XHR to the same origin is proven (the beacon channel)
- The filter-stack lessons: the low-32 rule, alignment, clustering — all necessary, none sufficient (denormal doubles impersonate heap pointers); recurring values are constants

## The Interactive Shell (the current instrument)

`tools/ws-shell/` — the pipeline plus a live command loop over XHR polling. The V61 gate at the CLI (proven bands + the session's own read-map; `force` logged), full session evidence logging, restore verification, the proven-lethal auto-stages neutered. Two questions that cost probe-boots each were answered in one command; the registry discovery came in the third session. **The probe method remains the evidence-producer** (multi-boot witnessed); the shell is the exploration instrument.

## Probe Count

~800+ probes across 24+ sessions (including the pre-V series). The V-series: 119 probes. The shell: 3 sessions (35+ consecutive REALBODY cores across all of them).
