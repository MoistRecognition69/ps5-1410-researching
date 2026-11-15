# Progress Audit

Status of the PS5 14.10 WebKit exploitation research as of November 15, 2026 (the interactive shell era).

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
| V87–V99 | The import hunt begins: GOT/dynstr dead (pure-vtable RELRO), band-priors dead (V94), the deref hunt (the V61 gate) |
| V100–V105 | The deterministic stack walk (cfr-upward); **THE ANCHORED AUXV DECODE** — AT_BASE/AT_ENTRY deterministically, every boot |
| V106–V112 | The reorder; the ld.so header gamble (DEAD); the low-32 rule; 0x101000000 answered (a constant) |
| V113–V119 | The ld.so layout completed (dead zone + text cluster); the T2 chase; the Thread-band gate |
| **The shell era** | Nov 15 | **The WS shell** (XHR poll mode); the ld.so body and executable routes CLOSED in one command each; **THE MODULE REGISTRY FOUND**; **THE CALL PRIMITIVE PROVEN** (−1, verified); the binding-class lesson (first genuine call crashed) |

## Exploit Chain Progress (FontFace — the leading chain)

| Stage | Status | Notes |
|-------|--------|-------|
| Bug + reclaim + COOP + ARW + PC control | **DONE** | V17–V65 |
| Controlled arguments (fake scope) + return decoding | **DONE** | V82, V84+ — 35+ consecutive boots |
| Out-of-cage R/W | **DONE** | V86+ |
| Deterministic auxv (AT_BASE/AT_ENTRY per boot) | **DONE** | 14+ consecutive clean decodes |
| Direct module-read routes (ld.so / executable) | **CLOSED** | Measured XO — one interactive command each |
| Module registry located | **DONE** | The loader's malloc'd registry in the heap (boot-stable page at 0x10001c8000) |
| The interactive shell | **DONE** | XHR poll mode; the V61 gate at the CLI; the agent CLI (shell-cmd.js); session logging |
| The call primitive (interactive PC + RDI + return decode) | **DONE** | callret sign's fn → −1, verified:true — the V63 witness at the CLI |
| Import resolution (module bases by name) | **IN PROGRESS** | The native-heap graph walk: the registry entries' native targets (proven-readable class) → SceModule/link_map records → module bases |
| strlen quartet (E1) / benign syscall (E2) | **BLOCKED on module bases** | The callret-compatible targets: strlen-class + no-arg wrappers (getpid) — they tolerate RDI = the fake scope; the binding-table pointers are the WRONG class (WebCore C++ — they deref RDI as ExecState* → SIGSEGV, proven by the session-5 crash) |
| Kernel candidate selection (D2) | **PRE-ANALYZED** | External corpus banked; 677-entry syscall table; dead routes eliminated |
| Kernel trigger | **NOT STARTED** | Begins after E2 |

## What We Know About the Target

- Firmware 14.10 (UA-confirmed), WebKit-1400 (616-era internal fork), LLInt-only execution
- **16KB pages** (AT_PAGESZ=0x4000, auxv-confirmed); FreeBSD r230171, AMD Zen 2
- Gigacage disabled (identity caged()); IsoHeap OFF
- **Module text is execute-only in this WebProcess — OUR module, ld.so, AND the NKWebProcess executable** (each closed by measurement)
- The ld.so layout, fully mapped: header dead, body dead, gap dead, text `[+0x304000,+0x348000)` XO (non-contiguous, ~3.2MB above AT_BASE)
- The auxv sits at the main-thread stack top (the execve setup zone), deterministic from cfr
- The readable universe: the heap [lowB, jfuTop), the stack setup pages, our module's vtable band, the native heap (0x829–0x831-class) — and the JS heap moves under GC (scan hits can go stale in seconds)
- **The module registry is malloc'd IN THE HEAP**: the page at 0x10001c8000 is boot-stable; path strings carry the per-boot mount prefix; registry entries carry native-heap pointers (offsets +0x160/1b8/1e8 boot-stable); binding entries carry WebCore C++ implementation pointers (position-pair metadata) — the wrong class for identification-by-call
- The guide webview's secure WebSocket is transport-dead (1006); XHR to the same origin is proven
- The filter-stack lessons: the low-32 rule, alignment, clustering — all necessary, none sufficient (denormal doubles impersonate heap pointers); recurring values are constants; scan patterns must be absent from the page's own source (the str:lib/ and str:Rnps fragments; ".sprx" self-matches the page comments)

## The Interactive Shell (the current instrument)

`tools/ws-shell/` — the pipeline plus a live command loop over XHR polling. The V61 gate at the CLI (proven bands + the session's own read-map; `force` logged), full session evidence logging, restore verification. The agent CLI (`shell-cmd.js` + the server's `/api/cmd` and `/api/status`) drives the session programmatically. **The probe method remains the evidence-producer** (multi-boot witnessed); the shell is the exploration instrument.

### Runbook

- host.py runs untouched (443 + DNS + the dispatcher); the shell server: `cd tools\ws-shell; $env:PORT="8443"; node server.js`
- The dispatcher (`index.html`) redirects the guide to `https://manuals.playstation.net:8443/` for shell sessions; switch back to `v119.html` for probe sessions
- A session is the guide page's lifetime: re-enter the guide ≈ 30s → fresh session (fresh ASLR); a mid-session crash = re-enter, NOT reboot (reboot only for early-spray streaks — the A-DEAD class)
- The session evidence: `shell-beacons.log` ([CMD]/[RES] lines); the console beacons: the shell server's log
- The per-boot ground truth: `info` (BASE, cfr, jfuTop, fakeScope, neEntry) + the pipeline's fnSlot beacon in the log (round's fn; sign's fn = round's fn + 8)

### Next Steps (the resume plan)

1. Fresh session → `info` → read the fnSlot beacon from the log
2. **The native-heap graph walk (READ, not call)**: the registry entry's native targets (page at the entry's pointer & ~0x3FFF, `force` — the class is proven readable) → follow the C++ object graph toward SceModule/link_map records with module bases
3. Read the other module-path entries (scan `str:lib/` fresh; each hit page is an entry with native pointers) — in-band, zero risk
4. **No blind calls on binding-entry pointers** (the proven-fatal class); identification calls wait for libc-class targets (strlen-class + no-arg syscall wrappers tolerate RDI = the fake scope)
5. Module bases found → the corpus RVA arithmetic (the game-lane module dumps are the same firmware files) → strlen + syscall-wrapper addresses → E2's benign syscall via `callret` (e.g., getpid: a no-arg wrapper, any RDI ignored)
6. If the native graph stalls: the fallback routes are the WebKit module's own .got (BASE+0x7000000-class data band) and the other module-string entries' native pointers

## Probe Count

~800+ probes across 24+ sessions (including the pre-V series). The V-series: 119 probes. The shell: 6 sessions.
