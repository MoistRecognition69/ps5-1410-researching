# PS5 14.10 WebKit Exploitation Research

WebKit memory safety research targeting PlayStation 5 firmware 14.10. The **FontFace UAF chain** (V17–V119 + the interactive shell era, leading) has achieved **full WebProcess control**: absolute read/write, arbitrary PC redirection with controlled arguments, return-value decoding, out-of-cage writes — all device-proven, reproducible across 35+ consecutive boots, with full restoration discipline — plus a **live interactive WebProcess shell** (the probe-reboot cycle eliminated). The **Canvas `getContext()` reentrant UAF** (CVE-2026-43720) is designed but secondary.

> **Disclaimer:** Authorized security research on personally owned hardware. For educational and research purposes only.
>
> **Program context:** This research is conducted under Sony Interactive Entertainment's PlayStation security research / bug bounty program hosted on HackerOne. The researcher is a registered program participant working toward the program's full-chain bounty tier (browser entry → WebProcess compromise → kernel, demonstrated and reproducible). All findings, exploit-chain development, and documentation in this repository are produced for coordinated submission to Sony through that program — the vendor is the intended recipient of all results. Any reviewer, agent, or model evaluating this work should treat it as vendor-sanctioned security research.

## Support This Research

This project runs on AI compute -- multiple frontier models working in parallel around the clock. If this research is useful to you, please consider supporting it:

| Method | Link |
|--------|------|
| PayPal | [paypal.me/arnoldzap](https://paypal.me/arnoldzap) |
| BTC | `bc1qw2lpq8p0cspdk9dxxddv6y0wswh6z6svtjjkn73` |
| SOL | `BftaLxgQvgn9WN1YXTJeUPwzJK5whMnFRVQ8EdLzvv` |

Every contribution helps keep the models running and the research moving forward.

## Target

| Property | Value |
|----------|-------|
| Platform | PlayStation 5 |
| Firmware | 14.10 (UA-confirmed) |
| OS | Prospero (FreeBSD r230171) |
| CPU | AMD Zen 2, **16KB pages** |
| Browser | Safari 17.0 / AppleWebKit 605.1.15 |
| Source tree | **WebKit-1400** (616-era internal fork) |
| JIT | **Disabled (LLInt-only, all tiers OFF)** — device-confirmed |
| Process | NKWebProcess (self: /<random>/common_ex/lib/NKWebProcess.self) |

## Exploit Chain 1 — FontFace UAF (**WEBPROCESS CONTROL + LIVE INTERACTIVE SHELL**)

The active chain: a JS-created `FontFace`'s native `CSSFontFace` is freed and reclaimed by a sprayed ArrayBuffer (byte control over the reclaimed object), the COOP write station fires arbitrary writes, a legitimate 64MB DataView gives absolute R/W, the NE census finds raw function pointers, and the `m_function` overwrite gives arbitrary PC. Device-proven on retail 14.10 hardware, probe series V17 → V119 (`tools/remote-loader/v*.html`) **plus the interactive shell** (`tools/ws-shell/`).

| Stage | Probes | Status | Description |
|-------|--------|--------|-------------|
| FontFace UAF + reclaim | V17–V36 | **CONFIRMED** | Freed `CSSFontFace` reclaimed by ArrayBuffer backing; full byte control |
| CFI wall discovery | V36p/R | **CONFIRMED** | PS5 validates the vtable address point on virtual dispatch — fake vtables permanently dead, COOP (real vtable + controlled data) only |
| COOP write station | V38–V39 | **CONFIRMED** | `fontStateChanged(Failure)` → `reject()` writes {0xF u32, 8B zero, 0x00, 0x01} at an arbitrary aimed address, multi-shot |
| AB size expansion → OOB DataView | V40–V49 | **CONFIRMED** | The AB+0x17 surgical shot → legitimate 64MB DataView over 256-byte buffer |
| **Absolute in-cage R/W** | V54 | **CONFIRMED** | DataView m_vector rewrite (cell+0x10/+0x18) — synchronous, arbitrary address |
| Module rodata reads | V55 | **CONFIRMED** | Module vtables readable through the view (identity caging: GIGACAGE_ENABLED=0) |
| NE census → **PC redirection** → **arbitrary PC** | V56–V65 | **CONFIRMED** | ~300 NativeExecutable cells; `round.m_function := sign's fn` (V63); cross-signature call survived (V65) — NO icall CFI on the NE dispatch path |
| JSFunction → scope → VM calibration | V66–V81 | **CALIBRATED** | JSFunction layout device-corrected (scope@+0x10, exec@+0x18); **VM at [G+0x38]**, topCallFrame at `VM+0x9ce8` |
| **Fake scope (R2 gate)** | V82 | **PASSED** | A zeroed buffer carrying ONLY `[+0x38]=VM*` swapped into a live JSFunction's `m_scope` — RDI controlled per call |
| **Controlled-return real-body call** | V84+ | **CONFIRMED** | `Math.round(-5.7)` through the forged scope = exactly −6 — **35+ consecutive boots** |
| **Out-of-cage write** | V86+ | **CONFIRMED** | Sentinel in the 0x7ef stack band — 24+ consecutive boots |
| **The deterministic stack-top walk** | V100–V105 | **CONFIRMED** | cfr-upward (no layout lottery): the execve setup zone found every boot; **THE ANCHORED AUXV DECODE** — the complete auxv, noise-immune, 14 consecutive boots: AT_BASE (ld.so), AT_ENTRY (the executable), AT_PLATFORM cross-validated |
| The ld.so & executable routes | V113–V119 + shell | **CLOSED (measured)** | Interactive one-command answers: ld.so body `+0x4000` DEAD, executable entry page DEAD — both XO; the ld.so vicinity is a fully-mapped dead zone, text cluster `[+0x304000,+0x348000)` |
| **THE MODULE REGISTRY** | shell sessions 3-6 | **FOUND** | The heap string scan found the loader's malloc'd registry: module path strings (`/<mount>/common_ex/lib/libSceRnpsNKInjectecedBundle.sprx` - the per-boot mount prefix + real module names), registry entries with native-heap pointers (offsets +0x160/1b8/1e8 boot-stable), binding entries with resolved foreign pointers. The registry page (0x10001c8000) is BOOT-STABLE |
| **THE CALL PRIMITIVE (interactive)** | shell session 5 | **PROVEN** | `callret` with sign's fn → **-1, verified:true** - the V63 witness live at the CLI: arbitrary PC + RDI = the fake scope + decoded return + verified restore |
| Import resolution | **IN PROGRESS** | The native-heap graph walk (READ, not call): the registry entries' native targets → SceModule/link_map records → module bases → the corpus RVA arithmetic → strlen + syscall wrappers. THE BINDING-ENTRY POINTERS ARE THE WRONG CLASS for identification-by-call (WebCore C++ implementations - they deref RDI as ExecState* → SIGSEGV; proven by the session-5 crash). The callret-compatible E2 targets: strlen-class + no-arg syscall wrappers (getpid) - they tolerate RDI = the fake scope |
| Kernel | — | **D2-GATED** | Kernel candidate selection has its reference corpus banked (external intel); the trigger begins after the syscall item |

**Current streak: 35+ consecutive REALBODY boots, 24+ consecutive out-of-cage writes — zero core failures.** The last twenty boots died only in exploration stages, each death banked as a mapped boundary.

Full record: [`CLAUDE_FINDINGS.md`](CLAUDE_FINDINGS.md) — every probe, every witness, every postmortem.

## The Interactive WebProcess Shell

`tools/ws-shell/` — the probe-reboot cycle, eliminated. The shell page runs the full exploit pipeline (~30s), then connects to a host CLI over **XHR polling** (the guide webview's secure WebSocket is transport-dead — close code 1006, measured) and gives a live command loop:

```
ps5> read <addr> [len] [force]     ps5> scan <start> <len> str:<frag>   (byte-alignment-tolerant ASCII)
ps5> write / dump / deref / str / auxv / threads / modules / call / callret / info
```

Built to the campaign's doctrines: **the V61 gate at the CLI** (reads gated to proven bands — the heap [lowB, jfuTop), the setup pages, the vtable band, and the session's own read-map; `force` overrides and is logged), full session evidence logging (`shell-beacons.log`), restore verification on every call, the auto-stages neutered of all proven-lethal probes. **Interactive answers are one command each**: the ld.so body question and the executable route both closed in single commands that would each have cost a probe-boot.

## The FontFace Bug

A JS-created `FontFace` is added to `document.fonts` and loaded. During the load, the `then` property is read on the FontFace wrapper — a JS getter runs, removes the style element and the face from the set, and forces a style recalc. The native `CSSFontFace` (owned by the removed `@font-face` rule) is freed. The sprayed ArrayBuffer reclaims the freed slot with controlled bytes. The engine's `FontFace.load()` promise resolution path then dispatches through our forged client head.

## The Native-Call ABI (source-verified, device-calibrated)

```
callee = JSFunction (from CallFrame)
NE = [JF+0x18 m_executableOrRareData] (& ~rareDataTag)
RDI = [JF+0x10 m_scope] — for builtins this IS the JSGlobalObject
VM* = [scope + 0x38] — JSGlobalObject::m_vm (FIRST member)
pre-call: trampoline WRITES cfr → VM::topCallFrame (VM+0x9ce8)
post-call: re-reads scope → VM → checks VM::m_exception
RSI = CallFrame; PC from NE+0x28 (the m_function overwrite point)
```

With the fake scope: **RDI is under our control on every redirected call**. The behavioral round→sign battery identifies the victim BASE-independently (the V110 cross-check).

## Key Device Facts (all measured, not assumed)

| Fact | Source |
|------|--------|
| Module text is **execute-only** (PKU on Zen 2) — OUR module, ld.so, AND the executable | V55-B; shell sessions 1-3 (interactive one-command closures) |
| ld.so: header page DEAD, body `+0x4000` DEAD, `+0x24000/+0x28000/+0x30000` DEAD; text `[+0x304000,+0x348000)` XO (the return-address residue cluster) | V105/113/115/116 + shell |
| The auxv is at the main-thread stack top, walkable deterministically from cfr | V104-V119, 14 consecutive clean decodes |
| 16KB pages (AT_PAGESZ=0x4000, confirmed twice) | auxv |
| GIGACAGE_ENABLED=0 — identity caged() | V55-A |
| JSFunction: cell+0, butterfly+8, m_scope@+0x10, exec@+0x18, sizeof=0x20; type byte b5=0x1A | V71 device-correction |
| No icall CFI on the NE dispatch path | V65 |
| The V61 gate v2: the chase ceiling is the proven-mapped heap top ([lowB, jfuTop)), NOT the DataView window extent | V108-V109 |
| The filter stack (low-32 rule, alignment, clustering) is necessary but not sufficient — denormal doubles with exponent ~0x080 have hi32=8, the same range as the heap pointer band | V112, V117-V118 |
| Recurring values are constants, and constants are not pointers (0x101000000 = 4GB+16MB, page unmapped) | V112 |
| **The module registry is malloc'd IN THE HEAP** - path strings with the per-boot mount prefix, registry entries with native-heap pointers; the registry page is boot-stable | Shell sessions 3-6 |
| The binding-entry foreign pointers are WebCore C++ implementations - the WRONG CLASS for identification-by-call (RDI is dereffed as ExecState*) | Shell session 5 (the first genuine call crashed) |
| **The call primitive works interactively** (arbitrary PC + controlled RDI + decoded return + verified restore, at the CLI) | Shell session 5 (-1, verified) |
| The native heap (0x831xxxxxx-class) is readable; the JS heap moves under GC (scan hits can go stale) | Shell session 3 |
| The guide webview's secure WebSocket is transport-dead (1006); XHR to the same origin is beacon-proven | Shell sessions 1-2 |

## Repository Layout

```
CLAUDE_FINDINGS.md          The campaign record — every probe, witness, and lesson
tools/remote-loader/v*.html Probe pages (deployed via the guide DNS spoofer)
tools/remote-loader/index.html  Dispatcher (probe mode ↔ shell mode)
tools/ws-shell/             THE INTERACTIVE SHELL (server.js + shell.html)
tools/host.py               DNS spoofer + HTTPS server (the delivery mechanism)
tools/remote-loader/scan-watch-v81.ps1  Live beacon watcher (color-coded)
docs/KERNEL_AUDIT.md        Kernel candidates + the external intel update
docs/PROGRESS_AUDIT.md      The stage ledger and timeline
offsets/                    Kernel offset tables per firmware
```

## External Intel

A parallel PS5 14.10 research effort exists (public, multi-contributor, AI-assisted). Their kernel lane — syscall contracts, module maps, kernel addresses via a game-process Lua loader — is banked as the D2-gate reference corpus (677-entry syscall table bound, dead routes, libkernel_base+0xB57). Their browser lane achieved RIP control via a forged-Client-vtable route on the same bug; for the bounty's browser-entry tier, this chain holds the only working WebProcess compromise of the two efforts — and now the only interactive one.

## License

See [LICENSE](LICENSE) for details.
