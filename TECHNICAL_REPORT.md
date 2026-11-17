# PS5 14.10 WebProcess Exploitation — Technical Report

Purely technical findings from a retail PS5 (firmware 14.10) WebProcess exploitation campaign. All facts are device-measured unless marked [S] (source-derived) or [I] (inferred). Self-contained; no session narrative. Companion data: `PS5-14.10-Jailbreak-Research/CLAUDE_FINDINGS.md` (chronological evidence), `tools/*.jsonl` (raw captures).

---

## 1. Environment

| Item | Value |
|---|---|
| Console | Retail PS5, firmware 14.10 |
| Entry | User's Guide browser (DNS-spoofed HTTP host) |
| Engine | WebKit 605.1.15 fork (616-internal), LLInt-only (JIT/DFG/FTL/Wasm off), heap NX, W^X, .text execute-only |
| WebProcess modules | WebProcess.self + libkernel + ~15 SPRX (WebKit, JSC, ICU, PNG, JPEG, WebP, Brotli, FreeType, Fontconfig, HarfBuzz, Cairo, LibPSL, LibXml2, libSceNKWebKitRequirements, WPE). **No libc.sprx** — C-library functions are provided by libkernel exports. |
| Module path prefix | `/U59S16EXZp/common_ex/lib/…` (system partition) |

---

## 2. Exploit primitives (all device-proven)

1. **FontFace UAF → full arbitrary R/W (E2, complete).** Two-stage CSSFontFace reclaim (192-byte class); forged client walk reaches the WebProcess vtable; ARW established and repeatable every session (~10 s).
2. **Native call primitive: PC + RDI.** NativeExecutable function-pointer redirect (`neEntry+0x28` → target), with the JSC scope-swap delivering `RDI = fakeScope`. Proven with `thr_self` (TID witness) and `gettimeofday` (time witness, pre-correction era).
3. **Decode-immune `rawcall`.** Call, discard the raw return value unbound (raw kernel returns are invalid JSValues and crash at first touch), restore, read the scope's first 0x20 bytes as a memory side-channel.
4. **addrof.** Certified via JSDataView cell `+0x10` (m_vector → ArrayBuffer+0x20).

---

## 3. Address derivations & constants (per boot)

**libkernel base (lk):** heap registry `0x10001c8000` → thread-record pointer (value in `[0x10001f0000,0x1000200000)`) → pthread pointer (value in `[0x880000000,0x900000000)`) → walk q[8] links until `(q & 0x3fff) == 0x218` → **lk = q − 0x6C218**. Canary gate: `[lk+0x751D0] > 0x1000000`.

**WebProcess base:** **VP = BASE + 0x724DB28** where VP = the leaked CSSFontFace Client secondary-vtable pointer. Independently derived; reconciles against the public COOP slot tables (see §5).

**Section map (WebProcess.self):**

| RVA | Region |
|---|---|
| `0x0–0x4000` | ELF headers/phdrs — readable |
| `~0x4000–0x6AD7000` | `.text` — **execute-only** (reads fault; ~111.8 MB) |
| `0x6AD7000–0x724DB28+` | `.rodata`/vtables/`.data` — readable |

**Known WebKit function RVAs [device-arithmetic: VP_RVA minus the device-measured slot deltas]:** `fontStateChanged = 0x5B3D6B0`, dtor pair `0x5B3CFB0/0x5B3CFE0`, `ref = 0x5793400`, `deref = 0x5B3D810`, ICF no-op `0x4001750`, `~FontFace 0x412C450`.

**Methodology guard:** no patched/unpatched conclusion in this report derives from Sony's WebKit source drops — firmware-level behavior is established only by on-device measurement or by disassembly of dumped binaries (the kernel body in §7, the libc-based syscall map in §6). Source is used solely for interface/layout facts (the Client slot order, object field offsets), each cross-confirmed at runtime. Runtime module access: WebKit `.text` is execute-only (unreadable, boundary measured); the main binary's `.rodata`/`.data` are runtime-readable (the vtable walk every session; the 114 KB import-GOT dump, `tools/vpmap2-*.jsonl`); satellite-SPRX (libWebKit/libJSC) data segments are untested.

---

## 4. Object layout (the UAF object graph)

**CSSFontFace (192 B, Sony fork):** `+0x58` m_clients hash-table ptr (the leak, engine-written), `+0x68` WeakPtrImpl* (second leak), `+0x82` status (0=Pending, 3=Success), `+0x87` FontLoadTimingOverride. Marker recipe: `w[0]=0, w[1..3]=0x80, w[0x82]=3, w[4..5]=0x1000+k`.

**Client walk (gated every session):** FACE = the certified reclaimed buffer (**not** the scratch buffer); `L1 = [FACE+0x58]`; WeakPtrImpl `m_ptr` at **IM+0x08**; closure checks `[FO+0x08] == IM` and `[FO+0x10] == FACE`; `VP = [FO+0x00]`.

**Vtable preheader:** `[VP−0x10] = 0xFFFFFFFFFFFFFFE0` (offset-to-top −32), `[VP−0x08] = 0` (typeinfo). Itanium secondary vtable — matches `CSSFontFaceSet : RefCounted<>, CSSFontFace::Client`.

**Nine-slot fingerprint (VP deltas, stable across all boots):**

| Slot | VP − slot | Slot | VP − slot |
|---|---|---|---|
| s0 | `0x1710B78` | s3 | `0x1710478` |
| s1 | `0x1710B48` | s6 | `0x1ABA728` |
| s2 = s4 = s5 (ICF no-op) | `0x324C3D8` | s7 | `0x1710318` |
| | | s8 | NULL |

Slot order (source): 0/1 dtor pair, 2 fontLoaded, 3 fontStateChanged, 4 fontPropertyChanged, 5 updateStyleIfNeeded, 6 ref, 7 deref. `ref()` is the first virtual reached (`copyToVectorOf<Ref<Client>>`).

---

## 5. Cross-campaign reconciliation

`VP_RVA = 0x724DB28` satisfies seven independent arithmetic checks against ZigZagBoi1/PS5-14.10-Research's published values: s0_RVA `0x5B3CFB0`, s3 `0x5B3D6B0`, s6 `0x5793400`, s7 `0x5B3D810`, ICF no-op `0x4001750`, text-size equation (`RVA − 0x76DB28 = 0x6AE0000 ≈` measured XO boundary), and the `mod 0x4000 = 0x1B28` observation. The competing candidate `0xC6A1B28` yields the round base `0x800000000` and is rejected.

---

## 6. Syscall & function map (libkernel RVAs)

| Function | RVA | Basis |
|---|---|---|
| `thr_self` (2) | `lk+0x2C0` | FDE#5 entry; TID witness on device |
| `thr_new` (455) | `lk+0x410` | FDE#8 entry |
| r10 trampoline (`mov r10,rcx; syscall`) | `lk+0x3B7` | mid FDE#7 (start `0x3A0`); delivers arg4 |
| `gettimeofday` (118) | `lk+0xB50` | mid FDE#24 (start `0xB10`); E2 time witness |
| `thr_create` (430) | **`lk+0x13D20`** | libc `Thrd_create` helper `+0x4BDE0`, call `+0x4BE47` → thunk `0x358` → GOT `0x1179F0` |
| `thr_exit` (431) | **`lk+0x13EC0`** | libc `Thrd_exit` `+0x4C240`, call `+0x4C246` → thunk `0x418` → GOT `0x117A50` |
| `sigreturn` (417) | **`lk+0x13ED0`** | libc wrapper `+0x2F310` → thunk `0x288` → GOT `0x117988` (a real measured loader-env resolution) |
| Context block | `0x13EB0`, `0x13F20`, `0x13F40`, `0x142C0`, `0x416E0` | the five-label family; FDE#685 spans `0x13EB0+` |

**Retraction:** the earlier attribution `thr_create = lk+0x13ED0` is wrong; every fire built on it is invalid.

**GOT formula (loader-env libc):** thunk `0x108+k·0x10` → GOT slot `0x1178A0+8·(5+k)`.

---

## 7. Kernel sigreturn (417) — full body facts [S: disassembly of the 13.60 kernel dump, `0xa07280–0xa07632`]

- `copyin`s **0x500 bytes** from RDI (the ucontext record).
- Gates: `[+0xD0] < 8` (else EINVAL); RFLAGS cookie at `+0xF0` = equality-mask test vs the live trapframe, mask `0xFFFFFFFFFFDAB22A` (masked bits forced to live values); CS at `+0xE8` with `&3 == 3`; type at `+0x110` ∈ {`0x10000`, `0x10002`}; subtype at `+0x118` ∈ {`0x20001`, `0x20002`}.
- Type `0x10000` → jumps directly to the success path (no FP restore). Type `0x10002`+`0x20001` → FP state installed from **`+0x140`, 0x140 bytes** (call at `0xa0751c`); the dword at `+0x158` is ANDed with the global mxcsr mask.
- Success path: `bcopy(user+0x48 → tf, 0x90)` (**18 qwords = the full GPR file**); `bcopy(user+0xD8 → tf+0xe0, 0x30)` (ERR/RIP/CS/RFLAGS/RSP/SS); **FS base ← `[+0x480]`, GS base ← `[+0x488]`**; signal mask from `+0x08`; returns `0xFFFFFFFE` (EJUSTRETURN).
- **GPR slot order:** rdi `+0x48`, rsi `+0x50`, rdx `+0x58`, rcx `+0x60`, r8 `+0x68`, r9 `+0x70`, rax `+0x78`, rbx `+0x80`, rbp `+0x88`, r10 `+0x90`, r11 `+0x98`, r12 `+0xA0`, r13 `+0xA8`, r14 `+0xB0`, r15 `+0xB8`.

**Measured native-call return slot:** `retSlot = cfr − 0x328` (four independent boots; the call's own push writes it at call time).

---

## 8. TLS / TCB model (device-measured)

```
[TCB+0x00] = 0
[TCB+0x08] = TCB+0x40
[TCB+0x10] = pthread struct pointer
[TCB+0x38] = TCB            ← the PS5 self-pointer (NOT FreeBSD's +0)
```

Discovery rule: scan the pthread struct (ptS) for `0x88`-band pointers `C` with `[C+0x10] == ptS`; validate `[C+0x38] == C`. The TCB allocation ends in `0x080` at the page level across boots. lk's own string `"allocating TLS+TCB for the primary thread. tls=%p size=%lx,map_size=%lx r=%x"` corroborates the model.

---

## 9. The SROP campaign — what twelve iterations established

Verified individually: the §7 gates decoded and written; the complete FP area (`+0x140..0x280`, 40 qwords from the measured 814a record: `0x20037F` at `+0x140`, `0x2FFFF00009FE5` at `+0x158`, `0xFFFF` at `+0x168/178/188/198/1A8`, `0x8180000000000000` at `+0x1D0`, `0x4007` at `+0x1D8`, `0x3FF0000000000000` at `+0x230`, `0xFFFF…` at `+0x270/+0x278`); the FS base (§8 TCB); the known GPRs (RDI=scope, RBP=cfr); retSlot; and a clean resume design (RIP = the no-op function entry, RSP = retSlot — the double-ret).

**Empirical call-safety rules (each paid for with sessions):**
- Multi-arg **writer** syscalls through the fake scope = session death (documented sweep class: export entries #0, #3, #24, #63). sigreturn is a **reader**-class syscall (kernel reads the ucontext, never writes it) — not blocked by this rule.
- The fake scope is a tuned slot inside a sprayed marker buffer (MBUF+0x80; zeros + the calibrated VM at `+0x38`). **Any bulk record written over the scope's live region (+0x00–0x4F0) or into neighboring spray slots corrupts live objects** and kills the next call. There is no engine-free scratch region in the WebProcess (the 64 MB view is a forged ArrayBuffer size).
- The RFLAGS cookie forces masked bits to live values — `0x202` passes.
- Stale FS bases are fatal: the loader-boot TCB (`0x881090080`-class) restored into the WebProcess kills on the first thread-local access.

**Closure (pre-registered negative, reproduced):** the sigreturn GPR restore installs the **full register file**; the native-call trampoline keeps live data in **callee-saved registers** across the call; those values are structurally unobtainable from the JS context (stack frames hold the caller's pushed values, not the trampoline's live ones). The resume faults in the trampoline's post-call code. **The WebProcess scope-swap SROP route is closed on the mechanism level.** The only architectures that capture the true register state: the game-lane `fcall_with_rax` (loader env) or a different call carrier whose registers can be captured.

---

## 10. WebProcess module map (fully dumped)

**Import GOT:** `VP+0x104000–0x120000` (readable; `VP+0x120000+` has an unmapped hole — reads die). Contents: 12 module-band clusters; the lk block = **83 resolved libkernel function pointers, all FDE-exact entries** (one slot = the canary address), stable count across boots. Region pointer census: bands 0x201 (141 ptrs), 0x202=lk (83), 0x203 (362), 0x204=self (45), 0x205 (221), 0x206 (9), 0x207 (92), 0x209 (239), 0x20b (34), 0x20c (142), 0x20e (75), 0x20f (14). **The WebProcess does not import the thread/context syscalls** — no NID bindings for them exist anywhere readable.

**Module registry (heap, `0x10001c8000+`):** the rtld entry with the inline path `…/libSceRnpsNKInjectedBundle.sprx`, string-object header `{(len<<32)|flags, ptr}`.

**JSC structures in the VP band:** `VP+0x10CC48` = 24-byte string/atom records (`{id|kind, str_ptr, hash}`); `VP+0x120000` = a tag-1 index array over them (first entry = `VP+0x10CC48` exactly); `VP+0x10000` = a vtable-interleave region over the JSC-class module (~`0x826c00000`-band, the module with the most references).

---

## 11. libkernel internal map (fully read)

| RVA | Content |
|---|---|
| `0x0–0x48000` | **XO text** (page-aligned to the data start; reads at `0x44000` die) |
| `0x48000` | **FDE/unwind table** — 2092 entries, `{lo32 = eh_frame/CIE offset, hi32 = rva offset (from 0x48000)}`; matches the banked FDE map (`FDE#[idx, start, len, lo32]`) |
| `0x4D000–0x5C000` | **SceRel relocation table** — 24-byte records `{offset, 0, addend}`; offsets increment +8 into `0x17300+` |
| `0x5C000–0x751D0` | **String/message region** — pthread messages, sysctl names (`kern.sandbox.id`, `kern.sdk_version`, `machdep.rcmgr_*`), module paths, the TLS/TCB format string |
| `0x751D0` | the canary slot; the page rest = misc data (hash-like qwords, `NPXS4008` title ID) |
| `0x76000+` | **.bss start** (all zeros; segment continues) |

**PS5 SPRX modules export by NID only** — no symbol-name tables exist in module data. The `sweep`-era "export table" reads were FDE entries.

## 12. NID data (banked)

| Function | NID (raw 64-bit LE qword) |
|---|---|
| `sigreturn` | `0x8ca4a965161b8d9a` |
| `getcontext` | `0x73faa703dcf4aa75` |
| `setcontext` | `0xef2caa18ef5454d9` |

Corpus NID strings decode via base64 (`mo0bFmWppIw` → sigreturn, `dar03AOn+nM` → getcontext, `2VRU7xiqLO8` → setcontext). The NIDs are **absent from every readable WebProcess region** (lk segments, VP band, scanned heap) in all tested encodings — verification of the §6 attributions requires the game lane (loader env, where libc.sprx is loaded and its GOT/NID data readable).

## 13. Empirical operational rules

- A "mem warning" on console = the WebProcess died; beacons already sent are valid evidence.
- Exact-value heap scans can hit the command's own parsed arguments (**self-hit artifact**) — verify by reading the hit neighborhood before accepting.
- `read ok` from the CLI is node's exit-0; check the reply content (timeout replies print as errors but exit 0).
- Fresh ASLR per guide entry; one command in flight; every `shell.html` change needs a dispatcher bump + `node --check` of the extracted script; CRLF normalization before newline-anchored patching.
- Read gates: the readable VP band ends at `VP+0x120000`; lk text is XO; only proven bands or `force` with known-mapped targets.

## 14. Open items

1. **Game lane** (Hamidashi Creative loader): `fcall_with_rax` register capture, `thr_new(param, 0x38)` spawn (383a/384b-proven in the public corpus), the NID walk in readable libc data, and the sigreturn/getcontext attribution verification. Prerequisites: the demo installed, payload save staged, PSN sign-in (the research DNS spoofer blocks update hosts while passing auth).
2. Kernel leg (downstream of a spawn): KASLR leak (the corpus's measured kernel anchors exist for 13.60), kernel bug, kernel R/W.
3. Community contributions drafted: the VP RVA reconciliation and section-map answers to ZigZagBoi1 issues #284/#295, the S0-1 byte-portability analysis for #282.

---

*Conducted on the owner's retail console under Sony Interactive Entertainment's PlayStation security research / bug bounty program (HackerOne). See `PS5-14.10-Jailbreak-Research/CLAUDE_FINDINGS.md` §Authorization.*
