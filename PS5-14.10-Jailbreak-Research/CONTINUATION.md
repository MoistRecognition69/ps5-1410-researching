# PS5 14.10 Jailbreak — Continuation Handoff

**Checkpoint date:** 2026-11-17  
**Current dispatcher:** `v=srop34`  
**Next device command:** `sropfire ic` (the PS5 TCB self-pointer validated at the measured +0x38 offset; the FP constants + the gates + the ret-gadget resume unchanged)  
**Status:** the WebProcess SROP route is EXHAUSTED (the clean-console verdict): the scope-call path is healthy for userland-only targets but ANY syscall target through the fake scope dies - the kernel's copyin/copyout of the ucontext crosses the cage-class pages and the record writes collide with live neighbors - the constraints have no overlap in the WebProcess. THE ROUTE FORWARD = the game lane (the Lua loader's fcall_with_rax: no scope-swap, RAX-controlled syscalls, the 383a/384b-proven spawns); the PSN constraint is manageable (the DNS spoofer blocks the update hosts while passing the auth servers, and the Hamidashi demo is a 14.00-era title).  
**Authorization:** Sony/HackerOne-sanctioned research on the user's retail PS5. Read the authorization block at the top of `CLAUDE_FINDINGS.md` before continuing.

## 1. Exact current state

The next experiment is ready but **has not run**:

```powershell
$env:SHELL_PORT = 8443
node "D:\ps5\PS5-14.10-Jailbreak-Research\tools\ws-shell\shell-cmd.js" sropfire rt
```

`sropfire rt` is a **gettimeofday sigreturn roundtrip**, not a thread-creation attempt.

Current result before this checkpoint:

- srop12–15 (four hand-built install shapes, ending with the complete 814a replication) all died after `SROP-CALL target=lk+0x13ED0`; the two capture probes (`gc`=0x142C0, `gc2`=0x13F20, VM-safe buffers) both died at the capture call. The scope-swap capture class is closed.
- **THE REAL DEATH CAUSE (found in the corpus's own kernel-side 417 disassembly, `docs/FINDINGS.md` 0xa07xxx):** the install sets the thread's **FS/GS base from the record's `+0x480`/`+0x488`** and copies only the GPRs (`+0x48`, 0x90 bytes), the tail (`+0xD8`, 0x30 bytes: ERR/RIP/CS/RFLAGS/RSP/SS), and the signal mask (`+0x08`). The `+0x280..0x2D8` chain is **never copied** (the old pointer-chain-kill theory RETRACTED). All four installs died because `+0x480` held fakeScope garbage (srop12–14) or the loader boot's TLS base `0x881090080` (srop15) — the resumed JS faults on its first fs-relative TLS access.
- Gate details confirmed: CS `&3==3`, type `0x10002|0x10000`, subtype `0x20001..0x20002`, and the RFLAGS cookie is an equality-mask test against the LIVE trapframe (mask `0xFFFFFFFFFFDAB22A`) whose masked bits the installer forces to the live values — our `0x202` passes.
- **srop18's fix:** the FS base is discovered in-session — the pthread struct (already walked) is scanned for the FreeBSD TCB self-pointer (`[fsbase]==fsbase`) and written to `+0x480`; `+0x488=0` (the captured GS); the mask region `+0x08-0x28` is zeroed. The record keeps the 814a constants, the captured D0, and the live VM pair (a 417 rejection still returns through the trampoline alive).

Do not start with plain `sropfire`; run `sropfire rt` first.

## 2. What is already proven

### WebProcess capability

- Full arbitrary read/write in the compromised WebProcess.
- Arbitrary native PC plus RDI through the native-executable redirect, with verified restoration.
- Decode-immune `rawcall` for native functions that return raw non-JS values.
- Per-session libkernel base derivation through the pthread backlink chain and canary gate.
- `thr_self` has been executed with a TID witness in earlier work.
- The UAF/FontFace object walk is now correctly identified instead of merely accepting the first pointer-shaped object.

### Correct FontFace Client identification

The corrected walk requires all of these:

- Start at **`v688_self`**, the certified reclaimed CSSFontFace, not `v688_buf`. The latter is the later OOB/scratch buffer.
- `L1 = [FACE+0x58]`.
- WeakPtrImpl `m_ptr` is at **`IM+0x08`**, not `+0x10`.
- `VP = S.BASE + 0x724DB28`.
- Vtable pre-header: offset-to-top `-32`, typeinfo `0`.
- Closed object cycle:
  - `[FO+0x08] == IM`
  - `[FO+0x10] == FACE`
- Nine-slot fingerprint from issue #295 and our older captures:

| Slot | `VP - slot` |
|---|---:|
| 0 | `0x1710B78` |
| 1 | `0x1710B48` |
| 2 / 4 / 5 | `0x324C3D8` |
| 3 | `0x1710478` |
| 6 | `0x1ABA728` |
| 7 | `0x1710318` |
| 8 | `NULL` |

`fire 7` passed this identity gate repeatedly.

### Corrected syscall mappings

Independent capstone verification of the saved 14.10 libc text and import window supports:

| Function | libkernel RVA | Static evidence |
|---|---:|---|
| `thr_create(430)` | **`lk+0x13D20`** | `Thrd_create` helper at libc `0x4BDE0`, call at `0x4BE47` → thunk `0x358` → i=42 → GOT `0x1179F0` |
| `sigreturn(417)` | **`lk+0x13ED0`** | libc wrapper `0x2F310` → thunk `0x288` → i=29 → GOT `0x117988` |
| `thr_exit(431)` | **`lk+0x13EC0`** | `Thrd_exit` wrapper `0x4C240`, call at `0x4C246` → thunk `0x418` → i=54 → GOT `0x117A50` |
| `gettimeofday(118)` | `lk+0xB50` | Previously E2-proven |

**Retraction:** the older `thr_create = lk+0x13ED0` attribution was wrong. Every earlier fire based on that assignment is invalid.

These mappings are strongly supported by imports and wrapper semantics, but the raw libkernel stub bytes are execute-only and have not been read. Treat the mapping as high-confidence static attribution, not direct byte proof.

### Measured native recovery slot

Four historical TWR measurements place the native-call return slot at:

```text
retSlot = cfr - 0x328
```

Examples include `0x7ef399ef8` against `0x7ef39a220` and three equivalent pairs. The sigreturn call's own native-call push writes that slot before the target returns, so its pre-fire contents and all later rehearsal scans were unnecessary.

## 3. Routes that are closed — do not repeat them

### Vtable payload routes are closed

1. **Heap FAKEVT:** the all-real, byte-identical ArrayBuffer table died when the actual asynchronous callback arrived. This reproduces issue #282's buffer-vptr wall.
2. **Real VP patching:** a same-value write to the real module VP died immediately. The real vtable is not writable by our ARW on this boot.

Do not run old `fire`, `fire 5`, `fire 6`, or `fire 8` variants as a workaround.

### The 13.60 high-stub map is falsified

- `callret(lk+0x1B860)` returned `-1`, not a WebProcess PID.
- `rawcall(lk+0x1B840)` died without a gettimeofday witness.

Do not use the 13.60 high offsets such as `0x1CDE0`, `0x1BA64`, `0x1B160`, or `0x1B4E0` on this WebProcess.

### Context-wrapper guessing is closed

Several low-PLT context assignments were tried and failed. Do not spend more sessions guessing `getcontext`, `setcontext`, or `swapcontext` RVAs. The current SROP path does not require `getcontext`.

### Blind scanning is closed

- No candidate marching or blind function sweeps.
- No linear ELF-magic walks.
- No raw module-text reads: module text is execute-only in this WebProcess.
- Do not resume the upward `cfr` pointer scan that died.
- Only identified targets and proven-readable regions are allowed.

## 4. Current SROP design

### Normal fire (`sropfire`)

1. Derive `lk` with the proven pthread backlink chain.
2. Build the child context at `CTX = fakeScope+0x1000` with `RIP=thr_exit(lk+0x13EC0)` and a mapped stack.
3. Build the parent sigreturn frame with:
   - `RDI=CTX`
   - `RSI=WIT` — a safe writable parent-side tid output
   - `RDX=0`
   - `RIP=thr_create(lk+0x13D20)`
   - `RSP=retSlot = cfr-0x328`
4. Call `sigreturn(lk+0x13ED0)`.
5. The parent writes the new tid to `WIT`; the child starts at `thr_exit`.

The intended result is `reply.threadCreated=true` and a small nonzero `reply.witness` tid.

### Roundtrip control (`sropfire rt`)

Same frame and recovery, except:

- `RIP=gettimeofday(lk+0xB50)`
- `RDI=CAP`
- `RSI=0`

A valid `reply.roundtrip.valid=true` plus a surviving parent would prove sigreturn and the recovery path before attempting `thr_create`.

## 5. New in srop18

The capture modes are gone; the fix is surgical. The record at `CAP=fakeScope`:

- **`+0x480` = the discovered live FS base** — srop19's v2 rule: scan the pthread struct (`ptS`, from the walk) for `0x88`-region pointers, read `+0x18` at each candidate, and accept the one whose **`+0x10` equals the pthread itself** (the mutual reference) — measured live: `ptS=0x880613b60`, its `+0x1F0` slot = `0x8ff81c080`, and `[TCB+0x10] == ptS`; TCB allocations end in `0x080` across boots/processes (`0x881068080`, `0x881090080`, `0x8ff81c080`). `+0x488 = 0` (the captured GS).
- **`+0x08-0x28` zeroed** — the empty signal mask instead of live scope bytes (the kernel sets the mask from there).
- The 814a constants ride along (GPR tail, selector pack, FP/reserved, captured D0 `0x3B003B00000001`), the `+0x280..0x2D8` chain zeroed (never copied — irrelevant), and the live VM pair `+0x38/+0x40` skipped (a 417 rejection still returns through the trampoline alive, the fire19 proof).
- Patches after the loop: the mode decides — `ic` = RIP `[cfr-0x328]` + RSP `cfr-0x320` (the 1359a [B] mechanics control, no target), `rt` = gettimeofday (`RDI=CAP`, `RSI=0`, `RIP=lk+0xB50`), real = `RDI=CTX, RSI=WIT, RIP=lk+0x13D20`; RSP = `cfr-0x328` and `RDX=0` for rt/real.
- `reply.fsbase` + `SF 1b` beacon confirm the discovery; if no TCB is found, `reply.pthreadHead` dumps the first 0x40 qwords for offline analysis and nothing fires.

## 6. How to interpret the next run

### If `sropfire rt` survives with a valid time signature

Sigreturn + the captured-shape install + the recovery path are all proven, **and the FS-base discovery is confirmed** (`reply.fsbase` sane). Next run:

```powershell
node "D:\ps5\PS5-14.10-Jailbreak-Research\tools\ws-shell\shell-cmd.js" sropfire
```

A small nonzero `reply.witness` with the parent alive is the spawn/E3 milestone.

### If it dies after `SROP-CALL target=...13ED0` (with a sane `reply.fsbase`)

The FS-base fix didn't complete the picture — the death would then be in the GS base (`+0x488=0` wrong for the WebProcess?) or another copied field's semantic (e.g., the garbage signal mask, or the GPR tail values). Do NOT fire more identical sessions: the next move is a diagnostic variant that installs with RIP = the ORIGINAL return path (the 1359a [B] mechanics control) to isolate install-vs-target, offline-designed first.

### If `reply.fsbase` is empty / `no fsbase self-pointer`

The TCB self-pointer isn't in the scanned pthread window. `reply.pthreadHead` (0x40 qwords) is banked in the reply — analyze offline, widen the scan, or check the alternate TCB locations before any fire.

### If the command returns but `witness=0`

That is a decline or a missed effect, not a spawn. Read the SROP beacons and `reply.sigreturnRestored`; do not reinterpret it as proof that `thr_create` is wrong.

### Beacons

- `SROP-1`: `lk` and canary
- `SROP-2`: direct `retSlot=cfr-0x328`
- `SROP-3`: selected roundtrip or real-fire target
- `SROP-CALL`: actual target about to execute
- `SROP-4`: post-call witness, if the parent survives
- `SROP-5`: settled witness, if the session remains alive

A console “mem warning” means the WebProcess died. Beacons already sent remain in `tools/ws-shell/shell-beacons.log`.

## 7. Instrumentation lessons that must not be reintroduced

- Do not zero `CAP=S.fakeScope`; it is live native-call scope metadata.
- `v688_buf` is scratch, not the certified face. Use `v688_self` for the walk and MBUF only for scratch.
- WeakPtrImpl `m_ptr` is at `+0x08`.
- VP is the slot-0 address point. A copied table must install `RAW+0x10`, not `RAW`.
- `FO+0x20` is not a second Client vtable.
- Do not overwrite DIAG5's gettimeofday with the generic diagnostic `else` branch.
- Never set `dispatchProven` after restoring the vtable pointer and comparing it to FAKEVT; that produced false positives.
- Do not rely on `RIP2-AFTER` alone: `style='italic'` can return early when the slope is unchanged.
- Keep real `ref`/`deref` slots when testing any callback; `ref()` is the first virtual reached.
- Preserve one shell command in flight at a time because of the server busy-guard.
- Bump and verify the dispatcher after every `shell.html` edit or the PS5 may serve the stale page.
- Normalize CRLF before any newline-anchored Node patching.
- Run `node --check` on the complete extracted page script after every edit.

## 8. Operational recipe

1. Ensure `host.py` is running with UTF-8 environment variables and Git's `usr/bin` on PATH for `openssl`.
2. Ensure the WS shell server is running on `8443` with the pinned cert in `tools/ws-shell/.certs/`.
3. Re-enter the PS5 User Guide. Each entry is a fresh WebProcess and fresh ASLR.
4. Wait for the `ready` beacon with `pcControl:true`.
5. Run commands directly; do not use the old timestamp watcher that missed an already-fired ready line.
6. Use `SHELL_PORT=8443` for every CLI invocation.
7. If the page dies, re-enter. Do not reuse addresses from the previous boot.

## 9. Important files

- `PS5-14.10-Jailbreak-Research/CONTINUATION.md` — this handoff.
- `PS5-14.10-Jailbreak-Research/CLAUDE_FINDINGS.md` — chronological campaign evidence and every correction.
- `PS5-14.10-Jailbreak-Research/tools/ws-shell/shell.html` — current `sropfire` implementation.
- `PS5-14.10-Jailbreak-Research/tools/ws-shell/shell-cmd.js` — CLI.
- `PS5-14.10-Jailbreak-Research/tools/ws-shell/shell-beacons.log` — live-session evidence.
- `PS5-14.10-Jailbreak-Research/tools/remote-loader/index.html` — dispatcher, currently `v=srop14`.
- `PS5-14.10-Jailbreak-Research/tools/lc-import-map.json` — corrected PLT/GOT and syscall mappings.
- `D:\ps5\PS5-14.10-Research\results\phase17_new_vectors\1215a_libc_dump_20261105_100131.txt` — saved libc text used for offline capstone analysis.
- `D:\ps5\PS5-14.10-Research\results\phase17_new_vectors\1215b_libc_import_window_20261105_100207.txt` — saved import slots.
- `D:\ps5\PS5-14.10-Research\results\phase17_new_vectors\814a_getcontext_dump_20261026_122659.txt` — measured sigreturn frame layout.
- `D:\ps5\PS5-14.10-Research\results\phase17_new_vectors\814b_sigreturn_roundtrip_20261026_122800.txt` — measured 421→417 roundtrip.

## 10. Repository state

- Last committed baseline: `b06745b7`.
- The current improvements are **uncommitted working-tree changes**. No commit or push has been made.
- Modified at checkpoint:
  - `CLAUDE_FINDINGS.md`
  - `tools/lc-import-map.json`
  - `tools/remote-loader/index.html`
  - `tools/ws-shell/shell-cmd.js`
  - `tools/ws-shell/shell.html`
- This handoff adds `CONTINUATION.md`.
- Other untracked files/directories also exist (`firmware/`, shell certs, candidate maps, etc.). Do not sweep unrelated untracked content into a commit.

## 11. If the spawn succeeds

The next stage is the child-as-executor, not more browser exploitation:

- Child ucontext GPR block:
  - `RDI+0x48`, `RSI+0x50`, `RDX+0x58`, `RCX+0x60`
  - `R8+0x68`, `R9+0x70`, `RAX+0x78`
- `lk+0x3B7` is a measured generic `mov r10,rcx; syscall` trampoline for a caller-selected `RAX` and controlled argument 4.
- Children must exit after their work; do not accumulate spinning threads.
- Kernel-leg work then proceeds through argument power, KASLR discovery, a validated kernel bug, and kernel R/W.

Until a tid witness is obtained with the parent alive, none of those post-spawn steps is unblocked.
