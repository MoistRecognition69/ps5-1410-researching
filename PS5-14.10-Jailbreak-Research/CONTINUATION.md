# PS5 14.10 Jailbreak — Continuation Handoff

**Checkpoint date:** 2026-11-17  
**Current dispatcher:** `v=srop16`  
**Next device command:** `sropfire gc` (capture probe) — then `sropfire rt` only if the capture gates pass  
**Authorization:** Sony/HackerOne-sanctioned research on the user's retail PS5. Read the authorization block at the top of `CLAUDE_FINDINGS.md` before continuing.

## 1. Exact current state

The next experiment is ready but **has not run**:

```powershell
$env:SHELL_PORT = 8443
node "D:\ps5\PS5-14.10-Jailbreak-Research\tools\ws-shell\shell-cmd.js" sropfire gc
```

`sropfire gc` is a **capture-only probe**: it calls `getcontext(lk+0x142C0)` with `RDI=B` (a scratch clone of the live scope head) and validates the record the kernel writes. **No sigreturn install happens in `gc` mode.**

Current result before this checkpoint:

- `srop12` (real), `srop13 rt`, `srop14 rt` (full 814a constants) and `srop15 rt` (the COMPLETE 814a replication — all 152 record qwords written, constants replicated, zeros where the record is zero, the boot-specific pointer chain zeroed, D0 captured, only the live VM pair skipped) all died immediately after `SROP-CALL target=lk+0x13ED0` — four installs, four deaths, one identical beacon pattern.
- With every record byte accounted for, the kill is the **boot-specific pointer chain** (`+0x280..0x2D8`, SCS/fsbase-class): the kernel cannot restore zeros there, and those values cannot be known without a live capture. **The hand-built frame class is closed — permanently.**
- `srop16` replaces the hand-built parent frame with an **in-session kernel capture**: `getcontext(lk+0x142C0)` with `RDI=B` writes the TRUE current record (real fsbase/gsbase/SCS/FP for this thread) into `B=fakeScope+0x2000`, which is pre-cloned with the live scope head so the post-call trampoline VM read (`[B+0x38]`) stays valid. `B+0x48==B` (the captured RDI self-pointer) + magic `0x480` proves the capture.

Do not run `sropfire rt` or plain `sropfire` before a `gc` run has passed its gates.

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

## 5. New in srop16

The hand-built parent frame is gone. All modes now share the **in-session kernel capture**:

- `B = fakeScope+0x2000` is pre-cloned with the live scope head (0x48 bytes, VM pair included), so the post-call trampoline read of `[B+0x38]` stays valid.
- The capture call is `getcontext(lk+0x142C0)` with `RDI=B` (scopeSlot swapped to B). The kernel writes the TRUE current record: fsbase/gsbase/SCS/FP all real for this thread, this boot.
- `mode=gc` stops after the capture gates — no install. It banks CS/SS/RFLAGS/magic/type/subtype/D0/RIP/RSP and answers the one open question: does the kernel also write the record preamble (`vmAfter` vs `vm38`)? If it does, the VM slot is zeroed mid-call — the V82-class death — and no capture through the scope-swap is survivable.
- `mode=rt` patches ONLY args (`+0x48/+0x50`), RIP (`+0xE0 = lk+0xB50`) and RSP (`+0xF8 = cfr-0x328`) on the captured record, then installs via `sigreturn(lk+0x13ED0)` with `RDI=B`. Every other byte is kernel-true.
- The real fire patches `RDI=CTX, RSI=WIT, RIP=thr_create` on the captured record instead.
- Hard capture gates (`B+0x48==B`, magic `0x480`, type `0x10002`, subtype `0x20001`, CS `0x43`, SS `0x3B`) abort before any install.

## 6. How to interpret the next run

### `sropfire gc` — the capture verdicts

| Outcome | Meaning | Next |
|---|---|---|
| Alive + `capture.valid=true` + `vmAfter==vm38` | `0x142C0` = getcontext, the kernel leaves the preamble, **the capture is banked and VM-safe** | `sropfire rt` |
| Alive + `capture.valid=true` + `vmAfter==0` | Capture works, but the kernel zeroes the record preamble — the VM slot only survived because nothing read it this time | stop; offline VM-slot analysis before any install |
| Alive + `capture.valid=false` with fields present | Wrong RVA or partial writer — read the fields, stop | offline |
| Death after `GC-CALL` | `0x142C0` is not a returning writer (setcontext/swapcontext/sigreturn class) | next candidate `0x13F20` in a NEW session, never two candidates per session |

### If `sropfire rt` survives with a valid time signature (after a passed `gc`)

This proves sigreturn + the captured-record install + the recovery path. Next run:

```powershell
node "D:\ps5\PS5-14.10-Jailbreak-Research\tools\ws-shell\shell-cmd.js" sropfire
```

A small nonzero `reply.witness` with the parent alive is the spawn/E3 milestone.

### If `sropfire rt` dies after `INSTALL target=...13ED0` (with a passed capture)

The captured record was kernel-true; the death would then be in the 417 mapping itself (`0x13ED0`) or the recovery mechanics. Stop firing; the next work is offline revalidation of the five-context-wrapper block (wrapper shapes in the 1215a dump) — no more device installs.

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
