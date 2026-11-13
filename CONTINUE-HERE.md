# PS5 14.10 WebKit Jailbreak — Session Continuation

You are continuing an active PS5 firmware 14.10 WebKit exploit research campaign. The owner's retail console is at `10.100.102.14`. The mission: browser entry → WebProcess code exec → kernel R/W → hypervisor bypass.

## Where to find everything

Read these in order before doing anything:
1. `D:\ps5\HANDOFF.md` — **start with the RESUME HERE block at the top** — the full mission status table, the current blocker, the ranked next moves, the file inventory, the console protocol
2. `D:\ps5\GLM_Findings.md` — chronological findings **E1 through E18** — E18 is the dispatch-campaign ledger with all 12 eliminated hypotheses
3. `D:\ps5\PS5-14.10-Research\docs\COOP_ANALYSIS.md` — the source-derived COOP analysis with **all device-verified offsets** (corrected from estimates by on-device evidence)
4. `D:\ps5\AGENTIC-FINDINGS.md` — companion doc (mirrors HANDOFF)

## Current state (the one-paragraph version)

The **entire read-side is certified, cached, and repeatable in ~10 seconds per session**: FontFace UAF → heap leak → arbitrary read (walk chain: IM→FO→VP) → module base (`BASE = VP − 0x724DB28`, ASCII-verified) → wrapper identity (FACE-IDENTITY-OK, 3 gates: vtable/impl-backptr/backing) → addrof (ADDROF-CERTIFIED: JSDataView cell found via calibrated oracle scan, all 6 markers verified) → **the write target is known**: `cell+0x10` (the DataView's m_vector field, beaconed every session). The engine also **writes into our forged client table** (the `document.fonts.add()` insert — witnessed twice). The **one blocker**: triggering the client dispatch (`faces[zi].load()`) hangs in the WeakHashSet's `computeSize()` → `removeIf()` on our forged `m_clients` — **before any vtable call** (proven by crash-bisection: garbage at the ref() slot → no crash). ~12 hypotheses eliminated on-device (v17b→v17r). The critical insight: the PS5's WebKit fork is **older than the 616 branch** (CSSFontFace has rc@+0x00, no vtable — the 616 source has a vtable), so the 616-era WeakHashSet/Algorithms/HashTable code we fetched may not match the fork's actual behavior.

## Your first move (ranked)

1. **Fetch the fork-era WebKit source** (Safari 13 / 605.1.x, ~2020): `Source/WebCore/css/CSSFontFace.cpp`, `Source/WTF/wtf/WeakHashSet.h`, `Source/WTF/wtf/Algorithms.h`, `Source/WTF/wtf/HashTable.h` from the WebKit GitHub mirror at a pre-616 commit (~2020 era). Compare the `computeSize()`/`removeIf()`/`copyToVectorOf` implementations against the 616 versions — the hang is in this machinery.
2. **Craft the WeakHashSet operation-counter bytes** (+0x60/+0x64 on the face) — the real face's values are {3, 2} (mutable counters). If the fork's code skips cleanup when counters are low, copying them may unblock the dispatch.
3. **Alternative dispatch triggers** that avoid the pump entirely: `fontLoadEventOccurred()` (the source-completion path), the GC destructor (`~FontFace` → `removeClient`), CSSFontFaceSet's family-merge.
4. **LLDB on-device** if the toolchain permits — attach to the hung WebProcess, read the PC.

## The probe infrastructure (all working, all proven)

- **`tools/remote-loader/v17.html`** — the current probe (dispatcher points at `v17.html?v=20`). Full chain + dispatch attempt. Cycles harmlessly (~30s/session). Modify this file for new experiments; bump `?v=N` in `index.html` for cache-bust.
- **`tools/remote-loader/v688.html`** — the certified read-chain probe (the stable base)
- **`tools/remote-loader/index.html`** — the dispatcher (what the console loads)
- **`tools/remote-loader/auto_continue.py`** — beacon-driven crash-dialog auto-dismiss (V6/V17-aware regex)
- **`tools/remote-loader/scan-watch.ps1`** — colored live watcher
- **`tools/remote-loader/host.py`** — the beacon sink; all probe beacons land in `host-beacons.log`
- **Cache keys (localStorage on the console, persist across reboots)**: `v688_self`, `v688_buf`, `v688_cell` — all pattern-verified per session

## Console protocol (learned the hard way)

- **Close/reopen the guide app** to load each new probe version (the URL `?v=N` busts the cache)
- **Reboot the console** only after memory-warning storms (the budget is ~1 crash per boot before OOM)
- Sessions that complete cleanly (PATHB-DONE) self-cycle via RT=16 (30s reload)
- The beacon log is ~160MB — use `Select-String -Pattern` to filter, never read it raw

## Key device-verified facts (do not re-derive)

```
VP_RVA = 0x724DB28                    (ASCII-verified: "Function\0TDZFail", "JSGlobalProxy\0JS")
BASE = VP − 0x724DB28                 (computable per session from the walk chain)
fontStateChanged = BASE + 0x5B3D6B0  (= VP − 0x1710478, device-confirmed via vtable slot 3)
noop = BASE + 0x4001750
destructor = BASE + 0x5B3CFB0

CSSFontFace (the 192B reclaimed object, device-measured):
  +0x82 = status byte (0=Pending, 1=Loading, 2=TimedOut, 3=Success, 4=Failure)
  +0x87 = FontLoadTimingOverride (0=None, 1=Block)
  +0x58 = m_clients table pointer
  +0x60..0x67 = hash-table object header (mutable counters, {3,2} on a real face)
  +0x68 = m_wrapper (WeakPtr impl pointer)
  +0x88..0xBF = timer region

FontFace wrapper (the JS-facing C++ object, device-measured):
  +0x00 = vtable (= VP)
  +0x08 = impl back-pointer (= L2, the leaked WeakPtrImpl)
  +0x10 = m_backing (= SELF, our reclaimed buffer)
  +0x18 = m_loadedPromise pointer

JSDataView cell (the addrof target, all 6 markers verified):
  +0x08 = butterfly (= 0)
  +0x10 = m_vector (→ ArrayBuffer+0x20) — THE COOP WRITE TARGET
  +0x18 = m_length (= 0x40)
  +0x20 = m_byteOffset (= 0x20)

Oracle semantics (fully decoded, device-calibrated):
  chk(c) = TRUE iff A ≤ c ≤ B where (A,B) = the two uint32s at the probe address
  Inverted pair (A>B) → always FALSE; test codepoints must be ≤ 0x10FFFF

WeakHashSet table format (device-verified from the real table):
  Metadata at T−0x10: {deletedCount, keyCount, tableSizeMask, tableSize} — real: {2, 1, 7, 8}
  Deleted marker = 0xFFFFFFFFFFFFFFFF
  The real table is 80B: 16B metadata + 8 buckets

Hash-table object header at +0x58..0x67 on the face:
  +0x58 = table pointer; +0x60..0x67 = the HashTable object's own fields (NOT the table's
  metadata — these are the fields the ITERATOR reads; the real face's are {3, 2})
```

## What to NOT waste time on (already eliminated)

Every hypothesis in GLM E18's ledger — table format (3 variants), timer (3 states), promise (3 configs), vtable slots (3 configs), status byte (confirmed offset), sources (post-read zeroing), hash-table object header (real-face copy), real clients (skipped), ref/deref slots (garbage probe → no crash → **the dispatch never reached the vtable**). The hang is in the WeakHashSet's pre-dispatch cleanup, and the 616-era source we already fetched may not describe the PS5's older fork.
