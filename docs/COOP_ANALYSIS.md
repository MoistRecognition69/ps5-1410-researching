# COOP Analysis — FontFace Vtable-to-Method Mapping

Date: 2026-11-12
Source: WebKit main branch (CSSFontFace.h, FontFace.h, FontFace.cpp, CSSFontFace.cpp)
Reference: LinearFox CSSFontFace-to-ARW writeup (ntfargo/ufm42)

## FontFace Class Hierarchy

```
FontFace final
  ├─ RefCounted<FontFace>          (no vtable, CRTP ref counting)
  ├─ ActiveDOMObject                (primary vtable, offset 0x00)
  │   └─ ContextDestructionObserver (virtual ref/deref, destructor)
  └─ CSSFontFaceClient             (secondary vtable, offset 0x20)
      └─ AbstractRefCountedAndCanMakeWeakPtr
```

offset_to_top for secondary = -32 (0xFFFFFFFFFFFFFFE0) [M from p809]

## Primary Vtable (PV_RVA = 0x724DAC0, 11 slots)

> **DEVICE MEASURED (2026-11-13, sessions NQ10G2/3B00VR) — THE LAYOUT BELOW WAS WRONG.**
> The real WebCore::FontFace wrapper layout (v688 v10, on-device, ASCII/pointer-certified):
>
> ```
> +0x00  vtable = VP (RVA 0x724DB28 — the walk-leaked vtable; there is NO
>        separate primary/secondary split at +0x00/+0x20 on the wrapper)
> +0x08  WeakPtrImpl* back-pointer (== L2, mutual with impl+8 → owner)
> +0x10  m_backing → CSSFontFace (== the reclaimed spray buffer, SELF) ✓ gate
> +0x18  canonical heap ptr (m_loadedPromise candidate — promise chase object)
> +0x20  0
> +0x28  0x53103fa9488 (epoch/handle, shared with impl+0x20)
> +0x30  data (0x7606f64a4405f6be — packed/string-ish)
> +0x38+ string-ish tail bytes
> ```
>
> Identity certification (FACE-IDENTITY-OK, session 3B00VR): vtable===VP &&
> impl-backptr===L2 && m_backing===SELF — all three exact. The wrapper and the
> reclaimed CSSFontFace form a closed 2-object cycle (m_wrapper / m_backing),
> and the walk's client object IS the wrapper itself.
> The promise object at +0x18 (e.g. 0x1000871200) leads to a resolve-callback
> wrapper (e.g. 0x10007a84e0) holding module-range vtables and JSC-side
> pointers (0x7ef28b5b5/5b7/5b6) — the JSC-side addrof leads.

ActiveDOMObject interface. Called when WebKit treats the object through its primary base.

| Slot | RVA       | Likely Method                          | Side Effects                                      |
|------|-----------|----------------------------------------|---------------------------------------------------|
| 0    | 0x412C450 | ~FontFace() D1 (complete destructor)   | m_backing->removeClient(*this)                    |
| 1    | 0x5B3CE20 | ~FontFace() D0 (deleting destructor)   | same + deallocate                                 |
| 2    | 0x5B3CFC0 | FontFace::ref() final                  | ++m_refCount at this+offset                       |
| 3    | 0x5B3D7A0 | FontFace::deref() final                | --m_refCount; if 0 → destroy                      |
| 4    | 0x4001750 | no-op (ActiveDOMObject::suspend)       | returns void                                      |
| 5    | 0x4001750 | no-op (ActiveDOMObject::resume)        | returns void                                      |
| 6    | 0x4001750 | no-op (ActiveDOMObject::stop)          | returns void                                      |
| 7    | 0x5B3D7B0 | virtualHasPendingActivity() const      | reads m_mayLoadedPromiseBeScriptObservable + m_loadedPromise->isFulfilled() |
| 8    | 0x5B3D410 | activeDOMObjectName() const            | returns "FontFace" string literal                 |
| 9    | 0x503EC80 | unknown (unique RVA, different region) | TBD                                               |
| 10   | —         | not dumped (PV+0x50)                   | TBD                                               |

## Secondary Vtable (VP_RVA = 0x724DB28, 8 valid + 2 NULL)

CSSFontFaceClient interface. Called when CSSFontFace notifies its clients.

| Slot | RVA       | Likely Method                              | Side Effects                                              |
|------|-----------|--------------------------------------------|-----------------------------------------------------------|
| 0    | 0x5B3CFB0 | ~CSSFontFaceClient() D1 thunk             | adjust this+32, call ~FontFace D1                         |
| 1    | 0x5B3CFE0 | ~CSSFontFaceClient() D0 thunk             | adjust this+32, call ~FontFace D0                         |
| 2    | 0x4001750 | fontLoaded(CSSFontFace&) — default no-op  | nothing                                                   |
| 3    | 0x5B3D6B0 | fontStateChanged() thunk → FontFace       | m_loadedPromise->resolve(*this) on Success                |
| 4    | 0x4001750 | fontPropertyChanged() — default no-op     | nothing                                                   |
| 5    | 0x4001750 | updateStyleIfNeeded() — default no-op     | nothing                                                   |
| 6    | 0x5793400 | ref() thunk                                | adjust this-32, ++refCount                                |
| 7    | 0x5B3D810 | deref() thunk                              | adjust this-32, --refCount; if 0 → destroy                |

## FontFace Object Layout (measured + source-derived)

```
FontFace base (+0x00 from FontFace*)
  +0x00  primary vtable ptr (PV)
  +0x08  RefCounted m_refCount (uint32) + padding
  +0x10  ContextDestructionObserver m_scriptExecutionContext (ptr)
  +0x18  ActiveDOMObject state / padding
  +0x20  secondary vtable ptr (VP) — CSSFontFaceClient subobject
  +0x28  AbstractRefCountedAndCanMakeWeakPtr state (weak ptr factory)
  +0x30  m_backing : Ref<CSSFontFace> (8B ptr)
  +0x38  m_loadedPromise : UniqueRef<LoadedPromise> (8B ptr)
  +0x40  m_mayLoadedPromiseBeScriptObservable : bool (1B)
  +0x41  m_sourceIsImmediateBuffer : bool (1B)
  +0x42  padding to alignment
  sizeof(FontFace) ≈ 0x48 (72 bytes), bmalloc size class TBD
```

NOTE: offsets after +0x20 are estimates. Need probe verification.

## CSSFontFace Layout (WebKit-1200, from LinearFox)

```
+0x00  vtable ptr (RefCountedAndCanMakeWeakPtr)
+0x08  m_refCount + flags
+0x10  m_propertiesOrCSSConnection (Variant, 16B)
+0x20  m_family (RefPtr<CSSValue>, 8B)
+0x28  m_ranges (Vector<UnicodeRange>)
+0x38  m_featureSettings (FontFeatureSettings)
+0x48  m_loadingBehavior (enum, 4B)
+0x4c  m_sizeAdjust (float, 4B)
+0x50  m_sources (Vector<unique_ptr<CSSFontFaceSource>>)
+0x60  m_clients (WeakHashSet<CSSFontFaceClient>)
+0x70  m_wrapper (WeakPtr<FontFace>)
+0x78  m_fontSelectionCapabilities
+0x8a  m_status (Status enum, 1B)
+0x98  m_timeoutTimer (Timer, embedded)
sizeof(CSSFontFace) ≈ 0xc8
```

## Key COOP Gadget: fontStateChanged (VS-3)

```cpp
void FontFace::fontStateChanged(CSSFontFace& face, Status, Status newState) {
    switch (newState) {
    case Status::Success:
        if (!m_loadedPromise->isFulfilled())
            m_loadedPromise->resolve(*this);  // WRITE: resolve stores *this
        return;
    case Status::Failure:
        if (!m_loadedPromise->isFulfilled())
            m_loadedPromise->reject(exception); // WRITE: reject stores exception
        return;
    }
}
```

If we control m_loadedPromise, the resolve/reject calls write through our pointer.
Requires understanding DOMPromiseProxyWithResolveCallback internals.

## Key COOP Gadget: ~FontFace() (PV-0)

```cpp
FontFace::~FontFace() {
    m_backing->removeClient(*this);
}
```

If we control m_backing, removeClient modifies WeakHashSet at m_backing->m_clients.
Two-level indirection: fake m_backing → fake m_clients → write target.

## LinearFox Approach (NOT COOP)

LinearFox does NOT use COOP. Their chain on PS4:

```
CSSFontFace UAF → ArrayBuffer reclaim → m_featureSettings relative read
→ JS array Butterfly indexing header corruption → oversized array
→ addrof/fakeobj (double/object array pair) → fake DataView → full ARW
```

Key points:
- m_featureSettings read BROKEN on PS5 14.10 (goes through m_propertiesOrCSSConnection)
- PS5 has vtable check at reclaim: `cmp [rdi], rax; jnz fail`
- They DO NOT demonstrate full PS5 exploitation (only "partially")
- Gigacage + IsoHeaps disabled on PS5 → Butterfly in same heap as C++ objects

## Our Position vs LinearFox

| Capability | LinearFox (PS4) | Us (PS5 14.10) |
|-----------|-----------------|-----------------|
| UAF trigger | CSSFontFace font-loading | Canvas2D getContext reentry |
| ASLR defeat | Not demonstrated | DONE (fault oracle) |
| Read primitive | 4-byte m_featureSettings | 16-byte syncRead16 (unlimited) |
| WebProcess base | Unknown | KNOWN (RVA calculations work) |
| Vtable knowledge | Not described | FULL (PV+VP, 19 slots mapped) |
| Write primitive | ArrayBuffer reclaim | ArrayBuffer reclaim (same) |
| Arbitrary write | Butterfly corruption → DataView | **NOT YET — one step left** |

## Path B Progress (device-verified, 2026-11-13)

> **DISPATCH CAMPAIGN STATUS (2026-11-13, 11:26):**
>
> The read-side is COMPLETE (leak → walk → BASE → identity → addrof, all certified
> and cached, ~10s/session). The WRITE-side is blocked at the dispatch trigger:
>
> - The **INSERT** works: `document.fonts.add(faces[zi])` → `m_clients.add()` —
>   the engine reads AND writes our forged table (keyCount 1→2, the SET's impl
>   at a bucket — witnessed twice). The add path skips the cleanup.
> - The **DISPATCH** (`faces[zi].load()` → `pump()` → `setStatus()` →
>   `iterateClients()`) hangs BEFORE any vtable call (crash-bisection proven).
>   The hang is in the WeakHashSet's `computeSize()` → `removeIf()` — the
>   unconditional pre-dispatch cleanup on our forged m_clients.
> - ~12 hypotheses eliminated on-device (table format, timer, promise, sources,
>   status byte, vtable slots, hash-table object header — full ledger in
>   GLM_Findings.md E18).
> - **CRITICAL: the PS5's fork is OLDER than the 616 branch** (proven: rc@+0x00
>   on CSSFontFace = no vtable = pre-616 era). The 616-era WeakHashSet/
>   Algorithms/HashTable source may not match the fork. Fetch the Safari-13-era
>   (605.1.x) sources before further dispatch design.
>
> **VERIFIED ON-DEVICE OFFSETS (from the real face, v17h):**
> ```
> CSSFontFace status byte: +0x82 (= 3 for Success, 0 = Pending)
> CSSFontFace m_fontLoadTimingOverride: +0x87 (0 = None, 1 = Block)
> CSSFontFace bool flags: +0x83..0x86 (isLocalFallback, sourcesPopulated, mayBePurged, shouldIgnore)
> CSSFontFace hash-table object header: +0x58(ptr) +0x60..0x67 (mutable counters, read {3,2} on a live face)
> CSSFontFace timer region: +0x88..0xBF
> WeakHashSet fresh-table metadata: {deletedCount@T-0x10, keyCount@T-0x0C, mask@T-0x08, tableSize@T-0x04}
>   — real table observed: {2, 1, 7, 8} with 0xFFFF... deleted markers
> JSDataView cell: {butterfly=0@+0x08, m_vector@+0x10, m_length@+0x18, m_byteOffset@+0x20}
>   — all verified via 6 marker reads; vectorFieldAddr = cell+0x10 (THE WRITE TARGET)
> ```

> **ADDROF-CERTIFIED** (session TFR4OD, v688 v15): the JSDataView cell was
> found via a calibrated oracle scan and verified against all 6 planted
> markers. **The read-side of Path B is COMPLETE** — leak → walk → BASE →
> wrapper identity → addrof, all cached, ~10s per session.
>
> **Verified on-device cell layout** (the ?dv= estimates all held):
> ```
> JSDataView JSCell:
>   +0x08  butterfly    = 0
>   +0x10  m_vector     → ArrayBuffer backing + 0x20   ← THE COOP WRITE TARGET
>   +0x18  m_length     = 0x40
>   +0x20  m_byteOffset = 0x20
> ```
> The write target is beaconed per session as `vectorFieldAddr = cell+0x10`
> (e.g. 0x1000880150 in the certifying session). One write retargeting
> m_vector converts the DataView into full arbitrary R/W.
>
> Wrapper layout also device-measured (corrects the estimate below):
> `{vtable=VP@+0x00, impl-backptr=L2@+0x08, m_backing=SELF@+0x10,
> promise-cand@+0x18}` — three identity gates certified (FACE-IDENTITY-OK).
> Oracle semantics decoded: chk(c)=T iff A≤c≤B (inclusive; inverted=all-F).

## Paths to Arbitrary Write

### Path A: JSC Butterfly Corruption (LinearFox-inspired)
1. Spray JS arrays whose Butterfly size = freed object size class
2. Use syncRead16 to find Butterfly near reclaimed slot
3. Attempt heap shaping to get Butterfly header within write range
4. Corrupt vectorLength → oversized array → addrof/fakeobj → fake DataView → ARW
- **Pro:** Well-understood, no .text reading needed
- **Con:** Requires exact heap feng shui, bmalloc boundaries may prevent overlap

### Path B: addrof-via-READ + single write escalation
1. Use syncRead16 to READ JSC object internals (JSCell → Butterfly → element pointers)
2. Build addrof from READ alone (no write needed for reading object addresses)
3. Find DataView/ArrayBuffer JSCell in memory, read its buffer pointer
4. Need ONE write to DataView's buffer pointer to retarget it → full ARW
5. Use COOP (fontStateChanged or destructor) for that one write
- **Pro:** Leverages our strong read primitive, minimal COOP needed
- **Con:** Still need one controlled write via COOP chain

### Path C: Pure COOP write chain
1. Forge fake FontFace in reclaimed slot with controlled m_backing + m_loadedPromise
2. Trigger fontStateChanged → m_loadedPromise->resolve(*this) writes through fake promise
3. The write lands at a controlled address (DataView buffer pointer)
4. Full ARW from there
- **Pro:** Direct use of vtable knowledge
- **Con:** Need DOMPromiseProxy internals, deep chain

### Path D: Re-trigger UAF for Butterfly overlap
1. Use first UAF for read primitive (keep it running)
2. Trigger SECOND UAF → don't reclaim, let Butterfly fill the slot
3. The Butterfly's indexing header is now exposed through the stale pointer
4. BUT: can't write to stale pointer directly...
- **Pro:** Gets Butterfly and stale pointer to overlap
- **Con:** Can't write to the overlap region without another primitive

## Recommended Next Step: Path B (addrof-via-READ)

Build p811 to:
1. Verify FontFace object layout (exact offsets of m_backing, m_loadedPromise)
2. Build addrof using ONLY syncRead16:
   - Create JS objects, find their JSArray JSCells in heap
   - Read Butterfly pointers, read element values
   - Decode NaN-boxed pointers
3. With addrof, find the target DataView's buffer pointer location
4. Then design the COOP write gadget to corrupt that single pointer
