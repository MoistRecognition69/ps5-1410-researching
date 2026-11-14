// V41 Patch: OOB READ/WRITE VIA DATAVIEW LENGTH EXPANSION
//
// ATTACK VECTOR (source-confirmed):
//   canUseRawFieldsDirectly() returns true for non-resizable DataViews.
//   This means the DataView's bounds check uses m_length from the JSCell
//   directly — it does NOT check the ArrayBuffer's current sizeInBytes.
//   If we can expand m_length in the cell, we get OOB past the backing store.
//
// THE TRICK:
//   1. Create a victim ArrayBuffer of size S (small, e.g. 8 bytes)
//   2. Create a DataView with byteOffset=S, length=0 (zero-byte view at end)
//      Cell: m_length=0, m_byteOffset=S, m_vector=backing_start
//   3. Find the victim DataView's JSCell address (via readAt scan)
//   4. COOP write aimed at (cell + 0x10):
//      - cell+0x18 (m_length):     low 4 bytes become 0x0000000F → length=15
//      - cell+0x20 (m_byteOffset): 8-byte ZERO → byteOffset=0
//      - cell+0x28 (m_mode):       low byte = 0x00 (was 0x88)
//      - cell+0x30 (m_buffer):     low byte = 0x01 (pointer corrupted)
//
// RESULT:
//   DataView now has m_length=15, m_byteOffset=0 in an 8-byte buffer.
//   Reads at offsets 8..14 are OOB — they read heap memory past the buffer!
//
// COLLATERAL DAMAGE:
//   - m_mode = 0x00 from 0x88: low byte zeroed. New mode = 0x80.
//     canUseRawFieldsDirectly: (0x80 & 0x07) = 0 <= 2 → still TRUE. Safe!
//     (Only the isWastefulTypedArrayMode bit changes, which doesn't affect bounds.)
//   - m_buffer low byte = 0x01 (was 0x20): pointer off by 0x1F.
//     The corrupted m_buffer is only used by possiblySharedBuffer() for
//     resizable checks (which we don't trigger) and for GC tracking.
//     As long as we don't trigger a GC that walks m_buffer, this is safe.
//     We KEEP STRONG REFERENCES to prevent GC collection.
//
// SAFETY:
//   m_mode corruption: 0x88 → 0x80 (bit 3 cleared).
//     0x88 = WastefulTypedArray (0b0101_1000) with high bit... wait:
//     0x88 = 0b1000_1000. This is: isTypedArrayMode(0x10)=no, isWastefulTypedArrayMode(0x40)=no.
//     Hmm, 0x88 doesn't match any named enum. Let me check: from V40 m_mode = 0x88.
//     The mode byte at cell+0x28 (q5=@40=0x88) — this is the m_mode field.
//     After zeroing low byte: 0x88 & 0xFF00... wait, the COOP write zeros
//     only byte +0x18 of the promise. At cell+0x28, that's 1 byte = 0x00.
//     m_mode is uint8 at cell+0x28. Writing 0x00 to cell+0x28 → m_mode=0.
//
//     TypedArrayMode 0 = no flags set. canUseRawFieldsDirectly: (0&7)=0<=2 → TRUE.
//     hasArrayBuffer: (0 & 0x10) → false? That could be a problem...
//     Actually: isTypedArrayMode = 0b0001_0000. mode=0 & that = 0 → not typed array mode.
//     But the DataView IS a typed array view. Having mode=0 might cause issues.
//
//   REVISED: The 0x00 write at +0x18 of the promise hits cell+0x28.
//     But wait — let me recheck. COOP write mask from V39:
//       +0x08: 4B write (0xF)
//       +0x10: 8B write (zero)
//       +0x18: 1B write (0x00)
//       +0x20: 1B write (0x01)
//     At cell+0x28 = promise+0x18: writes byte 0x00.
//     m_mode was 0x88. After write: 0x00.
//
//   This MIGHT be a problem. Let me check: m_mode=0 means "not wasteful, not fast".
//   For DataView operations (getUint8 etc.), the mode is checked via:
//     - canUseRawFieldsDirectly: (0&7)=0<=2 → TRUE (good)
//     - hasArrayBuffer: mode & isTypedArrayMode(0x10) → 0 → FALSE
//       This means possiblySharedBuffer() is not called for bounds.
//       For a non-resizable view, this is fine since we use raw fields.
//
//   The ACTUAL access path for dv.getUint8(i):
//     1. viewByteLength(getter) → canUseRawFieldsDirectly=true → return byteLengthRaw() = m_length
//     2. Check i + 1 <= viewByteLength → uses m_length only
//     3. Access: m_vector.get(m_length) + m_byteOffset + i
//        With m_byteOffset=0: just m_vector.get(m_length) + i
//        m_vector.get() does Gigacage caging: clips pointer to Gigacage range.
//        OOB accesses are WITHIN the Gigacage (same heap page), so caging allows them.
//
// CONCLUSION: This should give us 7 bytes of OOB read/write past the 8-byte buffer.
// That reads adjacent heap memory within Gigacage. We can then:
//   - Identify what's next in the heap (another ArrayBuffer's data?)
//   - Use that intel to plan a more powerful overlap attack.
//
// PHASE A: Recon — read SharedTask destructor + additional intel
// PHASE B: OOB — create victim, find cell, COOP write, attempt OOB reads
