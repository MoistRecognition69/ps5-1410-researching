// V40 Patch: ARRAYBUFFER LAYOUT RECON
//
// Injected into the ADDROF-CERTIFIED block (after DV certification).
// Reads the C++ ArrayBuffer object that backs the certified DataView,
// dumps every field, and validates the layout against source analysis.
//
// ArrayBuffer C++ object layout (from WebKit 1400 source):
//
//   DeferrableRefCountedBase:
//     +0x00: m_refCount        (uint32 — actual refs = m_refCount / 2)
//     +0x04: [padding]
//   GCIncomingRefCounted<ArrayBuffer>:
//     +0x08: m_encodedPointer   (uintptr_t — GC incoming reference tracking)
//   ArrayBufferContents (inline):
//     +0x10: m_data             (CagedPtr<Primitive> — raw pointer to backing store)
//     +0x18: m_destructor       (RefPtr<SharedTask<void(void*)>>)
//     +0x20: m_shared           (RefPtr<SharedArrayBufferContents>)
//     +0x28: m_memoryHandle     (RefPtr<BufferMemoryHandle>)
//     +0x30: m_sizeInBytes      (size_t)
//     +0x38: m_maxByteLength    (size_t)
//     +0x40: m_hasMaxByteLength (bool)
//   Post-contents:
//     +0x48: m_detachingWatchpointSet (InlineWatchpointSet = uintptr_t m_data)
//     +0x50: m_wrapper           (Weak<JSArrayBuffer> = WeakImpl*)
//     +0x58: m_pinCount          (Checked<unsigned>)
//     +0x5C: m_isWasmMemory      (bool)
//     +0x5D: m_locked            (bool)
//   Total: ~0x60 bytes
//
// Access: cell+0x30 = JSDataView.m_buffer = ArrayBuffer*
// dvH already read 64 bytes from cell, so qAt(dvH, 0x30) gives us AB_ADDR.
//
// The code is inserted inside the ADDROF-CERTIFIED success block in v40.html,
// right before the return statement. Variables available: cell, V, dvH, readAt, qAt.
