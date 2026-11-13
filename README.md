# PS5 14.10 WebKit Exploit Research

**Target:** PlayStation 5 firmware 14.10  
**Console:** Retail unit at 10.100.102.14  
**Mission:** Browser entry → WebProcess code exec → kernel R/W → hypervisor bypass

---

## Current Status

**Read Chain: ✅ COMPLETE & CERTIFIED**
- FontFace UAF leak → arbitrary read → module base → wrapper identity → addrof
- All cached and repeatable in ~10 seconds per session
- Write target known: `cell+0x10` (DataView m_vector field)

**Write Trigger: ⏸ BLOCKED**
- Dispatch hangs in WeakHashSet `computeSize()` → `removeIf()` before any vtable call
- ~12 hypotheses eliminated on-device (v17b→v17r)
- Fork is older than 616 branch (non-virtual CSSFontFace destructor)

---

## Repository Structure

```
ps5-1410-researching/
├── README.md                          # This file
├── HANDOFF.md                         # Mission status and resume point
├── CONTINUE-HERE.md                   # Session continuation guide
├── GLM_Findings.md                    # Chronological findings E1-E18
├── AGENTIC-FINDINGS.md                # Companion documentation
├── .gitignore                         # Excludes large files and build artifacts
│
├── tools/remote-loader/               # Probe infrastructure
│   ├── index.html                     # Dispatcher (what console loads)
│   ├── v17.html                       # Current probe (full chain + dispatch)
│   ├── v688.html                      # Certified read-chain probe
│   ├── host.py                        # Beacon sink (DNS spoof + HTTP server)
│   ├── auto_continue.py               # Crash dialog auto-dismiss
│   ├── scan-watch.ps1                 # Colored live watcher
│   └── logs/                          # Beacon logs (gitignored, samples only)
│
├── PS5-14.10-Research/                # Source analysis and documentation
│   └── docs/
│       └── COOP_ANALYSIS.md           # Source-derived COOP analysis
│
└── webkit-sources/                    # WebKit source archives (download separately)
    └── README.md                      # Download instructions
```

---

## Quick Start

### 1. Download WebKit Sources

The actual WebKit source code is too large for GitHub. Download from Sony:

```powershell
cd webkit-sources
.\download-sources.ps1
```

Or manually:
- WebKit_1400.zip (for 14.10): https://www.playstation.com/content/dam/global_pdc/en-us/external-resources/oss/PS5/webkit/WebKit_1400.zip
- WebKit-1200.zip (for comparison): https://www.playstation.com/content/dam/global_pdc/en-us/external-resources/oss/PS5/webkit/WebKit-1200.zip

### 2. Set Up Probe Infrastructure

```powershell
cd tools/remote-loader

# Start the beacon sink (requires elevated PowerShell)
$env:PYTHONIOENCODING="utf-8"
python host.py *> host-console.log
```

### 3. Configure PS5

1. Settings → Network → DNS: Manual → Primary = PC's LAN IP
2. Settings → User's Guide (loads the probe)
3. Restore DNS to Automatic afterward

### 4. Monitor Beacons

```powershell
# In another terminal
.\scan-watch.ps1
```

---

## Key Device-Verified Facts

```
VP_RVA = 0x724DB28                    (ASCII-verified)
BASE = VP − 0x724DB28                 (computable per session)
fontStateChanged = BASE + 0x5B3D6B0   (= VP − 0x1710478)
noop = BASE + 0x4001750
destructor = BASE + 0x5B3CFB0

CSSFontFace layout (192B reclaimed object):
  +0x58 = m_clients table pointer
  +0x60..0x67 = hash-table object header (counters {3,2})
  +0x82 = status byte (0=Pending, 3=Success)
  +0x87 = FontLoadTimingOverride

JSDataView cell (addrof target):
  +0x10 = m_vector → ArrayBuffer+0x20  (THE COOP WRITE TARGET)
```

---

## Next Steps

See `HANDOFF.md` for the full mission status and ranked next moves.

**Immediate priority:** Establish source/build dossier from Sony's WebKit_1400.zip to understand the WeakHashSet hang.

---

## Research Timeline

- **2026-11-12:** Initial FontFace UAF discovery and read chain development
- **2026-11-13 08:47:** VP_RVA verified on-device (BASE solved)
- **2026-11-13 09:34:** Wrapper identity certified (FACE-IDENTITY-OK)
- **2026-11-13 09:59:** addrof certified (ADDROF-CERTIFIED)
- **2026-11-13 10:25:** First engine write into forged structure witnessed
- **2026-11-13 11:26:** Dispatch hang localized to WeakHashSet cleanup

---

## Console Protocol

- Close/reopen guide app to load each new probe version
- Reboot only after memory-warning storms (~1 crash/boot budget)
- Sessions that complete cleanly self-cycle via RT=16 (30s reload)
- Beacon log is ~160MB — use `Select-String -Pattern` to filter

---

## License

Research conducted on owner's retail console for security research purposes.
