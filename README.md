# PS5 14.10 WebProcess Exploitation Research

**Target:** PlayStation 5, firmware 14.10 (retail console, owner-operated)
**Mission:** Browser entry → WebProcess code execution → thread/syscall capability → kernel R/W
**Authorization:** Sony Interactive Entertainment security research / bug bounty program (HackerOne)

---

## Capability Status

**WebProcess exploitation: COMPLETE (E2).** The FontFace UAF chain yields full arbitrary read/write in the WebProcess, plus a native call primitive (PC + RDI control, decode-immune returns) — the strongest userland position demonstrated on 14.10. Everything below is device-proven and repeatable per session in ~10 seconds.

**Spawn (SROP): CLOSED at the mechanism level — with the full fault isolation banked.** Twelve install iterations mapped the kernel's sigreturn gates, the FP restore area, the PS5 TLS/TCB layout, and the exact register-restore semantics. The route closes on a structural fact: the native-call trampoline keeps live data in callee-saved registers that are unobtainable from the JS context. The register-capture architecture that resolves this is the game lane (below).

**Module intelligence: COMPLETE.** The WebProcess import GOT fully dumped (12 module bands, 83 libkernel imports, all verified function entries); libkernel's internal data map fully read (FDE table, relocations, strings, TCB model); the NID values for the context-syscall family decoded.

---

## Key Results (all device-measured)

```
VP (Client vtable ptr)  = WebProcess_base + 0x724DB28      (independently derived, 7-check reconciliation)
libkernel base          = pthread-backlink chain            (0x10001c8000 registry → q−0x6C218, canary gate)
thr_create (430)        = lk+0x13D20    sigreturn (417) = lk+0x13ED0    thr_exit (431) = lk+0x13EC0
thr_new   (455)        = lk+0x410      thr_self   (2)  = lk+0x2C0      gettimeofday   = lk+0xB50
arg4 trampoline (r10)  = lk+0x3B7      retSlot           = cfr−0x328     (four boots)
PS5 TCB self-pointer   = [TCB+0x38]                       (not FreeBSD's +0)
sigreturn frame: gates at +0xD0/+0xE8/+0xF0/+0x110/+0x118, GPRs +0x48..+0xB8 (18 qwords),
                FP area +0x140 (0x140 bytes), FS/GS base +0x480/+0x488 — kernel body fully disassembled
Section map: headers 0x0-0x4000 (RO) | .text 0x4000-0x6AD7000 (XO, reads fault) | .rodata 0x6AD7000+ (RO)
```

Full technical detail in **`TECHNICAL_REPORT.md`** — a dense, model-feedable summary of every finding.

---

## Next Architecture: The Game Lane

The remaining objectives (true register capture, `thr_new` spawn, NID-walk attribution verification) run in the Lua loader lane (Hamidashi Creative demo, TCP 9026), where `fcall_with_rax` provides RAX-controlled syscalls without the WebProcess scope-swap constraints — the spawn ABI is already publicly proven there (383a/384b). Prerequisites: the demo installed, the payload save staged, PSN sign-in (the DNS spoofer blocks update hosts while passing auth servers, so sign-in cannot force an update).

---

## Repository Structure

```
├── README.md                            # This file
├── TECHNICAL_REPORT.md                  # Dense model-feedable report of all findings
├── HANDOFF.md / CONTINUE-HERE.md        # Legacy mission guides (early campaign)
├── GLM_Findings.md / AGENTIC-FINDINGS.md # Early campaign records
│
└── PS5-14.10-Jailbreak-Research/        # The active campaign
    ├── CONTINUATION.md                  # Current-state handoff (resume here)
    ├── CLAUDE_FINDINGS.md               # Chronological evidence ledger (authorization header)
    ├── tools/
    │   ├── ws-shell/                    # Interactive WebProcess shell (server + shell.html + CLI)
    │   ├── remote-loader/               # DNS-spoof host + dispatcher
    │   ├── vpmap2-*.jsonl               # Import GOT + module map captures
    │   ├── lk-*.jsonl                   # libkernel internal map captures
    │   └── lk-funcmap.json              # The 2092-entry FDE map
    └── src/utils/syscalls.js            # Syscall tables
```

The upstream community corpus (ZigZagBoi1/PS5-14.10-Research) is mirrored at `PS5-14.10-Research/` — the two campaigns' findings cross-reconcile (see `TECHNICAL_REPORT.md` §5).

---

## Quick Start

```powershell
# 1. Beacon sink (elevated PowerShell)
cd PS5-14.10-Jailbreak-Research/tools/remote-loader
$env:PYTHONIOENCODING="utf-8"; python host.py *> host-console.log

# 2. WS shell server (port 8443, cert in tools/ws-shell/.certs)
cd ../ws-shell; npm start

# 3. PS5: DNS → PC's LAN IP → User's Guide → accept cert → re-enter per session
# 4. Commands:
$env:SHELL_PORT=8443
node tools/ws-shell/shell-cmd.js info      # session state (base, cfr, pcControl)
node tools/ws-shell/shell-cmd.js vpmap     # module census sweep (pure reads)
```

---

## Research Timeline

- **2026-11-12/13:** FontFace UAF → read chain → certified walk → addrof (E1)
- **2026-11-14/15:** Full ARW + call primitive (E2); the wrapper corpus; the write/dispatch era
- **2026-11-16:** The SROP era — 36 install iterations, the kernel 417 body disassembled, the PS5 TCB discovered, the route closed on the trampoline-register mechanism
- **2026-11-17:** The module-map campaign — import GOT dumped, libkernel internals read, NIDs decoded, the libc-not-loaded finding; the full-repo community reconciliation

---

## License / Ethics

Research conducted on the owner's retail console under Sony's PlayStation security research program (HackerOne). No piracy, no distribution of exploit material, responsible disclosure through the bounty program.
