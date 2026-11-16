// Gadget search v3: the [rsi]-dispatcher in LIBC (the transferable module).
// RSI = cfr (the live frame) - the stack at [cfr+X] is ARW-WRITABLE.
// Target: mov rax,[rsi+X] ... call/jmp [rsi+Y]  (window +-0x40)
//   => RAX = [cfr+X] = 430 (ARW-written), target = [cfr+Y] = lk+0x3F7 (ARW-written),
//      RDI = the fake scope = the armed ucontext (UNTOUCHED) => thr_create fires.
// Also: push [rsi+X]; ret forms, and [rsi] plain (X=0).
const fs = require('fs');
const CORPUS = 'D:\\ps5\\PS5-14.10-Research\\docs\\ALL_RESULTS.md';
const lines = fs.readFileSync(CORPUS, 'utf8').split('\n');
function sectionRange(name) {
  const start = lines.findIndex(l => l.includes('## FILE:') && l.includes(name));
  if (start < 0) return null;
  for (let i = start + 1; i < lines.length; i++) if (lines[i].startsWith('## FILE:')) return [start, i];
  return [start, lines.length];
}
const r = sectionRange('1215a_libc_dump');
const re = /\[T\] off=0x([0-9A-Fa-f]+) len=0x[0-9A-Fa-f]+ ([0-9A-Fa-f]+)/g;
const text = lines.slice(r[0], r[1]).join('\n');
// build full contiguous buffer 0x0-0x114000
const pages = new Map();
let m;
while ((m = re.exec(text)) !== null) pages.set(parseInt(m[1], 16), Buffer.from(m[2], 'hex'));
const TOTAL = 0x114000;
const buf = Buffer.alloc(TOTAL);
let covered = 0;
for (const [off, b] of pages) { b.copy(buf, off); covered += b.length; }
console.log('libc buffer: covered=' + covered + ' of ' + TOTAL);

// collect: raxLoadsFromRsi = mov rax,[rsi+X]  (48 8B 46 X / 48 8B 86 XXXXXXXX / 48 8B 06)
//          rsiCalls = call/jmp [rsi+Y]        (FF 56 Y / FF 96 YYYYYYYY / FF D6=call rsi? no / FF 16=call [rsi] / FF 26 = jmp [rsi])
//          pushRsi = push [rsi+Y] (FF 76 Y / FF B6 ...) followed by C3 (ret) within 4 bytes
const raxLoads = [], rsiCalls = [], pushRets = [];
for (let i = 0; i < buf.length - 8; i++) {
  if (buf[i] === 0x48 && buf[i+1] === 0x8B && buf[i+2] === 0x46) raxLoads.push({ pos: i, x: buf[i+3], len: 4 });
  else if (buf[i] === 0x48 && buf[i+1] === 0x8B && buf[i+2] === 0x86) raxLoads.push({ pos: i, x: buf.readUInt32LE(i + 3), len: 7 });
  else if (buf[i] === 0x48 && buf[i+1] === 0x8B && buf[i+2] === 0x06) raxLoads.push({ pos: i, x: 0, len: 3 });
  if (buf[i] === 0xFF && (buf[i+1] === 0x56 || buf[i+1] === 0x96)) rsiCalls.push({ pos: i, kind: 'call', y: buf[i+1] === 0x56 ? buf[i+2] : buf.readUInt32LE(i + 2), len: buf[i+1] === 0x56 ? 3 : 6 });
  else if (buf[i] === 0xFF && (buf[i+1] === 0xB6)) rsiCalls.push({ pos: i, kind: 'jmp', y: buf.readUInt32LE(i + 2), len: 6 });
  else if (buf[i] === 0xFF && buf[i+1] === 0x16) rsiCalls.push({ pos: i, kind: 'call', y: 0, len: 2 });
  else if (buf[i] === 0xFF && buf[i+1] === 0x26) rsiCalls.push({ pos: i, kind: 'jmp', y: 0, len: 2 });
}
console.log('mov rax,[rsi+X] count: ' + raxLoads.length);
console.log('call/jmp [rsi+Y] count: ' + rsiCalls.length);

// ---- ROP entry gadget scan over the SAME buffer ----
const C3COUNT = (() => { let n = 0; for (let i = 0; i < buf.length; i++) if (buf[i] === 0xC3) n++; return n; })();
console.log('\nsanity: C3 byte count in buffer = ' + C3COUNT);
const pats = {
  'pop rax; ret': [0x58, 0xC3], 'pop rdi; ret': [0x5F, 0xC3], 'pop rsi; ret': [0x5E, 0xC3],
  'pop rdx; ret': [0x5A, 0xC3], 'pop rcx; ret': [0x59, 0xC3], 'pop r8; ret': [0x41, 0x58, 0xC3],
  'syscall; ret': [0x0F, 0x05, 0xC3],
};
const ropOut = {};
for (const [name, pat] of Object.entries(pats)) {
  const hits = [];
  for (let i = 0; i <= buf.length - pat.length; i++) {
    let ok = true;
    for (let j = 0; j < pat.length; j++) if (buf[i + j] !== pat[j]) { ok = false; break; }
    if (ok) hits.push(i);
  }
  ropOut[name] = hits;
  console.log(name + ': ' + hits.length + (hits.length ? '  first: ' + hits.slice(0, 6).map(h => '0x' + h.toString(16)).join(' ') : ''));
}
fs.writeFileSync(path.join(require('os').tmpdir(),'libc-rop-gadgets.json'), JSON.stringify(ropOut));

// pair: load then transfer within 0x40
const hits = [];
for (const L of raxLoads) {
  for (const C of rsiCalls) {
    const gap = C.pos - (L.pos + L.len);
    if (gap >= 0 && gap <= 0x40) {
      hits.push({ at: L.pos, x: L.x, y: C.y, kind: C.kind, gap,
        bytes: buf.slice(L.pos, Math.min(L.pos + L.len + gap + C.len + 2, L.pos + 64)).toString('hex') });
    }
  }
}
console.log('\n[rsi]-DISPATCHER HITS in libc: ' + hits.length);
hits.sort((a, b) => a.gap - b.gap);
for (const h of hits.slice(0, 30)) {
  console.log('libc+0x' + h.at.toString(16) + '  mov rax,[rsi+0x' + h.x.toString(16) + '] +' + h.gap + 'b ' + h.kind + ' [rsi+0x' + h.y.toString(16) + ']  ' + h.bytes);
}
fs.writeFileSync(path.join(require('os').tmpdir(),'rsi-dispatcher-hits.json'), JSON.stringify(hits, null, 1));
