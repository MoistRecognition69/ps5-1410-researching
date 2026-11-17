// v2: direct approach.
// 1) lkbase = q(0x1179A8) - 0xB50 (gettimeofday anchor, slot address known)
// 2) extract the full slot table 0x1178A0..0x118000 -> RVAs -> histogram vs harvest
// 3) hunt NID strings: scan ALL qwords in the window pointing anywhere into 0x0..0x114000,
//    read target strings, match the 50 banked NIDs
const fs = require('fs');
const CORPUS = 'D:\\ps5\\PS5-14.10-Research\\docs\\ALL_RESULTS.md';
const NIDFILE = 'D:\\ps5\\PS5-14.10-Jailbreak-Research\\tools\\nid-strings.json';
const lines = fs.readFileSync(CORPUS, 'utf8').split('\n');
const out = []; const say = s => out.push(s);

function sectionRange(name) {
  const start = lines.findIndex(l => l.includes('## FILE:') && l.includes(name));
  if (start < 0) return null;
  for (let i = start + 1; i < lines.length; i++) if (lines[i].startsWith('## FILE:')) return [start, i];
  return [start, lines.length];
}
const dump = new Map();
function parseSection(name) {
  const r = sectionRange(name); if (!r) return 0;
  let n = 0;
  const re = /\[[TID]\] off=0x([0-9A-Fa-f]+) len=0x([0-9A-Fa-f]+) ([0-9A-Fa-f]+)/;
  for (let i = r[0]; i < r[1]; i++) {
    const m = lines[i].match(re); if (!m || !m[3]) continue;
    const buf = Buffer.from(m[3], 'hex');
    if (buf.length < 0x1000) say('ELIDED page off=0x' + parseInt(m[1], 16).toString(16) + ' len=' + buf.length);
    dump.set(parseInt(m[1], 16), buf); n++;
  }
  return n;
}
say('pages: A=' + parseSection('1215a_libc_dump') + ' B=' + parseSection('1215b_libc_import_window'));

function rd(off, len) {
  const b = dump.get(off & ~0xfff); if (!b) return null;
  const p = off & 0xfff; if (p + len > b.length) return null;
  return b.slice(p, p + len);
}
const q = off => { const b = rd(off, 8); return b && b.length === 8 ? b.readBigUInt64LE(0) : null; };
function cstr(off, max) {
  const b = rd(off, max); if (!b) return null;
  let s = '';
  for (let i = 0; i < b.length; i++) { const c = b[i]; if (c === 0) break; if (c < 0x20 || c > 0x7e) return null; s += String.fromCharCode(c); }
  return s.length >= 6 ? s : null;
}

// ---- 1) lkbase from the gettimeofday anchor ----
const VGT = q(0x1179A8);
say('q(0x1179A8) = 0x' + (VGT === null ? 'NULL' : VGT.toString(16)));
if (VGT === null) { fs.writeFileSync(path.join(require('os').tmpdir(), 'opencode', 'nid-extract-result.txt'), out.join('\n')); console.log(out.join('\n')); process.exit(1); }
const LK = VGT - 0xB50n;
say('lkbase(1215-session) = 0x' + LK.toString(16));

// ---- 2) slot table walk ----
const SLOT_BASE = 0x1178A0;
const rvas = []; // {i, addr, val, rva}
for (let i = 0; ; i++) {
  const addr = SLOT_BASE + 8 * i;
  if (addr >= 0x118000) break;
  const v = q(addr); if (v === null) break;
  const d = v - LK;
  if (d > 0n && d < 0x400000n) rvas.push({ i, addr, val: v, rva: Number(d) });
}
say('lk-band slots visible: ' + rvas.length + ' of ' + ((0x118000 - SLOT_BASE) / 8));
// histogram by 0x1000 page
const hist = {};
for (const r of rvas) { const p = (r.rva & ~0xfff); hist[p] = (hist[p] || 0) + 1; }
const histStr = Object.keys(hist).map(p => '0x' + Number(p).toString(16) + ':' + hist[p]).join(' ');
say('RVA page histogram: ' + histStr);
// sorted RVA list (these are the stub/function RVAs in visible slots)
const sorted = rvas.map(r => r.rva).sort((a, b) => a - b);
say('low RVAs (<0x5000): ' + sorted.filter(x => x < 0x5000).map(x => '0x' + x.toString(16)).join(' '));
// full index -> RVA table
for (const r of rvas) say('SLOT i=' + r.i + ' addr=0x' + r.addr.toString(16) + ' RVA=0x' + r.rva.toString(16));

// ---- raw values of ALL slots 0..235 (incl. non-lk) for structure analysis ----
for (let i = 0; i < 236; i++) {
  const addr = SLOT_BASE + 8 * i;
  const v = q(addr);
  if (v === null) { say('RAW i=' + i + ' addr=0x' + addr.toString(16) + ' val=UNREADABLE'); continue; }
  const d = v - LK;
  const tag = (d > 0n && d < 0x400000n) ? 'LK' : (v === 0n ? 'NULL' : 'OTHER');
  if (tag !== 'LK') say('RAW i=' + i + ' addr=0x' + addr.toString(16) + ' val=0x' + v.toString(16) + ' ' + tag);
}

// ---- 3) NID string hunt across the whole window ----
const nidmap = JSON.parse(fs.readFileSync(NIDFILE, 'utf8'));
const want = {}; for (const [k, v] of Object.entries(nidmap)) want[v.split('#')[0]] = k;
const hits = []; // {holderOff, val, strOff, str, name}
for (let off = 0x114000; off < 0x118000; off += 8) {
  const v = q(off); if (v === null) continue;
  const d = Number(v - 0x1F3170000n);
  if (d < 0 || d >= 0x114000) continue;
  const s = cstr(d, 20);
  if (s && want[s]) hits.push({ holderOff: off, strOff: d, str: s, name: want[s] });
}
say('NID string hits: ' + hits.length);
for (const h of hits) say('  holder=0x' + h.holderOff.toString(16) + ' strOff=0x' + h.strOff.toString(16) + ' ' + h.str + ' -> ' + h.name);

fs.writeFileSync(path.join(require('os').tmpdir(), 'opencode', 'nid-extract-result.txt'), out.join('\n'));
console.log(out.join('\n'));
