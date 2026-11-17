#!/usr/bin/env node
'use strict';
/* xtab-match.js — the offline half of the xtab deterministic NID match.
 *
 * In-page half (shell.html case 'xtab'): exfiltrates the libkernel export
 * table at lk+0x48000 COMPLETE (all nE entries, full {A,S} qwords) plus the
 * name-record pool (contiguous raw hex, [poolBase, poolBase+pool)) via
 * sync POST beacons (tagged XT-) into tools/ws-shell/shell-beacons.log.
 *
 * This half: parse the XT- lines -> entries[] {A, text} + pool bytes ->
 * scan EVERY byte offset of the pool for any of ps5rs's 195K raw NID64s
 * (data/nids.csv column 2, the pre-base64 SHA1 value: e.g. thr_create =
 * 0x4E276BD12611981E) in BE, LE, and ASCII-hex/ASCII-b64 encodings ->
 * validate against the two PROVEN anchors (entry#5.text=0x2C0=thr_self,
 * entry#8.text=0x410=thr_new) -> then THE ANSWER: thr_create's NID ->
 * its record -> its A -> its entry -> text RVA.
 *
 * Usage: node xtab-match.js [beacons.log] [nids.csv]
 */
const fs = require('fs');
const path = require('path');

const LOG = process.argv[2] || path.join(__dirname, 'ws-shell', 'shell-beacons.log');
const CSV = process.argv[2] && process.argv[3] ? process.argv[3]
  : path.join(require('os').tmpdir(), 'opencode', 'ps5rs', 'data', 'nids.csv');

/* ---------- parse the beacon log ---------- */
const logTxt = fs.readFileSync(LOG, 'utf8');
const entries = {};      /* idx -> {a, text} */
const poolHex = {};       /* offHex -> hex string */
let sawHdr = null, sawN = null, sawE = 0, sawP = 0;
for (const line of logTxt.split(/\r?\n/)) {
  const m = line.match(/XT-([EPe]\S*)\s+(.*)$/);
  if (!m) {
    const h = line.match(/XT-([1-7])\s(.*)$/);
    if (h) { if (h[1] === '3') sawN = h[2]; if (h[1] === '2') sawHdr = h[2]; }
    continue;
  }
  const tag = m[1], rest = m[2];
  if (tag[0] === 'E') {
    for (const part of rest.split(',')) {
      const pm = part.match(/^(\d+):([0-9a-f]+):([0-9a-f]+)$/);
      if (pm) entries[parseInt(pm[1], 10)] = { a: parseInt(pm[2], 16), text: parseInt(pm[3], 16) };
    }
    sawE++;
  } else if (tag[0] === 'P') {
    poolHex[tag.substring(1)] = rest.trim();
    sawP++;
  }
}
const nEntries = Object.keys(entries).length;
console.log(`[log] E-lines=${sawE} P-lines=${sawP} entries parsed=${nEntries} hdr=${sawHdr || '-'} n=${sawN || '-'}`);
if (!nEntries) { console.error('NO ENTRIES PARSED - check the XT- beacon format'); process.exit(1); }

/* ---------- assemble the pool ---------- */
let pool = Buffer.alloc(0);
const offs = Object.keys(poolHex).map(x => parseInt(x, 16)).sort((a, b) => a - b);
if (offs.length) {
  const end = offs.reduce((mx, o) => Math.max(mx, o + poolHex[o.toString(16)].length / 2), 0);
  pool = Buffer.alloc(end);
  let holes = 0;
  for (const o of offs) {
    const hx = poolHex[o.toString(16)];
    const b = Buffer.from(hx, 'hex');
    if (b.length !== hx.length / 2) { console.error(`bad hex at P${o.toString(16)}`); process.exit(1); }
    /* overlap / hole detection */
    for (let i = 0; i < b.length; i++) if (pool[o + i] !== 0 && b[i] !== pool[o + i]) holes++;
    b.copy(pool, o);
  }
  console.log(`[pool] assembled ${pool.length} bytes from ${offs.length} chunks (first=0x${offs[0].toString(16)} last=0x${offs[offs.length - 1].toString(16)})`);
} else {
  console.log('[pool] NO P-LINES - pool scan skipped (entries-only pass)');
}

/* ---------- load the NID catalog ---------- */
const csv = fs.readFileSync(CSV, 'utf8');
const byRawBE = new Map();   /* raw64 BE hex(no 0x, lowercase) -> {nid, name, lib} */
let nNid = 0;
for (const line of csv.split(/\r?\n/)) {
  if (!line || line.startsWith('nid,')) continue;
  const c = line.split(',');
  if (c.length < 3) continue;
  const raw = (c[1] || '').replace(/^0x/i, '').toLowerCase();
  if (raw.length !== 16) continue;
  nNid++;
  if (!byRawBE.has(raw)) byRawBE.set(raw, { nid: c[0], name: c[2], lib: c[3] || '', raw });
}
console.log(`[nid] catalog: ${nNid} raw NID64s`);

/* ---------- scan the pool for NID hits (BE + LE u64 at every byte offset) ---------- */
const hits = [];
function hex8(off) { return pool.toString('hex', off, off + 8); }
for (let o = 0; o + 8 <= pool.length; o++) {
  const be = hex8(o);
  let r = byRawBE.get(be);
  if (r) hits.push({ off: o, enc: 'BE', raw: be, ...r });
  else {
    const le = hex8(o).match(/../g).reverse().join('');
    r = byRawBE.get(le);
    if (r) hits.push({ off: o, enc: 'LE', raw: le, ...r });
  }
}
/* ASCII encodings: the 11-char b64 NID string, and the 16-char hex raw */
const byNidStr = new Map(), byName = new Map();
for (const [raw, v] of byRawBE) { byNidStr.set(v.nid, { ...v, raw }); if (v.name) byName.set(v.name, v); }
const ascii = pool.toString('latin1');
for (const [nid, v] of byNidStr) {
  let i = -1;
  while ((i = ascii.indexOf(nid, i + 1)) !== -1) hits.push({ off: i, enc: 'ASCII-b64', raw: v.raw, nid, name: v.name, lib: v.lib });
  if (hits.length > 500) break;
}
console.log(`[scan] ${hits.length} NID hits in pool`);

/* ---------- anchor validation: entry#5=thr_self(0x2C0), #8=thr_new(0x410) ---------- */
const THR = { thr_self: '08e73651adbdfa92', thr_create: '4e276bd12611981e', thr_exit: '539543d4fd7cd620', thr_new: 'b750497ee6fc55d6', thr_kill: null };
for (const k of Object.keys(THR)) { if (THR[k]) { const v = byRawBE.get(THR[k]); if (v) THR[k] = v; } }
const a5 = entries[5], a8 = entries[8];
console.log(`[anchors] #5: text=0x${a5 ? a5.text.toString(16) : '?'} A=0x${a5 ? a5.a.toString(16) : '?'}  #8: text=0x${a8 ? a8.text.toString(16) : '?'} A=0x${a8 ? a8.a.toString(16) : '?'}`);

/* what would each A-semantics predict for the anchor records? */
if (a5 && a8 && pool.length) {
  for (const [label, rec] of [
    ['A = offset from pool base', o => o.a],
    ['A = offset - 16 (record header)', o => o.a + 16],
  ]) {
    const o5 = rec(a5), o8 = rec(a8);
    const in5 = o5 + 8 <= pool.length, in8 = o8 + 8 <= pool.length;
    console.log(`[A-semantics] ${label}: #5 rec@+0x${o5.toString(16)} ${in5 ? 'bytes=' + hex8(o5) : 'OUT OF POOL'}  #8 rec@+0x${o8.toString(16)} ${in8 ? 'bytes=' + hex8(o8) : 'OUT OF POOL'}`);
  }
}

/* ---------- the money shot: thr_create ---------- */
const tc = byRawBE.get(THR.thr_create) || (typeof THR.thr_create === 'string' ? null : THR.thr_create);
console.log(`[thr_create] NID64=${typeof THR.thr_create === 'object' ? '0x' + THR.thr_create.raw : THR.thr_create} name=${THR.thr_create.name}`);
const tcHits = hits.filter(h => h.raw === THR.thr_create.raw);
console.log(`[thr_create] pool hits: ${tcHits.length} ${tcHits.map(h => `off=+0x${h.off.toString(16)} enc=${h.enc}`).join(' ')}`);
/* map each hit back to the entry with the matching A (either A-semantics) */
for (const h of tcHits) {
  for (const [label, pred] of [['A=off', o => o === h.off], ['A=off-16', o => o === h.off - 16], ['A=off+16', o => o === h.off + 16]]) {
    const es = Object.entries(entries).filter(([k, v]) => pred(v.a));
    for (const [k, v] of es) console.log(`*** THR_CREATE CANDIDATE (${label}): entry #${k} text=0x${v.text.toString(16)} A=0x${v.a.toString(16)}`);
  }
}
/* also: dump the neighbors of any hit (record stride context) + entry list around any candidate */
if (tcHits.length && pool.length) {
  const h = tcHits[0];
  const lo = Math.max(0, h.off - 32), hi = Math.min(pool.length, h.off + 40);
  console.log(`[thr_create ctx] pool[+0x${lo.toString(16)}..+0x${hi.toString(16)}]:`);
  console.log(pool.toString('hex', lo, hi).replace(/(..)/g, '$1 ').trim());
}
console.log('[done]');