#!/usr/bin/env node
'use strict';
/* xtab-study.js — offline study of the banked xtab exfil.
 * Q1: what's AT the anchor records (A=0xec18 thr_self, A=0xf49c thr_new)?
 * Q2: are the NAME strings ("thr_self" etc.) in the dumped pool?
 * Q3: A-vs-text correlation (is A ordered/derived from text?)
 * Q4: the session-55 "repeating pattern" — where is 0xd430286100e4100?
 * Q5: 32-bit NID truncations anywhere? (hi32/lo32 of the thr NIDs)
 */
const fs = require('fs');
const path = require('path');
const LOG = path.join(__dirname, 'ws-shell', 'shell-beacons.log');
const CSV = path.join(require('os').tmpdir(),'ps5rs','data','nids.csv');

const logTxt = fs.readFileSync(LOG, 'utf8');
const entries = {}, poolHex = {};
for (const line of logTxt.split(/\r?\n/)) {
  const m = line.match(/XT-([EPe]\S*)\s+(.*)$/);
  if (!m) continue;
  if (m[1][0] === 'E') {
    for (const part of m[2].split(',')) {
      const pm = part.match(/^(\d+):([0-9a-f]+):([0-9a-f]+)$/);
      if (pm) entries[parseInt(pm[1], 10)] = { a: parseInt(pm[2], 16), text: parseInt(pm[3], 16) };
    }
  } else if (m[1][0] === 'P') poolHex[m[1].substring(1)] = m[2].trim();
}
const offs = Object.keys(poolHex).map(x => parseInt(x, 16)).sort((a, b) => a - b);
const end = offs.reduce((mx, o) => Math.max(mx, o + poolHex[o.toString(16)].length / 2), 0);
const pool = Buffer.alloc(end);
for (const o of offs) Buffer.from(poolHex[o.toString(16)], 'hex').copy(pool, o);
console.log(`[pool] ${pool.length} bytes`);

/* Q1: hexdump at the anchor records + the 0xB50 entry's record */
const byText = {}; for (const [k, v] of Object.entries(entries)) byText[v.text] = { idx: +k, a: v.a };
const KNOWN = { 0x2C0: 'thr_self(E2)', 0x410: 'thr_new(455,size-gate)', 0x3F0: 'thr_exit', 0x3B0: 'unknown3B0', 0xB50: 'gettimeofday(NAMED)' };
for (const [t, label] of Object.entries(KNOWN)) {
  const e = byText[t]; if (!e) { console.log(`text 0x${(+t).toString(16)} (${label}): NO ENTRY`); continue; }
  const a = e.a;
  console.log(`\n=== ${label} entry #${e.idx} text=0x${(+t).toString(16)} A=0x${a.toString(16)}`);
  if (a + 0x40 <= pool.length) {
    for (let r = 0; r < 0x40; r += 16) {
      const s = pool.slice(a + r, a + r + 16);
      console.log(`  +0x${(a + r).toString(16)}: ${s.toString('hex').replace(/(..)/g, '$1 ').trim()}  |${s.toString('latin1').replace(/[^\x20-\x7e]/g, '.')}|`);
    }
  } else console.log('  A OUT OF dumped pool');
}

/* Q2: name/NID ASCII strings in the pool */
const NAMES = ['thr_self', 'thr_new', 'thr_exit', 'thr_create', 'thr_kill', 'gettimeofday', 'getpid', 'nanosleep', 'clock_gettime', 'mmap', 'mprotect', 'umtx_op', 'Tidr0SYRmB4', 'n88vx3C5nW8', 'COc2Ua29+pI', 't1BJfub8VdY', 'U5VD1P181iA'];
const latin = pool.toString('latin1');
console.log('\n[Q2] ASCII strings:');
for (const n of NAMES) {
  const i = latin.indexOf(n);
  console.log(`  "${n}": ${i < 0 ? 'NOT FOUND' : '@+0x' + i.toString(16)}`);
}
/* all printable strings >= 6 chars in the pool */
console.log('\n[Q2b] printable runs >= 8 chars in dumped pool:');
let runs = [];
for (let i = 0; i < pool.length;) {
  if (pool[i] >= 0x20 && pool[i] < 0x7f) {
    let j = i; while (j < pool.length && pool[j] >= 0x20 && pool[j] < 0x7f) j++;
    if (j - i >= 8) runs.push({ off: i, s: pool.toString('latin1', i, j).slice(0, 64) });
    i = j;
  } else i++;
}
console.log(`  ${runs.length} runs (first 40):`);
for (const r of runs.slice(0, 40)) console.log(`  +0x${r.off.toString(16)}: "${r.s}"`);

/* Q3: A-vs-text correlation */
console.log('\n[Q3] monotonicity: A vs text (first 40 entries):');
let aMono = 0, tMono = 0, n = 0;
for (let k = 1; k <= 2092; k++) {
  if (!entries[k - 1] || !entries[k]) continue;
  n++;
  if (entries[k].a > entries[k - 1].a) aMono++;
  if (entries[k].text > entries[k - 1].text) tMono++;
}
console.log(`  pairs=${n} a-mono=${aMono} text-mono=${tMono} (text known non-monotone; a-?)`);
for (let k = 0; k < 40; k++) { const e = entries[k]; console.log(`  #${k}: text=0x${e.text.toString(16)} A=0x${e.a.toString(16)}`); }

/* Q4: the session-55 repeating pattern */
console.log('\n[Q4] pattern 0xd430286100e4100 (qword + 4-shift) in pool:');
for (const pat of ['d430286100e41000', 'd430286100e4100']) {
  let i = -1, cnt = 0, first = -1;
  const hex = pool.toString('hex');
  while ((i = hex.indexOf(pat, i + 1)) !== -1) { cnt++; if (first < 0) first = i / 2; }
  console.log(`  ${pat}: ${cnt} hits${first >= 0 ? ' first@+0x' + first.toString(16) : ''}`);
}

/* Q5: 32-bit truncations of the thr NIDs at any byte offset */
console.log('\n[Q5] 32-bit NID fragments (BE+LE, any offset):');
const FRAG = {
  'thr_create lo': 0x2611981E, 'thr_create hi': 0x4E276BD1,
  'thr_self lo': 0xADBDFA92, 'thr_self hi': 0x08E73651,
  'thr_new lo': 0xEE6FC55D, 'thr_new hi': 0xB750497E,
};
for (const [label, v] of Object.entries(FRAG)) {
  const be = Buffer.alloc(4); be.writeUInt32BE(v);
  const le = Buffer.alloc(4); le.writeUInt32LE(v);
  let hits = [];
  for (let o = 0; o + 4 <= pool.length; o++) {
    if (pool.readUInt32BE(o) === v) hits.push('+0x' + o.toString(16) + '(BE)');
    else if (pool.readUInt32LE(o) === v) hits.push('+0x' + o.toString(16) + '(LE)');
  }
  console.log(`  ${label} 0x${v.toString(16)}: ${hits.length ? hits.slice(0, 6).join(' ') : 'none'}`);
}