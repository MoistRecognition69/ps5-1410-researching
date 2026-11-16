#!/usr/bin/env node
'use strict';
/* xtab-look.js — hexdump the key pool regions from the banked exfil. */
const fs = require('fs');
const path = require('path');
const LOG = path.join(__dirname, 'ws-shell', 'shell-beacons.log');
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

function hd(label, from, len) {
  console.log(`\n=== ${label} [pool+0x${from.toString(16)} .. +0x${(from + len).toString(16)}]`);
  for (let r = 0; r < len; r += 16) {
    const s = pool.slice(from + r, from + r + Math.min(16, len - r));
    console.log(`  +0x${(from + r).toString(16).padStart(5, '0')}: ${s.toString('hex').replace(/(..)/g, '$1 ').trim().padEnd(47)} |${s.toString('latin1').replace(/[^\x20-\x7e]/g, '.')}|`);
  }
}
hd('POOL HEAD (no entry points here)', 0x0, 0x60);
hd('POOL HEAD+0x100', 0x100, 0x40);
hd('first pattern-hit region', 0x2060, 0x80);
hd('min-A record region (#16 text=0x7a0)', 0x9a00, 0x60);
hd('pattern region sample @+0x4000', 0x4000, 0x60);
hd('pattern region sample @+0x6000', 0x6000, 0x60);
hd('pattern region sample @+0x8000', 0x8000, 0x60);
hd('A-range midpoint @+0xb000', 0xb000, 0x60);

/* short-string rescan (>= 3 printable) */
console.log('\n=== printable runs >= 3 (dumped pool) — count by region');
let runs = [];
for (let i = 0; i < pool.length;) {
  if (pool[i] >= 0x20 && pool[i] < 0x7f) {
    let j = i; while (j < pool.length && pool[j] >= 0x20 && pool[j] < 0x7f) j++;
    if (j - i >= 3) runs.push({ off: i, s: pool.toString('latin1', i, j) });
    i = j;
  } else i++;
}
const by16k = {};
for (const r of runs) { const b = (r.off >> 14) & 7; by16k[b] = (by16k[b] || 0) + 1; }
console.log('  region 16KB-bucket:', JSON.stringify(by16k));
console.log(`  total=${runs.length}; first 30:`);
for (const r of runs.slice(0, 30)) console.log(`  +0x${r.off.toString(16)}: "${r.s.slice(0, 48)}"`);

/* u32 histogram of the pool head: if a {nid, selfrel} table existed, selfrels would appear */
console.log('\n=== selfrel-shaped u32s (0xfffb8000..0xfffc0000 negative) in pool[0..0x9a20)');
let sr = [];
for (let o = 0; o < 0x9a20; o += 4) {
  const v = pool.readUInt32LE(o);
  const sv = v | 0;
  if (sv < 0 && sv > -0x40000) sr.push({ off: o, v: '0x' + v.toString(16), text: '0x' + (0x48000 + sv).toString(16) });
}
console.log(`  count=${sr.length} (sample 10): ${JSON.stringify(sr.slice(0, 10))}`);