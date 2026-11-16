#!/usr/bin/env node
'use strict';
/* xtab-names.js — the entry->name resolution pass.
 * Corrected pool (per-8-chunk reversal) -> for each entry: the string at
 * pool+A (direct / +4 / +8). Then: thread-name hunt + scePthreadCreate
 * resolution + reference-hunt for the anchor records (#5 thr_self A=0xec18,
 * #8 thr_new A=0xf49c). */
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
for (const o of offs) {
  const raw = Buffer.from(poolHex[o.toString(16)], 'hex');
  const fix = Buffer.alloc(raw.length);
  for (let c = 0; c < raw.length; c += 8) for (let i = 0; i < 8 && c + i < raw.length; i++) fix[c + 7 - i] = raw[c + i] || 0;
  fix.copy(pool, o);
}
const latin = pool.toString('latin1');

function cstr(off) {
  if (off < 0 || off >= pool.length) return null;
  if (!(pool[off] >= 0x20 && pool[off] < 0x7f)) return null;
  let j = off; while (j < pool.length && pool[j] >= 0x20 && pool[j] < 0x7f) j++;
  if (j - off < 3) return null;
  return latin.substring(off, j);
}
/* entry -> name: string AT A, else at A+4, A+8, A-4, A-8 */
const named = [];
for (let k = 0; k < 2092; k++) {
  const e = entries[k]; if (!e) continue;
  let s = cstr(e.a), d = 0;
  if (!s) for (const dd of [4, 8, -4, -8, 2, 1]) { const t = cstr(e.a + dd); if (t) { s = t; d = dd; break; } }
  if (s) named.push({ k, text: e.text, a: e.a, name: s, delta: d });
}
console.log(`[names] ${named.length} of 2092 entries have strings at/near A`);
console.log('\n=== ALL thread/pthread/thr-related names:');
for (const n of named) if (/thr|Thread|pthread|Pthread/i.test(n.name))
  console.log(`  #${n.k}: "${n.name}" text=0x${n.text.toString(16)} A=0x${n.a.toString(16)}${n.delta ? ' (A' + (n.delta > 0 ? '+' : '') + n.delta + ')' : ''}`);

console.log('\n=== first 32 named entries:');
for (const n of named.slice(0, 32)) console.log(`  #${n.k}: "${n.name.slice(0, 32)}" text=0x${n.text.toString(16)} A=0x${n.a.toString(16)}${n.delta ? ' (+' + n.delta + ')' : ''}`);

/* the scePthreadCreate resolution: entry whose string == it (or A pointing at it) */
const tci = latin.indexOf('scePthreadCreate');
console.log(`\n[scePthreadCreate] string @ pool+0x${tci.toString(16)}; entries resolving to it:`);
for (const n of named) if (n.name.startsWith('scePthreadCreate')) console.log(`  #${n.k}: text=0x${n.text.toString(16)} A=0x${n.a.toString(16)} delta=${n.delta}`);

/* reference hunt: who in the pool points AT the anchor records / at key strings? (u32/u64 BE+LE) */
function refs(val, label) {
  const out = [];
  for (let o = 0; o + 8 <= pool.length; o++) {
    if (pool.readUInt32LE(o) === val || pool.readUInt32BE(o) === val) out.push({ off: o, enc: pool.readUInt32LE(o) === val ? 'LE32' : 'BE32' });
  }
  console.log(`  ${label} (0x${val.toString(16)}): ${out.length} refs: ${out.slice(0, 8).map(r => '+0x' + r.off.toString(16) + '/' + r.enc).join(' ')}`);
  return out;
}
console.log('\n[refs] u32 references INTO the pool:');
refs(tci, 'scePthreadCreate string');
refs(0xec18, 'anchor #5 record (thr_self)');
refs(0xf49c, 'anchor #8 record (thr_new)');

/* anchor-record CONTEXT: what's around 0xec18 and 0xf49c (the record region),
 * and do any NEARBY pool offsets appear as A values of entries? */
const byA = {}; for (let k = 0; k < 2092; k++) { const e = entries[k]; if (e) byA[e.a] = k; }
console.log('\n[anchor ctx] records + neighbors:');
for (const [a, label] of [[0xec18, '#5 thr_self'], [0xf49c, '#8 thr_new']]) {
  console.log(`  --- ${label} A=0x${a.toString(16)} (entry #${byA[a]})`);
  for (let r = -16; r <= 48; r += 8) {
    const o = a + r; if (o < 0) continue;
    const s = pool.slice(o, o + 8);
    const e = byA[o] !== undefined ? ` <-- A of entry #${byA[o]} (text=0x${entries[byA[o]].text.toString(16)})` : '';
    console.log(`    +0x${o.toString(16)}: ${s.toString('hex').replace(/(..)/g, '$1 ').trim()} |${s.toString('latin1').replace(/[^\x20-\x7e]/g, '.')}|${e}`);
  }
}
/* how MANY entries' A values are in the record region [0x9000, 0x10000) vs string region? */
let rec = 0, str = 0, other = 0;
for (let k = 0; k < 2092; k++) {
  const e = entries[k]; if (!e) continue;
  const s = cstr(e.a) || cstr(e.a + 4) || cstr(e.a + 8);
  if (s) str++; else if (e.a >= 0x9000 && e.a < 0x16000) rec++; else other++;
}
console.log(`\n[A classes] string-linked=${str} record-region-no-string=${rec} other=${other}`);
/* the string-region layout: dump around scePthreadCreate for structure */
console.log('\n[string ctx] around scePthreadCreate:');
for (let o = tci - 32; o <= tci + 48; o += 8) {
  if (o < 0) continue;
  const s = pool.slice(o, o + 8);
  console.log(`  +0x${o.toString(16)}: ${s.toString('hex').replace(/(..)/g, '$1 ').trim()} |${s.toString('latin1').replace(/[^\x20-\x7e]/g, '.')}|`);
}