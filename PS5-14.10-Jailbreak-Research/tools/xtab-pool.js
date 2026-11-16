#!/usr/bin/env node
'use strict';
/* xtab-pool.js — correct assembly (per-8-byte-chunk reversal) + string extraction
 * + thr_name hunt + entry linkage study, from the banked XT-P beacons. */
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
  const hx = poolHex[o.toString(16)];
  const raw = Buffer.from(hx, 'hex');
  /* CORRECT THE REVERSAL: the in-page hex builder emitted qword-value-BE,
   * absRead56 reads LE -> each 8-byte chunk is memory-reversed. Flip back. */
  const fix = Buffer.alloc(raw.length);
  for (let c = 0; c < raw.length; c += 8)
    for (let i = 0; i < 8 && c + i < raw.length; i++)
      fix[c + 7 - i] = raw[c + i] || 0;
  fix.copy(pool, o);
}
console.log(`[pool] ${pool.length} bytes (per-8-chunk corrected)`);

/* string extraction */
const runs = [];
for (let i = 0; i < pool.length;) {
  if (pool[i] >= 0x20 && pool[i] < 0x7f) {
    let j = i; while (j < pool.length && pool[j] >= 0x20 && pool[j] < 0x7f) j++;
    if (j - i >= 4) runs.push({ off: i, s: pool.toString('latin1', i, j) });
    i = j;
  } else i++;
}
console.log(`[strings] ${runs.length} runs >= 4 chars`);
const latin = pool.toString('latin1');
for (const probe of ['libSceDbgThread', 'thr_self', 'thr_new', 'thr_create', 'thr_exit', 'thr_kill', 'gettimeofday', 'getpid', 'nanosleep', 'clock_gettime', 'umtx_op', 'scePthreadCreate']) {
  const i = latin.indexOf(probe);
  console.log(`  "${probe}": ${i < 0 ? 'NOT FOUND' : '@pool+0x' + i.toString(16)}`);
}
/* thr_* hunt */
console.log('[thr_* strings]');
for (const r of runs) if (/^thr[_A-Z]/.test(r.s)) console.log(`  +0x${r.off.toString(16)}: "${r.s.slice(0, 48)}"`);

/* the anchor records: what's at pool+A for #5 (thr_self) and #8 (thr_new)? */
for (const [idx, name] of [[5, 'thr_self'], [8, 'thr_new']]) {
  const e = entries[idx];
  console.log(`\n[anchor #${idx} ${name}] text=0x${e.text.toString(16)} A=0x${e.a.toString(16)} -> pool+0x${e.a.toString(16)}`);
  if (e.a + 0x30 <= pool.length) {
    for (let r = 0; r < 0x30; r += 16) {
      const s = pool.slice(e.a + r, e.a + r + 16);
      console.log(`  +0x${(e.a + r).toString(16)}: ${s.toString('hex').replace(/(..)/g, '$1 ').trim()} |${s.toString('latin1').replace(/[^\x20-\x7e]/g, '.')}|`);
    }
  }
}

/* string-adjacency study: for every entry, is pool+A pointing at/near a string? */
let direct = 0, near = 0, none = 0;
const missing = [];
for (let k = 0; k < 2092; k++) {
  const e = entries[k]; if (!e) continue;
  if (e.a >= pool.length) { none++; continue; }
  const at = latin.indexOf('\0', e.a) === e.a || (pool[e.a] >= 0x20 && pool[e.a] < 0x7f);
  let isStr = pool[e.a] >= 0x20 && pool[e.a] < 0x7f;
  if (isStr) direct++; else {
    let f = false;
    for (let d = 1; d <= 8 && !f; d++) { const p = e.a + d; if (p < pool.length && pool[p] >= 0x20 && pool[p] < 0x7f && /[a-zA-Z_]/.test(latin[p])) f = true; }
    if (f) near++; else { none++; if (missing.length < 10) missing.push(`#${k} A=0x${e.a.toString(16)}`); }
  }
}
console.log(`\n[A-vs-strings] direct=${direct} near(<=8b)=${near} neither=${none} (sample neither: ${missing.join(', ')})`);

/* IF thr_create's string exists, list every entry whose A is within +/-32 of it */
const tci = latin.indexOf('thr_create');
if (tci >= 0) {
  console.log(`\n*** thr_create string @ pool+0x${tci.toString(16)}: "${latin.substring(tci, tci + 24)}"`);
  console.log('    entries with A near it:');
  for (let k = 0; k < 2092; k++) {
    const e = entries[k]; if (!e) continue;
    if (Math.abs(e.a - tci) <= 32) console.log(`    #${k}: text=0x${e.text.toString(16)} A=0x${e.a.toString(16)} (delta ${e.a - tci})`);
  }
}
/* same for thr_self/thr_new (anchor validation of any linkage) */
for (const [nm, idx] of [['thr_self', 5], ['thr_new', 8]]) {
  const i = latin.indexOf(nm);
  if (i < 0) continue;
  const e = entries[idx];
  console.log(`\n[link-check] ${nm} string @ +0x${i.toString(16)}; entry #${idx} A=0x${e.a.toString(16)} delta=${e.a - i}`);
}