#!/usr/bin/env node
'use strict';
/* xtab-eh.js — the .eh_frame parse: FDEs from the A-offsets ->
 * {init_loc, addr_range} per entry -> the complete function map ->
 * gap analysis (stub regions, the 0x20 grid) around the thr band. */
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
console.log(`[pool] ${pool.length} bytes`);

/* .eh_frame_hdr at tbl: {ver, ptr_enc, cnt_enc, tbl_enc} + {eh_frame_ptr@4, count@8} + table@0xC.
 * pool = tbl+0x416C. FDE offsets A are datarel -> relative tbl -> pool addr = A - 0x416C.
 * FDE in .eh_frame: {u32 len, s32 CIE_backref, s32 init_loc(DATAREL->tbl), u32 addr_range, CFI...} */
const POOL_OFF = 0x416C;
function fdeAt(poolOff) {
  if (poolOff < 0 || poolOff + 16 > pool.length) return null;
  const len = pool.readUInt32LE(poolOff);
  const cie = pool.readInt32LE(poolOff + 4);
  const loc = pool.readInt32LE(poolOff + 8);
  const range = pool.readUInt32LE(poolOff + 12);
  return { poolOff, len, cie, loc, range, total: len + 4 };
}
/* validate: FDE@pool+(A-0x416C): {len32, cie32, loc32(pcrel: init = A+8+loc), range32}.
 * EMPIRICALLY VALIDATED ON BOTH ANCHORS: init == 0x48000-relative text: A+8+loc == text. */
let ok = 0, bad = 0, badList = [];
const funcMap = [];
for (let k = 0; k < 2092; k++) {
  const e = entries[k]; if (!e) continue;
  const f = fdeAt(e.a - POOL_OFF);
  if (!f) { bad++; if (badList.length < 8) badList.push(`#${k} A out of pool`); continue; }
  const init = 0x48000 + e.a + 8 + f.loc;   /* datarel to tbl — VALIDATED: #5→0x2C0, #8→0x410 */
  if (init === e.text && f.range > 0 && f.range < 0x10000) { ok++; funcMap.push({ k, text: e.text, len: f.range, end: e.text + f.range, a: e.a }); }
  else { bad++; if (badList.length < 12) badList.push(`#${k} text=0x${e.text.toString(16)} init=0x${init.toString(16)} len=0x${f.len.toString(16)} range=0x${f.range.toString(16)}`); }
}
console.log(`[FDE] validated=${ok} mismatch=${bad}`);
if (badList.length) console.log('  mismatches:\n    ' + badList.join('\n    '));

/* print the function map around the thr band [0x200, 0x600) with gap analysis */
console.log('\n=== function map, texts < 0x800 (the thr band): start..start+len');
funcMap.filter(f => f.text < 0x800).forEach(f =>
  console.log(`  #${String(f.k).padStart(4)}: [0x${f.text.toString(16)}, 0x${(f.text + f.len).toString(16)})  len=0x${f.len.toString(16)}`));

/* GAPS: regions not covered by any function extent, in [0, 0x1000) */
const cov = [];
for (const f of funcMap) if (f.text < 0x1000) cov.push([f.text, f.end]);
cov.sort((a, b) => a[0] - b[0]);
let cur = 0; const gaps = [];
for (const [s, e] of cov) { if (s > cur) gaps.push([cur, s]); cur = Math.max(cur, e); }
if (cur < 0x1000) gaps.push([cur, 0x1000]);
console.log('\n=== non-function gaps in [0, 0x1000):');
for (const [s, e] of gaps) {
  const grid = [];
  for (let g = Math.ceil(s / 0x20) * 0x20; g < e; g += 0x20) grid.push('0x' + g.toString(16));
  console.log(`  [0x${s.toString(16)}, 0x${e.toString(16)}) len=0x${(e - s).toString(16)}  0x20-grid slots: ${grid.join(' ')}`);
}
/* full-module stats */
const totalFn = funcMap.length;
let textEnd = 0; for (const f of funcMap) textEnd = Math.max(textEnd, f.end);
console.log(`\n[stats] functions=${totalFn} maxEnd=0x${textEnd.toString(16)}`);
/* how do the known stubs sit relative to function extents? */
const KNOWN = { 0x2C0: 'thr_self(fn?)', 0x3B0: 'STUB(+7 test)', 0x3D0: 'twc-died', 0x3F0: 'thr_exit STUB', 0x410: 'thr_new(fn?)', 0xB50: 'gettimeofday STUB' };
console.log('\n=== known addresses vs function extents:');
for (const [t, label] of Object.entries(KNOWN)) {
  const tv = +t;
  const hit = funcMap.find(f => f.text === tv);
  const inside = funcMap.find(f => f.text < tv && tv < f.end);
  console.log(`  0x${tv.toString(16)} (${label}): ${hit ? 'FUNCTION START len=0x' + hit.len.toString(16) : inside ? 'INSIDE function [0x' + inside.text.toString(16) + ',0x' + inside.end.toString(16) + ')' : 'IN A GAP (no function covers it)'}`);
}
/* save the function map */
fs.writeFileSync(path.join(__dirname, 'lk-funcmap.json'), JSON.stringify(funcMap.map(f => [f.k, f.text, f.len, f.a]), null, 1));
console.log('\nwrote lk-funcmap.json (' + funcMap.length + ' functions)');