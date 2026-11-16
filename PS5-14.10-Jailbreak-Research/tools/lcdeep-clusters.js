#!/usr/bin/env node
'use strict';
/* lcdeep-clusters.js — cluster the lcfind-deep harvest, rank module-base candidates.
 *
 * The deep chunks hold STALE FRAMES of the sync-XHR call chain: return
 * addresses into the modules that actually ran (libSceNet, libSceLibcInternal,
 * libc.prx, ...). The stk/deep values in the cage band (~0x1_00xxxxxxx) are JS
 * heap noise; the module returns are in the 0x8-band (Sony system modules),
 * the 0x1-band (the shared libc.prx region on both game-lane boots), and
 * 0x88-band (pthread/heap structs - ignore).
 *
 * Method: band-split -> cluster by gaps > 0x100000 -> for each cluster with
 * >= 3 members: candidate bases = every 16KB-aligned C in
 * [clusterMin - maxModuleSize, clusterMin], ranked by member fit
 * (members in [C, C+maxSize)). Then: 'lcelf <C>' top-down (highest C first -
 * candidates above the real base are INSIDE the module = mapped = safe
 * garbage-rejects; the first ELF-magic hit = the base).
 *
 * Usage: node lcdeep-clusters.js <lcfind-reply.json>
 */
const fs = require('fs');

const reply = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const ptrs = (reply.ptrs || []).map(p => ({ v: BigInt(p.v), band: p.band }));
console.log(`[harvest] ${ptrs.length} values (cfr=${reply.cfr} base=${reply.base})`);

/* band split */
const bands = {
  b1: [],   // [0x100000000, 0x200000000): shared system region (libc.prx on game lane)
  b8: [],   // [0x800000000, 0x880000000): Sony system modules (libSceNet, libSceLibcInternal)
  b88: [],  // [0x880000000, 0x900000000): pthread/heap structs — ignore
  heap: [], // cage/JS values ~0x1_00xxxxxxx with low bits unset pattern — mostly noise
  other: [],
};
for (const p of ptrs) {
  const v = p.v;
  if (v >= 0x880000000n && v < 0x900000000n) bands.b88.push(p);
  else if (v >= 0x800000000n && v < 0x880000000n) bands.b8.push(p);
  else if (v >= 0x100000000n && v < 0x200000000n) bands.b1.push(p);
  else if (v >= 0x200000000n && v < 0x800000000n) bands.heap.push(p);
  else bands.other.push(p);
}
console.log(`[bands] b1(shared/libc-class)=${bands.b1.length}  b8(sysmods)=${bands.b8.length}  b88(pthread)=${bands.b88.length}  heap-noise=${bands.heap.length}  other=${bands.other.length}`);

/* cluster within a band: sort, split on gaps > 0x100000 */
function clusters(arr) {
  const s = [...arr].sort((a, b) => (a.v < b.v ? -1 : a.v > b.v ? 1 : 0));
  const out = [];
  let cur = [];
  for (const p of s) {
    if (cur.length && p.v - cur[cur.length - 1].v > 0x100000n) { out.push(cur); cur = []; }
    cur.push(p);
  }
  if (cur.length) out.push(cur);
  return out;
}
const MAXSIZE = 0x140000n; // generous: libSceLibcInternal 0x128000, libc.prx ~0x120000
for (const [label, arr] of [['b1', bands.b1], ['b8', bands.b8]]) {
  if (!arr.length) continue;
  console.log(`\n=== ${label} clusters:`);
  for (const cl of clusters(arr)) {
    const mn = cl[0].v, mx = cl[cl.length - 1].v;
    console.log(`  [0x${mn.toString(16)} .. 0x${mx.toString(16)}] n=${cl.length} span=0x${(mx - mn).toString(16)} bands=${[...new Set(cl.map(p => p.band))].join(',')}`);
    if (cl.length < 3 || mx - mn > MAXSIZE * 2n) { console.log('    (skip: <3 members or too wide)'); continue; }
    /* candidates: aligned bases in [mn-MAXSIZE, mn] */
    const lo = mn - MAXSIZE;
    let cands = [];
    for (let c = (lo / 0x4000n) * 0x4000n; c <= mn; c += 0x4000n) {
      let fit = 0;
      for (const p of cl) if (p.v >= c && p.v < c + MAXSIZE) fit++;
      if (fit === cl.length) cands.push(c);   // a base covering ALL members
    }
    console.log(`    full-fit aligned bases (${cands.length}): ${cands.map(c => '0x' + c.toString(16)).join(' ')}`);
    if (cands.length) console.log(`    [next] lcelf TOP-DOWN from 0x${cands[cands.length - 1].toString(16)} (in-module candidates are safe; the ELF magic hit = the base)`);
  }
}
/* raw lists for eyeballing */
for (const [label, arr] of [['b1', bands.b1], ['b8', bands.b8]]) {
  if (!arr.length) continue;
  console.log(`\n[${label} all values]`);
  for (const p of arr) console.log(`  0x${p.v.toString(16)} (${p.band})`);
}