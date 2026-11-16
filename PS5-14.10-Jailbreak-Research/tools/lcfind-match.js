#!/usr/bin/env node
'use strict';
/* lcfind-match.js — offline libc-base candidate ranking from an lcfind harvest.
 *
 * Input: the `lcfind` reply JSON (ptrs: [{v, band}]) — foreign module-band qwords.
 * Method: the game lane's 14.10 libc_addrofs (probe 1213a/p588 boots) give KNOWN
 * INTERNAL libc RVAs. For each ptr P and known offset F: base = P - F must be
 * 16KB-aligned (PS5 module granularity). Score bases; pairwise-difference
 * agreement (P1-P2 == F1-F2) is a second independent vote.
 * Output: ranked candidates + agreement details -> fire `lcverify <top>` for the
 * ONE deterministic read (C+0x1179A8 == lk+0xB50).
 *
 * Usage: node lcfind-match.js <lcfind-reply.json>
 */
const fs = require('fs');

/* the game-lane 14.10 libc_addrofs (from base 0x1EA93C000 boot, cross-checked
 * against the 0x1B4BD8000 boot for 0x1179A8). All RVAs = 14.10. */
const KNOWN = {
  0x168: 'error',
  0x198: 'sceKernelGetModuleInfoFromAddr',
  0x366E0: 'strerror',
  0x37BF0: 'Atomic_fetch_add_8',
  0x42410: 'memcpy',
  0x4C1C0: 'Thrd_join',
  0x4C240: 'Thrd_exit',
  0x4C3C0: 'Thrd_create',
  0x4CDB0: 'calloc',
  0xB020: 'setjmp',
  0xB070: 'longjmp',
  0x1179A8: 'gettimeofday_import_GOT',
};
/* NOTE: PS5 module bases are 16KB-aligned BUT the text base of the listed
 * modules is 0x4000-aligned too. libc.prx text base 0x...3C000/0x...D8000:
 * low bits vary; only demand (P-F) % 0x4000 == 0. */

const reply = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const ptrs = (reply.ptrs || []).map(p => ({ v: BigInt(p.v), band: p.band }));
console.log(`[harvest] ${ptrs.length} foreign pointers (bands: ${JSON.stringify([...new Set(ptrs.map(p => p.band))])})`);

/* dedupe */
const seen = new Map();
for (const p of ptrs) if (!seen.has(p.v.toString(16))) seen.set(p.v.toString(16), p.v);
const P = [...seen.values()];
console.log(`[harvest] ${P.length} unique`);

const scores = new Map();   // baseHex -> {score, votes: []}
function vote(base, why) {
  const k = base.toString(16);
  if (!scores.has(k)) scores.set(k, { base, score: 0, votes: [] });
  const s = scores.get(k);
  s.score += why.weight;
  s.votes.push(why.desc);
}
/* vote 1: P - F aligned */
for (const p of P) {
  for (const [F, name] of Object.entries(KNOWN)) {
    const f = Number(F);
    const base = p - BigInt(f);
    if (base <= 0n) continue;
    if (base % 0x4000n !== 0n) continue;
    if (base < 0x100000000n || base >= 0x10000000000n) continue;
    vote(base, { weight: 1, desc: `P=0x${p.toString(16)} - ${name}(0x${f.toString(16)})` });
  }
}

/* vote 2: pairwise differences == known differences */
const knownArr = Object.entries(KNOWN).map(([F, name]) => ({ f: Number(F), name }));
const pairScores = new Map();
for (let i = 0; i < P.length && i < 400; i++) {
  for (let j = 0; j < P.length && j < 400; j++) {
    if (i === j) continue;
    const d = P[i] - P[j];
    if (d <= 0n || d > 0x120000n) continue;
    for (const a of knownArr) for (const b of knownArr) {
      if (a.f - b.f !== Number(d)) continue;
      const base = P[i] - BigInt(a.f);
      if (base % 0x4000n !== 0n) continue;
      const k = base.toString(16);
      pairScores.set(k, (pairScores.get(k) || 0) + 1);
      vote(base, { weight: 1, desc: `pair P1=0x${P[i].toString(16)} P2=0x${P[j].toString(16)} = ${a.name}-${b.name}` });
    }
  }
}

const ranked = [...scores.values()].sort((a, b) => b.score - a.score).slice(0, 12);
console.log('\n=== ranked libc-base candidates:');
for (const r of ranked) {
  console.log(`  0x${r.base.toString(16).padStart(0, '0')}  score=${r.score}  (pair-votes=${pairScores.get(r.base.toString(16)) || 0})`);
  for (const v of [...new Set(r.votes)].slice(0, 6)) console.log(`      ${v}`);
}
if (ranked.length) {
  console.log(`\n[next] fire: node shell-cmd.js lcverify 0x${ranked[0].base.toString(16)}`);
  fs.writeFileSync(__dirname + '/lc-candidates.json', JSON.stringify(ranked.map(r => ({ base: '0x' + r.base.toString(16), score: r.score })), null, 1));
  console.log('wrote lc-candidates.json');
} else {
  console.log('\n[!] NO ALIGNED CANDIDATES — the harvest found no P-F-aligned bases.');
  console.log('    Next: dump the raw ptr list for eyeballing (bands: ' + JSON.stringify([...new Set(ptrs.map(p => p.band))]) + ').');
  const byBand = {};
  for (const p of ptrs) byBand[p.band] = (byBand[p.band] || 0) + 1;
  console.log('    per-band counts: ' + JSON.stringify(byBand));
  const sorted = [...new Set(ptrs.map(p => p.v.toString(16)))].sort();
  console.log('    first 40 unique values:');
  for (const s of sorted.slice(0, 40)) console.log('      0x' + s);
}