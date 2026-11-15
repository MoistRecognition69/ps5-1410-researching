#!/usr/bin/env node
'use strict';
/*
 * lk-match.js — offline libkernel-base candidate derivation.
 *
 * Method: the PS5 maps modules at 16KB granularity, so for any harvested
 * pointer P into libkernel and any known libkernel RVA R, the candidate
 * base B = P - R is only valid if (P & 0x3FFF) === (R & 0x3FFF) (B is
 * then 16KB-aligned by construction). With N pointers and M RVAs, each
 * coincidence has probability M/16384 per pointer; a base supported by
 * MULTIPLE (P, R) pairs is the real one.
 *
 * RVAs: the 13.60 syscall_map + OFFSET_lk_* constants (13.60.js) — the
 * external game lane reuses these on 14.10 (lk+0x1200, lk+0x27F00 both
 * proven live), so the layout carries over.
 *
 * Pointers: the ptrscan harvests from the WebProcess data band
 * (session 10, boot of the RU5FgxVA-era console, BASE=0x82cfd4000).
 *
 * Usage: node lk-match.js [pointers-file.json]   (default: embedded list)
 */
const fs = require('fs');
const path = require('path');

/* ---- parse the 13.60 offsets file ---- */
const offSrc = fs.readFileSync(path.join(__dirname, '..', 'offsets', '13.60.js'), 'utf8');
const rvas = [];
const names = {};
let m;
const mapRe = /0x([0-9A-Fa-f]+):\s*0x([0-9A-Fa-f]+)/g;
while ((m = mapRe.exec(offSrc))) {
  const num = parseInt(m[1], 16), rva = parseInt(m[2], 16);
  rvas.push(rva);
  names[rva] = 'syscall 0x' + num.toString(16);
}
const lkRe = /OFFSET_lk_(\w+)\s*=\s*0x([0-9A-Fa-f]+)/g;
while ((m = lkRe.exec(offSrc))) {
  const rva = parseInt(m[2], 16);
  rvas.push(rva);
  names[rva] = 'lk_' + m[1];
}
console.error('parsed ' + rvas.length + ' libkernel RVAs from 13.60.js');

/* ---- the session-10 harvest (ptrscan of BASE+0x7000000 band) ---- */
const harvest = [
  /* scan 1: band [0x0, 0x400000) */
  0x8081b5230, 0x8081c2780, 0x80819c6b0, 0x808196830, 0x80832cd30, 0x80830c5f0,
  0x8083342b8, 0x808334480, 0x813d1c430, 0x813d1c990, 0x808344ee0, 0x808344800,
  0x8083447f8, 0x808344f10, 0x808344f20, 0x8026094b0, 0x802672a70, 0x8081dde70,
  0x8266203d0, 0x8025c8960, 0x8064391d0, 0x8063d8650, 0x80819ea50, 0x80825d100,
  0x80819c620, 0x80820a340, 0x80820a3f0, 0x808184800, 0x80825d0b0, 0x8081fb5a0,
  0x8063eb650, 0x8063ebf90, 0x8063ebcb0, 0x8063e0b00, 0x8063ebec0, 0x8063ebf20,
  0x8063dbdc0, 0x8063dfdd0, 0x8063e19d0, 0x82bb6fba0, 0x82bb6fbd0, 0x82bbbdae0,
  0x82bbbda20, 0x82bbbe340, 0x82bbbe630, 0x82bb6fa30, 0x82bbade10, 0x82bbae840,
  0x82bb6faa0, 0x80819e990, 0x806405780, 0x829716620,
  /* scan 2: table continuation [0x352300, 0x353000) */
  0x8081c3a40, 0x8081c6060, 0x8081c2900, 0x8297166b0, 0x808183d40, 0x80829fdd0,
  0x808195250, 0x80829fe50, 0x80829fe80, 0x813daa360, 0x808194a40, 0x80819e9b0,
  0x8081eb880, 0x80819ea30, 0x82bbad4f0, 0x82bbbd670, 0x82bbbd730, 0x82bbad580,
  0x82bbbdaa0, 0x8081cd6f0, 0x8081d2280, 0x8081ddae0, 0x82bbc21a0, 0x8081cd660,
  0x8063e0420, 0x808180790, 0x82bbbd7c0, 0x82bbbd840, 0x8081c3250, 0x80314f7c0,
  0x80829bcd0, 0x80825b2a0, 0x8081c0760, 0x80825cfd0, 0x80825ff90, 0x80829c310,
  0x80315d240, 0x80314cfc0, 0x80314cdd0, 0x80314a0e0, 0x803148ef0, 0x8081cd6e0,
  0x8081c2930, 0x8081c1f60, 0x8063e1350, 0x8081f4aa0, 0x8081fba30, 0x80819e9a0,
  0x80819ea10, 0x8081c2160, 0x80820ab50, 0x8063dfb10, 0x8063eb750, 0x8063e1210,
  0x8063df710, 0x8063eb5a0, 0x8063df0b0, 0x8063e13f0, 0x8063cc310, 0x8063c6220,
  0x8081ddad0, 0x8081dfb60, 0x806405180, 0x806405720,
  /* scan 3: table continuation [0x352570, 0x400000) */
  0x8081f5d10, 0x808184ef0, 0x813e65630, 0x813e90260, 0x813e40cc0, 0x813f78e80,
  0x813f6cf90, 0x813dfa090, 0x8081967e0, 0x808194550, 0x813d64ae0, 0x813d8b660,
  0x808196680, 0x8081ba520, 0x8081cfc30, 0x8081fb5f0, 0x808184c00, 0x8081e0720,
  0x8081e0550, 0x808180490, 0x808184780, 0x808194720, 0x808180540, 0x813d631e0,
  0x8081e4060, 0x8081e4270, 0x8081e0990, 0x813f5f5b0, 0x813dfb3b0, 0x813d445f0,
  0x813d44380, 0x813e8ffd0, 0x813e90ce0, 0x813f5e7d0, 0x813e90a60, 0x813dfad00,
  0x813e902b0, 0x813f67420, 0x813e905d0, 0x813f67480, 0x813f5f400, 0x813f5f3c0,
  0x813f5f380, 0x813e65390, 0x813e65370, 0x813e65110, 0x813e65450, 0x813e651f0,
  0x813e65220, 0x813e65250, 0x813dfa2a0, 0x813d445c0, 0x813dfb0d0, 0x813f5f310,
  0x813f5f7a0, 0x813dfa930, 0x813f5f860, 0x813dfa940, 0x813dfaf30, 0x813e65190,
  0x813f5e660, 0x813f5e5c0, 0x813f5e6b0, 0x813f5ec90,
];

/* ---- match: every (P, R) with aligned base ---- */
const bases = {};
for (const P of harvest) {
  for (const R of rvas) {
    if ((P & 0x3fff) === (R & 0x3fff)) {
      const B = P - R;
      if (B < 0x800000000 || B > 0x900000000) continue;
      if (B % 0x4000 !== 0) continue; /* belt and braces */
      const key = '0x' + B.toString(16);
      (bases[key] = bases[key] || []).push({ P: '0x' + P.toString(16), R: '0x' + R.toString(16), fn: names[R] });
    }
  }
}

/* ---- report: bases grouped by support count ---- */
const sorted = Object.entries(bases).sort((a, b) => b[1].length - a[1].length);
console.log('\n=== libkernel base candidates (base => supporting pairs) ===');
for (const [B, pairs] of sorted.slice(0, 15)) {
  console.log('\nBASE ' + B + '  (' + pairs.length + ' supporting pair' + (pairs.length > 1 ? 's' : '') + ')');
  for (const p of pairs.slice(0, 12)) {
    console.log('   P=' + p.P + '  as ' + p.fn + ' (RVA ' + p.R + ')');
  }
}
if (!sorted.length) console.log('(no aligned candidates)');

/* ---- cluster summary of the harvest (band taxonomy) ---- */
const bands = {};
for (const P of harvest) {
  const band = '0x' + (P & ~0xfffff).toString(16);
  bands[band] = (bands[band] || 0) + 1;
}
console.log('\n=== harvest band census ===');
for (const [band, n] of Object.entries(bands).sort((a, b) => b[1] - a[1])) {
  console.log('  ' + band + ' x' + n);
}
