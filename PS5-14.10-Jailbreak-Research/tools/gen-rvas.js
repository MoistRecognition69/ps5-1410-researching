#!/usr/bin/env node
'use strict';
/* gen-rvas.js — emit tools/ws-shell/rvas.js (the embedded the lk target RVA table
 * for the page-side e2shot command) from offsets/13.60.js */
const fs = require('fs');
const path = require('path');
const src = fs.readFileSync(path.join(__dirname, '..', 'offsets', '13.60.js'), 'utf8');
const rvas = [];
let m;
const mapRe = /0x([0-9A-Fa-f]+):\s*0x([0-9A-Fa-f]+)/g;
while ((m = mapRe.exec(src))) rvas.push(parseInt(m[2], 16));
const lkRe = /OFFSET_lk_(\w+)\s*=\s*0x([0-9A-Fa-f]+)/g;
while ((m = lkRe.exec(src))) rvas.push(parseInt(m[2], 16));
const out = 'window.E2_RVAS = [' + rvas.map(r => '0x' + r.toString(16)).join(',') + '];\n' +
  'window.E2_WRAPPER_WINDOW = [0x1A000, 0x1E000];\n' +
  /* openWrapper (syscall 5 -> 0x1BCE0): called with RDI = the zeroed fake
   * scope it executes open("") -> ENOENT -> returns -1 -> decodes as Int32
   * -1, the DECODE-SAFE E2 witness. getCurrentCpu is deliberately NOT used
   * as the verifier: its CPU-0 return (RAX=0) is an invalid JSValue encoding
   * and crashes the engine at first touch - killed sessions 14 and 15 with
   * the base likely RIGHT both times. */
  'window.E2_LK = { getCurrentCpu: 0x1200, getpidWrapper: 0x1B860, openWrapper: 0x1BCE0, gettodWrapper: 0x1B840, stackChkGuard: 0x751D0 };\n';
fs.writeFileSync(path.join(__dirname, 'ws-shell', 'rvas.js'), out);
console.log('wrote ws-shell/rvas.js with ' + rvas.length + ' RVAs');
