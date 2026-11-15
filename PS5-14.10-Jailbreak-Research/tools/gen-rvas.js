#!/usr/bin/env node
'use strict';
/* gen-rvas.js — emit tools/ws-shell/rvas.js (the embedded libkernel RVA table
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
  'window.E2_LK = { getCurrentCpu: 0x1200, getpidWrapper: 0x1B860, stackChkGuard: 0x751D0 };\n';
fs.writeFileSync(path.join(__dirname, 'ws-shell', 'rvas.js'), out);
console.log('wrote ws-shell/rvas.js with ' + rvas.length + ' RVAs');
