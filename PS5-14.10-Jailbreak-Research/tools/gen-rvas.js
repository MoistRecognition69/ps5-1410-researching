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
  /* THE SPARSE ANCHORS (v6): the wrapper region spans 10+ 16KB pages so its
   * low-14 residues blanket the value space - wrapper matches are noise
   * (four dead sessions proved it). These EIGHT non-wrapper offsets have
   * sparse residues (~0.05% random-match each); the WK module imports
   * several of these functions DIRECTLY from the target module. Two
   * anchors agreeing on one base = confirmation. The stack-guard anchor
   * additionally verifies WITHOUT CALLING: its pointer targets the canary -
   * a random-looking 64-bit value at that address confirms everything. */
  'window.E2_SPARSE = [0x1200, 0x751D0, 0x21890, 0x229A0, 0x21C20, 0x27F00, 0x1FD01, 0x6C218];\n' +
  'window.E2_SPARSE_NAMES = { 0x1200: "GetCurrentCpu", 0x751D0: "stack_chk_guard", 0x21890: "pthread_create_name_np", 0x229A0: "pthread_join", 0x21C20: "pthread_exit", 0x27F00: "sleep", 0x1FD01: "worker_wait_return", 0x6C218: "thread_list" };\n' +
  'window.E2_LK = { getCurrentCpu: 0x1200, getpidWrapper: 0x1B860, openWrapper: 0x1BCE0, gettodWrapper: 0x1B840, stackChkGuard: 0x751D0 };\n';
fs.writeFileSync(path.join(__dirname, 'ws-shell', 'rvas.js'), out);
console.log('wrote ws-shell/rvas.js with ' + rvas.length + ' RVAs');
