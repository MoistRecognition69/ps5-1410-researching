#!/usr/bin/env node
'use strict';
/*
 * shell-cmd.js — Agent-facing CLI for the PS5 WebProcess shell.
 *
 * Usage:
 *   node shell-cmd.js status
 *   node shell-cmd.js info
 *   node shell-cmd.js read <addr> [len]
 *   node shell-cmd.js read <addr> [len] force
 *   node shell-cmd.js write <addr> <value>
 *   node shell-cmd.js dump <addr> [len] [force]
 *   node shell-cmd.js scan <start> <len> [pattern] [force]
 *   node shell-cmd.js ptrscan <start> <len> <lo> <hi> [max] [force]
 *   node shell-cmd.js deref <addr> [depth] [force]
 *   node shell-cmd.js str <addr>
 *   node shell-cmd.js auxv
 *   node shell-cmd.js modules [force]
 *   node shell-cmd.js threads
 *   node shell-cmd.js call <addr>
 *   node shell-cmd.js callret <addr>
 *   node shell-cmd.js e2shot [skipBase1,skipBase2,...] [maxcand]
 *   node shell-cmd.js raw '<json>'
 *
 * All output is JSON on stdout (parse with jq or JSON.parse).
 * Exit 0 on success, 1 on error.
 *
 * Set PORT env var to match the running server (default 443).
 */
const https = require('https');
const http = require('http');

const PORT = parseInt(process.env.SHELL_PORT || process.env.PORT || '443', 10);
const HOST = process.env.SHELL_HOST || '127.0.0.1';
const USE_HTTP = process.env.SHELL_HTTP === '1';
const TIMEOUT = parseInt(process.env.SHELL_TIMEOUT || '60000', 10);

const args = process.argv.slice(2);
if (!args.length) {
  console.error('Usage: node shell-cmd.js <command> [args...]\n       node shell-cmd.js status');
  process.exit(1);
}

const name = args[0].toLowerCase();

/* ---- status is a local GET, not a PS5 command ---- */
if (name === 'status') {
  const mod = USE_HTTP ? http : https;
  const opts = {
    hostname: HOST, port: PORT, path: '/api/status', method: 'GET',
    rejectUnauthorized: false, timeout: 5000,
  };
  const req = mod.request(opts, (res) => {
    let d = '';
    res.on('data', c => d += c);
    res.on('end', () => { process.stdout.write(d + '\n'); process.exit(0); });
  });
  req.on('error', e => { console.log(JSON.stringify({ err: e.message })); process.exit(1); });
  req.on('timeout', () => { req.destroy(); console.log(JSON.stringify({ err: 'timeout' })); process.exit(1); });
  req.end();
} else {
  /* ---- build command object ---- */
  let cmd;
  const hasForce = args.includes('force');
  const clean = args.filter(a => a !== 'force');

  if (name === 'raw') {
    try { cmd = JSON.parse(args.slice(1).join(' ')); } catch(e) {
      console.log(JSON.stringify({ err: 'invalid JSON: ' + e.message }));
      process.exit(1);
    }
  } else {
    switch (name) {
      case 'read': case 'r':
        cmd = { cmd: 'read', addr: clean[1], len: clean[2] || '0x80' }; break;
      case 'write': case 'w':
        cmd = { cmd: 'write', addr: clean[1], value: clean[2] }; break;
      case 'dump': case 'd':
        cmd = { cmd: 'dump', addr: clean[1], len: clean[2] || '0x100' }; break;
      case 'scan': case 's':
        /* str: fragments are PATTERNS (slot 3), not the start address -
         * 'scan str:lib/' silently shipped the fragment as start and the
         * page died parsing it (session 6). Catch the misuse at the CLI. */
        if (clean[1] && /^str:/i.test(clean[1])) {
          console.log(JSON.stringify({ err: 'str: patterns are the third arg: scan <start> <len> str:XXXX (use the proven cage band, e.g. scan 0x10001603a0 0x780060 str:lib/)' }));
          process.exit(1);
        }
        cmd = { cmd: 'scan', start: clean[1], len: clean[2], pattern: clean[3] || 'elf' }; break;
      case 'ptrscan': case 'p':
        cmd = { cmd: 'ptrscan', start: clean[1], len: clean[2], lo: clean[3], hi: clean[4], max: clean[5] || '64' }; break;
      case 'deref':
        cmd = { cmd: 'deref', addr: clean[1], depth: clean[2] || '2' }; break;
      case 'str':
        cmd = { cmd: 'str', addr: clean[1] }; break;
      case 'info':
        cmd = { cmd: 'info' }; break;
      case 'auxv':
        cmd = { cmd: 'auxv' }; break;
      case 'modules':
        cmd = { cmd: 'modules' }; break;
      case 'threads':
        cmd = { cmd: 'threads' }; break;
      case 'call':
        cmd = { cmd: 'call', addr: clean[1] }; break;
      case 'callret':
        cmd = { cmd: 'callret', addr: clean[1] }; break;
      case 'libc':
        /* THE LIBC IDENTIFIER: one command - stack scan (lk via the
         * guard), auxv (AT_PHDR), the phdrs on the stack, the main
         * module data segment, the GOT dump, foreign-pointer offset
         * matching vs the game lane addrofs table -> libc base +
         * the 1213a import window (96 lk stub pointers). */
        cmd = { cmd: 'libc' }; break;
      case 'xcl':
        /* EXPORT CLUSTER DUMP: entries [from,to) of the lk export
         * table - the 52-stub thread-syscall cluster (0x13000-
         * 0x16000) = the tw lottery targets. Usage: xcl [from] [to] */
        cmd = { cmd: 'xcl', from: clean[1] || '300', to: clean[2] || '500' }; break;
      case 'xtab':
        /* EXPORT-TABLE EXFIL (the deterministic NID-match route): all
         * nE entries full-precision + the name-record pool raw, via
         * sync beacons - then tools/xtab-match.js matches the pool
         * against ps5rs's 195K raw NID hexes offline. PURE DATA-BAND
         * READS (proven [lk+0x48000,+0x76000) band) - no calls, zero
         * crash risk. Usage: xtab [poolbytes] (default auto: maxA+0x100, 0x2000 floor, 64K cap) */
        cmd = { cmd: 'xtab', pool: clean[1] }; break;
      case 'nap':
        /* NANOSLEEP TEST: entry #arg called with scope={tv_sec:arg2}
         * - a blocking call = the entry IS nanosleep. Usage: nap <idx> <sec> */
        cmd = { cmd: 'nap', idx: clean[1] || '17', sec: clean[2] || '4' }; break;
      case 'twr':
        /* THE SURVIVABLE SETCONTEXT TEST: arg1 = the candidate RVA
         * (default 0x130), arg2 = the jump stub (default 0x7A0).
         * The reply posts = setcontext-class CONFIRMED. */
        cmd = { cmd: 'twr', rva: (clean[1]||'130').replace(/^0x/i,''), spin: (clean[2]||'7A0').replace(/^0x/i,'') }; break;
      case 'twc':
        /* THR_CREATE WITNESS: msg1 = the thr_create stub RVA
         * (default 0x130), msg2 = the spin stub (default 0x7A0).
         * The tid lands at [cfr]. Usage: twc [0xRVA] [0xSPIN] */
        cmd = { cmd: 'twc', rva: (clean[1]||'130').replace(/^0x/i,''), spin: (clean[2]||'7A0').replace(/^0x/i,'') }; break;
      case 'tw':
        /* THE THREAD WITNESS: thr_new candidate - export entry #arg1
         * OR (if arg1 starts with 0x) a RAW text RVA (the internal
         * stubs 0x3B0/0x3F0!). arg2 = the spin-stub RVA. */
        if (clean[1] && /^0x/i.test(clean[1])) {
          cmd = { cmd: 'tw', rva: clean[1].replace(/^0x/i,''), nap: clean[2] };
        } else {
          cmd = { cmd: 'tw', idx: clean[1] || '20', nap: clean[2] };
        } break;
      case 'sweep':
        /* THE STUB-LADDER SWEEP: derive lk_base, read export table entry
         * #arg, rawcall it with a zeroed scope. One-arg stubs write the
         * TID to scope[0] and survive. Usage: sweep <idx> */
        cmd = { cmd: 'sweep', idx: clean[1] || '0' }; break;
      case 'e2witness':
        /* THE ONE-COMMAND E2 WITNESS: registry -> thread record -> pthread
         * backlink -> lk_base -> canary gate -> gettimeofday at lk+0xB50
         * (RDI = the pre-zeroed fake scope; tv copies before tz; every step
         * on a blocking sync beacon). */
        cmd = { cmd: 'e2witness' }; break;
      case 'rawcall':
        /* decode-immune call: redirects, calls, DISCARDS the return
         * untouched (raw returns crash the JSValue engine at first touch),
         * restores, and reports the fake scope's first 0x20 bytes - the
         * memory side-channel. Use on TRUE function entries only
         * (imported wrappers - never mid-instruction guesses). */
        cmd = { cmd: 'rawcall', addr: clean[1] }; break;
      case 'e2shot':
        /* one-command E2 attempt.
         * arg1 = 'scan': PURE HARVEST + cluster census, no probes/calls
         *   (100% safe; the rawcall era picks the wrapper cluster offline)
         * arg1 starts with 0x: a registry-derived base to verify directly
         * arg1 otherwise: comma-separated failed bases to skip (hex)
         * arg2 (optional): max candidates to try (default 4) */
        if (clean[1] === 'scan') {
          cmd = { cmd: 'e2shot', scanonly: '1', maxcand: '1' };
        } else if (clean[1] === 'sweep') {
          /* harvest -> auto-pick tight clusters -> rawcall every member,
           * scope-check banked on sync beacons (deaths lose only the
           * remaining members). A time-class wrapper writes the wall
           * clock into the pre-zeroed fake scope = THE WITNESS. */
          cmd = { cmd: 'e2shot', sweep: '1', maxcand: '1' };
        } else if (clean[1] && /^0x/i.test(clean[1])) {
          cmd = { cmd: 'e2shot', base: clean[1], maxcand: clean[2] || '4' };
        } else {
          cmd = { cmd: 'e2shot', skip: clean[1], maxcand: clean[2] || '4' };
        }
        break;
      default:
        console.log(JSON.stringify({ err: 'unknown command: ' + name }));
        process.exit(1);
    }
  }

  if (hasForce) cmd.force = true;
  cmd.timeout = TIMEOUT;

  /* ---- send to server ---- */
  const body = JSON.stringify(cmd);
  const mod = USE_HTTP ? http : https;
  const opts = {
    hostname: HOST, port: PORT, path: '/api/cmd', method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    rejectUnauthorized: false,
    timeout: TIMEOUT + 10000,
  };
  const req = mod.request(opts, (res) => {
    let d = '';
    res.on('data', c => d += c);
    res.on('end', () => {
      process.stdout.write(d + '\n');
      try {
        const obj = JSON.parse(d);
        process.exit(obj.err ? 1 : 0);
      } catch(e) {
        process.exit(0);
      }
    });
  });
  req.on('error', e => { console.log(JSON.stringify({ err: 'server unreachable: ' + e.message })); process.exit(1); });
  req.on('timeout', () => { req.destroy(); console.log(JSON.stringify({ err: 'timeout waiting for PS5 response' })); process.exit(1); });
  req.write(body);
  req.end();
}
