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
      case 'e2shot':
        /* one-command E2 attempt.
         * arg1 starts with 0x: a REGISTRY-DERIVED base to verify directly
         *   (v5 - the low-14 matching is dead, four sessions proved it)
         * arg1 otherwise: comma-separated failed bases to skip (hex)
         * arg2 (optional): max candidates to try (default 4) */
        if (clean[1] && /^0x/i.test(clean[1])) {
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
