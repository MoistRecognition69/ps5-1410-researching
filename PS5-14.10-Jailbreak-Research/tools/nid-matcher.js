#!/usr/bin/env node
'use strict';
/* nid-matcher.js — the PS5 NID computation + table matcher.
 * Algorithm from ps5rs (algorithm.rs):
 *   SHA1(name + salt 518D64A635DED8C1E6B039B1C3E55230)
 *   -> reverse first 8 bytes -> custom base64 (+- alphabet) -> 11 chars
 * Verified: memcpy=Q3VBxCXhUHs, sceKernelSleep=-ZR+hG7aDHw,
 *           scePthreadCreate=6UgtwV+0zb4 (3/3 ps5rs test vectors).
 *
 * Usage: node nid-matcher.js [nidTableJson]
 *   If nidTableJson provided, match entries against all computed NIDs.
 *   Otherwise, just print the computed NID table.
 */
const crypto = require('crypto');
const fs = require('fs');

const SALT = Buffer.from('518D64A635DED8C1E6B039B1C3E55230', 'hex');
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-';

function hash(name) {
  const h = crypto.createHash('sha1').update(Buffer.concat([Buffer.from(name), SALT])).digest();
  const rev = Buffer.alloc(8);
  for (let i = 0; i < 8; i++) rev[i] = h[7 - i];
  let nid = '';
  for (let i = 0; i < 8; i += 3) {
    const b0 = rev[i], b1 = i + 1 < 8 ? rev[i + 1] : 0, b2 = i + 2 < 8 ? rev[i + 2] : 0;
    const triple = (b0 << 16) | (b1 << 8) | b2;
    nid += B64[(triple >> 18) & 63];
    nid += B64[(triple >> 12) & 63];
    if (i + 1 < 8) nid += B64[(triple >> 6) & 63];
    if (i + 2 < 8) nid += B64[triple & 63];
  }
  return nid.substring(0, 11);
}

function nidToU64(nid) {
  const values = nid.split('').map(c => B64.indexOf(c));
  const bytes = Buffer.alloc(8);
  bytes[0] = ((values[0] << 2) | (values[1] >> 4)) & 0xFF;
  bytes[1] = (((values[1] & 0x0f) << 4) | (values[2] >> 2)) & 0xFF;
  bytes[2] = (((values[2] & 0x03) << 6) | values[3]) & 0xFF;
  bytes[3] = ((values[4] << 2) | (values[5] >> 4)) & 0xFF;
  bytes[4] = (((values[5] & 0x0f) << 4) | (values[6] >> 2)) & 0xFF;
  bytes[5] = (((values[6] & 0x03) << 6) | values[7]) & 0xFF;
  bytes[6] = ((values[8] << 2) | (values[9] >> 4)) & 0xFF;
  bytes[7] = (((values[9] & 0x0f) << 4) | (values[10] >> 2)) & 0xFF;
  return bytes.readBigUInt64BE(0);
}

// The candidate function names (raw syscalls + sceKernel wrappers)
const NAMES = [
  // Raw syscall names (the E2 targets)
  'thr_self', 'getpid', 'gettid', 'getuid', 'geteuid', 'getppid',
  'write', 'read', 'open', 'close', 'mmap', 'munmap', 'mprotect',
  'clock_gettime', 'gettimeofday', 'nanosleep', 'sysarch', 'sysctl',
  'fork', 'exit', 'wait4', 'execve', 'pipe', 'socket', 'connect',
  'sendto', 'recvfrom', 'accept', 'bind', 'listen', 'shutdown',
  'dup', 'dup2', 'fstat', 'stat', 'lstat', 'lseek', 'ioctl',
  'kill', 'sigaction', 'sigprocmask', 'kqueue', 'kevent',
  'pread', 'pwrite', 'access', 'chdir', 'mkdir', 'rmdir',
  'unlink', 'rename', 'chmod', 'chown', 'fsync', 'ftruncate',
  'sched_yield', 'getpriority', 'setpriority', 'mincore', 'minherit',
  'madvise', 'mlock', 'munlock', 'getrlimit', 'setrlimit',
  'getitimer', 'setitimer', 'getpagesize', 'sysconf', 'futex',
  'umtx_op', 'cpuset_getaffinity', 'cpuset_setaffinity',
  'rtprio_thread', 'thr_new', 'thr_exit', 'thr_kill',
  'thr_suspend', 'thr_wake', 'thr_set_name', 'thr_get_name',
  'sigreturn', 'sigpending', 'sigsuspend', 'sigwait',
  'sigtimedwait', 'sigqueue', 'getdents', 'getdirentries',
  'poll', 'select', 'pselect', 'ums_sleep',
  'umtx_wakeup', 'umtx_lock', 'umtx_unlock',
  // sceKernel wrappers (the NID table entries)
  'sceKernelGetModuleInfo', 'sceKernelGetModuleInfoByName',
  'sceKernelDlsym', 'sceKernelLoadStartModule', 'sceKernelGetProcParam',
  'sceKernelSendNotificationRequest', 'sceKernelDebugOutText',
  'sceKernelGetCurrentCpu', 'sceKernelUsleep', 'sceKernelSleep',
  'sceKernelOpen', 'sceKernelClose', 'sceKernelRead', 'sceKernelWrite',
  'sceKernelMmap', 'sceKernelMunmap', 'sceKernelGetProcessTime',
  'sceKernelAllocateDirectMemory', 'sceKernelMapDirectMemory',
  'sceKernelGetModuleInfoFromAddr', 'sceKernelJitCreateSharedMemory',
  'sceKernelJitCreateAliasOfSharedMemory', 'sceKernelJitMapSharedMemory',
  'sceKernelStat', 'sceKernelGetdents', 'sceKernelLseek',
  'sceKernelIoctl', 'sceKernelKill', 'sceKernelSigaction',
  'sceKernelSigprocmask', 'sceKernelKqueue', 'sceKernelKevent',
  'sceKernelPread', 'sceKernelPwrite', 'sceKernelAccess',
  'sceKernelChdir', 'sceKernelMkdir', 'sceKernelRmdir',
  'sceKernelUnlink', 'sceKernelRename', 'sceKernelChmod',
  'sceKernelChown', 'sceKernelFsync', 'sceKernelFtruncate',
  'sceKernelSchedYield', 'sceKernelGetpriority', 'sceKernelSetpriority',
  'sceKernelMincore', 'sceKernelMinherit', 'sceKernelMadvise',
  'sceKernelMlock', 'sceKernelMunlock', 'sceKernelGetrlimit',
  'sceKernelSetrlimit', 'sceKernelGetitimer', 'sceKernelSetitimer',
  'sceKernelGetpagesize', 'sceKernelSysconf', 'sceKernelFutex',
  'sceKernelGetpid', 'sceKernelGettid', 'sceKernelGetuid',
  'sceKernelGeteuid', 'sceKernelGetppid', 'sceKernelFork',
  'sceKernelExit', 'sceKernelWait4', 'sceKernelExecve',
  'sceKernelPipe', 'sceKernelSocket', 'sceKernelConnect',
  'sceKernelSendto', 'sceKernelRecvfrom', 'sceKernelAccept',
  'sceKernelBind', 'sceKernelListen', 'sceKernelShutdown',
  'sceKernelDup', 'sceKernelDup2', 'sceKernelFstat',
  'sceKernelLstat', 'sceKernelPoll', 'sceKernelSelect',
  'sceKernelThrSelf', 'sceKernelThrNew', 'sceKernelThrExit',
  // libc
  'memcpy', 'memset', 'malloc', 'free', 'strlen', 'strcmp',
  'scePthreadCreate', 'scePthreadMutexLock', 'scePthreadMutexUnlock',
];

// Compute NIDs for all names
const nidMap = {}; // nid -> name
const u64Map = {}; // hi32 hex -> name
for (const name of NAMES) {
  const nid = hash(name);
  const u64 = nidToU64(nid);
  const hi32 = Number(u64 >> 32n);
  nidMap[nid] = name;
  u64Map['0x' + hi32.toString(16).toUpperCase().padStart(8, '0')] = name;
}

// Print the computed table
console.log('=== COMPUTED NIDs ===');
for (const name of NAMES) {
  const nid = hash(name);
  const u64 = nidToU64(nid);
  const hi32 = Number(u64 >> 32n);
  console.log(`  ${name}: nid=${nid} hi32=0x${hi32.toString(16).toUpperCase().padStart(8, '0')}`);
}

// If a NID table JSON was provided, match entries
if (process.argv[2]) {
  const tableData = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
  console.log('\n=== NID TABLE MATCHES ===');
  let matched = 0;
  for (const entry of tableData) {
    const nid = entry.nid;
    // Try matching the full hi32
    if (u64Map[nid]) {
      console.log(`  *** MATCH: ${nid} -> ${u64Map[nid]} (rva=${entry.rva})`);
      matched++;
    }
    // Also try: 0xFFFF0000 | (computed_hi32 & 0xFFFF)
    for (const [name, n] of Object.entries(nidMap)) {
      const u64 = nidToU64(n);
      const hi32 = Number(u64 >> 32n);
      const candidate = '0xFFFF' + (hi32 & 0xFFFF).toString(16).toUpperCase().padStart(4, '0');
      if (candidate === nid) {
        console.log(`  *** TRUNC-MATCH: ${nid} -> ${name} (rva=${entry.rva})`);
        matched++;
      }
      // Try hi16
      const candidate2 = '0xFFFF' + (hi32 >>> 16).toString(16).toUpperCase().padStart(4, '0');
      if (candidate2 === nid) {
        console.log(`  *** HI16-MATCH: ${nid} -> ${name} (rva=${entry.rva})`);
        matched++;
      }
    }
  }
  console.log(`\n${matched} matches out of ${tableData.length} entries`);
  if (matched === 0) {
    console.log('No matches - the numeric NID encoding differs from the base64 NID.');
    console.log('Dump all entries for manual analysis:');
    for (const entry of tableData) {
      console.log(`  ${entry.off}: ${entry.nid} -> rva ${entry.rva}`);
    }
  }
}
