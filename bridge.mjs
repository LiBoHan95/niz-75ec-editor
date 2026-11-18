#!/usr/bin/env node
/**
 * 75EC 改键台 · 本地桥接
 *
 * Chrome 的 WebHID 会把带键盘功能的 HID 设备当作受保护设备，页面拿不到
 * 75EC 的配置接口。这个小服务用 node-hid 直接和键盘通信，并向本机页面
 * 提供 /api/read、/api/write。只监听 127.0.0.1，且需要启动时生成的令牌。
 */
import http from 'node:http';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFile, execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const HID = require('node-hid');

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const LOCK_PATH = path.join(ROOT, '.bridge.pid');
const VID = 0x0483;
const PID = 0x5026;
const CONFIG_INTERFACE = 1;
const CMD = { VERSION: 0xf9, READ_ALL: 0xf2, WRITE_ALL: 0xf1, KEY_DATA: 0xf0, DATA_END: 0xf6 };
const DEFAULT_KEYCOUNT = 75;
const MAX_BODY = 256 * 1024;
const TOKEN = crypto.randomBytes(24).toString('hex');

const args = process.argv.slice(2);
const shouldOpen = !args.includes('--no-open');
const argPort = Number((args.find(a => a.startsWith('--port=')) || '').split('=')[1]);
const START_PORT = Number.isInteger(argPort) && argPort > 0 ? argPort : 8787;

/* ============================================================
   Keyboard protocol (verified against the real 75EC)
   ============================================================ */
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

class DeviceError extends Error {
  constructor(message, code = 'device') {
    super(message);
    this.code = code;
  }
}

function listDevices() {
  try {
    return HID.devices();
  } catch (err) {
    return [];
  }
}

function findConfigDevice() {
  return listDevices().find(d =>
    d.vendorId === VID && d.productId === PID &&
    d.interface === CONFIG_INTERFACE &&
    (d.usagePage === 0x8c || d.usagePage === 140)
  );
}

function openDevice() {
  const info = findConfigDevice();
  if (!info) {
    throw new DeviceError('没有找到 75EC-XRGB 的配置接口。请确认键盘已插好、线没有松动。');
  }
  let dev;
  try {
    dev = new HID.HID(info.path);
  } catch (err) {
    if (/exclusive access|already open/i.test(err.message)) {
      const busy = new DeviceError(
        '键盘的配置接口正被另一个程序占用（通常是另一个改键台窗口或旧进程）。请关闭其他改键台窗口后重试；仍然失败就拔插一次键盘。',
        'busy'
      );
      busy.exclusive = true;
      throw busy;
    }
    throw new DeviceError(
      `无法打开键盘（${err.message}）。macOS 可能要求输入监控权限：系统设置 → 隐私与安全性 → 输入监控，允许终端后重试。`
    );
  }
  return { dev, info };
}

function makeChannel(dev) {
  let onPacket = null;
  let broken = false;
  const onData = (buf) => { if (onPacket) onPacket(Buffer.from(buf)); };
  const onError = () => { broken = true; };
  dev.on('data', onData);
  dev.on('error', onError);
  return {
    get broken() { return broken; },
    send(cmd, data = Buffer.alloc(0)) {
      const buf = Buffer.alloc(65);
      buf[0] = 0;
      buf.writeUInt16BE(cmd, 1);
      data.copy(buf, 3, 0, Math.min(62, data.length));
      dev.write(buf);
    },
    setHandler(fn) {
      const previous = onPacket;
      onPacket = fn;
      return () => { if (onPacket === fn) onPacket = previous; };
    },
    waitFor(predicate, timeoutMs, label) {
      return new Promise((resolve, reject) => {
        let done = false;
        const timer = setTimeout(() => {
          if (done) return;
          done = true;
          onPacket = null;
          reject(new DeviceError(`等待键盘响应超时（${label || '未知步骤'}）`));
        }, timeoutMs);
        onPacket = (packet) => {
          if (done) return;
          let hit = false;
          try { hit = predicate(packet); } catch (err) {
            done = true;
            clearTimeout(timer);
            onPacket = null;
            reject(err);
            return;
          }
          if (!hit) return;
          done = true;
          clearTimeout(timer);
          onPacket = null;
          resolve(packet);
        };
      });
    },
    close() {
      onPacket = null;
      try { dev.removeListener('data', onData); } catch (err) { /* ignore */ }
      try { dev.removeListener('error', onError); } catch (err) { /* ignore */ }
      try { dev.close(); } catch (err) { /* ignore */ }
    }
  };
}

function decodeAscii(data, start) {
  let out = '';
  for (let i = start; i < data.length; i++) {
    const c = data[i];
    if (!c) break;
    if (c >= 32 && c < 127) out += String.fromCharCode(c);
  }
  return out.trim();
}

function parseKeycount(version) {
  const match = /^(\d+)/.exec(version || '');
  const n = match ? Number(match[1]) : NaN;
  return Number.isFinite(n) && n > 0 && n <= 200 ? n : DEFAULT_KEYCOUNT;
}

async function readVersion(channel) {
  const packet = channel.waitFor(
    p => p.length >= 3 && p.readUInt16BE(0) === CMD.VERSION,
    3000,
    '读取固件版本'
  );
  try {
    channel.send(CMD.VERSION);
  } catch (err) {
    await packet.catch(() => {});
    throw err;
  }
  const version = decodeAscii(await packet, 2);
  if (!version) throw new DeviceError('键盘没有返回固件版本');
  return version;
}

async function readAllRows(channel, keycount) {
  const rows = [];
  let ended = false;
  const stop = channel.setHandler((p) => {
    if (p[0] === CMD.DATA_END) {
      ended = true;
      return;
    }
    if (p.length >= 7 && p.readUInt16BE(0) === CMD.KEY_DATA) {
      const level = p[2];
      const key = p[3];
      const hw = p[6];
      if (level >= 1 && key >= 1) rows.push({ level, key, hw });
    }
  });
  try {
    channel.send(CMD.READ_ALL);
    const started = Date.now();
    while (!ended) {
      if (Date.now() - started > 20000) {
        if (rows.length >= keycount) break;
        throw new DeviceError('读取键位超时，请重新读取');
      }
      await sleep(40);
    }
  } finally {
    stop();
  }
  if (rows.length < keycount) {
    throw new DeviceError(`只读到 ${rows.length} 条键位，请重试`);
  }
  return normalizeRows(rows.filter(r => r.level <= 2));
}

async function openDeviceWithRetry() {
  let lastError;
  for (let attempt = 0; attempt < 10; attempt++) {
    try {
      return openDevice();
    } catch (err) {
      lastError = err;
      if (!err.exclusive && !/exclusive access|already open/i.test(err.message)) throw err;
      await sleep(150);
    }
  }
  throw lastError;
}

/* Keep the config interface open: reopening it per request races with macOS
   releasing exclusive access, which shows up as "device already open". */
let openState = null;

async function ensureChannel() {
  if (openState && !openState.channel.broken) return openState.channel;
  if (openState) dropChannel();
  const { dev, info } = await openDeviceWithRetry();
  const channel = makeChannel(dev);
  openState = { dev, info, channel };
  return channel;
}

function dropChannel() {
  if (!openState) return;
  try { openState.channel.close(); } catch (err) { /* ignore */ }
  openState = null;
}

async function withDevice(fn) {
  const channel = await ensureChannel();
  await sleep(80); // let any late report from the previous operation drain
  try {
    return await fn(channel);
  } catch (err) {
    if (err.code === 'input' || err.code === 'stale' || err.code === 'verify') throw err;
    dropChannel();
    throw err;
  }
}

function normalizeRows(rows) {
  return rows
    .map(r => ({ level: r.level, key: r.key, hw: r.hw }))
    .sort((a, b) => a.level - b.level || a.key - b.key);
}

function validateRows(rows, keycount) {
  if (!Array.isArray(rows)) throw new DeviceError('键位数据格式不正确', 'input');
  if (rows.length !== keycount * 2) {
    throw new DeviceError(`应该有 ${keycount * 2} 条键位（2 层 × ${keycount} 键），实际 ${rows.length} 条`, 'input');
  }
  const seen = new Set();
  for (const row of rows) {
    if (!row || !Number.isInteger(row.level) || !Number.isInteger(row.key) || !Number.isInteger(row.hw)) {
      throw new DeviceError('键位数据里含有非整数值', 'input');
    }
    if (row.level < 1 || row.level > 2) throw new DeviceError(`无效的层 ${row.level}`, 'input');
    if (row.key < 1 || row.key > keycount) throw new DeviceError(`无效的键位 ${row.key}`, 'input');
    if (row.hw < 0 || row.hw > 255) throw new DeviceError(`无效的键码 ${row.hw}`, 'input');
    const id = `${row.level}:${row.key}`;
    if (seen.has(id)) throw new DeviceError(`键位重复：第 ${row.level} 层 ${row.key}`, 'input');
    seen.add(id);
  }
  for (let level = 1; level <= 2; level++) {
    for (let key = 1; key <= keycount; key++) {
      if (!seen.has(`${level}:${key}`)) {
        throw new DeviceError(`缺少第 ${level} 层键位 ${key}`, 'input');
      }
    }
  }
}

function sameRows(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  const index = new Map(b.map(r => [`${r.level}:${r.key}`, r.hw]));
  return a.every(r => index.get(`${r.level}:${r.key}`) === r.hw);
}

async function readMapping(channel) {
  const version = await readVersion(channel);
  const keycount = parseKeycount(version);
  const rows = await readAllRows(channel, keycount);
  validateRows(rows, keycount);
  return { version, keycount, rows };
}

async function writeRows(channel, rows) {
  const ordered = normalizeRows(rows);
  channel.send(CMD.WRITE_ALL);
  await sleep(20);
  for (let i = 0; i < ordered.length; i++) {
    const r = ordered[i];
    channel.send(CMD.KEY_DATA, Buffer.from([r.level, r.key, 0, r.hw ? 1 : 0, r.hw]));
    if ((i + 1) % 10 === 0) await sleep(4);
  }
  channel.send(CMD.DATA_END, Buffer.alloc(62, 0xf6));
  await sleep(600);
}

/* Serialize keyboard access: one operation at a time. */
let queue = Promise.resolve();
function enqueue(fn) {
  const run = queue.then(fn, fn);
  queue = run.catch(() => {});
  return run;
}

async function apiRead() {
  return enqueue(() => withDevice(async (channel) => readMapping(channel)));
}

async function apiWrite(body) {
  const rows = body && body.rows;
  const baseline = body && body.baseline;
  if (!Array.isArray(rows) || !Array.isArray(baseline)) {
    throw new DeviceError('缺少键位或基线数据', 'input');
  }
  return enqueue(() => withDevice(async (channel) => {
    const current = await readMapping(channel);
    validateRows(rows, current.keycount);
    validateRows(baseline, current.keycount);
    if (!sameRows(baseline, current.rows)) {
      const err = new DeviceError('键盘上的配置已经变化（可能切换了模式或重新改过键）。请先重新读取，确认后再写入。', 'stale');
      err.rows = current.rows;
      err.version = current.version;
      err.keycount = current.keycount;
      throw err;
    }
    await writeRows(channel, rows);
    const back = await readMapping(channel);
    if (!sameRows(rows, back.rows)) {
      const err = new DeviceError('写入后读回的内容与预期不一致。键盘可能处于部分写入状态，请重新读取并重试。', 'verify');
      err.rows = back.rows;
      err.version = back.version;
      err.keycount = back.keycount;
      throw err;
    }
    return { version: back.version, keycount: back.keycount, rows: back.rows };
  }));
}

/* ============================================================
   HTTP server
   ============================================================ */
function json(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Content-Length': Buffer.byteLength(body)
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        reject(new DeviceError('请求内容过大', 'input'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try {
        resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {});
      } catch (err) {
        reject(new DeviceError('请求不是有效的 JSON', 'input'));
      }
    });
    req.on('error', reject);
  });
}

function originAllowed(req, port) {
  const host = (req.headers.host || '').toLowerCase();
  const allowedHosts = new Set([`127.0.0.1:${port}`, `localhost:${port}`]);
  if (!allowedHosts.has(host)) return false;
  const origin = req.headers.origin;
  if (!origin) return true; // same-origin fetches may omit it; token still required
  const allowedOrigins = new Set([`http://127.0.0.1:${port}`, `http://localhost:${port}`]);
  return allowedOrigins.has(origin.toLowerCase());
}

async function serveFile(res, name, type) {
  const data = await fs.readFile(path.join(ROOT, name));
  res.writeHead(200, {
    'Content-Type': type,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Content-Length': data.length
  });
  res.end(data);
}

async function createServer() {
  const server = http.createServer(async (req, res) => {
    try {
      const port = server.address().port;
      if (!originAllowed(req, port)) {
        json(res, 403, { ok: false, error: '只允许从本机页面访问' });
        return;
      }
      const url = new URL(req.url || '/', `http://127.0.0.1:${port}`);
      const pathname = url.pathname;

      if (req.method === 'GET' && (pathname === '/' || pathname === '/index.html')) {
        await serveFile(res, 'index.html', 'text/html; charset=utf-8');
        return;
      }
      if (req.method === 'GET' && pathname === '/bridge-config.js') {
        const body = `window.NIZ_BRIDGE = ${JSON.stringify({ token: TOKEN })};\n`;
        res.writeHead(200, {
          'Content-Type': 'application/javascript; charset=utf-8',
          'Cache-Control': 'no-store',
          'X-Content-Type-Options': 'nosniff',
          'Content-Length': Buffer.byteLength(body)
        });
        res.end(body);
        return;
      }
      if (req.method === 'GET' && pathname === '/favicon.ico') {
        res.writeHead(204);
        res.end();
        return;
      }

      if (pathname.startsWith('/api/')) {
        if (req.headers['x-bridge-token'] !== TOKEN) {
          json(res, 403, { ok: false, error: '令牌不正确，请刷新页面' });
          return;
        }
        if (req.method === 'GET' && pathname === '/api/status') {
          const info = findConfigDevice();
          json(res, 200, {
            ok: true,
            bridge: true,
            present: !!info,
            product: info ? info.product || '75EC-XRGB' : null
          });
          return;
        }
        if (req.method === 'POST' && pathname === '/api/read') {
          const mapping = await apiRead();
          json(res, 200, {
            ok: true,
            ...mapping,
            layers: [...new Set(mapping.rows.map(r => r.level))].sort((a, b) => a - b)
          });
          return;
        }
        if (req.method === 'POST' && pathname === '/api/write') {
          const body = await readBody(req);
          const result = await apiWrite(body);
          json(res, 200, { ok: true, ...result });
          return;
        }
        json(res, 404, { ok: false, error: '没有这个接口' });
        return;
      }

      json(res, 404, { ok: false, error: '没有这个页面' });
    } catch (err) {
      const status = err.code === 'input' ? 400
        : err.code === 'stale' ? 409
        : err.code === 'verify' ? 409
        : err.code === 'busy' ? 409
        : 503;
      const payload = { ok: false, code: err.code || 'error', error: err.message || '未知错误' };
      if (Array.isArray(err.rows)) {
        payload.rows = err.rows;
        payload.version = err.version;
        payload.keycount = err.keycount;
      }
      json(res, status, payload);
      if (status === 503) console.error(`[bridge] ${err.stack || err.message}`);
    }
  });
  server.requestTimeout = 60000;
  server.headersTimeout = 10000;
  return server;
}

function listen(server, port) {
  return new Promise((resolve, reject) => {
    const onError = (err) => {
      server.removeListener('listening', onListening);
      reject(err);
    };
    const onListening = () => {
      server.removeListener('error', onError);
      resolve();
    };
    server.once('error', onError);
    server.once('listening', onListening);
    server.listen(port, '127.0.0.1');
  });
}

/* ============================================================
   Single instance
   ============================================================ */
async function readLockPid() {
  try {
    const pid = Number((await fs.readFile(LOCK_PATH, 'utf8')).trim());
    return Number.isInteger(pid) && pid > 0 ? pid : null;
  } catch (err) {
    return null;
  }
}

function pidAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err.code === 'EPERM';
  }
}

function isBridgeProcess(pid) {
  try {
    const out = execFileSync('ps', ['-p', String(pid), '-o', 'command='], { encoding: 'utf8' });
    return out.includes('bridge.mjs');
  } catch (err) {
    return false;
  }
}

async function acquireLock() {
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      await fs.writeFile(LOCK_PATH, `${process.pid}\n`, { flag: 'wx' });
      return { ok: true };
    } catch (err) {
      if (err.code !== 'EEXIST') throw err;
      const pid = await readLockPid();
      if (pid && pidAlive(pid) && isBridgeProcess(pid)) return { ok: false, pid };
      try { await fs.unlink(LOCK_PATH); } catch (e) { /* raced with another cleanup */ }
    }
  }
  return { ok: false, pid: null };
}

function probeBridge(port) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    const req = http.get(
      { host: '127.0.0.1', port, path: '/bridge-config.js', timeout: 250, agent: false },
      (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          body += chunk;
          if (body.length > 4096) { req.destroy(); finish(false); }
        });
        res.on('end', () => finish(res.statusCode === 200 && body.includes('window.NIZ_BRIDGE')));
        res.on('error', () => finish(false));
      }
    );
    req.on('timeout', () => { req.destroy(); finish(false); });
    req.on('error', () => finish(false));
  });
}

async function findRunningBridge() {
  for (let port = START_PORT; port < START_PORT + 24; port++) {
    if (await probeBridge(port)) return port;
  }
  return null;
}

function openUrl(url) {
  execFile('open', ['-a', 'Google Chrome', url], (err) => {
    if (err) execFile('open', [url], () => {});
  });
}

async function main() {
  const runningPort = await findRunningBridge();
  if (runningPort) {
    const runningUrl = `http://127.0.0.1:${runningPort}/`;
    console.log('');
    console.log(`改键台已经在运行：${runningUrl}`);
    console.log('不重复启动：同一时间只允许一个进程访问键盘的配置接口。');
    console.log('');
    if (shouldOpen) openUrl(runningUrl);
    return;
  }

  const lock = await acquireLock();
  if (!lock.ok) {
    console.error('');
    console.error(`已有改键台进程（PID ${lock.pid || '未知'}）在运行，但页面端口没有响应。`);
    console.error('请关闭对应的终端窗口，或结束该进程后重新双击 start.command。');
    console.error('');
    process.exit(1);
  }
  process.on('exit', () => {
    try {
      if (Number(fsSync.readFileSync(LOCK_PATH, 'utf8').trim()) === process.pid) {
        fsSync.unlinkSync(LOCK_PATH);
      }
    } catch (err) { /* lock already gone */ }
  });

  const server = await createServer();
  let port = START_PORT;
  let lastError;
  for (let attempt = 0; attempt < 60; attempt++, port++) {
    try {
      await listen(server, port);
      lastError = null;
      break;
    } catch (err) {
      lastError = err;
      if (err.code !== 'EADDRINUSE') break;
    }
  }
  if (lastError) {
    console.error(`无法监听本地端口（从 ${START_PORT} 开始）：${lastError.message}`);
    process.exit(1);
  }

  const url = `http://127.0.0.1:${port}/`;
  const info = findConfigDevice();
  console.log('');
  console.log('75EC 改键台 · 本地桥接已启动');
  console.log(`  ${url}`);
  console.log(info ? `  已检测到键盘：${info.product || '75EC-XRGB'}` : '  尚未检测到键盘（插好后刷新页面即可）');
  console.log('  关闭这个窗口即停止服务。');
  console.log('');

  if (shouldOpen) openUrl(url);

  let shuttingDown = false;
  const shutdown = () => {
    if (shuttingDown) return;
    shuttingDown = true;
    dropChannel();
    if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
    server.close();
    // Don't wait on server.close(): keep-alive sockets or the HID handle can
    // keep the event loop alive and leave the keyboard exclusively locked.
    setTimeout(() => process.exit(0), 250);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
  process.on('SIGHUP', shutdown);
}

main().catch((err) => {
  console.error(err.stack || err.message);
  process.exit(1);
});
