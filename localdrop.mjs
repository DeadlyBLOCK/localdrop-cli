#!/usr/bin/env node
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import crypto from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { StringDecoder } from 'node:string_decoder';
import { fileURLToPath } from 'node:url';

const VERSION = '1.0.0';
const SELF = (() => { try { return fileURLToPath(import.meta.url); } catch { return process.execPath; } })();
const seaApi = async () => { try { const sea = await import('node:sea'); return sea.isSea() ? sea : null; } catch { return null; } };
const WIN = process.platform === 'win32';
const READ = 1 << 20, HIGH = 4 << 20, LOW = 1 << 20, NOTE_MAX = 64 << 10, TEXT_MAX = 20000, MAX_FILES = 10000;
const ASK_MS = 60000, CONNECT_MS = 25000, BYE_MS = 20000;
const KINDS = ['phone', 'tablet', 'computer'];
const OSES = ['ios', 'android', 'windows', 'macos', 'linux', 'chromeos'];
const ID_RE = /^p[a-f0-9]{15}$/;
const NO_ROUTE = "couldn't connect. this network may block devices from reaching each other (guest wi-fi, client isolation).";
const DEFAULT_ICE = ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'];

/* ---------- helpers ---------- */
const hex = (n) => crypto.randomBytes(n).toString('hex');
const plural = (n, w) => n + ' ' + w + (n === 1 ? '' : 's');
const clamp01 = (f) => Math.min(1, Math.max(0, f || 0));
const pct = (f) => Math.floor(clamp01(f) * 100) + '%';
const cut = (s, n) => { s = String(s); return s.length <= n ? s : Array.from(s.slice(0, n * 2)).slice(0, n).join(''); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const now = () => performance.now();

function fmtBytes(n) {
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < 4) { n /= 1024; i++; }
  return (i && n < 10 ? n.toFixed(1) : Math.round(n)) + ' ' + u[i];
}
function fmtTime(s) {
  if (!(s >= 1)) return 'under 1s';
  s = Math.round(s);
  if (s < 60) return s + 's';
  const m = Math.floor(s / 60);
  return m < 60 ? m + 'm ' + String(s % 60).padStart(2, '0') + 's' : Math.floor(m / 60) + 'h ' + String(m % 60).padStart(2, '0') + 'm';
}
const took = (c) => { const s = Math.max(0.05, (c.endAt - c.t0) / 1000); return (s < 10 ? s.toFixed(1) + 's' : fmtTime(s)) + (c.total > 1 << 20 ? ' · ' + fmtBytes(c.total / s) + '/s' : ''); };
const ago = (t) => { const s = (Date.now() - t) / 1000; return s < 50 ? 'just now' : s < 3600 ? Math.round(s / 60) + 'm ago' : Math.round(s / 3600) + 'h ago'; };
const cleanName = (s) => cut(String(s ?? '').replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]/g, '').replace(/\s+/g, ' ').trim(), 32).trim();
const safeName = (s) => cut(String(s ?? '').replace(/[\u0000-\u001f\u007f\u200b-\u200f\u202a-\u202e\u2066-\u2069\\/:*?"<>|]+/g, '_').replace(/^\s+|[\s.]+$/g, ''), 160) || 'file';
function fitBytes(name, max = 200) {
  if (Buffer.byteLength(name) <= max) return name;
  const ext = (/\.[^.\s]{1,12}$/.exec(name) || [''])[0], base = Array.from(name.slice(0, name.length - ext.length));
  while (base.length && Buffer.byteLength(base.join('') + ext) > max) base.pop();
  return base.join('') + ext || 'file';
}
function safePart(p) {
  const m = /^(.+?)(\.[A-Za-z0-9]{1,12})?$/.exec(p);
  return m[2] ? fitBytes(cut(safeName(m[1]), 150) + m[2]) : fitBytes(safeName(p));
}
const safeRel = (s) => String(s ?? '').split('/').map((p) => p.trim()).filter((p) => p && p !== '.' && p !== '..').map(safePart).slice(-8).join(path.sep) || 'file';
function safeMime(m) {
  m = String(m || '').toLowerCase();
  return /^(image\/(png|jpeg|gif|webp|avif|heic|heif|bmp)|video\/[\w.+-]+|audio\/[\w.+-]+|application\/pdf|text\/plain)$/.test(m) ? m : 'application/octet-stream';
}
const MIME = { png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp', avif: 'image/avif', heic: 'image/heic', heif: 'image/heif', bmp: 'image/bmp', pdf: 'application/pdf', txt: 'text/plain', md: 'text/plain', log: 'text/plain', csv: 'text/plain', mp4: 'video/mp4', mov: 'video/quicktime', webm: 'video/webm', mkv: 'video/x-matroska', mp3: 'audio/mpeg', m4a: 'audio/mp4', wav: 'audio/wav', ogg: 'audio/ogg', flac: 'audio/flac' };
const mimeOf = (n) => MIME[(/\.([a-z0-9]{1,5})$/i.exec(n) || [])[1]?.toLowerCase()] || '';
const ABC = 'abcdefghjkmnpqrstuvwxyz23456789';
const normCode = (v) => String(v || '').toLowerCase().replace(/[^a-z0-9]/g, '');
const validCode = (v) => /^[a-z0-9]{6,32}$/.test(v);
const pretty = (c) => c.replace(/(.{4})(?=.)/g, '$1-');
const newCode = () => Array.from(crypto.randomBytes(8), (b) => ABC[b % ABC.length]).join('');
const ADJ = ['quiet', 'brave', 'cosmic', 'velvet', 'amber', 'lunar', 'swift', 'mellow', 'crimson', 'jade', 'solar', 'misty', 'nimble', 'golden', 'silent', 'electric', 'wild', 'cobalt'];
const ANI = ['otter', 'falcon', 'lynx', 'heron', 'panda', 'wolf', 'koala', 'bison', 'raven', 'tapir', 'gecko', 'marten', 'ferret', 'orca', 'moth', 'newt', 'stork', 'fox'];
const pick = (a) => a[crypto.randomInt(a.length)];
const HOME = os.homedir();
const tilde = (p) => (p === HOME ? '~' : p.startsWith(HOME + path.sep) ? '~' + p.slice(HOME.length) : p);
const expand = (p) => path.resolve(p === '~' ? HOME : p.startsWith('~/') || p.startsWith('~\\') ? path.join(HOME, p.slice(2)) : p);
const isDir = (p) => { try { return fs.statSync(p).isDirectory(); } catch { return false; } };
const privateIp = (ip) => /^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|f[cd][0-9a-f]{2}:|fe80:|::1$)/i.test(String(ip || '').replace(/^::ffff:/i, ''));

/* ---------- config ---------- */
const CONF_DIR = path.join(process.env.XDG_CONFIG_HOME || (WIN ? process.env.APPDATA || HOME : path.join(HOME, '.config')), 'localdrop');
const CACHE_DIR = path.join(process.env.XDG_CACHE_HOME || (WIN ? process.env.LOCALAPPDATA || HOME : process.platform === 'darwin' ? path.join(HOME, 'Library', 'Caches') : path.join(HOME, '.cache')), 'localdrop');
const CONF_FILE = path.join(CONF_DIR, 'config.json');
let conf = {};
try { conf = JSON.parse(fs.readFileSync(CONF_FILE, 'utf8')) || {}; } catch {}
function saveConf(patch) {
  Object.assign(conf, patch);
  try { fs.mkdirSync(CONF_DIR, { recursive: true }); fs.writeFileSync(CONF_FILE, JSON.stringify(conf, null, 2) + '\n'); } catch {}
}
function normServer(u) {
  u = String(u || '').trim();
  if (!u) return '';
  if (!/^https?:\/\//i.test(u)) u = (/^(localhost|127\.|10\.|192\.168\.|\[)/.test(u) ? 'http://' : 'https://') + u;
  try { const x = new URL(u); x.hash = ''; return x.href; } catch { return ''; }
}

/* ---------- arguments ---------- */
const HELP = `localdrop ${VERSION} · send files between your devices

usage
  localdrop [files...]              open the interface (files start staged)
  localdrop host [--port 8080]      share from this computer: relay + web page, no server needed
  localdrop send <files...>         send without the interface (stdin is sent as a note)
  localdrop recv                    receive without the interface
  localdrop devices                 list nearby devices
  localdrop serve [--port 8080]     run only the relay and web page (headless)

options
  -s, --server <url>    relay address (where index.php is hosted)      env LOCALDROP_SERVER
  -r, --room <code>     use a private room instead of this network
  -n, --name <name>     device name shown to others
  -o, --out <dir>       where received files are saved
  -t, --to <name>       send: target device (name, prefix, or "all")
      --text <text>     send: send a note instead of files
      --from <name>     recv: only accept from this device
  -y, --yes             recv: accept without asking
      --count <n>       recv: exit after n transfers
      --json            devices: machine-readable output
      --web <file>      host/serve: index.php for the web page (default: next to localdrop, or built in)
      --bind <addr>     host/serve: listen address (default 0.0.0.0)
      --theme <t>       auto, dark, light, ansi or mono                 env NO_COLOR
      --no-mouse        keep the terminal's own mouse selection
  -h, --help            show this help
  -v, --version         show the version

keys
  f files · t note · c connect · enter send · tab focus · r rename · o folder · ? help · q quit
  drop files onto the terminal or paste text to send it
`;

function parseArgs(argv) {
  const out = { cmd: 'tui', files: [], f: {} };
  const short = { s: 'server', r: 'room', n: 'name', o: 'out', t: 'to', y: 'yes', h: 'help', v: 'version', p: 'port' };
  const bools = new Set(['yes', 'help', 'version', 'json', 'no-mouse']);
  const vals = new Set(['server', 'room', 'name', 'out', 'to', 'from', 'text', 'port', 'bind', 'web', 'theme', 'count']);
  const cmds = { send: 'send', recv: 'recv', receive: 'recv', devices: 'devices', host: 'host', serve: 'serve', help: 'help', version: 'version' };
  let i = 0, rest = false;
  if (cmds[argv[0]]) out.cmd = cmds[argv[i++]];
  for (; i < argv.length; i++) {
    const a = argv[i];
    if (rest || a === '-' || !a.startsWith('-')) { out.files.push(a); continue; }
    if (a === '--') { rest = true; continue; }
    const m = /^--([a-z-]+)(?:=([\s\S]*))?$/.exec(a) || /^-([a-z])$/i.exec(a);
    const k = m && (m[1].length === 1 ? short[m[1]] : m[1]);
    if (!k || (!bools.has(k) && !vals.has(k))) throw new Error('unknown option ' + a);
    if (bools.has(k)) { out.f[k] = true; continue; }
    const v = m[2] ?? argv[++i];
    if (v === undefined) throw new Error('missing value for --' + k);
    out.f[k] = v;
  }
  return out;
}

/* ---------- webrtc engine (node-datachannel, installed on first use) ---------- */
let RTC = null;
async function engine(say = (t) => process.stderr.write(t + '\n')) {
  if (RTC) return RTC;
  const load = (m) => m.default && m.default.PeerConnection ? m.default : m;
  const sea = await seaApi();
  if (sea) {
    try {
      const buf = Buffer.from(sea.getRawAsset('node_datachannel.node'));
      const file = path.join(CACHE_DIR, 'bin-' + VERSION + '-' + crypto.createHash('sha1').update(buf).digest('hex').slice(0, 12), 'node_datachannel.node');
      if (!fs.existsSync(file)) { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file + '.' + process.pid, buf); fs.renameSync(file + '.' + process.pid, file); }
      const m = { exports: {} };
      process.dlopen(m, file);
      RTC = m.exports;
    } catch (e) { debug(e); }
  }
  if (!RTC) { try { RTC = load(await import('node-datachannel')); } catch {} }
  const dir = path.join(CACHE_DIR, 'engine');
  const req = createRequire(path.join(dir, 'package.json'));
  if (!RTC) { try { RTC = load(req('node-datachannel')); } catch {} }
  if (!RTC) {
    say('localdrop: first run, installing the webrtc engine (node-datachannel) into ' + tilde(dir));
    fs.mkdirSync(dir, { recursive: true });
    if (!fs.existsSync(path.join(dir, 'package.json'))) fs.writeFileSync(path.join(dir, 'package.json'), '{"private":true}\n');
    const r = spawnSync(WIN ? 'npm.cmd' : 'npm', ['install', '--no-audit', '--no-fund', '--loglevel=error', 'node-datachannel@^0.33.4'], { cwd: dir, stdio: ['ignore', 2, 2], shell: WIN });
    if (r.status !== 0) throw new Error('could not install node-datachannel. run: npm install -g node-datachannel');
    RTC = load(req('node-datachannel'));
  }
  const log = process.env.LOCALDROP_DEBUG;
  RTC.initLogger(log ? 'Debug' : 'Fatal', (lvl, msg) => { if (log) try { fs.appendFileSync(log, `[rtc ${lvl}] ${msg}\n`); } catch {} });
  try { RTC.setSctpSettings({ recvBufferSize: 16 << 20, sendBufferSize: 16 << 20 }); } catch {}
  return RTC;
}
function debug(...a) { const log = process.env.LOCALDROP_DEBUG; if (log) try { fs.appendFileSync(log, new Date().toISOString() + ' ' + a.map((x) => (x instanceof Error ? x.stack : typeof x === 'string' ? x : JSON.stringify(x))).join(' ') + '\n'); } catch {} }

/* ---------- state ---------- */
const me = { secret: hex(24), name: '', kind: process.platform === 'android' ? 'phone' : 'computer', os: { darwin: 'macos', win32: 'windows', linux: 'linux', android: 'android' }[process.platform] || '' };
let SERVER = '', SHARE = '', room = '', OUT = '', ICE = DEFAULT_ICE;
const peers = new Map(), conns = new Map(), ended = new Map(), stray = new Map();
const outbox = [], received = [], asks = [], history = [];
const autoAccept = new Set(), reserved = new Set();
let lastSeq = 0, online = null, offWhy = '';
const hooks = { change() {}, peers() {}, toast() {}, ask() {}, offer() {}, received() {}, done() {} };
const shareUrl = () => (SHARE || SERVER).replace(/#.*$/, '') + (room ? '#' + room : '');
const statusText = () => online === null ? 'connecting…' : online === false ? offWhy || 'offline · retrying…'
  : (room ? 'room ' + pretty(room) : 'this network') + ' · ' + (peers.size ? plural(peers.size, 'device') : 'no devices yet');

/* ---------- relay ---------- */
async function api(body, ms = 10000) {
  let res, d = null;
  try {
    res = await fetch(SERVER, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(ms) });
  } catch (e) { const err = new Error(e && e.name === 'TimeoutError' ? 'timed out' : 'unreachable'); err.status = 0; throw err; }
  try { d = await res.json(); } catch {}
  if (!d) { const e = new Error('not a localdrop relay (http ' + res.status + ')'); e.status = res.status || 1; throw e; }
  if (!res.ok || d.ok !== true) { const e = new Error(d.error || 'http ' + res.status); e.status = res.status; throw e; }
  return d;
}
function setOnline(ok, why) { online = ok; offWhy = ok ? '' : why || ''; hooks.change(); }

let polling = false, again = false, pollT = 0, fails = 0, stopped = true;
const busy = () => outbox.length > 0 || [...conns.values()].some((c) => !c.dead && (c.state === 'connecting' || (c.state === 'asking' && c.role === 'send')));
function schedule(ms) {
  clearTimeout(pollT);
  if (stopped) return;
  if (ms == null) ms = busy() ? 400 : 2000;
  if (fails) ms = Math.max(ms, Math.min(15000, 1000 * 2 ** Math.min(fails - 1, 4)));
  pollT = setTimeout(poll, ms);
}
function pollNow() { if (polling) again = true; else schedule(0); }
function kick() { if (!polling) schedule(); }

async function poll() {
  clearTimeout(pollT);
  if (polling || stopped) return;
  polling = true;
  const asked = room;
  try {
    const r = await api({ a: 'poll', s: me.secret, room, name: me.name, kind: me.kind, os: me.os, bg: false, ack: lastSeq });
    if (asked !== room) return;
    fails = 0;
    setOnline(true);
    reconcile(Array.isArray(r.peers) ? r.peers : []);
    for (const m of Array.isArray(r.msgs) ? r.msgs : []) {
      if (!m || typeof m.q !== 'number' || m.q <= lastSeq) continue;
      lastSeq = m.q;
      try { onSignal(String(m.f || ''), m.d); } catch (e) { debug(e); }
    }
  } catch (e) {
    fails++;
    setOnline(false, e.status === 429 ? (e.message === 'room is full' ? 'this room is full' : 'too many requests · slowing down')
      : e.status >= 500 ? 'server error: ' + e.message : e.status === 0 ? 'relay ' + e.message + ' · retrying…' : e.message);
  } finally {
    polling = false;
    const a = again;
    again = false;
    schedule(a ? 0 : undefined);
    const t = Date.now();
    for (const [k, v] of ended) if (t - v > 180000) ended.delete(k);
    for (const [k, v] of stray) if (t - v.t > 30000) stray.delete(k);
  }
}

let flushing = false, flushT = 0, flushFails = 0;
function signal(to, d) { outbox.push({ to, d, room }); if (!flushT && !flushing) flushT = setTimeout(flush, 25); }
const keep = (m) => m.room === room && (m.d.k === 'cancel' || m.d.k === 'decline' || (conns.has(m.d.c) && !conns.get(m.d.c).dead));
async function flush() {
  clearTimeout(flushT);
  flushT = 0;
  if (flushing) return;
  while (outbox.length && outbox[0].room !== room) outbox.shift();
  if (!outbox.length) return;
  flushing = true;
  const r0 = room, batch = [];
  while (batch.length < 24 && outbox.length && outbox[0].room === r0) batch.push(outbox.shift());
  let wait = 0;
  try {
    const r = await api({ a: 'send', s: me.secret, room: r0, msgs: batch.map((m) => ({ to: m.to, d: m.d })) });
    flushFails = 0;
    const res = Array.isArray(r.res) ? r.res : [];
    batch.forEach((m, i) => { if (res[i] !== 1) undelivered(m, res[i]); });
  } catch (e) {
    if (e.status === 400) batch.forEach((m) => undelivered(m, -1));
    else {
      if (e.status === 409) pollNow();
      flushFails++;
      wait = Math.min(8000, 300 * 2 ** Math.min(flushFails, 5));
      outbox.unshift(...batch.filter(keep));
    }
  } finally {
    flushing = false;
    if (outbox.length && !flushT) flushT = setTimeout(flush, wait);
  }
}
function undelivered(m, code) {
  const c = conns.get(m.d.c);
  if (c && !c.dead && m.d.k !== 'cancel' && m.d.k !== 'decline') fail(c, code === 0 ? c.peerName + ' went offline' : "couldn't reach " + c.peerName, false);
}

function onSignal(from, d) {
  if (!d || typeof d !== 'object' || typeof d.c !== 'string' || !ID_RE.test(from)) return;
  if (d.k === 'offer') return void onOffer(from, d);
  const c = conns.get(d.c);
  if (!c || c.peer !== from) {
    if (d.k === 'ice' && Array.isArray(d.list) && !ended.has(d.c) && stray.size < 64) {
      const s = stray.get(d.c) || { t: Date.now(), from, list: [] };
      if (s.from === from && s.list.length < 64) { s.list.push(...d.list.slice(0, 32)); stray.set(d.c, s); }
    }
    return;
  }
  if (d.k === 'answer') onAnswer(c, d);
  else if (d.k === 'ice') addIce(c, Array.isArray(d.list) ? d.list : []);
  else if (d.k === 'decline') fail(c, c.peerName + (d.why === 'busy' ? ' is busy, try again shortly' : d.why === 'expired' ? " didn't answer" : ' declined'), false);
  else if (d.k === 'cancel') fail(c, c.peerName + ' cancelled', false);
}

function reconcile(list) {
  const seen = new Set();
  let changed = false;
  for (const p of list) {
    if (!p || typeof p.id !== 'string' || !ID_RE.test(p.id) || seen.has(p.id)) continue;
    seen.add(p.id);
    const name = cleanName(p.name) || 'device', kind = KINDS.includes(p.kind) ? p.kind : 'computer';
    const os = OSES.includes(p.os) ? p.os : '', bg = p.bg === true, peer = peers.get(p.id);
    if (!peer) { peers.set(p.id, { id: p.id, name, kind, os, bg, flash: null, since: Date.now() }); changed = true; }
    else if (name !== peer.name || kind !== peer.kind || os !== peer.os || bg !== peer.bg) { Object.assign(peer, { name, kind, os, bg }); changed = true; }
  }
  for (const id of peers.keys()) if (!seen.has(id)) { peers.delete(id); changed = true; }
  const t = Date.now();
  for (const c of conns.values()) {
    if (c.dead || (c.state !== 'asking' && c.state !== 'connecting')) continue;
    if (seen.has(c.peer)) c.goneAt = 0;
    else if (!c.goneAt) c.goneAt = t;
    else if (t - c.goneAt > 6000) fail(c, c.peerName + ' went offline', false);
  }
  if (changed) hooks.peers();
  hooks.change();
}

/* ---------- connections ---------- */
const amt = (c) => { try { return c.ch ? c.ch.bufferedAmount() : 0; } catch { return 0; } };
function makeConn(id, peer, role) {
  const p = peers.get(peer);
  const c = {
    id, peer, role, pc: null, ch: null, peerName: p ? p.name : 'the other device', peerKind: p ? p.kind : 'computer', state: 'new', dead: false,
    opened: false, remoteSet: false, sigReady: false, offered: false, iceOut: [], iceIn: [], iceT: 0, timer: 0, discT: 0, goneAt: 0, askEnd: 0,
    what: null, files: null, isText: false, manifest: null, offer: null, label: '', total: 0, count: 0, sent: 0, done: 0, rx: null, got: [],
    announced: 0, file: '', t: Date.now(), t0: 0, endAt: 0, rate: 0, mark: null, error: '', route: '', drain: null,
  };
  conns.set(id, c);
  return c;
}
function openPc(c) {
  const pc = (c.pc = new RTC.PeerConnection('localdrop', { iceServers: ICE }));
  pc.onLocalDescription((sdp, type) => { if (!c.dead) onLocalDesc(c, sdp, String(type).toLowerCase()); });
  pc.onLocalCandidate((cand, mid) => {
    if (c.dead || !cand) return;
    c.iceOut.push({ candidate: cand.replace(/^a=/, ''), sdpMid: mid || '0', sdpMLineIndex: 0 });
    if (c.sigReady && !c.iceT) c.iceT = setTimeout(() => flushIce(c), 60);
  });
  pc.onStateChange((s) => {
    if (c.dead) return;
    if (s === 'connected') { clearTimeout(c.discT); c.discT = 0; }
    else if (s === 'disconnected' && !c.discT) c.discT = setTimeout(() => fail(c, 'lost the connection to ' + c.peerName), 8000);
    else if (s === 'failed') fail(c, c.state === 'connecting' ? NO_ROUTE : 'lost the connection to ' + c.peerName);
  });
  return pc;
}
function onLocalDesc(c, sdp, type) {
  if (c.offered) return;
  if (c.role === 'send' && type === 'offer') {
    c.offered = true;
    clearTimeout(c.timer);
    signal(c.peer, { k: 'offer', c: c.id, sdp, m: { n: c.count, b: c.total, name: c.isText ? '' : cut(c.files[0].name, 120), text: c.isText } });
    ready(c);
    c.timer = setTimeout(() => fail(c, c.peerName + " didn't answer"), ASK_MS);
    kick();
  } else if (c.role === 'recv' && type === 'answer') {
    c.offered = true;
    signal(c.peer, { k: 'answer', c: c.id, sdp });
    ready(c);
    kick();
  }
}
function flushIce(c) { c.iceT = 0; while (c.iceOut.length && !c.dead) signal(c.peer, { k: 'ice', c: c.id, list: c.iceOut.splice(0, 16) }); }
function ready(c) { c.sigReady = true; if (c.iceOut.length) flushIce(c); }
function addIce(c, list) {
  for (const x of list.slice(0, 32)) {
    if (!x || typeof x.candidate !== 'string' || !x.candidate) continue;
    if (!c.remoteSet) { if (c.iceIn.length < 64) c.iceIn.push(x); continue; }
    try { c.pc.addRemoteCandidate(x.candidate, typeof x.sdpMid === 'string' ? x.sdpMid : '0'); } catch (e) { debug('ice', e.message); }
  }
}
function gotRemote(c) { c.remoteSet = true; for (const x of c.iceIn.splice(0)) addIce(c, [x]); }

async function collect(paths) {
  const files = [], skip = new Set(['.DS_Store', 'Thumbs.db', 'desktop.ini']);
  const walk = async (abs, rel, depth) => {
    const st = await fsp.stat(abs);
    if (st.isFile()) return void files.push({ path: abs, name: rel, size: st.size });
    if (!st.isDirectory() || depth > 24) return;
    const ents = (await fsp.readdir(abs, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name));
    for (const e of ents) {
      if (files.length > MAX_FILES) return;
      if (!skip.has(e.name) && (e.isFile() || e.isDirectory())) await walk(path.join(abs, e.name), rel + '/' + e.name, depth + 1).catch(() => {});
    }
  };
  for (const p of paths) { const abs = expand(p); await walk(abs, path.basename(abs), 0); }
  return files;
}

async function startSend(peerId, what) {
  const peer = peers.get(peerId);
  if (!peer) return void hooks.toast('that device is gone', true);
  const isText = typeof what.text === 'string';
  let files;
  if (isText) { const buf = Buffer.from(cut(what.text, TEXT_MAX)); files = [{ buf, name: 'note.txt', size: buf.length }]; }
  else {
    try { files = what.files || (what.files = await collect(what.paths || [])); }
    catch (e) { return void hooks.toast("couldn't read " + (e.path ? tilde(e.path) : 'those files'), true); }
  }
  if (!files.length || (isText && !what.text.trim())) return void hooks.toast(isText ? 'write something first' : 'nothing to send: the folder is empty', true);
  if (files.length > MAX_FILES) return void hooks.toast('too many files at once (10,000 max). zip them first.', true);
  if (peer.bg) hooks.toast(peer.name + ' is in the background, so it may take a moment to answer');
  await engine();
  const c = makeConn(hex(12), peerId, 'send');
  const folder = !isText && what.paths && what.paths.length === 1 && isDir(expand(what.paths[0]));
  Object.assign(c, {
    what, files, isText, count: files.length, total: files.reduce((a, f) => a + f.size, 0), state: 'asking',
    label: isText ? 'a note' : folder ? path.basename(expand(what.paths[0])) + '/ · ' + plural(files.length, 'file') : files.length === 1 ? path.basename(files[0].name) : plural(files.length, 'file'),
  });
  hooks.change();
  try {
    openPc(c);
    channel(c, c.pc.createDataChannel('localdrop'));
    c.timer = setTimeout(() => fail(c, "couldn't start the connection"), 10000);
  } catch (e) { debug(e); fail(c, "couldn't start the connection", false); }
  return c;
}

function onOffer(from, d) {
  if (conns.has(d.c) || ended.has(d.c) || typeof d.sdp !== 'string') return;
  const m = d.m && typeof d.m === 'object' ? d.m : {};
  if (!Number.isSafeInteger(m.n) || m.n < 1 || m.n > MAX_FILES || !Number.isSafeInteger(m.b) || m.b < 0) return;
  if (asks.length >= 5 || !RTC) return signal(from, { k: 'decline', c: d.c, why: 'busy' });
  const c = makeConn(d.c, from, 'recv'), text = m.text === true;
  c.manifest = { n: m.n, b: m.b, text, name: safeName(m.name) };
  c.offer = d.sdp;
  Object.assign(c, { count: m.n, total: m.b, state: 'asking', askEnd: Date.now() + ASK_MS - 5000, label: text ? 'a note' : m.n === 1 ? c.manifest.name : plural(m.n, 'file') });
  const s = stray.get(d.c);
  if (s) { stray.delete(d.c); if (s.from === from) addIce(c, s.list); }
  c.timer = setTimeout(() => {
    if (c.state !== 'asking') return;
    signal(c.peer, { k: 'decline', c: c.id, why: 'expired' });
    fail(c, 'request from ' + c.peerName + ' expired', false);
  }, ASK_MS - 5000);
  const v = autoAccept.has(from) ? 'accept' : hooks.offer(c);
  if (v === 'accept') accept(c);
  else if (v === 'decline') decline(c);
  else { asks.push(c); hooks.ask(c); }
  hooks.change();
}
function accept(c) {
  if (c.dead || c.state !== 'asking') return;
  clearTimeout(c.timer);
  c.state = 'connecting';
  dropRequest(c);
  hooks.change();
  try {
    openPc(c);
    c.pc.onDataChannel((ch) => { if (!c.dead && !c.ch) channel(c, ch); });
    c.pc.setRemoteDescription(c.offer, 'offer');
    gotRemote(c);
    c.timer = setTimeout(() => fail(c, NO_ROUTE), CONNECT_MS);
    kick();
  } catch (e) { debug(e); signal(c.peer, { k: 'decline', c: c.id }); fail(c, 'bad request from ' + c.peerName, false); }
}
function decline(c) { if (c.dead || c.state !== 'asking') return; signal(c.peer, { k: 'decline', c: c.id }); fail(c, '', false); }
function dropRequest(c) { const i = asks.indexOf(c); if (i >= 0) { asks.splice(i, 1); hooks.change(); } }
function onAnswer(c, d) {
  if (c.role !== 'send' || c.state !== 'asking' || typeof d.sdp !== 'string') return;
  clearTimeout(c.timer);
  c.state = 'connecting';
  hooks.change();
  try { c.pc.setRemoteDescription(d.sdp, 'answer'); gotRemote(c); c.timer = setTimeout(() => fail(c, NO_ROUTE), CONNECT_MS); }
  catch (e) { debug(e); fail(c, 'handshake with ' + c.peerName + ' failed'); }
}

function channel(c, ch) {
  c.ch = ch;
  try { ch.setBufferedAmountLowThreshold(LOW); } catch {}
  ch.onBufferedAmountLow(() => { const d = c.drain; c.drain = null; if (d) d(); });
  const open = () => {
    if (c.dead || c.opened) return;
    c.opened = true;
    clearTimeout(c.timer);
    c.state = 'transfer';
    c.t0 = now();
    c.mark = { t: c.t0, b: 0 };
    try {
      const p = c.pc.getSelectedCandidatePair();
      if (p) c.route = p.remote.type === 'relay' || p.local.type === 'relay' ? 'relayed' : privateIp(p.remote.address) ? 'lan' : 'direct';
    } catch {}
    hooks.change();
    if (c.role === 'send') pump(c).catch((e) => fail(c, e && e.message === 'read' ? "couldn't read " + (c.file || 'a file') : 'transfer failed'));
  };
  ch.onOpen(open);
  ch.onMessage((msg) => { if (!c.dead) (c.role === 'send' ? fromReceiver : fromSender)(c, msg); });
  ch.onClosed(() => { if (!c.dead) fail(c, 'connection to ' + c.peerName + ' closed', false); });
  ch.onError((e) => debug('channel', e));
  if (ch.isOpen()) setImmediate(open);
}

async function pump(c) {
  const ch = c.ch, size = Math.min(65536, ch.maxMessageSize() || 16384);
  for (const f of c.files) {
    if (c.dead) return;
    c.file = c.isText ? 'note' : path.basename(f.name);
    ch.sendMessage(JSON.stringify({ t: 'file', name: cut(f.name, 200), size: f.size, mime: mimeOf(f.name) }));
    if (f.buf) { await sendBuf(c, f.buf, size); continue; }
    let fh;
    try { fh = await fsp.open(f.path, 'r'); } catch { throw new Error('read'); }
    try {
      for (let off = 0; off < f.size;) {
        const want = Math.min(READ, f.size - off), buf = Buffer.allocUnsafe(want);
        let n = 0;
        try { n = (await fh.read(buf, 0, want, off)).bytesRead; } catch { throw new Error('read'); }
        if (!n) throw new Error('read');
        await sendBuf(c, n < want ? buf.subarray(0, n) : buf, size);
        if (c.dead) return;
        off += n;
      }
    } finally { await fh.close().catch(() => {}); }
  }
  if (c.dead) return;
  ch.sendMessage(JSON.stringify({ t: 'end' }));
  c.state = 'finishing';
  hooks.change();
  let deadline = now() + BYE_MS;
  const iv = setInterval(() => {
    if (c.dead || c.state !== 'finishing') return clearInterval(iv);
    if (amt(c) > 0) deadline = now() + BYE_MS;
    else if (now() > deadline) { clearInterval(iv); fail(c, c.peerName + ' never confirmed the transfer'); }
  }, 500);
}
async function sendBuf(c, buf, size) {
  for (let p = 0; p < buf.length; p += size) {
    if (amt(c) > HIGH) await drained(c);
    if (c.dead) return;
    const n = Math.min(size, buf.length - p);
    c.ch.sendMessageBinary(buf.subarray(p, p + n));
    c.sent += n;
  }
}
function drained(c) {
  return new Promise((res) => {
    const done = () => { clearInterval(iv); if (c.drain === done) c.drain = null; res(); };
    const iv = setInterval(() => { if (c.dead || !c.ch || amt(c) <= LOW) done(); }, 200);
    c.drain = done;
  });
}
function fromReceiver(c, data) {
  if (typeof data !== 'string') return;
  let m;
  try { m = JSON.parse(data); } catch { return; }
  if (m.t === 'bye' && c.state === 'finishing') finish(c);
  else if (m.t === 'cancel') fail(c, c.peerName + ' cancelled', false);
}

function fromSender(c, data) {
  if (typeof data === 'string') {
    let m;
    try { m = JSON.parse(data); } catch { return fail(c, 'garbled data from ' + c.peerName); }
    if (m.t === 'file') rxBegin(c, m);
    else if (m.t === 'end') rxEnd(c);
    else if (m.t === 'cancel') fail(c, c.peerName + ' cancelled', false);
    return;
  }
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data), rx = c.rx;
  if (!rx || rx.got + buf.length > rx.size) return fail(c, c.peerName + ' sent more than it announced');
  try {
    if (rx.mem) rx.mem.push(buf);
    else for (let o = 0; o < buf.length;) o += fs.writeSync(rx.fd, buf, o, buf.length - o);
  } catch (e) { return fail(c, "couldn't write " + rx.name + ' (' + (e.code || e.message) + ')'); }
  rx.got += buf.length;
  c.done += buf.length;
  if (rx.got === rx.size) rxFile(c);
}
const nextFree = new Map();
function uniquePath(p) {
  const ext = path.extname(p), base = p.slice(0, p.length - ext.length);
  for (let i = nextFree.get(p) || 0; ; i++) {
    const q = i ? `${base} (${i})${ext}` : p;
    if (!reserved.has(q) && !fs.existsSync(q) && !fs.existsSync(q + '.part')) { nextFree.set(p, i); return q; }
  }
}
function rxBegin(c, m) {
  const M = c.manifest;
  if (c.rx || c.got.length >= M.n || !Number.isSafeInteger(m.size) || m.size < 0 || c.announced + m.size > M.b) {
    return fail(c, c.peerName + " sent something it didn't announce");
  }
  c.announced += m.size;
  const rel = M.text ? 'note.txt' : safeRel(m.name);
  const rx = (c.rx = { name: path.basename(rel), rel, size: m.size, mime: safeMime(m.mime), got: 0, fd: null, tmp: '', final: '', mem: null });
  c.file = M.text ? 'note' : rx.name;
  if (M.text && M.n === 1 && m.size <= NOTE_MAX) rx.mem = [];
  else {
    try {
      rx.final = uniquePath(path.join(OUT, rel));
      reserved.add(rx.final);
      fs.mkdirSync(path.dirname(rx.final), { recursive: true });
      rx.tmp = rx.final + '.part';
      rx.fd = fs.openSync(rx.tmp, 'wx');
    } catch (e) { return fail(c, "couldn't save " + rx.name + ' (' + (e.code || e.message) + ')'); }
  }
  if (!m.size) rxFile(c);
}
function rxFile(c) {
  const rx = c.rx;
  c.rx = null;
  const item = { name: rx.name, path: '', size: rx.size, mime: rx.mime, from: c.peerName, t: Date.now(), text: null };
  if (rx.mem) item.text = Buffer.concat(rx.mem).toString('utf8');
  else {
    try { fs.closeSync(rx.fd); } catch {}
    let dest = rx.final;
    try {
      if (fs.existsSync(dest)) { reserved.delete(rx.final); dest = uniquePath(rx.final); }
      fs.renameSync(rx.tmp, dest);
    } catch { dest = rx.tmp; }
    reserved.delete(rx.final);
    markDownloaded(dest);
    item.path = dest;
    item.name = path.basename(dest);
  }
  c.got.push(item);
  received.push(item);
  hooks.received(item, c);
  hooks.change();
}
function markDownloaded(p) {
  try {
    if (process.platform === 'darwin') spawn('xattr', ['-w', 'com.apple.quarantine', '0081;' + Math.floor(Date.now() / 1000).toString(16) + ';localdrop;', p], { stdio: 'ignore' }).on('error', () => {});
    else if (WIN) fs.writeFileSync(p + ':Zone.Identifier', '[ZoneTransfer]\r\nZoneId=3\r\n');
  } catch {}
}
function rxEnd(c) {
  if (c.rx || c.got.length !== c.manifest.n || c.done !== c.manifest.b) return fail(c, 'the transfer from ' + c.peerName + ' was incomplete');
  try { c.ch.sendMessage(JSON.stringify({ t: 'bye' })); } catch {}
  finish(c);
}

function stop(c) { clearTimeout(c.timer); clearTimeout(c.discT); clearTimeout(c.iceT); c.timer = c.discT = c.iceT = 0; }
function flashPeer(id, ok, text) { const p = peers.get(id); if (p) p.flash = { ok, text, until: Date.now() + 4000 }; }
function finish(c) {
  if (c.dead) return;
  c.dead = true;
  c.state = 'finished';
  c.endAt = now();
  stop(c);
  flashPeer(c.peer, true, c.role === 'send' ? 'sent' : 'received');
  if (c.role === 'send') history.push(c);
  hooks.done(c);
  hooks.change();
  setTimeout(() => teardown(c), c.role === 'send' ? 300 : 3000);
}
function fail(c, msg, notify = true) {
  if (c.dead) return;
  const was = c.state;
  c.dead = true;
  c.state = 'failed';
  c.error = msg;
  c.endAt = now();
  stop(c);
  for (let i = outbox.length - 1; i >= 0; i--) if (outbox[i].d.c === c.id && !keep(outbox[i])) outbox.splice(i, 1);
  if (notify && was !== 'new') {
    try { if (c.ch && c.ch.isOpen()) c.ch.sendMessage(JSON.stringify({ t: 'cancel' })); } catch {}
    signal(c.peer, { k: 'cancel', c: c.id });
  }
  if (c.rx) {
    if (c.rx.fd != null) { try { fs.closeSync(c.rx.fd); } catch {} try { fs.unlinkSync(c.rx.tmp); } catch {} }
    if (c.rx.final) reserved.delete(c.rx.final);
  }
  c.rx = null;
  dropRequest(c);
  if (msg) { flashPeer(c.peer, false, msg === 'cancelled' ? 'cancelled' : 'failed'); history.push(c); }
  hooks.done(c);
  hooks.change();
  setTimeout(() => teardown(c), notify && c.opened ? 2500 : 400);
}
function teardown(c) {
  stop(c);
  try { if (c.ch) c.ch.close(); } catch {}
  try { if (c.pc) c.pc.close(); } catch {}
  c.ch = c.pc = c.files = null;
  if (conns.get(c.id) === c) conns.delete(c.id);
  ended.set(c.id, Date.now());
}
function bytesOf(c) {
  if (c.role === 'recv') return c.done;
  if (c.state === 'finished' || c.state === 'finishing') return c.total;
  return c.state === 'transfer' ? Math.max(0, c.sent - amt(c)) : 0;
}
function tickRates() {
  const t = now();
  for (const c of conns.values()) {
    if (c.dead || (c.state !== 'transfer' && c.state !== 'finishing') || !c.mark || t - c.mark.t < 1000) continue;
    const b = bytesOf(c), r = (b - c.mark.b) * 1000 / (t - c.mark.t);
    c.rate = c.rate ? c.rate * 0.6 + r * 0.4 : r;
    c.mark = { t, b };
  }
}
const active = () => [...conns.values()].filter((c) => !c.dead && (c.state === 'transfer' || c.state === 'finishing'));

function leave() { return SERVER ? api({ a: 'leave', s: me.secret, room }, 1500).catch(() => {}) : Promise.resolve(); }
function setRoom(code) {
  if (code === room) return;
  leave();
  for (const c of conns.values()) if (!c.dead && (c.state === 'asking' || c.state === 'connecting')) fail(c, 'switched rooms');
  room = code;
  peers.clear();
  hooks.peers();
  hooks.change();
  pollNow();
}
function startCore() { stopped = false; poll(); }
async function stopCore() {
  for (const c of conns.values()) if (!c.dead) c.state === 'asking' && c.role === 'recv' ? decline(c) : fail(c, 'cancelled');
  stopped = true;
  clearTimeout(pollT);
  await Promise.race([Promise.all([flush(), leave()]), sleep(1500)]);
  for (const c of [...conns.values()]) teardown(c);
  try { if (RTC) RTC.cleanup(); } catch {}
}

/* ---------- built-in relay: a port of index.php's api, plus its web page ---------- */
const PEER_TTL = 10, AWAY_TTL = 75, MAX_PEERS = 24, MAX_MSG = 16384, MAX_QUEUE = 131072, MAX_BATCH = 32, MAX_BODY = 262144, RATE_10S = 2000, GC_AFTER = 900;

function lanIps() {
  const out = [];
  for (const [name, list] of Object.entries(os.networkInterfaces())) {
    for (const a of list || []) {
      if ((a.family !== 'IPv4' && a.family !== 4) || a.internal) continue;
      let score = privateIp(a.address) ? 2 : 1;
      if (/^(en|eth|wl|wlan|wi-?fi)/i.test(name)) score += 2;
      if (/^(docker|br-|veth|virbr|vmnet|vboxnet|utun|tun|tap|zt|tailscale|wg)/i.test(name)) score -= 3;
      out.push({ ip: a.address, score });
    }
  }
  return out.sort((a, b) => b.score - a.score).map((x) => x.ip);
}
function netKey(ip, hostIp) {
  ip = String(ip || '').replace(/^::ffff:/i, '').replace(/%.*$/, '');
  if (ip === '::1' || /^127\./.test(ip)) ip = hostIp || '127.0.0.1';
  const v4 = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip);
  if (v4) {
    const o = v4.slice(1).map(Number);
    const lan = o[0] === 10 || o[0] === 127 || (o[0] === 172 && o[1] >= 16 && o[1] <= 31) || (o[0] === 192 && o[1] === 168) || (o[0] === 169 && o[1] === 254);
    return lan ? 'lan|' + o.slice(0, 3).join('.') : 'v4|' + ip;
  }
  if (ip.includes(':')) {
    const [head, tail] = ip.split('::'), h = head ? head.split(':') : [], t = tail === undefined ? null : tail ? tail.split(':') : [];
    const g = t === null ? h : [...h, ...Array(Math.max(0, 8 - h.length - t.length)).fill('0'), ...t];
    return 'v6|' + g.slice(0, 4).map((x) => x.padStart(4, '0')).join(':');
  }
  return 'x|' + ip;
}
const tooDeep = (v, d = 0) => d > 16 || (!!v && typeof v === 'object' && Object.values(v).some((x) => tooDeep(x, d + 1)));
function validSignal(d) {
  if (!d || typeof d !== 'object' || Array.isArray(d) || typeof d.c !== 'string' || !/^[a-f0-9]{16,32}$/.test(d.c)) return false;
  if (d.k === 'offer') return typeof d.sdp === 'string' && !!d.m && typeof d.m === 'object';
  if (d.k === 'answer') return typeof d.sdp === 'string';
  if (d.k === 'ice') return Array.isArray(d.list) && d.list.length <= 32;
  return d.k === 'cancel' || d.k === 'decline';
}

const pageFrom = (src) => { const i = String(src || '').indexOf('?><!DOCTYPE html>'); return i >= 0 ? src.slice(i + 2) : null; };
async function webPage(web) {
  const guess = path.join(path.dirname(SELF), 'index.php');
  if (!web && fs.existsSync(guess)) web = guess;
  if (web) { try { return { page: pageFrom(fs.readFileSync(web, 'utf8')), from: tilde(web) }; } catch { return { page: null, from: tilde(web) }; } }
  const sea = await seaApi();
  try { if (sea) return { page: pageFrom(sea.getAsset('index.php', 'utf8')), from: 'built in' }; } catch {}
  return { page: null, from: '' };
}
function createRelay({ page, hostIp }) {
  const key = crypto.randomBytes(32), rooms = new Map();
  const hmac = (s) => crypto.createHmac('sha256', key).update(s).digest('hex');
  const E = (code, error) => [code, { ok: false, error }];

  function rpoll(st, me, inp, t) {
    let ack = inp.ack ?? 0;
    ack = Number.isInteger(ack) && ack > 0 && ack < Number.MAX_SAFE_INTEGER - 1e6 ? ack : 0;
    let p = st.p.get(me);
    if (!p) {
      if (st.p.size >= MAX_PEERS) return E(429, 'room is full');
      p = { q: [], qb: 0, seq: ack + 1 };
    } else {
      if (ack > 0 && p.q.length) p.q = p.q.filter((m) => m.q > ack);
      p.qb = p.q.reduce((a, m) => a + m.z, 0);
      if (p.seq <= ack) p.seq = ack + 1;
    }
    Object.assign(p, { name: cleanName(inp.name) || 'device', kind: KINDS.includes(inp.kind) ? inp.kind : 'computer', os: OSES.includes(inp.os) ? inp.os : '', bg: inp.bg === true, seen: t });
    st.p.set(me, p);
    const list = [];
    for (const [id, o] of st.p) if (id !== me) list.push({ id, name: o.name, kind: o.kind, os: o.os, bg: o.bg });
    return [200, { ok: true, peers: list, msgs: p.q.map((m) => ({ q: m.q, f: m.f, d: m.d })) }];
  }
  function rsend(st, me, inp, t) {
    const self = st.p.get(me);
    if (!self) return E(409, 'not registered');
    self.seen = t;
    const list = inp.msgs;
    if (!Array.isArray(list) || !list.length || list.length > MAX_BATCH) return E(400, 'bad batch');
    const res = [];
    for (const m of list) {
      const to = m && m.to, d = m && m.d;
      if (typeof to !== 'string' || !/^p[a-f0-9]{15}$/.test(to) || !validSignal(d)) { res.push(-1); continue; }
      const tp = st.p.get(to);
      if (to === me || !tp) { res.push(0); continue; }
      let z;
      try { z = Buffer.byteLength(JSON.stringify(d)); } catch { res.push(-1); continue; }
      if (z > MAX_MSG || tp.qb + z > MAX_QUEUE) { res.push(-1); continue; }
      tp.q.push({ q: tp.seq++, f: me, d, z });
      tp.qb += z;
      res.push(1);
    }
    return [200, { ok: true, res }];
  }
  function handle(ip, inp) {
    if (!inp || typeof inp !== 'object' || Array.isArray(inp) || tooDeep(inp)) return E(400, 'invalid json');
    if (typeof inp.s !== 'string' || !/^[A-Za-z0-9_-]{32,128}$/.test(inp.s)) return E(400, 'bad session');
    const code = inp.room ?? '';
    if (typeof code !== 'string' || (code !== '' && !/^[a-z0-9]{6,32}$/.test(code))) return E(400, 'bad room code');
    const me = 'p' + hmac('peer|' + inp.s).slice(0, 15), rk = hmac(code ? 'code|' + code : 'net|' + netKey(ip, hostIp)).slice(0, 24);
    const t = Date.now() / 1000, win = Math.floor(t / 10);
    let st = rooms.get(rk);
    if (!st) {
      if (rooms.size >= 5000) { for (const [k, r] of rooms) if (t - r.at > 60 && !r.p.size) rooms.delete(k); if (rooms.size >= 5000) return E(503, 'relay is busy'); }
      rooms.set(rk, (st = { p: new Map(), w: win, c: 0, at: t }));
    }
    if (st.w !== win) { st.w = win; st.c = 0; }
    st.at = t;
    if (++st.c > RATE_10S) return E(429, 'too many requests');
    for (const [id, p] of st.p) if (t - p.seen > (p.bg ? AWAY_TTL : PEER_TTL)) st.p.delete(id);
    const out = inp.a === 'poll' ? rpoll(st, me, inp, t) : inp.a === 'send' ? rsend(st, me, inp, t)
      : inp.a === 'leave' ? (st.p.delete(me), [200, { ok: true }]) : E(400, 'unknown action');
    if (Math.random() < 0.02) for (const [k, r] of rooms) if (t - r.at > GC_AFTER) rooms.delete(k);
    return out;
  }

  const server = http.createServer(async (req, res) => {
    const json = (code, body) => {
      let out;
      try { out = JSON.stringify(body); } catch { code = 500; out = '{"ok":false,"error":"server error"}'; }
      res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
      res.end(out);
    };
    try {
      if (req.method === 'POST') {
        const site = req.headers['sec-fetch-site'];
        if (site && site !== 'same-origin') return json(403, { ok: false, error: 'forbidden' });
        const chunks = [];
        let size = 0;
        for await (const ch of req) { size += ch.length; if (size > MAX_BODY) return json(413, { ok: false, error: 'request too large' }); chunks.push(ch); }
        let inp = null;
        try { inp = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch {}
        const [code, body] = handle(req.socket.remoteAddress, inp);
        return json(code, body);
      }
      if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405, { Allow: 'GET, HEAD, POST' }); return res.end(); }
      const p = new URL(req.url, 'http://x').pathname;
      if (p === '/favicon.ico') { res.writeHead(204); return res.end(); }
      if (p !== '/' && p !== '/index.php') { res.writeHead(404, { 'Content-Type': 'text/plain' }); return res.end('not found\n'); }
      if (!page) {
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
        return res.end('localdrop relay is running.\nthe web page (index.php) was not found next to localdrop, so only terminals can join.\nstart it with --web /path/to/index.php to serve the page too.\n');
      }
      const nonce = crypto.randomBytes(18).toString('base64'), stun = ICE.filter((u) => /^stuns?:/i.test(u));
      const cfg = JSON.stringify({ ice: [{ urls: stun.length ? stun : DEFAULT_ICE }] }).replace(/[<>&']/g, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Security-Policy': `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'self' data: blob:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
        'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY',
        'Permissions-Policy': 'camera=(), microphone=(), geolocation=()', 'Cache-Control': 'no-store',
      });
      res.end(req.method === 'HEAD' ? undefined : page.replaceAll('<?= $nonce ?>', nonce).replace('<?= $cfg ?>', cfg));
    } catch (e) { debug(e); try { if (!res.headersSent) json(500, { ok: false, error: 'server error' }); else res.end(); } catch {} }
  });
  return { server, hasPage: !!page, rooms };
}
function listen(server, port, bind) {
  return new Promise((res, rej) => {
    const bad = (e) => { server.off('listening', ok); rej(e); };
    const ok = () => { server.off('error', bad); res(server.address().port); };
    server.once('error', bad);
    server.once('listening', ok);
    server.listen(port, bind);
  });
}
async function startRelay({ port = 8080, bind = '0.0.0.0', web = '' } = {}) {
  const hostIp = lanIps()[0] || '';
  const { page, from } = await webPage(web);
  const r = createRelay({ page, hostIp });
  let p;
  try { p = await listen(r.server, Number(port), bind); }
  catch (e) { if (e.code !== 'EADDRINUSE') throw e; p = await listen(r.server, 0, bind); }
  const lan = hostIp ? `http://${hostIp}:${p}/` : '';
  return { ...r, port: p, hostIp, web: from, local: `http://127.0.0.1:${p}/`, lan };
}

/* ---------- qr code (byte mode, versions 1-10, ecc M then L), ported from index.php ---------- */
const qrMatrix = (() => {
  const TAB = {
    M: [[10, 1], [16, 1], [26, 1], [18, 2], [24, 2], [16, 4], [18, 4], [22, 4], [22, 5], [26, 5]],
    L: [[7, 1], [10, 1], [15, 1], [20, 1], [26, 1], [18, 2], [20, 2], [24, 2], [30, 2], [18, 4]],
  };
  const FMT = { M: 0, L: 1 };
  const mul = (x, y) => { let z = 0; for (let i = 7; i >= 0; i--) { z = (z << 1) ^ ((z >>> 7) * 0x11d); z ^= ((y >>> i) & 1) * x; } return z; };
  const raw = (v) => { let r = (16 * v + 128) * v + 64; if (v >= 2) { const a = Math.floor(v / 7) + 2; r -= (25 * a - 10) * a - 55; if (v >= 7) r -= 36; } return r; };
  const align = (v) => {
    if (v === 1) return [];
    const a = Math.floor(v / 7) + 2, step = Math.ceil((v * 4 + 4) / (a * 2 - 2)) * 2, out = [6];
    for (let p = v * 4 + 10; out.length < a; p -= step) out.splice(1, 0, p);
    return out;
  };
  function rsDiv(deg) {
    const r = new Array(deg).fill(0);
    r[deg - 1] = 1;
    let root = 1;
    for (let i = 0; i < deg; i++) {
      for (let j = 0; j < deg; j++) { r[j] = mul(r[j], root); if (j + 1 < deg) r[j] ^= r[j + 1]; }
      root = mul(root, 2);
    }
    return r;
  }
  function rsRem(data, div) {
    const r = div.map(() => 0);
    for (const b of data) { const f = b ^ r.shift(); r.push(0); div.forEach((c, i) => { r[i] ^= mul(c, f); }); }
    return r;
  }
  function maskOn(k, x, y) {
    switch (k) {
      case 0: return (x + y) % 2 === 0;
      case 1: return y % 2 === 0;
      case 2: return x % 3 === 0;
      case 3: return (x + y) % 3 === 0;
      case 4: return (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0;
      case 5: return ((x * y) % 2) + ((x * y) % 3) === 0;
      case 6: return (((x * y) % 2) + ((x * y) % 3)) % 2 === 0;
      default: return (((x + y) % 2) + ((x * y) % 3)) % 2 === 0;
    }
  }
  function penalty(g, n) {
    let p = 0, dark = 0;
    for (let pass = 0; pass < 2; pass++) for (let a = 0; a < n; a++) {
      let run = 0, prev = null, line = '';
      for (let b = 0; b < n; b++) {
        const v = pass ? g[b][a] : g[a][b];
        line += v ? '1' : '0';
        if (v === prev) { run++; if (run === 5) p += 3; else if (run > 5) p++; } else { run = 1; prev = v; }
      }
      const s = '0000' + line + '0000';
      for (const pat of ['00001011101', '10111010000']) for (let i = s.indexOf(pat); i >= 0; i = s.indexOf(pat, i + 1)) p += 40;
    }
    for (let y = 0; y < n - 1; y++) for (let x = 0; x < n - 1; x++) {
      const v = g[y][x];
      if (v === g[y][x + 1] && v === g[y + 1][x] && v === g[y + 1][x + 1]) p += 3;
    }
    for (const row of g) for (const v of row) if (v) dark++;
    return p + Math.max(0, Math.ceil(Math.abs(dark * 20 - n * n * 10) / (n * n)) - 1) * 10;
  }
  function draw(v, lvl, cw) {
    const n = v * 4 + 17;
    const g = Array.from({ length: n }, () => new Array(n).fill(false));
    const fn = Array.from({ length: n }, () => new Array(n).fill(false));
    const set = (x, y, d) => { g[y][x] = d; fn[y][x] = true; };
    for (let i = 0; i < n; i++) { set(6, i, i % 2 === 0); set(i, 6, i % 2 === 0); }
    for (const [cx, cy] of [[3, 3], [n - 4, 3], [3, n - 4]]) {
      for (let dy = -4; dy <= 4; dy++) for (let dx = -4; dx <= 4; dx++) {
        const x = cx + dx, y = cy + dy, d = Math.max(Math.abs(dx), Math.abs(dy));
        if (x >= 0 && x < n && y >= 0 && y < n) set(x, y, d !== 2 && d !== 4);
      }
    }
    const ap = align(v), na = ap.length;
    for (let i = 0; i < na; i++) for (let j = 0; j < na; j++) {
      if ((i === 0 && j === 0) || (i === 0 && j === na - 1) || (i === na - 1 && j === 0)) continue;
      for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) set(ap[i] + dx, ap[j] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    }
    const fmt = (grid, mask) => {
      const d = (FMT[lvl] << 3) | mask;
      let r = d;
      for (let i = 0; i < 10; i++) r = (r << 1) ^ ((r >>> 9) * 0x537);
      const b = ((d << 10) | r) ^ 0x5412, bit = (i) => ((b >>> i) & 1) === 1;
      const s = (x, y, val) => { grid[y][x] = val; fn[y][x] = true; };
      for (let i = 0; i <= 5; i++) s(8, i, bit(i));
      s(8, 7, bit(6)); s(8, 8, bit(7)); s(7, 8, bit(8));
      for (let i = 9; i < 15; i++) s(14 - i, 8, bit(i));
      for (let i = 0; i < 8; i++) s(n - 1 - i, 8, bit(i));
      for (let i = 8; i < 15; i++) s(8, n - 15 + i, bit(i));
      s(8, n - 8, true);
    };
    fmt(g, 0);
    if (v >= 7) {
      let r = v;
      for (let i = 0; i < 12; i++) r = (r << 1) ^ ((r >>> 11) * 0x1f25);
      const b = (v << 12) | r;
      for (let i = 0; i < 18; i++) { const d = ((b >>> i) & 1) === 1, a = n - 11 + (i % 3), c = Math.floor(i / 3); set(a, c, d); set(c, a, d); }
    }
    let i = 0;
    for (let right = n - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (let vert = 0; vert < n; vert++) for (let j = 0; j < 2; j++) {
        const x = right - j, y = ((right + 1) & 2) === 0 ? n - 1 - vert : vert;
        if (!fn[y][x] && i < cw.length * 8) { g[y][x] = ((cw[i >>> 3] >>> (7 - (i & 7))) & 1) === 1; i++; }
      }
    }
    let best = null, bestP = Infinity;
    for (let k = 0; k < 8; k++) {
      const t = g.map((row) => row.slice());
      for (let y = 0; y < n; y++) for (let x = 0; x < n; x++) if (!fn[y][x] && maskOn(k, x, y)) t[y][x] = !t[y][x];
      fmt(t, k);
      const p = penalty(t, n);
      if (p < bestP) { bestP = p; best = t; }
    }
    return best;
  }
  function encode(text) {
    const bytes = new TextEncoder().encode(text);
    for (const lvl of ['M', 'L']) for (let v = 1; v <= 10; v++) {
      const [ecLen, nb] = TAB[lvl][v - 1], total = Math.floor(raw(v) / 8), cap = (total - ecLen * nb) * 8, cc = v < 10 ? 8 : 16;
      if (4 + cc + bytes.length * 8 > cap) continue;
      const bits = [];
      const put = (val, len) => { for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1); };
      put(4, 4);
      put(bytes.length, cc);
      for (const b of bytes) put(b, 8);
      put(0, Math.min(4, cap - bits.length));
      put(0, (8 - (bits.length % 8)) % 8);
      for (let pad = 0xec; bits.length < cap; pad ^= 0xec ^ 0x11) put(pad, 8);
      const data = [];
      for (let i = 0; i < bits.length; i += 8) { let x = 0; for (let j = 0; j < 8; j++) x = (x << 1) | bits[i + j]; data.push(x); }
      const nShort = nb - (total % nb), shortLen = Math.floor(total / nb), div = rsDiv(ecLen), blocks = [];
      for (let i = 0, k = 0; i < nb; i++) {
        const dat = data.slice(k, k + shortLen - ecLen + (i < nShort ? 0 : 1));
        k += dat.length;
        const ecc = rsRem(dat, div);
        if (i < nShort) dat.push(0);
        blocks.push(dat.concat(ecc));
      }
      const cw = [];
      for (let i = 0; i < blocks[0].length; i++) blocks.forEach((b, j) => { if (i !== shortLen - ecLen || j >= nShort) cw.push(b[i]); });
      return draw(v, lvl, cw);
    }
    return null;
  }
  const cache = new Map();
  return (text) => { if (!cache.has(text)) { let m = null; try { m = encode(text); } catch {} cache.set(text, m); } return cache.get(text); };
})();
function qrRows(text, q = 2) {
  const m = qrMatrix(text);
  if (!m) return null;
  const n = m.length, s = n + q * 2, at = (x, y) => x >= q && y >= q && x < n + q && y < n + q && m[y - q][x - q];
  const rows = [];
  for (let y = 0; y < s; y += 2) { let line = ''; for (let x = 0; x < s; x++) line += ' ▀▄█'[(at(x, y) ? 1 : 0) | (at(x, y + 1) ? 2 : 0)]; rows.push(line); }
  return rows;
}

/* ---------- terminal: text width, screen buffer, styles ---------- */
const SEG = new Intl.Segmenter();
const ZWJ = String.fromCharCode(0x200d), VS16 = String.fromCharCode(0xfe0f);
const WIDE_RE = /[ᄀ-ᅟ⌚⌛⏩-⏬⏰⏳◽◾☔☕♈-♓♿⚓⚡⚪⚫⚽⚾⛄⛅⛎⛔⛪⛲⛳⛵⛺⛽✅✊✋✨❌❎❓-❕❗➕-➗➰➿⬛⬜⭐⭕⺀-〾ぁ-㏿㐀-䶿一-鿿ꀀ-꓏가-힣豈-﫿︰-﹯＀-｠￠-￦]|[\u{1f300}-\u{1f64f}\u{1f680}-\u{1f6ff}\u{1f900}-\u{1f9ff}\u{1fa70}-\u{1faff}\u{1f1e6}-\u{1f1ff}\u{20000}-\u{3fffd}]/u;
const UNSAFE_RE = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069]/g;
const ASCII_RE = /^[\x20-\x7e]*$/;
function gw(g) {
  const cp = g.codePointAt(0);
  if (cp < 0x300) return 1;
  if (/^\p{M}+$/u.test(g)) return 0;
  return g.includes(VS16) || g.includes(ZWJ) || WIDE_RE.test(g) ? 2 : 1;
}
const graphemes = (s) => (ASCII_RE.test(s) ? s.split('') : Array.from(SEG.segment(s), (x) => x.segment));
const sw = (s) => (ASCII_RE.test(s) ? s.length : graphemes(s).reduce((a, g) => a + gw(g), 0));
function fit(s, n, ell = '…') {
  s = String(s).replace(UNSAFE_RE, '');
  if (n <= 0) return '';
  if (sw(s) <= n) return s;
  let out = '', w = 0;
  for (const g of graphemes(s)) { const k = gw(g); if (w + k > n - sw(ell)) break; out += g; w += k; }
  return out + ell;
}
const fitName = (s, n) => { if (sw(s) <= n) return s; const ext = (/\.[^.\s/]{1,10}$/.exec(s) || [''])[0]; return ext && n > ext.length + 4 ? fit(s.slice(0, -ext.length), n - ext.length) + ext : fit(s, n); };
const fitL = (s, n) => (sw(s) <= n ? s : '…' + graphemes(s).reverse().reduce((a, g) => (sw(a) + gw(g) < n ? g + a : a), ''));
const center = (s, n) => ' '.repeat(Math.max(0, (n - sw(s)) >> 1)) + s;

class Screen {
  constructor(w, h) { this.w = w; this.h = h; this.ch = new Array(w * h).fill(' '); this.st = new Uint16Array(w * h); }
  put(x, y, s, st = 0, maxX = this.w) {
    if (y < 0 || y >= this.h || s == null) return x;
    s = String(s).replace(UNSAFE_RE, '');
    maxX = Math.min(maxX, this.w);
    for (const g of graphemes(s)) {
      const k = gw(g);
      if (!k) continue;
      if (x + k > maxX) break;
      if (x >= 0) {
        const i = y * this.w + x;
        if (this.ch[i] === '' && x > 0) this.ch[i - 1] = ' ';
        if (x + k < this.w && this.ch[i + k] === '') this.ch[i + k] = ' ';
        this.ch[i] = g;
        this.st[i] = st;
        if (k === 2) { this.ch[i + 1] = ''; this.st[i + 1] = st; }
      }
      x += k;
    }
    return x;
  }
  segs(x, y, parts, maxX) { for (const [t, st] of parts) x = this.put(x, y, t, st, maxX); return x; }
  fill(x, y, w, h, st = 0, ch = ' ') {
    const x0 = Math.max(0, x), x1 = Math.min(this.w, x + w);
    for (let r = Math.max(0, y); r < Math.min(this.h, y + h); r++) {
      const o = r * this.w;
      if (x0 > 0 && this.ch[o + x0] === '') this.ch[o + x0 - 1] = ' ';
      if (x1 < this.w && this.ch[o + x1] === '') this.ch[o + x1] = ' ';
      for (let c = x0; c < x1; c++) { this.ch[o + c] = ch; this.st[o + c] = st; }
    }
  }
  restyle(st) { this.st.fill(st); }
}

const TC = /truecolor|24bit/i.test(process.env.COLORTERM || '') || !!process.env.WT_SESSION || /^(iTerm\.app|WezTerm|vscode|ghostty|Hyper)$/.test(process.env.TERM_PROGRAM || '') || /kitty|alacritty|ghostty|wezterm|foot/i.test(process.env.TERM || '');
const styles = [''], styleIds = new Map(), T = {};
function rgb(h) { const n = parseInt(h.slice(1), 16); return [n >> 16, (n >> 8) & 255, n & 255]; }
function color(c, bg) {
  if (typeof c === 'number') return String(bg ? c + 10 : c);
  const [r, g, b] = rgb(c);
  if (TC) return (bg ? '48;2;' : '38;2;') + r + ';' + g + ';' + b;
  let idx;
  if (Math.max(r, g, b) - Math.min(r, g, b) < 12) { const v = (r + g + b) / 3; idx = v < 4 ? 16 : v > 246 ? 231 : 232 + Math.round(((v - 8) / 238) * 23); }
  else idx = 16 + 36 * Math.round((r / 255) * 5) + 6 * Math.round((g / 255) * 5) + Math.round((b / 255) * 5);
  return (bg ? '48;5;' : '38;5;') + idx;
}
function sty(o) {
  const parts = [];
  if (o.b) parts.push('1');
  if (o.d) parts.push('2');
  if (o.u) parts.push('4');
  if (o.r) parts.push('7');
  if (o.fg != null) parts.push(color(o.fg, false));
  if (o.bg != null) parts.push(color(o.bg, true));
  const k = parts.join(';');
  if (!styleIds.has(k)) { styleIds.set(k, styles.length); styles.push(k); }
  return styleIds.get(k);
}
function setTheme(mode) {
  const P = {
    dark: { bright: '#ffffff', fg: '#d0d0d0', dim: '#8c8c8c', faint: '#5e5e5e', line: '#3c3c3c', err: '#ff7b72', ok: '#7ee787', bg: '#0e0e0e' },
    light: { bright: '#000000', fg: '#242424', dim: '#6a6a6a', faint: '#a0a0a0', line: '#c8c8c8', err: '#c62828', ok: '#1a7f37', bg: '#f2f2f2' },
  }[mode];
  if (P) {
    Object.assign(T, {
      bright: sty({ fg: P.bright, b: 1 }), hi: sty({ fg: P.bright }), fg: sty({ fg: P.fg }), dim: sty({ fg: P.dim }), faint: sty({ fg: P.faint }),
      line: sty({ fg: P.line }), err: sty({ fg: P.err }), ok: sty({ fg: P.ok }), inv: sty({ fg: P.bg, bg: P.bright }), invErr: sty({ fg: P.bg, bg: P.err }),
      sel: sty({ fg: P.bg, bg: P.dim }), qr: sty({ fg: '#000000', bg: '#ffffff' }),
    });
  } else if (mode === 'ansi') {
    Object.assign(T, { bright: sty({ b: 1 }), hi: sty({}), fg: sty({}), dim: sty({ fg: 90 }), faint: sty({ fg: 90, d: 1 }), line: sty({ fg: 90 }), err: sty({ fg: 31 }), ok: sty({ fg: 32 }), inv: sty({ r: 1 }), invErr: sty({ fg: 97, bg: 31 }), sel: sty({ r: 1 }), qr: sty({ fg: 30, bg: 97 }) });
  } else {
    Object.assign(T, { bright: sty({ b: 1 }), hi: sty({}), fg: sty({}), dim: sty({ d: 1 }), faint: sty({ d: 1 }), line: sty({ d: 1 }), err: sty({ b: 1 }), ok: sty({}), inv: sty({ r: 1 }), invErr: sty({ r: 1, b: 1 }), sel: sty({ r: 1 }), qr: sty({ r: 1 }) });
  }
  T.mode = mode;
}
function queryBg() {
  return new Promise((res) => {
    if (!process.stdin.isTTY || !process.stdout.isTTY || process.env.TERM === 'dumb') return res(null);
    let buf = '';
    const done = (v) => { clearTimeout(t); process.stdin.off('data', on); process.stdin.setRawMode(false); process.stdin.pause(); res(v); };
    const on = (d) => {
      buf += d.toString('latin1');
      const m = /\]11;rgb:([0-9a-f]{1,4})\/([0-9a-f]{1,4})\/([0-9a-f]{1,4})/i.exec(buf);
      if (m) done(m.slice(1).map((x) => parseInt(x, 16) / (16 ** x.length - 1)));
    };
    const t = setTimeout(() => done(null), 160);
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.on('data', on);
    process.stdout.write('\x1b]11;?\x1b\\');
  });
}
async function detectTheme(pref) {
  if (process.env.NO_COLOR) return 'mono';
  if (['dark', 'light', 'ansi', 'mono'].includes(pref)) return pref;
  const bg = await queryBg();
  if (bg) return 0.2126 * bg[0] + 0.7152 * bg[1] + 0.0722 * bg[2] < 0.5 ? 'dark' : 'light';
  const fgbg = /(\d+)$/.exec(process.env.COLORFGBG || '');
  if (fgbg) return +fgbg[1] === 7 || +fgbg[1] >= 9 ? 'light' : 'dark';
  return 'ansi';
}

/* ---------- terminal: input ---------- */
let inBuf = '', inT = 0, pasteBuf = null, altNext = false, keyHandler = () => {};
const utf8 = new StringDecoder('utf8');
function onData(d) {
  inBuf += utf8.write(d);
  clearTimeout(inT);
  drainInput(false);
  if (inBuf || pasteBuf !== null) inT = setTimeout(() => drainInput(true), pasteBuf !== null ? 1500 : 35);
}
function emitKey(k) { if (altNext) { k.alt = true; altNext = false; } try { keyHandler(k); } catch (e) { debug(e); } }
function drainInput(force) {
  while (inBuf.length || (force && pasteBuf !== null)) {
    if (pasteBuf !== null) {
      const end = inBuf.indexOf('\x1b[201~');
      if (end < 0) {
        let keep = 0;
        if (!force) for (let n = Math.min(5, inBuf.length); n > 0; n--) if ('\x1b[201~'.startsWith(inBuf.slice(-n))) { keep = n; break; }
        pasteBuf += inBuf.slice(0, inBuf.length - keep);
        inBuf = inBuf.slice(inBuf.length - keep);
        if (!force && pasteBuf.length < 8e6) return;
      } else { pasteBuf += inBuf.slice(0, end); inBuf = inBuf.slice(end + 6); }
      const text = pasteBuf;
      pasteBuf = null;
      emitKey({ name: 'paste', text });
      continue;
    }
    if (inBuf.startsWith('\x1b[200~')) { pasteBuf = ''; inBuf = inBuf.slice(6); continue; }
    const c = inBuf[0];
    if (c === '\x1b') {
      if (inBuf.length === 1) { if (!force) return; inBuf = ''; emitKey({ name: 'escape' }); continue; }
      const n = inBuf[1];
      if (n === '\x1b') { inBuf = inBuf.slice(1); altNext = true; continue; }
      if (n === '[') {
        const m = /^\x1b\[([0-9;<?:]*)([\x40-\x7e])/.exec(inBuf);
        if (!m) { if (!force && inBuf.length < 32) return; inBuf = inBuf.slice(2); emitKey({ name: 'escape' }); continue; }
        inBuf = inBuf.slice(m[0].length);
        csiKey(m[1], m[2]);
        continue;
      }
      if (n === 'O') {
        if (inBuf.length < 3 && !force) return;
        const k = inBuf[2] || '';
        inBuf = inBuf.slice(3);
        emitKey({ name: { A: 'up', B: 'down', C: 'right', D: 'left', H: 'home', F: 'end' }[k] || 'unknown' });
        continue;
      }
      if (n === ']' || n === 'P' || n === '_') {
        const m = /^\x1b[\]P_][\s\S]*?(\x07|\x1b\\)/.exec(inBuf);
        if (!m) { if (!force && inBuf.length < 512) return; inBuf = inBuf.slice(2); continue; }
        inBuf = inBuf.slice(m[0].length);
        continue;
      }
      const g = graphemes(inBuf.slice(1))[0];
      inBuf = inBuf.slice(1 + g.length);
      emitKey(g === '\x7f' ? { name: 'backspace', alt: true } : g === '\r' ? { name: 'newline' } : { name: 'char', ch: g, alt: true });
      continue;
    }
    const code = c.charCodeAt(0);
    if (code < 32 || code === 127) {
      inBuf = inBuf.slice(1);
      emitKey(code === 13 ? { name: 'enter' } : code === 10 ? { name: 'newline' } : code === 9 ? { name: 'tab' } : code === 127 || code === 8 ? { name: 'backspace' } : { name: 'ctrl', ch: String.fromCharCode(code + 96) });
      continue;
    }
    const run = /^[^\x00-\x1f\x7f\x1b]+/.exec(inBuf)[0];
    inBuf = inBuf.slice(run.length);
    if (run.length >= 8) emitKey({ name: 'paste', text: run, guessed: true });
    else for (const g of graphemes(run)) emitKey({ name: 'char', ch: g });
  }
}
function csiKey(p, f) {
  if (p.startsWith('<') && (f === 'M' || f === 'm')) {
    const [b, x, y] = p.slice(1).split(';').map(Number);
    return emitKey({ name: 'mouse', x: x - 1, y: y - 1, button: b & 3, wheel: b & 64 ? (b & 1 ? 'down' : 'up') : null, motion: !!(b & 32), release: f === 'm' });
  }
  const parts = p.split(';'), mod = parseInt(parts[1] || '1', 10) - 1, shift = !!(mod & 1);
  const name = { A: 'up', B: 'down', C: 'right', D: 'left', H: 'home', F: 'end', Z: 'backtab' }[f]
    || (f === '~' ? { 1: 'home', 7: 'home', 4: 'end', 8: 'end', 2: 'insert', 3: 'delete', 5: 'pageup', 6: 'pagedown' }[parts[0]] : null);
  if (name) emitKey({ name, shift, ctrl: !!(mod & 4), alt: !!(mod & 2) });
}

/* ---------- terminal: lifecycle ---------- */
let termOn = false, prevLines = [], frameW = 0, frameH = 0, lastTitle = '';
function enterTerm(mouse) {
  termOn = true;
  process.stdin.setRawMode(true);
  process.stdin.resume();
  process.stdin.on('data', onData);
  process.stdout.write('\x1b[22;0t\x1b[?1049h\x1b[?25l\x1b[?7l\x1b[?2004h' + (mouse ? '\x1b[?1000h\x1b[?1006h' : '') + '\x1b[2J');
  prevLines = [];
}
function restoreTerm() {
  if (!termOn) return;
  termOn = false;
  process.stdout.write('\x1b[?1000l\x1b[?1006l\x1b[?2004l\x1b[?7h\x1b[0m\x1b[?25h\x1b[?1049l\x1b[23;0t');
  try { process.stdin.setRawMode(false); } catch {}
  process.stdin.off('data', onData);
  process.stdin.pause();
}
function present(scr) {
  let o = '';
  if (scr.w !== frameW || scr.h !== frameH || !prevLines.length) { prevLines = []; frameW = scr.w; frameH = scr.h; o += '\x1b[0m\x1b[2J'; }
  for (let y = 0; y < scr.h; y++) {
    let line = '', cur = -1;
    for (let x = 0; x < scr.w; x++) {
      const i = y * scr.w + x, ch = scr.ch[i];
      if (ch === '') continue;
      if (scr.st[i] !== cur) { cur = scr.st[i]; line += '\x1b[0' + (styles[cur] ? ';' + styles[cur] : '') + 'm'; }
      line += ch;
    }
    if (line !== prevLines[y]) { o += '\x1b[' + (y + 1) + ';1H' + line; prevLines[y] = line; }
  }
  if (o) process.stdout.write('\x1b[?2026h' + o + '\x1b[0m\x1b[?2026l');
}
function setTitle(t) { if (t !== lastTitle) { lastTitle = t; process.stdout.write('\x1b]2;' + t.replace(UNSAFE_RE, '') + '\x07'); } }

/* ---------- interface: state and drawing helpers ---------- */
const U = { scr: null, focus: 'near', sel: 0, actSel: 0, actTop: 0, gridCols: 1, modal: null, staged: null, toasts: [], hits: [], mouse: true, askAuto: false, askCur: null, lastClick: null };
const TAU = Math.PI * 2;
const BANNER = [
  '    __                 __    __',
  '   / /___  _________ _/ /___/ /________  ____',
  '  / / __ \\/ ___/ __ `/ / __  / ___/ __ \\/ __ \\',
  ' / / /_/ / /__/ /_/ / / /_/ / /  / /_/ / /_/ /',
  '/_/\\____/\\___/\\__,_/_/\\__,_/_/   \\____/ .___/',
  '                                     /_/',
];
const GLYPH = ['    /\\', '   /  \\', '  /_  _\\', '    ||', ' ___||___', '|________|'];
const ICONS = {
  computer: { top: [' .---------. '], l: ' |', r: '| ', w: 9, rows: 3, bot: [" '---------' ", '/___________\\'] },
  tablet: { top: [' .---------. '], l: ' |', r: '| ', w: 9, rows: 4, bot: [" '----o----' "] },
  phone: { top: ['   .-----.   '], l: '   |', r: '|   ', w: 5, rows: 4, bot: ["   '--o--'   "] },
};
const tick4 = () => Math.floor(Date.now() / 250);
function screenRows(kind, mode, frac) {
  const { w, rows } = ICONS[kind] || ICONS.computer, mid = (rows - 1) >> 1, out = new Array(rows).fill(' '.repeat(w)), t = tick4();
  const mark = (s) => { out[mid] = (' '.repeat(Math.max(0, (w - s.length) >> 1)) + s).padEnd(w).slice(0, w); };
  if (mode === 'fill') {
    let left = Math.round(clamp01(frac) * w * rows);
    for (let r = rows - 1; r >= 0; r--) { const f = Math.min(w, Math.max(0, left)); out[r] = '#'.repeat(f) + ' '.repeat(w - f); left -= w; }
  } else if (mode === 'wait') mark(['.  ', '.. ', '...', '   '][Math.floor(t / 2) % 4]);
  else if (mode === 'spin') mark('-\\|/'[t % 4]);
  else if (mode === 'ask') mark(t % 4 < 2 ? '?' : ' ');
  else if (mode === 'q') mark('?');
  else if (mode === 'ok') mark(':)');
  else if (mode === 'bad') mark(':(');
  else if (mode === 'plus') mark('+');
  else if (mode === 'you') mark('you');
  return out;
}
function drawIcon(s, x, y, kind, mode, frac, st = T.dim, scr = T.bright) {
  const I = ICONS[kind] || ICONS.computer;
  let r = y;
  for (const l of I.top) s.put(x, r++, l, st);
  for (const row of screenRows(kind, mode, frac)) s.put(s.put(s.put(x, r, I.l, st), r, row, scr), r++, I.r, st);
  for (const l of I.bot) s.put(x, r++, l, st);
}
function box(s, x, y, w, h, o = {}) {
  if (w < 4 || h < 2) return;
  const B = o.heavy ? '┏┓┗┛━┃' : o.dashed ? '┌┐└┘╌╎' : '┌┐└┘─│', st = o.st ?? T.line;
  s.put(x, y, B[0] + B[4].repeat(w - 2) + B[1], st);
  s.put(x, y + h - 1, B[2] + B[4].repeat(w - 2) + B[3], st);
  for (let r = y + 1; r < y + h - 1; r++) { s.put(x, r, B[5], st); s.put(x + w - 1, r, B[5], st); }
  let end = x + 2;
  if (o.title) { s.put(x + 2, y, ' ', st); end = s.segs(x + 3, y, o.title, x + w - 3); s.put(end, y, ' ', st); }
  if (o.right) {
    const len = o.right.reduce((a, p) => a + sw(p[0]), 0), rx = x + w - 3 - len;
    if (rx > end + 2) { s.put(rx - 1, y, ' ', st); s.segs(rx, y, o.right); s.put(rx + len, y, ' ', st); if (o.rightFn) hit(rx, y, len, 1, o.rightFn); }
  }
}
function hit(x, y, w, h, fn) { U.hits.push({ x, y, w, h, fn }); }
function wrap(text, w, max = Infinity) {
  w = Math.max(1, w | 0);
  const out = [], push = (a) => out.push(a.join('').trimEnd());
  for (const para of String(text).split('\n')) {
    let cur = [], cw = 0, sp = -1;
    for (const g of graphemes(para)) {
      const k = gw(g), space = /\s/.test(g);
      if (cw + k > w) {
        if (space) { push(cur); cur = []; cw = 0; sp = -1; if (out.length >= max) return out; continue; }
        if (sp >= 0) { push(cur.slice(0, sp)); cur = cur.slice(sp + 1); cw = cur.reduce((a, x) => a + gw(x), 0); }
        else { push(cur); cur = []; cw = 0; }
        sp = -1;
        if (out.length >= max) return out;
      }
      if (space) sp = cur.length;
      cur.push(g);
      cw += k;
    }
    push(cur);
    if (out.length >= max) return out.slice(0, max);
  }
  return out;
}
const noteLines = (it, w) => { if (!it._wrap || it._wrap.w !== w) it._wrap = { w, lines: wrap(it.text.trim() || ' ', w, 4) }; return it._wrap.lines; };
function bar2(s, x, y, w, f, st = T.bright, rest = T.line) {
  const k = clamp01(f) * w, full = Math.floor(k);
  s.put(x, y, '━'.repeat(full), st);
  if (full < w) { s.put(x + full, y, k - full >= 0.5 ? '╸' : '━', k - full >= 0.5 ? st : rest); s.put(x + full + 1, y, '━'.repeat(Math.max(0, w - full - 1)), rest); }
}
function hints(s, x, y, list, maxX = s.w - 1) {
  for (const [k, label, fn] of list) {
    const need = sw(k) + 1 + sw(label);
    if (x + need > maxX) break;
    const x0 = x;
    x = s.put(s.put(x, y, k, T.hi) + 1, y, label, T.faint);
    if (fn) hit(x0, y, x - x0, 1, fn);
    x += 2;
  }
  return x;
}
const tagOf = (p) => p.kind + (p.os ? ' · ' + p.os : '');
const peerList = () => [...peers.values()];
const selPeer = () => { const l = peerList(); return l[Math.min(U.sel, l.length - 1)] || null; };
function peerViews() {
  const best = new Map(), out = new Map(), t = Date.now();
  for (const c of conns.values()) {
    if (c.dead) continue;
    let v = null;
    if (c.state === 'transfer' || c.state === 'finishing') { const f = c.total ? bytesOf(c) / c.total : 1; v = { r: 3, mode: 'fill', frac: f, text: (c.role === 'send' ? 'sending ' : 'receiving ') + pct(f), live: 1 }; }
    else if (c.state === 'connecting') v = { r: 2, mode: 'spin', text: 'connecting…', live: 1 };
    else if (c.state === 'asking') v = c.role === 'send' ? { r: 1, mode: 'wait', text: 'waiting for ok…', live: 1 } : { r: 1, mode: 'ask', text: 'wants to send', live: 1 };
    const cur = best.get(c.peer);
    if (v && (!cur || v.r > cur.r)) best.set(c.peer, v);
  }
  for (const p of peers.values()) {
    let v = best.get(p.id);
    if (!v && p.flash && p.flash.until > t) v = { mode: p.flash.ok ? 'ok' : 'bad', text: p.flash.text, ok: p.flash.ok, bad: !p.flash.ok };
    else if (!v && U.staged) v = { mode: 'plus', text: U.mouse ? 'click to send' : 'enter to send', live: 1 };
    else if (!v) v = { mode: 'idle', text: p.bg ? 'in background' : 'ready' };
    out.set(p.id, v);
  }
  return out;
}

/* ---------- interface: header, footer, sidebar ---------- */
function drawHeader(s) {
  const t = Date.now();
  s.put(s.put(1, 0, 'localdrop', T.bright), 0, Math.floor(t / 550) % 2 ? '_' : ' ', T.bright);
  if (HOSTED) s.put(12, 0, ' hosting ', T.inv);
  const txt = fit(statusText(), s.w - 26), rx = s.w - 2 - sw(txt) - 2;
  s.put(rx, 0, '●', online === false ? T.err : online ? (Math.floor(t / 1200) % 2 ? T.bright : T.dim) : T.faint);
  s.put(rx + 2, 0, txt, online === false ? T.err : T.dim);
}
function footerHints() {
  const m = U.modal, p = selPeer();
  if (asks.length) return [['y', 'accept', () => askAnswer(true)], ['n', 'decline', () => askAnswer(false)], ['a', "don't ask again", () => { U.askAuto = !U.askAuto; }]];
  if (m) return m.hints ? m.hints() : [['esc', 'close', closeModal]];
  if (U.staged) return [['↵', p ? 'send to ' + fit(p.name, 18) : 'send', () => p && sendTo(p.id)], ['E', 'everyone', sendEveryone], ['f', 'add more', () => openBrowse(null)], ['esc', 'clear', clearStaged], ['?', 'help', openHelp]];
  if (U.focus === 'act') return [['↑↓', 'select'], ['↵', 'open', () => actAction('open')], ['y', 'copy', () => actAction('copy')], ['d', 'folder', () => actAction('folder')], ['x', 'cancel/dismiss', () => actAction('dismiss')], ['R', 'retry', () => actAction('retry')], ['tab', 'devices', toggleFocus], ['?', 'help', openHelp]];
  return [['f', 'files', () => openBrowse(null)], ['t', 'note', () => openNote(p && p.id)], ['c', 'connect', openPair], ['↵', 'send', () => p && sendTo(p.id)], ['tab', 'activity', toggleFocus], ['r', 'rename', openRename], ['o', 'folder', openOut], ['?', 'help', openHelp], ['q', 'quit', quit]];
}
function drawMe(s, x, y, w, h, big) {
  box(s, x, y, w, h, { title: [['this device', T.dim]] });
  const mx = x + w - 2;
  if (big) {
    drawIcon(s, x + 2, y + 1, me.kind, 'you', 0);
    const tx = x + 17;
    s.put(tx, y + 2, fit(me.name, mx - tx), T.bright);
    s.put(tx, y + 3, fit(tagOf(me), mx - tx), T.dim);
    s.put(tx, y + 4, fit('saves to ' + tilde(OUT), mx - tx), T.dim);
    hints(s, tx, y + 6, [['r', 'rename', openRename], ['o', 'folder', openOut]], mx);
  } else {
    s.put(s.put(x + 2, y + 1, fit(me.name, w - 20), T.bright) + 2, y + 1, fit(tagOf(me), mx - x - sw(me.name) - 6), T.dim);
    const e = s.put(x + 2, y + 2, fit('saves to ' + tilde(OUT), w - 24), T.dim);
    hints(s, Math.max(e + 2, mx - 20), y + 2, [['r', 'rename', openRename], ['o', 'folder', openOut]], mx);
  }
}
function sendHeight(big) {
  if (!U.staged) return big ? 8 : 4;
  const n = U.staged.items.length;
  return 5 + Math.min(4, n) + (n > 4 ? 1 : 0);
}
function drawSend(s, x, y, w, h) {
  const st = U.staged;
  box(s, x, y, w, h, { dashed: true, st: st ? T.dim : T.line, title: [['send', st ? T.bright : T.dim]], right: st ? [['esc', T.hi], [' clear', T.faint]] : null, rightFn: clearStaged });
  const ix = x + 2, iw = w - 4, mx = ix + iw;
  if (!st) {
    if (h >= 8) {
      GLYPH.forEach((l, i) => s.put(ix + 1, y + 1 + i, l, T.dim));
      const tx = ix + 14;
      s.put(tx, y + 2, fit('drop files anywhere', mx - tx), T.bright);
      s.put(tx, y + 3, fit('or paste text, links or paths.', mx - tx), T.dim);
      hints(s, tx, y + 5, [['f', 'choose files', () => openBrowse(null)]], mx);
      hints(s, tx, y + 6, [['t', 'write a note', () => openNote(selPeer() && selPeer().id)]], mx);
    } else {
      s.put(ix, y + 1, fit('drop files onto the terminal or paste text', iw), T.fg);
      hints(s, ix, y + 2, [['f', 'choose files', () => openBrowse(null)], ['t', 'write a note', () => openNote(selPeer() && selPeer().id)]], mx);
    }
    return;
  }
  const total = st.files ? st.files.reduce((a, f) => a + f.size, 0) : st.items.reduce((a, it) => a + (it.size || 0), 0);
  const count = st.files ? st.files.length : null;
  s.segs(ix, y + 1, [['ready: ', T.dim], [count == null ? 'counting…' : plural(count, 'file') + ' · ' + fmtBytes(total), T.bright]], mx);
  let r = y + 2;
  const room = Math.max(0, h - 4), more = st.items.length > room, shown = st.items.slice(0, more ? Math.max(0, room - 1) : room);
  for (const it of shown) {
    const meta = it.dir ? (it.count != null ? plural(it.count, 'file') + ' · ' + fmtBytes(it.size) : 'folder') : fmtBytes(it.size);
    s.put(mx - sw(meta), r, meta, T.dim);
    s.put(ix + 1, r, it.dir ? fit(it.name + '/', iw - sw(meta) - 3) : fitName(it.name, iw - sw(meta) - 3), T.fg);
    r++;
  }
  if (more && room > 0) s.put(ix + 1, r++, '+ ' + (st.items.length - shown.length) + ' more', T.faint);
  const p = selPeer();
  hints(s, ix, y + h - 2, peers.size ? [['↵', 'send to ' + fit(p ? p.name : '', Math.max(6, iw - 26)), () => p && sendTo(p.id)], ...(peers.size > 1 ? [['E', 'everyone', sendEveryone]] : [])] : [['…', 'waiting for a device']], mx);
}

/* ---------- interface: activity ---------- */
function actEntries() {
  const live = [...conns.values()].filter((c) => !c.dead && !(c.role === 'recv' && c.state === 'asking')).map((c) => ({ k: 'tx', c, t: c.t }));
  const past = [...history.filter((c) => !c.hidden).map((c) => ({ k: 'tx', c, t: c.endAt ? Date.now() - (now() - c.endAt) : c.t })), ...received.filter((it) => !it.hidden).map((it) => ({ k: 'rx', it, t: it.t }))];
  return [...live, ...past.sort((a, b) => b.t - a.t)];
}
function entryHeight(e, w) {
  if (e.k === 'tx') return e.c.dead ? 2 : e.c.state === 'transfer' || e.c.state === 'finishing' ? 3 : 2;
  return e.it.text != null ? 1 + Math.min(3, noteLines(e.it, w - 4).length) : 2;
}
function drawEntry(s, e, x, y, w, selected, maxY) {
  const mx = x + w, tst = selected ? T.bright : T.hi;
  if (selected) for (let r = y; r < Math.min(maxY, y + entryHeight(e, w)); r++) s.put(x - 2, r, '▌', T.bright);
  if (e.k === 'tx') {
    const c = e.c, moving = c.state === 'transfer' || c.state === 'finishing', b = bytesOf(c), f = c.total ? b / c.total : c.state === 'finished' ? 1 : 0;
    const who = (c.role === 'send' ? 'to ' : 'from ') + c.peerName;
    const right = c.state === 'finished' ? ['✓', T.ok] : c.state === 'failed' ? (c.role === 'send' && c.what && c.error !== 'cancelled' ? ['R retry', T.dim] : ['✗', T.err]) : ['x cancel', T.faint];
    s.put(mx - sw(right[0]), y, right[0], right[1]);
    s.segs(x, y, [[c.role === 'send' ? '↑ ' : '↓ ', T.dim], [fitName(c.label + (c.count > 1 && c.state === 'transfer' && c.file ? ' · ' + c.file : ''), w - sw(right[0]) - 4), c.dead && c.state !== 'finished' ? T.fg : tst]], mx - sw(right[0]) - 1);
    const sub = c.state === 'asking' ? (c.role === 'send' ? 'waiting for ' + c.peerName + ' to accept…' : who)
      : c.state === 'connecting' ? who + ' · connecting…'
      : c.state === 'transfer' ? who + ' · ' + fmtBytes(b) + ' / ' + fmtBytes(c.total)
      : c.state === 'finishing' ? who + ' · finishing…'
      : c.state === 'finished' ? who + ' · ' + fmtBytes(c.total) + ' in ' + took(c) + (c.route ? ' · ' + c.route : '')
      : c.error || who;
    if (y + 1 < maxY) s.put(x + 2, y + 1, fit(sub, w - 2), c.state === 'failed' ? T.err : T.dim);
    if (moving && y + 2 < maxY) {
      let info = pct(f).padStart(4);
      if (c.state === 'transfer' && c.rate > 0) { const more = info + ' · ' + fmtBytes(c.rate) + '/s · ' + fmtTime((c.total - b) / c.rate); if (sw(more) <= w - 14) info = more; }
      bar2(s, x + 2, y + 2, Math.max(4, w - 3 - sw(info)), f);
      s.put(mx - sw(info), y + 2, info, T.fg);
    }
    return;
  }
  const it = e.it;
  if (it.text != null) {
    if (selected) s.put(mx - 6, y, 'y copy', T.faint);
    s.segs(x, y, [['¶ ', T.dim], ['note', tst], [' from ' + it.from + ' · ' + ago(it.t), T.dim]], selected ? mx - 8 : mx);
    const lines = noteLines(it, w - 4);
    lines.slice(0, 3).forEach((l, i) => { if (y + 1 + i < maxY) s.segs(x + 2, y + 1 + i, [['│ ', T.line], [fit(i === 2 && lines.length > 3 ? l + ' …' : l, w - 4), T.fg]]); });
    return;
  }
  const meta = fmtBytes(it.size);
  s.put(mx - sw(meta), y, meta, T.dim);
  s.segs(x, y, [['↓ ', T.dim], [fitName(it.name, w - sw(meta) - 4), tst]], mx - sw(meta) - 1);
  if (y + 1 < maxY) s.put(x + 2, y + 1, fit('from ' + it.from + ' · ' + ago(it.t) + ' · ' + tilde(path.dirname(it.path)), w - 2), T.dim);
}
function drawActivity(s, x, y, w, h) {
  const ents = actEntries(), focused = U.focus === 'act' && !U.modal;
  const clearable = ents.some((e) => e.k === 'rx' || e.c.dead);
  box(s, x, y, w, h, { title: [['activity', focused ? T.bright : T.dim], ...(ents.length ? [[' (' + ents.length + ')', T.faint]] : [])], right: clearable ? [['X', T.hi], [' clear', T.faint]] : null, rightFn: clearHistory, st: focused ? T.dim : T.line });
  const ix = x + 2, iw = w - 4, iy = y + 1, ih = h - 2;
  if (!ents.length) {
    const txt = 'file contents go straight between devices and are never uploaded. the relay only passes the connection handshake, plus the names and sizes shown in the accept prompt.';
    wrap(txt, iw).slice(0, ih).forEach((l, i) => s.put(ix, iy + i, l, T.faint));
    return;
  }
  U.actSel = Math.max(0, Math.min(U.actSel, ents.length - 1));
  if (!focused) U.actTop = 0;
  const hs = ents.map((e) => entryHeight(e, iw));
  if (U.actSel < U.actTop) U.actTop = U.actSel;
  const used = (a, b) => hs.slice(a, b + 1).reduce((t, v) => t + v + 1, -1);
  while (focused && U.actTop < U.actSel && used(U.actTop, U.actSel) > ih) U.actTop++;
  let r = iy, i = U.actTop;
  for (; i < ents.length && r < iy + ih; i++) {
    drawEntry(s, ents[i], ix, r, iw, focused && i === U.actSel, iy + ih);
    const idx = i;
    hit(ix - 1, r, iw + 2, Math.min(hs[i], iy + ih - r), () => { const again = U.focus === 'act' && U.actSel === idx; U.focus = 'act'; U.actSel = idx; if (again) actAction('open'); });
    r += hs[i] + 1;
  }
  if (U.actTop > 0) s.put(x + w - 4, y, '↑', T.dim);
  if (i < ents.length || r > iy + ih + 1) s.put(x + w - 4, y + h - 1, '↓', T.dim);
}

/* ---------- interface: nearby devices ---------- */
const CW = 21, CH = 11;
const RADAR = (() => {
  const R = 6, cells = [];
  for (let y = 0; y <= R * 2; y++) for (let x = 0; x <= R * 4; x++) {
    const dx = (x - R * 2) / 2, dy = y - R, d = Math.hypot(dx, dy);
    cells.push({ x, y, d, a: Math.atan2(dy, dx), base: d < 0.5 ? '@' : Math.abs(d - R) < 0.45 || Math.abs(d - R / 2) < 0.3 ? '.' : ' ' });
  }
  return { R, W: R * 4 + 1, H: R * 2 + 1, cells };
})();
function drawRadar(s, x, y) {
  const ang = (0.9 + (Date.now() / 70) * 0.13) % TAU;
  for (const c of RADAR.cells) {
    let l = c.base, u = ' ';
    if (c.d >= 0.5 && c.d <= RADAR.R + 0.3) {
      let df = (ang - c.a) % TAU;
      if (df < 0) df += TAU;
      if (df < 0.2) { u = '#'; l = ' '; } else if (df < 0.45) { u = '+'; l = ' '; } else if (df < 0.85) l = '-'; else if (df < 1.35 && l === ' ') l = '.';
    }
    if (u !== ' ') s.put(x + c.x, y + c.y, u, T.bright);
    else if (l !== ' ') s.put(x + c.x, y + c.y, l, l === '@' ? T.bright : l === '-' ? T.dim : T.faint);
  }
}
function drawEmpty(s, x, y, w, h) {
  const url = shareUrl(), side = w >= RADAR.W + 4 + 34, tw = Math.min(46, side ? w - RADAR.W - 6 : w - 2);
  const msg = room ? `this device is in room ${pretty(room)}. open the same link on your other device, or enter the code there.`
    : HOSTED ? 'open this address on your other device, connected to the same wi-fi:' : 'open localdrop on your other device, connected to the same wi-fi:';
  const text = [[['looking for devices', T.bright], [Math.floor(Date.now() / 550) % 2 ? '_' : ' ', T.bright]], [], ...wrap(msg, tw).map((l) => [[l, T.fg]]), [], [[fitL(url, tw), T.hi]]];
  const qr = qrRows(url), qrOk = !!qr && side && text.length + 1 + qr.length + 2 <= h && qr[0].length <= w - RADAR.W - 6;
  const tail = qrOk ? [[], ...wrap("or point your phone's camera at the code.", tw).map((l) => [[l, T.faint]])]
    : [[], [['c', T.hi], [' qr code & link', T.faint], ...(room ? [] : [['   p', T.hi], [' private code', T.faint]])]];
  const body = (qrOk ? [...text, [], ...qr.map((l) => [[l, T.qr]]), ...tail] : [...text, ...tail]).slice(0, h);
  if (side) {
    const bh = Math.max(RADAR.H, body.length), bw = RADAR.W + 4 + Math.max(tw, qrOk ? qr[0].length : 0);
    const bx = x + Math.max(0, (w - bw) >> 1), by = y + Math.max(0, (h - bh) >> 1);
    if (h >= RADAR.H) drawRadar(s, bx, by + Math.max(0, (bh - RADAR.H) >> 1));
    body.forEach((l, i) => s.segs(bx + RADAR.W + 4, by + i, l, x + w));
  } else {
    const showRadar = h >= RADAR.H + body.length + 1;
    let by = y + Math.max(0, (h - body.length - (showRadar ? RADAR.H + 1 : 0)) >> 1);
    if (showRadar) { drawRadar(s, x + ((w - RADAR.W) >> 1), by); by += RADAR.H + 1; }
    for (const l of body) { const len = l.reduce((a, p) => a + sw(p[0]), 0); s.segs(x + Math.max(0, (w - len) >> 1), by++, l, x + w); }
  }
}
function drawCard(s, p, v, x, y, sel, armed, i) {
  box(s, x, y, CW, CH, { heavy: sel, st: sel ? T.bright : armed ? T.dim : T.line });
  s.put(x + 2, y + 1, fit(tagOf(p), CW - 4), T.faint);
  drawIcon(s, x + 4, y + 2, p.kind, v.mode, v.frac, sel ? T.fg : T.dim, T.bright);
  const nm = fit(p.name, CW - 4), st = fit(v.text, CW - 4);
  s.put(x + ((CW - sw(nm)) >> 1), y + 8, nm, p.bg && !sel ? T.fg : T.bright);
  s.put(x + ((CW - sw(st)) >> 1), y + 9, st, v.bad ? T.err : v.ok ? T.ok : v.live ? T.hi : T.dim);
  hit(x, y, CW, CH, () => clickPeer(p.id));
}
function drawNear(s, x, y, w, h) {
  const list = peerList(), n = list.length, focused = U.focus === 'near' && !U.modal, armed = !!U.staged;
  box(s, x, y, w, h, { title: [['nearby', focused && n ? T.bright : T.dim], ...(n ? [[' (' + n + ')', T.bright]] : [])], right: [['+ connect a device', T.hi], ['  c', T.faint]], rightFn: openPair, st: focused && n ? T.dim : T.line });
  const ix = x + 2, iy = y + 1, iw = w - 4, ih = h - 2;
  if (ih < 1) return;
  if (!n) { U.gridCols = 1; return drawEmpty(s, ix, iy, iw, ih); }
  U.sel = Math.max(0, Math.min(U.sel, n - 1));
  const views = peerViews(), cols = Math.max(1, Math.min(n, Math.floor((iw + 2) / (CW + 2)))), rows = Math.ceil(n / cols);
  if (rows * CH + rows - 1 <= ih) {
    U.gridCols = cols;
    const gw0 = cols * CW + (cols - 1) * 2, gh = rows * CH + rows - 1, gx = ix + ((iw - gw0) >> 1), gy = iy + ((ih - gh) >> 1);
    list.forEach((p, i) => drawCard(s, p, views.get(p.id), gx + (i % cols) * (CW + 2), gy + Math.floor(i / cols) * (CH + 1), i === U.sel && (focused || armed), armed, i));
    return;
  }
  U.gridCols = 1;
  const top = Math.max(0, Math.min(U.sel - (ih >> 1), n - ih)), nameW = Math.min(26, Math.max(8, iw - 42));
  for (let r = 0; r < ih && top + r < n; r++) {
    const i = top + r, p = list[i], v = views.get(p.id), sel = i === U.sel && (focused || armed), yy = iy + r, stT = fit(v.text, 20);
    if (sel) s.put(ix - 1, yy, '›', T.bright);
    s.put(ix + iw - sw(stT), yy, stT, v.bad ? T.err : v.ok ? T.ok : v.live ? T.hi : T.dim);
    s.put(ix + 1, yy, fit(p.name, nameW), sel ? T.bright : T.hi);
    if (ix + nameW + 3 + 16 < ix + iw - sw(stT)) s.put(ix + nameW + 3, yy, fit(tagOf(p), iw - nameW - sw(stT) - 5), T.faint);
    if (v.mode === 'fill' && ix + iw - sw(stT) - 14 > ix + nameW + 22) bar2(s, ix + iw - sw(stT) - 13, yy, 11, v.frac);
    hit(ix - 1, yy, iw + 2, 1, () => clickPeer(p.id));
  }
}
function drawStack(s, x, y, w, h) {
  s.segs(x + 1, y, [['● ', T.dim], [fit(me.name, 24), T.bright], [fit('  ' + tagOf(me) + ' · saves to ' + tilde(OUT), w - sw(me.name) - 6), T.faint]], x + w);
  const ents = actEntries();
  const ah = ents.length ? Math.min(Math.max(5, Math.round(h * 0.3)), 2 + ents.slice(0, 3).reduce((a, e) => a + entryHeight(e, w - 4) + 1, -1)) : 0;
  const sh = Math.min(sendHeight(false), Math.max(4, h - 1 - ah - 8)), nh = h - 1 - sh - ah;
  drawNear(s, x, y + 1, w, nh);
  if (ah) drawActivity(s, x, y + 1 + nh, w, ah);
  drawSend(s, x, y + 1 + nh + ah, w, sh);
}
function drawSide(s, x, y, w, h) {
  let cy = y;
  if (h >= 40) { BANNER.forEach((l, i) => s.put(x + 1, cy + i, l, T.dim)); cy += 7; }
  const big = y + h - cy >= 30, gap = h >= 34 ? 1 : 0;
  drawMe(s, x, cy, w, big ? 8 : 4, big);
  cy += (big ? 8 : 4) + gap;
  const sh = sendHeight(big);
  drawSend(s, x, cy, w, sh);
  cy += sh + gap;
  if (y + h - cy >= 4) drawActivity(s, x, cy, w, y + h - cy);
}

/* ---------- interface: drawing modals ---------- */
function mbox(s, w, h, title, right, rightFn = closeModal) {
  w = Math.min(w, s.w - 2);
  h = Math.min(h, s.h - 2);
  const x = (s.w - w) >> 1, y = Math.max(1, (s.h - h) >> 1);
  s.fill(x, y, w, h, 0);
  box(s, x, y, w, h, { title: [[title, T.bright]], right, rightFn: right ? rightFn : null, st: T.dim });
  return { x, y, w, h, ix: x + 2, iy: y + 1, iw: w - 4, ih: h - 2 };
}
function drawField(s, x, y, w, f, placeholder) {
  let start = f.cur, acc = 0;
  while (start > 0 && acc + gw(f.chars[start - 1]) <= w - 2) acc += gw(f.chars[--start]);
  const cx = s.put(x, y, f.chars.slice(start, f.cur).join(''), T.bright, x + w);
  const at = f.chars[f.cur] || ' ';
  s.put(cx, y, at, T.inv);
  if (!f.chars.length && placeholder) s.put(cx + 2, y, fit(placeholder, w - 3), T.faint);
  else s.put(cx + gw(at), y, f.chars.slice(f.cur + 1, f.cur + 1 + w).join(''), T.bright, x + w);
}
function drawAsk(s) {
  const c = asks[0];
  if (U.askCur !== c) { U.askCur = c; U.askAuto = false; }
  const roomy = s.h >= 24, b = mbox(s, Math.min(54, s.w - 4), roomy ? 19 : 12, 'incoming');
  const cx = b.x + (b.w >> 1);
  let y = b.iy + 1;
  if (roomy) { drawIcon(s, cx - 6, y, (peers.get(c.peer) || {}).kind || c.peerKind, 'q', 0); y += 7; }
  const line = (t, st, name) => { const f = name ? fitName(t, b.iw) : fit(t, b.iw); s.put(cx - (sw(f) >> 1), y++, f, st); };
  line(c.peerName + ' wants to send you', T.fg);
  line(c.label, T.bright, true);
  line(fmtBytes(c.total) + (c.count > 1 && !c.manifest.text ? ' · starts with ' + c.manifest.name : ''), T.dim);
  y++;
  const left = Math.max(0, c.askEnd - Date.now()), secs = Math.ceil(left / 1000) + 's', bw = Math.min(26, b.iw - 6), bx = cx - ((bw + 1 + secs.length) >> 1);
  bar2(s, bx, y, bw, left / (ASK_MS - 5000), T.dim, T.line);
  s.put(bx + bw + 1, y++, secs, T.dim);
  y++;
  const tog = (U.askAuto ? '[x]' : '[ ]') + " don't ask again for " + fit(c.peerName, 18), tx = cx - (sw(tog) >> 1);
  s.put(tx, y, tog, U.askAuto ? T.hi : T.faint);
  hit(tx, y, sw(tog), 1, () => { U.askAuto = !U.askAuto; });
  y += 2;
  const no = '[ n  decline ]', yes = '  y  accept  ', nx = cx - ((sw(no) + 3 + sw(yes)) >> 1), yx = nx + sw(no) + 3;
  s.put(nx, y, no, T.fg);
  s.put(yx, y, yes, T.inv);
  hit(nx, y, sw(no), 1, () => askAnswer(false));
  hit(yx, y, sw(yes), 1, () => askAnswer(true));
  y += 2;
  if (asks.length > 1) line('+ ' + (asks.length - 1) + ' more waiting', T.faint);
}
function drawPair(s) {
  const m = U.modal, url = shareUrl(), qr = qrRows(url), qw = qr ? qr[0].length : 0, qh = qr ? qr.length : 0;
  const explain = room ? 'private: only devices using this code see each other, on any network.'
    : HOSTED ? 'devices on this wi-fi that open the link see each other. nothing leaves your network.'
    : "devices reaching the relay from the same internet connection see each other. if one doesn't show up, use a private code.";
  const side = !!qr && s.w >= qw + 52 && s.h >= qh + 12, top = !side && !!qr && s.w >= qw + 8 && s.h >= qh + 18;
  const w = Math.min(s.w - 4, side ? qw + 48 : 64), iw = w - 4, ex = wrap(explain, iw);
  const intro = ['open this link on your other device,', qr && (side || top) ? 'or scan the code with its camera.' : 'or type the address there.'];
  const headH = side ? Math.max(qh, 6) : (top ? qh + 1 : 0) + 5;
  const b = mbox(s, w, 2 + 1 + headH + 2 + 1 + ex.length + 2 + 1, 'connect a device', [['esc', T.hi], [' close', T.faint]]);
  let y = b.iy + 1;
  if (side) {
    qr.forEach((l, i) => s.put(b.ix, y + i, l, T.qr));
    const tx = b.ix + qw + 3, tw = b.ix + b.iw - tx;
    let ty = y + Math.max(0, (qh - 6) >> 1);
    for (const l of intro) s.put(tx, ty++, fit(l, tw), T.fg);
    s.put(tx, ++ty, fitL(url, tw), T.hi);
    ty += 2;
    hints(s, tx, ty, [['y', 'copy link', () => copyText(url, 'link copied')]], tx + tw);
    y += headH + 1;
  } else {
    if (top) { qr.forEach((l, i) => s.put(b.ix + ((b.iw - qw) >> 1), y + i, l, T.qr)); y += qh + 1; }
    for (const l of intro) s.put(b.ix, y++, fit(l, b.iw), T.fg);
    s.put(b.ix, ++y, fitL(url, b.iw), T.hi);
    y += 2;
    hints(s, b.ix, y, [['y', 'copy link', () => copyText(url, 'link copied')]]);
    y += 2;
  }
  s.put(b.ix, y++, '╌'.repeat(b.iw), T.line);
  y++;
  s.segs(b.ix, y++, [['room · ', T.dim], [room ? pretty(room) : 'this network', T.bright]]);
  for (const l of ex) s.put(b.ix, y++, l, T.dim);
  y++;
  if (m.join) { s.put(b.ix, y, 'code', T.dim); drawField(s, b.ix + 5, y, b.iw - 5, m.join, 'abcd-efgh'); if (m.join.err) s.put(b.ix + b.iw - sw(m.join.err), y, m.join.err, T.err); }
  else hints(s, b.ix, y, room ? [['p', 'new code', () => setRoom(newCode())], ['n', 'back to this network', () => setRoom('')], ['j', 'join a code', () => startJoin()]] : [['p', 'use a private code', () => setRoom(newCode())], ['j', 'join a code', () => startJoin()]]);
}
function drawBrowse(s) {
  const m = U.modal, tgt = m.target && peers.get(m.target);
  const b = mbox(s, Math.min(86, s.w - 4), Math.min(s.h - 2, 34), tgt ? 'send to ' + fit(tgt.name, 28) : 'choose files', [['esc', T.hi], [' cancel', T.faint]]);
  let y = b.iy;
  s.put(b.ix, y++, fitL(tilde(m.dir), b.iw), T.dim);
  s.put(b.ix, y, '›', T.hi);
  drawField(s, b.ix + 2, y++, b.iw - 2, m.filter, 'type to filter · / or ~/ to jump · . shows hidden');
  s.put(b.ix, y++, '─'.repeat(b.iw), T.line);
  const listH = b.ih - 5;
  m.sel = Math.max(0, Math.min(m.sel, m.list.length - 1));
  if (m.sel < m.top) m.top = m.sel;
  if (m.sel >= m.top + listH) m.top = m.sel - listH + 1;
  m.top = Math.max(0, Math.min(m.top, Math.max(0, m.list.length - listH)));
  m.listH = listH;
  for (let i = 0; i < listH; i++) {
    const idx = m.top + i, e = m.list[idx];
    if (!e) break;
    const yy = y + i, sel = idx === m.sel, marked = m.marks.has(e.path), meta = e.dir ? '' : fmtBytes(e.size);
    if (sel) s.fill(b.ix - 1, yy, b.iw + 2, 1, T.sel);
    s.put(b.ix, yy, marked ? '●' : ' ', sel ? T.sel : T.bright);
    s.put(b.ix + b.iw - sw(meta), yy, meta, sel ? T.sel : T.dim);
    s.put(b.ix + 2, yy, e.dir ? fit(e.name + (e.up ? '' : '/'), b.iw - sw(meta) - 4) : fitName(e.name, b.iw - sw(meta) - 4), sel ? T.sel : marked ? T.bright : e.dir ? T.hi : T.fg);
    hit(b.ix - 1, yy, b.iw + 2, 1, () => { if (m.sel === idx) browseEnter(); else m.sel = idx; });
  }
  if (!m.list.length) s.put(b.ix + 2, y, fit(m.err || m.jumpHint || (m.filter.chars.length ? 'nothing matches' : 'empty folder'), b.iw - 2), m.err ? T.err : m.jumpHint ? T.hi : T.faint);
  if (m.list.length > listH) s.put(b.x + b.w - 1, y + Math.round((m.top / Math.max(1, m.list.length - listH)) * (listH - 1)), '┃', T.dim);
  y = b.iy + b.ih - 2;
  s.put(b.ix, y++, '─'.repeat(b.iw), T.line);
  const total = [...m.marks.values()].reduce((a, v) => a + v, 0);
  s.put(b.ix, y, m.marks.size ? plural(m.marks.size, 'item') + ' marked' + (total ? ' · ' + fmtBytes(total) : '') : 'space marks several · ↵ picks one', m.marks.size ? T.bright : T.faint);
}
function noteRows(chars, w) {
  const rows = [];
  let start = 0, cw = 0;
  for (let i = 0; i < chars.length; i++) {
    if (chars[i] === '\n') { rows.push({ s: start, e: i }); start = i + 1; cw = 0; continue; }
    const k = gw(chars[i]);
    if (cw + k > w) { rows.push({ s: start, e: i }); start = i; cw = 0; }
    cw += k;
  }
  rows.push({ s: start, e: chars.length });
  return rows;
}
const rowOf = (rows, cur) => { for (let r = rows.length - 1; r > 0; r--) if (cur >= rows[r].s) return r; return 0; };
function drawNote(s) {
  const m = U.modal, b = mbox(s, Math.min(76, s.w - 4), Math.min(s.h - 2, 16), 'note', [['esc', T.hi], [' cancel', T.faint]]);
  const viewH = b.ih - 2, rows = noteRows(m.chars, b.iw - 1), cr = rowOf(rows, m.cur);
  m.rowsCache = { rows, w: b.iw - 1 };
  if (cr < m.top) m.top = cr;
  if (cr >= m.top + viewH) m.top = cr - viewH + 1;
  if (!m.chars.length) { s.put(b.ix, b.iy, ' ', T.inv); s.put(b.ix + 2, b.iy, 'type or paste text, a link, a code…', T.faint); }
  else for (let i = 0; i < viewH && m.top + i < rows.length; i++) {
    const row = rows[m.top + i], yy = b.iy + i;
    let x = b.ix;
    for (let j = row.s; j < row.e; j++) x = s.put(x, yy, m.chars[j], j === m.cur ? T.inv : T.fg);
    if (m.top + i === cr && m.cur >= row.e) s.put(x, yy, ' ', T.inv);
  }
  const yy = b.iy + b.ih - 1, t = noteTarget(m), cnt = m.chars.length + ' / ' + TEXT_MAX;
  s.put(b.ix + b.iw - sw(cnt), yy, cnt, m.chars.length > TEXT_MAX ? T.err : T.faint);
  s.segs(b.ix, yy, [['→ ', T.dim], [t ? (t === '*' ? 'everyone' : fit(peers.get(t).name, 30)) : 'no device yet', t ? T.bright : T.faint], ...(peers.size > 1 ? [['   tab', T.hi], [' change', T.faint]] : [])], b.ix + b.iw - sw(cnt) - 2);
}
function drawInput(s) {
  const m = U.modal, w = Math.min(68, s.w - 4), lines = (m.lines || []).flatMap((l) => (l ? wrap(l, w - 4) : ['']));
  const b = mbox(s, w, 2 + 1 + lines.length + (lines.length ? 1 : 0) + 1 + 2, m.title, [['esc', T.hi], [m.noCancel ? ' quit' : ' cancel', T.faint]], m.noCancel ? () => exitApp(0) : closeModal);
  let y = b.iy + 1;
  for (const l of lines) s.put(b.ix, y++, l, T.dim);
  if (lines.length) y++;
  const lab = m.label + ' ';
  s.put(b.ix, y, lab, T.dim);
  drawField(s, b.ix + sw(lab), y, b.iw - sw(lab), m, m.placeholder);
  if (m.err) s.put(b.ix, y + 1, fit(m.err, b.iw), T.err);
}
const HELP_KEYS = [
  ['', 'devices'], ['f', 'choose files to send'], ['t', 'write a note'], ['c', 'connect a device: link, qr code, private rooms'], ['↵ / click', 'send to the selected device'],
  ['E', 'send to everyone'], ['arrows · hjkl', 'pick a device'], ['tab', 'switch between devices and activity'], ['r · o', 'rename this device · change the save folder'],
  ['esc', 'clear what is staged'], ['q · ctrl+c', 'quit'], ['', 'activity'], ['↵', 'open the file'], ['d', 'show it in its folder'], ['y', 'copy the note or the file path'],
  ['x', 'cancel a transfer or dismiss an entry'], ['R · X', 'retry a failed send · clear finished entries'], ['', 'anywhere'], ['drop · paste', 'drop files onto the terminal, or paste text, to send it'], ['y · n · a', "accept · decline · don't ask again"],
];
function drawHelp(s) {
  const b = mbox(s, Math.min(72, s.w - 4), Math.min(s.h - 2, HELP_KEYS.length + 4), 'keys', [['esc', T.hi], [' close', T.faint]]);
  HELP_KEYS.slice(0, b.ih - 1).forEach(([k, d], i) => {
    const y = b.iy + 1 + i;
    if (!k) s.put(b.ix, y, d, T.bright);
    else { s.put(b.ix + 2, y, k, T.hi); s.put(b.ix + 18, y, fit(d, b.iw - 18), T.dim); }
  });
}
function drawQuit(s) {
  const b = mbox(s, Math.min(58, s.w - 4), 7, 'quit?');
  const n = active().length + [...conns.values()].filter((c) => !c.dead && c.role === 'send' && c.state !== 'transfer').length;
  s.put(b.ix, b.iy + 1, fit(plural(n, 'transfer') + ' still running. quit and cancel ' + (n === 1 ? 'it' : 'them') + '?', b.iw), T.fg);
  hints(s, b.ix, b.iy + 3, [['y', 'quit', () => exitApp(0)], ['n', 'keep going', closeModal]]);
}
function drawToasts(s) {
  const t = Date.now();
  U.toasts = U.toasts.filter((x) => x.until > t);
  U.toasts.slice(-3).forEach((x, i) => { const txt = ' ' + fit(x.text, s.w - 8) + ' '; s.put((s.w - sw(txt)) >> 1, 1 + i, txt, x.bad ? T.invErr : T.inv); });
}

function render() { try { renderFrame(); } catch (e) { debug(e); } }
function renderFrame() {
  const w = process.stdout.columns || 80, h = process.stdout.rows || 24, s = (U.scr = new Screen(w, h));
  U.hits = [];
  U.drawn = Date.now();
  if (w < 60 || h < 18) {
    ['localdrop', '', 'make the window a little bigger', `needs 60×18, now ${w}×${h}`].forEach((l, i) => s.put(Math.max(0, (w - sw(l)) >> 1), Math.max(0, (h >> 1) - 2 + i), fit(l, w), i ? T.dim : T.bright));
    return present(s);
  }
  drawHeader(s);
  if (w >= 100 && h >= 24) {
    const sideW = Math.min(54, Math.max(44, Math.round(w * 0.34)));
    drawSide(s, 1, 1, sideW, h - 2);
    drawNear(s, sideW + 2, 1, w - sideW - 3, h - 2);
  } else drawStack(s, 1, 1, w - 2, h - 2);
  if (U.modal || asks.length) {
    s.restyle(T.faint);
    U.hits = [];
    if (U.modal) ({ pair: drawPair, browse: drawBrowse, note: drawNote, input: drawInput, help: drawHelp, quit: drawQuit })[U.modal.type](s);
    if (asks.length) { if (U.modal) s.restyle(T.faint), (U.hits = []); drawAsk(s); }
  }
  s.fill(0, h - 1, w, 1, 0);
  hints(s, 1, h - 1, footerHints());
  drawToasts(s);
  present(s);
  const act = active(), done = act.reduce((a, c) => a + bytesOf(c), 0), tot = act.reduce((a, c) => a + c.total, 0);
  setTitle((asks.length ? '(' + asks.length + ') ' : act.length ? pct(tot ? done / tot : 1) + ' · ' : '') + 'localdrop');
}

/* ---------- interface: actions ---------- */
let drawQueued = false, exiting = false;
function draw() { if (!drawQueued && termOn) { drawQueued = true; setImmediate(() => { drawQueued = false; if (termOn) render(); }); } }
function toast(text, bad = false) { U.toasts.push({ text, bad, until: Date.now() + (bad ? 6500 : 3500) }); if (U.toasts.length > 3) U.toasts.shift(); draw(); }
function closeModal() { U.modal = null; }
function toggleFocus() { U.focus = U.focus === 'near' && actEntries().length ? 'act' : 'near'; }
function clearHistory() { history.forEach((c) => { c.hidden = true; }); received.forEach((it) => { it.hidden = true; }); U.actSel = 0; if (!actEntries().length) U.focus = 'near'; }
function clickPeer(id) {
  const i = peerList().findIndex((p) => p.id === id);
  if (i < 0) return;
  const again = U.sel === i && U.focus === 'near';
  U.sel = i;
  U.focus = 'near';
  if (again || U.staged) sendTo(id);
}
function askAnswer(yes) {
  const c = asks[0];
  if (!c) return;
  if (yes) { if (U.askAuto) autoAccept.add(c.peer); accept(c); } else decline(c);
  U.askAuto = false;
}
function sendTo(id) {
  if (!peers.has(id)) return;
  if (!U.staged) return openBrowse(id);
  const st = U.staged;
  U.staged = null;
  startSend(id, { paths: st.paths, files: st.files || undefined });
}
async function sendEveryone() {
  if (!peers.size) return toast('no devices yet');
  if (!U.staged) return toast('stage something first: press f, or drop files here');
  const st = U.staged, what = { paths: st.paths, files: st.files || undefined };
  U.staged = null;
  for (const p of peerList()) await startSend(p.id, what);
}
function stage(paths) {
  const items = U.staged ? U.staged.items.slice() : [], have = new Set(items.map((i) => i.path));
  for (const p of paths) {
    const abs = expand(p);
    if (have.has(abs)) continue;
    let st;
    try { st = fs.statSync(abs); } catch { continue; }
    items.push({ path: abs, name: path.basename(abs) || abs, dir: st.isDirectory(), size: st.isDirectory() ? 0 : st.size, count: null });
    have.add(abs);
  }
  if (!items.length) return;
  const staged = (U.staged = { items, paths: items.map((i) => i.path), files: null });
  U.focus = 'near';
  collect(staged.paths).then((files) => {
    if (U.staged !== staged) return;
    staged.files = files;
    for (const it of items) if (it.dir) { const sub = files.filter((f) => f.path.startsWith(it.path + path.sep)); it.count = sub.length; it.size = sub.reduce((a, f) => a + f.size, 0); }
    if (files.length > MAX_FILES) toast('only 10,000 files at a time. zip the rest.', true);
    draw();
  }, () => {});
}
function clearStaged() { U.staged = null; }
function parsePaths(text) {
  const t = text.replace(/\r/g, '').trim();
  if (!t || t.length > 200000) return null;
  const looks = (p) => /^(\/|~|\.{1,2}[\\/]|file:\/\/|[a-z]:\\)/i.test(p) || p.includes('/');
  if (!t.includes('\n') && looks(t) && fs.existsSync(expand(t))) return [expand(t)];
  const toks = [];
  let cur = '', q = '', esc = false;
  for (const ch of t) {
    if (esc) { cur += ch; esc = false; continue; }
    if (q) { if (ch === q) q = ''; else cur += ch; continue; }
    if (ch === '\\' && !WIN) { esc = true; continue; }
    if (ch === "'" || ch === '"') { q = ch; continue; }
    if (/\s/.test(ch)) { if (cur) toks.push(cur); cur = ''; continue; }
    cur += ch;
  }
  if (cur) toks.push(cur);
  if (!toks.length || !toks.every(looks)) return null;
  const paths = toks.map((p) => { if (/^file:\/\//i.test(p)) { try { return fileURLToPath(p); } catch { return p; } } return expand(p); });
  return paths.length <= MAX_FILES && paths.every((p) => fs.existsSync(p)) ? paths : null;
}
function onPaste(text) {
  const ps = parsePaths(text);
  if (ps) return stage(ps);
  if (text.trim()) openNote(selPeer() && selPeer().id, cut(text.replace(/\r\n?/g, '\n'), TEXT_MAX));
}
function copyText(text, msg = 'copied') {
  const run = (cmd, args, input = text) => { try { return spawnSync(cmd, args, { input, stdio: ['pipe', 'ignore', 'ignore'], timeout: 2000 }).status === 0; } catch { return false; } };
  if (process.platform === 'darwin') run('pbcopy', []);
  else if (WIN) run('clip', [], Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(text, 'utf16le')]));
  else if (process.env.WAYLAND_DISPLAY) run('wl-copy', []);
  else if (process.env.DISPLAY) run('xclip', ['-selection', 'clipboard']) || run('xsel', ['-bi']);
  if (text.length < 75000) process.stdout.write('\x1b]52;c;' + Buffer.from(text).toString('base64') + '\x07');
  toast(msg);
}
function openPath(p, reveal = false) {
  if (!p || !fs.existsSync(p)) return toast('that file is gone', true);
  const [cmd, args] = process.platform === 'darwin' ? ['open', reveal ? ['-R', p] : [p]] : WIN ? ['explorer', reveal ? ['/select,' + p] : [p]] : ['xdg-open', [reveal ? path.dirname(p) : p]];
  try {
    const ch = spawn(cmd, args, { detached: true, stdio: 'ignore' });
    ch.on('error', () => toast("couldn't open it (" + cmd + ' not available)', true));
    ch.unref();
    toast((reveal ? 'showing ' : 'opening ') + path.basename(p));
  } catch { toast("couldn't open it", true); }
}
const RISKY = /\.(app|command|terminal|tool|workflow|pkg|mpkg|dmg|scpt|exe|com|bat|cmd|msi|msp|scr|pif|lnk|url|hta|js|jse|vbs|vbe|wsf|wsh|ps1|psm1|reg|cpl|jar|sh|bash|zsh|run|appimage|desktop|deb|rpm)$/i;
function actAction(kind) {
  const e = actEntries()[U.actSel];
  if (!e) return;
  if (e.k === 'rx') {
    const it = e.it;
    if (kind === 'dismiss') it.hidden = true;
    else if (kind === 'copy' || (kind === 'open' && it.text != null)) copyText(it.text ?? it.path, it.text != null ? 'note copied' : 'path copied');
    else if (kind === 'open' && RISKY.test(it.path)) { openPath(it.path, true); toast(it.name + ' can run code, so it is only shown in its folder'); }
    else if (kind === 'open') openPath(it.path);
    else if (kind === 'folder' && it.path) openPath(it.path, true);
    return;
  }
  const c = e.c, src = c.role === 'send' && c.what && c.what.paths ? c.what.paths[0] : c.got.length && c.got[0].path;
  if (kind === 'dismiss') { if (c.dead) c.hidden = true; else fail(c, 'cancelled'); }
  else if (kind === 'retry') {
    if (!(c.dead && c.state === 'failed' && c.role === 'send' && c.what)) return;
    if (!peers.has(c.peer)) return toast(c.peerName + ' is no longer here', true);
    c.hidden = true;
    startSend(c.peer, c.what);
  } else if (kind === 'copy') copyText(c.what && c.what.text != null ? c.what.text : (c.what && c.what.paths ? c.what.paths : c.got.map((g) => g.path)).join('\n'), 'copied');
  else if (src) openPath(src, kind === 'folder' || RISKY.test(src));
}

/* ---------- interface: modal logic ---------- */
const field = (v = '') => { const chars = graphemes(String(v)); return { chars, cur: chars.length }; };
const lineStart = (f) => { let i = f.cur; while (i > 0 && f.chars[i - 1] !== '\n') i--; return i; };
const lineEnd = (f) => { let i = f.cur; while (i < f.chars.length && f.chars[i] !== '\n') i++; return i; };
function editField(f, k, multi = false) {
  const ins = (s) => {
    const room = (multi ? TEXT_MAX : 4096) - f.chars.length;
    if (room <= 0) return;
    const g = graphemes(s.slice(0, room * 4)).slice(0, room);
    f.chars.splice(f.cur, 0, ...g);
    f.cur += g.length;
  };
  const ws = (ch) => /\s/.test(ch || '');
  const wordL = () => { let i = f.cur; while (i > 0 && ws(f.chars[i - 1])) i--; while (i > 0 && !ws(f.chars[i - 1])) i--; return i; };
  const wordR = () => { let i = f.cur; while (i < f.chars.length && ws(f.chars[i])) i++; while (i < f.chars.length && !ws(f.chars[i])) i++; return i; };
  const del = (a, b) => { f.chars.splice(a, b - a); f.cur = a; };
  switch (k.name) {
    case 'char':
      if (!k.alt) return ins(k.ch), true;
      if (k.ch === 'b') f.cur = wordL(); else if (k.ch === 'f') f.cur = wordR(); else if (k.ch === 'd') f.chars.splice(f.cur, wordR() - f.cur); else return false;
      return true;
    case 'paste': ins(multi ? k.text.replace(/\r\n?/g, '\n') : k.text.replace(/[\r\n]+/g, ' ')); return true;
    case 'newline': if (!multi) return false; ins('\n'); return true;
    case 'backspace': if (k.alt) del(wordL(), f.cur); else if (f.cur > 0) del(f.cur - 1, f.cur); return true;
    case 'delete': if (f.cur < f.chars.length) f.chars.splice(f.cur, 1); return true;
    case 'left': f.cur = k.ctrl || k.alt ? wordL() : Math.max(0, f.cur - 1); return true;
    case 'right': f.cur = k.ctrl || k.alt ? wordR() : Math.min(f.chars.length, f.cur + 1); return true;
    case 'home': f.cur = multi ? lineStart(f) : 0; return true;
    case 'end': f.cur = multi ? lineEnd(f) : f.chars.length; return true;
    case 'ctrl':
      if (k.ch === 'a') f.cur = multi ? lineStart(f) : 0;
      else if (k.ch === 'e') f.cur = multi ? lineEnd(f) : f.chars.length;
      else if (k.ch === 'u') del(multi ? lineStart(f) : 0, f.cur);
      else if (k.ch === 'k') f.chars.splice(f.cur, (multi ? lineEnd(f) : f.chars.length) - f.cur);
      else if (k.ch === 'w') del(wordL(), f.cur);
      else return false;
      return true;
  }
  return false;
}
function openHelp() { U.modal = { type: 'help' }; }
function quit() {
  if (active().length || [...conns.values()].some((c) => !c.dead && c.role === 'send')) U.modal = { type: 'quit', hints: () => [['y', 'quit', () => exitApp(0)], ['n', 'keep going', closeModal]] };
  else exitApp(0);
}
function openPair() {
  U.modal = {
    type: 'pair', join: null,
    hints: () => U.modal.join ? [['↵', 'join'], ['esc', 'back']] : [['y', 'copy link', () => copyText(shareUrl(), 'link copied')], ['p', room ? 'new code' : 'private code', () => setRoom(newCode())], ...(room ? [['n', 'this network', () => setRoom('')]] : []), ['j', 'join a code', startJoin], ['esc', 'close', closeModal]],
  };
}
function startJoin() { if (U.modal && U.modal.type === 'pair') U.modal.join = { ...field(), err: '' }; }
function pairKey(k) {
  const m = U.modal;
  if (m.join) {
    if (k.name === 'escape') m.join = null;
    else if (k.name === 'enter') {
      const v = normCode(m.join.chars.join(''));
      if (!validCode(v)) { m.join.err = '6 to 32 letters or digits'; return; }
      m.join = null;
      setRoom(v);
      toast('joined room ' + pretty(v));
    } else if (editField(m.join, k)) m.join.err = '';
    return;
  }
  if (k.name === 'escape' || k.name === 'enter' || (k.name === 'char' && k.ch === 'q')) return closeModal();
  if (k.name !== 'char') return;
  if (k.ch === 'y') copyText(shareUrl(), 'link copied');
  else if (k.ch === 'p') { setRoom(newCode()); toast('private room ' + pretty(room)); }
  else if (k.ch === 'n' && room) { setRoom(''); toast('back to this network'); }
  else if (k.ch === 'j') startJoin();
}
function openInput(o) {
  U.modal = { type: 'input', ...o, ...field(o.value || ''), err: '', hints: () => [['↵', o.ok || 'save'], ['esc', o.noCancel ? 'quit' : 'cancel']] };
}
async function submitInput(m) {
  m.err = '';
  let r = m.submit(m.chars.join(''));
  if (r && typeof r.then === 'function') { m.err = 'checking…'; draw(); r = await r; }
  if (r) m.err = r;
  else if (U.modal === m) closeModal();
  draw();
}
function inputKey(k) {
  const m = U.modal;
  if (k.name === 'escape') return m.noCancel ? exitApp(0) : closeModal();
  if (k.name === 'enter') return void submitInput(m);
  if (editField(m, k)) m.err = '';
}
function openRename() {
  openInput({ title: 'rename', label: 'name', value: me.name, lines: ['how this device shows up on your other devices.'], submit: (v) => {
    const n = cleanName(v);
    if (!n) return 'pick a name';
    me.name = n;
    saveConf({ name: n });
    pollNow();
    toast('this device is now ' + n);
  } });
}
function openOut() {
  openInput({ title: 'save folder', label: 'folder', value: tilde(OUT), lines: ['received files go here. the folder is created if it does not exist.'], submit: (v) => {
    const p = expand(v.trim() || '.');
    try { fs.mkdirSync(p, { recursive: true }); fs.accessSync(p, fs.constants.W_OK); } catch (e) { return "can't save there (" + (e.code || e.message) + ')'; }
    OUT = p;
    saveConf({ out: p });
    toast('saving to ' + tilde(p));
  } });
}
function openSetup() {
  openInput({
    title: 'set up localdrop', label: 'relay', ok: 'connect', placeholder: 'https://drop.example.com', noCancel: true,
    lines: ['localdrop finds your other devices through a small relay: the index.php from this repo, hosted anywhere that runs php.', '', 'paste its address. or quit and run "localdrop host" to share straight from this computer, no server needed.'],
    submit: async (v) => {
      const u = normServer(v);
      if (!u) return "that doesn't look like a web address";
      const prev = SERVER;
      SERVER = u;
      try { await api({ a: 'poll', s: me.secret, room, name: me.name, kind: me.kind, os: me.os, bg: false, ack: 0 }, 6000); }
      catch (e) { SERVER = prev; return "couldn't reach a localdrop relay there (" + e.message + ')'; }
      saveConf({ server: u });
      startCore();
      toast('connected to ' + new URL(u).host);
    },
  });
}
function openNote(target, text = '') {
  U.modal = { type: 'note', ...field(text), top: 0, target: target && peers.has(target) ? target : null, hints: () => [['↵', 'send'], ['ctrl+j', 'new line'], ...(peers.size > 1 ? [['tab', 'recipient']] : []), ['esc', 'cancel', closeModal]] };
}
function noteTarget(m) {
  if (m.target === '*' && peers.size > 1) return '*';
  if (m.target && peers.has(m.target)) return m.target;
  const p = selPeer();
  return p ? p.id : null;
}
function noteKey(k) {
  const m = U.modal;
  if (k.name === 'escape') return closeModal();
  if (k.name === 'enter') {
    const text = m.chars.join(''), t = noteTarget(m);
    if (!text.trim()) return toast('write something first');
    if (!t) return toast('no devices yet', true);
    closeModal();
    (async () => { for (const id of t === '*' ? [...peers.keys()] : [t]) await startSend(id, { text }); })();
    return;
  }
  if (k.name === 'tab' || k.name === 'backtab') {
    const list = [...peers.keys(), ...(peers.size > 1 ? ['*'] : [])];
    if (list.length) m.target = list[(list.indexOf(noteTarget(m)) + (k.name === 'tab' ? 1 : list.length - 1)) % list.length];
    return;
  }
  if ((k.name === 'up' || k.name === 'down') && m.rowsCache) {
    const rows = m.rowsCache.rows, r = rowOf(rows, m.cur), nr = r + (k.name === 'up' ? -1 : 1);
    if (nr < 0) m.cur = 0;
    else if (nr >= rows.length) m.cur = m.chars.length;
    else {
      const col = sw(m.chars.slice(rows[r].s, m.cur).join(''));
      let i = rows[nr].s, w = 0;
      while (i < rows[nr].e && w + gw(m.chars[i]) <= col) w += gw(m.chars[i++]);
      m.cur = i;
    }
    return;
  }
  editField(m, k, true);
}
function openBrowse(target) {
  const start = U.lastDir && isDir(U.lastDir) ? U.lastDir : process.cwd();
  U.modal = {
    type: 'browse', target: target || null, dir: start, all: [], list: [], sel: 0, top: 0, filter: field(), marks: new Map(), err: '', jumpHint: '',
    hints: () => [['↑↓', 'move'], ['→', 'open'], ['←', 'up'], ['space', 'mark'], ['^a', 'all'], ['↵', U.modal.marks.size ? 'done' : 'pick'], ['esc', 'cancel', closeModal]],
  };
  loadDir(U.modal, start);
}
function loadDir(m, dir, focusName) {
  let ents;
  try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { m.err = "can't open " + tilde(dir) + ' (' + (e.code || e.message) + ')'; return draw(); }
  m.err = '';
  m.dir = dir;
  U.lastDir = dir;
  const all = [];
  for (const e of ents.slice(0, 5000)) {
    const p = path.join(dir, e.name);
    let d = e.isDirectory(), size = 0;
    try { if (e.isSymbolicLink()) { const st = fs.statSync(p); d = st.isDirectory(); size = st.size; } else if (e.isFile()) size = fs.statSync(p).size; else if (!d) continue; } catch { continue; }
    all.push({ name: e.name, path: p, dir: d, size });
  }
  all.sort((a, b) => b.dir - a.dir || a.name.localeCompare(b.name, undefined, { sensitivity: 'base', numeric: true }));
  const parent = path.dirname(dir);
  m.all = parent !== dir ? [{ name: '..', path: parent, dir: true, up: true, size: 0 }, ...all] : all;
  m.filter = field();
  applyFilter(m);
  m.sel = focusName ? Math.max(0, m.list.findIndex((e) => e.name === focusName)) : 0;
  m.top = 0;
}
function applyFilter(m) {
  const raw = m.filter.chars.join(''), q = raw.toLowerCase();
  m.sel = 0;
  if (/^(~|\/|\.\.?[\\/])/.test(raw) || (WIN && /^[a-z]:\\/i.test(raw))) {
    const p = expand(raw);
    m.list = [];
    m.jump = true;
    m.jumpHint = isDir(p) ? '↵ open ' + tilde(p) : fs.existsSync(p) ? '↵ pick ' + tilde(p) : 'no such file or folder';
    return;
  }
  m.jump = false;
  m.jumpHint = '';
  m.list = m.all.filter((e) => (e.up ? !q : (q.startsWith('.') || !e.name.startsWith('.')) && (!q || e.name.toLowerCase().includes(q))));
}
function browseDone(paths) {
  const m = U.modal;
  closeModal();
  if (m.target && peers.has(m.target)) return void startSend(m.target, { paths });
  if (m.target) toast('that device left, so your files are staged instead');
  stage(paths);
}
function browseEnter() {
  const m = U.modal;
  if (m.jump) {
    const p = expand(m.filter.chars.join(''));
    if (isDir(p)) return loadDir(m, p);
    if (fs.existsSync(p)) return browseDone([p]);
    return;
  }
  if (m.marks.size) return browseDone([...m.marks.keys()]);
  const e = m.list[m.sel];
  if (!e) return;
  if (e.dir) return loadDir(m, e.path, e.up ? path.basename(m.dir) : null);
  browseDone([e.path]);
}
function browseKey(k) {
  const m = U.modal, e = m.list[m.sel], up = () => { const p = path.dirname(m.dir); if (p !== m.dir) loadDir(m, p, path.basename(m.dir)); };
  if (k.name === 'escape') { if (m.filter.chars.length) { m.filter = field(); applyFilter(m); } else closeModal(); }
  else if (k.name === 'paste' && parsePaths(k.text)) browseDone(parsePaths(k.text));
  else if (k.name === 'up' || (k.name === 'ctrl' && k.ch === 'p')) m.sel = Math.max(0, m.sel - 1);
  else if (k.name === 'down' || (k.name === 'ctrl' && k.ch === 'n')) m.sel = Math.min(m.list.length - 1, m.sel + 1);
  else if (k.name === 'pageup') m.sel = Math.max(0, m.sel - (m.listH || 10));
  else if (k.name === 'pagedown') m.sel = Math.min(m.list.length - 1, m.sel + (m.listH || 10));
  else if (k.name === 'right' && e && e.dir && !m.jump) loadDir(m, e.path, e.up ? path.basename(m.dir) : null);
  else if ((k.name === 'left' || k.name === 'backspace') && !m.filter.chars.length) up();
  else if (k.name === 'enter') browseEnter();
  else if (k.name === 'char' && k.ch === ' ' && !m.jump) {
    if (e && !e.up) { if (m.marks.has(e.path)) m.marks.delete(e.path); else m.marks.set(e.path, e.dir ? 0 : e.size); m.sel = Math.min(m.list.length - 1, m.sel + 1); }
  } else if (k.name === 'ctrl' && k.ch === 'a') {
    const items = m.list.filter((x) => !x.up && !x.dir), all = items.length && items.every((x) => m.marks.has(x.path));
    for (const x of items) all ? m.marks.delete(x.path) : m.marks.set(x.path, x.size);
  } else if (k.name === 'tab' && m.list.filter((x) => !x.up).length === 1) { const only = m.list.find((x) => !x.up); if (only.dir) loadDir(m, only.path); }
  else if (editField(m.filter, k)) applyFilter(m);
}

/* ---------- interface: input routing ---------- */
function onKey(k) {
  if (k.name === 'ctrl' && k.ch === 'c') { if (U.modal && U.modal.type === 'quit') exitApp(0); else quit(); return draw(); }
  if (k.name === 'ctrl' && k.ch === 'z' && !WIN) return suspend();
  if (k.name === 'ctrl' && k.ch === 'l') { prevLines = []; return draw(); }
  if (k.name === 'mouse') { onMouse(k); return draw(); }
  if (asks.length) {
    if (k.name === 'char' && /^[yY]$/.test(k.ch)) askAnswer(true);
    else if ((k.name === 'char' && /^[nN]$/.test(k.ch)) || k.name === 'escape') askAnswer(false);
    else if (k.name === 'char' && k.ch === 'a') U.askAuto = !U.askAuto;
    return draw();
  }
  if (U.modal) {
    const t = U.modal.type;
    if (t === 'help') { if (['escape', 'enter'].includes(k.name) || (k.name === 'char' && /^[q?]$/.test(k.ch))) closeModal(); }
    else if (t === 'quit') { if (k.name === 'char' && /^[yYq]$/.test(k.ch)) exitApp(0); else if (k.name === 'escape' || (k.name === 'char' && /^[nN]$/.test(k.ch))) closeModal(); }
    else ({ pair: pairKey, input: inputKey, note: noteKey, browse: browseKey })[t](k);
    return draw();
  }
  if (k.name === 'paste') { onPaste(k.text); return draw(); }
  mainKey(k);
  draw();
}
function mainKey(k) {
  const n = peers.size, p = selPeer();
  if (k.name === 'char' && !k.alt) {
    const fn = {
      f: () => openBrowse(null), t: () => openNote(p && p.id), c: openPair, r: openRename, o: openOut, '?': openHelp, q: quit, E: sendEveryone, X: clearHistory,
      p: () => { if (!n && !room) { setRoom(newCode()); toast('private room ' + pretty(room) + ' · press c to share it'); } },
    }[k.ch];
    if (fn) return fn();
  }
  if (k.name === 'tab' || k.name === 'backtab') return toggleFocus();
  if (k.name === 'escape') { if (U.staged) clearStaged(); else U.focus = 'near'; return; }
  if (U.focus === 'act') {
    const len = actEntries().length;
    if (k.name === 'up' || (k.name === 'char' && k.ch === 'k')) U.actSel = Math.max(0, U.actSel - 1);
    else if (k.name === 'down' || (k.name === 'char' && k.ch === 'j')) U.actSel = Math.min(len - 1, U.actSel + 1);
    else if (k.name === 'home') U.actSel = 0;
    else if (k.name === 'end') U.actSel = len - 1;
    else if (k.name === 'enter') actAction('open');
    else if (k.name === 'delete' || k.name === 'backspace') actAction('dismiss');
    else if (k.name === 'char') ({ y: 'copy', d: 'folder', x: 'dismiss', R: 'retry' })[k.ch] && actAction({ y: 'copy', d: 'folder', x: 'dismiss', R: 'retry' }[k.ch]);
    return;
  }
  if (!n) return;
  const cols = U.gridCols || 1, mv = { left: -1, right: 1, up: -cols, down: cols }[k.name] ?? (k.name === 'char' ? { h: -1, l: 1, k: -cols, j: cols }[k.ch] : undefined);
  if (mv !== undefined) U.sel = Math.max(0, Math.min(n - 1, U.sel + mv));
  else if (k.name === 'home') U.sel = 0;
  else if (k.name === 'end') U.sel = n - 1;
  else if (k.name === 'enter' || (k.name === 'char' && k.ch === ' ')) sendTo(p.id);
  else if (k.name === 'char' && k.ch === 'n') openNote(p.id);
}
function onMouse(k) {
  if (k.wheel) {
    const d = k.wheel === 'up' ? -1 : 1, m = U.modal;
    if (asks.length) return;
    if (m && m.type === 'browse') m.sel = Math.max(0, Math.min(m.list.length - 1, m.sel + d * 2));
    else if (!m && U.focus === 'act') U.actSel = Math.max(0, Math.min(actEntries().length - 1, U.actSel + d));
    else if (!m) U.sel = Math.max(0, Math.min(peers.size - 1, U.sel + d));
    return;
  }
  if (k.release || k.motion || k.button !== 0) return;
  for (let i = U.hits.length - 1; i >= 0; i--) {
    const h = U.hits[i];
    if (k.x >= h.x && k.x < h.x + h.w && k.y >= h.y && k.y < h.y + h.h) return void h.fn(k);
  }
}
function suspend() {
  restoreTerm();
  process.once('SIGCONT', () => { enterTerm(U.mouse); draw(); });
  process.kill(process.pid, 'SIGTSTP');
}
async function exitApp(code = 0) {
  if (exiting) return;
  exiting = true;
  restoreTerm();
  await stopCore();
  if (HOSTED) HOSTED.server.close();
  process.exit(code);
}

async function runTui(o) {
  if (!process.stdin.isTTY || !process.stdout.isTTY) { say('localdrop: the interface needs an interactive terminal. in scripts, use "localdrop send" or "localdrop recv".'); return 2; }
  U.mouse = !o.f['no-mouse'] && !process.env.LOCALDROP_NO_MOUSE;
  try { await engine(); } catch (e) { say('localdrop: ' + e.message); return 1; }
  setTheme(await detectTheme(o.f.theme || process.env.LOCALDROP_THEME || conf.theme));
  Object.assign(hooks, {
    change: draw, peers: draw, toast, offer: () => undefined,
    ask: () => { process.stdout.write('\x07'); draw(); },
    done: (c) => {
      if (c.state === 'finished' && c.role === 'recv') toast('received ' + c.label + ' from ' + c.peerName);
      else if (c.state === 'failed' && c.error && c.error !== 'cancelled' && c.error !== 'switched rooms') toast(c.error, true);
    },
  });
  keyHandler = onKey;
  process.stdout.on('resize', () => { prevLines = []; draw(); });
  process.on('SIGTERM', () => exitApp(143));
  process.on('SIGHUP', () => exitApp(129));
  process.on('SIGINT', () => exitApp(130));
  process.on('uncaughtException', (e) => { restoreTerm(); debug(e); process.stderr.write('localdrop crashed: ' + ((e && e.stack) || e) + '\n'); process.exit(1); });
  process.on('unhandledRejection', (e) => { debug(e); toast('something went wrong: ' + ((e && e.message) || e), true); });
  enterTerm(U.mouse);
  const missing = o.files.filter((f) => !fs.existsSync(expand(f)));
  if (o.files.length > missing.length) stage(o.files.filter((f) => fs.existsSync(expand(f))));
  if (missing.length) toast('no such file: ' + missing.join(', '), true);
  if (HOSTED) toast(HOSTED.lan ? 'hosting on ' + HOSTED.lan.replace(/\/$/, '') + (HOSTED.hasPage ? '' : ' · web page missing, terminals only') : 'hosting on this computer only: no network found', !HOSTED.hasPage || !HOSTED.lan);
  if (SERVER) startCore(); else openSetup();
  render();
  setInterval(() => {
    if (!termOn) return;
    tickRates();
    const busyUI = !peers.size || conns.size || asks.length || U.toasts.length || online === null;
    if (busyUI || Date.now() - U.drawn > 250) render();
  }, 100);
  return new Promise(() => {});
}

/* ---------- headless commands ---------- */
const ERR_TTY = !!process.stderr.isTTY, PAINT = ERR_TTY && !process.env.NO_COLOR;
const C = {
  b: (s) => (PAINT ? '\x1b[1m' + s + '\x1b[22m' : s),
  dim: (s) => (PAINT ? '\x1b[2m' + s + '\x1b[22m' : s),
  err: (s) => (PAINT ? '\x1b[31m' + s + '\x1b[39m' : s),
  ok: (s) => (PAINT ? '\x1b[32m' + s + '\x1b[39m' : s),
};
const say = (s) => process.stderr.write(s + '\n');
const bar = (f, n) => { const k = Math.round(clamp01(f) * n); return PAINT ? C.b('━'.repeat(k)) + C.dim('━'.repeat(n - k)) : '━'.repeat(k) + '─'.repeat(n - k); };
function txLine(c) {
  const b = bytesOf(c), f = c.total ? b / c.total : c.state === 'finished' ? 1 : 0, moving = c.state === 'transfer' || c.state === 'finishing';
  const head = (c.role === 'send' ? '↑ ' : '↓ ') + C.b(cut(c.label, 48)) + ' ' + C.dim((c.role === 'send' ? '→ ' : '← ') + c.peerName);
  const st = c.state === 'asking' ? C.dim(c.role === 'send' ? 'waiting for ' + c.peerName + ' to accept…' : 'waiting for you…')
    : c.state === 'connecting' ? C.dim('connecting…')
    : c.state === 'transfer' ? pct(f).padStart(4) + C.dim('  ' + fmtBytes(b) + ' / ' + fmtBytes(c.total) + (c.rate > 0 ? '  ' + fmtBytes(c.rate) + '/s  ' + fmtTime((c.total - b) / c.rate) + ' left' : ''))
    : c.state === 'finishing' ? C.dim('finishing…')
    : c.state === 'finished' ? C.ok('done') + C.dim(' · ' + fmtBytes(c.total) + ' in ' + took(c) + (c.route ? ' · ' + c.route : ''))
    : C.err(c.error || 'failed');
  return head + '  ' + (moving ? bar(f, 24) + ' ' : '') + st;
}
function liveArea(filter) {
  let shown = 0, held = false;
  const clear = () => { if (ERR_TTY && shown) process.stderr.write(`\x1b[${shown}A\r\x1b[J`); shown = 0; };
  const paint = () => {
    if (!ERR_TTY || held) return;
    const lines = [...conns.values()].filter((c) => !c.dead && filter(c)).map(txLine);
    if (lines.length) process.stderr.write(lines.map((l) => '\x1b[2K' + l).join('\n') + '\n');
    shown = lines.length;
  };
  const iv = setInterval(() => { tickRates(); clear(); paint(); }, 200);
  return {
    log(s) { clear(); process.stderr.write(s + '\n'); paint(); },
    hold(v) { clear(); held = v; paint(); },
    stop() { clearInterval(iv); clear(); },
  };
}
function matchPeers(spec) {
  const list = [...peers.values()];
  if (!spec) return list.length === 1 ? list : list.length ? null : [];
  const s = spec.toLowerCase();
  if (['all', 'everyone', '*'].includes(s)) return list;
  for (const test of [(n) => n === s, (n) => n.startsWith(s), (n) => n.includes(s)]) {
    const hit = list.filter((p) => test(p.name.toLowerCase()));
    if (hit.length) return hit.length === 1 ? hit : null;
  }
  return [];
}
async function readStdin() { const chunks = []; for await (const ch of process.stdin) chunks.push(ch); return Buffer.concat(chunks); }
function noteOrFile(buf, name) {
  let text = null;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(buf); } catch {}
  if (text != null && !text.trim()) return null;
  if (text != null) text = text.replace(/\r?\n$/, '');
  if (text != null && text.length <= TEXT_MAX * 2 && Array.from(text).length <= TEXT_MAX) return { text };
  const file = name + (text == null ? '.bin' : '.txt');
  say(C.dim(text == null ? 'that is not text, so it goes as ' + file : 'longer than ' + TEXT_MAX.toLocaleString('en') + ' characters, so it goes as ' + file));
  return { files: [{ buf, name: file, size: buf.length }] };
}
function readKey() {
  return new Promise((res) => {
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.once('data', (d) => {
      process.stdin.setRawMode(false);
      process.stdin.pause();
      const k = d.toString();
      if (k === '\x03') { process.kill(process.pid, 'SIGINT'); return res(false); }
      res(k === 'y' || k === 'Y');
    });
  });
}
async function waitOnline(ms) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) { if (online === true) return true; if (online === false && fails >= 3) break; await sleep(100); }
  return online === true;
}
const where = () => (room ? 'room ' + pretty(room) : 'this network');
const whyOff = () => (offWhy || 'relay unreachable').replace(/ · retrying…$/, '') + ' (' + SERVER + ')';

async function cmdSend(o) {
  let what;
  if (o.f.text != null) { what = noteOrFile(Buffer.from(String(o.f.text)), 'note'); if (!what) { say('localdrop: --text is empty'); return 2; } }
  else if (o.files.length && o.files[0] !== '-') {
    for (const f of o.files) if (!fs.existsSync(expand(f))) { say(C.err('localdrop: no such file: ' + f)); return 2; }
    what = { paths: o.files.map(expand) };
  } else if (!process.stdin.isTTY) {
    what = noteOrFile(await readStdin(), 'stdin');
    if (!what) { say('localdrop: nothing to send on stdin'); return 2; }
  } else { say('usage: localdrop send <files...> [--to <name>]   (localdrop --help)'); return 2; }
  await engine();
  startCore();
  say(C.dim(`looking for ${o.f.to ? '"' + o.f.to + '"' : 'a device'} on ${where()} as "${me.name}"…`));
  if (!(await waitOnline(12000))) { say(C.err('localdrop: ' + whyOff())); return 1; }
  let targets = [];
  for (let t0 = Date.now(); Date.now() - t0 < 15000; await sleep(250)) { targets = matchPeers(o.f.to); if (targets === null || targets.length) break; }
  if (!targets || !targets.length) {
    const names = [...peers.values()].map((p) => '"' + p.name + '"').join(', ');
    say(C.err('localdrop: ' + (!names ? 'no devices found on ' + where() + '. open localdrop on the other device first.'
      : (targets === null ? (o.f.to ? `"${o.f.to}" matches more than one device: ` : 'more than one device is here, pick one with --to: ') : `no device matches "${o.f.to}". nearby: `) + names)));
    return 1;
  }
  const live = liveArea(() => true), cs = [];
  hooks.toast = (t, bad) => live.log(bad ? C.err(t) : C.dim(t));
  hooks.done = (c) => live.log(txLine(c));
  for (const p of targets) { const c = await startSend(p.id, what); if (c) cs.push(c); }
  if (!ERR_TTY) for (const c of cs) say(txLine(c));
  while (cs.some((c) => !c.dead)) await sleep(100);
  live.stop();
  return cs.length && cs.every((c) => c.state === 'finished') ? 0 : 1;
}

async function cmdRecv(o) {
  await engine();
  const want = o.f.count ? Math.max(1, parseInt(o.f.count, 10) || 1) : Infinity, from = String(o.f.from || '').toLowerCase();
  const interactive = !!process.stdin.isTTY && !o.f.yes;
  let finished = 0, failed = 0, prompting = false, resolveAll;
  const all = new Promise((r) => { resolveAll = r; });
  const live = liveArea((c) => c.role === 'recv' && c.state !== 'asking');
  hooks.toast = (t, bad) => live.log(bad ? C.err(t) : C.dim(t));
  hooks.offer = (c) => from && !c.peerName.toLowerCase().startsWith(from) ? 'decline' : o.f.yes ? 'accept' : interactive ? undefined : 'decline';
  hooks.ask = () => next();
  hooks.received = (it) => {
    const out = it.text != null ? it.text + (it.text.endsWith('\n') ? '' : '\n') : it.path + '\n';
    process.stdout.write(process.stdout.isTTY ? out.replace(/[\x00-\x08\x0b-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069]/g, '') : out);
  };
  hooks.done = (c) => {
    if (c.role !== 'recv' || (!c.error && c.state !== 'finished')) return;
    live.log(txLine(c));
    if (c.state === 'finished') finished++; else failed++;
    if (finished + failed >= want) resolveAll();
  };
  async function next() {
    const c = asks.find((x) => !x.dead);
    if (prompting || !c) return;
    prompting = true;
    live.hold(true);
    process.stderr.write(`${C.b(c.peerName)} wants to send ${C.b(c.label)} ${C.dim('(' + fmtBytes(c.total) + ')')}. accept? [y/N] `);
    const yes = await readKey();
    process.stderr.write(yes ? 'y\n' : 'n\n');
    if (c.dead) say(C.dim('that request expired'));
    else if (yes) accept(c);
    else decline(c);
    live.hold(false);
    prompting = false;
    next();
  }
  startCore();
  if (!(await waitOnline(12000))) { live.stop(); say(C.err('localdrop: ' + whyOff())); return 1; }
  live.log(C.dim(`ready as "${me.name}" on ${where()} · saving to ${tilde(OUT)}${o.f.yes ? ' · accepting everything' : ''} · ctrl+c to stop`));
  await all;
  live.stop();
  return failed && !finished ? 1 : 0;
}

async function cmdDevices(o) {
  startCore();
  if (!(await waitOnline(8000))) { say(C.err('localdrop: ' + whyOff())); return 1; }
  const list = [...peers.values()];
  if (o.f.json) process.stdout.write(JSON.stringify(list.map(({ id, name, kind, os, bg }) => ({ id, name, kind, os, background: bg })), null, 2) + '\n');
  else if (!list.length) say(C.dim('no devices on ' + where() + ' yet'));
  else {
    const w = Math.max(...list.map((p) => p.name.length));
    for (const p of list) process.stdout.write(p.name.padEnd(w + 2) + p.kind + (p.os ? ' · ' + p.os : '') + (p.bg ? '  (in background)' : '') + '\n');
  }
  return 0;
}

async function cmdServe(o) {
  const r = await startRelay({ port: o.f.port || 8080, bind: o.f.bind || '0.0.0.0', web: o.f.web ? expand(o.f.web) : '' });
  const url = r.lan || r.local;
  say(C.b('localdrop relay') + C.dim(' ' + VERSION));
  say('listening on ' + C.b(url) + (r.lan ? C.dim('  (also ' + r.local + ')') : ''));
  say(r.hasPage ? C.dim('web page: ' + r.web) : C.err('web page: index.php not found, only terminals can join. use --web <file>'));
  const rows = r.lan && process.stderr.isTTY && qrRows(url);
  if (rows) { say(''); for (const l of rows) say('  ' + (PAINT ? '\x1b[30;107m' + l + '\x1b[0m' : l)); say(''); }
  say(C.dim('open the address on your devices · ctrl+c to stop'));
  await new Promise((res) => { process.once('SIGINT', res); process.once('SIGTERM', res); });
  r.server.close();
  return 0;
}

/* ---------- main ---------- */
let HOSTED = null;
async function main() {
  const [maj, min] = process.versions.node.split('.').map(Number);
  if (maj < 18 || (maj === 18 && min < 20)) { say('localdrop needs Node.js 18.20 or newer (this is ' + process.version + ').'); return 1; }
  let o;
  try { o = parseArgs(process.argv.slice(2)); } catch (e) { say('localdrop: ' + e.message + '\ntry: localdrop --help'); return 2; }
  if (o.f.help || o.cmd === 'help') { process.stdout.write(HELP); return 0; }
  if (o.f.version || o.cmd === 'version') { process.stdout.write('localdrop ' + VERSION + '\n'); return 0; }
  me.name = cleanName(o.f.name || process.env.LOCALDROP_NAME || conf.name) || pick(ADJ) + ' ' + pick(ANI);
  if (!conf.name && !o.f.name && !process.env.LOCALDROP_NAME) saveConf({ name: me.name });
  const dl = path.join(HOME, 'Downloads');
  OUT = expand(o.f.out || process.env.LOCALDROP_OUT || conf.out || (isDir(dl) ? dl : process.cwd()));
  ICE = (process.env.LOCALDROP_ICE || (Array.isArray(conf.ice) ? conf.ice.join(',') : '')).split(',').map((s) => s.trim()).filter(Boolean);
  if (!ICE.length) ICE = DEFAULT_ICE;
  if (o.f.room != null) {
    const v = normCode(o.f.room);
    if (!validCode(v)) { say('localdrop: room codes are 6 to 32 letters or digits'); return 2; }
    room = v;
  }
  if (o.cmd === 'serve') return cmdServe(o);
  if (o.cmd === 'host') {
    HOSTED = await startRelay({ port: o.f.port || 8080, bind: o.f.bind || '0.0.0.0', web: o.f.web ? expand(o.f.web) : '' });
    SERVER = HOSTED.local;
    SHARE = HOSTED.lan || HOSTED.local;
  } else SERVER = normServer(o.f.server || process.env.LOCALDROP_SERVER || conf.server);
  if (o.cmd === 'tui' || o.cmd === 'host') return runTui(o);
  if (!SERVER) { say('localdrop: no relay configured. pass --server <url> (where index.php is hosted), set LOCALDROP_SERVER, or run "localdrop host".'); return 2; }
  let quitting = false;
  const bye = async (code) => { if (quitting) return; quitting = true; await stopCore(); process.exit(code); };
  process.on('SIGINT', () => bye(130));
  process.on('SIGTERM', () => bye(143));
  const code = await (o.cmd === 'send' ? cmdSend(o) : o.cmd === 'recv' ? cmdRecv(o) : cmdDevices(o));
  await bye(code);
}
main().then((code) => { if (typeof code === 'number') process.exit(code); }, (e) => {
  try { if (typeof restoreTerm === 'function') restoreTerm(); } catch {}
  process.stderr.write('localdrop: ' + ((e && e.message) || e) + '\n');
  debug(e);
  process.exit(1);
});
