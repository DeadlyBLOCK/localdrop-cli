#!/usr/bin/env node
// builds dist/localdrop: one executable with node, localdrop.mjs, its webrtc engine and the web page inside
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const root = path.dirname(fileURLToPath(import.meta.url));
const dist = path.join(root, 'dist');
const win = process.platform === 'win32', mac = process.platform === 'darwin';
const out = path.join(dist, win ? 'localdrop.exe' : 'localdrop');
const rel = path.relative(process.cwd(), out) || out;
const require = createRequire(import.meta.url);
const fail = (m) => { console.error('build: ' + m); process.exit(1); };
const step = (m) => console.log('  ' + m);

const [maj, min] = process.versions.node.split('.').map(Number);
if (maj < 20 || (maj === 20 && min < 12)) fail(`building needs Node.js 20.12 or newer (this is ${process.version})`);

const libc = process.platform === 'linux' ? (process.report.getReport().header.glibcVersionRuntime ? 'gnu' : 'musl') : '';
const target = { linux: `linux-${process.arch}-${libc}`, darwin: `darwin-${process.arch}`, win32: `win32-${process.arch}-msvc`, android: `android-${process.arch}` }[process.platform];
let addon, esbuild, postject;
try { addon = require.resolve(`@node-datachannel/${target}/node_datachannel.node`); } catch { fail(`the webrtc engine for ${target} is missing, run: npm install`); }
try { esbuild = await import('esbuild'); postject = require.resolve('postject/dist/cli.js'); } catch { fail('the build tools are missing, run: npm install'); }

fs.rmSync(dist, { recursive: true, force: true });
fs.mkdirSync(dist, { recursive: true });
const cjs = path.join(dist, 'localdrop.cjs'), blob = path.join(dist, 'localdrop.blob'), conf = path.join(dist, 'sea.json');

step('bundle   localdrop.mjs');
await esbuild.build({
  entryPoints: [path.join(root, 'localdrop.mjs')], outfile: cjs, bundle: true, platform: 'node', format: 'cjs', target: 'node20',
  external: ['node-datachannel'], logLevel: 'error', logOverride: { 'empty-import-meta': 'silent' },
});
fs.writeFileSync(cjs, fs.readFileSync(cjs, 'utf8').replace(/^#!.*\n/, ''));

step(`pack     webrtc engine (${target}) and web page`);
fs.writeFileSync(conf, JSON.stringify({
  main: cjs, output: blob, disableExperimentalSEAWarning: true,
  assets: { 'node_datachannel.node': addon, 'index.php': path.join(root, 'index.php') },
}));
execFileSync(process.execPath, ['--experimental-sea-config', conf], { stdio: ['ignore', 'ignore', 'inherit'] });

step(`build    ${rel}`);
fs.copyFileSync(process.execPath, out);
fs.chmodSync(out, 0o755);
if (mac) execFileSync('codesign', ['--remove-signature', out]);
try {
  execFileSync(process.execPath, [postject, out, 'NODE_SEA_BLOB', blob, '--sentinel-fuse', 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2', ...(mac ? ['--macho-segment-name', 'NODE_SEA'] : [])], { stdio: ['ignore', 'ignore', 'pipe'] });
} catch (e) { fail('could not write the executable:\n' + (e.stderr || e.message)); }
if (mac) execFileSync('codesign', ['--sign', '-', out]);
for (const f of [cjs, blob, conf]) fs.rmSync(f, { force: true });

console.log(`\n  done: ${rel} (${Math.round(fs.statSync(out).size / 1048576)} MB, runs without node)`);
console.log(win ? '  install: move it to a folder on your PATH\n' : `  install: sudo mkdir -p /usr/local/bin && sudo mv ${rel} /usr/local/bin/\n`);
