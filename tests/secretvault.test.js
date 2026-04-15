const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'src', 'cli.js');
const INSTALL = path.join(ROOT, 'install.sh');
const UNINSTALL = path.join(ROOT, 'uninstall.sh');
const BIN_DIR = path.join(ROOT, 'tmp', 'test-bin');
const MASTER_KEY = Buffer.alloc(32, 7).toString('hex');
const ENV = { ...process.env, SECRETVAULT_MASTER_KEY: MASTER_KEY };
const DIRS = ['secrets', 'grants', 'audit', 'tmp'];

function run(args, extra = {}) {
  return spawnSync('node', [CLI, ...args], { cwd: ROOT, env: ENV, encoding: 'utf8', ...extra });
}

function runShell(script) {
  return spawnSync('bash', ['-lc', script], { cwd: ROOT, env: ENV, encoding: 'utf8' });
}

function clean() {
  for (const dir of DIRS) {
    const root = path.join(ROOT, dir);
    for (const entry of fs.readdirSync(root)) {
      if (entry === '.gitkeep') continue;
      fs.rmSync(path.join(root, entry), { recursive: true, force: true });
    }
  }
  fs.rmSync(BIN_DIR, { recursive: true, force: true });
  fs.rmSync(path.join(ROOT, 'config', 'allow-all-keyman.js'), { force: true });
}

test.beforeEach(clean);
test.after(clean);

test('install script creates runnable symlink', () => {
  const install = spawnSync('bash', [INSTALL, BIN_DIR], { cwd: ROOT, env: ENV, encoding: 'utf8' });
  assert.equal(install.status, 0, install.stderr);
  const linked = path.join(BIN_DIR, 'supervisor-secretvault');
  assert.equal(fs.existsSync(linked), true);
  const init = spawnSync(linked, ['init'], { cwd: ROOT, env: ENV, encoding: 'utf8' });
  assert.equal(init.status, 0, init.stderr);
  const uninstall = spawnSync('bash', [UNINSTALL, BIN_DIR], { cwd: ROOT, env: ENV, encoding: 'utf8' });
  assert.equal(uninstall.status, 0, uninstall.stderr);
  assert.equal(fs.existsSync(linked), false);
});

test('seed keeps fake secret encrypted at rest', () => {
  assert.equal(run(['init']).status, 0);
  const seeded = run(['seed', '--alias', 'fake-openai', '--label', 'fake-label', '--value', 'FAKE-SECRET-123']);
  assert.equal(seeded.status, 0, seeded.stderr);
  const stored = fs.readFileSync(path.join(ROOT, 'secrets', 'fake-openai.json'), 'utf8');
  assert.match(stored, /aes-256-gcm/);
  assert.equal(stored.includes('FAKE-SECRET-123'), false);
  assert.equal(stored.includes('fake-label'), false);
});

test('request uses forwarded authorization path and creates usable grant', () => {
  assert.equal(run(['init']).status, 0);
  assert.equal(run(['seed', '--alias', 'fake-github', '--value', 'FAKE-TOKEN-456']).status, 0);
  fs.writeFileSync(path.join(ROOT, 'config', 'allow-all-keyman.js'), '#!/usr/bin/env node\nprocess.stdout.write(JSON.stringify({approved:true, authorizationPath:"keyman-forward"}))\n');
  fs.chmodSync(path.join(ROOT, 'config', 'allow-all-keyman.js'), 0o755);
  const config = {
    vault: { defaultTtlSeconds: 180, maxTtlSeconds: 3600, interactiveFallback: true },
    keyman: { command: './allow-all-keyman.js' },
  };
  fs.writeFileSync(path.join(ROOT, 'config', 'default.json'), JSON.stringify(config, null, 2));
  const granted = run(['request', '--alias', 'fake-github', '--purpose', 'integration-test', '--agent', 'tester']);
  assert.equal(granted.status, 0, granted.stderr);
  const body = JSON.parse(granted.stdout);
  assert.equal(body.authorizationPath, 'keyman-forward');
  const payload = fs.readFileSync(body.path, 'utf8');
  assert.equal(payload, 'FAKE-TOKEN-456');
  const grantMeta = JSON.parse(fs.readFileSync(path.join(ROOT, 'grants', `${body.grantId}.json`), 'utf8'));
  assert.equal(grantMeta.state, 'issued');
});

test('ttl expiry cleanup removes expired grant and logs cleanup', async () => {
  assert.equal(run(['init']).status, 0);
  assert.equal(run(['seed', '--alias', 'fake-short', '--value', 'FAKE-SHORT']).status, 0);
  fs.writeFileSync(path.join(ROOT, 'config', 'allow-all-keyman.js'), '#!/usr/bin/env node\nprocess.stdout.write(JSON.stringify({approved:true, authorizationPath:"keyman-forward"}))\n');
  fs.chmodSync(path.join(ROOT, 'config', 'allow-all-keyman.js'), 0o755);
  fs.writeFileSync(path.join(ROOT, 'config', 'default.json'), JSON.stringify({ vault: { defaultTtlSeconds: 1, maxTtlSeconds: 3600, interactiveFallback: true }, keyman: { command: './allow-all-keyman.js' } }, null, 2));
  const granted = run(['request', '--alias', 'fake-short', '--purpose', 'short-ttl', '--ttl', '1']);
  assert.equal(granted.status, 0, granted.stderr);
  const body = JSON.parse(granted.stdout);
  assert.equal(fs.existsSync(body.path), true);
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1200);
  const cleanup = run(['cleanup']);
  assert.equal(cleanup.status, 0, cleanup.stderr);
  assert.equal(fs.existsSync(body.path), false);
  assert.equal(fs.existsSync(path.join(ROOT, 'grants', `${body.grantId}.json`)), false);
  const auditFile = path.join(ROOT, 'audit', `${new Date().toISOString().slice(0, 10)}.jsonl`);
  const log = fs.readFileSync(auditFile, 'utf8');
  assert.match(log, /grant_issued/);
  assert.match(log, /grant_cleanup/);
  assert.equal(log.includes('FAKE-SHORT'), false);
});

test('request denies unattended fallback when keyman missing', () => {
  fs.writeFileSync(path.join(ROOT, 'config', 'default.json'), JSON.stringify({ vault: { defaultTtlSeconds: 180, maxTtlSeconds: 3600, interactiveFallback: true }, keyman: { command: './missing-keyman.js' } }, null, 2));
  assert.equal(run(['init']).status, 0);
  assert.equal(run(['seed', '--alias', 'fake-deny', '--value', 'FAKE-DENY']).status, 0);
  const denied = run(['request', '--alias', 'fake-deny', '--purpose', 'non-interactive']);
  assert.equal(denied.status, 4);
  const body = JSON.parse(denied.stdout);
  assert.equal(body.authorizationPath, 'local-human-fallback-unavailable');
});

test('SECRETVAULT_ROOT isolates runtime layout while keeping absolute Keyman path valid', () => {
  const isolatedRoot = path.join(ROOT, 'tmp', 'isolated-root');
  fs.rmSync(isolatedRoot, { recursive: true, force: true });
  fs.mkdirSync(path.join(isolatedRoot, 'config'), { recursive: true });
  fs.mkdirSync(path.join(isolatedRoot, 'secrets'), { recursive: true });
  fs.mkdirSync(path.join(isolatedRoot, 'grants'), { recursive: true });
  fs.mkdirSync(path.join(isolatedRoot, 'audit'), { recursive: true });
  fs.mkdirSync(path.join(isolatedRoot, 'tmp'), { recursive: true });

  const keyman = path.join(ROOT, 'config', 'allow-all-keyman.js');
  fs.writeFileSync(keyman, '#!/usr/bin/env node\nprocess.stdout.write(JSON.stringify({approved:true, authorizationPath:"keyman-forward"}))\n');
  fs.chmodSync(keyman, 0o755);
  fs.writeFileSync(
    path.join(isolatedRoot, 'config', 'default.json'),
    JSON.stringify({
      vault: { defaultTtlSeconds: 180, maxTtlSeconds: 3600, interactiveFallback: false },
      keyman: { command: keyman },
    }, null, 2)
  );

  const env = { ...ENV, SECRETVAULT_ROOT: isolatedRoot };
  const init = spawnSync('node', [CLI, 'init'], { cwd: ROOT, env, encoding: 'utf8' });
  assert.equal(init.status, 0, init.stderr);

  const seed = spawnSync('node', [CLI, 'seed', '--alias', 'fake-iso', '--value', 'FAKE-ISO'], { cwd: ROOT, env, encoding: 'utf8' });
  assert.equal(seed.status, 0, seed.stderr);
  assert.equal(fs.existsSync(path.join(isolatedRoot, 'secrets', 'fake-iso.json')), true);
  assert.equal(fs.existsSync(path.join(ROOT, 'secrets', 'fake-iso.json')), false);

  const granted = spawnSync('node', [CLI, 'request', '--alias', 'fake-iso', '--purpose', 'isolated-test', '--agent', 'tester'], { cwd: ROOT, env, encoding: 'utf8' });
  assert.equal(granted.status, 0, granted.stderr);
  const body = JSON.parse(granted.stdout);
  assert.equal(body.authorizationPath, 'keyman-forward');
  assert.equal(body.path.startsWith(path.join(isolatedRoot, 'grants')), true);
});
