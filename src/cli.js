#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(process.env.SECRETVAULT_ROOT || path.resolve(__dirname, '..'));
const DIRS = {
  secrets: path.join(ROOT, 'secrets'),
  grants: path.join(ROOT, 'grants'),
  audit: path.join(ROOT, 'audit'),
  config: path.join(ROOT, 'config'),
  tmp: path.join(ROOT, 'tmp'),
};
const CONFIG_PATH = process.env.SECRETVAULT_CONFIG_PATH
  ? path.resolve(process.env.SECRETVAULT_CONFIG_PATH)
  : path.join(DIRS.config, 'default.json');
const MASTER_KEY_ENV = 'SECRETVAULT_MASTER_KEY';

function ensureLayout() {
  Object.values(DIRS).forEach((dir) => fs.mkdirSync(dir, { recursive: true, mode: 0o700 }));
}

function loadConfig() {
  return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
}

function parseArgs(argv) {
  const result = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token.startsWith('--')) {
      const [rawKey, inline] = token.slice(2).split('=');
      if (inline !== undefined) {
        result[rawKey] = inline;
      } else if (argv[i + 1] && !argv[i + 1].startsWith('--')) {
        result[rawKey] = argv[++i];
      } else {
        result[rawKey] = true;
      }
    } else {
      result._.push(token);
    }
  }
  return result;
}

function getMasterKey() {
  const value = process.env[MASTER_KEY_ENV];
  if (!value) {
    throw new Error(`${MASTER_KEY_ENV} is required`);
  }
  const normalized = /^[a-f0-9]{64}$/i.test(value) ? Buffer.from(value, 'hex') : Buffer.from(value, 'base64');
  if (normalized.length !== 32) {
    throw new Error(`${MASTER_KEY_ENV} must decode to 32 bytes`);
  }
  return normalized;
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function aliasFingerprint(alias) {
  return sha256(alias).slice(0, 16);
}

function encryptString(plaintext, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    alg: 'aes-256-gcm',
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
  };
}

function decryptString(payload, key) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(payload.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(payload.tag, 'base64'));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(payload.ciphertext, 'base64')),
    decipher.final(),
  ]);
  return plaintext.toString('utf8');
}

function appendAudit(event) {
  const day = new Date().toISOString().slice(0, 10);
  const target = path.join(DIRS.audit, `${day}.jsonl`);
  fs.appendFileSync(target, `${JSON.stringify({ ts: new Date().toISOString(), ...event })}\n`, { mode: 0o600 });
}

function secretPath(alias) {
  return path.join(DIRS.secrets, `${alias}.json`);
}

function grantPath(grantId) {
  return path.join(DIRS.grants, `${grantId}.json`);
}

function writeJson(target, value, mode = 0o600) {
  fs.writeFileSync(target, `${JSON.stringify(value, null, 2)}\n`, { mode });
}

function readJson(target) {
  return JSON.parse(fs.readFileSync(target, 'utf8'));
}

function fileExists(target) {
  try {
    fs.accessSync(target, fs.constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

function resolveKeymanCommand(config) {
  const configured = config.keyman && config.keyman.command;
  if (!configured) return null;
  return path.resolve(DIRS.config, configured);
}

function requestDecision(request, config) {
  const keymanCmd = resolveKeymanCommand(config);
  if (keymanCmd && fileExists(keymanCmd)) {
    const traceId = crypto.randomUUID();
    const authorizationRequest = {
      ...request,
      requester: request.agent || null,
      secret_alias: request.alias,
      reason: request.purpose,
      ttl_seconds: request.ttlSeconds,
      trace_id: traceId,
      request_id: traceId,
      scope: request.alias,
    };
    const result = spawnSync(keymanCmd, ['authorize'], {
      input: JSON.stringify(authorizationRequest),
      encoding: 'utf8',
      env: process.env,
    });
    if (result.status !== 0) {
      appendAudit({
        type: 'authorization_error',
        aliasFingerprint: request.aliasFingerprint,
        purpose: request.purpose,
        authorizationPath: 'keyman-forward',
        stderr: (result.stderr || '').trim().slice(0, 400),
      });
      return { approved: false, authorizationPath: 'keyman-forward', reason: 'keyman-error' };
    }
    try {
      const parsed = JSON.parse(result.stdout || '{}');
      return { ...parsed, authorizationPath: parsed.authorizationPath || 'keyman-forward' };
    } catch {
      return { approved: false, authorizationPath: 'keyman-forward', reason: 'keyman-invalid-response' };
    }
  }

  if (!config.vault.interactiveFallback || !process.stdin.isTTY || !process.stdout.isTTY) {
    appendAudit({
      type: 'authorization_denied',
      aliasFingerprint: request.aliasFingerprint,
      purpose: request.purpose,
      authorizationPath: 'local-human-fallback-unavailable',
      agent: request.agent || null,
      issued: false,
      reason: 'no-keyman-and-no-local-human',
    });
    return { approved: false, authorizationPath: 'local-human-fallback-unavailable', reason: 'human-presence-required' };
  }

  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(
      `Secret request for alias ${request.alias} (fp ${request.aliasFingerprint}) purpose=\"${request.purpose}\" ttl=${request.ttlSeconds}s agent=${request.agent || 'unknown'} approve? [y/N]: `,
      (answer) => {
        rl.close();
        const approved = /^y(es)?$/i.test(String(answer).trim());
        resolve({
          approved,
          authorizationPath: 'local-human-fallback-interactive',
          reason: approved ? 'approved-by-local-human' : 'denied-by-local-human',
        });
      }
    );
  });
}

function cleanupExpiredGrants() {
  ensureLayout();
  let cleaned = 0;
  for (const entry of fs.readdirSync(DIRS.grants)) {
    if (!entry.endsWith('.json')) continue;
    const target = path.join(DIRS.grants, entry);
    try {
      const grant = readJson(target);
      const expired = Date.now() >= Date.parse(grant.expiresAt);
      const missingPayload = !grant.secretFile || !fileExists(path.join(DIRS.grants, grant.secretFile));
      if (expired || missingPayload) {
        if (grant.secretFile) {
          const payloadPath = path.join(DIRS.grants, grant.secretFile);
          if (fileExists(payloadPath)) fs.rmSync(payloadPath, { force: true });
        }
        fs.rmSync(target, { force: true });
        cleaned += 1;
        appendAudit({
          type: 'grant_cleanup',
          grantId: grant.grantId,
          aliasFingerprint: grant.aliasFingerprint,
          cleanupResult: expired ? 'expired-removed' : 'orphan-metadata-removed',
        });
      }
    } catch {
      fs.rmSync(target, { force: true });
      cleaned += 1;
      appendAudit({ type: 'grant_cleanup', cleanupResult: 'corrupt-metadata-removed', grantFile: entry });
    }
  }
  return cleaned;
}

async function cmdInit() {
  ensureLayout();
  loadConfig();
  cleanupExpiredGrants();
  console.log(JSON.stringify({ ok: true, root: ROOT }));
}

async function cmdSeed(args) {
  const alias = args.alias;
  const value = args.value;
  const label = args.label || 'opaque-secret';
  if (!alias || !value) throw new Error('seed requires --alias and --value');
  if (!/^[a-z0-9][a-z0-9._-]{1,63}$/i.test(alias)) throw new Error('invalid alias');
  ensureLayout();
  const key = getMasterKey();
  const fingerprint = aliasFingerprint(alias);
  const payload = {
    version: 1,
    alias,
    aliasFingerprint: fingerprint,
    labelDigest: sha256(label),
    createdAt: new Date().toISOString(),
    encryptedSecret: encryptString(value, key),
  };
  writeJson(secretPath(alias), payload);
  appendAudit({ type: 'secret_seeded', aliasFingerprint: fingerprint, authorizationPath: 'local-admin', issued: false });
  console.log(JSON.stringify({ ok: true, alias, aliasFingerprint: fingerprint }));
}

async function cmdRequest(args) {
  ensureLayout();
  cleanupExpiredGrants();
  const config = loadConfig();
  const key = getMasterKey();
  const alias = args.alias;
  const purpose = args.purpose || 'unspecified';
  const agent = args.agent || null;
  const ttlRequested = Number(args.ttl || config.vault.defaultTtlSeconds);
  const ttlSeconds = Math.max(1, Math.min(ttlRequested, Number(config.vault.maxTtlSeconds || 3600)));
  if (!alias) throw new Error('request requires --alias');
  const secretFile = secretPath(alias);
  if (!fileExists(secretFile)) {
    const fp = aliasFingerprint(alias);
    appendAudit({ type: 'grant_denied', aliasFingerprint: fp, purpose, agent, authorizationPath: 'precheck', issued: false, reason: 'alias-not-found' });
    process.exitCode = 3;
    console.log(JSON.stringify({ ok: false, error: 'alias-not-found', aliasFingerprint: fp }));
    return;
  }
  const stored = readJson(secretFile);
  const decision = await requestDecision({ alias, aliasFingerprint: stored.aliasFingerprint, purpose, ttlSeconds, agent }, config);
  if (!decision.approved) {
    appendAudit({ type: 'grant_denied', aliasFingerprint: stored.aliasFingerprint, purpose, agent, authorizationPath: decision.authorizationPath, issued: false, ttlSeconds, reason: decision.reason || 'denied' });
    process.exitCode = 4;
    console.log(JSON.stringify({ ok: false, alias, aliasFingerprint: stored.aliasFingerprint, authorizationPath: decision.authorizationPath, error: decision.reason || 'denied' }));
    return;
  }
  const plaintext = decryptString(stored.encryptedSecret, key);
  const grantId = crypto.randomUUID();
  const secretBasename = `${grantId}.secret`;
  const secretGrantPath = path.join(DIRS.grants, secretBasename);
  fs.writeFileSync(secretGrantPath, plaintext, { mode: 0o600 });
  const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();
  const grant = {
    grantId,
    alias,
    aliasFingerprint: stored.aliasFingerprint,
    purpose,
    agent,
    authorizationPath: decision.authorizationPath,
    issued: true,
    ttlSeconds,
    createdAt: new Date().toISOString(),
    expiresAt,
    secretFile: secretBasename,
    state: 'issued',
  };
  writeJson(grantPath(grantId), grant);
  appendAudit({ type: 'grant_issued', grantId, aliasFingerprint: stored.aliasFingerprint, purpose, agent, authorizationPath: decision.authorizationPath, issued: true, ttlSeconds, cleanupResult: 'pending' });
  console.log(JSON.stringify({ ok: true, grantId, path: secretGrantPath, expiresAt, ttlSeconds, aliasFingerprint: stored.aliasFingerprint, authorizationPath: decision.authorizationPath }));
}

async function cmdCleanup() {
  const cleaned = cleanupExpiredGrants();
  console.log(JSON.stringify({ ok: true, cleaned }));
}

async function cmdStatus() {
  ensureLayout();
  const grants = fs.readdirSync(DIRS.grants).filter((entry) => entry.endsWith('.json')).length;
  const secrets = fs.readdirSync(DIRS.secrets).filter((entry) => entry.endsWith('.json')).length;
  console.log(JSON.stringify({ ok: true, secrets, activeGrantMetadata: grants }));
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const command = args._[0];
  switch (command) {
    case 'init': return cmdInit();
    case 'seed': return cmdSeed(args);
    case 'request': return cmdRequest(args);
    case 'cleanup': return cmdCleanup();
    case 'status': return cmdStatus();
    default:
      console.error('Usage: supervisor-secretvault <init|seed|request|cleanup|status> [--flags]');
      process.exitCode = 2;
  }
}

main().catch((error) => {
  console.error(error.message || String(error));
  process.exitCode = 1;
});
