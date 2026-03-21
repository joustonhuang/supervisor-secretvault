# supervisor-secretvault.unifai

MVP governed secret vault plugin for supervisor-managed AI agents.

## What it does

- stores secrets encrypted at rest with AES-256-GCM
- uses alias-based access instead of exposing real secret names in audit/grant flows
- routes authorization to `supervisor-keyman.unifai` if present
- otherwise allows only local interactive human-present fallback
- issues time-limited grant files in `grants/`
- cleans up expired/orphaned grants on startup and via explicit cleanup
- writes JSONL audit records without plaintext secret content

## Layout

All secret-related state stays inside this plugin root:

- `secrets/` encrypted secret records
- `grants/` temporary plaintext grant files + metadata
- `audit/` JSONL audit trail
- `config/` local config and optional keyman shim path
- `tmp/` temporary/test helpers

## Requirements

- Node.js 20+
- `SECRETVAULT_MASTER_KEY` environment variable set to a 32-byte key in hex or base64

Generate a fake local key for testing:

```bash
export SECRETVAULT_MASTER_KEY="$(openssl rand -hex 32)"
```

## Install / enable

```bash
cd /home/little7/.openclaw/workspace/unifai/supervisor/supervisor-secretvault
./install.sh
export PATH="$HOME/.local/bin:$PATH"
export SECRETVAULT_MASTER_KEY="$(openssl rand -hex 32)"
supervisor-secretvault init
```

This installs a symlink at `~/.local/bin/supervisor-secretvault` by default.

## Usage

### 1) Seed an encrypted secret

```bash
supervisor-secretvault seed \
  --alias fake-openai \
  --label provider-token \
  --value FAKE-OPENAI-TOKEN
```

### 2) Request a temporary grant

If a sibling `supervisor-keyman.unifai` approver exists at the configured path, the vault forwards the decision request there. Otherwise the vault requires a local interactive TTY human confirmation and denies unattended use.

```bash
supervisor-secretvault request \
  --alias fake-openai \
  --purpose "run integration test" \
  --agent "agent/tester" \
  --ttl 180
```

Success returns JSON like:

```json
{
  "ok": true,
  "grantId": "...",
  "path": "/.../grants/<uuid>.secret",
  "expiresAt": "2026-03-22T00:00:00.000Z",
  "ttlSeconds": 180,
  "aliasFingerprint": "...",
  "authorizationPath": "keyman-forward"
}
```

The caller reads the granted temporary file, then either waits for TTL expiry or runs cleanup.

### 3) Cleanup orphaned/expired grants

```bash
supervisor-secretvault cleanup
```

## Config

`config/default.json`

```json
{
  "vault": {
    "defaultTtlSeconds": 180,
    "maxTtlSeconds": 3600,
    "interactiveFallback": true
  },
  "keyman": {
    "command": "../supervisor-keyman.unifai/bin/supervisor-keyman"
  }
}
```

`keyman.command` is resolved relative to `config/`.

Expected keyman contract for MVP:

- executable receives `authorize` as argv[2]
- JSON request on stdin
- JSON response on stdout: `{ "approved": true|false, "authorizationPath": "keyman-forward", "reason": "..." }`

## Audit model

Each audit record includes timestamp plus relevant fields such as:

- alias fingerprint, not plaintext secret content
- purpose
- agent identity when supplied
- authorization path
- issued/denied
- TTL
- cleanup result

Audit logs live in `audit/YYYY-MM-DD.jsonl`.

## Test

Uses fake secrets only.

```bash
cd /home/little7/.openclaw/workspace/unifai/supervisor/supervisor-secretvault
npm test
```

Covered locally:

- install/uninstall path
- encrypted seed storage
- forwarded authorization path simulation
- grant creation and usability
- TTL expiry and cleanup
- audit logging
- non-interactive fallback denial when keyman is missing

## Known MVP limitations

- master key is env-based for now; no HSM/OS keyring integration
- interactive fallback is CLI-only and intentionally denies unattended flows
- keyman integration is a simple executable contract, not a richer RPC/plugin protocol yet
- grant payload files are plaintext during active TTL by design; cleanup must run or startup must re-run to remove expired grants
