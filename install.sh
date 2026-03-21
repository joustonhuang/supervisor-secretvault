#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_BIN="${1:-$HOME/.local/bin}"

mkdir -p "$TARGET_BIN"
chmod 700 "$SCRIPT_DIR/secrets" "$SCRIPT_DIR/grants" "$SCRIPT_DIR/audit" "$SCRIPT_DIR/config" "$SCRIPT_DIR/tmp" 2>/dev/null || true
ln -sf "$SCRIPT_DIR/src/cli.js" "$TARGET_BIN/supervisor-secretvault"
chmod +x "$SCRIPT_DIR/src/cli.js"

echo "Installed supervisor-secretvault -> $TARGET_BIN/supervisor-secretvault"
echo "Export SECRETVAULT_MASTER_KEY before use."
