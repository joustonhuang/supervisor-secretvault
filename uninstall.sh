#!/usr/bin/env bash
set -euo pipefail

TARGET_BIN="${1:-$HOME/.local/bin}"
rm -f "$TARGET_BIN/supervisor-secretvault"
echo "Removed $TARGET_BIN/supervisor-secretvault"
