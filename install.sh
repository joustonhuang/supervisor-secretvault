#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_SEC="${SCRIPT_DIR}/secrets"
DST_SEC="/etc/little7/secrets"

sudo mkdir -p "$DST_SEC"
sudo rsync -a "$SRC_SEC/" "$DST_SEC/"
sudo chown -R root:root "$DST_SEC"
sudo chmod 700 "$DST_SEC"
sudo find "$DST_SEC" -type f -name '*.gpg' -exec chmod 600 {} \;
sudo chmod -R go-rwx "$DST_SEC"

echo "Installed supervisor-secretvault secrets to $DST_SEC"
