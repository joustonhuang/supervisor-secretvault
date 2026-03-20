#!/usr/bin/env bash
set -euo pipefail

DST_SEC="/etc/little7/secrets"

if [ -d "$DST_SEC" ]; then
  sudo rm -rf "$DST_SEC"
  echo "Removed supervisor-secretvault secrets from $DST_SEC"
else
  echo "Nothing to remove: $DST_SEC does not exist"
fi
