#!/bin/sh
# Run wg-monitor on a LAN machine (Mac/PC) against the router RCI.
# Useful until Entware is installed on the router.
# Usage: ./scripts/run-lan.sh

set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
CREDS=${CREDS_FILE:-"$ROOT/../creds"}
STATE_DIR=${TMPDIR:-/tmp}/wg-monitor-lan
mkdir -p "$STATE_DIR"

if [ ! -f "$ROOT/config.json" ]; then
  if [ -f "$CREDS" ]; then
    LOGIN=$(sed -n '1p' "$CREDS")
    PASS=$(sed -n '2p' "$CREDS")
    python3 - <<PY
import json
cfg=json.load(open("$ROOT/config.example.json"))
cfg["rci_url"]="http://192.168.1.1"
cfg["username"]="$LOGIN"
cfg["password"]="$PASS"
cfg["listen_host"]="0.0.0.0"
cfg["listen_port"]=8088
cfg["state_path"]="$STATE_DIR/state.json"
cfg["backup_dir"]="$STATE_DIR"
json.dump(cfg, open("$ROOT/config.json","w"), indent=2)
print("created config.json from creds")
PY
    chmod 600 "$ROOT/config.json"
  else
    echo "Create $ROOT/config.json first" >&2
    exit 1
  fi
fi

exec python3 "$ROOT/main.py" -c "$ROOT/config.json" "$@"
