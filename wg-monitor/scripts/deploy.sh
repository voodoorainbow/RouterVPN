#!/bin/sh
# Deploy wg-monitor to a router that already has working Entware shell
# (SSH to BusyBox on port 222 after Entware install, or exec /opt/bin/ash).
#
# Usage:
#   ./scripts/deploy.sh [user@host] [ssh_port]
# Example:
#   ./scripts/deploy.sh root@192.168.1.1 222

set -eu
TARGET=${1:-root@192.168.1.1}
PORT=${2:-222}
SRC=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
STAGE=/tmp/wg-monitor-deploy-$$

echo "Packaging $SRC -> $TARGET:$PORT"
rm -rf "$STAGE"
mkdir -p "$STAGE"
cp -R "$SRC/lib" "$SRC/main.py" "$SRC/install.sh" "$SRC/entware" "$SRC/config.example.json" "$SRC/README.md" "$STAGE/"
if [ -f "$SRC/config.json" ]; then
  cp "$SRC/config.json" "$STAGE/config.json"
fi

scp -P "$PORT" -o StrictHostKeyChecking=accept-new -r "$STAGE" "$TARGET:/tmp/wg-monitor"
ssh -p "$PORT" -o StrictHostKeyChecking=accept-new "$TARGET" "/opt/bin/sh /tmp/wg-monitor/install.sh"
rm -rf "$STAGE"
echo "Done. Open http://192.168.1.1:8088/"
