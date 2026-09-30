#!/bin/sh
# Install wg-monitor onto Keenetic Entware (/opt).
# Run on the router as root (Entware shell), or via:
#   scp -r wg-monitor admin@192.168.1.1:/tmp/
#   ssh admin@192.168.1.1
#   # then enter Entware: /opt/bin/sh or similar, and run install.sh

set -eu

SRC_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
OPT_ROOT=${OPT_ROOT:-/opt}
SHARE="$OPT_ROOT/share/wg-monitor"
ETC="$OPT_ROOT/etc/wg-monitor"
INITD="$OPT_ROOT/etc/init.d"
VAR="$OPT_ROOT/var/lib/wg-monitor"
BIN_LINK="$OPT_ROOT/bin/wg-monitor"

echo "==> Installing wg-monitor from $SRC_DIR"

if [ ! -x "$OPT_ROOT/bin/opkg" ]; then
  echo "ERROR: Entware opkg not found at $OPT_ROOT/bin/opkg" >&2
  exit 1
fi

"$OPT_ROOT/bin/opkg" update || true
"$OPT_ROOT/bin/opkg" install python3-light python3-logging python3-codecs || true
# Prefer light stack; full python3 metapackage is large for internal storage

if [ ! -x "$OPT_ROOT/bin/python3" ]; then
  echo "ERROR: python3 is required. Install with: opkg install python3" >&2
  exit 1
fi

mkdir -p "$SHARE" "$ETC" "$INITD" "$VAR" "$OPT_ROOT/var/run" "$OPT_ROOT/var/log" "$OPT_ROOT/bin"

# Copy application files
rm -rf "$SHARE"
mkdir -p "$SHARE/lib"
cp -f "$SRC_DIR/main.py" "$SHARE/main.py"
cp -f "$SRC_DIR/lib/"*.py "$SHARE/lib/"
cp -f "$SRC_DIR/config.example.json" "$SHARE/config.example.json"
chmod 755 "$SHARE/main.py"

# Config (do not overwrite existing)
if [ ! -f "$ETC/config.json" ]; then
  if [ -f "$SRC_DIR/config.json" ]; then
    cp -f "$SRC_DIR/config.json" "$ETC/config.json"
  else
    cp -f "$SRC_DIR/config.example.json" "$ETC/config.json"
    echo "WARNING: Created $ETC/config.json from example — set username/password!"
  fi
  chmod 600 "$ETC/config.json"
else
  echo "Keeping existing $ETC/config.json"
fi

# Wrapper
cat >"$BIN_LINK" <<EOF
#!/bin/sh
exec $OPT_ROOT/bin/python3 $SHARE/main.py "\$@"
EOF
chmod 755 "$BIN_LINK"

# Init script
cp -f "$SRC_DIR/entware/S99wg-monitor" "$INITD/S99wg-monitor"
chmod 755 "$INITD/S99wg-monitor"

# Restart service
if [ -x "$INITD/S99wg-monitor" ]; then
  "$INITD/S99wg-monitor" stop || true
  "$INITD/S99wg-monitor" start
fi

PORT=$( "$OPT_ROOT/bin/python3" -c "import json;print(json.load(open('$ETC/config.json')).get('listen_port',8088))" 2>/dev/null || echo 8088 )

echo
echo "==> Installed."
echo "    Config:  $ETC/config.json"
echo "    App:     $SHARE"
echo "    Service: $INITD/S99wg-monitor {start|stop|restart|status}"
echo "    Dashboard: http://<router-ip>:$PORT/"
echo
echo "Tip: on first install edit password in $ETC/config.json then restart the service."
