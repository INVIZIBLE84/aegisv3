#!/bin/bash
# watchdog.sh — Aegis-LX Tamper Resistance
# ==========================================
# Run this ONCE after setup to:
#   1. Install Aegis as a systemd service (auto-restart if killed)
#   2. Set immutable flags on critical files (attacker can't delete them)
#   3. Start an inotifywait watcher that alerts if any Aegis file is modified
#
# Usage: sudo bash watchdog.sh

set -e

AEGIS_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVICE_FILE="/etc/systemd/system/aegis-lx.service"
PYTHON_BIN="$(which python3)"

echo "[Aegis-LX Watchdog] Installing tamper resistance..."

# ── Step 1: Create systemd service ────────────────────────────────────────────
# This means if an attacker kills the aegis.py process, systemd restarts it
# within 5 seconds automatically.

cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Aegis-LX Adaptive Security Engine
After=network.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
ExecStart=$PYTHON_BIN $AEGIS_DIR/aegis.py --monitor
WorkingDirectory=$AEGIS_DIR
Restart=always
RestartSec=5
User=root
StandardOutput=journal
StandardError=journal
KillMode=process

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable aegis-lx.service
echo "  [+] systemd service installed and enabled"
echo "      (Aegis will auto-restart if killed)"

# ── Step 2: Set immutable flags on critical Aegis files ───────────────────────
# chattr +i makes files undeletable even by root without first removing the flag.
# An attacker who doesn't know about chattr will be stuck.

CRITICAL_FILES=(
    "$AEGIS_DIR/aegis.py"
    "$AEGIS_DIR/detection/stat_engine.py"
    "$AEGIS_DIR/detection/signature_engine.py"
    "$AEGIS_DIR/response/tier_manager.py"
    "$AEGIS_DIR/response/response_engine.py"
    "$AEGIS_DIR/translator/signal_translator.py"
    "$AEGIS_DIR/observer/system_observer.py"
)

for f in "${CRITICAL_FILES[@]}"; do
    if [ -f "$f" ]; then
        chattr +i "$f" 2>/dev/null && echo "  [+] Immutable: $f" || echo "  [-] chattr failed for $f (filesystem may not support it)"
    fi
done

echo ""
echo "  NOTE: To update Aegis code, first run:"
echo "    sudo chattr -i <filename>   (remove immutable)"
echo "    # edit the file"
echo "    sudo chattr +i <filename>   (restore immutable)"

# ── Step 3: Install inotifywait file integrity monitor ────────────────────────
# If someone DOES manage to modify a file (e.g. after removing immutable),
# this watcher logs and alerts immediately.

if ! command -v inotifywait &> /dev/null; then
    echo ""
    echo "  [!] inotifywait not found. Installing inotify-tools..."
    apt-get install -y inotify-tools -qq
fi

WATCHER_SERVICE="/etc/systemd/system/aegis-fim.service"

cat > "$WATCHER_SERVICE" << EOF
[Unit]
Description=Aegis-LX File Integrity Monitor
After=aegis-lx.service

[Service]
Type=simple
ExecStart=/bin/bash -c 'inotifywait -m -r -e modify,delete,move,create $AEGIS_DIR \
  --format "%T [FIM] %%e %%w%%f" --timefmt "%Y-%m-%d %H:%M:%S" \
  | while read line; do
      echo "\$line" >> $AEGIS_DIR/alerts.log
      logger -t "aegis-fim" "\$line"
    done'
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable aegis-fim.service
systemctl start aegis-fim.service
echo "  [+] File Integrity Monitor (inotifywait) installed and running"

echo ""
echo "══════════════════════════════════════════════════"
echo "  Aegis-LX tamper resistance setup complete."
echo "  Start monitoring: sudo systemctl start aegis-lx"
echo "  View logs:        sudo journalctl -u aegis-lx -f"
echo "══════════════════════════════════════════════════"
