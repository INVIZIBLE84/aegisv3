#!/bin/bash
# setup.sh — Aegis-LX First-Time Setup
# ======================================
# Run once after cloning/copying the project.
# Usage: sudo bash setup.sh

echo "╔══════════════════════════════════════╗"
echo "║   Aegis-LX v3.0 — Setup             ║"
echo "╚══════════════════════════════════════╝"

# Install Python dependencies
echo "[1/4] Installing Python packages..."
pip3 install bcc scikit-learn numpy joblib --break-system-packages -q

# Install system tools
echo "[2/4] Installing system tools..."
apt-get install -y cpulimit inotify-tools linux-headers-$(uname -r) python3-bcc -qq

# Create __init__.py files so Python treats folders as modules
echo "[3/4] Creating module init files..."
touch observer/__init__.py
touch translator/__init__.py
touch detection/__init__.py
touch response/__init__.py
touch alert/__init__.py
touch logger/__init__.py

# Copy system_observer.py if not already there
if [ ! -f observer/system_observer.py ]; then
    echo "  [!] observer/system_observer.py missing — copy it manually"
fi

echo "[4/4] Setup complete."
echo ""
echo "  Next steps:"
echo "    sudo python3 aegis.py --demo       Test with demo mode"
echo "    sudo python3 aegis.py --monitor    Start real monitoring"
echo "    sudo bash watchdog.sh              Install tamper resistance"
echo ""
