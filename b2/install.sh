#!/bin/bash
set -e

PROJECT_DIR="/home/vboxuser/Desktop/leaktrace"
FILTER_SRC="$PROJECT_DIR/driver/vpfilter.c"
BACKEND_SRC="$PROJECT_DIR/driver/vpbackend.c"

echo "[*] Creating LeakTrace directories..."
sudo mkdir -p /var/lib/leaktrace
sudo mkdir -p /var/spool/virtprinter

echo "[*] Setting ownership..."
sudo chown -R lp:lp /var/lib/leaktrace
sudo chown -R lp:lp /var/spool/virtprinter

echo "[*] Setting permissions..."
sudo chmod 750 /var/lib/leaktrace
sudo chmod 755 /var/spool/virtprinter

echo "[*] Making project accessible to CUPS..."
sudo chmod 755 /home/vboxuser
chmod -R o+rX "$PROJECT_DIR"

echo "[*] Installing Python dependencies..."
pip3 install --break-system-packages cryptography pypdf 2>/dev/null || \
  pip3 install cryptography pypdf

echo "[*] Building filter and backend..."
gcc -Wall -O2 "$FILTER_SRC" -o vpfilter
gcc -Wall -O2 "$BACKEND_SRC" -o virtprinter

echo "[*] Installing CUPS components..."
sudo cp vpfilter /usr/lib/cups/filter/vpfilter
sudo cp virtprinter /usr/lib/cups/backend/virtprinter

sudo chown root:root /usr/lib/cups/filter/vpfilter
sudo chown root:root /usr/lib/cups/backend/virtprinter

sudo chmod 755 /usr/lib/cups/filter/vpfilter
sudo chmod 755 /usr/lib/cups/backend/virtprinter

echo "[*] Installing leaktrace CLI..."
sudo ln -sf "$PROJECT_DIR/tool/leaktrace.py" /usr/local/bin/leaktrace
sudo chmod +x "$PROJECT_DIR/tool/leaktrace.py"

echo "[*] Restarting CUPS..."
sudo systemctl restart cups

echo "[✓] LeakTrace installed successfully."
echo ""
echo "Next steps:"
echo "  sudo leaktrace genkey        # generate activation key"
echo "  leaktrace activate <key>     # activate"
echo "  leaktrace whoami             # verify"
