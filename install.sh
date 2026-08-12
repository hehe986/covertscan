#!/bin/bash
echo "[*] Installing CovertScan dependencies..."
pip install -r requirements.txt --break-system-packages
echo "[✓] Done. Run: python covertscan.py --help"
