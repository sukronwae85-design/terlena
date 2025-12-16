. README.md
markdown

# Terlena VPN Manager
SSH + VMess + UDP Custom All-in-One Solution

## Features
- SSH with custom banner & login limits
- VMess (V2Ray) with WebSocket + TLS
- UDP Custom (BadVPN-UDPGw) multiple ports
- Auto IP limit enforcement
- SSL certificate (Let's Encrypt)
- Monitoring & auto backup
- User management system

## Quick Install
```bash
curl -sL https://raw.githubusercontent.com/sukronwae85-design/terlena/main/installer.sh | bash

Usage
bash

# Interactive menu
terlena menu

# Create user
terlena add

# List users
terlena list

# Monitor
terlena monitor

# Auto lock check
terlena check

# Backup
terlena backup

Ports Used

    SSH: 22, 2259, 2269

    VMess: 443 (WS+TLS)

    UDP: 7100, 7200, 7300

    UDP Random: 10000-50000 (all open)

    Web: 80

    SSL: 443

Auto Features

    Auto lock on IP limit violation

    Auto lock on expiration

    Auto SSL renewal

    Auto backup weekly

    Auto monitoring

text


### **2. Cara Upload ke GitHub Anda:**

```bash
# 1. Clone repository Anda
git clone https://github.com/sukronwae85-design/terlena.git
cd terlena

# 2. Buat file installer.sh
nano installer.sh
# Paste script lengkap di atas

# 3. Buat README.md
nano README.md
# Paste README di atas

# 4. Buat file update.sh untuk auto-update
nano update.sh

update.sh:
bash

#!/bin/bash
# Auto update script
REPO="https://github.com/sukronwae85-design/terlena"
wget -q -O /tmp/terlena-update.sh $REPO/raw/main/installer.sh
chmod +x /tmp/terlena-update.sh
/tmp/terlena-update.sh
echo "Terlena VPN updated!"

bash

# 5. Commit ke GitHub
git add installer.sh README.md update.sh
git commit -m "Add Terlena VPN Manager"
git push origin main

🚀 INSTALASI DI VPS ANDA (1 BARIS):
bash

# METODE 1: Install langsung
curl -sL https://raw.githubusercontent.com/sukronwae85-design/terlena/main/installer.sh | bash

# METODE 2: Download dulu
wget https://raw.githubusercontent.com/sukronwae85-design/terlena/main/installer.sh
chmod +x installer.sh
./installer.sh

# METODE 3: Uninstall
./installer.sh uninstall

🎯 CONTOH HASIL SETELAH BUAT USER:
text

╔══════════════════════════════════════════════════════════════╗
║          USER BERHASIL DIBUAT!                              ║
╚══════════════════════════════════════════════════════════════╝

┌────────────────────────────────────────────────────────────┐
│ Username      : john_doe                                  │
│ Password      : XyZ8pQ2rK9mW                             │
│ Server IP     : 192.168.1.100                            │
│ Expire Date   : 2024-12-31                               │
│ Max IP Login  : 2                                        │
│ Account Type  : both (SSH + VMess)                       │
└────────────────────────────────────────────────────────────┘

🔐 SSH CONFIG:
Host: 192.168.1.100
Port: 22, 2269, 2259
Username: john_doe
Password: XyZ8pQ2rK9mW

📱 SSH TUNNEL UDP:
Command: ssh -D 8080 -C -N -f john_doe@192.168.1.100 -p 22

🌐 VMESS CONFIG:
vmess://ewoidiI6ICIyIiwKInBzIjogIlRlcmxlbmEtam9obl9kb2UiLAoiYWRkIjogIjE5Mi4xNjguMS4xMDAiLAoicG9ydCI6ICI0NDMiLAoiaWQiOiAiODk5ZGY1Y2QtYmQ4ZC00ZjE3LWI5ZjQtMWY4N2E4NDIyYmQ2IiwKI

This response is AI-generated, for reference only.
