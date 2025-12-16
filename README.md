README.md (Documentation)
markdown

# 🚀 VPN TUNNELING MANAGER SUPER LENGKAP

## 🌟 ULTIMATE FEATURES
- **SSH on Port 22, 80, 443, 8080, 8888** - Maximum bypass capability
- **VMESS on Port 80 (WS) & 443 (WSS+TLS)** - Dual protocol support
- **UDP Custom ALL Ports 1-65535** - Complete UDP port range
- **Auto Domain + SSL** - One-click domain setup
- **Random UDP Ports** - Dynamic port allocation
- **Full Monitoring** - Real-time connection tracking
- **Auto Lock System** - Security enforcement

## 🚀 INSTALLATION
```bash
# One-line installation
curl -sL https://raw.githubusercontent.com/sukronwae85-design/terlena/main/installer.sh | bash

# Or download first
wget https://raw.githubusercontent.com/sukronwae85-design/terlena/main/installer.sh
chmod +x installer.sh
./installer.sh install

📖 USAGE
bash

# After installation:
vpntunnel menu          # Interactive menu
vpntunnel ssh           # Create SSH account
vpntunnel vmess         # Create VMESS account
vpntunnel ssl           # Setup domain + SSL
vpntunnel testudp       # Test UDP port
vpntunnel restartudp    # Restart UDP random ports

🔥 PORT CONFIGURATION
Service	Ports	Protocol	Purpose
SSH	22, 80, 443, 8080, 8888	TCP	SSH tunneling (bypass all)
VMESS	80 (WS), 443 (WSS+TLS)	TCP	V2Ray WebSocket
UDP Custom	1-65535 (ALL)	UDP	Unlimited UDP ports
Dropbear	445	TCP	Alternative SSH
Nginx	80, 443	TCP	Web server & proxy
🎯 CONNECTION EXAMPLES
SSH Connection (Bypass Firewall):
bash

# Via HTTPS Port (443)
ssh username@your-domain.com -p 443

# Via HTTP Port (80)
ssh username@your-domain.com -p 80

# Standard SSH
ssh username@your-domain.com -p 22

# SSH Tunneling (SOCKS5)
ssh -D 1080 -C -N -f username@your-domain.com -p 443

VMESS Connection:
text

Port 80:  ws://your-domain.com/vmess
Port 443: wss://your-domain.com/vmess

UDP Custom:
bash

# Test any UDP port
test-udp-port.sh 12345

# All UDP ports 1-65535 are open!

🔧 FEATURES DETAIL
1. SSH Multi-Port

    Port 22: Standard SSH

    Port 80: HTTP Bypass (works in restricted networks)

    Port 443: HTTPS Bypass (works everywhere)

    Port 8080/8888: Alternative ports

2. VMESS Dual Protocol

    Port 80: WebSocket (no encryption)

    Port 443: WebSocket + TLS (encrypted)

    Automatic SSL with Let's Encrypt

3. UDP Unlimited Ports

    All UDP ports 1-65535 open

    Random port assignment

    Dynamic port rotation

    No port restrictions

4. Security Features

    Auto lock on IP violation

    Account expiration system

    Login monitoring

    Fail2ban protection

    SSL encryption

⚡ QUICK START

    Install: ./installer.sh install

    Setup domain: vpntunnel ssl

    Create user: vpntunnel ssh

    Connect: ssh user@domain -p 443

    Test UDP: vpntunnel testudp 12345

📊 MONITORING
bash

vpntunnel monitor      # System monitoring
vpntunnel list         # Active users
vpntunnel info         # Server information

🔄 UPDATES
bash

vpntunnel update       # Auto update from GitHub

🆘 SUPPORT

    Ubuntu 18.04/20.04/22.04

    Minimum 1GB RAM

    Root access required

text


## 🎯 **CARA INSTALL & GUNAKAN:**

```bash
# 1. INSTALL
wget https://raw.githubusercontent.com/sukronwae85-design/terlena/main/installer.sh
chmod +x installer.sh
./installer.sh install

# 2. SETUP DOMAIN (Optional)
vpntunnel ssl
# Ikuti petunjuk untuk pointing domain

# 3. BUAT USER SSH
vpntunnel ssh
# Hasilnya bisa pakai port 80 atau 443

# 4. BUAT USER VMESS
vpntunnel vmess
# Bisa pakai port 80 atau 443

# 5. TEST UDP PORT
vpntunnel testudp
# Masukkan port random 1-65535

# 6. MONITOR
vpntunnel monitor

💡 KEUNGGULAN SCRIPT INI:

    ✅ SSH Port 80/443 - Bypass SEMUA firewall

    ✅ VMESS Port 80/443 - WebSocket + TLS

    ✅ UDP 1-65535 - SEMUA port UDP terbuka

    ✅ Random Ports - Port berubah otomatis

    ✅ Auto Domain SSL - Setup domain 1 klik

    ✅ Complete Monitoring - Pantau semua koneksi

    ✅ Auto Lock System - Keamanan maksimal

SCRIPT INI SUDAH SUPER LENGKAP DAN READY TO USE! 🚀
This response is AI-generated, for reference only.
