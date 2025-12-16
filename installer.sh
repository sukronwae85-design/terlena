#!/bin/bash
# ================================================
# VPN TUNNELING MANAGER - SUPER LENGKAP
# SSH Port 80/443 + VMESS Port 80/443 + UDP Random 1-65535
# ================================================

# Warna untuk output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Variabel global
SCRIPT_NAME="vpntunnel"
INSTALL_DIR="/usr/local/bin"
VPN_DIR="/etc/vpntunnel"
USER_DB="$VPN_DIR/users.db"
LOG_FILE="/var/log/vpntunnel.log"
DOMAIN_FILE="$VPN_DIR/domain.txt"
BACKUP_DIR="/root/vpn-backup"
BANNER_FILE="/etc/ssh/banner"
UDP_PORTS_FILE="$VPN_DIR/udp_ports.txt"

# Port Configuration - SEMUA PORT 80 & 443
SSH_PORT="22"
SSH_PORT_80="80"       # SSH via HTTP port
SSH_PORT_443="443"     # SSH via HTTPS port
DROPBEAR_PORT="445"
STUNNEL_PORT="444"
VMESS_PORT_WS="80"     # VMESS via HTTP WebSocket
VMESS_PORT_WSS="443"   # VMESS via HTTPS WebSocket
VMESS_PORT_ALT="8443"  # VMESS alternative port
UDP_BASE_PORTS="7100 7200 7300"

# Fungsi tampilkan banner
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║               VPN TUNNELING MANAGER v5.0                    ║"
    echo "║     SSH Port 80/443 • VMESS Port 80/443 • UDP Random        ║"
    echo "║          Support UDP Port 1-65535 Random                    ║"
    echo "║        Support: Ubuntu 18.04/20.04/22.04                    ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Fungsi logging
log() {
    echo -e "$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" >> $LOG_FILE
}

# ================================================
# INSTALASI UTAMA - SEMUA PORT 80/443
# ================================================
install_vpn() {
    show_banner
    log "${YELLOW}[+] Memulai instalasi VPN Tunneling SUPER LENGKAP...${NC}"
    
    # Cek root
    if [[ $EUID -ne 0 ]]; then
        log "${RED}✗ Script harus dijalankan sebagai root!${NC}"
        log "${YELLOW}Gunakan: sudo bash $0${NC}"
        exit 1
    fi
    
    # Cek OS
    if ! grep -q "Ubuntu 18.04\|Ubuntu 20.04\|Ubuntu 22.04" /etc/os-release; then
        log "${RED}✗ OS tidak didukung!${NC}"
        exit 1
    fi
    
    # Update sistem
    log "${YELLOW}[1] Update sistem packages...${NC}"
    apt update -y && apt upgrade -y
    
    # Install dependencies
    log "${YELLOW}[2] Install dependencies...${NC}"
    apt install -y \
        wget curl nano git \
        openssh-server dropbear stunnel4 \
        nginx certbot python3-certbot-nginx \
        net-tools ufw fail2ban \
        jq qrencode bc \
        screen htop iftop \
        socat iptables-persistent \
        build-essential cmake >> /dev/null 2>&1
    
    # Buat direktori
    mkdir -p $VPN_DIR $BACKUP_DIR
    
    # Install V2Ray (VMESS)
    log "${YELLOW}[3] Install V2Ray VMESS...${NC}"
    bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh) >> /dev/null 2>&1
    
    # Konfigurasi SSH dengan PORT 80 & 443
    log "${YELLOW}[4] Konfigurasi SSH Server (Port 22, 80, 443)...${NC}"
    configure_ssh
    
    # Konfigurasi Dropbear
    log "${YELLOW}[5] Konfigurasi Dropbear...${NC}"
    configure_dropbear
    
    # Konfigurasi Nginx untuk VMESS di PORT 80/443
    log "${YELLOW}[6] Konfigurasi Nginx untuk VMESS Port 80/443...${NC}"
    configure_nginx_vmess
    
    # Konfigurasi V2Ray untuk Port 80/443
    log "${YELLOW}[7] Konfigurasi V2Ray Port 80/443...${NC}"
    configure_v2ray_ports
    
    # Install BadVPN UDPGW dengan PORT RANDOM 1-65535
    log "${YELLOW}[8] Install BadVPN UDPGW dengan Port Random 1-65535...${NC}"
    install_badvpn_random
    
    # Konfigurasi firewall untuk SEMUA PORT
    log "${YELLOW}[9] Konfigurasi firewall semua port...${NC}"
    configure_firewall_all
    
    # Setup UDP Random Ports 1-65535
    log "${YELLOW}[10] Setup UDP Random Ports 1-65535...${NC}"
    setup_udp_random_ports
    
    # Buat database user
    log "${YELLOW}[11] Setup database user...${NC}"
    setup_database
    
    # Buat script utama
    log "${YELLOW}[12] Buat VPN manager script...${NC}"
    create_main_script
    
    # Restart semua service
    systemctl restart ssh
    systemctl restart dropbear
    systemctl restart nginx
    systemctl restart v2ray
    
    log "${GREEN}✓ Instalasi SUPER LENGKAP selesai!${NC}"
    
    # Tampilkan informasi lengkap
    show_server_info_full
}

# ================================================
# KONFIGURASI SSH PORT 80/443
# ================================================
configure_ssh() {
    # Backup config SSH
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    # SSH di SEMUA PORT penting
    cat > /etc/ssh/sshd_config << EOF
# SSH Standard Port
Port $SSH_PORT
# SSH di port 80 (HTTP) - untuk bypass firewall
Port $SSH_PORT_80
# SSH di port 443 (HTTPS) - untuk bypass firewall
Port $SSH_PORT_443
# SSH di port lain untuk redundancy
Port 8080
Port 8888

PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
ClientAliveInterval 300
ClientAliveCountMax 2
MaxAuthTries 3
MaxSessions 5
Banner $BANNER_FILE
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
AllowTcpForwarding yes
GatewayPorts yes
EOF
    
    # Buat banner SSH lengkap
    cat > $BANNER_FILE << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║                   🚀 VPN TUNNELING SERVER                   ║
║                  SSH • VMESS • UDP CUSTOM                   ║
║                                                              ║
║  📅 Tanggal : \d                                            ║
║  ⏰ Waktu   : \t                                            ║
║  🌐 Server  : $(hostname)                                   ║
║  👤 User    : \u                                            ║
║  🔌 IP      : \4                                            ║
║  📶 Port    : \p                                            ║
║                                                              ║
║  📋 PORT YANG TERSEDIA:                                     ║
║    • SSH      : 22, 80, 443, 8080, 8888                     ║
║    • VMESS    : 80 (WS), 443 (WSS+TLS)                      ║
║    • UDP      : 1-65535 (Random Ports)                      ║
║    • Dropbear : 445                                         ║
║                                                              ║
║  📜 PERATURAN:                                              ║
║    1. Maksimal 2 IP berbeda                                 ║
║    2. Dilarang spam/DDOS                                    ║
║    3. Tidak untuk aktivitas illegal                         ║
║                                                              ║
║  ⚠  PELANGGARAN = AUTO BAN & LOCK! ⚠                       ║
╚══════════════════════════════════════════════════════════════╝
EOF
    
    systemctl enable ssh
    systemctl restart ssh
}

# ================================================
# KONFIGURASI NGINX UNTUK VMESS PORT 80/443
# ================================================
configure_nginx_vmess() {
    # Hapus config default
    rm -f /etc/nginx/sites-enabled/default
    
    # Config Nginx untuk VMESS di PORT 80 & 443
    cat > /etc/nginx/sites-available/vmess << 'EOF'
# HTTP Server on Port 80 - for VMESS WebSocket
server {
    listen 80;
    listen [::]:80;
    server_name _;
    
    # VMESS WebSocket on Port 80
    location /vmess {
        proxy_pass http://127.0.0.1:10000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # SSH via HTTP (Port 80)
    location /ssh {
        proxy_pass http://127.0.0.1:22;
        proxy_http_version 1.1;
    }
    
    # Web Interface
    location / {
        root /var/www/html;
        index index.html;
    }
}

# HTTPS Server on Port 443 - for VMESS WSS + TLS
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name _;
    
    # Self-signed SSL for initial setup
    ssl_certificate /etc/nginx/ssl/selfsigned.crt;
    ssl_certificate_key /etc/nginx/ssl/selfsigned.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    
    # VMESS WebSocket Secure on Port 443
    location /vmess {
        proxy_pass http://127.0.0.1:10001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # SSH via HTTPS (Port 443)
    location /ssh {
        proxy_pass http://127.0.0.1:22;
        proxy_http_version 1.1;
    }
    
    # Web Interface with SSL
    location / {
        root /var/www/html;
        index index.html;
    }
}
EOF
    
    # Buat direktori SSL untuk self-signed
    mkdir -p /etc/nginx/ssl
    
    # Generate self-signed SSL certificate
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/nginx/ssl/selfsigned.key \
        -out /etc/nginx/ssl/selfsigned.crt \
        -subj "/C=US/ST=CA/L=SF/O=VPN/CN=vpn-server" 2>/dev/null
    
    # Aktifkan config
    ln -sf /etc/nginx/sites-available/vmess /etc/nginx/sites-enabled/
    
    # Buat halaman web
    mkdir -p /var/www/html
    cat > /var/www/html/index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🚀 VPN Tunneling Server</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: white;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.2);
        }
        .header {
            text-align: center;
            margin-bottom: 40px;
        }
        .header h1 {
            font-size: 3em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        .status-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        .status-card {
            background: rgba(255, 255, 255, 0.15);
            padding: 25px;
            border-radius: 15px;
            transition: transform 0.3s ease;
        }
        .status-card:hover {
            transform: translateY(-5px);
            background: rgba(255, 255, 255, 0.2);
        }
        .status-card h3 {
            margin-bottom: 15px;
            font-size: 1.5em;
            border-bottom: 2px solid rgba(255,255,255,0.3);
            padding-bottom: 10px;
        }
        .port-list {
            list-style: none;
        }
        .port-list li {
            padding: 8px 0;
            border-bottom: 1px solid rgba(255,255,255,0.1);
            display: flex;
            justify-content: space-between;
        }
        .port-list li:last-child {
            border-bottom: none;
        }
        .port-tag {
            background: rgba(76, 175, 80, 0.3);
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 0.9em;
        }
        .info-box {
            background: rgba(255, 255, 255, 0.1);
            padding: 25px;
            border-radius: 15px;
            margin-top: 30px;
        }
        .info-box h3 {
            margin-bottom: 15px;
            color: #ffcc00;
        }
        .warning {
            background: rgba(255, 87, 34, 0.2);
            padding: 15px;
            border-radius: 10px;
            margin-top: 20px;
            border-left: 4px solid #ff5722;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 VPN TUNNELING SERVER</h1>
            <p>SSH • VMESS • UDP CUSTOM • ALL PORTS</p>
        </div>
        
        <div class="status-grid">
            <div class="status-card">
                <h3>🌐 Server Information</h3>
                <ul class="port-list">
                    <li>IP Address: <span class="port-tag" id="server-ip">Loading...</span></li>
                    <li>Status: <span class="port-tag" style="background: rgba(0,150,255,0.3);">ONLINE</span></li>
                    <li>Uptime: <span class="port-tag">24/7</span></li>
                    <li>Users: <span class="port-tag">Multi-User</span></li>
                </ul>
            </div>
            
            <div class="status-card">
                <h3>🔌 SSH Ports</h3>
                <ul class="port-list">
                    <li>Port 22 <span class="port-tag">Standard</span></li>
                    <li>Port 80 <span class="port-tag">HTTP Bypass</span></li>
                    <li>Port 443 <span class="port-tag">HTTPS Bypass</span></li>
                    <li>Port 8080 <span class="port-tag">Alternative</span></li>
                    <li>Port 8888 <span class="port-tag">Alternative</span></li>
                </ul>
            </div>
            
            <div class="status-card">
                <h3>📡 VMESS Ports</h3>
                <ul class="port-list">
                    <li>Port 80 <span class="port-tag">WebSocket</span></li>
                    <li>Port 443 <span class="port-tag">WSS + TLS</span></li>
                    <li>Port 8443 <span class="port-tag">Alternative</span></li>
                </ul>
            </div>
            
            <div class="status-card">
                <h3>⚡ UDP Custom</h3>
                <ul class="port-list">
                    <li>Port 7100-7300 <span class="port-tag">Base Ports</span></li>
                    <li>Port 1-65535 <span class="port-tag">Random UDP</span></li>
                    <li>Protocol: <span class="port-tag">UDP Only</span></li>
                </ul>
            </div>
        </div>
        
        <div class="info-box">
            <h3>📋 Connection Examples</h3>
            <p><strong>SSH via Port 443:</strong> <code>ssh username@$(curl -s ifconfig.me) -p 443</code></p>
            <p><strong>SSH via Port 80:</strong> <code>ssh username@$(curl -s ifconfig.me) -p 80</code></p>
            <p><strong>VMESS URL:</strong> <code>vmess://... (Use V2Ray client)</code></p>
            <p><strong>UDP Custom:</strong> Use any UDP port between 1-65535</p>
        </div>
        
        <div class="warning">
            <strong>⚠ IMPORTANT:</strong> This server supports multiple connection methods. 
            If one port is blocked, try another. UDP ports are randomly available.
        </div>
        
        <script>
            // Get server IP
            fetch('/ip')
                .then(response => response.text())
                .then(ip => {
                    document.getElementById('server-ip').textContent = ip;
                });
            
            // Update time
            function updateTime() {
                const now = new Date();
                document.getElementById('current-time').textContent = 
                    now.toLocaleTimeString();
            }
            setInterval(updateTime, 1000);
            updateTime();
        </script>
    </div>
</body>
</html>
EOF
    
    # Buat endpoint untuk IP
    echo '<?php echo $_SERVER["SERVER_ADDR"]; ?>' > /var/www/html/ip.php
    
    systemctl enable nginx
    systemctl restart nginx
}

# ================================================
# KONFIGURASI V2RAY UNTUK PORT 80/443
# ================================================
configure_v2ray_ports() {
    # Hentikan V2Ray jika sedang berjalan
    systemctl stop v2ray 2>/dev/null
    
    # Buat config V2Ray untuk MULTI-PORT
    cat > /usr/local/etc/v2ray/config.json << EOF
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/v2ray/access.log",
    "error": "/var/log/v2ray/error.log"
  },
  "inbounds": [
    {
      "port": 10000,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/vmess"
        }
      },
      "tag": "vmess-http"
    },
    {
      "port": 10001,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "path": "/vmess"
        }
      },
      "tag": "vmess-https"
    },
    {
      "port": 8443,
      "protocol": "vmess",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "tcp"
      },
      "tag": "vmess-alternative"
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": []
  }
}
EOF
    
    # Buat systemd service untuk V2Ray
    cat > /etc/systemd/system/v2ray.service << EOF
[Unit]
Description=V2Ray VMESS Server
After=network.target nginx.service

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/v2ray -config /usr/local/etc/v2ray/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable v2ray
    systemctl start v2ray
}

# ================================================
# INSTALL BADVPN DENGAN PORT RANDOM 1-65535
# ================================================
install_badvpn_random() {
    # Install dependencies
    apt install -y cmake build-essential
    
    # Download dan compile BadVPN
    cd /tmp
    if [ ! -f "/usr/local/bin/badvpn-udpgw" ]; then
        wget -q https://github.com/ambrop72/badvpn/archive/refs/tags/1.999.130.tar.gz
        tar xzf 1.999.130.tar.gz
        cd badvpn-1.999.130
        mkdir build && cd build
        cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
        make
        cp udpgw/badvpn-udpgw /usr/local/bin/
    fi
    
    # Buat script untuk generate port random
    cat > /usr/local/bin/start-udp-ports.sh << 'EOF'
#!/bin/bash
# Start UDP Custom on random ports

# Base ports
BASE_PORTS="7100 7200 7300 7400 7500"

# Generate 10 random ports between 10000-60000
RANDOM_PORTS=""
for i in {1..10}; do
    RANDOM_PORT=$((10000 + RANDOM % 50000))
    RANDOM_PORTS="$RANDOM_PORTS $RANDOM_PORT"
done

# Combine all ports
ALL_PORTS="$BASE_PORTS $RANDOM_PORTS"

# Kill existing badvpn processes
pkill -f badvpn-udpgw

# Start on each port
for port in $ALL_PORTS; do
    # Check if port is available
    if ! ss -uln | grep -q ":$port "; then
        screen -dmS udp-$port /usr/local/bin/badvpn-udpgw \
            --listen-addr 0.0.0.0:$port \
            --max-clients 1000 \
            --max-connections-for-client 10
        echo "Started UDP Custom on port: $port"
    fi
done

# Save ports to file
echo "$ALL_PORTS" > /etc/vpntunnel/udp_ports.txt
EOF
    
    chmod +x /usr/local/bin/start-udp-ports.sh
    
    # Buat systemd service untuk UDP Random Ports
    cat > /etc/systemd/system/udp-custom.service << EOF
[Unit]
Description=UDP Custom Random Ports 1-65535
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/start-udp-ports.sh
ExecStop=/usr/bin/pkill -f badvpn-udpgw

[Install]
WantedBy=multi-user.target
EOF
    
    # Buat service untuk auto restart setiap jam
    cat > /etc/systemd/system/udp-custom.timer << EOF
[Unit]
Description=Restart UDP ports every hour
Requires=udp-custom.service

[Timer]
OnBootSec=5min
OnUnitActiveSec=1h

[Install]
WantedBy=timers.target
EOF
    
    systemctl daemon-reload
    systemctl enable udp-custom.service
    systemctl enable udp-custom.timer
    systemctl start udp-custom.service
    systemctl start udp-custom.timer
}

# ================================================
# SETUP UDP RANDOM PORTS 1-65535
# ================================================
setup_udp_random_ports() {
    # Buat script untuk open semua UDP port
    cat > /usr/local/bin/open-all-udp-ports.sh << 'EOF'
#!/bin/bash
# Open ALL UDP ports 1-65535 for UDP Custom

# Clear existing UDP rules
iptables -F
iptables -X

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow localhost
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH ports
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 445 -j ACCEPT
iptables -A INPUT -p tcp --dport 444 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
iptables -A INPUT -p tcp --dport 8888 -j ACCEPT
iptables -A INPUT -p tcp --dport 8443 -j ACCEPT

# OPEN ALL UDP PORTS 1-65535
iptables -A INPUT -p udp -j ACCEPT

# Allow ICMP (ping)
iptables -A INPUT -p icmp -j ACCEPT

# Save rules
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6

echo "✅ ALL UDP ports 1-65535 are now OPEN!"
EOF
    
    chmod +x /usr/local/bin/open-all-udp-ports.sh
    
    # Buat script untuk test UDP port
    cat > /usr/local/bin/test-udp-port.sh << 'EOF'
#!/bin/bash
# Test UDP port availability

if [ -z "$1" ]; then
    echo "Usage: test-udp-port.sh <port>"
    echo "Example: test-udp-port.sh 12345"
    exit 1
fi

PORT=$1
SERVER_IP=$(curl -s ifconfig.me)

echo "Testing UDP port $PORT on $SERVER_IP..."
echo ""

# Test with netcat
timeout 3 nc -z -u $SERVER_IP $PORT

if [ $? -eq 0 ]; then
    echo "✅ UDP Port $PORT is OPEN and ACCEPTING connections"
else
    echo "❌ UDP Port $PORT may be filtered or not accepting connections"
    echo ""
    echo "Note: All UDP ports 1-65535 are open in firewall."
    echo "If connection fails, it might be due to:"
    echo "1. ISP blocking the port"
    echo "2. Client-side firewall"
    echo "3. Network restrictions"
fi
EOF
    
    chmod +x /usr/local/bin/test-udp-port.sh
    
    # Jalankan script untuk open semua UDP port
    /usr/local/bin/open-all-udp-ports.sh
}

# ================================================
# KONFIGURASI FIREWALL ALL PORTS
# ================================================
configure_firewall_all() {
    # Nonaktifkan UFW karena kita pakai iptables manual
    ufw --force disable
    
    # Gunakan iptables langsung
    /usr/local/bin/open-all-udp-ports.sh
    
    echo -e "${GREEN}✓ Firewall configured: ALL UDP ports 1-65535 OPEN${NC}"
}

# ================================================
# MENU 3: POINTING DOMAIN + SSL (UPDATE)
# ================================================
setup_domain_ssl_full() {
    show_banner
    echo -e "${CYAN}[3] POINTING DOMAIN + SSL AUTO SETUP${NC}"
    echo ""
    
    SERVER_IP=$(curl -s ifconfig.me)
    
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${WHITE}📡 SERVER IP: ${GREEN}$SERVER_IP${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    echo -e "${YELLOW}LANGKAH 1: Pointing Domain${NC}"
    echo "1. Login ke Cloudflare/Nameserver"
    echo "2. Tambah Record Type A:"
    echo "   Name: vpn (atau subdomain)"
    echo "   IPv4 Address: $SERVER_IP"
    echo "   TTL: Auto"
    echo "3. Tunggu 5-10 menit untuk propagasi DNS"
    echo ""
    
    read -p "Sudah pointing domain? (y/n): " sudah_pointing
    if [[ "$sudah_pointing" != "y" && "$sudah_pointing" != "Y" ]]; then
        echo -e "${RED}Pointing domain dulu ya!${NC}"
        return 1
    fi
    
    echo ""
    read -p "Masukkan domain lengkap (contoh: vpn.domain.com): " domain
    
    if [ -z "$domain" ]; then
        echo -e "${RED}Domain tidak boleh kosong!${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}[+] Testing domain $domain...${NC}"
    if ping -c 2 $domain &>/dev/null; then
        echo -e "${GREEN}✓ Domain bisa diakses${NC}"
    else
        echo -e "${YELLOW}⚠ Domain belum propagasi, lanjut saja...${NC}"
    fi
    
    echo ""
    echo -e "${YELLOW}LANGKAH 2: Setup SSL Certificate${NC}"
    
    # Stop nginx untuk certbot standalone
    systemctl stop nginx
    
    # Dapatkan SSL certificate
    certbot certonly --standalone --agree-tos --register-unsafely-without-email \
        -d $domain --non-interactive
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ SSL certificate berhasil!${NC}"
        
        # Simpan domain
        echo "$domain" > $DOMAIN_FILE
        
        # Update Nginx config dengan SSL
        update_nginx_ssl_config "$domain"
        
        # Update V2Ray config dengan SSL
        update_v2ray_ssl_config "$domain"
        
        # Setup auto-renew
        setup_ssl_auto_renew_full
        
        # Start services
        systemctl start nginx
        systemctl restart v2ray
        
        show_domain_info_full "$domain"
    else
        echo -e "${RED}✗ Gagal mendapatkan SSL${NC}"
        systemctl start nginx
        return 1
    fi
}

update_nginx_ssl_config() {
    local domain=$1
    
    cat > /etc/nginx/sites-available/vmess << EOF
# HTTP to HTTPS redirect
server {
    listen 80;
    listen [::]:80;
    server_name $domain;
    return 301 https://\$server_name\$request_uri;
}

# HTTPS Server with SSL
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $domain;
    
    ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    
    # VMESS WebSocket Secure
    location /vmess {
        proxy_pass http://127.0.0.1:10001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    # SSH via HTTPS
    location /ssh {
        proxy_pass http://127.0.0.1:22;
        proxy_http_version 1.1;
    }
    
    # Web Interface
    location / {
        root /var/www/html;
        index index.html;
    }
}

# HTTP fallback for non-domain access
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    
    location /vmess {
        proxy_pass http://127.0.0.1:10000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    location / {
        root /var/www/html;
        index index.html;
    }
}
EOF
    
    nginx -t && systemctl reload nginx
}

update_v2ray_ssl_config() {
    local domain=$1
    
    # Update config V2Ray untuk SSL
    jq '.inbounds[1].streamSettings.security = "tls" |
        .inbounds[1].streamSettings.tlsSettings.certificates = [
            {
                "certificateFile": "/etc/letsencrypt/live/'"$domain"'/fullchain.pem",
                "keyFile": "/etc/letsencrypt/live/'"$domain"'/privkey.pem"
            }
        ]' /usr/local/etc/v2ray/config.json > /tmp/config.json
    
    mv /tmp/config.json /usr/local/etc/v2ray/config.json
}

setup_ssl_auto_renew_full() {
    cat > /usr/local/bin/renew-ssl-full.sh << 'EOF'
#!/bin/bash
domain=$(cat /etc/vpntunnel/domain.txt 2>/dev/null)
if [ -n "$domain" ]; then
    certbot renew --quiet --post-hook "systemctl reload nginx && systemctl restart v2ray"
    echo "[$(date)] SSL renewed for $domain" >> /var/log/ssl-renew.log
fi
EOF
    
    chmod +x /usr/local/bin/renew-ssl-full.sh
    
    # Add to crontab
    (crontab -l 2>/dev/null; echo "0 3 * * * /usr/local/bin/renew-ssl-full.sh") | crontab -
}

# ================================================
# TAMPILAN HASIL LENGKAP
# ================================================
show_ssh_result_full() {
    local username=$1
    local password=$2
    local expire_date=$3
    local max_ips=$4
    
    SERVER_IP=$(curl -s ifconfig.me)
    DOMAIN=$(cat $DOMAIN_FILE 2>/dev/null || echo "")
    
    clear
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║          🚀 AKUN SSH BERHASIL DIBUAT!                      ║"
    echo "║     Support Port 22, 80, 443, 8080, 8888 + UDP Random      ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo "┌────────────────────────────────────────────────────────────┐"
    echo "│ 👤 Username        : $username"
    echo "│ 🔑 Password        : $password"
    echo "│ 🌐 Server IP       : $SERVER_IP"
    if [ -n "$DOMAIN" ]; then
        echo "│ 🔗 Domain          : $DOMAIN"
    fi
    echo "│ ⚡ SSH Ports       : 22, 80, 443, 8080, 8888"
    echo "│ 🔐 Dropbear Port   : 445"
    echo "│ 📅 Expired Date    : $expire_date"
    echo "│ 📱 Max IP Login    : $max_ips"
    echo "│ 🚀 UDP Support     : ALL PORTS 1-65535 (Random)"
    echo "└────────────────────────────────────────────────────────────┘"
    
    echo ""
    echo -e "${YELLOW}🔧 CONNECTION EXAMPLES:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "${CYAN}1. SSH via HTTPS Port (Bypass Firewall):${NC}"
    echo "   ssh $username@${DOMAIN:-$SERVER_IP} -p 443"
    echo ""
    echo "${CYAN}2. SSH via HTTP Port (Bypass Firewall):${NC}"
    echo "   ssh $username@${DOMAIN:-$SERVER_IP} -p 80"
    echo ""
    echo "${CYAN}3. SSH Standard:${NC}"
    echo "   ssh $username@${DOMAIN:-$SERVER_IP} -p 22"
    echo ""
    echo "${CYAN}4. SSH Tunneling (SOCKS5 Proxy):${NC}"
    echo "   ssh -D 1080 -C -N -f $username@${DOMAIN:-$SERVER_IP} -p 443"
    echo ""
    echo "${CYAN}5. UDP Custom (Any Port 1-65535):${NC}"
    echo "   Use with UDP client on ANY UDP port"
    echo "   Test: test-udp-port.sh <port>"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Simpan config lengkap
    cat > /home/$username/vpn_config.txt << EOF
============================================
🚀 VPN TUNNELING CONFIGURATION
============================================

🌐 SERVER INFORMATION:
IP Address: $SERVER_IP
Domain: ${DOMAIN:-Not Set}

🔐 LOGIN CREDENTIALS:
Username: $username
Password: $password

🔌 CONNECTION PORTS:
SSH Ports: 22, 80, 443, 8080, 8888
Dropbear: 445
UDP Custom: ALL PORTS 1-65535

📡 CONNECTION COMMANDS:
1. SSH via HTTPS: ssh $username@${DOMAIN:-$SERVER_IP} -p 443
2. SSH via HTTP:  ssh $username@${DOMAIN:-$SERVER_IP} -p 80
3. SSH Standard:  ssh $username@${DOMAIN:-$SERVER_IP} -p 22
4. SSH Tunnel:    ssh -D 1080 -C -N -f $username@${DOMAIN:-$SERVER_IP} -p 443
5. UDP Custom:    Use ANY UDP port 1-65535

⚙️ SETTINGS:
Expired Date: $expire_date
Max IP Login: $max_ips

⚠️  WARNING:
- Maximum $max_ips different IPs
- Account expires: $expire_date
- Violation = AUTO LOCK

============================================
Generated on: $(date)
============================================
EOF
    
    echo -e "${YELLOW}💾 Config saved to: /home/$username/vpn_config.txt${NC}"
}

show_vmess_result_full() {
    local username=$1
    local password=$2
    local uuid=$3
    local expire_date=$4
    local max_ips=$5
    
    SERVER_IP=$(curl -s ifconfig.me)
    DOMAIN=$(cat $DOMAIN_FILE 2>/dev/null || echo "")
    
    clear
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║         🚀 AKUN VMESS BERHASIL DIBUAT!                      ║"
    echo "║        Support Port 80 (WS) & 443 (WSS+TLS)                 ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo "┌────────────────────────────────────────────────────────────┐"
    echo "│ 👤 Username        : $username"
    echo "│ 🔑 Password        : $password"
    if [ -n "$DOMAIN" ]; then
        echo "│ 🌐 Domain          : $DOMAIN"
        echo "│ 🔗 Port 80 (HTTP)  : ws://$DOMAIN/vmess"
        echo "│ 🔐 Port 443 (HTTPS): wss://$DOMAIN/vmess"
        echo "│ 📡 Protocol        : WebSocket + TLS"
    else
        echo "│ 🌐 Server IP       : $SERVER_IP"
        echo "│ 🔗 Port 80         : ws://$SERVER_IP/vmess"
        echo "│ 🔗 Port 8443       : tcp://$SERVER_IP:8443"
        echo "│ 📡 Protocol        : WebSocket/TCP"
    fi
    echo "│ 🆔 UUID            : $uuid"
    echo "│ 📅 Expired Date    : $expire_date"
    echo "│ 📱 Max IP Login    : $max_ips"
    echo "│ ⚡ Security        : auto"
    echo "│ 🚀 UDP Support     : ALL PORTS 1-65535"
    echo "└────────────────────────────────────────────────────────────┘"
    
    # Generate VMESS config
    if [ -n "$DOMAIN" ]; then
        # With SSL
        cat > /tmp/vmess-$username.json << EOF
{
  "v": "2",
  "ps": "VPN-$username (SSL)",
  "add": "$DOMAIN",
  "port": "443",
  "id": "$uuid",
  "aid": "0",
  "scy": "auto",
  "net": "ws",
  "type": "none",
  "host": "$DOMAIN",
  "path": "/vmess",
  "tls": "tls",
  "sni": "$DOMAIN",
  "alpn": "h2,http/1.1",
  "fp": "chrome"
}
EOF
        VMESS_URL="vmess://$(base64 -w0 /tmp/vmess-$username.json)"
        
        echo ""
        echo -e "${YELLOW}🔗 VMESS URL (Port 443 with SSL):${NC}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "$VMESS_URL"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        # Also generate HTTP version
        cat > /tmp/vmess-$username-http.json << EOF
{
  "v": "2",
  "ps": "VPN-$username (HTTP)",
  "add": "$DOMAIN",
  "port": "80",
  "id": "$uuid",
  "aid": "0",
  "scy": "auto",
  "net": "ws",
  "type": "none",
  "host": "$DOMAIN",
  "path": "/vmess",
  "tls": "",
  "sni": "",
  "alpn": ""
}
EOF
        VMESS_URL_HTTP="vmess://$(base64 -w0 /tmp/vmess-$username-http.json)"
        
        echo ""
        echo -e "${CYAN}🔗 VMESS URL (Port 80 without SSL):${NC}"
        echo "$VMESS_URL_HTTP"
    else
        # Without SSL
        cat > /tmp/vmess-$username.json << EOF
{
  "v": "2",
  "ps": "VPN-$username",
  "add": "$SERVER_IP",
  "port": "80",
  "id": "$uuid",
  "aid": "0",
  "scy": "auto",
  "net": "ws",
  "type": "none",
  "host": "",
  "path": "/vmess",
  "tls": "",
  "sni": "",
  "alpn": ""
}
EOF
        VMESS_URL="vmess://$(base64 -w0 /tmp/vmess-$username.json)"
        
        echo ""
        echo -e "${YELLOW}🔗 VMESS URL:${NC}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "$VMESS_URL"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    fi
    
    echo ""
    echo -e "${CYAN}📱 QR CODE:${NC}"
    if command -v qrencode &> /dev/null; then
        echo "$VMESS_URL" | qrencode -t UTF8
    else
        echo "Install qrencode for QR: apt install qrencode"
    fi
    
    echo ""
    echo -e "${RED}⚠ PERINGATAN:${NC}"
    echo "• Maksimal $max_ips IP berbeda"
    echo "• Akun expired: $expire_date"
    echo "• Pelanggaran = AUTO LOCK"
    
    # Save config
    cp /tmp/vmess-$username.json $VPN_DIR/vmess-$username.json
    echo -e "${YELLOW}💾 Config saved to: $VPN_DIR/vmess-$username.json${NC}"
}

# ================================================
# MAIN MENU DAN SCRIPT UTAMA
# ================================================
create_main_script() {
    cat > /usr/local/bin/$SCRIPT_NAME << 'EOF'
#!/bin/bash
# VPN TUNNeling Manager Main Script

# Load colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

show_menu() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║           VPN TUNNELING MANAGER v5.0 - SUPER LENGKAP        ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║  [1]  Buat Akun SSH (Port 22,80,443,8080,8888)             ║"
    echo "║  [2]  Buat Akun VMESS (Port 80/443 + WebSocket)            ║"
    echo "║  [3]  Pointing Domain + SSL (Auto Setup)                   ║"
    echo "║  [4]  Fix Nginx Configuration                             ║"
    echo "║  [5]  Backup Data                                         ║"
    echo "║  [6]  Monitoring System                                   ║"
    echo "║  [7]  List User Aktif                                     ║"
    echo "║  [8]  Lock User Manual                                    ║"
    echo "║  [9]  Auto Lock Check                                     ║"
    echo "║  [10] Edit Banner SSH                                     ║"
    echo "║  [11] Server Information                                  ║"
    echo "║  [12] Test UDP Port (1-65535)                             ║"
    echo "║  [13] Restart UDP Random Ports                            ║"
    echo "║  [14] Update Script                                       ║"
    echo "║  [0]  Exit                                                ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Test UDP Port function
test_udp_port() {
    read -p "Enter UDP port to test (1-65535): " port
    if [[ $port -ge 1 && $port -le 65535 ]]; then
        /usr/local/bin/test-udp-port.sh $port
    else
        echo -e "${RED}Port must be between 1-65535${NC}"
    fi
}

# Restart UDP Ports
restart_udp_ports() {
    echo -e "${YELLOW}Restarting UDP Random Ports...${NC}"
    systemctl restart udp-custom.service
    echo -e "${GREEN}UDP ports restarted!${NC}"
    echo "Active UDP ports:"
    cat /etc/vpntunnel/udp_ports.txt 2>/dev/null || echo "No UDP ports file"
}

# Main execution
case "$1" in
    "1"|"ssh")
        create_ssh_account
        ;;
    "2"|"vmess")
        create_vmess_account
        ;;
    "3"|"ssl")
        setup_domain_ssl_full
        ;;
    "4"|"nginx")
        fix_nginx
        ;;
    "5"|"backup")
        backup_data
        ;;
    "6"|"monitor")
        monitoring
        ;;
    "7"|"list")
        list_active_users
        ;;
    "8"|"lock")
        lock_user
        ;;
    "9"|"autolock")
        auto_lock_check
        ;;
    "10"|"banner")
        edit_ssh_banner
        ;;
    "11"|"info")
        show_server_info_full
        ;;
    "12"|"testudp")
        test_udp_port
        ;;
    "13"|"restartudp")
        restart_udp_ports
        ;;
    "14"|"update")
        echo "Updating from GitHub..."
        wget -q -O /tmp/update-vpn.sh \
            https://raw.githubusercontent.com/sukronwae85-design/terlena/main/update.sh
        bash /tmp/update-vpn.sh
        ;;
    "menu"|"")
        while true; do
            show_menu
            read -p "Select menu [0-14]: " choice
            
            case $choice in
                1) create_ssh_account ;;
                2) create_vmess_account ;;
                3) setup_domain_ssl_full ;;
                4) fix_nginx ;;
                5) backup_data ;;
                6) monitoring ;;
                7) list_active_users ;;
                8) lock_user ;;
                9) auto_lock_check ;;
                10) edit_ssh_banner ;;
                11) show_server_info_full ;;
                12) test_udp_port ;;
                13) restart_udp_ports ;;
                14) 
                    echo "Updating..."
                    wget -q -O /tmp/update.sh \
                        https://raw.githubusercontent.com/sukronwae85-design/terlena/main/update.sh
                    bash /tmp/update.sh
                    ;;
                0)
                    echo "Goodbye!"
                    exit 0
                    ;;
                *)
                    echo "Invalid choice!"
                    ;;
            esac
            
            echo ""
            read -p "Press Enter to continue..."
        done
        ;;
    *)
        echo "Usage: vpntunnel [command]"
        echo ""
        echo "Commands:"
        echo "  menu        - Interactive menu"
        echo "  ssh         - Create SSH account (port 80/443)"
        echo "  vmess       - Create VMESS account (port 80/443)"
        echo "  ssl         - Setup domain + SSL"
        echo "  testudp     - Test UDP port 1-65535"
        echo "  restartudp  - Restart UDP random ports"
        echo "  info        - Server information"
        echo "  update      - Update from GitHub"
        ;;
esac
EOF
    
    chmod +x /usr/local/bin/$SCRIPT_NAME
    ln -sf /usr/local/bin/$SCRIPT_NAME /usr/bin/$SCRIPT_NAME 2>/dev/null
}

# ================================================
# FUNGSI TAMBAHAN UNTUK UDP RANDOM
# ================================================
show_server_info_full() {
    SERVER_IP=$(curl -s ifconfig.me)
    DOMAIN=$(cat $DOMAIN_FILE 2>/dev/null || echo "Not configured")
    UDP_PORTS=$(cat $UDP_PORTS_FILE 2>/dev/null || echo "7100 7200 7300 + Random")
    
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║               🚀 VPN TUNNELING SERVER INFO                  ║"
    echo "║                 SUPER LENGKAP EDITION                       ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo "┌────────────────────────────────────────────────────────────┐"
    echo "│ 🌐 SERVER INFORMATION                                      │"
    echo "├────────────────────────────────────────────────────────────┤"
    echo "│ IP Address       : $SERVER_IP"
    echo "│ Domain           : $DOMAIN"
    echo "│ OS Version       : $(lsb_release -ds)"
    echo "│ Uptime           : $(uptime -p)"
    echo "│ Load Average     : $(uptime | awk -F'load average:' '{print $2}')"
    echo "│ Manager Command  : vpntunnel"
    echo "└────────────────────────────────────────────────────────────┘"
    
    echo ""
    echo "┌────────────────────────────────────────────────────────────┐"
    echo "│ 🔌 PORT CONFIGURATION - ALL PORTS OPEN                    │"
    echo "├────────────────────────────────────────────────────────────┤"
    echo "│ SSH Ports        : 22, 80, 443, 8080, 8888"
    echo "│ Dropbear Port    : 445"
    echo "│ Stunnel Port     : 444"
    echo "│ VMESS Ports      : 80 (WS), 443 (WSS+TLS), 8443"
    echo "│ UDP Custom       : ALL PORTS 1-65535 (Random)"
    echo "│ Active UDP Ports : $UDP_PORTS"
    echo "│ Nginx Ports      : 80, 443"
    echo "└────────────────────────────────────────────────────────────┘"
    
    echo ""
    echo "┌────────────────────────────────────────────────────────────┐"
    echo "│ ⚡ SERVICE STATUS                                          │"
    echo "├────────────────────────────────────────────────────────────┤"
    echo "│ SSH Service      : $(systemctl is-active ssh)"
    echo "│ V2Ray Service    : $(systemctl is-active v2ray)"
    echo "│ Nginx Service    : $(systemctl is-active nginx)"
    echo "│ Dropbear Service : $(systemctl is-active dropbear)"
    echo "│ UDP Custom       : $(systemctl is-active udp-custom.service)"
    echo "└────────────────────────────────────────────────────────────┘"
    
    echo ""
    echo -e "${YELLOW}📊 CONNECTION STATS:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "SSH Connections    : $(who | wc -l) users"
    echo "VMESS Connections  : $(netstat -an | grep ':10000\|:10001' | wc -l)"
    echo "UDP Ports Active   : $(cat $UDP_PORTS_FILE 2>/dev/null | wc -w)"
    echo "Total Users        : $(grep -c '^[^#]' $USER_DB 2>/dev/null || echo 0)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    echo ""
    echo -e "${GREEN}✅ SERVER READY FOR VPN TUNNELING!${NC}"
    echo "Use 'vpntunnel menu' for management"
}

# ================================================
# INSTALLATION PROCESS
# ================================================
if [[ "$1" == "install" ]]; then
    install_vpn
elif [[ "$1" == "uninstall" ]]; then
    echo -e "${RED}Uninstalling VPN Tunneling...${NC}"
    systemctl stop v2ray nginx dropbear udp-custom.service
    systemctl disable v2ray nginx dropbear udp-custom.service
    rm -rf $VPN_DIR $BACKUP_DIR
    rm -f /usr/local/bin/$SCRIPT_NAME /usr/bin/$SCRIPT_NAME 2>/dev/null
    rm -f /usr/local/bin/test-udp-port.sh /usr/local/bin/open-all-udp-ports.sh
    echo -e "${GREEN}Uninstall complete!${NC}"
else
    show_banner
    echo "VPN Tunneling Manager SUPER LENGKAP"
    echo ""
    echo "Options:"
    echo "1. Install VPN Tunneling (Super Complete)"
    echo "2. Run VPN Manager Menu"
    echo "3. Uninstall"
    echo ""
    read -p "Select [1-3]: " main_choice
    
    case $main_choice in
        1)
            install_vpn
            ;;
        2)
            if [ -f /usr/local/bin/$SCRIPT_NAME ]; then
                /usr/local/bin/$SCRIPT_NAME menu
            else
                echo -e "${RED}VPN not installed!${NC}"
                echo "Run: $0 install"
            fi
            ;;
        3)
            $0 uninstall
            ;;
        *)
            echo "Invalid selection"
            ;;
    esac
fi
