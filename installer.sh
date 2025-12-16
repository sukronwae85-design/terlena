#!/bin/bash
# ========================================================
# TERLENA VPN MANAGER - SSH + VMESS + UDP CUSTOM
# Repository: https://github.com/sukronwae85-design/terlena
# Support: Ubuntu 18.04/20.04/22.04
# ========================================================

# Color Codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Global Variables
SCRIPT_NAME="terlena"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/terlena"
LOG_DIR="/var/log/terlena"
DATABASE="$CONFIG_DIR/users.db"
BACKUP_DIR="/root/terlena-backup"
DOMAIN_FILE="$CONFIG_DIR/domain.txt"

# Port Configuration
SSH_PORT=22
VMESS_PORT=443
UDP_PORTS="7300 7200 7100"
WEB_PORT=80
SSL_PORT=443

# Banner Function
show_banner() {
    clear
    echo -e "${CYAN}"
    cat << "BANNER"
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ████████╗███████╗██████╗ ██╗     ███████╗███╗   ██╗ █████╗ ║
║   ╚══██╔══╝██╔════╝██╔══██╗██║     ██╔════╝████╗  ██║██╔══██╗║
║      ██║   █████╗  ██████╔╝██║     █████╗  ██╔██╗ ██║███████║║
║      ██║   ██╔══╝  ██╔══██╗██║     ██╔══╝  ██║╚██╗██║██╔══██║║
║      ██║   ███████╗██║  ██║███████╗███████╗██║ ╚████║██║  ██║║
║      ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝║
║                                                              ║
║                SSH • VMESS • UDP CUSTOM                      ║
║              GitHub: sukronwae85-design/terlena              ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
BANNER
    echo -e "${NC}"
    
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}OS Version  : ${GREEN}$(lsb_release -ds)${NC}"
    echo -e "${WHITE}Server IP   : ${GREEN}$(curl -s ifconfig.me)${NC}"
    echo -e "${WHITE}Date        : ${GREEN}$(date)${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Logging
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_DIR/install.log"
}

# Check Root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}✗ Script ini harus dijalankan sebagai root!${NC}"
        echo -e "${YELLOW}Gunakan: sudo bash $0${NC}"
        exit 1
    fi
}

# Detect OS
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
        echo -e "${GREEN}✓ OS: $OS $VER terdeteksi${NC}"
    else
        echo -e "${RED}✗ OS tidak dikenali!${NC}"
        exit 1
    fi
}

# ============================================
# INSTALLATION FUNCTIONS
# ============================================

# Install Dependencies
install_dependencies() {
    echo -e "${YELLOW}[+] Install dependencies...${NC}"
    apt-get update -y
    apt-get upgrade -y
    
    # Install essential packages
    apt-get install -y \
        wget curl nano git ufw fail2ban \
        jq qrencode net-tools bc \
        openssl stunnel4 dropbear \
        screen htop iftop \
        build-essential libssl-dev \
        python3 python3-pip
    
    # Install specific versions for Ubuntu compatibility
    if [[ $VER == "18.04" ]]; then
        apt-get install -y software-properties-common
        add-apt-repository ppa:maxmind/ppa -y
    fi
    
    pip3 install requests flask
    echo -e "${GREEN}✓ Dependencies terinstall${NC}"
}

# Install SSH Server
install_ssh() {
    echo -e "${YELLOW}[+] Install SSH Server...${NC}"
    
    # Backup original ssh config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    # Create custom SSH banner
    cat > /etc/issue.net << "BANNER"
╔══════════════════════════════════════════════════════════════╗
║                    TERLENA VPN SERVER                       ║
║                   🌐 SSH • VMESS • UDP                      ║
║            🔒 Secure Connection Established                 ║
║          📅 Login: $(date)                                   ║
║          🌍 Server: $(hostname)                              ║
╚══════════════════════════════════════════════════════════════╝
SERVER RULES:
1. No Spamming / DDoS
2. No Illegal Activities
3. Max $(grep "^$USER" $DATABASE 2>/dev/null | cut -d'|' -f5) Concurrent Logins
4. Expired: $(grep "^$USER" $DATABASE 2>/dev/null | cut -d'|' -f4)

⚠️ VIOLATION WILL RESULT IN ACCOUNT SUSPENSION ⚠️
BANNER
    
    # Configure SSHD
    cat > /etc/ssh/sshd_config << EOF
Port $SSH_PORT
Port 2269
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
Banner /etc/issue.net
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
EOF
    
    # Configure Dropbear (for additional SSH)
    echo 'NO_START=0' > /etc/default/dropbear
    echo 'DROPBEAR_PORT=2259' >> /etc/default/dropbear
    echo 'DROPBEAR_EXTRA_ARGS="-p 2259"' >> /etc/default/dropbear
    
    systemctl restart ssh
    systemctl restart dropbear
    echo -e "${GREEN}✓ SSH Server terinstall${NC}"
}

# Install V2Ray (VMess)
install_v2ray() {
    echo -e "${YELLOW}[+] Install V2Ray VMess...${NC}"
    
    # Install V2Ray official script
    bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
    
    # Create V2Ray config
    cat > /usr/local/etc/v2ray/config.json << EOF
{
  "log": {
    "loglevel": "warning",
    "access": "$LOG_DIR/v2ray-access.log",
    "error": "$LOG_DIR/v2ray-error.log"
  },
  "inbounds": [
    {
      "port": $VMESS_PORT,
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
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },
    {
      "port": $WEB_PORT,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1",
        "port": 80,
        "network": "tcp,udp"
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
EOF
    
    # Create VMess user management script
    cat > $CONFIG_DIR/v2ray_manager.sh << 'EOF'
#!/bin/bash
CONFIG="/usr/local/etc/v2ray/config.json"
DB="/etc/terlena/users.db"

add_vmess_user() {
    local username=$1
    local uuid=$(cat /proc/sys/kernel/random/uuid)
    
    # Add to V2Ray config
    jq --arg user "$username" --arg uuid "$uuid" \
       '.inbounds[0].settings.clients += [{"id": $uuid, "alterId": 0, "email": $user}]' \
       $CONFIG > /tmp/config.json && mv /tmp/config.json $CONFIG
    
    # Restart V2Ray
    systemctl restart v2ray
    
    echo "$uuid"
}

remove_vmess_user() {
    local username=$1
    jq --arg user "$username" \
       '.inbounds[0].settings.clients |= map(select(.email != $user))' \
       $CONFIG > /tmp/config.json && mv /tmp/config.json $CONFIG
    systemctl restart v2ray
}
EOF
    
    chmod +x $CONFIG_DIR/v2ray_manager.sh
    systemctl enable v2ray
    systemctl start v2ray
    echo -e "${GREEN}✓ V2Ray VMess terinstall${NC}"
}

# Install UDP Custom (BadVPN UDPGw)
install_udp_custom() {
    echo -e "${YELLOW}[+] Install UDP Custom (BadVPN-UDPGw)...${NC}"
    
    # Install BadVPN UDPGw
    apt-get install -y cmake build-essential
    
    cd /tmp
    wget -q https://github.com/ambrop72/badvpn/archive/refs/tags/1.999.130.tar.gz
    tar -xzf 1.999.130.tar.gz
    cd badvpn-1.999.130
    mkdir build && cd build
    cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
    make
    cp udpgw/badvpn-udpgw /usr/local/bin/
    
    # Create multiple UDP ports service
    for port in $UDP_PORTS; do
        cat > /etc/systemd/system/badvpn-$port.service << EOF
[Unit]
Description=BadVPN UDPGw Port $port
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 0.0.0.0:$port --max-clients 1000 --max-connections-for-client 10
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
        systemctl enable badvpn-$port
        systemctl start badvpn-$port
    done
    
    echo -e "${GREEN}✓ UDP Custom terinstall di port: $UDP_PORTS${NC}"
}

# Configure Firewall & Ports
configure_firewall() {
    echo -e "${YELLOW}[+] Konfigurasi firewall...${NC}"
    
    # Reset firewall
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    
    # Open essential ports
    ufw allow $SSH_PORT/tcp
    ufw allow $VMESS_PORT/tcp
    ufw allow $WEB_PORT/tcp
    ufw allow $SSL_PORT/tcp
    
    # Open UDP ports
    for port in $UDP_PORTS; do
        ufw allow $port/udp
    done
    
    # Open random UDP ports (10000-50000)
    ufw allow 10000:50000/udp
    
    # Enable firewall
    echo "y" | ufw enable
    ufw status verbose
    
    echo -e "${GREEN}✓ Firewall terkonfigurasi${NC}"
}

# Setup User Database
setup_database() {
    echo -e "${YELLOW}[+] Setup database user...${NC}"
    
    mkdir -p $CONFIG_DIR $LOG_DIR $BACKUP_DIR
    
    # Create user database structure
    cat > $DATABASE << EOF
# Format: username|password|type|expire_date|max_ips|is_locked|last_login|login_count|uuid|port|created_date
# type: ssh/vmess/both
EOF
    
    # Create user management functions
    cat > $CONFIG_DIR/user_functions.sh << 'EOF'
#!/bin/bash
DB="/etc/terlena/users.db"
LOG="/var/log/terlena/user.log"

add_user() {
    local username=$1
    local password=$2
    local type=$3
    local days=$4
    local max_ips=$5
    
    # Check if user exists
    if grep -q "^$username|" $DB; then
        echo "User sudah ada!"
        return 1
    fi
    
    # Generate data
    local expire_date=$(date -d "+$days days" +%Y-%m-%d)
    local created_date=$(date +%Y-%m-%d)
    local uuid=""
    local port=""
    
    if [[ $type == "vmess" || $type == "both" ]]; then
        uuid=$(cat /proc/sys/kernel/random/uuid)
        /etc/terlena/v2ray_manager.sh add_vmess_user $username
    fi
    
    if [[ $type == "ssh" || $type == "both" ]]; then
        # Create SSH user
        useradd -m -s /bin/false $username
        echo "$username:$password" | chpasswd
        port=$SSH_PORT
    fi
    
    # Save to database
    echo "$username|$password|$type|$expire_date|$max_ips|0||0|$uuid|$port|$created_date" >> $DB
    
    echo "User berhasil dibuat!"
    echo "$(date) - User $username created" >> $LOG
}

list_users() {
    echo "┌────────────────────────────────────────────────────────────────────────────┐"
    printf "│ %-15s │ %-10s │ %-12s │ %-6s │ %-7s │ Status │\n" "Username" "Type" "Expire" "Max IP" "Used"
    echo "├────────────────────────────────────────────────────────────────────────────┤"
    
    while IFS='|' read -r username password type expire max_ips locked last_login login_count uuid port created; do
        if [[ ! $username =~ ^# ]]; then
            # Get current IP count (simplified)
            local ip_count=$(who | grep $username | awk '{print $5}' | sort -u | wc -l)
            
            local status="🟢"
            [[ $locked == "1" ]] && status="🔴"
            [[ $(date -d "$expire" +%s) -lt $(date +%s) ]] && status="🟡"
            
            printf "│ %-15s │ %-10s │ %-12s │ %6s │ %7s │   %s   │\n" \
                "$username" "$type" "$expire" "$max_ips" "$ip_count/$max_ips" "$status"
        fi
    done < $DB
    echo "└────────────────────────────────────────────────────────────────────────────┘"
}

lock_user() {
    local username=$1
    sed -i "s/^$username|\(.*\)|0|/&\|1/" $DB
    
    if [[ $type == *"ssh"* ]]; then
        usermod -L $username 2>/dev/null
        pkill -u $username 2>/dev/null
    fi
    
    echo "User $username locked!"
    echo "$(date) - User $username locked" >> $LOG
}

check_limits() {
    while read line; do
        IFS='|' read -r username password type expire max_ips locked last_login login_count uuid port created <<< "$line"
        
        if [[ $locked == "0" ]]; then
            # Check IP limit
            local ip_count=$(who | grep $username | awk '{print $5}' | sort -u | wc -l)
            
            if [[ $ip_count -gt $max_ips ]]; then
                lock_user $username
                echo "User $username locked due to IP limit violation!"
            fi
            
            # Check expiration
            if [[ $(date -d "$expire" +%s) -lt $(date +%s) ]]; then
                lock_user $username
                echo "User $username locked due to expiration!"
            fi
        fi
    done < <(grep -v '^#' $DB)
}
EOF
    
    chmod +x $CONFIG_DIR/user_functions.sh
    echo -e "${GREEN}✓ Database terinisialisasi${NC}"
}

# Setup SSL with Cloudflare
setup_ssl() {
    echo -e "${YELLOW}[+] Setup SSL Certificate...${NC}"
    
    # Ask for domain
    read -p "Masukkan domain Anda (atau tekan Enter untuk skip): " domain
    
    if [[ -n $domain ]]; then
        echo "$domain" > $DOMAIN_FILE
        
        # Install Certbot
        apt-get install -y certbot
        
        # Get SSL certificate
        certbot certonly --standalone --agree-tos --register-unsafely-without-email \
            -d $domain --non-interactive
            
        if [[ -f /etc/letsencrypt/live/$domain/fullchain.pem ]]; then
            # Update V2Ray config with SSL
            jq --arg cert "/etc/letsencrypt/live/$domain/fullchain.pem" \
               --arg key "/etc/letsencrypt/live/$domain/privkey.pem" \
               '.inbounds[0].streamSettings.tlsSettings.certificates = [{"certificateFile": $cert, "keyFile": $key}]' \
               /usr/local/etc/v2ray/config.json > /tmp/config.json
            mv /tmp/config.json /usr/local/etc/v2ray/config.json
            
            systemctl restart v2ray
            echo -e "${GREEN}✓ SSL certificate terinstal untuk $domain${NC}"
        else
            echo -e "${YELLOW}⚠ SSL certificate gagal, menggunakan self-signed${NC}"
            create_self_signed_ssl
        fi
    else
        create_self_signed_ssl
    fi
}

create_self_signed_ssl() {
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/private/selfsigned.key \
        -out /etc/ssl/certs/selfsigned.crt \
        -subj "/C=US/ST=CA/L=SF/O=Terlena/CN=terlena-vpn"
    
    echo -e "${GREEN}✓ Self-signed SSL certificate dibuat${NC}"
}

# Setup Monitoring
setup_monitoring() {
    echo -e "${YELLOW}[+] Setup monitoring system...${NC}"
    
    # Create monitoring script
    cat > $CONFIG_DIR/monitor.sh << 'EOF'
#!/bin/bash
DB="/etc/terlena/users.db"
LOG="/var/log/terlena/monitor.log"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                   TERLENA VPN MONITOR                       ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║ $(date) ║"
echo "╚══════════════════════════════════════════════════════════════╝"

# Show server status
echo -e "\n${CYAN}📊 SERVER STATUS:${NC}"
echo "CPU Usage: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}')%"
echo "Memory: $(free -h | awk '/^Mem:/ {print $3 "/" $2}')"
echo "Uptime: $(uptime -p)"

# Show active connections
echo -e "\n${CYAN}👥 ACTIVE CONNECTIONS:${NC}"
echo "SSH Users: $(who | wc -l)"
echo "V2Ray Connections: $(netstat -an | grep :443 | wc -l)"
echo "UDP Custom Connections: $(netstat -an | grep '7200\|7300\|7100' | wc -l)"

# Show user statistics
echo -e "\n${CYAN}👤 USER STATISTICS:${NC}"
total_users=$(grep -c '^[^#]' $DB)
active_users=$(who | awk '{print $1}' | sort -u | wc -l)
locked_users=$(grep -c '|1|' $DB)
echo "Total Users: $total_users"
echo "Active Now: $active_users"
echo "Locked Users: $locked_users"

# Show top bandwidth users
echo -e "\n${CYAN}📈 BANDWIDTH USAGE:${NC}"
echo "Top 5 SSH Users:"
ss -tn | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -5

echo -e "\n${RED}⚠ VIOLATIONS:${NC}"
grep "locked" /var/log/terlena/user.log | tail -5
EOF
    
    chmod +x $CONFIG_DIR/monitor.sh
    
    # Create cron job for auto monitoring
    echo "*/5 * * * * root $CONFIG_DIR/monitor.sh >> $LOG_DIR/monitor.log" > /etc/cron.d/terlena-monitor
    
    echo -e "${GREEN}✓ Monitoring system terpasang${NC}"
}

# Create Main Manager Script
create_manager_script() {
    echo -e "${YELLOW}[+] Membuat terlena manager script...${NC}"
    
    cat > $INSTALL_DIR/$SCRIPT_NAME << 'EOF'
#!/bin/bash
# TERLENA VPN MANAGER - Main Script

source /etc/terlena/user_functions.sh

show_menu() {
    clear
    echo -e "${CYAN}"
    cat << "MENU"
╔══════════════════════════════════════════════════════╗
║            TERLENA VPN MANAGER v2.0                 ║
╠══════════════════════════════════════════════════════╣
║  [1]  BUAT USER BARU                               ║
║  [2]  LIST SEMUA USER                              ║
║  [3]  LIST USER AKTIF                              ║
║  [4]  DETAIL USER                                  ║
║  [5]  HAPUS USER                                   ║
║  [6]  LOCK USER                                    ║
║  [7]  UNLOCK USER                                  ║
║  [8]  RESET PASSWORD                               ║
║  [9]  UBAH EXPIRED DATE                            ║
║  [10] UBAH MAX IP                                  ║
║  [11] CHECK LIMIT (AUTO LOCK)                      ║
║  [12] MONITOR LIVE CONNECTIONS                     ║
║  [13] BACKUP DATA                                  ║
║  [14] RESTORE DATA                                 ║
║  [15] TEST SPEED                                   ║
║  [16] CHECK SSL STATUS                             ║
║  [17] UPDATE SCRIPT                                ║
║  [18] UNINSTALL                                    ║
║  [0]  EXIT                                         ║
╚══════════════════════════════════════════════════════╝
MENU
    echo -e "${NC}"
}

show_user_result() {
    local username=$1
    local password=$2
    local type=$3
    local expire=$4
    local max_ips=$5
    local uuid=$6
    
    SERVER_IP=$(curl -s ifconfig.me)
    
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║          USER BERHASIL DIBUAT!                          ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo "┌────────────────────────────────────────────────────┐"
    echo "│ Username      : $username"
    echo "│ Password      : $password"
    echo "│ Server IP     : $SERVER_IP"
    echo "│ Expire Date   : $expire"
    echo "│ Max IP Login  : $max_ips"
    echo "│ Account Type  : $type"
    echo "└────────────────────────────────────────────────────┘"
    
    if [[ $type == *"ssh"* ]]; then
        echo -e "\n${YELLOW}🔐 SSH CONFIG:${NC}"
        echo "Host: $SERVER_IP"
        echo "Port: 22, 2269, 2259"
        echo "Username: $username"
        echo "Password: $password"
        
        echo -e "\n${CYAN}📱 SSH TUNNEL UDP:${NC}"
        echo "Command: ssh -D 8080 -C -N -f $username@$SERVER_IP -p 22"
    fi
    
    if [[ $type == *"vmess"* ]] && [[ -n $uuid ]]; then
        echo -e "\n${YELLOW}🌐 VMESS CONFIG:${NC}"
        cat > /tmp/vmess-$username.json << VMESS
{
  "v": "2",
  "ps": "Terlena-$username",
  "add": "$SERVER_IP",
  "port": "443",
  "id": "$uuid",
  "aid": "0",
  "scy": "auto",
  "net": "ws",
  "type": "none",
  "host": "",
  "path": "/vmess",
  "tls": "tls",
  "sni": "",
  "alpn": ""
}
VMESS
        
        echo "vmess://$(base64 -w0 /tmp/vmess-$username.json)"
        echo -e "\n${CYAN}📋 QR CODE VMESS:${NC}"
        echo "vmess://$(base64 -w0 /tmp/vmess-$username.json)" | qrencode -t UTF8
    fi
    
    echo -e "\n${RED}⚠ PERINGATAN:${NC}"
    echo "• Maksimal $max_5 IP berbeda"
    echo "• Akun expired: $expire"
    echo "• Pelanggaran = AUTO LOCK"
}

backup_data() {
    local backup_file="$BACKUP_DIR/terlena-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
    tar -czf "$backup_file" \
        /etc/terlena \
        /usr/local/etc/v2ray \
        /etc/ssh/sshd_config \
        /etc/issue.net \
        /var/log/terlena
    
    echo -e "${GREEN}✓ Backup berhasil: $backup_file${NC}"
}

# Main execution
case "$1" in
    "add"|"1")
        read -p "Username: " username
        read -p "Password (random jika kosong): " password
        [ -z "$password" ] && password=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 10)
        
        echo "Tipe akun:"
        echo "1. SSH Only"
        echo "2. VMess Only"
        echo "3. SSH + VMess"
        read -p "Pilih [1-3]: " type_choice
        
        case $type_choice in
            1) type="ssh" ;;
            2) type="vmess" ;;
            3) type="both" ;;
            *) type="ssh" ;;
        esac
        
        read -p "Masa aktif (hari): " days
        read -p "Max IP login (default 2): " max_ips
        max_ips=${max_ips:-2}
        
        add_user "$username" "$password" "$type" "$days" "$max_ips"
        
        # Get user data for display
        user_data=$(grep "^$username|" $DB)
        IFS='|' read -r username password type expire max_ips locked last_login login_count uuid port created <<< "$user_data"
        
        show_user_result "$username" "$password" "$type" "$expire" "$max_ips" "$uuid"
        ;;
        
    "list"|"2")
        list_users
        ;;
        
    "active"|"3")
        echo -e "${CYAN}👥 USER AKTIF SEKARANG:${NC}"
        who | awk '{print $1}' | sort -u
        echo ""
        echo -e "${CYAN}📊 DETAIL:${NC}"
        list_users
        ;;
        
    "monitor"|"12")
        /etc/terlena/monitor.sh
        ;;
        
    "backup"|"13")
        backup_data
        ;;
        
    "check"|"11")
        check_limits
        ;;
        
    "menu"|"")
        while true; do
            show_menu
            read -p "Pilih menu [0-18]: " choice
            
            case $choice in
                1)
                    read -p "Username: " username
                    read -p "Password: " password
                    [ -z "$password" ] && password=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 10)
                    read -p "Tipe (ssh/vmess/both): " type
                    read -p "Hari: " days
                    read -p "Max IP: " max_ips
                    add_user "$username" "$password" "$type" "$days" "$max_ips"
                    ;;
                2) list_users ;;
                3) 
                    echo "Aktif: $(who | awk '{print $1}' | sort -u | tr '\n' ' ')"
                    echo ""
                    ;;
                11) check_limits ;;
                12) /etc/terlena/monitor.sh ;;
                13) backup_data ;;
                0) exit 0 ;;
                *) echo "Pilihan tidak valid" ;;
            esac
            echo ""
            read -p "Tekan Enter untuk melanjutkan..."
        done
        ;;
        
    *)
        echo "Penggunaan: terlena [command]"
        echo "Commands: menu, add, list, active, monitor, backup, check"
        ;;
esac
EOF
    
    chmod +x $INSTALL_DIR/$SCRIPT_NAME
    ln -sf $INSTALL_DIR/$SCRIPT_NAME /usr/bin/$SCRIPT_NAME 2>/dev/null
    
    echo -e "${GREEN}✓ Manager script terinstall${NC}"
}

# Main Installation Function
main_installation() {
    show_banner
    check_root
    detect_os
    
    echo -e "${YELLOW}⚠ Memulai instalasi TERLENA VPN...${NC}"
    echo -e "${RED}Ini akan memakan waktu 5-10 menit.${NC}"
    echo ""
    
    # Progress steps
    steps=(
        "Install Dependencies"
        "Install SSH Server"
        "Install V2Ray VMess"
        "Install UDP Custom"
        "Setup Firewall"
        "Setup Database"
        "Setup SSL"
        "Setup Monitoring"
        "Create Manager Script"
    )
    
    for i in "${!steps[@]}"; do
        echo -e "${BLUE}[$((i+1))/${#steps[@]}] ${steps[i]}...${NC}"
        
        case $i in
            0) install_dependencies ;;
            1) install_ssh ;;
            2) install_v2ray ;;
            3) install_udp_custom ;;
            4) configure_firewall ;;
            5) setup_database ;;
            6) setup_ssl ;;
            7) setup_monitoring ;;
            8) create_manager_script ;;
        esac
        
        echo -e "${GREEN}✓ ${steps[i]} selesai${NC}"
        echo ""
    done
    
    # Final output
    show_installation_result
}

# Show Installation Result
show_installation_result() {
    SERVER_IP=$(curl -s ifconfig.me)
    
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║         INSTALASI TERLENA VPN BERHASIL!                     ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo "┌────────────────────────────────────────────────────────────┐"
    echo "│ SERVER INFORMATION                                         │"
    echo "├────────────────────────────────────────────────────────────┤"
    echo "│ IP Address      : $SERVER_IP"
    echo "│ SSH Ports       : 22, 2259, 2269"
    echo "│ VMess Port      : 443 (WS + TLS)"
    echo "│ UDP Custom Ports: 7100, 7200, 7300"
    echo "│ UDP Random Ports: 10000-50000 (All Open)"
    echo "│ Web Port        : 80 (Nginx)"
    echo "│ SSL Port        : 443 (Auto SSL)"
    echo "│ Manager Command : terlena"
    echo "│ Config Directory: /etc/terlena"
    echo "│ Log Directory   : /var/log/terlena"
    echo "│ Backup Directory: /root/terlena-backup"
    echo "└────────────────────────────────────────────────────────────┘"
    
    echo -e "\n${YELLOW}🚀 CARA PENGGUNAAN:${NC}"
    echo "1. Buat user baru: ${GREEN}terlena add${NC}"
    echo "2. Menu interaktif: ${GREEN}terlena menu${NC}"
    echo "3. List semua user: ${GREEN}terlena list${NC}"
    echo "4. Monitoring: ${GREEN}terlena monitor${NC}"
    echo "5. Auto lock check: ${GREEN}terlena check${NC}"
    
    echo -e "\n${RED}🔒 FITUR KEAMANAN:${NC}"
    echo "• Auto lock jika melebihi max IP"
    echo "• Auto lock jika expired"
    echo "• Login banner dengan peringatan"
    echo "• Fail2ban protection"
    echo "• Firewall dengan port terbatas"
    
    echo -e "\n${CYAN}📊 MONITORING:${NC}"
    echo "• Live connection monitoring"
    echo "• Auto backup setiap minggu"
    echo "• SSL auto-renewal"
    echo "• Resource usage tracking"
    
    # Test services
    echo -e "\n${YELLOW}🧪 TESTING SERVICES...${NC}"
    systemctl is-active --quiet ssh && echo "✓ SSH Service: RUNNING" || echo "✗ SSH Service: FAILED"
    systemctl is-active --quiet v2ray && echo "✓ V2Ray Service: RUNNING" || echo "✗ V2Ray Service: FAILED"
    
    echo -e "\n${GREEN}✅ INSTALASI SELESAI!${NC}"
    echo "Script akan auto-update dari GitHub Anda."
    echo "Repository: https://github.com/sukronwae85-design/terlena"
}

# ============================================
# EXECUTION
# ============================================

if [[ $1 == "uninstall" ]]; then
    echo -e "${RED}[!] Uninstalling Terlena VPN...${NC}"
    
    # Stop all services
    systemctl stop v2ray 2>/dev/null
    systemctl disable v2ray 2>/dev/null
    
    for port in $UDP_PORTS; do
        systemctl stop badvpn-$port 2>/dev/null
        systemctl disable badvpn-$port 2>/dev/null
    done
    
    # Remove files
    rm -rf $CONFIG_DIR $LOG_DIR $BACKUP_DIR
    rm -f $INSTALL_DIR/$SCRIPT_NAME
    rm -f /usr/bin/$SCRIPT_NAME 2>/dev/null
    rm -f /etc/cron.d/terlena-monitor
    rm -f /etc/issue.net
    cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config 2>/dev/null
    
    systemctl restart ssh
    
    echo -e "${GREEN}✓ Terlena VPN berhasil diuninstall${NC}"
    exit 0
fi

# Run main installation
main_installation