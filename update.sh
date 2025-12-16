#!/bin/bash
echo "🔄 Updating VPN Tunneling Manager SUPER LENGKAP..."
echo ""

# Backup existing config
BACKUP_DIR="/root/vpn-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p $BACKUP_DIR

# Backup important files
cp -r /etc/vpntunnel $BACKUP_DIR/ 2>/dev/null
cp /usr/local/etc/v2ray/config.json $BACKUP_DIR/ 2>/dev/null
cp /etc/nginx/sites-available/vmess $BACKUP_DIR/ 2>/dev/null

echo "✅ Backup created at: $BACKUP_DIR"

# Download latest installer
wget -q -O /tmp/vpn-update.sh \
    https://raw.githubusercontent.com/sukronwae85-design/terlena/main/installer.sh

if [ -f /usr/local/bin/vpntunnel ]; then
    echo "🔄 Applying update..."
    bash /tmp/vpn-update.sh install
    
    # Restore domain if exists
    if [ -f $BACKUP_DIR/vpntunnel/domain.txt ]; then
        cp $BACKUP_DIR/vpntunnel/domain.txt /etc/vpntunnel/
        echo "✅ Domain configuration restored"
    fi
    
    # Restore users if exists
    if [ -f $BACKUP_DIR/vpntunnel/users.db ]; then
        cp $BACKUP_DIR/vpntunnel/users.db /etc/vpntunnel/
        echo "✅ User database restored"
    fi
    
    echo ""
    echo "✅ UPDATE COMPLETE!"
    echo ""
    echo "New Features:"
    echo "• SSH Port 80/443 support"
    echo "• VMESS Port 80/443 support"
    echo "• UDP Random Ports 1-65535"
    echo "• Enhanced monitoring"
    echo ""
    echo "Run: vpntunnel menu"
else
    echo "❌ VPN not installed. Run installer.sh first"
fi