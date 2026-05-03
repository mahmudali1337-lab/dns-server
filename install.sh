#!/bin/bash
set -e

REPO_URL="https://github.com/mahmudali1337-lab/dns-server"
INSTALL_DIR="/opt/dns-server"
SERVICE="dns-server"
DOMAIN="${1:-dstat.coffee}"
SERVER_IP="${2:-$(hostname -I | awk '{print $1}')}"

echo "[*] Installing dependencies..."
apt-get update -qq
apt-get install -y -qq git golang-go

echo "[*] Building dns-server..."
TMP=$(mktemp -d)
cd "$TMP"
git clone "$REPO_URL" src
cd src
go build -o "$INSTALL_DIR/$SERVICE" .
cp config.yaml "$INSTALL_DIR/config.yaml"
cp dns-server.service /etc/systemd/system/dns-server.service
cd /
rm -rf "$TMP"

echo "[*] Writing config..."
cat > "$INSTALL_DIR/config.yaml" << EOF
listen: ":53"
zones:
  - domain: "$DOMAIN"
    ip: "$SERVER_IP"
    ttl: 300
    subs:
      - name: "www"
        ip: "$SERVER_IP"
      - name: "mail"
        ip: "$SERVER_IP"
      - name: "api"
        ip: "$SERVER_IP"
EOF

echo "[*] Opening firewall ports..."
if command -v ufw &>/dev/null && ufw status &>/dev/null 2>&1; then
    ufw allow 53/udp comment "DNS" || true
    ufw allow 53/tcp comment "DNS" || true
    ufw --force enable || true
    echo "  [ufw] rules added"
elif command -v iptables &>/dev/null; then
    iptables -C INPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport 53 -j ACCEPT
    iptables -C INPUT -p tcp --dport 53 -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport 53 -j ACCEPT
    echo "  [iptables] rules added"
else
    echo "  [!] No firewall tool found, skipping — open port 53 manually if needed"
fi

echo "[*] Enabling and starting service..."
systemctl daemon-reload
systemctl enable "$SERVICE"
systemctl restart "$SERVICE"

echo ""
echo "===== DNS SERVER INSTALLED ====="
echo ""
echo "Server IP : $SERVER_IP"
echo "Domain    : $DOMAIN"
echo "Status    : $(systemctl is-active $SERVICE)"
echo ""
echo "Logs: journalctl -u $SERVICE -f"
