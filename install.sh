#!/bin/bash
set -e

REPO_URL="https://github.com/mahmudali1337-lab/dns-server"
INSTALL_DIR="/opt/dns-server"
SERVICE="dns-server"
DOMAIN="${1:-dstat.coffee}"
SERVER_IP="${2:-$(hostname -I | awk '{print $1}')}"

echo "[*] Installing dependencies..."
apt-get update -qq
apt-get install -y -qq git golang-go ufw

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
ufw allow 53/udp comment "DNS"
ufw allow 53/tcp comment "DNS"
ufw --force enable

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
