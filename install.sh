#!/usr/bin/env bash
set -e

### ================= CONFIG =================
INSTALL_DIR="/opt/mtproxy"
BIN="/usr/local/bin/mtproto-proxy"
CONF_DIR="/etc/mtproxy"
SERVICE="/etc/systemd/system/mtproxy.service"

### ================= ROOT =================
if [[ $EUID -ne 0 ]]; then
  echo "❌ Run as root"
  exit 1
fi

clear
echo "======================================"
echo "   MTProto Proxy Installer (MTPulse)"
echo "      Stable + Iran Optimized"
echo "======================================"
echo ""

### ================= MODE =================
echo "Select installation mode:"
echo "  1) Normal (Global)"
echo "  2) 🇮🇷 Iran Optimized (Recommended for Iran VPS)"
echo ""
read -p "Enter choice [1-2]: " MODE

if [[ "$MODE" == "2" ]]; then
  IRAN_MODE=1
  echo "✅ Iran mode enabled"
else
  IRAN_MODE=0
  echo "✅ Normal mode enabled"
fi

### ================= PORT =================
read -p "Enter proxy port [443]: " PORT
PORT=${PORT:-443}

### ================= PACKAGES =================
apt update -y
apt install -y \
  git curl build-essential \
  libssl-dev zlib1g-dev xxd \
  net-tools

### ================= SYSCTL =================
echo "⚙️ Applying kernel optimizations..."

cat > /etc/sysctl.d/99-mtproxy.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr

net.core.somaxconn=8192
net.ipv4.tcp_max_syn_backlog=8192

net.ipv4.tcp_fastopen=3
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_keepalive_time=300
net.ipv4.tcp_keepalive_intvl=30
net.ipv4.tcp_keepalive_probes=5

net.core.rmem_max=67108864
net.core.wmem_max=67108864
net.ipv4.tcp_rmem=4096 87380 67108864
net.ipv4.tcp_wmem=4096 65536 67108864
EOF

if [[ $IRAN_MODE -eq 1 ]]; then
cat >> /etc/sysctl.d/99-mtproxy.conf <<EOF

# Iran Anti-Filter Tuning
net.ipv4.tcp_syn_retries=3
net.ipv4.tcp_synack_retries=3
net.ipv4.tcp_retries2=5
net.ipv4.tcp_orphan_retries=3
net.ipv4.tcp_tw_reuse=1
EOF
fi

sysctl --system >/dev/null

### ================= BUILD =================
echo "📥 Building MTProxy..."

rm -rf /tmp/MTProxy
git clone https://github.com/TelegramMessenger/MTProxy.git /tmp/MTProxy
cd /tmp/MTProxy
make -j$(nproc)

cp objs/bin/mtproto-proxy $BIN
chmod +x $BIN

### ================= CONFIG =================
mkdir -p $CONF_DIR

curl -fsSL https://core.telegram.org/getProxySecret -o $CONF_DIR/proxy-secret
curl -fsSL https://core.telegram.org/getProxyConfig -o $CONF_DIR/proxy.conf

SECRET=$(head -c 16 /dev/urandom | xxd -ps)

### ================= SYSTEMD =================
echo "🧩 Creating service..."

EXEC="$BIN -H $PORT -S $SECRET --aes-pwd $CONF_DIR/proxy-secret -c $CONF_DIR/proxy.conf -M 1"

cat > $SERVICE <<EOF
[Unit]
Description=MTProto Proxy
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$EXEC
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable mtproxy
systemctl restart mtproxy

### ================= FIREWALL =================
if command -v ufw >/dev/null 2>&1; then
  ufw allow $PORT/tcp >/dev/null 2>&1 || true
fi

### ================= INFO =================
IP=$(curl -s https://api.ipify.org)

echo ""
echo "======================================"
echo " ✅ MTProto Proxy Installed"
echo "======================================"
echo " Mode   : $( [[ $IRAN_MODE -eq 1 ]] && echo "Iran Optimized 🇮🇷" || echo "Normal" )"
echo " Server : $IP"
echo " Port   : $PORT"
echo " Secret : $SECRET"
echo ""
echo " 🔗 Telegram Links:"
echo " tg://proxy?server=$IP&port=$PORT&secret=dd$SECRET"
echo ""
echo " 📊 Status:"
systemctl --no-pager status mtproxy | head -15
