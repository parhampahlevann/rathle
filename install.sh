#!/usr/bin/env bash
set -e

### ================= BASIC =================
BIN="/usr/local/bin/mtproto-proxy"
CONF_DIR="/etc/mtproxy"
SERVICE="/etc/systemd/system/mtproxy.service"

if [[ $EUID -ne 0 ]]; then
  echo "❌ Run as root"
  exit 1
fi

clear
echo "======================================"
echo "   MTPulse – Ultimate Iran Edition"
echo "======================================"
echo ""

### ================= MODE =================
echo "Select mode:"
echo "  1) Normal"
echo "  2) 🇮🇷 Iran Optimized"
read -p "Choice [1-2]: " MODE
IRAN_MODE=0
[[ "$MODE" == "2" ]] && IRAN_MODE=1

read -p "Port [443]: " PORT
PORT=${PORT:-443}

### ================= PACKAGES =================
apt update -y
apt install -y git curl build-essential libssl-dev zlib1g-dev xxd net-tools

### ================= SYSCTL =================
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
net.ipv4.tcp_syn_retries=3
net.ipv4.tcp_synack_retries=3
net.ipv4.tcp_retries2=5
net.ipv4.tcp_tw_reuse=1
EOF
fi

sysctl --system >/dev/null

### ================= BUILD =================
echo "📥 Building MTProxy (smart mode)..."
rm -rf /tmp/MTProxy
git clone https://github.com/TelegramMessenger/MTProxy.git /tmp/MTProxy
cd /tmp/MTProxy

build_ok=0

echo "▶ Try optimized build"
make clean || true
if make -j$(nproc) CC=gcc; then
  build_ok=1
fi

if [[ $build_ok -eq 0 ]]; then
  echo "▶ Try portable build"
  make clean
  if make -j$(nproc) CC=gcc CFLAGS="-O2 -fno-omit-frame-pointer"; then
    build_ok=1
  fi
fi

if [[ $build_ok -eq 0 ]]; then
  echo "▶ Try NO_AESNI build"
  make clean
  if make -j$(nproc) CC=gcc CFLAGS="-O2 -DNO_AESNI"; then
    build_ok=1
  fi
fi

if [[ $build_ok -eq 0 ]]; then
  echo "❌ Build failed – trying prebuilt binary"
  curl -fsSL https://github.com/TelegramMessenger/MTProxy/releases/latest/download/mtproto-proxy -o $BIN
  chmod +x $BIN
else
  cp objs/bin/mtproto-proxy $BIN
  chmod +x $BIN
fi

### ================= CONFIG =================
mkdir -p $CONF_DIR
curl -fsSL https://core.telegram.org/getProxySecret -o $CONF_DIR/proxy-secret
curl -fsSL https://core.telegram.org/getProxyConfig -o $CONF_DIR/proxy.conf
SECRET=$(head -c 16 /dev/urandom | xxd -ps)

### ================= SYSTEMD =================
cat > $SERVICE <<EOF
[Unit]
Description=MTProto Proxy
After=network-online.target

[Service]
ExecStart=$BIN -H $PORT -S $SECRET --aes-pwd $CONF_DIR/proxy-secret -c $CONF_DIR/proxy.conf -M 1
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
command -v ufw >/dev/null 2>&1 && ufw allow $PORT/tcp >/dev/null 2>&1 || true

### ================= INFO =================
IP=$(curl -s https://api.ipify.org)

echo ""
echo "======================================"
echo " ✅ MTProxy Ready"
echo "======================================"
echo " Mode   : $( [[ $IRAN_MODE -eq 1 ]] && echo "Iran Optimized 🇮🇷" || echo "Normal" )"
echo " Server : $IP"
echo " Port   : $PORT"
echo " Secret : $SECRET"
echo ""
echo " tg://proxy?server=$IP&port=$PORT&secret=dd$SECRET"
echo ""
systemctl --no-pager status mtproxy | head -12
