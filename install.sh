#!/usr/bin/env bash
set -e

### ===== ROOT CHECK =====
[[ $EUID -ne 0 ]] && { echo "Run as root"; exit 1; }

### ===== VARS =====
BIN="/usr/local/bin/mtg"
CONF_DIR="/etc/mtg"
CONF="$CONF_DIR/config.toml"
SERVICE="/etc/systemd/system/mtg.service"

read -p "Port [443]: " PORT
PORT=${PORT:-443}

### ===== BASE =====
apt update -y
apt install -y curl jq ca-certificates

### ===== BBR (STABLE) =====
cat > /etc/sysctl.d/99-mtg-iran.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr

net.ipv4.tcp_fastopen=3
net.ipv4.tcp_low_latency=1
net.ipv4.tcp_mtu_probing=1

net.core.netdev_max_backlog=250000
net.core.somaxconn=65535
net.ipv4.tcp_max_syn_backlog=65535
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_keepalive_time=600
net.ipv4.tcp_keepalive_intvl=30
net.ipv4.tcp_keepalive_probes=5
EOF
sysctl --system >/dev/null

### ===== DOWNLOAD MTG =====
ARCH=$(uname -m)
case "$ARCH" in
  x86_64) A="linux-amd64" ;;
  aarch64) A="linux-arm64" ;;
  *) echo "Unsupported arch"; exit 1 ;;
esac

curl -fsSL "https://github.com/9seconds/mtg/releases/latest/download/mtg-$A" -o "$BIN"
chmod +x "$BIN"

### ===== CONFIG =====
mkdir -p "$CONF_DIR"
SECRET=$(head -c 16 /dev/urandom | xxd -ps)

cat > "$CONF" <<EOF
bind = "0.0.0.0:$PORT"
secret = "dd$SECRET"
workers = 0
EOF

### ===== SYSTEMD =====
cat > "$SERVICE" <<EOF
[Unit]
Description=MTG MTProto Proxy (Iran Stable)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$BIN run $CONF
Restart=always
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable mtg
systemctl restart mtg

### ===== INFO =====
IP=$(curl -s https://api.ipify.org)

echo ""
echo "======================================"
echo " ✅ MTG Iran-Stable READY"
echo "======================================"
echo " Server : $IP"
echo " Port   : $PORT"
echo " Secret : dd$SECRET"
echo ""
echo " tg://proxy?server=$IP&port=$PORT&secret=dd$SECRET"
echo "======================================"
