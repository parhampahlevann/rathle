sudo bash -c 'cat > /tmp/rathole-manager.sh << "EOF"
#!/usr/bin/env bash
set -e

VERSION="0.5.0"
CONFIG_DIR="/root/rathole-core"
BIN_LOCAL="$CONFIG_DIR/rathole"
BIN_SYSTEM="/usr/local/bin/rathole"

SERVICE_SERVER="/etc/systemd/system/rathole-server.service"
SERVICE_CLIENT="/etc/systemd/system/rathole-client.service"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'

ok(){ echo -e "${GREEN}$1${NC}"; }
err(){ echo -e "${RED}$1${NC}"; }
warn(){ echo -e "${YELLOW}$1${NC}"; }

arch_detect() {
  case "$(uname -m)" in
    x86_64|amd64) echo "x86_64" ;;
    aarch64|arm64) echo "aarch64" ;;
    armv7l) echo "armv7" ;;
    *) echo "$(uname -m)" ;;
  esac
}

install_rathole() {
  mkdir -p "$CONFIG_DIR"
  ARCH=$(arch_detect)

  URL1="https://github.com/rathole-org/rathole/releases/download/v${VERSION}/rathole-${VERSION}-${ARCH}-unknown-linux-gnu.tar.gz"
  URL2="https://github.com/rathole-org/rathole/releases/download/v0.4.8/rathole-0.4.8-${ARCH}-unknown-linux-gnu.tar.gz"

  TMP="/tmp/rathole.tar.gz"

  ok "Downloading Rathole core..."
  if ! curl -fsSL "$URL1" -o "$TMP"; then
    warn "Fallback download..."
    curl -fsSL "$URL2" -o "$TMP"
  fi

  mkdir -p /tmp/rathole-extract
  tar -xzf "$TMP" -C /tmp/rathole-extract

  BIN_FOUND=$(find /tmp/rathole-extract -type f -name rathole | head -n 1)

  if [[ ! -f "$BIN_FOUND" ]]; then
    err "Download failed — binary not found."
    exit 1
  fi

  chmod +x "$BIN_FOUND"
  cp "$BIN_FOUND" "$BIN_LOCAL"
  cp "$BIN_FOUND" "$BIN_SYSTEM"

  ok "Rathole installed successfully!"
  "$BIN_SYSTEM" --version || true
}

create_server() {
  read -rp "Enter listen port [2333]: " PORT
  PORT=${PORT:-2333}
  TOKEN=$(openssl rand -hex 32)
  cat > "$CONFIG_DIR/server.toml" <<EOF2
[server]
bind_addr = "0.0.0.0:$PORT"
default_token = "$TOKEN"

[server.services.reverse_tunnel]
bind_addr = "0.0.0.0:$PORT"
type = "tcp+udp"
EOF2
  ok "Server config created: $CONFIG_DIR/server.toml"
  echo "TOKEN: $TOKEN"
}

create_client() {
  read -rp "Enter Iran server IP: " IP
  read -rp "Enter Iran server port [2333]: " PORT
  PORT=${PORT:-2333}
  read -rp "Enter token: " TOKEN
  cat > "$CONFIG_DIR/client.toml" <<EOF3
[client]
remote_addr = "$IP:$PORT"
default_token = "$TOKEN"

[client.services.reverse_tunnel]
local_addr = "127.0.0.1:$PORT"
type = "tcp+udp"
EOF3
  ok "Client config created: $CONFIG_DIR/client.toml"
}

systemd_server() {
  cat > "$SERVICE_SERVER" <<EOF4
[Unit]
Description=Rathole Server
After=network.target

[Service]
ExecStart=$BIN_SYSTEM --server $CONFIG_DIR/server.toml
Restart=always

[Install]
WantedBy=multi-user.target
EOF4
  systemctl daemon-reload
  systemctl enable --now rathole-server
  ok "Rathole server service started!"
}

systemd_client() {
  cat > "$SERVICE_CLIENT" <<EOF5
[Unit]
Description=Rathole Client
After=network.target

[Service]
ExecStart=$BIN_SYSTEM --client $CONFIG_DIR/client.toml
Restart=always

[Install]
WantedBy=multi-user.target
EOF5
  systemctl daemon-reload
  systemctl enable --now rathole-client
  ok "Rathole client service started!"
}

status_screen() {
  echo "========= Rathole Status ========="
  echo
  [[ -f "$BIN_SYSTEM" ]] && ok "Core Installed" || err "Core Not Installed"
  [[ -f "$CONFIG_DIR/server.toml" ]] && ok "Server Config OK" || warn "No Server Config"
  [[ -f "$CONFIG_DIR/client.toml" ]] && ok "Client Config OK" || warn "No Client Config"
  systemctl is-active --quiet rathole-server && ok "Server Service Active" || warn "Server Service Inactive"
  systemctl is-active --quiet rathole-client && ok "Client Service Active" || warn "Client Service Inactive"
  echo
}

remove_all() {
  systemctl disable --now rathole-server 2>/dev/null || true
  systemctl disable --now rathole-client 2>/dev/null || true
  rm -f "$SERVICE_SERVER" "$SERVICE_CLIENT"
  systemctl daemon-reload
  rm -rf "$CONFIG_DIR"
  rm -f "$BIN_SYSTEM"
  ok "Rathole core + tunnels + services removed completely."
}

menu() {
while true; do
echo "
===============================
   Rathole Manager Main Menu
===============================
1) Install Rathole Core
2) Create Iran Server Tunnel
3) Create Foreign Client Tunnel
4) Create Server Systemd Service
5) Create Client Systemd Service
6) Show Status
7) Remove All (core + tunnels)
8) Exit
"
read -rp "Select: " CH
case $CH in
 1) install_rathole ;;
 2) create_server ;;
 3) create_client ;;
 4) systemd_server ;;
 5) systemd_client ;;
 6) status_screen ;;
 7) remove_all ;;
 8) exit 0 ;;
 *) echo "Invalid";;
esac
done
}

menu
EOF
bash /tmp/rathole-manager.sh
'
