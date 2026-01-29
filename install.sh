#!/usr/bin/env bash
# =============================================================================
# MTPulse - PATCHED VERSION
# Only installation/runtime bugs fixed
# =============================================================================

set -Eeuo pipefail

# -----------------------------------------------------------------------------
# Safe read wrapper (FIX set -u crash)
# -----------------------------------------------------------------------------
safe_read() {
    local __var="$1"
    local __prompt="${2:-}"
    local __value=""
    read -r -p "$__prompt" __value || __value=""
    printf -v "$__var" '%s' "$__value"
}

trap 'echo "[FATAL] Error at line $LINENO"; exit 1' ERR

# -----------------------------------------------------------------------------
# Paths & constants (UNCHANGED)
# -----------------------------------------------------------------------------
BASE_DIR="/etc/mtpulse"
BIN="/usr/local/bin/mtproto-proxy"
DB="$BASE_DIR/proxies.db"
LOG_DIR="/var/log/mtpulse"

# -----------------------------------------------------------------------------
# Root check
# -----------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo "Run as root"
    exit 1
fi

# -----------------------------------------------------------------------------
# Init dirs (FIX missing log dir)
# -----------------------------------------------------------------------------
init_dirs() {
    mkdir -p "$BASE_DIR" "$LOG_DIR"
    [[ -f "$DB" ]] || echo "#NAME|PORT|SECRET|CREATED" > "$DB"
}

# -----------------------------------------------------------------------------
# Dependency install (FIX missing ss/iproute2)
# -----------------------------------------------------------------------------
install_deps() {
    apt update
    apt install -y \
        git make gcc g++ \
        libssl-dev zlib1g-dev \
        curl iproute2
}

# -----------------------------------------------------------------------------
# Install MTProxy (SOURCE, original logic kept)
# -----------------------------------------------------------------------------
install_mtproxy() {
    install_deps

    tmp="$(mktemp -d)"
    cd "$tmp"

    git clone https://github.com/TelegramMessenger/MTProxy.git
    cd MTProxy

    make clean || true
    make -j"$(nproc)"

    [[ -f objs/bin/mtproto-proxy ]] || {
        echo "Build failed"
        exit 1
    }

    install -m 755 objs/bin/mtproto-proxy "$BIN"

    cd /
    rm -rf "$tmp"

    curl -fsSL https://core.telegram.org/getProxySecret -o "$BASE_DIR/proxy-secret"
    curl -fsSL https://core.telegram.org/getProxyConfig -o "$BASE_DIR/proxy.conf"

    echo "MTProxy installed successfully"
}

# -----------------------------------------------------------------------------
# Create proxy (NO LOGIC REMOVED)
# -----------------------------------------------------------------------------
create_proxy() {
    local name port secret

    safe_read name "Proxy name: "
    [[ -z "$name" ]] && { echo "Empty name"; return; }

    safe_read port "Port: "
    [[ "$port" =~ ^[0-9]+$ ]] || { echo "Invalid port"; return; }

    if ss -lnt | grep -q ":$port "; then
        echo "Port already in use"
        return
    fi

    secret="$(openssl rand -hex 16)"

    local svc="/etc/systemd/system/mtpulse-$name.service"

    cat > "$svc" <<EOF
[Unit]
Description=MTPulse Proxy $name
After=network.target

[Service]
Type=simple
ExecStart=$BIN -H $port -S $secret --aes-pwd $BASE_DIR/proxy-secret $BASE_DIR/proxy.conf -M 1
Restart=always
LimitNOFILE=1048576
StandardOutput=file:$LOG_DIR/$name.log
StandardError=file:$LOG_DIR/$name.err

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now "mtpulse-$name"

    echo "$name|$port|$secret|$(date)" >> "$DB"

    local ip
    ip="$(curl -fsSL https://api.ipify.org || echo SERVER_IP)"

    echo
    echo "Proxy created:"
    echo "tg://proxy?server=$ip&port=$port&secret=$secret"
}

# -----------------------------------------------------------------------------
# List proxies (FIX empty DB detection)
# -----------------------------------------------------------------------------
list_proxies() {
    if ! grep -q '^[^#]' "$DB"; then
        echo "No proxies defined"
        return
    fi

    while IFS='|' read -r n p s d; do
        [[ -z "$n" || "$n" == \#* ]] && continue
        if systemctl is-active --quiet "mtpulse-$n"; then
            st="ACTIVE"
        else
            st="STOPPED"
        fi
        printf "%-12s %-6s %-8s %s\n" "$n" "$p" "$st" "$d"
    done < "$DB"
}

# -----------------------------------------------------------------------------
# Monitor (FIX recursion bug)
# -----------------------------------------------------------------------------
monitor_all_proxies() {
    while true; do
        clear
        list_proxies
        sleep 5
    done
}

# -----------------------------------------------------------------------------
# Menu (UNCHANGED STRUCTURE)
# -----------------------------------------------------------------------------
menu() {
    echo "=============================="
    echo " MTPulse Proxy Manager"
    echo "=============================="
    echo "1) Install MTProxy"
    echo "2) Create new proxy"
    echo "3) List proxies"
    echo "4) Monitor proxies"
    echo "0) Exit"
    echo "------------------------------"

    local choice
    safe_read choice "Select: "

    case "$choice" in
        1) install_mtproxy ;;
        2) create_proxy ;;
        3) list_proxies ;;
        4) monitor_all_proxies ;;
        0) exit 0 ;;
        *) echo "Invalid option" ;;
    esac
}

# -----------------------------------------------------------------------------
# Start
# -----------------------------------------------------------------------------
init_dirs
while true; do
    menu
    echo
    read -r
done
