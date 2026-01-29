#!/usr/bin/env bash
# =============================================================================
# MTPulse - Consolidated bugfixes
# =============================================================================

set -Eeuo pipefail

# -----------------------------------------------------------------------------
# Safe read wrapper (prevents set -u crash when read fails)
# -----------------------------------------------------------------------------
safe_read() {
    local __var="$1"
    local __prompt="${2:-}"
    local __value=""
    # If read fails (e.g. EOF), we still want to set the variable to empty string
    read -r -p "$__prompt" __value || __value=""
    printf -v "$__var" '%s' "$__value"
}

trap 'echo "[FATAL] Error at line $LINENO"; exit 1' ERR

# -----------------------------------------------------------------------------
# Paths & constants
# -----------------------------------------------------------------------------
BASE_DIR="/etc/mtpulse"
BIN="/usr/local/bin/mtproto-proxy"
DB="$BASE_DIR/proxies.db"
LOG_DIR="/var/log/mtpulse"
SERVICE_DIR="/etc/systemd/system"
REQUIRED_CMDS=(curl git make gcc g++ openssl ss systemctl)

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

ensure_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "Run as root"
        exit 1
    fi
}

ensure_cmds_or_install_hint() {
    # Only check commands that may not exist; don't auto-fix here other than apt path below
    local missing=()
    for c in "${REQUIRED_CMDS[@]}"; do
        # ss may come from iproute2; check 'ss' command presence specifically
        if ! command_exists "$c"; then
            missing+=("$c")
        fi
    done
    # If only ss is missing, we will install iproute2 later. Don't abort here; use install_deps to fix.
    if ((${#missing[@]})); then
        echo "Note: Some helper commands are missing: ${missing[*]}"
        echo "They will be installed if package manager is available."
    fi
}

# -----------------------------------------------------------------------------
# Init dirs and DB
# -----------------------------------------------------------------------------
init_dirs() {
    mkdir -p "$BASE_DIR" "$LOG_DIR"
    chown root:root "$BASE_DIR" "$LOG_DIR" || true
    chmod 755 "$BASE_DIR" "$LOG_DIR" || true

    if [[ ! -f "$DB" ]]; then
        echo "#NAME|PORT|SECRET|CREATED" > "$DB"
        chmod 600 "$DB" || true
    else
        # Ensure DB has header
        if ! head -n1 "$DB" | grep -q '^#NAME|PORT|SECRET|CREATED'; then
            # backup then add header
            cp -a "$DB" "$DB".bak || true
            sed -i '1i#NAME|PORT|SECRET|CREATED' "$DB"
        fi
    fi
}

# -----------------------------------------------------------------------------
# Dependency install (Debian/Ubuntu apt-based) - safe and idempotent
# -----------------------------------------------------------------------------
install_deps() {
    if command_exists apt; then
        apt update -y
        apt install -y \
          git make gcc g++ \
          libssl-dev zlib1g-dev \
          curl iproute2 openssl ca-certificates
    else
        echo "apt not found. Please install dependencies manually: git make gcc g++ libssl-dev zlib1g-dev curl iproute2 openssl ca-certificates"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Build & install MTProxy from upstream source
# -----------------------------------------------------------------------------
install_mtproxy() {
    ensure_root
    install_deps || true

    # build in temporary dir
    tmp="$(mktemp -d)"
    cd "$tmp" || exit 1

    git clone https://github.com/TelegramMessenger/MTProxy.git || { echo "git clone failed"; rm -rf "$tmp"; return 1; }
    cd MTProxy || { rm -rf "$tmp"; return 1; }

    make clean || true
    make -j"$(nproc)" || { echo "Build failed (make)"; cd /; rm -rf "$tmp"; return 1; }

    if [[ ! -f objs/bin/mtproto-proxy ]]; then
        echo "Build failed: objs/bin/mtproto-proxy missing"
        cd /
        rm -rf "$tmp"
        return 1
    fi

    install -m 755 objs/bin/mtproto-proxy "$BIN" || { echo "Install to $BIN failed"; cd /; rm -rf "$tmp"; return 1; }

    cd /
    rm -rf "$tmp"

    # Download secrets/config only if missing
    if [[ ! -f "$BASE_DIR/proxy-secret" ]]; then
        curl -fsSL https://core.telegram.org/getProxySecret -o "$BASE_DIR/proxy-secret" || echo "Failed to download proxy-secret"
        chmod 600 "$BASE_DIR/proxy-secret" || true
    fi
    if [[ ! -f "$BASE_DIR/proxy.conf" ]]; then
        curl -fsSL https://core.telegram.org/getProxyConfig -o "$BASE_DIR/proxy.conf" || echo "Failed to download proxy.conf"
        chmod 600 "$BASE_DIR/proxy.conf" || true
    fi

    echo "MTProxy installed successfully at $BIN"
}

# -----------------------------------------------------------------------------
# Helper to check port availability: prefer ss, fallback to netstat
# -----------------------------------------------------------------------------
port_in_use() {
    local port="$1"
    if command_exists ss; then
        ss -lnt 2>/dev/null | awk '{print $4}' | grep -E "[:.]$port\$" >/dev/null 2>&1
        return $?
    elif command_exists netstat; then
        netstat -lnt 2>/dev/null | awk '{print $4}' | grep -E "[:.]$port\$" >/dev/null 2>&1
        return $?
    else
        # Last resort: try /proc/net/tcp (not perfect)
        grep -q "$port" /proc/net/tcp 2>/dev/null || return 1
    fi
}

# -----------------------------------------------------------------------------
# Create a new proxy service
# -----------------------------------------------------------------------------
create_proxy() {
    local name port secret svc ip

    safe_read name "Proxy name: "
    if [[ -z "$name" ]]; then
        echo "Empty name"
        return
    fi
    # allow only alnum, dash, underscore
    if [[ ! "$name" =~ ^[A-Za-z0-9_-]+$ ]]; then
        echo "Invalid name. Use only letters, numbers, hyphen and underscore."
        return
    fi

    # check name uniqueness in DB and existing services
    if grep -qE "^${name}\\|" "$DB"; then
        echo "Proxy name already exists in DB"
        return
    fi
    if [[ -f "$SERVICE_DIR/mtpulse-$name.service" ]]; then
        echo "Service file already exists: $SERVICE_DIR/mtpulse-$name.service"
        return
    fi

    safe_read port "Port: "
    if [[ ! "$port" =~ ^[0-9]+$ ]]; then
        echo "Invalid port"
        return
    fi
    if (( port < 1 || port > 65535 )); then
        echo "Port out of range"
        return
    fi

    if port_in_use "$port"; then
        echo "Port already in use"
        return
    fi

    if [[ ! -x "$BIN" ]]; then
        echo "MTProxy binary not found at $BIN. Run option 1 to install first."
        return
    fi

    secret="$(openssl rand -hex 16)"
    svc="$SERVICE_DIR/mtpulse-$name.service"

    # Make sure proxy-secret and proxy.conf exist
    if [[ ! -f "$BASE_DIR/proxy-secret" ]]; then
        echo "proxy-secret missing; downloading..."
        curl -fsSL https://core.telegram.org/getProxySecret -o "$BASE_DIR/proxy-secret" || { echo "Failed to download proxy-secret"; return; }
        chmod 600 "$BASE_DIR/proxy-secret"
    fi
    if [[ ! -f "$BASE_DIR/proxy.conf" ]]; then
        echo "proxy.conf missing; downloading..."
        curl -fsSL https://core.telegram.org/getProxyConfig -o "$BASE_DIR/proxy.conf" || { echo "Failed to download proxy.conf"; return; }
        chmod 600 "$BASE_DIR/proxy.conf"
    fi

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
    systemctl enable --now "mtpulse-$name.service" || { echo "Failed to enable/start systemd service"; return; }

    printf "%s|%s|%s|%s\n" "$name" "$port" "$secret" "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> "$DB"
    chmod 600 "$DB" || true

    ip="$(curl -fsSL https://api.ipify.org || echo SERVER_IP)"

    echo
    echo "Proxy created:"
    echo "tg://proxy?server=$ip&port=$port&secret=$secret"
}

# -----------------------------------------------------------------------------
# List proxies
# -----------------------------------------------------------------------------
list_proxies() {
    # If DB contains only header or is missing, show message
    if [[ ! -f "$DB" ]] || ! awk 'NR>1{print; found=1} END{exit !found}' "$DB"; then
        echo "No proxies defined"
        return
    fi

    printf "%-12s %-6s %-8s %s\n" "NAME" "PORT" "STATE" "CREATED"
    while IFS='|' read -r n p s d; do
        [[ -z "$n" || "$n" == \#* ]] && continue
        if systemctl is-active --quiet "mtpulse-$n.service"; then
            st="ACTIVE"
        else
            st="STOPPED"
        fi
        printf "%-12s %-6s %-8s %s\n" "$n" "$p" "$st" "$d"
    done < <(tail -n +2 "$DB")
}

# -----------------------------------------------------------------------------
# Monitor proxies (simple loop, non-recursive)
# -----------------------------------------------------------------------------
monitor_all_proxies() {
    while true; do
        clear
        list_proxies
        sleep 5
    done
}

# -----------------------------------------------------------------------------
# Menu
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
ensure_root
ensure_cmds_or_install_hint
init_dirs

while true; do
    menu
    echo
    # pause for Enter; don't fail if stdin closed
    read -r || true
done
