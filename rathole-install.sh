sudo bash -c 'cat > /tmp/rathole-manager.sh << "EOF"
#!/usr/bin/env bash
set -e

VERSION="0.5.0"
CONFIG_DIR="/root/rathole-core"
BIN_LOCAL="$CONFIG_DIR/rathole"
BIN_SYSTEM="/usr/local/bin/rathole"

SERVICE_SERVER="/etc/systemd/system/rathole-server.service"
SERVICE_CLIENT="/etc/systemd/system/rathole-client.service"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

ok(){ echo -e "${GREEN}$1${NC}"; }
err(){ echo -e "${RED}$1${NC}"; }
warn(){ echo -e "${YELLOW}$1${NC}"; }
info(){ echo -e "${CYAN}$1${NC}"; }

banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════╗"
    echo "║   Rathole Tunnel Manager - Fixed v6.0    ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"
}

arch_detect() {
  case "$(uname -m)" in
    x86_64|amd64) echo "x86_64" ;;
    aarch64|arm64) echo "aarch64" ;;
    armv7l) echo "armv7" ;;
    *) echo "x86_64" ;;
  esac
}

# Fix package locks
fix_locks() {
    echo -e "${YELLOW}[*] Fixing system locks...${NC}"
    for lock in /var/lib/apt/lists/lock /var/lib/dpkg/lock; do
        if [[ -f $lock ]]; then
            rm -f $lock 2>/dev/null || true
        fi
    done
    sleep 2
}

# Install dependencies
install_deps() {
    echo -e "${YELLOW}[*] Installing dependencies...${NC}"
    fix_locks
    
    apt-get update 2>/dev/null || true
    
    for pkg in curl wget tar openssl; do
        if ! command -v $pkg >/dev/null 2>&1; then
            echo -e "${YELLOW}[-] Installing $pkg...${NC}"
            apt-get install -y $pkg 2>/dev/null || true
        fi
    done
    
    ok "[✓] Dependencies ready"
}

# Multiple download methods for Rathole
install_rathole() {
    mkdir -p "$CONFIG_DIR"
    ARCH=$(arch_detect)
    
    info "Architecture detected: $ARCH"
    info "Attempting to install Rathole v$VERSION"
    
    # Multiple download URLs with fallbacks
    declare -a URLS=(
        "https://github.com/rathole-org/rathole/releases/download/v${VERSION}/rathole-${VERSION}-${ARCH}-unknown-linux-gnu.tar.gz"
        "https://github.com/rathole-org/rathole/releases/download/v0.4.8/rathole-0.4.8-${ARCH}-unknown-linux-gnu.tar.gz"
        "https://github.com/Musixal/rathole-tunnel/raw/main/core/rathole.zip"
        "https://github.com/rathole-org/rathole/releases/download/v0.4.7/rathole-0.4.7-${ARCH}-unknown-linux-gnu.tar.gz"
    )
    
    local download_success=false
    local temp_dir="/tmp/rathole-download-$$"
    mkdir -p "$temp_dir"
    
    for i in "${!URLS[@]}"; do
        URL="${URLS[$i]}"
        echo -e "${YELLOW}[Attempt $((i+1))] Trying: ${URL:0:60}...${NC}"
        
        if [[ "$URL" == *.zip ]]; then
            # ZIP file download (for Musixal repo)
            if curl -fsSL "$URL" -o "$temp_dir/rathole.zip"; then
                if command -v unzip >/dev/null 2>&1; then
                    unzip -q "$temp_dir/rathole.zip" -d "$temp_dir" 2>/dev/null || true
                    download_success=true
                    break
                else
                    warn "unzip not available, trying next URL..."
                fi
            fi
        else
            # TAR.GZ download
            if curl -fsSL "$URL" -o "$temp_dir/rathole.tar.gz"; then
                tar -xzf "$temp_dir/rathole.tar.gz" -C "$temp_dir" 2>/dev/null || {
                    # Try alternative extraction
                    gzip -dc "$temp_dir/rathole.tar.gz" | tar xf - -C "$temp_dir" 2>/dev/null || true
                }
                download_success=true
                break
            fi
        fi
        
        sleep 1
    done
    
    if [[ "$download_success" == false ]]; then
        # LAST RESORT: Try to compile from source
        err "All downloads failed, trying to compile from source..."
        compile_from_source
        return $?
    fi
    
    # Find binary in extracted files
    BIN_FOUND=$(find "$temp_dir" -type f -name rathole 2>/dev/null | head -n 1)
    
    if [[ -f "$BIN_FOUND" ]]; then
        chmod +x "$BIN_FOUND"
        cp "$BIN_FOUND" "$BIN_LOCAL"
        cp "$BIN_FOUND" "$BIN_SYSTEM" 2>/dev/null || true
        
        # Test binary
        if "$BIN_LOCAL" --version >/dev/null 2>&1; then
            local version=$("$BIN_LOCAL" --version 2>/dev/null || echo "v$VERSION")
            ok "[✓] Rathole installed successfully! Version: $version"
        else
            warn "[!] Binary installed but version check failed"
            ok "[✓] Rathole binary copied to: $BIN_LOCAL"
        fi
    else
        # Try to find binary in system PATH
        if command -v rathole >/dev/null 2>&1; then
            warn "[!] Using existing rathole from system PATH"
            cp "$(command -v rathole)" "$BIN_LOCAL" 2>/dev/null || true
        else
            err "[ERROR] Could not find rathole binary after download"
            return 1
        fi
    fi
    
    # Cleanup
    rm -rf "$temp_dir"
    return 0
}

# Compile from source as last resort
compile_from_source() {
    warn "[!] Compiling Rathole from source (this may take a while)..."
    
    # Install Rust if needed
    if ! command -v cargo >/dev/null 2>&1; then
        info "Installing Rust..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y || {
            apt-get install -y rustc cargo 2>/dev/null || {
                err "Failed to install Rust"
                return 1
            }
        }
        source "$HOME/.cargo/env" 2>/dev/null || true
    fi
    
    local temp_dir="/tmp/rathole-compile-$$"
    mkdir -p "$temp_dir"
    cd "$temp_dir"
    
    # Clone repository
    if git clone https://github.com/rathole-org/rathole.git 2>/dev/null; then
        cd rathole
        info "Compiling Rathole (please wait)..."
        
        if cargo build --release 2>&1 | tee /tmp/rathole-compile.log; then
            cp target/release/rathole "$BIN_LOCAL"
            cp target/release/rathole "$BIN_SYSTEM" 2>/dev/null || true
            chmod +x "$BIN_LOCAL"
            ok "[✓] Successfully compiled and installed!"
            cd /
            rm -rf "$temp_dir"
            return 0
        fi
    fi
    
    err "[ERROR] Compilation failed"
    cd /
    rm -rf "$temp_dir"
    return 1
}

create_server() {
    banner
    info "=== Iran Server Configuration ==="
    
    read -rp "Enter tunnel port [2333]: " PORT
    PORT=${PORT:-2333}
    
    TOKEN=$(openssl rand -hex 32 2>/dev/null || echo "default_token_$(date +%s)")
    
    cat > "$CONFIG_DIR/server.toml" <<EOF2
[server]
bind_addr = "0.0.0.0:$PORT"
default_token = "$TOKEN"

[server.services.tunnel]
bind_addr = "0.0.0.0:$PORT"
bind_addr_v6 = "[::]:$PORT"
type = "tcp+udp"
nodelay = true
EOF2
    
    ok "[✓] Iran server config created: $CONFIG_DIR/server.toml"
    echo ""
    info "IMPORTANT: Share this token with foreign server:"
    info "TOKEN: $TOKEN"
    echo ""
    info "For foreign server config:"
    echo "remote_addr = \"YOUR_IRAN_IP:$PORT\""
    echo "default_token = \"$TOKEN\""
}

create_client() {
    banner
    info "=== Foreign Client Configuration ==="
    
    read -rp "Enter Iran server IP address: " IP
    read -rp "Enter Iran server port [2333]: " PORT
    PORT=${PORT:-2333}
    read -rp "Enter token from Iran server: " TOKEN
    
    cat > "$CONFIG_DIR/client.toml" <<EOF3
[client]
remote_addr = "$IP:$PORT"
default_token = "$TOKEN"
retry_interval = 1

[client.services.tunnel]
local_addr = "127.0.0.1:$PORT"
local_addr_v6 = "[::1]:$PORT"
type = "tcp+udp"
nodelay = true
EOF3
    
    ok "[✓] Foreign client config created: $CONFIG_DIR/client.toml"
}

systemd_server() {
    if [[ ! -f "$CONFIG_DIR/server.toml" ]]; then
        err "Server config not found! Create it first (option 2)."
        return 1
    fi
    
    cat > "$SERVICE_SERVER" <<EOF4
[Unit]
Description=Rathole Server (Iran)
After=network.target

[Service]
Type=simple
ExecStart=$BIN_SYSTEM $CONFIG_DIR/server.toml
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF4
    
    systemctl daemon-reload
    systemctl enable rathole-server --now
    ok "[✓] Rathole Iran server service started and enabled!"
    
    # Check status
    sleep 2
    if systemctl is-active --quiet rathole-server; then
        ok "[✓] Service is running successfully"
    else
        warn "[!] Service may have issues. Check: systemctl status rathole-server"
    fi
}

systemd_client() {
    if [[ ! -f "$CONFIG_DIR/client.toml" ]]; then
        err "Client config not found! Create it first (option 3)."
        return 1
    fi
    
    cat > "$SERVICE_CLIENT" <<EOF5
[Unit]
Description=Rathole Client (Foreign)
After=network.target

[Service]
Type=simple
ExecStart=$BIN_SYSTEM $CONFIG_DIR/client.toml
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF5
    
    systemctl daemon-reload
    systemctl enable rathole-client --now
    ok "[✓] Rathole Foreign client service started and enabled!"
    
    # Check status
    sleep 2
    if systemctl is-active --quiet rathole-client; then
        ok "[✓] Service is running successfully"
    else
        warn "[!] Service may have issues. Check: systemctl status rathole-client"
    fi
}

status_screen() {
    banner
    echo "=========== Rathole Status ==========="
    echo ""
    
    # Core installation
    if [[ -f "$BIN_LOCAL" ]]; then
        ok "[✓] Rathole Core: INSTALLED"
        echo "    Local: $BIN_LOCAL"
        if [[ -f "$BIN_SYSTEM" ]]; then
            echo "    System: $BIN_SYSTEM"
        fi
    else
        err "[✗] Rathole Core: NOT INSTALLED"
    fi
    
    echo ""
    
    # Config files
    if [[ -f "$CONFIG_DIR/server.toml" ]]; then
        ok "[✓] Iran Server Config: PRESENT"
    else
        warn "[!] Iran Server Config: MISSING"
    fi
    
    if [[ -f "$CONFIG_DIR/client.toml" ]]; then
        ok "[✓] Foreign Client Config: PRESENT"
    else
        warn "[!] Foreign Client Config: MISSING"
    fi
    
    echo ""
    
    # Services
    if systemctl is-active --quiet rathole-server 2>/dev/null; then
        ok "[✓] Iran Server Service: ACTIVE"
    elif systemctl is-enabled --quiet rathole-server 2>/dev/null; then
        warn "[○] Iran Server Service: ENABLED (not running)"
    else
        warn "[!] Iran Server Service: NOT CONFIGURED"
    fi
    
    if systemctl is-active --quiet rathole-client 2>/dev/null; then
        ok "[✓] Foreign Client Service: ACTIVE"
    elif systemctl is-enabled --quiet rathole-client 2>/dev/null; then
        warn "[○] Foreign Client Service: ENABLED (not running)"
    else
        warn "[!] Foreign Client Service: NOT CONFIGURED"
    fi
    
    echo ""
    echo "====================================="
}

remove_all() {
    banner
    warn "WARNING: This will completely remove Rathole!"
    echo ""
    read -rp "Type 'YES' to confirm: " confirm
    
    if [[ "$confirm" != "YES" ]]; then
        info "Operation cancelled."
        return
    fi
    
    info "Removing Rathole completely..."
    
    # Stop and disable services
    systemctl stop rathole-server 2>/dev/null || true
    systemctl stop rathole-client 2>/dev/null || true
    systemctl disable rathole-server 2>/dev/null || true
    systemctl disable rathole-client 2>/dev/null || true
    
    # Remove service files
    rm -f "$SERVICE_SERVER" "$SERVICE_CLIENT"
    systemctl daemon-reload
    
    # Remove binaries and configs
    rm -rf "$CONFIG_DIR"
    rm -f "$BIN_SYSTEM"
    
    ok "[✓] Rathole completely removed!"
}

menu() {
    while true; do
        banner
        echo -e "${CYAN}===============================${NC}"
        echo -e "${CYAN}   Rathole Manager Main Menu   ${NC}"
        echo -e "${CYAN}===============================${NC}"
        echo ""
        echo -e "1) ${GREEN}Install Rathole Core${NC}"
        echo -e "2) ${YELLOW}Create Iran Server Tunnel${NC}"
        echo -e "3) ${YELLOW}Create Foreign Client Tunnel${NC}"
        echo -e "4) ${CYAN}Start Iran Server Service${NC}"
        echo -e "5) ${CYAN}Start Foreign Client Service${NC}"
        echo -e "6) ${GREEN}Show Status${NC}"
        echo -e "7) ${RED}Remove All${NC}"
        echo -e "8) ${CYAN}Exit${NC}"
        echo ""
        echo -e "${CYAN}===============================${NC}"
        
        read -rp "Select option [1-8]: " CH
        
        case $CH in
            1) 
                install_deps
                install_rathole
                ;;
            2) create_server ;;
            3) create_client ;;
            4) systemd_server ;;
            5) systemd_client ;;
            6) status_screen ;;
            7) remove_all ;;
            8) 
                ok "Goodbye!"
                exit 0
                ;;
            *) 
                err "Invalid option!"
                ;;
        esac
        
        echo ""
        read -rp "Press Enter to continue..."
    done
}

# Main execution
if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root"
    echo "Please run with: sudo bash \$0"
    exit 1
fi

menu
EOF
bash /tmp/rathole-manager.sh'
