#!/bin/bash
# ============================================
# Ultimate Rathole Tunnel Manager - Auto Installer
# Combines best of both scripts with automatic binary/compile fallback
# Version: 4.1
# ============================================

set -euo pipefail

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; PURPLE='\033[0;35m'; NC='\033[0m'

# Config
RATHOLE_VERSION="0.5.0"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/rathole"
SERVICE_DIR="/etc/systemd/system"
LOG_DIR="/var/log/rathole"
TUNNEL_SERVICE="rathole-tunnel"
ARCH=$(uname -m)
OS="unknown-linux-gnu"

# Banner
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════╗"
    echo "║      RATHOLE TUNNEL - AUTO INSTALLER     ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${YELLOW}Smart Installer | Auto Binary/Compile Detection${NC}"
    echo -e "${BLUE}===============================================${NC}"
}

# Check root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR] Root access required.${NC}"
        echo -e "${YELLOW}Please run with: sudo bash \$0${NC}"
        exit 1
    fi
}

# Fix package locks
fix_apt_locks() {
    echo -e "${YELLOW}[*] Checking system locks...${NC}"
    for lock in /var/lib/apt/lists/lock /var/lib/dpkg/lock; do
        if [[ -f $lock ]]; then
            echo -e "${YELLOW}[-] Removing lock: $lock${NC}"
            rm -f $lock 2>/dev/null || true
        fi
    done
    sleep 2
}

# Install dependencies
install_deps() {
    echo -e "${YELLOW}[*] Installing dependencies...${NC}"
    fix_apt_locks
    apt-get update -o DPkg::Lock::Timeout=10 || true
    for pkg in wget curl tar openssl build-essential pkg-config libssl-dev git; do
        if ! command -v $pkg &>/dev/null; then
            echo -e "${YELLOW}[-] Installing $pkg...${NC}"
            apt-get install -y -o DPkg::Lock::Timeout=10 $pkg || true
        fi
    done
}

# Detect architecture and install method
setup_installation() {
    echo -e "${BLUE}[*] System Detection${NC}"
    echo -e "${YELLOW}Architecture: $ARCH${NC}"
    
    # Check if binary is likely to work
    local BINARY_OK=true
    
    # Check OS version (for libc compatibility)
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        echo -e "${YELLOW}Distribution: $PRETTY_NAME${NC}"
        
        # Older systems may have compatibility issues with pre-built binaries[citation:3]
        if [[ "$VERSION_ID" =~ ^(18|20) ]]; then
            echo -e "${YELLOW}[!] Older OS detected. May need compiled version.[citation:3]${NC}"
            BINARY_OK=false
        fi
    fi
    
    # Set architecture for binary download
    case "$ARCH" in
        "x86_64"|"amd64") BIN_ARCH="x86_64" ;;
        "aarch64"|"arm64") BIN_ARCH="aarch64" ;;
        "armv7l"|"armhf") BIN_ARCH="armv7" ;;
        *) 
            echo -e "${RED}[!] Uncommon architecture detected.${NC}"
            BINARY_OK=false 
            BIN_ARCH="x86_64" # default fallback
            ;;
    esac
    
    # Ask user for preferred method
    echo -e "${CYAN}"
    echo "Installation Method:"
    echo "1) Auto (Try Binary First, Fallback to Compile)"
    echo "2) Force Binary Installation"
    echo "3) Force Compile from Source[citation:3]"
    echo -e "${NC}"
    
    read -p "Choose [1-3] (Default: 1): " method
    method=${method:-1}
    
    case $method in
        1) INSTALL_METHOD="auto" ;;
        2) INSTALL_METHOD="binary" ;;
        3) INSTALL_METHOD="compile" ;;
        *) INSTALL_METHOD="auto" ;;
    esac
    
    echo -e "${GREEN}[✓] Method: $INSTALL_METHOD${NC}"
}

# Try binary installation first
install_binary() {
    local arch=$1
    echo -e "${YELLOW}[*] Attempting Binary Installation...${NC}"
    
    local url="https://github.com/rathole-org/rathole/releases/download/v${RATHOLE_VERSION}/rathole-${RATHOLE_VERSION}-${arch}-${OS}.tar.gz"
    echo -e "${YELLOW}URL: $url${NC}"
    
    local temp_dir=$(mktemp -d)
    cd "$temp_dir"
    
    # Download
    if command -v wget &>/dev/null; then
        wget -q --timeout=20 "$url" -O rathole.tar.gz || return 1
    elif command -v curl &>/dev/null; then
        curl -fsSL --connect-timeout 20 "$url" -o rathole.tar.gz || return 1
    else
        echo -e "${RED}[!] No download tool.${NC}"
        return 1
    fi
    
    # Extract
    tar -xzf rathole.tar.gz 2>/dev/null || { gzip -dc rathole.tar.gz | tar xf - 2>/dev/null || return 1; }
    
    # Find and install binary
    local bin=$(find . -name "rathole" -type f | head -1)
    if [[ -f "$bin" ]]; then
        cp "$bin" "$INSTALL_DIR/rathole"
        chmod +x "$INSTALL_DIR/rathole"
        
        # Test the binary
        if "$INSTALL_DIR/rathole" --version &>/dev/null; then
            echo -e "${GREEN}[✓] Binary installed and working.${NC}"
            cd /
            rm -rf "$temp_dir"
            return 0
        fi
    fi
    
    echo -e "${YELLOW}[!] Binary method failed.${NC}"
    cd /
    rm -rf "$temp_dir"
    return 1
}

# Compile from source (fallback method)[citation:3]
install_compile() {
    echo -e "${YELLOW}[*] Compiling from Source...${NC}"
    echo -e "${YELLOW}This may take several minutes and requires ~2GB space.[citation:3]${NC}"
    
    # Install Rust if needed[citation:3]
    if ! command -v cargo &>/dev/null; then
        echo -e "${YELLOW}[-] Installing Rust...${NC}"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y || {
            echo -e "${YELLOW}[-] Alternative Rust install...${NC}"
            apt-get install -y rustc cargo 2>/dev/null || true
        }
        source "$HOME/.cargo/env" 2>/dev/null || true
    fi
    
    # Clone and compile[citation:3]
    local temp_dir=$(mktemp -d)
    cd "$temp_dir"
    
    echo -e "${YELLOW}[-] Cloning repository...${NC}"
    git clone https://github.com/rathole-org/rathole.git 2>/dev/null || {
        # Fallback to alternative repo
        git clone https://github.com/miyugundam/rathole.git 2>/dev/null || return 1
    }
    
    cd rathole
    echo -e "${YELLOW}[-] Compiling (be patient)...${NC}"
    
    # Fix potential compilation issue[citation:3]
    if grep -q "strip = true" Cargo.toml; then
        sed -i 's/strip = true/strip = "symbols"/' Cargo.toml
    fi
    
    # Build
    if cargo build --release 2>&1 | tee /tmp/compile.log; then
        cp target/release/rathole "$INSTALL_DIR/rathole"
        chmod +x "$INSTALL_DIR/rathole"
        echo -e "${GREEN}[✓] Successfully compiled and installed.${NC}"
        cd /
        rm -rf "$temp_dir"
        return 0
    else
        echo -e "${RED}[ERROR] Compilation failed. Check /tmp/compile.log${NC}"
        echo -e "${YELLOW}Common fixes[citation:3]:"
        echo "1. Ensure sufficient disk space (~2GB)"
        echo "2. Run: sudo apt install build-essential pkg-config libssl-dev"
        echo "3. Check Rust version: rustc --version"
        echo "4. Try manual fixes from error log"
        cd /
        rm -rf "$temp_dir"
        return 1
    fi
}

# Main installation routine
install_rathole_core() {
    echo -e "${GREEN}[*] Installing Rathole Core${NC}"
    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR"
    
    local max_attempts=2
    local attempt=1
    local success=false
    
    while [[ $attempt -le $max_attempts && $success == false ]]; do
        case $INSTALL_METHOD in
            "binary")
                if install_binary "$BIN_ARCH"; then
                    success=true
                fi
                ;;
            "compile")
                if install_compile; then
                    success=true
                fi
                ;;
            "auto")
                if [[ $attempt -eq 1 ]]; then
                    echo -e "${YELLOW}Attempt $attempt: Trying Binary...${NC}"
                    if install_binary "$BIN_ARCH"; then
                        success=true
                    fi
                else
                    echo -e "${YELLOW}Attempt $attempt: Trying Compile...${NC}"
                    if install_compile; then
                        success=true
                    fi
                fi
                ;;
        esac
        
        if [[ $success == false ]]; then
            echo -e "${YELLOW}[!] Installation attempt $attempt failed.${NC}"
            ((attempt++))
            sleep 2
        fi
    done
    
    if [[ $success == true ]]; then
        echo -e "${GREEN}[✓] Rathole core installed successfully.${NC}"
        return 0
    else
        echo -e "${RED}[ERROR] All installation methods failed.${NC}"
        return 1
    fi
}

# Setup systemd and configs
setup_system() {
    echo -e "${YELLOW}[*] Setting up system...${NC}"
    
    # Systemd service
    cat > "$SERVICE_DIR/$TUNNEL_SERVICE.service" << EOF
[Unit]
Description=Rathole Tunnel Service
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/rathole $CONFIG_DIR/tunnel.toml
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF
    
    # Default config
    cat > "$CONFIG_DIR/tunnel.toml" << 'EOF'
# Rathole Configuration
# Server Mode (for Iran server):
# [server]
# bind_addr = "0.0.0.0:2333"
# default_token = "your_secure_token_here"
# 
# [server.services.tunnel]
# bind_addr = "0.0.0.0:2333"

# Client Mode (for Foreign server):
# [client]
# remote_addr = "SERVER_IP:2333"
# default_token = "your_secure_token_here"
EOF
    
    systemctl daemon-reload 2>/dev/null || true
    echo -e "${GREEN}[✓] System setup complete.${NC}"
}

# Create tunnel wizard
create_tunnel() {
    echo -e "${CYAN}[Tunnel Setup]${NC}"
    read -p "Server location (1=Iran, 2=Foreign): " loc
    
    if [[ $loc == "1" ]]; then
        read -p "Foreign server IP: " ip
        read -p "Port [2333]: " port; port=${port:-2333}
        token=$(openssl rand -hex 32)
        
        cat > "$CONFIG_DIR/tunnel.toml" << EOF
[client]
remote_addr = "$ip:$port"
default_token = "$token"

[client.services.tunnel]
local_addr = "127.0.0.1:$port"
type = "tcp+udp"
EOF
        
        echo -e "${GREEN}[✓] Iran client config created.${NC}"
        echo -e "${YELLOW}Foreign server needs this config:${NC}"
        echo "=========================="
        echo "[server]"
        echo "bind_addr = \"0.0.0.0:$port\""
        echo "default_token = \"$token\""
        echo "=========================="
    else
        read -p "Iran server IP: " ip
        read -p "Port [2333]: " port; port=${port:-2333}
        token=$(openssl rand -hex 32)
        
        cat > "$CONFIG_DIR/tunnel.toml" << EOF
[client]
remote_addr = "$ip:$port"
default_token = "$token"

[client.services.tunnel]
local_addr = "127.0.0.1:$port"
type = "tcp+udp"
EOF
        
        echo -e "${GREEN}[✓] Foreign client config created.${NC}"
    fi
}

# Main menu
show_menu() {
    clear
    show_banner
    echo -e "${CYAN}1) Install Rathole Core${NC}"
    echo -e "${CYAN}2) Create Tunnel${NC}"
    echo -e "${CYAN}3) Start Tunnel Service${NC}"
    echo -e "${CYAN}4) Show Status${NC}"
    echo -e "${CYAN}5) Uninstall${NC}"
    echo -e "${CYAN}6) Exit${NC}"
    echo -e "${BLUE}=================================${NC}"
}

# One-click setup: Auto-install then show menu
auto_install_and_menu() {
    check_root
    show_banner
    
    echo -e "${GREEN}[*] Starting automatic setup...${NC}"
    install_deps
    setup_installation
    
    if install_rathole_core; then
        setup_system
        echo -e "${GREEN}[✓] Setup complete! Starting interactive menu.${NC}"
        sleep 2
        interactive_menu
    else
        echo -e "${RED}[!] Setup failed. Please check errors above.${NC}"
        exit 1
    fi
}

# Interactive menu loop
interactive_menu() {
    while true; do
        show_menu
        read -p "Select option: " choice
        
        case $choice in
            1) 
                install_deps
                setup_installation
                install_rathole_core
                setup_system
                ;;
            2) create_tunnel ;;
            3) 
                systemctl restart $TUNNEL_SERVICE 2>/dev/null || true
                echo -e "${GREEN}[✓] Service command sent.${NC}"
                ;;
            4) 
                echo -e "${YELLOW}Status:${NC}"
                systemctl status $TUNNEL_SERVICE --no-pager 2>/dev/null || echo "Service not running"
                ;;
            5) 
                systemctl stop $TUNNEL_SERVICE 2>/dev/null
                rm -f $INSTALL_DIR/rathole
                rm -f $SERVICE_DIR/$TUNNEL_SERVICE.service
                echo -e "${GREEN}[✓] Uninstalled.${NC}"
                ;;
            6) 
                echo -e "${GREEN}Goodbye!${NC}"
                exit 0
                ;;
        esac
        echo -e "\n${YELLOW}Press Enter to continue...${NC}"
        read
    done
}

# ============================================
# EXECUTION STARTS HERE - ONE COMMAND ONLY
# ============================================

# This is the main entry point
# User just runs: sudo bash <(curl ...)
# Script auto-installs then shows menu

auto_install_and_menu
