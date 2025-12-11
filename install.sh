#!/bin/bash

# ============================================
# Rathole Tunnel Manager - One Click Install
# Version: 3.1
# Fixes apt lock issues
# ============================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Config
RATHOLE_VERSION="0.5.0"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/rathole"
LOG_DIR="/var/log/rathole"
TUNNEL_SERVICE="rathole-tunnel"

# Fix apt lock function
fix_apt_lock() {
    echo -e "${YELLOW}[*] Checking for apt lock issues...${NC}"
    
    # Kill apt processes if stuck
    for pid in $(ps aux | grep -i apt | grep -v grep | awk '{print $2}'); do
        echo -e "${YELLOW}[-] Killing stuck apt process: $pid${NC}"
        kill -9 $pid 2>/dev/null || true
    done
    
    # Remove lock files
    for lock in /var/lib/apt/lists/lock /var/lib/dpkg/lock /var/cache/apt/archives/lock; do
        if [ -f "$lock" ]; then
            echo -e "${YELLOW}[-] Removing lock file: $lock${NC}"
            rm -f "$lock"
        fi
    done
    
    # Remove lock directories
    for lock_dir in /var/lib/apt/lists/lock /var/lib/dpkg/lock; do
        if [ -d "$lock_dir" ]; then
            echo -e "${YELLOW}[-] Removing lock directory: $lock_dir${NC}"
            rm -rf "$lock_dir"
        fi
    done
    
    sleep 2
    echo -e "${GREEN}[✓] Apt lock issues fixed${NC}"
}

# Check and install dependencies without apt lock
install_dependencies_safe() {
    echo -e "${YELLOW}[*] Installing dependencies (safe mode)...${NC}"
    
    # First fix any existing locks
    fix_apt_lock
    
    # Try to update without locking
    apt-get update -o DPkg::Lock::Timeout=10 -o APT::Get::AllowUnauthenticated=1 || {
        echo -e "${YELLOW}[-] Apt update failed, trying alternative method...${NC}"
        # Alternative: use dpkg directly if possible
        return 0
    }
    
    # Check and install each dependency
    for pkg in wget curl tar openssl; do
        if ! command -v $pkg >/dev/null 2>&1; then
            echo -e "${YELLOW}[-] Installing $pkg...${NC}"
            apt-get install -y -o DPkg::Lock::Timeout=10 --allow-unauthenticated $pkg || {
                echo -e "${YELLOW}[!] Failed to install $pkg via apt, trying alternative...${NC}"
                # Try manual download for critical packages
                if [ "$pkg" = "wget" ] || [ "$pkg" = "curl" ]; then
                    install_manual_dependency $pkg
                fi
            }
        fi
    done
    
    echo -e "${GREEN}[✓] Dependencies check complete${NC}"
}

# Manual dependency installation
install_manual_dependency() {
    local pkg=$1
    echo -e "${YELLOW}[!] Manual install of $pkg...${NC}"
    
    case $pkg in
        wget)
            # Try to get wget binary directly
            if [ -f /usr/bin/wget ]; then
                echo -e "${GREEN}[✓] wget already exists${NC}"
            else
                # Download static wget binary
                curl -sSL https://github.com/moparisthebest/static-curl/releases/download/v7.88.1/wget-amd64 -o /tmp/wget
                chmod +x /tmp/wget
                mv /tmp/wget /usr/bin/wget 2>/dev/null || cp /tmp/wget /usr/local/bin/wget
            fi
            ;;
        curl)
            if [ -f /usr/bin/curl ]; then
                echo -e "${GREEN}[✓] curl already exists${NC}"
            else
                # Download static curl binary
                wget -q https://github.com/moparisthebest/static-curl/releases/download/v7.88.1/curl-amd64 -O /tmp/curl 2>/dev/null || \
                curl -sSL https://github.com/moparisthebest/static-curl/releases/download/v7.88.1/curl-amd64 -o /tmp/curl
                chmod +x /tmp/curl
                mv /tmp/curl /usr/bin/curl 2>/dev/null || cp /tmp/curl /usr/local/bin/curl
            fi
            ;;
    esac
}

# Detect architecture
detect_arch() {
    local arch=$(uname -m)
    case $arch in
        x86_64|amd64) echo "x86_64" ;;
        aarch64|arm64) echo "aarch64" ;;
        armv7l|armhf) echo "armv7" ;;
        i386|i686) echo "i686" ;;
        *) echo "unsupported" ;;
    esac
}

# Download and install rathole directly
install_rathole_direct() {
    echo -e "${GREEN}[*] Installing Rathole Core...${NC}"
    
    # Get architecture
    ARCH=$(detect_arch)
    if [ "$ARCH" = "unsupported" ]; then
        echo -e "${RED}[ERROR] Unsupported architecture$(uname -m)${NC}"
        exit 1
    fi
    
    # Download URL
    OS="unknown-linux-gnu"
    URL="https://github.com/rathole-org/rathole/releases/download/v${RATHOLE_VERSION}/rathole-${RATHOLE_VERSION}-${ARCH}-${OS}.tar.gz"
    
    echo -e "${YELLOW}[-] Downloading Rathole...${NC}"
    
    # Create temp directory
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"
    
    # Download using available tool
    if command -v wget >/dev/null 2>&1; then
        wget -q "$URL" -O rathole.tar.gz || {
            echo -e "${RED}[ERROR] Download failed${NC}"
            return 1
        }
    elif command -v curl >/dev/null 2>&1; then
        curl -sSL "$URL" -o rathole.tar.gz || {
            echo -e "${RED}[ERROR] Download failed${NC}"
            return 1
        }
    else
        echo -e "${RED}[ERROR] No download tool available${NC}"
        return 1
    fi
    
    # Extract
    tar -xzf rathole.tar.gz 2>/dev/null || {
        # Try alternative extraction
        gzip -dc rathole.tar.gz | tar xf - 2>/dev/null || true
    }
    
    # Find and install binary
    RATHOLE_BIN=$(find . -name "rathole" -type f 2>/dev/null | head -1)
    
    if [ -z "$RATHOLE_BIN" ]; then
        # Extract with wildcard
        tar -xzf rathole.tar.gz --wildcards '*/rathole' --strip-components=1 2>/dev/null || true
        RATHOLE_BIN="./rathole"
    fi
    
    if [ -f "$RATHOLE_BIN" ]; then
        mkdir -p "$INSTALL_DIR"
        cp "$RATHOLE_BIN" "$INSTALL_DIR/rathole"
        chmod +x "$INSTALL_DIR/rathole"
        echo -e "${GREEN}[✓] Rathole installed to $INSTALL_DIR/rathole${NC}"
    else
        echo -e "${RED}[ERROR] Could not find rathole binary${NC}"
        return 1
    fi
    
    # Cleanup
    cd /
    rm -rf "$TEMP_DIR"
    
    # Verify
    if "$INSTALL_DIR/rathole" --version >/dev/null 2>&1; then
        echo -e "${GREEN}[✓] Rathole installation verified${NC}"
    else
        echo -e "${YELLOW}[!] Rathole installed but version check failed${NC}"
    fi
    
    return 0
}

# Create directories and configs
setup_rathole() {
    echo -e "${YELLOW}[*] Setting up Rathole...${NC}"
    
    # Create directories
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    
    # Create systemd service
    cat > "/etc/systemd/system/$TUNNEL_SERVICE.service" << EOF
[Unit]
Description=Rathole Tunnel
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/rathole $CONFIG_DIR/config.toml
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF
    
    # Create sample config
    cat > "$CONFIG_DIR/config.toml" << 'EOF'
# Rathole Configuration
# Server Mode Example:
# [server]
# bind_addr = "0.0.0.0:2333"
# default_token = "your_token_here"
# 
# [server.services.tunnel1]
# bind_addr = "0.0.0.0:2333"
# type = "tcp+udp"

# Client Mode Example:
# [client]
# remote_addr = "server_ip:2333"
# default_token = "your_token_here"
# 
# [client.services.tunnel1]
# local_addr = "127.0.0.1:2333"
# type = "tcp+udp"
EOF
    
    # Create tunnel script
    cat > "$CONFIG_DIR/create_tunnel.sh" << 'EOF'
#!/bin/bash
# Tunnel creation helper

echo "Rathole Tunnel Setup"
echo "===================="

read -p "Are you on Iran server? (y/n): " is_iran

if [[ "$is_iran" =~ ^[Yy]$ ]]; then
    read -p "Foreign server IP: " remote_ip
    read -p "Foreign server port [2333]: " remote_port
    remote_port=${remote_port:-2333}
    
    # Generate key
    token=$(openssl rand -hex 32)
    
    cat > /etc/rathole/config.toml << CONFIG
[client]
remote_addr = "$remote_ip:$remote_port"
default_token = "$token"
retry_interval = 1

[client.services.iran_tunnel]
local_addr = "127.0.0.1:2333"
local_addr_v6 = "[::1]:2333"
type = "tcp+udp"
nodelay = true
CONFIG
    
    echo -e "\n✓ Client config created"
    echo -e "\nServer config for FOREIGN server:"
    echo "=================================="
    cat << SERVER_CONFIG
[server]
bind_addr = "0.0.0.0:$remote_port"
default_token = "$token"

[server.services.foreign_tunnel]
bind_addr = "0.0.0.0:$remote_port"
bind_addr_v6 = "[::]:$remote_port"
type = "tcp+udp"
nodelay = true
SERVER_CONFIG
    
else
    read -p "Iran server IP: " remote_ip
    read -p "Iran server port [2333]: " remote_port
    remote_port=${remote_port:-2333}
    
    # Generate key
    token=$(openssl rand -hex 32)
    
    cat > /etc/rathole/config.toml << CONFIG
[client]
remote_addr = "$remote_ip:$remote_port"
default_token = "$token"
retry_interval = 1

[client.services.foreign_tunnel]
local_addr = "127.0.0.1:2333"
local_addr_v6 = "[::1]:2333"
type = "tcp+udp"
nodelay = true
CONFIG
    
    echo -e "\n✓ Client config created"
    echo -e "\nServer config for IRAN server:"
    echo "=================================="
    cat << SERVER_CONFIG
[server]
bind_addr = "0.0.0.0:$remote_port"
default_token = "$token"

[server.services.iran_tunnel]
bind_addr = "0.0.0.0:$remote_port"
bind_addr_v6 = "[::]:$remote_port"
type = "tcp+udp"
nodelay = true
SERVER_CONFIG
fi

echo -e "\n✓ Configuration saved to /etc/rathole/config.toml"
echo -e "\nTo start tunnel: systemctl start rathole-tunnel"
echo "To auto-start: systemctl enable rathole-tunnel"
EOF
    
    chmod +x "$CONFIG_DIR/create_tunnel.sh"
    
    # Enable service
    systemctl daemon-reload 2>/dev/null || true
    
    echo -e "${GREEN}[✓] Rathole setup complete${NC}"
}

# Start tunnel
start_tunnel() {
    echo -e "${YELLOW}[*] Starting tunnel service...${NC}"
    
    systemctl daemon-reload 2>/dev/null || true
    systemctl enable "$TUNNEL_SERVICE.service" 2>/dev/null || true
    systemctl restart "$TUNNEL_SERVICE.service" 2>/dev/null || {
        echo -e "${YELLOW}[!] Starting service manually...${NC}"
        nohup "$INSTALL_DIR/rathole" "$CONFIG_DIR/config.toml" > "$LOG_DIR/rathole.log" 2>&1 &
    }
    
    echo -e "${GREEN}[✓] Tunnel service started${NC}"
}

# Show status
show_status() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════╗"
    echo "║      Rathole Tunnel Status           ║"
    echo "╚══════════════════════════════════════╝"
    echo -e "${NC}"
    
    # Check if rathole exists
    if [ -f "$INSTALL_DIR/rathole" ]; then
        echo -e "${GREEN}✓ Rathole installed at: $INSTALL_DIR/rathole${NC}"
        "$INSTALL_DIR/rathole" --version 2>/dev/null || echo -e "${YELLOW}Version check failed${NC}"
    else
        echo -e "${RED}✗ Rathole not installed${NC}"
    fi
    
    # Check service
    if systemctl is-active "$TUNNEL_SERVICE.service" >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Tunnel service: RUNNING${NC}"
    else
        echo -e "${YELLOW}⚠ Tunnel service: NOT RUNNING${NC}"
    fi
    
    # Check config
    if [ -f "$CONFIG_DIR/config.toml" ]; then
        echo -e "${GREEN}✓ Config file: $CONFIG_DIR/config.toml${NC}"
        echo -e "${YELLOW}Config preview:${NC}"
        head -10 "$CONFIG_DIR/config.toml"
    else
        echo -e "${YELLOW}⚠ No config file found${NC}"
    fi
    
    # Network status
    echo -e "\n${YELLOW}Network connections:${NC}"
    ss -tunlp 2>/dev/null | grep -E "(rathole|2333)" | head -5 || echo "No rathole connections"
    
    echo -e "\n${CYAN}Quick commands:${NC}"
    echo "  Create tunnel: /etc/rathole/create_tunnel.sh"
    echo "  Start tunnel: systemctl start $TUNNEL_SERVICE"
    echo "  View logs: tail -f /var/log/rathole/rathole.log"
}

# Uninstall
uninstall_rathole() {
    echo -e "${RED}[!] Uninstalling Rathole...${NC}"
    
    # Stop services
    systemctl stop "$TUNNEL_SERVICE.service" 2>/dev/null || true
    pkill -f "rathole" 2>/dev/null || true
    
    # Remove files
    rm -f "$INSTALL_DIR/rathole"
    rm -f "/etc/systemd/system/$TUNNEL_SERVICE.service"
    
    # Ask about config removal
    read -p "Remove config files? (y/n): " remove_config
    if [[ "$remove_config" =~ ^[Yy]$ ]]; then
        rm -rf "$CONFIG_DIR"
        rm -rf "$LOG_DIR"
    fi
    
    systemctl daemon-reload 2>/dev/null || true
    
    echo -e "${GREEN}[✓] Rathole uninstalled${NC}"
}

# Main installation flow
main_install() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════╗"
    echo "║   Rathole Tunnel - One Click Install ║"
    echo "╚══════════════════════════════════════╝"
    echo -e "${NC}"
    
    # Check root
    if [ "$EUID" -ne 0 ]; then 
        echo -e "${RED}Please run as root: sudo bash \$0${NC}"
        exit 1
    fi
    
    # Fix apt locks first
    fix_apt_lock
    
    # Install dependencies
    install_dependencies_safe
    
    # Install rathole
    install_rathole_direct
    
    # Setup
    setup_rathole
    
    # Show status
    show_status
    
    echo -e "\n${GREEN}════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}✅ Installation Complete!${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════${NC}"
    echo -e "\n${YELLOW}Next steps:${NC}"
    echo "1. Create tunnel: /etc/rathole/create_tunnel.sh"
    echo "2. Start service: systemctl start rathole-tunnel"
    echo "3. Enable auto-start: systemctl enable rathole-tunnel"
    echo -e "\n${YELLOW}Need help?${NC}"
    echo "- View logs: tail -f /var/log/rathole/rathole.log"
    echo "- Check status: systemctl status rathole-tunnel"
    echo -e "${GREEN}════════════════════════════════════════════════${NC}"
}

# Interactive menu
interactive_menu() {
    while true; do
        echo -e "\n${CYAN}Rathole Tunnel Manager${NC}"
        echo -e "${BLUE}1)${NC} One-Click Install (Recommended)"
        echo -e "${BLUE}2)${NC} Create Tunnel"
        echo -e "${BLUE}3)${NC} Show Status"
        echo -e "${BLUE}4)${NC} Start Tunnel Service"
        echo -e "${BLUE}5)${NC} Uninstall"
        echo -e "${BLUE}6)${NC} Exit"
        
        read -p "Select option: " choice
        
        case $choice in
            1) main_install ;;
            2) bash "$CONFIG_DIR/create_tunnel.sh" 2>/dev/null || {
                echo -e "${YELLOW}First install Rathole (option 1)${NC}"
               } ;;
            3) show_status ;;
            4) start_tunnel ;;
            5) uninstall_rathole ;;
            6) echo -e "${GREEN}Goodbye!${NC}"; exit 0 ;;
            *) echo -e "${RED}Invalid option${NC}" ;;
        esac
    done
}

# Auto-install if no arguments
if [ $# -eq 0 ]; then
    main_install
else
    case $1 in
        --install) main_install ;;
        --menu) interactive_menu ;;
        --status) show_status ;;
        --create-tunnel) bash "$CONFIG_DIR/create_tunnel.sh" ;;
        --uninstall) uninstall_rathole ;;
        --help)
            echo "Usage:"
            echo "  sudo bash install.sh           # One-click install"
            echo "  sudo bash install.sh --menu    # Interactive menu"
            echo "  sudo bash install.sh --status  # Show status"
            echo "  sudo bash install.sh --create-tunnel  # Create tunnel"
            echo "  sudo bash install.sh --uninstall      # Uninstall"
            ;;
        *) main_install ;;
    esac
fi
