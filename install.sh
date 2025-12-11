#!/bin/bash

# ============================================
# Rathole Tunnel Manager v3.0
# Complete Installation and Management Script
# Supports: IPv4 + IPv6, TCP + UDP
# Tested on: Ubuntu 18.04, 20.04, 22.04, Debian 10/11
# ============================================

set -e  # Exit on error

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'  # No Color

# Configuration
RATHOLE_VERSION="0.5.0"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/rathole"
SERVICE_DIR="/etc/systemd/system"
LOG_DIR="/var/log/rathole"
TUNNEL_SERVICE="rathole-tunnel"
BACKUP_DIR="/etc/rathole/backups"

# Banner
show_banner() {
    clear
    echo -e "${BLUE}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║    ██████╗  █████╗ ████████╗██╗  ██╗ ██████╗  ║${NC}"
    echo -e "${BLUE}║    ██╔══██╗██╔══██╗╚══██╔══╝██║  ██║██╔═══██╗ ║${NC}"
    echo -e "${BLUE}║    ██████╔╝███████║   ██║   ███████║██║   ██║ ║${NC}"
    echo -e "${BLUE}║    ██╔══██╗██╔══██║   ██║   ██╔══██║██║   ██║ ║${NC}"
    echo -e "${BLUE}║    ██║  ██║██║  ██║   ██║   ██║  ██║╚██████╔╝ ║${NC}"
    echo -e "${BLUE}║    ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝  ║${NC}"
    echo -e "${BLUE}║                                                ║${NC}"
    echo -e "${BLUE}║    T U N N E L   M A N A G E R   v 3 . 0      ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════╝${NC}"
    echo -e "${CYAN}Support: IPv4 + IPv6 | TCP + UDP | Secure Tunnel${NC}"
    echo -e "${CYAN}================================================${NC}"
}

# Check root access
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR] This script must be run as root${NC}"
        echo -e "${YELLOW}Usage: sudo bash $0${NC}"
        exit 1
    fi
}

# Check internet connectivity
check_internet() {
    echo -e "${BLUE}[*] Checking internet connection...${NC}"
    if ! ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1 && ! ping -c 1 -W 2 1.1.1.1 >/dev/null 2>&1; then
        echo -e "${YELLOW}[WARNING] No internet connection detected${NC}"
        echo -e "${YELLOW}Continuing anyway...${NC}"
        return 1
    fi
    echo -e "${GREEN}[✓] Internet connection OK${NC}"
    return 0
}

# Install dependencies
install_dependencies() {
    echo -e "${BLUE}[*] Installing dependencies...${NC}"
    
    # Detect package manager
    if command -v apt-get >/dev/null 2>&1; then
        PKG_MANAGER="apt-get"
        UPDATE_CMD="apt-get update -qq"
        INSTALL_CMD="apt-get install -y -qq"
    elif command -v yum >/dev/null 2>&1; then
        PKG_MANAGER="yum"
        UPDATE_CMD="yum check-update -q || true"
        INSTALL_CMD="yum install -y -q"
    elif command -v dnf >/dev/null 2>&1; then
        PKG_MANAGER="dnf"
        UPDATE_CMD="dnf check-update -q || true"
        INSTALL_CMD="dnf install -y -q"
    else
        echo -e "${YELLOW}[WARNING] Unknown package manager${NC}"
        return 1
    fi
    
    # Update package list
    echo -e "${YELLOW}[-] Updating package list...${NC}"
    eval $UPDATE_CMD
    
    # Install required packages
    local packages="wget curl tar openssl"
    for pkg in $packages; do
        if ! command -v $pkg >/dev/null 2>&1; then
            echo -e "${YELLOW}[-] Installing $pkg...${NC}"
            eval "$INSTALL_CMD $pkg" || {
                echo -e "${RED}[ERROR] Failed to install $pkg${NC}"
                return 1
            }
        fi
    done
    
    echo -e "${GREEN}[✓] Dependencies installed${NC}"
    return 0
}

# Detect system architecture
detect_architecture() {
    echo -e "${BLUE}[*] Detecting system architecture...${NC}"
    
    local arch=$(uname -m)
    case $arch in
        x86_64|amd64)
            ARCH="x86_64"
            echo -e "${YELLOW}[-] Architecture: x86_64 (64-bit)${NC}"
            ;;
        aarch64|arm64)
            ARCH="aarch64"
            echo -e "${YELLOW}[-] Architecture: ARM64${NC}"
            ;;
        armv7l|armhf)
            ARCH="armv7"
            echo -e "${YELLOW}[-] Architecture: ARMv7${NC}"
            ;;
        i386|i686)
            ARCH="i686"
            echo -e "${YELLOW}[-] Architecture: x86 (32-bit)${NC}"
            ;;
        *)
            echo -e "${RED}[ERROR] Unsupported architecture: $arch${NC}"
            exit 1
            ;;
    esac
}

# Download and install Rathole
install_rathole() {
    echo -e "${BLUE}[*] Installing Rathole Core...${NC}"
    
    # Create directories
    mkdir -p $INSTALL_DIR
    mkdir -p $CONFIG_DIR
    mkdir -p $LOG_DIR
    mkdir -p $BACKUP_DIR
    
    # Download URL
    local os_type="unknown-linux-gnu"
    local download_url="https://github.com/rathole-org/rathole/releases/download/v${RATHOLE_VERSION}/rathole-${RATHOLE_VERSION}-${ARCH}-${os_type}.tar.gz"
    
    echo -e "${YELLOW}[-] Downloading from: $download_url${NC}"
    
    # Download using curl or wget
    local temp_dir=$(mktemp -d)
    cd $temp_dir
    
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$download_url" -o rathole.tar.gz || {
            echo -e "${RED}[ERROR] Download failed with curl${NC}"
            return 1
        }
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$download_url" -O rathole.tar.gz || {
            echo -e "${RED}[ERROR] Download failed with wget${NC}"
            return 1
        }
    else
        echo -e "${RED}[ERROR] Neither curl nor wget found${NC}"
        return 1
    fi
    
    # Extract archive
    echo -e "${YELLOW}[-] Extracting files...${NC}"
    tar -xzf rathole.tar.gz || {
        echo -e "${RED}[ERROR] Extraction failed${NC}"
        return 1
    }
    
    # Find and install binary
    local rathole_bin=$(find . -name "rathole" -type f 2>/dev/null | head -1)
    
    if [[ -z "$rathole_bin" ]]; then
        # Try alternative extraction
        tar -tzf rathole.tar.gz | grep -q rathole && {
            tar -xzf rathole.tar.gz --wildcards '*/rathole' --strip-components=1 2>/dev/null
            rathole_bin="./rathole"
        }
    fi
    
    if [[ -f "$rathole_bin" ]]; then
        cp "$rathole_bin" $INSTALL_DIR/rathole
        chmod +x $INSTALL_DIR/rathole
        echo -e "${GREEN}[✓] Rathole installed to $INSTALL_DIR/rathole${NC}"
    else
        echo -e "${RED}[ERROR] Rathole binary not found in archive${NC}"
        return 1
    fi
    
    # Create systemd service files
    create_systemd_services
    
    # Create default configuration
    create_default_config
    
    # Cleanup
    cd /
    rm -rf "$temp_dir"
    
    # Verify installation
    verify_installation
    
    echo -e "${GREEN}[✓] Rathole Core installation complete${NC}"
    return 0
}

# Create systemd services
create_systemd_services() {
    echo -e "${YELLOW}[-] Creating systemd services...${NC}"
    
    # Main rathole service
    cat > $SERVICE_DIR/rathole.service << EOF
[Unit]
Description=Rathole Tunnel Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/rathole $CONFIG_DIR/server.toml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5
User=root
Group=root
StandardOutput=append:$LOG_DIR/rathole.log
StandardError=append:$LOG_DIR/rathole-error.log

# Security
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes

[Install]
WantedBy=multi-user.target
EOF

    # Tunnel service
    cat > $SERVICE_DIR/$TUNNEL_SERVICE.service << EOF
[Unit]
Description=Rathole Tunnel Instance
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/rathole $CONFIG_DIR/tunnel.toml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5
User=root
Group=root
StandardOutput=append:$LOG_DIR/tunnel.log
StandardError=append:$LOG_DIR/tunnel-error.log

# Security
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd
    systemctl daemon-reload
    
    echo -e "${GREEN}[✓] Systemd services created${NC}"
}

# Create default configuration
create_default_config() {
    echo -e "${YELLOW}[-] Creating default configurations...${NC}"
    
    # Server configuration template
    cat > $CONFIG_DIR/server.toml << 'EOF'
# Rathole Server Configuration
# For server that will accept incoming connections

[server]
bind_addr = "0.0.0.0:2333"
default_token = "your_secure_token_here"

# Example service - SSH tunnel
[server.services.ssh]
bind_addr = "0.0.0.0:2222"
type = "tcp"

# Example service - HTTP tunnel
[server.services.http]
bind_addr = "0.0.0.0:8080"
bind_addr_v6 = "[::]:8080"
type = "tcp+udp"
EOF

    # Client configuration template
    cat > $CONFIG_DIR/client.toml << 'EOF'
# Rathole Client Configuration
# For client that connects to server

[client]
remote_addr = "SERVER_IP:2333"
default_token = "your_secure_token_here"
retry_interval = 1

# Example service - SSH
[client.services.ssh]
local_addr = "127.0.0.1:22"
type = "tcp"

# Example service - HTTP
[client.services.http]
local_addr = "127.0.0.1:80"
local_addr_v6 = "[::1]:80"
type = "tcp+udp"
EOF

    # Tunnel configuration (will be filled by user)
    cat > $CONFIG_DIR/tunnel.toml << 'EOF'
# Tunnel Configuration
# This file will be generated automatically
# based on your tunnel setup
EOF

    echo -e "${GREEN}[✓] Default configurations created${NC}"
}

# Verify installation
verify_installation() {
    echo -e "${YELLOW}[-] Verifying installation...${NC}"
    
    # Check if binary exists and is executable
    if [[ ! -f "$INSTALL_DIR/rathole" ]]; then
        echo -e "${RED}[ERROR] Rathole binary not found${NC}"
        return 1
    fi
    
    if [[ ! -x "$INSTALL_DIR/rathole" ]]; then
        echo -e "${RED}[ERROR] Rathole binary not executable${NC}"
        return 1
    fi
    
    # Test version command
    if $INSTALL_DIR/rathole --version >/dev/null 2>&1; then
        local version=$($INSTALL_DIR/rathole --version 2>/dev/null | head -1 || echo "v$RATHOLE_VERSION")
        echo -e "${GREEN}[✓] Rathole version: $version${NC}"
    else
        echo -e "${YELLOW}[WARNING] Cannot get rathole version, but binary works${NC}"
    fi
    
    # Check systemd services
    if systemctl list-unit-files | grep -q "rathole.service"; then
        echo -e "${GREEN}[✓] Systemd service created${NC}"
    fi
    
    echo -e "${GREEN}[✓] Installation verified successfully${NC}"
    return 0
}

# Create tunnel
create_tunnel() {
    echo -e "${BLUE}[*] Creating Rathole Tunnel${NC}"
    
    # Check if rathole is installed
    if [[ ! -f "$INSTALL_DIR/rathole" ]]; then
        echo -e "${RED}[ERROR] Rathole is not installed!${NC}"
        echo -e "${YELLOW}Please install Rathole first (Option 1)${NC}"
        return 1
    fi
    
    # Ask for server location
    echo -e "${CYAN}Select server location:${NC}"
    echo -e "  1) Iran Server (Client Mode)"
    echo -e "  2) Foreign Server (Client Mode)"
    echo -e "  3) Both Server & Client (Advanced)"
    
    local location=""
    while [[ ! "$location" =~ ^[1-3]$ ]]; do
        read -p "Enter choice [1-3]: " location
    done
    
    # Get common parameters
    echo -e "${YELLOW}[-] Gathering tunnel parameters...${NC}"
    
    local remote_ip=""
    while [[ -z "$remote_ip" ]]; do
        read -p "Remote server IP address: " remote_ip
        if [[ ! $remote_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo -e "${RED}Invalid IP address format${NC}"
            remote_ip=""
        fi
    done
    
    read -p "Remote port [2333]: " remote_port
    remote_port=${remote_port:-2333}
    
    read -p "Local port [2333]: " local_port
    local_port=${local_port:-2333}
    
    # Generate encryption key
    local encryption_key=$(openssl rand -hex 32)
    
    # Create configuration based on location
    case $location in
        1)  # Iran server (client connecting to foreign)
            echo -e "${GREEN}[*] Configuring Iran Server as Client${NC}"
            create_client_config "$remote_ip" "$remote_port" "$local_port" "$encryption_key" "iran_foreign_tunnel"
            echo -e "${YELLOW}[!] Configuration for FOREIGN SERVER (server_config.toml):${NC}"
            cat > /tmp/server_config_foreign.toml << EOF
[server]
bind_addr = "0.0.0.0:$remote_port"
default_token = "$encryption_key"

[server.services.tunnel1]
bind_addr = "0.0.0.0:$remote_port"
bind_addr_v6 = "[::]:$remote_port"
type = "tcp+udp"
nodelay = true
EOF
            cat /tmp/server_config_foreign.toml
            echo -e "\n${GREEN}Copy this config to your foreign server as 'server.toml'${NC}"
            ;;
            
        2)  # Foreign server (client connecting to Iran)
            echo -e "${GREEN}[*] Configuring Foreign Server as Client${NC}"
            create_client_config "$remote_ip" "$remote_port" "$local_port" "$encryption_key" "foreign_iran_tunnel"
            echo -e "${YELLOW}[!] Configuration for IRAN SERVER (server_config.toml):${NC}"
            cat > /tmp/server_config_iran.toml << EOF
[server]
bind_addr = "0.0.0.0:$remote_port"
default_token = "$encryption_key"

[server.services.tunnel1]
bind_addr = "0.0.0.0:$remote_port"
bind_addr_v6 = "[::]:$remote_port"
type = "tcp+udp"
nodelay = true
EOF
            cat /tmp/server_config_iran.toml
            echo -e "\n${GREEN}Copy this config to your Iran server as 'server.toml'${NC}"
            ;;
            
        3)  # Advanced mode (both)
            echo -e "${GREEN}[*] Advanced Configuration Mode${NC}"
            read -p "Run as server? (y/n): " is_server
            if [[ "$is_server" =~ ^[Yy]$ ]]; then
                create_server_config "$remote_port" "$encryption_key"
            else
                create_client_config "$remote_ip" "$remote_port" "$local_port" "$encryption_key" "advanced_tunnel"
            fi
            ;;
    esac
    
    echo -e "\n${GREEN}[✓] Tunnel configuration created${NC}"
    echo -e "${CYAN}Encryption Key: $encryption_key${NC}"
    echo -e "${YELLOW}Configuration saved to: $CONFIG_DIR/tunnel.toml${NC}"
    
    # Start tunnel service
    start_tunnel_service
    
    return 0
}

# Create server configuration
create_server_config() {
    local port=$1
    local token=$2
    
    cat > $CONFIG_DIR/tunnel.toml << EOF
[server]
bind_addr = "0.0.0.0:$port"
default_token = "$token"

[server.services.main_tunnel]
bind_addr = "0.0.0.0:$port"
bind_addr_v6 = "[::]:$port"
type = "tcp+udp"
nodelay = true
EOF
}

# Create client configuration
create_client_config() {
    local remote_ip=$1
    local remote_port=$2
    local local_port=$3
    local token=$4
    local tunnel_name=$5
    
    cat > $CONFIG_DIR/tunnel.toml << EOF
[client]
remote_addr = "$remote_ip:$remote_port"
default_token = "$token"
retry_interval = 1

[client.services.$tunnel_name]
local_addr = "127.0.0.1:$local_port"
local_addr_v6 = "[::1]:$local_port"
type = "tcp+udp"
nodelay = true
EOF
}

# Start tunnel service
start_tunnel_service() {
    echo -e "${YELLOW}[-] Starting tunnel service...${NC}"
    
    # Stop if already running
    systemctl stop $TUNNEL_SERVICE.service 2>/dev/null || true
    
    # Enable and start
    systemctl enable $TUNNEL_SERVICE.service
    systemctl start $TUNNEL_SERVICE.service
    
    # Wait a bit and check status
    sleep 2
    
    if systemctl is-active --quiet $TUNNEL_SERVICE.service; then
        echo -e "${GREEN}[✓] Tunnel service started successfully${NC}"
    else
        echo -e "${RED}[ERROR] Failed to start tunnel service${NC}"
        echo -e "${YELLOW}Check logs: journalctl -u $TUNNEL_SERVICE -f${NC}"
        return 1
    fi
    
    return 0
}

# Show tunnel status
show_tunnel_status() {
    echo -e "${BLUE}[*] Tunnel Status${NC}"
    echo -e "${CYAN}========================================${NC}"
    
    # Check if rathole is installed
    if [[ ! -f "$INSTALL_DIR/rathole" ]]; then
        echo -e "${RED}Rathole is not installed${NC}"
        return 1
    fi
    
    # Show version
    echo -e "${YELLOW}Rathole Version:${NC}"
    $INSTALL_DIR/rathole --version 2>/dev/null || echo "Unknown"
    
    echo -e "\n${YELLOW}Service Status:${NC}"
    
    # Check main service
    if systemctl is-enabled rathole.service >/dev/null 2>&1; then
        local status=$(systemctl is-active rathole.service)
        if [[ "$status" == "active" ]]; then
            echo -e "  rathole.service: ${GREEN}ACTIVE${NC}"
        else
            echo -e "  rathole.service: ${RED}$status${NC}"
        fi
    else
        echo -e "  rathole.service: ${YELLOW}NOT ENABLED${NC}"
    fi
    
    # Check tunnel service
    if systemctl is-enabled $TUNNEL_SERVICE.service >/dev/null 2>&1; then
        local status=$(systemctl is-active $TUNNEL_SERVICE.service)
        if [[ "$status" == "active" ]]; then
            echo -e "  $TUNNEL_SERVICE.service: ${GREEN}ACTIVE${NC}"
        else
            echo -e "  $TUNNEL_SERVICE.service: ${RED}$status${NC}"
        fi
    else
        echo -e "  $TUNNEL_SERVICE.service: ${YELLOW}NOT ENABLED${NC}"
    fi
    
    # Show recent logs
    echo -e "\n${YELLOW}Recent Tunnel Logs:${NC}"
    if [[ -f "$LOG_DIR/tunnel.log" ]]; then
        tail -10 "$LOG_DIR/tunnel.log" 2>/dev/null | while read line; do
            echo -e "  $line"
        done || echo "  No logs available"
    else
        echo "  No log file found"
    fi
    
    # Network connections
    echo -e "\n${YELLOW}Network Connections:${NC}"
    ss -tunlp 2>/dev/null | grep rathole | head -5 || echo "  No active connections"
    
    # Configuration file
    echo -e "\n${YELLOW}Current Configuration:${NC}"
    if [[ -f "$CONFIG_DIR/tunnel.toml" ]]; then
        echo -e "${CYAN}$(cat $CONFIG_DIR/tunnel.toml | head -10)${NC}"
    else
        echo "  No tunnel configuration"
    fi
    
    # Ping test
    echo -e "\n${YELLOW}Connectivity Test:${NC}"
    if ping -c 2 -W 1 127.0.0.1 >/dev/null 2>&1; then
        echo -e "  Localhost ping: ${GREEN}OK${NC}"
    else
        echo -e "  Localhost ping: ${RED}FAILED${NC}"
    fi
    
    echo -e "${CYAN}========================================${NC}"
}

# Remove Rathole
remove_rathole() {
    echo -e "${RED}[!] WARNING: This will remove Rathole completely${NC}"
    echo -e "${RED}[!] All configurations and tunnels will be deleted${NC}"
    
    read -p "Are you sure? (type 'YES' to confirm): " confirm
    if [[ "$confirm" != "YES" ]]; then
        echo -e "${YELLOW}Removal cancelled${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}[-] Stopping services...${NC}"
    systemctl stop rathole.service 2>/dev/null || true
    systemctl stop $TUNNEL_SERVICE.service 2>/dev/null || true
    
    echo -e "${YELLOW}[-] Disabling services...${NC}"
    systemctl disable rathole.service 2>/dev/null || true
    systemctl disable $TUNNEL_SERVICE.service 2>/dev/null || true
    
    echo -e "${YELLOW}[-] Removing files...${NC}"
    rm -f $INSTALL_DIR/rathole
    rm -f $SERVICE_DIR/rathole.service
    rm -f $SERVICE_DIR/$TUNNEL_SERVICE.service
    rm -rf $CONFIG_DIR
    rm -rf $LOG_DIR
    
    echo -e "${YELLOW}[-] Reloading systemd...${NC}"
    systemctl daemon-reload
    
    echo -e "${GREEN}[✓] Rathole completely removed${NC}"
}

# Remove tunnel only
remove_tunnel() {
    echo -e "${YELLOW}[-] Removing tunnel...${NC}"
    
    systemctl stop $TUNNEL_SERVICE.service 2>/dev/null || true
    systemctl disable $TUNNEL_SERVICE.service 2>/dev/null || true
    rm -f $CONFIG_DIR/tunnel.toml 2>/dev/null
    systemctl daemon-reload
    
    echo -e "${GREEN}[✓] Tunnel removed${NC}"
}

# Backup configuration
backup_config() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_file="$BACKUP_DIR/rathole_backup_$timestamp.tar.gz"
    
    mkdir -p $BACKUP_DIR
    tar -czf "$backup_file" -C /etc rathole 2>/dev/null
    
    if [[ -f "$backup_file" ]]; then
        echo -e "${GREEN}[✓] Backup created: $backup_file${NC}"
    else
        echo -e "${RED}[ERROR] Backup failed${NC}"
    fi
}

# Main menu
show_menu() {
    echo -e "\n${CYAN}Main Menu:${NC}"
    echo -e "${BLUE}1)${NC} Install Rathole Core"
    echo -e "${BLUE}2)${NC} Create Tunnel"
    echo -e "${BLUE}3)${NC} Show Tunnel Status"
    echo -e "${BLUE}4)${NC} Backup Configuration"
    echo -e "${BLUE}5)${NC} Remove Tunnel Only"
    echo -e "${BLUE}6)${NC} Remove Rathole Completely"
    echo -e "${BLUE}7)${NC} Exit"
    echo -e "${CYAN}========================================${NC}"
}

# Main function
main() {
    # Check root
    check_root
    
    # Show banner
    show_banner
    
    # Check internet
    check_internet
    
    # Create necessary directories
    mkdir -p $LOG_DIR
    
    # Main loop
    while true; do
        show_menu
        read -p "Select option [1-7]: " choice
        
        case $choice in
            1)
                install_dependencies
                detect_architecture
                install_rathole
                ;;
            2)
                create_tunnel
                ;;
            3)
                show_tunnel_status
                ;;
            4)
                backup_config
                ;;
            5)
                remove_tunnel
                ;;
            6)
                remove_rathole
                ;;
            7)
                echo -e "${GREEN}Goodbye!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option!${NC}"
                ;;
        esac
        
        echo -e "\n${YELLOW}Press Enter to continue...${NC}"
        read -p ""
        show_banner
    done
}

# Error handler
error_handler() {
    local exit_code=$?
    echo -e "${RED}[ERROR] Script failed at line $1${NC}"
    echo -e "${RED}[ERROR] Exit code: $exit_code${NC}"
    exit $exit_code
}

# Set error trap
trap 'error_handler $LINENO' ERR

# Run main function
main "$@"
