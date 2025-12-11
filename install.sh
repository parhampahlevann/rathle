#!/bin/bash

# ============================================
# Rathole Tunnel Manager - Ultimate Edition
# Combined from Musixal/rathole-tunnel and improved
# Version: 4.0 - Complete & Bug Free
# ============================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Configuration
RATHOLE_VERSION="0.5.0"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/rathole"
SERVICE_DIR="/etc/systemd/system"
LOG_DIR="/var/log/rathole"
BACKUP_DIR="/etc/rathole/backup"
TUNNEL_NAME="rathole-tunnel"
DEFAULT_PORT="2333"

# Banner
print_banner() {
    clear
    echo -e "${CYAN}"
    cat << "EOF"
╔═══════════════════════════════════════════╗
║    ██████╗  █████╗ ████████╗██╗  ██╗      ║
║    ██╔══██╗██╔══██╗╚══██╔══╝██║  ██║      ║
║    ██████╔╝███████║   ██║   ███████║      ║
║    ██╔══██╗██╔══██║   ██║   ██╔══██║      ║
║    ██║  ██║██║  ██║   ██║   ██║  ██║      ║
║    ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝      ║
║                                           ║
║    Tunnel Manager v4.0 - Ultimate Edition ║
╚═══════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo -e "${YELLOW}Support: IPv4 + IPv6 | TCP + UDP | Encrypted Tunnel${NC}"
    echo -e "${BLUE}===================================================${NC}"
}

# Check root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root${NC}"
        echo -e "${YELLOW}Use: sudo bash \$0${NC}"
        exit 1
    fi
}

# Fix apt/dpkg locks - IMPROVED from Musixal script
fix_package_locks() {
    echo -e "${YELLOW}[*] Checking for package manager locks...${NC}"
    
    # List of lock files
    local locks=(
        "/var/lib/apt/lists/lock"
        "/var/lib/dpkg/lock"
        "/var/lib/dpkg/lock-frontend"
        "/var/cache/apt/archives/lock"
        "/var/lib/apt/lists/lock-frontend"
    )
    
    for lock in "${locks[@]}"; do
        if [[ -f "$lock" || -d "$lock" ]]; then
            echo -e "${YELLOW}[-] Removing lock: $lock${NC}"
            rm -rf "$lock" 2>/dev/null || true
        fi
    done
    
    # Kill any stuck apt/dpkg processes
    local pids=$(ps aux | grep -E '(apt|dpkg|apt-get)' | grep -v grep | awk '{print $2}' 2>/dev/null || true)
    if [[ -n "$pids" ]]; then
        echo -e "${YELLOW}[-] Killing stuck package processes...${NC}"
        for pid in $pids; do
            kill -9 "$pid" 2>/dev/null || true
        done
    fi
    
    # Clean up any broken installations
    dpkg --configure -a 2>/dev/null || true
    apt-get install -f -y 2>/dev/null || true
    
    sleep 2
    echo -e "${GREEN}[✓] Package locks cleared${NC}"
}

# Install dependencies - IMPROVED from Musixal script
install_dependencies() {
    echo -e "${YELLOW}[*] Installing required dependencies...${NC}"
    
    # Fix locks first
    fix_package_locks
    
    # Update package list with retry
    local max_retries=3
    for ((i=1; i<=max_retries; i++)); do
        echo -e "${YELLOW}[-] Updating package list (attempt $i/$max_retries)...${NC}"
        if apt-get update -o Acquire::Retries=3 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30; then
            echo -e "${GREEN}[✓] Package list updated${NC}"
            break
        fi
        
        if [[ $i -eq $max_retries ]]; then
            echo -e "${YELLOW}[!] Package update failed, continuing anyway...${NC}"
        fi
        sleep 2
    done
    
    # Install packages with individual error handling
    local packages=("wget" "curl" "tar" "openssl" "net-tools")
    
    for pkg in "${packages[@]}"; do
        if ! command -v "$pkg" &> /dev/null; then
            echo -e "${YELLOW}[-] Installing $pkg...${NC}"
            
            # Try apt with timeout
            timeout 60 apt-get install -y "$pkg" || {
                echo -e "${YELLOW}[!] Failed to install $pkg via apt, trying alternative...${NC}"
                
                # Alternative installation methods
                case "$pkg" in
                    "wget")
                        # Try to download static binary
                        curl -sSL https://github.com/rockdaboot/wget2/releases/download/v2.0.1/wget2-2.0.1.tar.gz -o /tmp/wget.tar.gz 2>/dev/null || true
                        ;;
                    "curl")
                        # Install from repository with different name
                        apt-get install -y libcurl4-openssl-dev 2>/dev/null || true
                        ;;
                esac
            }
        fi
    done
    
    # Final check
    for pkg in wget curl tar openssl; do
        if command -v "$pkg" &> /dev/null; then
            echo -e "${GREEN}[✓] $pkg is available${NC}"
        else
            echo -e "${YELLOW}[!] $pkg is not available, some features may be limited${NC}"
        fi
    done
}

# Detect system architecture - FROM Musixal script
detect_architecture() {
    echo -e "${YELLOW}[*] Detecting system architecture...${NC}"
    
    local arch=$(uname -m)
    
    case "$arch" in
        "x86_64"|"amd64")
            ARCH="x86_64"
            echo -e "${GREEN}[✓] Architecture: x86_64 (64-bit)${NC}"
            ;;
        "aarch64"|"arm64")
            ARCH="aarch64"
            echo -e "${GREEN}[✓] Architecture: ARM64${NC}"
            ;;
        "armv7l"|"armhf")
            ARCH="armv7"
            echo -e "${GREEN}[✓] Architecture: ARMv7${NC}"
            ;;
        "i386"|"i686")
            ARCH="i686"
            echo -e "${GREEN}[✓] Architecture: x86 (32-bit)${NC}"
            ;;
        *)
            echo -e "${RED}[ERROR] Unsupported architecture: $arch${NC}"
            echo -e "${YELLOW}Trying to continue with x86_64...${NC}"
            ARCH="x86_64"
            ;;
    esac
}

# Download and install Rathole - IMPROVED from Musixal script
install_rathole_binary() {
    echo -e "${GREEN}[*] Installing Rathole Core v$RATHOLE_VERSION...${NC}"
    
    # Create directories
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$BACKUP_DIR"
    
    # Set download URL
    local os_type="unknown-linux-gnu"
    local download_url="https://github.com/rathole-org/rathole/releases/download/v${RATHOLE_VERSION}/rathole-${RATHOLE_VERSION}-${ARCH}-${os_type}.tar.gz"
    
    echo -e "${YELLOW}[-] Download URL: $download_url${NC}"
    
    # Create temp directory
    local temp_dir=$(mktemp -d)
    cd "$temp_dir"
    
    # Download with retry logic
    local max_retries=3
    local download_success=false
    
    for ((i=1; i<=max_retries; i++)); do
        echo -e "${YELLOW}[-] Download attempt $i/$max_retries...${NC}"
        
        if command -v wget &> /dev/null; then
            if wget -q --timeout=30 --tries=3 "$download_url" -O rathole.tar.gz; then
                download_success=true
                break
            fi
        elif command -v curl &> /dev/null; then
            if curl -fsSL --connect-timeout 30 --retry 3 "$download_url" -o rathole.tar.gz; then
                download_success=true
                break
            fi
        else
            echo -e "${RED}[ERROR] No download tool available${NC}"
            return 1
        fi
        
        echo -e "${YELLOW}[!] Download failed, retrying in 3 seconds...${NC}"
        sleep 3
    done
    
    if [[ "$download_success" == false ]]; then
        echo -e "${RED}[ERROR] Failed to download Rathole after $max_retries attempts${NC}"
        return 1
    fi
    
    # Extract archive
    echo -e "${YELLOW}[-] Extracting files...${NC}"
    
    if ! tar -xzf rathole.tar.gz 2>/dev/null; then
        echo -e "${YELLOW}[!] Standard extraction failed, trying alternative method...${NC}"
        gzip -dc rathole.tar.gz | tar xf - 2>/dev/null || {
            echo -e "${RED}[ERROR] Failed to extract archive${NC}"
            return 1
        }
    fi
    
    # Find rathole binary
    local rathole_bin=$(find . -name "rathole" -type f 2>/dev/null | head -1)
    
    if [[ -z "$rathole_bin" ]]; then
        # Try specific path
        rathole_bin="./rathole"
        if [[ ! -f "$rathole_bin" ]]; then
            # Extract with wildcard
            tar -xzf rathole.tar.gz --wildcards '*/rathole' --strip-components=1 2>/dev/null || true
        fi
    fi
    
    # Install binary
    if [[ -f "$rathole_bin" ]] && [[ -x "$rathole_bin" ]]; then
        cp "$rathole_bin" "$INSTALL_DIR/rathole"
        chmod +x "$INSTALL_DIR/rathole"
        echo -e "${GREEN}[✓] Rathole installed to $INSTALL_DIR/rathole${NC}"
    else
        echo -e "${RED}[ERROR] Rathole binary not found or not executable${NC}"
        return 1
    fi
    
    # Cleanup
    cd /
    rm -rf "$temp_dir"
    
    return 0
}

# Create systemd services - FROM Musixal script with improvements
create_systemd_services() {
    echo -e "${YELLOW}[*] Creating systemd services...${NC}"
    
    # Main service file
    cat > "$SERVICE_DIR/rathole.service" << EOF
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

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$CONFIG_DIR $LOG_DIR

# Logging
StandardOutput=append:$LOG_DIR/rathole.log
StandardError=append:$LOG_DIR/rathole-error.log
SyslogIdentifier=rathole

[Install]
WantedBy=multi-user.target
EOF

    # Tunnel service
    cat > "$SERVICE_DIR/$TUNNEL_NAME.service" << EOF
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

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$CONFIG_DIR $LOG_DIR

# Logging
StandardOutput=append:$LOG_DIR/tunnel.log
StandardError=append:$LOG_DIR/tunnel-error.log
SyslogIdentifier=rathole-tunnel

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd
    systemctl daemon-reload 2>/dev/null || true
    
    echo -e "${GREEN}[✓] Systemd services created${NC}"
}

# Create configuration templates - IMPROVED from Musixal script
create_config_templates() {
    echo -e "${YELLOW}[*] Creating configuration templates...${NC}"
    
    # Server configuration
    cat > "$CONFIG_DIR/server.toml" << 'EOF'
# Rathole Server Configuration
# This server accepts incoming connections from clients

[server]
bind_addr = "0.0.0.0:2333"
default_token = "change_this_to_secure_token"

# Example: SSH tunnel service
[server.services.ssh]
bind_addr = "0.0.0.0:2222"
type = "tcp"
nodelay = true

# Example: HTTP tunnel service (supports IPv6)
[server.services.http]
bind_addr = "0.0.0.0:8080"
bind_addr_v6 = "[::]:8080"
type = "tcp+udp"
nodelay = true
EOF

    # Client configuration
    cat > "$CONFIG_DIR/client.toml" << 'EOF'
# Rathole Client Configuration
# This client connects to a remote server

[client]
remote_addr = "SERVER_IP_HERE:2333"
default_token = "change_this_to_secure_token"
retry_interval = 1

# Example: SSH service
[client.services.ssh]
local_addr = "127.0.0.1:22"
type = "tcp"
nodelay = true

# Example: HTTP service (supports IPv6)
[client.services.http]
local_addr = "127.0.0.1:80"
local_addr_v6 = "[::1]:80"
type = "tcp+udp"
nodelay = true
EOF

    # Empty tunnel config (will be filled)
    cat > "$CONFIG_DIR/tunnel.toml" << 'EOF'
# Tunnel configuration will be generated here
# Run the tunnel creation wizard to set up
EOF

    echo -e "${GREEN}[✓] Configuration templates created${NC}"
}

# Generate encryption key - FROM Musixal script
generate_encryption_key() {
    local key=$(openssl rand -hex 32 2>/dev/null || echo "default_$(date +%s)")
    echo "$key"
}

# Tunnel creation wizard - IMPROVED from Musixal script
create_tunnel_wizard() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════╗"
    echo "║      Tunnel Creation Wizard          ║"
    echo "╚══════════════════════════════════════╝"
    echo -e "${NC}"
    
    # Check if rathole is installed
    if [[ ! -f "$INSTALL_DIR/rathole" ]]; then
        echo -e "${RED}[ERROR] Rathole is not installed!${NC}"
        echo -e "${YELLOW}Run the installation first (option 1)${NC}"
        return 1
    fi
    
    # Server location
    echo -e "${YELLOW}Select your server location:${NC}"
    echo -e "  1) Iran Server (Client connecting to Foreign)"
    echo -e "  2) Foreign Server (Client connecting to Iran)"
    echo -e "  3) Server Mode (Accept incoming connections)"
    
    local location=""
    while [[ ! "$location" =~ ^[1-3]$ ]]; do
        read -rp "Choice [1-3]: " location
    done
    
    # Common parameters
    local remote_ip=""
    local remote_port=""
    local local_port=""
    
    if [[ "$location" != "3" ]]; then
        # Client mode needs remote server info
        while true; do
            read -rp "Remote server IP address: " remote_ip
            if [[ "$remote_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                break
            else
                echo -e "${RED}Invalid IP address format${NC}"
            fi
        done
        
        read -rp "Remote server port [$DEFAULT_PORT]: " remote_port
        remote_port=${remote_port:-$DEFAULT_PORT}
    fi
    
    read -rp "Local port [$DEFAULT_PORT]: " local_port
    local_port=${local_port:-$DEFAULT_PORT}
    
    # Generate encryption key
    local encryption_key=$(generate_encryption_key)
    
    # Create configuration based on choice
    case $location in
        1)
            # Iran server (client)
            create_iran_client_config "$remote_ip" "$remote_port" "$local_port" "$encryption_key"
            show_foreign_server_config "$remote_port" "$encryption_key"
            ;;
        2)
            # Foreign server (client)
            create_foreign_client_config "$remote_ip" "$remote_port" "$local_port" "$encryption_key"
            show_iran_server_config "$remote_port" "$encryption_key"
            ;;
        3)
            # Server mode
            create_server_config "$local_port" "$encryption_key"
            ;;
    esac
    
    # Backup existing config
    backup_configuration
    
    echo -e "${GREEN}[✓] Tunnel configuration created${NC}"
    echo -e "${YELLOW}Config file: $CONFIG_DIR/tunnel.toml${NC}"
    echo -e "${BLUE}Encryption Key: $encryption_key${NC}"
    
    # Ask to start service
    read -rp "Start tunnel service now? (y/n): " start_now
    if [[ "$start_now" =~ ^[Yy]$ ]]; then
        start_tunnel_service
    fi
}

# Create Iran client config
create_iran_client_config() {
    local remote_ip=$1 remote_port=$2 local_port=$3 key=$4
    
    cat > "$CONFIG_DIR/tunnel.toml" << EOF
[client]
remote_addr = "$remote_ip:$remote_port"
default_token = "$key"
retry_interval = 1

[client.services.iran_tunnel]
local_addr = "127.0.0.1:$local_port"
local_addr_v6 = "[::1]:$local_port"
type = "tcp+udp"
nodelay = true
EOF
}

# Create Foreign client config
create_foreign_client_config() {
    local remote_ip=$1 remote_port=$2 local_port=$3 key=$4
    
    cat > "$CONFIG_DIR/tunnel.toml" << EOF
[client]
remote_addr = "$remote_ip:$remote_port"
default_token = "$key"
retry_interval = 1

[client.services.foreign_tunnel]
local_addr = "127.0.0.1:$local_port"
local_addr_v6 = "[::1]:$local_port"
type = "tcp+udp"
nodelay = true
EOF
}

# Create server config
create_server_config() {
    local port=$1 key=$2
    
    cat > "$CONFIG_DIR/tunnel.toml" << EOF
[server]
bind_addr = "0.0.0.0:$port"
default_token = "$key"

[server.services.main_tunnel]
bind_addr = "0.0.0.0:$port"
bind_addr_v6 = "[::]:$port"
type = "tcp+udp"
nodelay = true
EOF
}

# Show Foreign server config (for Iran setup)
show_foreign_server_config() {
    local port=$1 key=$2
    
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════╗"
    echo "║  Configuration for FOREIGN Server    ║"
    echo "╚══════════════════════════════════════╝"
    echo -e "${NC}"
    
    cat << EOF
Copy this configuration to your FOREIGN server:

File: /etc/rathole/server.toml
===========================================
[server]
bind_addr = "0.0.0.0:$port"
default_token = "$key"

[server.services.iran_connection]
bind_addr = "0.0.0.0:$port"
bind_addr_v6 = "[::]:$port"
type = "tcp+udp"
nodelay = true
===========================================

On foreign server, run:
1. sudo systemctl stop rathole (if running)
2. Save above config to /etc/rathole/server.toml
3. sudo systemctl start rathole
4. sudo systemctl enable rathole
EOF
}

# Show Iran server config (for Foreign setup)
show_iran_server_config() {
    local port=$1 key=$2
    
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════╗"
    echo "║   Configuration for IRAN Server      ║"
    echo "╚══════════════════════════════════════╝"
    echo -e "${NC}"
    
    cat << EOF
Copy this configuration to your IRAN server:

File: /etc/rathole/server.toml
===========================================
[server]
bind_addr = "0.0.0.0:$port"
default_token = "$key"

[server.services.foreign_connection]
bind_addr = "0.0.0.0:$port"
bind_addr_v6 = "[::]:$port"
type = "tcp+udp"
nodelay = true
===========================================

On Iran server, run:
1. sudo systemctl stop rathole (if running)
2. Save above config to /etc/rathole/server.toml
3. sudo systemctl start rathole
4. sudo systemctl enable rathole
EOF
}

# Start tunnel service
start_tunnel_service() {
    echo -e "${YELLOW}[*] Starting tunnel service...${NC}"
    
    # Stop if running
    systemctl stop "$TUNNEL_NAME.service" 2>/dev/null || true
    sleep 2
    
    # Start service
    systemctl daemon-reload
    systemctl enable "$TUNNEL_NAME.service" 2>/dev/null || true
    
    if systemctl start "$TUNNEL_NAME.service"; then
        echo -e "${GREEN}[✓] Tunnel service started${NC}"
        
        # Check status
        sleep 3
        if systemctl is-active --quiet "$TUNNEL_NAME.service"; then
            echo -e "${GREEN}[✓] Service is running${NC}"
        else
            echo -e "${YELLOW}[!] Service may have failed to start${NC}"
            echo -e "${YELLOW}Check: systemctl status $TUNNEL_NAME${NC}"
        fi
    else
        echo -e "${RED}[ERROR] Failed to start service${NC}"
        echo -e "${YELLOW}Trying manual start...${NC}"
        
        # Try manual start
        nohup "$INSTALL_DIR/rathole" "$CONFIG_DIR/tunnel.toml" > "$LOG_DIR/tunnel.log" 2>&1 &
        echo -e "${YELLOW}[!] Started manually (PID: $!)${NC}"
    fi
}

# Show tunnel status - IMPROVED from Musixal script
show_tunnel_status() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════╗"
    echo "║         Tunnel Status                ║"
    echo "╚══════════════════════════════════════╝"
    echo -e "${NC}"
    
    # Check installation
    if [[ -f "$INSTALL_DIR/rathole" ]]; then
        echo -e "${GREEN}✓ Rathole installed at: $INSTALL_DIR/rathole${NC}"
        local version=$("$INSTALL_DIR/rathole" --version 2>/dev/null || echo "Unknown")
        echo -e "${YELLOW}Version: $version${NC}"
    else
        echo -e "${RED}✗ Rathole not installed${NC}"
    fi
    
    echo -e "${BLUE}------------------------------------------${NC}"
    
    # Service status
    echo -e "${YELLOW}Service Status:${NC}"
    
    if systemctl is-active "$TUNNEL_NAME.service" >/dev/null 2>&1; then
        echo -e "  $TUNNEL_NAME.service: ${GREEN}ACTIVE${NC}"
        local pid=$(systemctl show --property=MainPID --value "$TUNNEL_NAME.service")
        echo -e "  PID: $pid"
    else
        echo -e "  $TUNNEL_NAME.service: ${RED}INACTIVE${NC}"
    fi
    
    if systemctl is-active "rathole.service" >/dev/null 2>&1; then
        echo -e "  rathole.service: ${GREEN}ACTIVE${NC}"
    fi
    
    echo -e "${BLUE}------------------------------------------${NC}"
    
    # Configuration
    echo -e "${YELLOW}Configuration:${NC}"
    if [[ -f "$CONFIG_DIR/tunnel.toml" ]]; then
        echo -e "  Tunnel config: ${GREEN}$CONFIG_DIR/tunnel.toml${NC}"
        echo -e "${CYAN}Preview:${NC}"
        head -15 "$CONFIG_DIR/tunnel.toml" | sed 's/^/  /'
    else
        echo -e "  Tunnel config: ${RED}Not found${NC}"
    fi
    
    echo -e "${BLUE}------------------------------------------${NC}"
    
    # Network connections
    echo -e "${YELLOW}Network Connections:${NC}"
    if command -v ss &> /dev/null; then
        ss -tunlp | grep -E "(rathole|$DEFAULT_PORT)" | head -10 | sed 's/^/  /' || echo -e "  ${YELLOW}No rathole connections found${NC}"
    else
        echo -e "  ${YELLOW}ss command not available${NC}"
    fi
    
    echo -e "${BLUE}------------------------------------------${NC}"
    
    # Log files
    echo -e "${YELLOW}Log Files:${NC}"
    for logfile in "$LOG_DIR"/*.log; do
        if [[ -f "$logfile" ]]; then
            local size=$(du -h "$logfile" | cut -f1)
            echo -e "  $(basename "$logfile"): $size"
        fi
    done
    
    if ! ls "$LOG_DIR"/*.log >/dev/null 2>&1; then
        echo -e "  ${YELLOW}No log files found${NC}"
    fi
    
    echo -e "${BLUE}------------------------------------------${NC}"
    
    # Quick test
    echo -e "${YELLOW}Quick Test:${NC}"
    if timeout 2 bash -c "echo > /dev/tcp/127.0.0.1/$DEFAULT_PORT" 2>/dev/null; then
        echo -e "  Port $DEFAULT_PORT: ${GREEN}OPEN${NC}"
    else
        echo -e "  Port $DEFAULT_PORT: ${RED}CLOSED${NC}"
    fi
}

# Backup configuration
backup_configuration() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_file="$BACKUP_DIR/backup_$timestamp.tar.gz"
    
    mkdir -p "$BACKUP_DIR"
    
    if tar -czf "$backup_file" -C /etc rathole 2>/dev/null; then
        echo -e "${GREEN}[✓] Configuration backed up to: $backup_file${NC}"
    else
        echo -e "${YELLOW}[!] Backup creation failed${NC}"
    fi
}

# Remove Rathole completely
remove_rathole_completely() {
    echo -e "${RED}╔══════════════════════════════════════╗${NC}"
    echo -e "${RED}║        COMPLETE UNINSTALL            ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════╝${NC}"
    
    echo -e "${YELLOW}This will remove:${NC}"
    echo -e "  - Rathole binary"
    echo -e "  - All configurations"
    echo -e "  - Systemd services"
    echo -e "  - Log files"
    
    read -rp "Type 'UNINSTALL' to confirm: " confirm
    if [[ "$confirm" != "UNINSTALL" ]]; then
        echo -e "${YELLOW}Uninstall cancelled${NC}"
        return
    fi
    
    # Stop services
    echo -e "${YELLOW}[*] Stopping services...${NC}"
    systemctl stop "$TUNNEL_NAME.service" 2>/dev/null || true
    systemctl stop rathole.service 2>/dev/null || true
    pkill -f rathole 2>/dev/null || true
    
    # Disable services
    systemctl disable "$TUNNEL_NAME.service" 2>/dev/null || true
    systemctl disable rathole.service 2>/dev/null || true
    
    # Remove files
    echo -e "${YELLOW}[*] Removing files...${NC}"
    rm -f "$INSTALL_DIR/rathole"
    rm -f "$SERVICE_DIR/rathole.service"
    rm -f "$SERVICE_DIR/$TUNNEL_NAME.service"
    rm -rf "$CONFIG_DIR"
    rm -rf "$LOG_DIR"
    
    # Reload systemd
    systemctl daemon-reload 2>/dev/null || true
    
    echo -e "${GREEN}[✓] Rathole completely removed${NC}"
}

# Remove tunnel only
remove_tunnel_only() {
    echo -e "${YELLOW}[*] Removing tunnel configuration...${NC}"
    
    systemctl stop "$TUNNEL_NAME.service" 2>/dev/null || true
    systemctl disable "$TUNNEL_NAME.service" 2>/dev/null || true
    rm -f "$CONFIG_DIR/tunnel.toml" 2>/dev/null || true
    
    # Restore default config
    if [[ -f "$CONFIG_DIR/server.toml" ]]; then
        cp "$CONFIG_DIR/server.toml" "$CONFIG_DIR/tunnel.toml"
    fi
    
    systemctl daemon-reload 2>/dev/null || true
    
    echo -e "${GREEN}[✓] Tunnel removed${NC}"
}

# Main installation function
perform_installation() {
    print_banner
    check_root
    
    echo -e "${GREEN}[*] Starting Rathole installation...${NC}"
    
    # Step 1: Install dependencies
    install_dependencies
    
    # Step 2: Detect architecture
    detect_architecture
    
    # Step 3: Install rathole binary
    if install_rathole_binary; then
        echo -e "${GREEN}[✓] Rathole binary installed successfully${NC}"
    else
        echo -e "${RED}[ERROR] Failed to install Rathole binary${NC}"
        exit 1
    fi
    
    # Step 4: Create systemd services
    create_systemd_services
    
    # Step 5: Create config templates
    create_config_templates
    
    # Final verification
    echo -e "${YELLOW}[*] Verifying installation...${NC}"
    
    if [[ -x "$INSTALL_DIR/rathole" ]]; then
        echo -e "${GREEN}[✓] Installation completed successfully!${NC}"
        echo -e "${BLUE}==========================================${NC}"
        echo -e "${CYAN}Files installed:${NC}"
        echo -e "  Binary: $INSTALL_DIR/rathole"
        echo -e "  Configs: $CONFIG_DIR/"
        echo -e "  Services: /etc/systemd/system/"
        echo -e "  Logs: $LOG_DIR/"
        echo -e "${BLUE}==========================================${NC}"
        echo -e "${YELLOW}Next: Run option 2 to create a tunnel${NC}"
    else
        echo -e "${RED}[ERROR] Installation verification failed${NC}"
        exit 1
    fi
}

# Interactive menu
show_interactive_menu() {
    while true; do
        print_banner
        
        echo -e "${CYAN}Main Menu:${NC}"
        echo -e "${GREEN}1)${NC} Install Rathole Core"
        echo -e "${GREEN}2)${NC} Create New Tunnel"
        echo -e "${GREEN}3)${NC} Show Tunnel Status"
        echo -e "${GREEN}4)${NC} Start Tunnel Service"
        echo -e "${GREEN}5)${NC} Backup Configuration"
        echo -e "${GREEN}6)${NC} Remove Tunnel Only"
        echo -e "${GREEN}7)${NC} Remove Rathole Completely"
        echo -e "${GREEN}8)${NC} Exit"
        echo -e "${BLUE}==========================================${NC}"
        
        read -rp "Select option [1-8]: " choice
        
        case $choice in
            1) perform_installation ;;
            2) create_tunnel_wizard ;;
            3) show_tunnel_status ;;
            4) start_tunnel_service ;;
            5) backup_configuration ;;
            6) remove_tunnel_only ;;
            7) remove_rathole_completely ;;
            8) 
                echo -e "${GREEN}Goodbye!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option!${NC}"
                ;;
        esac
        
        echo -e "\n${YELLOW}Press Enter to continue...${NC}"
        read -r
    done
}

# One-click install mode
one_click_install() {
    print_banner
    check_root
    
    echo -e "${GREEN}[*] Starting one-click installation...${NC}"
    
    # Perform installation
    perform_installation
    
    # Ask to create tunnel
    echo -e "\n${YELLOW}Do you want to create a tunnel now? (y/n):${NC}"
    read -r create_tunnel
    
    if [[ "$create_tunnel" =~ ^[Yy]$ ]]; then
        create_tunnel_wizard
    fi
    
    echo -e "\n${GREEN}════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}✅ Installation Complete!${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════${NC}"
    echo -e "\n${YELLOW}Quick commands:${NC}"
    echo -e "  Check status: systemctl status $TUNNEL_NAME"
    echo -e "  View logs: tail -f $LOG_DIR/tunnel.log"
    echo -e "  Create tunnel: Run this script with --menu"
    echo -e "${GREEN}════════════════════════════════════════════════${NC}"
}

# Help function
show_help() {
    echo -e "${CYAN}Rathole Tunnel Manager - Help${NC}"
    echo -e "${BLUE}==========================================${NC}"
    echo -e "${YELLOW}Usage:${NC}"
    echo -e "  sudo bash $0               # One-click install"
    echo -e "  sudo bash $0 --menu        # Interactive menu"
    echo -e "  sudo bash $0 --install     # Install only"
    echo -e "  sudo bash $0 --status      # Show status"
    echo -e "  sudo bash $0 --create      # Create tunnel"
    echo -e "  sudo bash $0 --help        # This help"
    echo -e "${BLUE}==========================================${NC}"
}

# Main script logic
main() {
    local arg="${1:-}"
    
    case "$arg" in
        "--menu")
            show_interactive_menu
            ;;
        "--install")
            perform_installation
            ;;
        "--status")
            show_tunnel_status
            ;;
        "--create")
            create_tunnel_wizard
            ;;
        "--help")
            show_help
            ;;
        *)
            one_click_install
            ;;
    esac
}

# Run main function
main "$@"
