#!/bin/bash
# ============================================
# Rathole Tunnel Manager - Ultimate Fixed Version
# Version: 5.0
# ============================================

set -euo pipefail

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

# Main Configuration
RATHOLE_VERSION="0.5.0"
CONFIG_DIR="/root/rathole-core"
SERVICE_DIR="/etc/systemd/system"

# Banner
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════╗"
    echo "║   Rathole Tunnel Manager - Fixed v5.0    ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Check Root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR] Please run as root: sudo bash \$0${NC}"
        exit 1
    fi
}

# Fix Common Issues
fix_system_issues() {
    echo -e "${YELLOW}[*] Fixing system issues...${NC}"
    
    # Fix apt locks
    for lock in /var/lib/apt/lists/lock /var/lib/dpkg/lock; do
        if [[ -f $lock ]]; then
            rm -f $lock 2>/dev/null || true
        fi
    done
    
    # Add GitHub to hosts if needed
    if ! grep -q "raw.githubusercontent.com" /etc/hosts; then
        echo "185.199.108.133 raw.githubusercontent.com" >> /etc/hosts
    fi
    
    echo -e "${GREEN}[✓] System fixes applied${NC}"
}

# Install Dependencies
install_dependencies() {
    echo -e "${YELLOW}[*] Installing dependencies...${NC}"
    
    apt-get update || true
    
    local packages=("curl" "wget" "unzip" "jq" "openssl")
    for pkg in "${packages[@]}"; do
        if ! command -v "$pkg" &>/dev/null; then
            echo -e "${YELLOW}[-] Installing $pkg...${NC}"
            apt-get install -y "$pkg" 2>/dev/null || true
        fi
    done
    
    echo -e "${GREEN}[✓] Dependencies installed${NC}"
}

# Install Rathole Core - FIXED VERSION
install_rathole_core() {
    echo -e "${GREEN}[*] Installing Rathole Core v${RATHOLE_VERSION}...${NC}"
    
    # Remove old installation if exists
    if [[ -d "$CONFIG_DIR" ]]; then
        echo -e "${YELLOW}[-] Removing old installation...${NC}"
        rm -rf "$CONFIG_DIR"
    fi
    
    # Create directory
    mkdir -p "$CONFIG_DIR"
    
    # Detect architecture
    local ARCH=$(uname -m)
    case "$ARCH" in
        "x86_64") BIN_ARCH="x86_64" ;;
        "aarch64"|"arm64") BIN_ARCH="aarch64" ;;
        "armv7l") BIN_ARCH="armv7" ;;
        *) 
            echo -e "${YELLOW}[!] Unknown architecture, using x86_64${NC}"
            BIN_ARCH="x86_64"
            ;;
    esac
    
    echo -e "${YELLOW}[-] Architecture: $BIN_ARCH${NC}"
    
    # Download from official GitHub releases - FIXED URL
    local DOWNLOAD_URL="https://github.com/rathole-org/rathole/releases/download/v${RATHOLE_VERSION}/rathole-${RATHOLE_VERSION}-${BIN_ARCH}-unknown-linux-gnu.tar.gz"
    
    echo -e "${YELLOW}[-] Download URL: $DOWNLOAD_URL${NC}"
    
    # Download and extract
    local TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"
    
    if curl -fsSL -o rathole.tar.gz "$DOWNLOAD_URL"; then
        echo -e "${GREEN}[✓] Download successful${NC}"
        
        # Extract
        tar -xzf rathole.tar.gz 2>/dev/null || {
            # Try alternative extraction
            gzip -dc rathole.tar.gz | tar xf - 2>/dev/null
        }
        
        # Find and copy binary
        local RATHOLE_BIN=$(find . -name "rathole" -type f | head -1)
        
        if [[ -f "$RATHOLE_BIN" ]]; then
            cp "$RATHOLE_BIN" "$CONFIG_DIR/rathole"
            chmod +x "$CONFIG_DIR/rathole"
            
            # Test binary
            if "$CONFIG_DIR/rathole" --version &>/dev/null; then
                echo -e "${GREEN}[✓] Rathole Core installed successfully!${NC}"
                echo -e "${YELLOW}Location: $CONFIG_DIR/rathole${NC}"
            else
                echo -e "${YELLOW}[!] Binary installed but version check failed${NC}"
            fi
        else
            echo -e "${RED}[ERROR] Rathole binary not found in archive${NC}"
            return 1
        fi
    else
        echo -e "${RED}[ERROR] Download failed from official repo${NC}"
        echo -e "${YELLOW}Trying alternative source...${NC}"
        
        # Alternative download from Musixal repo
        local ALT_URL="https://github.com/Musixal/rathole-tunnel/raw/main/core/rathole.zip"
        if curl -fsSL -o rathole.zip "$ALT_URL"; then
            unzip -q rathole.zip -d "$CONFIG_DIR"
            chmod +x "$CONFIG_DIR/rathole" 2>/dev/null || true
            echo -e "${GREEN}[✓] Installed from alternative source${NC}"
        else
            echo -e "${RED}[ERROR] All download methods failed${NC}"
            return 1
        fi
    fi
    
    # Cleanup
    cd /
    rm -rf "$TEMP_DIR"
    
    return 0
}

# Create Tunnel Configuration
create_tunnel() {
    echo -e "${CYAN}[Tunnel Creation Wizard]${NC}"
    
    # Check if core is installed
    if [[ ! -f "$CONFIG_DIR/rathole" ]]; then
        echo -e "${RED}[ERROR] Install Rathole Core first!${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}Select server location:${NC}"
    echo -e "  1) Iran Server (Accepts connections)"
    echo -e "  2) Foreign Server (Connects to Iran)"
    
    read -p "Choice [1-2]: " choice
    
    if [[ "$choice" == "1" ]]; then
        # Iran Server Configuration
        echo -e "${GREEN}[*] Configuring Iran Server${NC}"
        
        read -p "Tunnel port [2333]: " tunnel_port
        tunnel_port=${tunnel_port:-2333}
        
        read -p "Number of services: " num_services
        
        # Generate config
        cat > "$CONFIG_DIR/server.toml" << EOF
[server]
bind_addr = "0.0.0.0:${tunnel_port}"
default_token = "$(openssl rand -hex 32)"
heartbeat_interval = 30
EOF
        
        for ((i=1; i<=num_services; i++)); do
            read -p "Service $i port: " service_port
            cat >> "$CONFIG_DIR/server.toml" << EOF

[server.services.service_${i}]
type = "tcp"
bind_addr = "0.0.0.0:${service_port}"
nodelay = true
EOF
        done
        
        # Create service file
        cat > "$SERVICE_DIR/rathole-iran.service" << EOF
[Unit]
Description=Rathole Iran Server
After=network.target

[Service]
Type=simple
ExecStart=$CONFIG_DIR/rathole $CONFIG_DIR/server.toml
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
        
        systemctl daemon-reload
        systemctl enable rathole-iran.service
        systemctl start rathole-iran.service
        
        echo -e "${GREEN}[✓] Iran server configured${NC}"
        
    elif [[ "$choice" == "2" ]]; then
        # Foreign Server Configuration
        echo -e "${GREEN}[*] Configuring Foreign Server${NC}"
        
        read -p "Iran server IP: " iran_ip
        read -p "Tunnel port [2333]: " tunnel_port
        tunnel_port=${tunnel_port:-2333}
        
        read -p "Number of services: " num_services
        
        # Generate config
        cat > "$CONFIG_DIR/client.toml" << EOF
[client]
remote_addr = "${iran_ip}:${tunnel_port}"
default_token = "$(openssl rand -hex 32)"
retry_interval = 1
EOF
        
        for ((i=1; i<=num_services; i++)); do
            read -p "Service $i local port: " local_port
            cat >> "$CONFIG_DIR/client.toml" << EOF

[client.services.service_${i}]
type = "tcp"
local_addr = "127.0.0.1:${local_port}"
EOF
        done
        
        # Create service file
        cat > "$SERVICE_DIR/rathole-foreign.service" << EOF
[Unit]
Description=Rathole Foreign Client
After=network.target

[Service]
Type=simple
ExecStart=$CONFIG_DIR/rathole $CONFIG_DIR/client.toml
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
        
        systemctl daemon-reload
        systemctl enable rathole-foreign.service
        systemctl start rathole-foreign.service
        
        echo -e "${GREEN}[✓] Foreign server configured${NC}"
    else
        echo -e "${RED}[ERROR] Invalid choice${NC}"
    fi
}

# Show Status
show_status() {
    echo -e "${CYAN}[System Status]${NC}"
    
    # Check Rathole installation
    if [[ -f "$CONFIG_DIR/rathole" ]]; then
        echo -e "${GREEN}✓ Rathole Core: INSTALLED${NC}"
        echo -e "${YELLOW}  Location: $CONFIG_DIR/rathole${NC}"
    else
        echo -e "${RED}✗ Rathole Core: NOT INSTALLED${NC}"
    fi
    
    # Check services
    echo -e "\n${YELLOW}Active Services:${NC}"
    for service in rathole-iran rathole-foreign; do
        if systemctl is-active --quiet "$service.service" 2>/dev/null; then
            echo -e "  ${GREEN}✓ $service.service: RUNNING${NC}"
        elif systemctl is-enabled --quiet "$service.service" 2>/dev/null; then
            echo -e "  ${YELLOW}○ $service.service: ENABLED (not running)${NC}"
        fi
    done
    
    # Show config files
    echo -e "\n${YELLOW}Configuration Files:${NC}"
    for config in server.toml client.toml; do
        if [[ -f "$CONFIG_DIR/$config" ]]; then
            echo -e "  ${GREEN}✓ $config${NC}"
        fi
    done
}

# Main Menu
show_menu() {
    clear
    show_banner
    
    echo -e "${CYAN}Main Menu:${NC}"
    echo -e "${GREEN}1)${NC} Install Rathole Core"
    echo -e "${GREEN}2)${NC} Create Tunnel"
    echo -e "${GREEN}3)${NC} Start Tunnel Service"
    echo -e "${GREEN}4)${NC} Show Status"
    echo -e "${GREEN}5)${NC} Uninstall"
    echo -e "${GREEN}6)${NC} Exit"
    echo -e "${BLUE}=================================${NC}"
}

# Uninstall
uninstall_rathole() {
    echo -e "${RED}[!] Uninstalling Rathole...${NC}"
    
    # Stop services
    systemctl stop rathole-iran.service 2>/dev/null || true
    systemctl stop rathole-foreign.service 2>/dev/null || true
    
    # Remove files
    rm -rf "$CONFIG_DIR"
    rm -f "$SERVICE_DIR/rathole-iran.service"
    rm -f "$SERVICE_DIR/rathole-foreign.service"
    
    systemctl daemon-reload
    
    echo -e "${GREEN}[✓] Rathole uninstalled${NC}"
}

# Main Program
main() {
    check_root
    show_banner
    
    while true; do
        show_menu
        read -p "Select option [1-6]: " choice
        
        case $choice in
            1)
                fix_system_issues
                install_dependencies
                install_rathole_core
                ;;
            2)
                create_tunnel
                ;;
            3)
                read -p "Service to start (iran/foreign): " service
                if [[ "$service" == "iran" ]]; then
                    systemctl restart rathole-iran.service
                elif [[ "$service" == "foreign" ]]; then
                    systemctl restart rathole-foreign.service
                fi
                ;;
            4)
                show_status
                ;;
            5)
                uninstall_rathole
                ;;
            6)
                echo -e "${GREEN}Goodbye!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option!${NC}"
                ;;
        esac
        
        echo -e "\n${YELLOW}Press Enter to continue...${NC}"
        read
    done
}

# Start the program
main "$@"
