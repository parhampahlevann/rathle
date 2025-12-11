#!/bin/bash
# ============================================
# Rathole Tunnel Manager - Enhanced Version
# Based on Musixal/rathole-tunnel with fixes
# Version: 6.0
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
CONFIG_DIR="/root/rathole-core"
SERVICE_DIR="/etc/systemd/system"
LOG_DIR="/var/log/rathole"

# Display logo
display_logo() {
    clear
    echo -e "${CYAN}"
    cat << "EOF"
               __  .__           .__          
____________ _/  |_|  |__   ____ |  |   ____  
\_  __ \__  \\   __|  |  \ /  _ \|  | _/ __ \ 
 |  | \// __ \|  | |   Y  (  <_> |  |_\  ___/ 
 |__|  (____  |__| |___|  /\____/|____/\___  >
            \/          \/                 \/ 	
EOF
    echo -e "${NC}${GREEN}"
    echo -e "${YELLOW}High-performance reverse tunnel${GREEN}"
    echo -e "Version: ${YELLOW}v6.0${GREEN}"
    echo -e "Based on: ${YELLOW}Musixal/rathole-tunnel${GREEN}"
    echo -e "${BLUE}===========================================${NC}"
}

# Check root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}This script must be run as root${NC}"
        sleep 1
        exit 1
    fi
}

# Fix apt locks
fix_apt_locks() {
    echo -e "${YELLOW}[*] Checking for package locks...${NC}"
    for lock in /var/lib/apt/lists/lock /var/lib/dpkg/lock; do
        if [[ -f $lock ]]; then
            echo -e "${YELLOW}[-] Removing lock: $lock${NC}"
            rm -f $lock 2>/dev/null || true
        fi
    done
    sleep 2
}

# Install unzip
install_unzip() {
    if ! command -v unzip &> /dev/null; then
        echo -e "${YELLOW}[-] Installing unzip...${NC}"
        apt-get update
        apt-get install -y unzip
    fi
}

# Install jq
install_jq() {
    if ! command -v jq &> /dev/null; then
        echo -e "${YELLOW}[-] Installing jq...${NC}"
        apt-get install -y jq
    fi
}

# Install iptables
install_iptables() {
    if ! command -v iptables &> /dev/null; then
        echo -e "${YELLOW}[-] Installing iptables...${NC}"
        apt-get install -y iptables
    fi
}

# Install bc
install_bc() {
    if ! command -v bc &> /dev/null; then
        echo -e "${YELLOW}[-] Installing bc...${NC}"
        apt-get install -y bc
    fi
}

# Fix GitHub host entry
fix_github_host() {
    local ENTRY="185.199.108.133 raw.githubusercontent.com"
    if ! grep -q "$ENTRY" /etc/hosts; then
        echo -e "${YELLOW}[-] Adding GitHub to /etc/hosts...${NC}"
        echo "$ENTRY" >> /etc/hosts
    fi
}

# Download and extract Rathole - IMPROVED VERSION
download_and_extract_rathole() {
    echo -e "${GREEN}[*] Installing Rathole Core...${NC}"
    
    if [[ -d "$CONFIG_DIR" ]]; then
        echo -e "${YELLOW}Rathole Core is already installed.${NC}"
        read -p "Reinstall? (y/n): " reinstall
        if [[ ! "$reinstall" =~ ^[Yy]$ ]]; then
            return 1
        fi
        rm -rf "$CONFIG_DIR"
    fi
    
    fix_github_host
    
    # Detect architecture
    if [[ $(uname) == "Linux" ]]; then
        ARCH=$(uname -m)
        echo -e "${YELLOW}[-] Architecture: $ARCH${NC}"
        
        # Try multiple download sources
        local download_success=false
        
        # Source 1: Musixal repo (primary)
        echo -e "${YELLOW}[-] Trying Musixal repository...${NC}"
        DOWNLOAD_URL='https://github.com/Musixal/rathole-tunnel/raw/main/core/rathole.zip'
        
        DOWNLOAD_DIR=$(mktemp -d)
        if curl -fsSL -o "$DOWNLOAD_DIR/rathole.zip" "$DOWNLOAD_URL"; then
            echo -e "${GREEN}[✓] Download successful${NC}"
            download_success=true
        else
            echo -e "${YELLOW}[!] Musixal download failed, trying official repo...${NC}"
            
            # Source 2: Official rathole repo
            case "$ARCH" in
                "x86_64") 
                    DOWNLOAD_URL="https://github.com/rathole-org/rathole/releases/download/v0.5.0/rathole-0.5.0-x86_64-unknown-linux-gnu.tar.gz"
                    ;;
                "aarch64"|"arm64")
                    DOWNLOAD_URL="https://github.com/rathole-org/rathole/releases/download/v0.5.0/rathole-0.5.0-aarch64-unknown-linux-gnu.tar.gz"
                    ;;
                "armv7l")
                    DOWNLOAD_URL="https://github.com/rathole-org/rathole/releases/download/v0.5.0/rathole-0.5.0-armv7-unknown-linux-gnu.tar.gz"
                    ;;
                *)
                    echo -e "${RED}[!] Unsupported architecture: $ARCH${NC}"
                    return 1
                    ;;
            esac
            
            if curl -fsSL -o "$DOWNLOAD_DIR/rathole.tar.gz" "$DOWNLOAD_URL"; then
                echo -e "${GREEN}[✓] Official download successful${NC}"
                tar -xzf "$DOWNLOAD_DIR/rathole.tar.gz" -C "$DOWNLOAD_DIR"
                # Find binary in extracted files
                find "$DOWNLOAD_DIR" -name "rathole" -type f -exec cp {} "$DOWNLOAD_DIR/rathole" \; 2>/dev/null || true
                download_success=true
            fi
        fi
        
        if [[ "$download_success" == true ]]; then
            echo -e "${YELLOW}[-] Extracting files...${NC}"
            
            if [[ -f "$DOWNLOAD_DIR/rathole.zip" ]]; then
                unzip -q "$DOWNLOAD_DIR/rathole.zip" -d "$CONFIG_DIR"
            elif [[ -f "$DOWNLOAD_DIR/rathole" ]]; then
                mkdir -p "$CONFIG_DIR"
                cp "$DOWNLOAD_DIR/rathole" "$CONFIG_DIR/"
            else
                # Find binary in extracted directory
                local BINARY=$(find "$DOWNLOAD_DIR" -name "rathole" -type f | head -1)
                if [[ -f "$BINARY" ]]; then
                    mkdir -p "$CONFIG_DIR"
                    cp "$BINARY" "$CONFIG_DIR/rathole"
                fi
            fi
            
            # Verify installation
            if [[ -f "$CONFIG_DIR/rathole" ]]; then
                chmod +x "$CONFIG_DIR/rathole"
                echo -e "${GREEN}[✓] Rathole installation completed.${NC}"
                
                # Test the binary
                if "$CONFIG_DIR/rathole" --version &>/dev/null; then
                    local version=$("$CONFIG_DIR/rathole" --version 2>/dev/null || echo "v0.5.0")
                    echo -e "${GREEN}[✓] Rathole version: $version${NC}"
                else
                    echo -e "${YELLOW}[!] Rathole binary works but version check failed${NC}"
                fi
            else
                echo -e "${RED}[ERROR] Rathole binary not found after extraction${NC}"
                return 1
            fi
        else
            echo -e "${RED}[ERROR] All download methods failed${NC}"
            return 1
        fi
        
        rm -rf "$DOWNLOAD_DIR"
    else
        echo -e "${RED}Unsupported operating system.${NC}"
        return 1
    fi
    
    return 0
}

# Display server info
display_server_info() {
    SERVER_IP=$(hostname -I | awk '{print $1}')
    SERVER_COUNTRY=$(curl --max-time 3 -sS "http://ip-api.com/json/$SERVER_IP" 2>/dev/null | jq -r '.country' || echo "Unknown")
    SERVER_ISP=$(curl --max-time 3 -sS "http://ip-api.com/json/$SERVER_IP" 2>/dev/null | jq -r '.isp' || echo "Unknown")
    
    echo -e "\e[93m═════════════════════════════════════════════\e[0m"  
    echo -e "${CYAN}Server Country:${NC} $SERVER_COUNTRY"
    echo -e "${CYAN}Server IP:${NC} $SERVER_IP"
    echo -e "${CYAN}Server ISP:${NC} $SERVER_ISP"
}

# Display Rathole Core status
display_rathole_core_status() {
    if [[ -d "$CONFIG_DIR" ]]; then
        echo -e "${CYAN}Rathole Core:${NC} ${GREEN}Installed${NC}"
    else
        echo -e "${CYAN}Rathole Core:${NC} ${RED}Not installed${NC}"
    fi
    echo -e "\e[93m═════════════════════════════════════════════\e[0m"
}

# Configure tunnel
configure_tunnel() {
    if [[ ! -d "$CONFIG_DIR" ]]; then
        echo -e "\n${RED}Rathole-core directory not found. Install it first through option 1.${NC}\n"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    clear
    echo -e "${YELLOW}Configuring RatHole Tunnel...${NC}"
    echo -e "\e[93m═════════════════════════════════════════════\e[0m" 
    echo ''
    echo -e "1. For ${GREEN}IRAN${NC} Server"
    echo -e "2. For ${CYAN}Foreign${NC} Server"
    echo ''
    read -p "Enter your choice: " configure_choice
    
    case "$configure_choice" in
        1) iran_server_configuration ;;
        2) foreign_server_configuration ;;
        *) echo -e "${RED}Invalid option!${NC}" && sleep 1 ;;
    esac
    
    echo ''
    read -p "Press Enter to continue..."
}

# Iran server configuration
iran_server_configuration() {
    clear
    echo -e "${YELLOW}Configuring IRAN server...${NC}\n" 
    
    # Tunnel port
    read -p "Enter the tunnel port [2333]: " tunnel_port
    tunnel_port=${tunnel_port:-2333}
    
    # Config ports
    echo ''
    read -p "Enter the number of services: " num_ports
    
    config_ports=()
    for ((i=1; i<=num_ports; i++)); do
        read -p "Enter Port $i: " port
        config_ports+=("$port")
    done
    
    echo ''
    
    # Transport type
    transport=""
    while [[ "$transport" != "tcp" && "$transport" != "udp" ]]; do
        read -p "Enter transport type (tcp/udp): " transport
        if [[ "$transport" != "tcp" && "$transport" != "udp" ]]; then
            echo -e "${RED}Invalid transport type. Please enter 'tcp' or 'udp'.${NC}"
        fi
    done
    
    echo ''
    
    # TCP No-Delay
    nodelay=""
    while [[ "$nodelay" != "true" && "$nodelay" != "false" ]]; do
        read -p "TCP No-Delay (true / false): " nodelay
        if [[ "$nodelay" != "true" && "$nodelay" != "false" ]]; then
            echo -e "${RED}Invalid nodelay input. Please enter 'true' or 'false'.${NC}"
        fi
    done
    
    echo ''
    
    # IPv6 Support
    local_ip='0.0.0.0'
    read -p "Do you want to use IPv6 for connecting? (yes/no): " answer
    echo ''
    if [[ "$answer" == "yes" ]]; then
        echo -e "${CYAN}IPv6 selected.${NC}"
        local_ip='[::]'
    else
        echo -e "${CYAN}IPv4 selected.${NC}"
    fi
    
    # Generate config file
    cat > "$CONFIG_DIR/server.toml" << EOF
[server]
bind_addr = "${local_ip}:${tunnel_port}"
default_token = "secure_token_$(openssl rand -hex 16)"
heartbeat_interval = 30

[server.transport]
type = "tcp"

[server.transport.tcp]
nodelay = $nodelay

EOF
    
    # Add services
    for port in "${config_ports[@]}"; do
        cat << EOF >> "$CONFIG_DIR/server.toml"
[server.services.service_${port}]
type = "$transport"
bind_addr = "${local_ip}:${port}"

EOF
    done
    
    echo ''
    echo -e "${GREEN}IRAN server configuration completed.${NC}\n"
    
    # Create systemd service
    create_iran_service
}

# Foreign server configuration
foreign_server_configuration() {
    clear
    echo -e "${YELLOW}Configuring Foreign server...${NC}\n"
    
    read -p "Enter Iran server IP address: " iran_ip
    read -p "Enter tunnel port [2333]: " tunnel_port
    tunnel_port=${tunnel_port:-2333}
    read -p "Enter token from Iran server: " token
    
    echo ''
    read -p "Enter the number of local services: " num_ports
    
    local_ports=()
    for ((i=1; i<=num_ports; i++)); do
        read -p "Enter Local Port $i: " port
        local_ports+=("$port")
    done
    
    # Generate config file
    cat > "$CONFIG_DIR/client.toml" << EOF
[client]
remote_addr = "${iran_ip}:${tunnel_port}"
default_token = "${token}"
retry_interval = 1

EOF
    
    # Add services
    for ((i=0; i<num_ports; i++)); do
        cat << EOF >> "$CONFIG_DIR/client.toml"
[client.services.service_$((i+1))]
type = "tcp"
local_addr = "127.0.0.1:${local_ports[$i]}"
nodelay = true

EOF
    done
    
    echo ''
    echo -e "${GREEN}Foreign server configuration completed.${NC}\n"
    
    # Create systemd service
    create_foreign_service
}

# Create Iran service
create_iran_service() {
    local service_name="rathole-iran"
    local service_file="$SERVICE_DIR/${service_name}.service"
    
    cat > "$service_file" << EOF
[Unit]
Description=Rathole Iran Server
After=network.target

[Service]
Type=simple
ExecStart=$CONFIG_DIR/rathole $CONFIG_DIR/server.toml
Restart=always
RestartSec=3
User=root
StandardOutput=append:$LOG_DIR/rathole-iran.log
StandardError=append:$LOG_DIR/rathole-iran-error.log

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable "$service_name" >/dev/null 2>&1
    systemctl start "$service_name"
    
    echo -e "${GREEN}Iran server service started and enabled!${NC}"
    echo -e "${YELLOW}Check status: systemctl status $service_name${NC}"
}

# Create Foreign service
create_foreign_service() {
    local service_name="rathole-foreign"
    local service_file="$SERVICE_DIR/${service_name}.service"
    
    cat > "$service_file" << EOF
[Unit]
Description=Rathole Foreign Client
After=network.target

[Service]
Type=simple
ExecStart=$CONFIG_DIR/rathole $CONFIG_DIR/client.toml
Restart=always
RestartSec=3
User=root
StandardOutput=append:$LOG_DIR/rathole-foreign.log
StandardError=append:$LOG_DIR/rathole-foreign-error.log

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable "$service_name" >/dev/null 2>&1
    systemctl start "$service_name"
    
    echo -e "${GREEN}Foreign server service started and enabled!${NC}"
    echo -e "${YELLOW}Check status: systemctl status $service_name${NC}"
}

# Show status
show_status() {
    clear
    display_logo
    display_server_info
    display_rathole_core_status
    
    echo -e "${YELLOW}Service Status:${NC}"
    
    # Check Iran service
    if systemctl is-active --quiet rathole-iran 2>/dev/null; then
        echo -e "  rathole-iran: ${GREEN}ACTIVE${NC}"
    elif systemctl is-enabled --quiet rathole-iran 2>/dev/null; then
        echo -e "  rathole-iran: ${YELLOW}ENABLED (not running)${NC}"
    fi
    
    # Check Foreign service
    if systemctl is-active --quiet rathole-foreign 2>/dev/null; then
        echo -e "  rathole-foreign: ${GREEN}ACTIVE${NC}"
    elif systemctl is-enabled --quiet rathole-foreign 2>/dev/null; then
        echo -e "  rathole-foreign: ${YELLOW}ENABLED (not running)${NC}"
    fi
    
    echo ''
    read -p "Press Enter to continue..."
}

# Remove Rathole
remove_rathole() {
    echo -e "${RED}[!] WARNING: This will remove Rathole completely${NC}"
    read -p "Are you sure? (y/n): " confirm
    
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        # Stop services
        systemctl stop rathole-iran 2>/dev/null || true
        systemctl stop rathole-foreign 2>/dev/null || true
        
        # Disable services
        systemctl disable rathole-iran 2>/dev/null || true
        systemctl disable rathole-foreign 2>/dev/null || true
        
        # Remove files
        rm -rf "$CONFIG_DIR"
        rm -f "$SERVICE_DIR/rathole-iran.service"
        rm -f "$SERVICE_DIR/rathole-foreign.service"
        
        # Reload systemd
        systemctl daemon-reload
        
        echo -e "${GREEN}[✓] Rathole completely removed${NC}"
    else
        echo -e "${YELLOW}Operation cancelled${NC}"
    fi
    
    echo ''
    read -p "Press Enter to continue..."
}

# Main menu
main_menu() {
    while true; do
        clear
        display_logo
        display_server_info
        display_rathole_core_status
        
        echo -e "${CYAN}Main Menu:${NC}"
        echo -e "1. ${GREEN}Install/Update Rathole Core${NC}"
        echo -e "2. ${YELLOW}Configure Tunnel${NC}"
        echo -e "3. ${BLUE}Show Service Status${NC}"
        echo -e "4. ${RED}Remove Rathole Completely${NC}"
        echo -e "5. ${CYAN}Exit${NC}"
        echo ''
        
        read -p "Enter your choice [1-5]: " choice
        
        case $choice in
            1)
                fix_apt_locks
                install_unzip
                install_jq
                install_iptables
                install_bc
                download_and_extract_rathole
                ;;
            2)
                configure_tunnel
                ;;
            3)
                show_status
                ;;
            4)
                remove_rathole
                ;;
            5)
                echo -e "${GREEN}Goodbye!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option!${NC}"
                sleep 1
                ;;
        esac
    done
}

# Create log directory
mkdir -p "$LOG_DIR"

# Start program
check_root
main_menu
