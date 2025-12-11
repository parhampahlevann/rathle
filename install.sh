#!/bin/bash

# ============================================
# Rathole Tunnel Manager
# Version: 2.0
# Support: IPv4 + IPv6, TCP + UDP
# Author: Rathole Tunnel Manager
# ============================================

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Variables
RATHOLE_VERSION="0.5.0"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/rathole"
SERVICE_DIR="/etc/systemd/system"
LOG_DIR="/var/log/rathole"
TUNNEL_NAME="rathole-tunnel"
LOCAL_IP="127.0.0.1"
LOCAL_PORT="2333"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root!${NC}"
   exit 1
fi

# Function to check dependencies
check_dependencies() {
    echo -e "${BLUE}Checking dependencies...${NC}"
    
    local missing_deps=()
    
    # Check for wget
    if ! command -v wget &> /dev/null; then
        echo -e "${YELLOW}Installing wget...${NC}"
        apt-get update && apt-get install -y wget
    fi
    
    # Check for netcat
    if ! command -v nc &> /dev/null; then
        echo -e "${YELLOW}Installing netcat...${NC}"
        apt-get install -y netcat
    fi
    
    # Check for openssl
    if ! command -v openssl &> /dev/null; then
        echo -e "${YELLOW}Installing openssl...${NC}"
        apt-get install -y openssl
    fi
    
    # Check for tar
    if ! command -v tar &> /dev/null; then
        echo -e "${YELLOW}Installing tar...${NC}"
        apt-get install -y tar
    fi
    
    echo -e "${GREEN}All dependencies are satisfied.${NC}"
}

# Function to display menu
show_menu() {
    clear
    echo -e "${BLUE}===========================================${NC}"
    echo -e "${GREEN}    Rathole Tunnel Manager v2.0${NC}"
    echo -e "${BLUE}===========================================${NC}"
    echo -e "1. Install Rathole Core"
    echo -e "2. Create Rathole Tunnel"
    echo -e "3. Show Tunnel Status and Ping Test"
    echo -e "4. Remove Rathole Core"
    echo -e "5. Remove Tunnel"
    echo -e "6. Exit"
    echo -e "${BLUE}===========================================${NC}"
}

# Function to install rathole
install_rathole() {
    echo -e "${GREEN}Installing Rathole Core...${NC}"
    
    # Check dependencies first
    check_dependencies
    
    # Detect architecture
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        armv7l|armhf)
            ARCH="armv7"
            ;;
        *)
            echo -e "${RED}Architecture $ARCH is not supported!${NC}"
            exit 1
            ;;
    esac
    
    # Download rathole
    echo -e "${YELLOW}Downloading Rathole version $RATHOLE_VERSION...${NC}"
    wget -q "https://github.com/rathole-org/rathole/releases/download/v${RATHOLE_VERSION}/rathole-${RATHOLE_VERSION}-${ARCH}-unknown-linux-gnu.tar.gz" -O /tmp/rathole.tar.gz
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}Error downloading Rathole!${NC}"
        echo -e "${YELLOW}Trying alternative download method...${NC}"
        
        # Try alternative URL
        wget -q "https://github.com/rathole-org/rathole/releases/download/v${RATHOLE_VERSION}/rathole-x86_64-unknown-linux-gnu.tar.gz" -O /tmp/rathole.tar.gz
        
        if [ $? -ne 0 ]; then
            echo -e "${RED}Failed to download Rathole. Please check your internet connection.${NC}"
            exit 1
        fi
    fi
    
    # Extract and install
    echo -e "${YELLOW}Extracting files...${NC}"
    tar -xzf /tmp/rathole.tar.gz -C /tmp 2>/dev/null
    
    # Find rathole binary in extracted files
    RATHOLE_BINARY=$(find /tmp -name "rathole" -type f | head -1)
    
    if [ -z "$RATHOLE_BINARY" ]; then
        echo -e "${RED}Rathole binary not found in downloaded archive!${NC}"
        exit 1
    fi
    
    # Install binary
    cp "$RATHOLE_BINARY" $INSTALL_DIR/
    chmod +x $INSTALL_DIR/rathole
    
    # Create directories
    mkdir -p $CONFIG_DIR
    mkdir -p $LOG_DIR
    mkdir -p $CONFIG_DIR/tunnels
    
    # Create default config
    cat > $CONFIG_DIR/config.toml << EOF
# Default Rathole configuration
# This file can be customized as needed
EOF
    
    # Create systemd service file
    cat > $SERVICE_DIR/rathole.service << EOF
[Unit]
Description=Rathole Tunnel Service
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/rathole $CONFIG_DIR/config.toml
Restart=always
RestartSec=3
User=root
StandardOutput=append:$LOG_DIR/rathole.log
StandardError=append:$LOG_DIR/rathole-error.log

[Install]
WantedBy=multi-user.target
EOF
    
    # Create tunnel service file
    cat > $SERVICE_DIR/${TUNNEL_NAME}.service << EOF
[Unit]
Description=Rathole Tunnel Instance
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/rathole $CONFIG_DIR/tunnels/current.toml
Restart=always
RestartSec=3
User=root
StandardOutput=append:$LOG_DIR/tunnel.log
StandardError=append:$LOG_DIR/tunnel-error.log

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    
    # Cleanup
    rm -rf /tmp/rathole* /tmp/rathole-*
    
    echo -e "${GREEN}Rathole Core installed successfully!${NC}"
    echo -e "${YELLOW}Binary location: $INSTALL_DIR/rathole${NC}"
    echo -e "${YELLOW}Configuration directory: $CONFIG_DIR${NC}"
    echo -e "${YELLOW}Log directory: $LOG_DIR${NC}"
    
    # Test the installation
    echo -e "${BLUE}Testing installation...${NC}"
    if $INSTALL_DIR/rathole --version &> /dev/null; then
        echo -e "${GREEN}Rathole is working correctly.${NC}"
    else
        echo -e "${YELLOW}Rathole version check failed, but installation completed.${NC}"
    fi
}

# Function to create tunnel
create_tunnel() {
    echo -e "${GREEN}Creating Rathole Tunnel...${NC}"
    
    # Check if rathole is installed
    if [ ! -f "$INSTALL_DIR/rathole" ]; then
        echo -e "${RED}Rathole is not installed! Please install it first.${NC}"
        return 1
    fi
    
    # Ask for server location
    echo -e "${YELLOW}Where is this server located?${NC}"
    echo "1. Iran"
    echo "2. Outside Iran (Foreign)"
    read -p "Select (1 or 2): " location
    
    if [ "$location" = "1" ]; then
        # Iran server (client)
        echo -e "${BLUE}Configuring Iran Server (Client Mode)${NC}"
        read -p "Foreign server IPv4 address: " foreign_ip
        
        # Validate IP address
        if ! [[ $foreign_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo -e "${RED}Invalid IP address format!${NC}"
            return 1
        fi
        
        read -p "Foreign server port (default: 2333): " foreign_port
        foreign_port=${foreign_port:-2333}
        
        # Generate encryption key
        echo -e "${YELLOW}Generating encryption key...${NC}"
        encryption_key=$(openssl rand -hex 32)
        
        # Create server config (for foreign server)
        cat > /tmp/server_config.toml << EOF
[server]
bind_addr = "[::]:$foreign_port"
default_token = "$encryption_key"

[server.services.tunnel1]
bind_addr = "0.0.0.0:$foreign_port"
bind_addr_v6 = "[::]:$foreign_port"
type = "tcp+udp"
nodelay = true
EOF
        
        # Create client config (for Iran server)
        cat > /tmp/client_config.toml << EOF
[client]
remote_addr = "$foreign_ip:$foreign_port"
default_token = "$encryption_key"
retry_interval = 1

[client.services.tunnel1]
local_addr = "$LOCAL_IP:$LOCAL_PORT"
local_addr_v6 = "[::1]:$LOCAL_PORT"
type = "tcp+udp"
nodelay = true
EOF
        
        echo -e "${GREEN}Configuration files created successfully!${NC}"
        echo -e "${YELLOW}===============================================${NC}"
        echo -e "${GREEN}FOR FOREIGN SERVER (server_config.toml):${NC}"
        echo -e "${YELLOW}===============================================${NC}"
        cat /tmp/server_config.toml
        echo -e "${YELLOW}===============================================${NC}"
        echo -e "\n${GREEN}FOR THIS SERVER (IRAN - client_config.toml):${NC}"
        echo -e "${YELLOW}===============================================${NC}"
        cat /tmp/client_config.toml
        echo -e "${YELLOW}===============================================${NC}"
        echo -e "\n${GREEN}Encryption Key: $encryption_key${NC}"
        
        # Copy config to local
        cp /tmp/client_config.toml $CONFIG_DIR/tunnels/current.toml
        
        echo -e "\n${BLUE}Instructions:${NC}"
        echo "1. Copy server_config.toml to your foreign server"
        echo "2. On foreign server, run: rathole server_config.toml"
        echo "3. This server (Iran) will connect as client"
        
    elif [ "$location" = "2" ]; then
        # Foreign server (client)
        echo -e "${BLUE}Configuring Foreign Server (Client Mode)${NC}"
        read -p "Iran server IPv4 address: " iran_ip
        
        # Validate IP address
        if ! [[ $iran_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo -e "${RED}Invalid IP address format!${NC}"
            return 1
        fi
        
        read -p "Iran server port (default: 2333): " iran_port
        iran_port=${iran_port:-2333}
        
        # Generate encryption key
        echo -e "${YELLOW}Generating encryption key...${NC}"
        encryption_key=$(openssl rand -hex 32)
        
        # Create server config (for Iran server)
        cat > /tmp/server_config.toml << EOF
[server]
bind_addr = "[::]:$iran_port"
default_token = "$encryption_key"

[server.services.tunnel1]
bind_addr = "0.0.0.0:$iran_port"
bind_addr_v6 = "[::]:$iran_port"
type = "tcp+udp"
nodelay = true
EOF
        
        # Create client config (for foreign server)
        cat > /tmp/client_config.toml << EOF
[client]
remote_addr = "$iran_ip:$iran_port"
default_token = "$encryption_key"
retry_interval = 1

[client.services.tunnel1]
local_addr = "$LOCAL_IP:$LOCAL_PORT"
local_addr_v6 = "[::1]:$LOCAL_PORT"
type = "tcp+udp"
nodelay = true
EOF
        
        echo -e "${GREEN}Configuration files created successfully!${NC}"
        echo -e "${YELLOW}===============================================${NC}"
        echo -e "${GREEN}FOR IRAN SERVER (server_config.toml):${NC}"
        echo -e "${YELLOW}===============================================${NC}"
        cat /tmp/server_config.toml
        echo -e "${YELLOW}===============================================${NC}"
        echo -e "\n${GREEN}FOR THIS SERVER (FOREIGN - client_config.toml):${NC}"
        echo -e "${YELLOW}===============================================${NC}"
        cat /tmp/client_config.toml
        echo -e "${YELLOW}===============================================${NC}"
        echo -e "\n${GREEN}Encryption Key: $encryption_key${NC}"
        
        # Copy config to local
        cp /tmp/client_config.toml $CONFIG_DIR/tunnels/current.toml
        
        echo -e "\n${BLUE}Instructions:${NC}"
        echo "1. Copy server_config.toml to your Iran server"
        echo "2. On Iran server, run: rathole server_config.toml"
        echo "3. This server (Foreign) will connect as client"
    else
        echo -e "${RED}Invalid selection!${NC}"
        return 1
    fi
    
    # Start tunnel service
    systemctl daemon-reload
    systemctl start ${TUNNEL_NAME}.service
    systemctl enable ${TUNNEL_NAME}.service
    
    # Wait a moment for service to start
    sleep 2
    
    # Check if service is running
    if systemctl is-active --quiet ${TUNNEL_NAME}.service; then
        echo -e "${GREEN}Tunnel service started successfully!${NC}"
    else
        echo -e "${YELLOW}Tunnel service started but may not be active yet.${NC}"
        echo -e "${YELLOW}Check status with: systemctl status ${TUNNEL_NAME}.service${NC}"
    fi
    
    echo -e "\n${GREEN}Tunnel created successfully!${NC}"
    echo -e "${YELLOW}Local address for testing: $LOCAL_IP:$LOCAL_PORT${NC}"
    echo -e "${YELLOW}Use option 3 to test the tunnel connection${NC}"
}

# Function to show tunnel status
show_status() {
    echo -e "${GREEN}Rathole Tunnel Status:${NC}"
    echo "=================================="
    
    # Check if rathole is installed
    if [ ! -f "$INSTALL_DIR/rathole" ]; then
        echo -e "${RED}Rathole is not installed!${NC}"
        return 1
    fi
    
    # Show rathole version
    echo -e "${BLUE}Rathole Version:${NC}"
    $INSTALL_DIR/rathole --version 2>/dev/null || echo "Version check failed"
    
    echo "=================================="
    
    # Check if tunnel service exists and is running
    if systemctl list-unit-files | grep -q "${TUNNEL_NAME}.service"; then
        if systemctl is-active --quiet ${TUNNEL_NAME}.service; then
            echo -e "Tunnel Service: ${GREEN}ACTIVE${NC}"
        else
            echo -e "Tunnel Service: ${RED}INACTIVE${NC}"
        fi
        
        # Show service status
        echo -e "\n${BLUE}Tunnel Service Status:${NC}"
        systemctl status ${TUNNEL_NAME}.service --no-pager -l | head -20
    else
        echo -e "Tunnel Service: ${YELLOW}NOT CONFIGURED${NC}"
    fi
    
    # Check if rathole service exists and is running
    if systemctl list-unit-files | grep -q "rathole.service"; then
        if systemctl is-active --quiet rathole.service; then
            echo -e "\nRathole Service: ${GREEN}ACTIVE${NC}"
        else
            echo -e "\nRathole Service: ${RED}INACTIVE${NC}"
        fi
    fi
    
    # Show logs
    echo -e "\n${BLUE}Recent Tunnel Logs:${NC}"
    if [ -f "$LOG_DIR/tunnel.log" ]; then
        tail -10 $LOG_DIR/tunnel.log
    else
        echo "No tunnel logs found"
    fi
    
    echo -e "\n${BLUE}Recent Rathole Logs:${NC}"
    if [ -f "$LOG_DIR/rathole.log" ]; then
        tail -10 $LOG_DIR/rathole.log
    else
        echo "No rathole logs found"
    fi
    
    # Ping test to localhost
    echo -e "\n${BLUE}Ping Test to Localhost:${NC}"
    if ping -c 2 -W 1 $LOCAL_IP &> /dev/null; then
        echo -e "Ping to $LOCAL_IP: ${GREEN}SUCCESS${NC}"
    else
        echo -e "Ping to $LOCAL_IP: ${RED}FAILED${NC}"
    fi
    
    # Test local port
    echo -e "\n${BLUE}Local Port Test ($LOCAL_PORT):${NC}"
    if timeout 2 bash -c "cat < /dev/null > /dev/tcp/$LOCAL_IP/$LOCAL_PORT" 2>/dev/null; then
        echo -e "Port $LOCAL_PORT: ${GREEN}OPEN${NC}"
    else
        echo -e "Port $LOCAL_PORT: ${RED}CLOSED${NC}"
    fi
    
    # Show network connections
    echo -e "\n${BLUE}Active Network Connections:${NC}"
    ss -tunlp | grep -E "(rathole|$LOCAL_PORT)" | head -10 || echo "No rathole connections found"
    
    # Show configuration file
    echo -e "\n${BLUE}Current Tunnel Configuration:${NC}"
    if [ -f "$CONFIG_DIR/tunnels/current.toml" ]; then
        cat $CONFIG_DIR/tunnels/current.toml
    else
        echo "No tunnel configuration found"
    fi
}

# Function to remove rathole core
remove_rathole() {
    echo -e "${RED}WARNING: Are you sure you want to remove Rathole Core?${NC}"
    echo "This will remove all tunnels and configurations!"
    read -p "Confirm (y/n): " confirm
    
    if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
        # Stop services
        systemctl stop ${TUNNEL_NAME}.service 2>/dev/null
        systemctl stop rathole.service 2>/dev/null
        systemctl disable ${TUNNEL_NAME}.service 2>/dev/null
        systemctl disable rathole.service 2>/dev/null
        
        # Remove files
        rm -f $INSTALL_DIR/rathole
        rm -rf $CONFIG_DIR
        rm -f $SERVICE_DIR/rathole.service
        rm -f $SERVICE_DIR/${TUNNEL_NAME}.service
        rm -rf $LOG_DIR
        
        systemctl daemon-reload
        
        echo -e "${GREEN}Rathole Core removed successfully!${NC}"
    else
        echo -e "${YELLOW}Operation cancelled.${NC}"
    fi
}

# Function to remove tunnel
remove_tunnel() {
    echo -e "${YELLOW}Removing tunnel...${NC}"
    
    # Stop and disable tunnel service
    systemctl stop ${TUNNEL_NAME}.service 2>/dev/null
    systemctl disable ${TUNNEL_NAME}.service 2>/dev/null
    
    # Remove configuration
    rm -f $CONFIG_DIR/tunnels/current.toml 2>/dev/null
    
    # Reload systemd
    systemctl daemon-reload
    
    echo -e "${GREEN}Tunnel removed successfully!${NC}"
}

# Function to test the script
test_installation() {
    echo -e "${BLUE}Running self-test...${NC}"
    
    # Test 1: Check if running as root
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}FAIL: Script is not running as root${NC}"
        return 1
    else
        echo -e "${GREEN}PASS: Running as root${NC}"
    fi
    
    # Test 2: Check dependencies
    for cmd in wget tar openssl; do
        if command -v $cmd &> /dev/null; then
            echo -e "${GREEN}PASS: $cmd is installed${NC}"
        else
            echo -e "${YELLOW}WARN: $cmd is not installed${NC}"
        fi
    done
    
    # Test 3: Check directories
    for dir in $INSTALL_DIR $CONFIG_DIR $LOG_DIR; do
        if [ -d "$dir" ]; then
            echo -e "${GREEN}PASS: Directory $dir exists${NC}"
        else
            echo -e "${YELLOW}INFO: Directory $dir doesn't exist (will be created)${NC}"
        fi
    done
    
    echo -e "${GREEN}Self-test completed!${NC}"
}

# Main menu loop
while true; do
    show_menu
    read -p "Please select an option (1-6): " choice
    
    case $choice in
        1)
            install_rathole
            ;;
        2)
            create_tunnel
            ;;
        3)
            show_status
            ;;
        4)
            remove_rathole
            ;;
        5)
            remove_tunnel
            ;;
        6)
            echo -e "${BLUE}Exiting...${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid selection! Please enter a number between 1 and 6.${NC}"
            ;;
    esac
    
    echo ""
    echo -e "${YELLOW}Press Enter to continue...${NC}"
    read -p ""
done
