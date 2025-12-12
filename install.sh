#!/bin/bash
# ============================================
# Rathole Tunnel Manager - Enhanced Version
# Based on Musixal/rathole-tunnel with fixes
# Version: 6.1
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
    echo -e "Version: ${YELLOW}v6.1${GREEN}"
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
    for lock in /var/lib/apt/lists/lock /var/lib/dpkg/lock /var/lib/dpkg/lock-frontend /var/cache/apt/archives/lock; do
        if [[ -f $lock ]]; then
            echo -e "${YELLOW}[-] Removing lock: $lock${NC}"
            rm -f $lock 2>/dev/null || true
        fi
    done
    # Kill any apt processes
    pkill -9 apt-get 2>/dev/null || true
    pkill -9 apt 2>/dev/null || true
    sleep 2
}

# Install dependencies
install_dependencies() {
    echo -e "${YELLOW}[*] Installing dependencies...${NC}"
    
    # Update package list
    apt-get update -y
    
    # Install required packages
    local packages="unzip jq iptables bc curl wget tar"
    
    for pkg in $packages; do
        if ! command -v "$pkg" &> /dev/null; then
            echo -e "${YELLOW}[-] Installing $pkg...${NC}"
            apt-get install -y "$pkg" 2>/dev/null || {
                echo -e "${RED}[ERROR] Failed to install $pkg${NC}"
                return 1
            }
        fi
    done
    
    echo -e "${GREEN}[✓] Dependencies installed${NC}"
    return 0
}

# Fix GitHub host entry
fix_github_host() {
    echo -e "${YELLOW}[*] Updating GitHub DNS entries...${NC}"
    
    # Multiple IPs for GitHub
    local entries=(
        "185.199.108.133 raw.githubusercontent.com"
        "185.199.109.133 raw.githubusercontent.com"
        "185.199.110.133 raw.githubusercontent.com"
        "185.199.111.133 raw.githubusercontent.com"
        "140.82.113.3 github.com"
        "140.82.114.3 github.com"
    )
    
    # Remove old entries
    sed -i '/raw.githubusercontent.com/d' /etc/hosts
    sed -i '/github.com/d' /etc/hosts
    
    # Add new entries
    for entry in "${entries[@]}"; do
        if ! grep -q "$entry" /etc/hosts; then
            echo "$entry" >> /etc/hosts
        fi
    done
    
    # Test connectivity
    if timeout 10 curl -s https://raw.githubusercontent.com > /dev/null; then
        echo -e "${GREEN}[✓] GitHub connectivity OK${NC}"
        return 0
    else
        echo -e "${YELLOW}[!] GitHub connectivity issues, using mirror...${NC}"
        return 1
    fi
}

# Download rathole binary from official releases
download_rathole_official() {
    local download_dir=$1
    local arch=$2
    
    echo -e "${YELLOW}[*] Downloading from official repository...${NC}"
    
    # Determine download URL based on architecture
    local url=""
    case "$arch" in
        "x86_64") 
            url="https://github.com/rapiz1/rathole/releases/download/v0.5.0/rathole-x86_64-unknown-linux-gnu.tar.gz"
            ;;
        "aarch64"|"arm64")
            url="https://github.com/rapiz1/rathole/releases/download/v0.5.0/rathole-aarch64-unknown-linux-gnu.tar.gz"
            ;;
        "armv7l")
            url="https://github.com/rapiz1/rathole/releases/download/v0.5.0/rathole-armv7-unknown-linux-gnu.tar.gz"
            ;;
        "i386"|"i686")
            url="https://github.com/rapiz1/rathole/releases/download/v0.5.0/rathole-i686-unknown-linux-gnu.tar.gz"
            ;;
        *)
            echo -e "${RED}[!] Unsupported architecture: $arch${NC}"
            return 1
            ;;
    esac
    
    echo -e "${YELLOW}[-] Download URL: $url${NC}"
    
    # Download with retry
    for i in {1..3}; do
        echo -e "${YELLOW}[-] Attempt $i/3...${NC}"
        if curl -L -s -o "$download_dir/rathole.tar.gz" "$url"; then
            echo -e "${GREEN}[✓] Download successful${NC}"
            return 0
        fi
        sleep 2
    done
    
    echo -e "${RED}[ERROR] Failed to download from official repo${NC}"
    return 1
}

# Download from Musixal repository (alternative)
download_rathole_musixal() {
    local download_dir=$1
    
    echo -e "${YELLOW}[*] Trying Musixal repository...${NC}"
    
    # Direct link to binary
    local url="https://raw.githubusercontent.com/Musixal/rathole-tunnel/main/core/rathole-linux-amd64"
    
    for i in {1..3}; do
        echo -e "${YELLOW}[-] Attempt $i/3...${NC}"
        if curl -L -s -o "$download_dir/rathole" "$url"; then
            if [[ -s "$download_dir/rathole" ]]; then
                echo -e "${GREEN}[✓] Download successful${NC}"
                chmod +x "$download_dir/rathole"
                return 0
            fi
        fi
        sleep 2
    done
    
    echo -e "${RED}[ERROR] Failed to download from Musixal repo${NC}"
    return 1
}

# Download and extract Rathole - IMPROVED VERSION
download_and_extract_rathole() {
    echo -e "${GREEN}[*] Installing Rathole Core...${NC}"
    
    if [[ -d "$CONFIG_DIR" ]]; then
        echo -e "${YELLOW}Rathole Core is already installed.${NC}"
        read -p "Reinstall? (y/n): " reinstall
        if [[ ! "$reinstall" =~ ^[Yy]$ ]]; then
            return 0
        fi
        rm -rf "$CONFIG_DIR"
    fi
    
    # Fix GitHub connectivity
    fix_github_host
    
    # Detect architecture
    ARCH=$(uname -m)
    echo -e "${YELLOW}[-] Detected architecture: $ARCH${NC}"
    
    # Create temporary directory
    DOWNLOAD_DIR=$(mktemp -d)
    trap "rm -rf '$DOWNLOAD_DIR'" EXIT
    
    # Try multiple download methods
    local download_success=false
    
    # Method 1: Official repository (primary)
    if download_rathole_official "$DOWNLOAD_DIR" "$ARCH"; then
        echo -e "${YELLOW}[-] Extracting files...${NC}"
        
        # Extract tar.gz
        if tar -xzf "$DOWNLOAD_DIR/rathole.tar.gz" -C "$DOWNLOAD_DIR" 2>/dev/null; then
            # Find binary in extracted files
            local BINARY=$(find "$DOWNLOAD_DIR" -name "rathole" -type f 2>/dev/null | head -1)
            if [[ -f "$BINARY" ]]; then
                mkdir -p "$CONFIG_DIR"
                cp "$BINARY" "$CONFIG_DIR/rathole"
                download_success=true
            fi
        fi
    fi
    
    # Method 2: Musixal repository (fallback)
    if [[ "$download_success" == false ]] && [[ "$ARCH" == "x86_64" ]]; then
        if download_rathole_musixal "$DOWNLOAD_DIR"; then
            mkdir -p "$CONFIG_DIR"
            cp "$DOWNLOAD_DIR/rathole" "$CONFIG_DIR/rathole"
            download_success=true
        fi
    fi
    
    # Method 3: Direct download from release assets
    if [[ "$download_success" == false ]]; then
        echo -e "${YELLOW}[*] Trying direct download...${NC}"
        
        # Alternative URL
        local alt_url=""
        if [[ "$ARCH" == "x86_64" ]]; then
            alt_url="https://github.com/rapiz1/rathole/releases/download/v0.5.0/rathole-x86_64-unknown-linux-gnu"
        elif [[ "$ARCH" == "aarch64" ]]; then
            alt_url="https://github.com/rapiz1/rathole/releases/download/v0.5.0/rathole-aarch64-unknown-linux-gnu"
        fi
        
        if [[ -n "$alt_url" ]]; then
            if curl -L -s -o "$CONFIG_DIR/rathole" "$alt_url"; then
                download_success=true
            fi
        fi
    fi
    
    # Verify installation
    if [[ "$download_success" == true ]]; then
        # Make binary executable
        chmod +x "$CONFIG_DIR/rathole" 2>/dev/null
        
        # Test the binary
        if [[ -f "$CONFIG_DIR/rathole" ]] && "$CONFIG_DIR/rathole" --help &>/dev/null; then
            local version=$("$CONFIG_DIR/rathole" --version 2>&1 | head -1 | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+' || echo "0.5.0")
            echo -e "${GREEN}[✓] Rathole installed successfully${NC}"
            echo -e "${GREEN}[✓] Version: $version${NC}"
            
            # Create sample configs
            create_sample_configs
            
            return 0
        else
            echo -e "${RED}[ERROR] Rathole binary is corrupted or incompatible${NC}"
            
            # Try to fix permissions
            chmod 755 "$CONFIG_DIR/rathole"
            
            # Check if it's a valid ELF binary
            if file "$CONFIG_DIR/rathole" | grep -q "ELF"; then
                echo -e "${YELLOW}[!] Binary is ELF format, trying to fix...${NC}"
                
                # Check dependencies
                if ldd "$CONFIG_DIR/rathole" 2>&1 | grep -q "not found"; then
                    echo -e "${YELLOW}[!] Missing libraries, installing glibc...${NC}"
                    apt-get install -y libc6 2>/dev/null || true
                fi
                
                # Test again
                if "$CONFIG_DIR/rathole" --help &>/dev/null; then
                    echo -e "${GREEN}[✓] Fixed! Rathole is now working${NC}"
                    return 0
                fi
            fi
            
            return 1
        fi
    else
        echo -e "${RED}[ERROR] Failed to download Rathole${NC}"
        echo -e "${YELLOW}[!] You can manually download rathole:${NC}"
        echo -e "${CYAN}1. Visit: https://github.com/rapiz1/rathole/releases${NC}"
        echo -e "${CYAN}2. Download the binary for your architecture${NC}"
        echo -e "${CYAN}3. Place it at: $CONFIG_DIR/rathole${NC}"
        echo -e "${CYAN}4. Run: chmod +x $CONFIG_DIR/rathole${NC}"
        
        # Create directory anyway for manual installation
        mkdir -p "$CONFIG_DIR"
        
        return 1
    fi
}

# Create sample configs
create_sample_configs() {
    echo -e "${YELLOW}[*] Creating sample configurations...${NC}"
    
    # Create sample server config
    cat > "$CONFIG_DIR/server.example.toml" << 'EOF'
[server]
bind_addr = "0.0.0.0:2333"
default_token = "your_secure_token_here"
heartbeat_timeout = 30

[server.transport]
type = "tcp"
keepalive_secs = 7200
keepalive_interval = 15

[server.transport.tcp]
nodelay = true

[server.services.my_service]
type = "tcp"
bind_addr = "0.0.0.0:8080"
EOF

    # Create sample client config
    cat > "$CONFIG_DIR/client.example.toml" << 'EOF'
[client]
remote_addr = "SERVER_IP:2333"
default_token = "your_secure_token_here"
retry_interval = 1

[client.transport]
type = "tcp"

[client.transport.tcp]
keepalive_secs = 7200
keepalive_interval = 15
nodelay = true

[client.services.my_service]
type = "tcp"
local_addr = "127.0.0.1:80"
EOF

    echo -e "${GREEN}[✓] Sample configurations created${NC}"
}

# Display server info
display_server_info() {
    echo -e "\n${YELLOW}═════════════════════════════════════════════${NC}"  
    
    # Get server IP
    SERVER_IP=$(hostname -I | awk '{print $1}' 2>/dev/null || echo "127.0.0.1")
    
    # Try to get country info with timeout
    COUNTRY_INFO=$(timeout 3 curl -sS "http://ip-api.com/line/?fields=country,isp" 2>/dev/null || true)
    
    if [[ -n "$COUNTRY_INFO" ]]; then
        SERVER_COUNTRY=$(echo "$COUNTRY_INFO" | sed -n '1p')
        SERVER_ISP=$(echo "$COUNTRY_INFO" | sed -n '2p')
    else
        SERVER_COUNTRY="Unknown"
        SERVER_ISP="Unknown"
    fi
    
    echo -e "${CYAN}Server Country:${NC} $SERVER_COUNTRY"
    echo -e "${CYAN}Server IP:${NC} $SERVER_IP"
    echo -e "${CYAN}Server ISP:${NC} $SERVER_ISP"
}

# Display Rathole Core status
display_rathole_core_status() {
    echo -e "${YELLOW}═════════════════════════════════════════════${NC}\n"
    
    if [[ -f "$CONFIG_DIR/rathole" ]]; then
        echo -e "${CYAN}Rathole Core:${NC} ${GREEN}Installed${NC}"
        
        # Show version if possible
        if "$CONFIG_DIR/rathole" --version &>/dev/null; then
            local version=$("$CONFIG_DIR/rathole" --version 2>&1 | head -1)
            echo -e "${CYAN}Version:${NC} $version"
        fi
        
        # Check if binary is executable
        if [[ -x "$CONFIG_DIR/rathole" ]]; then
            echo -e "${CYAN}Status:${NC} ${GREEN}Executable${NC}"
        else
            echo -e "${CYAN}Status:${NC} ${RED}Not executable${NC}"
            echo -e "${YELLOW}[!] Run: chmod +x $CONFIG_DIR/rathole${NC}"
        fi
    else
        echo -e "${CYAN}Rathole Core:${NC} ${RED}Not installed${NC}"
    fi
}

# Configure tunnel
configure_tunnel() {
    if [[ ! -f "$CONFIG_DIR/rathole" ]]; then
        echo -e "\n${RED}Rathole binary not found. Install it first through option 1.${NC}\n"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    clear
    echo -e "${YELLOW}Configuring RatHole Tunnel...${NC}"
    echo -e "${YELLOW}═════════════════════════════════════════════${NC}\n"
    
    echo -e "1. For ${GREEN}IRAN${NC} Server (Client connects to you)"
    echo -e "2. For ${CYAN}FOREIGN${NC} Server (You connect to Iran server)"
    echo -e "3. ${YELLOW}View current configuration${NC}"
    echo ''
    
    read -p "Enter your choice [1-3]: " configure_choice
    
    case "$configure_choice" in
        1) iran_server_configuration ;;
        2) foreign_server_configuration ;;
        3) view_current_config ;;
        *) echo -e "${RED}Invalid option!${NC}" && sleep 1 ;;
    esac
    
    echo ''
    read -p "Press Enter to continue..."
}

# View current configuration
view_current_config() {
    echo -e "\n${YELLOW}Current configurations:${NC}"
    
    if [[ -f "$CONFIG_DIR/server.toml" ]]; then
        echo -e "\n${GREEN}Server configuration (Iran):${NC}"
        echo -e "${YELLOW}═════════════════════════════════════════════${NC}"
        cat "$CONFIG_DIR/server.toml"
    fi
    
    if [[ -f "$CONFIG_DIR/client.toml" ]]; then
        echo -e "\n${GREEN}Client configuration (Foreign):${NC}"
        echo -e "${YELLOW}═════════════════════════════════════════════${NC}"
        cat "$CONFIG_DIR/client.toml"
    fi
    
    if [[ ! -f "$CONFIG_DIR/server.toml" ]] && [[ ! -f "$CONFIG_DIR/client.toml" ]]; then
        echo -e "${RED}No configurations found${NC}"
        echo -e "${YELLOW}Use option 1 or 2 to create configuration${NC}"
    fi
}

# Iran server configuration
iran_server_configuration() {
    clear
    echo -e "${YELLOW}Configuring IRAN server...${NC}\n" 
    
    # Tunnel port
    read -p "Enter the tunnel port [2333]: " tunnel_port
    tunnel_port=${tunnel_port:-2333}
    
    # Generate token
    TOKEN=$(openssl rand -hex 16 2>/dev/null || echo "default_token_$(date +%s)")
    
    echo -e "${CYAN}Generated token: $TOKEN${NC}"
    echo -e "${YELLOW}Save this token for foreign server configuration!${NC}"
    echo ''
    
    # Config ports
    echo -e "Enter service ports (one per line, leave empty to finish):"
    echo -e "${YELLOW}Format: PORT:PROTOCOL (e.g., 8080:tcp or 53:udp)${NC}"
    
    config_ports=()
    config_protocols=()
    i=1
    
    while true; do
        read -p "Service $i (PORT:PROTOCOL or empty to finish): " service_input
        
        if [[ -z "$service_input" ]]; then
            break
        fi
        
        local port=$(echo "$service_input" | cut -d: -f1)
        local protocol=$(echo "$service_input" | cut -d: -f2 | tr '[:upper:]' '[:lower:]')
        
        if [[ ! "$port" =~ ^[0-9]+$ ]] || [[ "$port" -lt 1 ]] || [[ "$port" -gt 65535 ]]; then
            echo -e "${RED}Invalid port number${NC}"
            continue
        fi
        
        if [[ "$protocol" != "tcp" ]] && [[ "$protocol" != "udp" ]]; then
            echo -e "${RED}Protocol must be tcp or udp${NC}"
            continue
        fi
        
        config_ports+=("$port")
        config_protocols+=("$protocol")
        echo -e "${GREEN}Added service $i: port $port ($protocol)${NC}"
        ((i++))
    done
    
    if [[ ${#config_ports[@]} -eq 0 ]]; then
        echo -e "${YELLOW}No services added. Using default port 8080${NC}"
        config_ports=("8080")
        config_protocols=("tcp")
    fi
    
    echo ''
    
    # TCP No-Delay
    read -p "TCP No-Delay (true/false) [true]: " nodelay
    nodelay=${nodelay:-true}
    
    # IPv6 Support
    read -p "Enable IPv6? (yes/no) [no]: " ipv6_answer
    ipv6_answer=${ipv6_answer:-no}
    
    if [[ "$ipv6_answer" =~ ^[Yy](es)?$ ]]; then
        local_ip='[::]'
        echo -e "${CYAN}IPv6 enabled${NC}"
    else
        local_ip='0.0.0.0'
        echo -e "${CYAN}IPv4 only${NC}"
    fi
    
    # Generate config file
    cat > "$CONFIG_DIR/server.toml" << EOF
[server]
bind_addr = "${local_ip}:${tunnel_port}"
default_token = "${TOKEN}"
heartbeat_timeout = 30

[server.transport]
type = "tcp"

[server.transport.tcp]
keepalive_secs = 7200
keepalive_interval = 15
nodelay = ${nodelay}

EOF
    
    # Add services
    for i in "${!config_ports[@]}"; do
        cat << EOF >> "$CONFIG_DIR/server.toml"
[server.services.service_${config_ports[$i]}]
type = "${config_protocols[$i]}"
bind_addr = "${local_ip}:${config_ports[$i]}"

EOF
    done
    
    echo -e "${GREEN}[✓] IRAN server configuration saved to: $CONFIG_DIR/server.toml${NC}"
    
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
    
    if [[ -z "$iran_ip" ]] || [[ -z "$token" ]]; then
        echo -e "${RED}IP address and token are required!${NC}"
        return 1
    fi
    
    echo ''
    echo -e "Enter local services (one per line, leave empty to finish):"
    echo -e "${YELLOW}Format: LOCAL_PORT:REMOTE_PORT:PROTOCOL${NC}"
    echo -e "${YELLOW}Example: 80:8080:tcp${NC}"
    
    services=()
    i=1
    
    while true; do
        read -p "Service $i (LOCAL:REMOTE:PROTOCOL or empty to finish): " service_input
        
        if [[ -z "$service_input" ]]; then
            break
        fi
        
        local_port=$(echo "$service_input" | cut -d: -f1)
        remote_port=$(echo "$service_input" | cut -d: -f2)
        protocol=$(echo "$service_input" | cut -d: -f3 | tr '[:upper:]' '[:lower:]')
        
        if [[ ! "$local_port" =~ ^[0-9]+$ ]] || [[ ! "$remote_port" =~ ^[0-9]+$ ]]; then
            echo -e "${RED}Invalid port numbers${NC}"
            continue
        fi
        
        if [[ "$protocol" != "tcp" ]] && [[ "$protocol" != "udp" ]]; then
            echo -e "${RED}Protocol must be tcp or udp${NC}"
            continue
        fi
        
        services+=("${local_port}:${remote_port}:${protocol}")
        echo -e "${GREEN}Added service $i: local:$local_port → remote:$remote_port ($protocol)${NC}"
        ((i++))
    done
    
    if [[ ${#services[@]} -eq 0 ]]; then
        echo -e "${YELLOW}No services added. Using default 80:8080:tcp${NC}"
        services=("80:8080:tcp")
    fi
    
    # Generate config file
    cat > "$CONFIG_DIR/client.toml" << EOF
[client]
remote_addr = "${iran_ip}:${tunnel_port}"
default_token = "${token}"
retry_interval = 1
heartbeat_timeout = 30

[client.transport]
type = "tcp"

[client.transport.tcp]
keepalive_secs = 7200
keepalive_interval = 15
nodelay = true

EOF
    
    # Add services
    for i in "${!services[@]}"; do
        IFS=':' read -r local_port remote_port protocol <<< "${services[$i]}"
        cat << EOF >> "$CONFIG_DIR/client.toml"
[client.services.service_$((i+1))]
type = "${protocol}"
local_addr = "127.0.0.1:${local_port}"
remote_port = ${remote_port}

EOF
    done
    
    echo -e "${GREEN}[✓] Foreign server configuration saved to: $CONFIG_DIR/client.toml${NC}"
    
    # Create systemd service
    create_foreign_service
}

# Create Iran service
create_iran_service() {
    local service_name="rathole-iran"
    local service_file="$SERVICE_DIR/${service_name}.service"
    
    # Ensure log directory exists
    mkdir -p "$LOG_DIR"
    
    cat > "$service_file" << EOF
[Unit]
Description=Rathole Iran Server
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$CONFIG_DIR
ExecStart=$CONFIG_DIR/rathole server.toml
Restart=always
RestartSec=3
LimitNOFILE=65536
StandardOutput=append:$LOG_DIR/rathole-iran.log
StandardError=append:$LOG_DIR/rathole-iran-error.log

# Security
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable "$service_name" >/dev/null 2>&1
    
    echo -e "${YELLOW}[-] Starting Iran server service...${NC}"
    
    if systemctl start "$service_name"; then
        sleep 2
        if systemctl is-active --quiet "$service_name"; then
            echo -e "${GREEN}[✓] Iran server service started successfully${NC}"
            echo -e "${CYAN}Check status: systemctl status $service_name${NC}"
            echo -e "${CYAN}Check logs: tail -f $LOG_DIR/rathole-iran.log${NC}"
        else
            echo -e "${YELLOW}[!] Service started but not active. Checking logs...${NC}"
            systemctl status "$service_name" --no-pager -l
        fi
    else
        echo -e "${RED}[ERROR] Failed to start service${NC}"
        systemctl status "$service_name" --no-pager -l
    fi
}

# Create Foreign service
create_foreign_service() {
    local service_name="rathole-foreign"
    local service_file="$SERVICE_DIR/${service_name}.service"
    
    # Ensure log directory exists
    mkdir -p "$LOG_DIR"
    
    cat > "$service_file" << EOF
[Unit]
Description=Rathole Foreign Client
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$CONFIG_DIR
ExecStart=$CONFIG_DIR/rathole client.toml
Restart=always
RestartSec=3
LimitNOFILE=65536
StandardOutput=append:$LOG_DIR/rathole-foreign.log
StandardError=append:$LOG_DIR/rathole-foreign-error.log

# Security
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable "$service_name" >/dev/null 2>&1
    
    echo -e "${YELLOW}[-] Starting Foreign client service...${NC}"
    
    if systemctl start "$service_name"; then
        sleep 2
        if systemctl is-active --quiet "$service_name"; then
            echo -e "${GREEN}[✓] Foreign client service started successfully${NC}"
            echo -e "${CYAN}Check status: systemctl status $service_name${NC}"
            echo -e "${CYAN}Check logs: tail -f $LOG_DIR/rathole-foreign.log${NC}"
        else
            echo -e "${YELLOW}[!] Service started but not active. Checking logs...${NC}"
            systemctl status "$service_name" --no-pager -l
        fi
    else
        echo -e "${RED}[ERROR] Failed to start service${NC}"
        systemctl status "$service_name" --no-pager -l
    fi
}

# Show status
show_status() {
    clear
    display_logo
    
    echo -e "${YELLOW}═════════════════════════════════════════════${NC}"
    echo -e "${CYAN}RATHOLE TUNNEL STATUS${NC}"
    echo -e "${YELLOW}═════════════════════════════════════════════${NC}\n"
    
    # Show server info
    display_server_info
    
    # Show core status
    display_rathole_core_status
    
    # Show service status
    echo -e "${CYAN}Service Status:${NC}"
    echo -e "${YELLOW}─────────────────────────────────────────────${NC}"
    
    local services=("rathole-iran" "rathole-foreign")
    
    for service in "${services[@]}"; do
        if systemctl is-enabled "$service" 2>/dev/null | grep -q "enabled"; then
            local enabled="${GREEN}ENABLED${NC}"
        else
            local enabled="${RED}DISABLED${NC}"
        fi
        
        if systemctl is-active "$service" &>/dev/null; then
            local active="${GREEN}ACTIVE${NC}"
            local pid=$(systemctl show "$service" --property=MainPID | cut -d= -f2)
            if [[ "$pid" -ne 0 ]]; then
                local uptime=$(ps -o etimes= -p "$pid" 2>/dev/null | awk '{printf "%dd %dh %dm", $1/86400, ($1%86400)/3600, ($1%3600)/60}')
                active="${GREEN}ACTIVE${NC} (PID: $pid, Uptime: ${uptime:-unknown})"
            fi
        else
            active="${RED}INACTIVE${NC}"
        fi
        
        echo -e "  $service:"
        echo -e "    Status: $active"
        echo -e "    Auto-start: $enabled"
        
        # Show config file if exists
        if [[ "$service" == "rathole-iran" ]] && [[ -f "$CONFIG_DIR/server.toml" ]]; then
            local bind_addr=$(grep "bind_addr" "$CONFIG_DIR/server.toml" | head -1 | cut -d= -f2 | tr -d ' "')
            echo -e "    Listening on: $bind_addr"
        elif [[ "$service" == "rathole-foreign" ]] && [[ -f "$CONFIG_DIR/client.toml" ]]; then
            local remote_addr=$(grep "remote_addr" "$CONFIG_DIR/client.toml" | head -1 | cut -d= -f2 | tr -d ' "')
            echo -e "    Connecting to: $remote_addr"
        fi
        
        echo ""
    done
    
    # Show recent logs
    echo -e "${CYAN}Recent Logs:${NC}"
    echo -e "${YELLOW}─────────────────────────────────────────────${NC}"
    
    for log_file in "$LOG_DIR"/*.log; do
        if [[ -f "$log_file" ]]; then
            echo -e "\n${YELLOW}$(basename "$log_file"):${NC}"
            tail -5 "$log_file" 2>/dev/null | while read line; do
                echo "  $line"
            done || echo "  No logs available"
        fi
    done
    
    echo ''
    echo -e "${YELLOW}═════════════════════════════════════════════${NC}"
    echo -e "${CYAN}Commands:${NC}"
    echo -e "  Start Iran: systemctl start rathole-iran"
    echo -e "  Stop Iran: systemctl stop rathole-iran"
    echo -e "  Start Foreign: systemctl start rathole-foreign"
    echo -e "  Stop Foreign: systemctl stop rathole-foreign"
    echo -e "  View logs: journalctl -u rathole-iran -f"
    echo -e "${YELLOW}═════════════════════════════════════════════${NC}"
    
    read -p "Press Enter to continue..."
}

# Remove Rathole
remove_rathole() {
    echo -e "${RED}[!] WARNING: This will remove Rathole completely${NC}"
    echo -e "${YELLOW}This includes:${NC}"
    echo -e "  - Rathole binary and configs"
    echo -e "  - Systemd services"
    echo -e "  - Log files"
    echo ''
    
    read -p "Are you sure? (y/n): " confirm
    
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}[*] Removing Rathole...${NC}"
        
        # Stop and disable services
        for service in rathole-iran rathole-foreign; do
            if systemctl is-active --quiet "$service" 2>/dev/null; then
                echo -e "${YELLOW}[-] Stopping $service...${NC}"
                systemctl stop "$service"
            fi
            
            if systemctl is-enabled --quiet "$service" 2>/dev/null; then
                echo -e "${YELLOW}[-] Disabling $service...${NC}"
                systemctl disable "$service"
            fi
        done
        
        # Remove service files
        echo -e "${YELLOW}[-] Removing service files...${NC}"
        rm -f "$SERVICE_DIR/rathole-iran.service"
        rm -f "$SERVICE_DIR/rathole-foreign.service"
        
        # Remove config directory
        if [[ -d "$CONFIG_DIR" ]]; then
            echo -e "${YELLOW}[-] Removing config directory...${NC}"
            rm -rf "$CONFIG_DIR"
        fi
        
        # Optional: remove logs
        read -p "Remove log files? (y/n): " remove_logs
        if [[ "$remove_logs" =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}[-] Removing log files...${NC}"
            rm -rf "$LOG_DIR"
        fi
        
        # Reload systemd
        systemctl daemon-reload
        systemctl reset-failed
        
        echo -e "${GREEN}[✓] Rathole completely removed${NC}"
    else
        echo -e "${YELLOW}Operation cancelled${NC}"
    fi
    
    echo ''
    read -p "Press Enter to continue..."
}

# Test Rathole installation
test_rathole_installation() {
    echo -e "${YELLOW}[*] Testing Rathole installation...${NC}"
    
    if [[ ! -f "$CONFIG_DIR/rathole" ]]; then
        echo -e "${RED}[ERROR] Rathole binary not found${NC}"
        return 1
    fi
    
    # Test 1: Binary executable
    if [[ ! -x "$CONFIG_DIR/rathole" ]]; then
        echo -e "${YELLOW}[!] Binary not executable, fixing...${NC}"
        chmod +x "$CONFIG_DIR/rathole"
    fi
    
    # Test 2: Version check
    echo -e "${YELLOW}[-] Checking version...${NC}"
    if "$CONFIG_DIR/rathole" --version &>/dev/null; then
        local version=$("$CONFIG_DIR/rathole" --version 2>&1)
        echo -e "${GREEN}[✓] Version: $version${NC}"
    else
        echo -e "${YELLOW}[!] Version check failed, but binary exists${NC}"
    fi
    
    # Test 3: Help command
    if "$CONFIG_DIR/rathole" --help &>/dev/null; then
        echo -e "${GREEN}[✓] Binary responds to --help${NC}"
    fi
    
    # Test 4: Config check
    if [[ -f "$CONFIG_DIR/server.toml" ]] && "$CONFIG_DIR/rathole" -c "$CONFIG_DIR/server.toml" --check &>/dev/null; then
        echo -e "${GREEN}[✓] Server config syntax OK${NC}"
    fi
    
    if [[ -f "$CONFIG_DIR/client.toml" ]] && "$CONFIG_DIR/rathole" -c "$CONFIG_DIR/client.toml" --check &>/dev/null; then
        echo -e "${GREEN}[✓] Client config syntax OK${NC}"
    fi
    
    echo -e "${GREEN}[✓] Installation test completed${NC}"
    return 0
}

# Main menu
main_menu() {
    while true; do
        clear
        display_logo
        
        echo -e "${CYAN}Main Menu:${NC}"
        echo -e "${YELLOW}═════════════════════════════════════════════${NC}"
        echo -e "1. ${GREEN}Install/Update Rathole Core${NC}"
        echo -e "2. ${YELLOW}Configure Tunnel${NC}"
        echo -e "3. ${BLUE}Show Service Status${NC}"
        echo -e "4. ${CYAN}Test Installation${NC}"
        echo -e "5. ${RED}Remove Rathole Completely${NC}"
        echo -e "6. ${GREEN}Exit${NC}"
        echo -e "${YELLOW}═════════════════════════════════════════════${NC}"
        echo ''
        
        read -p "Enter your choice [1-6]: " choice
        
        case $choice in
            1)
                echo -e "${YELLOW}[*] Starting installation process...${NC}"
                fix_apt_locks
                install_dependencies
                download_and_extract_rathole
                ;;
            2)
                configure_tunnel
                ;;
            3)
                show_status
                ;;
            4)
                test_rathole_installation
                read -p "Press Enter to continue..."
                ;;
            5)
                remove_rathole
                ;;
            6)
                echo -e "${GREEN}Goodbye!${NC}"
                echo -e "${CYAN}Thank you for using Rathole Tunnel Manager${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option!${NC}"
                sleep 1
                ;;
        esac
    done
}

# Initialize
initialize() {
    echo -e "${YELLOW}[*] Initializing Rathole Tunnel Manager...${NC}"
    
    # Create required directories
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    
    # Set permissions
    chmod 700 "$CONFIG_DIR" 2>/dev/null || true
    
    echo -e "${GREEN}[✓] Initialization complete${NC}"
    sleep 1
}

# Main execution
check_root
initialize
main_menu
