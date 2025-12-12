#!/bin/bash
# ============================================
# Rathole Tunnel Manager - Stable Version
# Fixed installation issues and status=203 errors
# Version: 7.0
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
BACKUP_DIR="/root/rathole-backup"

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
    echo -e "Version: ${YELLOW}v7.0${GREEN}"
    echo -e "Status: ${GREEN}FIXED - Stable Installation${NC}"
    echo -e "${BLUE}===========================================${NC}"
}

# Check root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}This script must be run as root${NC}"
        echo -e "${YELLOW}Use: sudo bash $0${NC}"
        sleep 1
        exit 1
    fi
}

# Fix all system issues
fix_system_issues() {
    echo -e "${YELLOW}[*] Fixing system issues...${NC}"
    
    # Fix apt locks
    echo -e "${YELLOW}[-] Checking for package locks...${NC}"
    rm -f /var/lib/apt/lists/lock 2>/dev/null || true
    rm -f /var/lib/dpkg/lock 2>/dev/null || true
    rm -f /var/lib/dpkg/lock-frontend 2>/dev/null || true
    rm -f /var/cache/apt/archives/lock 2>/dev/null || true
    
    # Kill stuck apt processes
    pkill -9 apt-get 2>/dev/null || true
    pkill -9 apt 2>/dev/null || true
    pkill -9 dpkg 2>/dev/null || true
    
    # Fix broken packages
    dpkg --configure -a 2>/dev/null || true
    
    # Clean up
    apt-get autoremove -y 2>/dev/null || true
    apt-get autoclean -y 2>/dev/null || true
    
    sleep 2
}

# Install all dependencies
install_dependencies() {
    echo -e "${YELLOW}[*] Installing dependencies...${NC}"
    
    # Update package list
    echo -e "${YELLOW}[-] Updating package list...${NC}"
    apt-get update -y
    
    # Install essential packages
    local packages="curl wget tar gzip unzip jq iptables iproute2 net-tools lsof"
    
    for pkg in $packages; do
        if ! dpkg -l | grep -q "^ii.*$pkg"; then
            echo -e "${YELLOW}[-] Installing $pkg...${NC}"
            apt-get install -y "$pkg" --fix-missing
        fi
    done
    
    # Install build dependencies if needed
    apt-get install -y build-essential libssl-dev pkg-config 2>/dev/null || true
    
    echo -e "${GREEN}[✓] Dependencies installed${NC}"
}

# Download STATIC binary (no dependencies)
download_static_rathole() {
    local arch=$1
    local target_dir=$2
    
    echo -e "${YELLOW}[*] Downloading STATIC Rathole binary...${NC}"
    
    # Static binaries (no glibc dependencies)
    case "$arch" in
        "x86_64")
            # Static musl binary - works on most systems
            url="https://github.com/rapiz1/rathole/releases/download/v0.4.7/rathole-x86_64-unknown-linux-musl.tar.gz"
            ;;
        "aarch64"|"arm64")
            url="https://github.com/rapiz1/rathole/releases/download/v0.4.7/rathole-aarch64-unknown-linux-musl.tar.gz"
            ;;
        "armv7l")
            url="https://github.com/rapiz1/rathole/releases/download/v0.4.7/rathole-armv7-unknown-linux-musleabi.tar.gz"
            ;;
        "i386"|"i686")
            url="https://github.com/rapiz1/rathole/releases/download/v0.4.7/rathole-i686-unknown-linux-musl.tar.gz"
            ;;
        *)
            echo -e "${RED}[!] Unsupported architecture: $arch${NC}"
            return 1
            ;;
    esac
    
    echo -e "${CYAN}Downloading from: $url${NC}"
    
    # Download with retry
    for i in {1..5}; do
        echo -e "${YELLOW}[-] Attempt $i/5...${NC}"
        
        if curl -L -s -o "/tmp/rathole-static.tar.gz" "$url"; then
            echo -e "${GREEN}[✓] Download successful${NC}"
            
            # Extract
            if tar -xzf "/tmp/rathole-static.tar.gz" -C "/tmp/" 2>/dev/null; then
                # Find binary
                local binary=$(find /tmp -name "rathole" -type f 2>/dev/null | head -1)
                
                if [[ -f "$binary" ]]; then
                    # Copy to target
                    mkdir -p "$target_dir"
                    cp "$binary" "$target_dir/rathole"
                    chmod +x "$target_dir/rathole"
                    
                    # Verify it's static
                    if file "$target_dir/rathole" | grep -q "statically linked"; then
                        echo -e "${GREEN}[✓] Static binary verified${NC}"
                    else
                        echo -e "${YELLOW}[!] Binary is not static, but should work${NC}"
                    fi
                    
                    rm -f "/tmp/rathole-static.tar.gz"
                    return 0
                fi
            fi
        fi
        
        sleep 2
    done
    
    echo -e "${RED}[ERROR] Failed to download static binary${NC}"
    return 1
}

# Alternative: Download from IPFS/alternative sources
download_alternative_rathole() {
    local arch=$1
    local target_dir=$2
    
    echo -e "${YELLOW}[*] Trying alternative sources...${NC}"
    
    # Alternative URLs (older but stable versions)
    local urls=()
    
    if [[ "$arch" == "x86_64" ]]; then
        urls=(
            "https://github.com/rapiz1/rathole/releases/download/v0.4.6/rathole-x86_64-unknown-linux-gnu.tar.gz"
            "https://github.com/rapiz1/rathole/releases/download/v0.4.5/rathole-x86_64-unknown-linux-gnu.tar.gz"
            "https://github.com/rapiz1/rathole/releases/download/v0.4.4/rathole-x86_64-unknown-linux-gnu.tar.gz"
        )
    elif [[ "$arch" == "aarch64" ]]; then
        urls=(
            "https://github.com/rapiz1/rathole/releases/download/v0.4.6/rathole-aarch64-unknown-linux-gnu.tar.gz"
            "https://github.com/rapiz1/rathole/releases/download/v0.4.5/rathole-aarch64-unknown-linux-gnu.tar.gz"
        )
    fi
    
    for url in "${urls[@]}"; do
        echo -e "${CYAN}Trying: $url${NC}"
        
        if curl -L -s -o "/tmp/rathole-alt.tar.gz" "$url"; then
            if tar -xzf "/tmp/rathole-alt.tar.gz" -C "/tmp/" 2>/dev/null; then
                local binary=$(find /tmp -name "rathole" -type f 2>/dev/null | head -1)
                
                if [[ -f "$binary" ]]; then
                    mkdir -p "$target_dir"
                    cp "$binary" "$target_dir/rathole"
                    chmod +x "$target_dir/rathole"
                    
                    echo -e "${GREEN}[✓] Downloaded from alternative source${NC}"
                    rm -f "/tmp/rathole-alt.tar.gz"
                    return 0
                fi
            fi
        fi
        
        sleep 1
    done
    
    return 1
}

# COMPATIBILITY MODE: Build from source if all else fails
build_from_source() {
    local target_dir=$1
    
    echo -e "${YELLOW}[*] Building Rathole from source...${NC}"
    
    # Install Rust if not present
    if ! command -v cargo &> /dev/null; then
        echo -e "${YELLOW}[-] Installing Rust...${NC}"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
    fi
    
    # Clone and build
    local build_dir="/tmp/rathole-build"
    rm -rf "$build_dir"
    
    git clone https://github.com/rapiz1/rathole.git "$build_dir" 2>/dev/null || {
        echo -e "${RED}[ERROR] Failed to clone repository${NC}"
        return 1
    }
    
    cd "$build_dir"
    
    # Build static binary
    echo -e "${YELLOW}[-] Building binary (this may take a few minutes)...${NC}"
    cargo build --release --target-dir="/tmp/rathole-build-output" 2>/dev/null || {
        echo -e "${RED}[ERROR] Build failed${NC}"
        return 1
    }
    
    # Find and copy binary
    local binary=$(find "/tmp/rathole-build-output" -name "rathole" -type f 2>/dev/null | head -1)
    
    if [[ -f "$binary" ]]; then
        mkdir -p "$target_dir"
        cp "$binary" "$target_dir/rathole"
        chmod +x "$target_dir/rathole"
        
        echo -e "${GREEN}[✓] Successfully built from source${NC}"
        return 0
    fi
    
    return 1
}

# Main installation function
install_rathole_core() {
    echo -e "${GREEN}[*] Installing Rathole Core (Stable)...${NC}"
    
    # Backup existing installation
    if [[ -d "$CONFIG_DIR" ]]; then
        echo -e "${YELLOW}Rathole Core is already installed.${NC}"
        read -p "Backup and reinstall? (y/n): " reinstall
        
        if [[ ! "$reinstall" =~ ^[Yy]$ ]]; then
            return 0
        fi
        
        # Create backup
        mkdir -p "$BACKUP_DIR"
        cp -r "$CONFIG_DIR" "$BACKUP_DIR/rathole-core-$(date +%Y%m%d-%H%M%S)"
        echo -e "${GREEN}[✓] Backup created${NC}"
        
        # Clean old services
        systemctl stop rathole-iran 2>/dev/null || true
        systemctl stop rathole-foreign 2>/dev/null || true
        systemctl disable rathole-iran 2>/dev/null || true
        systemctl disable rathole-foreign 2>/dev/null || true
        
        rm -rf "$CONFIG_DIR"
    fi
    
    # Create fresh directory
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    
    # Detect architecture
    ARCH=$(uname -m)
    echo -e "${CYAN}Architecture: $ARCH${NC}"
    
    # Try multiple installation methods
    local installed=false
    
    # Method 1: Static binary (recommended)
    echo -e "${YELLOW}[1] Trying static binary...${NC}"
    if download_static_rathole "$ARCH" "$CONFIG_DIR"; then
        installed=true
    fi
    
    # Method 2: Alternative sources
    if [[ "$installed" == false ]]; then
        echo -e "${YELLOW}[2] Trying alternative sources...${NC}"
        if download_alternative_rathole "$ARCH" "$CONFIG_DIR"; then
            installed=true
        fi
    fi
    
    # Method 3: Build from source
    if [[ "$installed" == false ]]; then
        echo -e "${YELLOW}[3] Building from source...${NC}"
        if build_from_source "$CONFIG_DIR"; then
            installed=true
        fi
    fi
    
    # Final verification
    if [[ "$installed" == true ]]; then
        # Test the binary
        if [[ -x "$CONFIG_DIR/rathole" ]]; then
            # Run basic test
            if timeout 5 "$CONFIG_DIR/rathole" --help &>/dev/null; then
                local version=$("$CONFIG_DIR/rathole" --version 2>&1 | head -1 || echo "v0.4.7")
                echo -e "${GREEN}[✓] Rathole installed successfully${NC}"
                echo -e "${GREEN}[✓] Version: $version${NC}"
                
                # Create test config
                create_test_config
                return 0
            else
                echo -e "${RED}[ERROR] Binary exists but fails to run${NC}"
                
                # Check dependencies
                echo -e "${YELLOW}[-] Checking binary dependencies...${NC}"
                ldd "$CONFIG_DIR/rathole" 2>/dev/null || echo "Binary check failed"
                
                return 1
            fi
        else
            echo -e "${RED}[ERROR] Binary not found or not executable${NC}"
            return 1
        fi
    else
        echo -e "${RED}[ERROR] All installation methods failed${NC}"
        
        # Manual installation instructions
        echo -e "${YELLOW}===========================================${NC}"
        echo -e "${CYAN}MANUAL INSTALLATION INSTRUCTIONS:${NC}"
        echo -e "1. Visit: ${BLUE}https://github.com/rapiz1/rathole/releases${NC}"
        echo -e "2. Download appropriate version for your architecture"
        echo -e "3. Extract and place binary at: ${CONFIG_DIR}/rathole"
        echo -e "4. Run: chmod +x ${CONFIG_DIR}/rathole"
        echo -e "${YELLOW}===========================================${NC}"
        
        # Create directory for manual install
        mkdir -p "$CONFIG_DIR"
        return 1
    fi
}

# Create test configuration
create_test_config() {
    echo -e "${YELLOW}[*] Creating test configuration...${NC}"
    
    # Simple server config for testing
    cat > "$CONFIG_DIR/server-test.toml" << 'EOF'
[server]
bind_addr = "0.0.0.0:2333"
default_token = "test_token_12345"

[server.services.test]
type = "tcp"
bind_addr = "0.0.0.0:8080"
EOF

    # Simple client config for testing
    cat > "$CONFIG_DIR/client-test.toml" << 'EOF'
[client]
remote_addr = "127.0.0.1:2333"
default_token = "test_token_12345"

[client.services.test]
type = "tcp"
local_addr = "127.0.0.1:80"
EOF

    echo -e "${GREEN}[✓] Test configurations created${NC}"
}

# Fix permissions and ownership
fix_permissions() {
    echo -e "${YELLOW}[*] Fixing permissions...${NC}"
    
    # Fix binary permissions
    if [[ -f "$CONFIG_DIR/rathole" ]]; then
        chmod 755 "$CONFIG_DIR/rathole"
        chown root:root "$CONFIG_DIR/rathole"
    fi
    
    # Fix directory permissions
    chmod 700 "$CONFIG_DIR"
    chown root:root "$CONFIG_DIR"
    
    # Fix log directory
    mkdir -p "$LOG_DIR"
    chmod 755 "$LOG_DIR"
    chown root:root "$LOG_DIR"
    
    echo -e "${GREEN}[✓] Permissions fixed${NC}"
}

# Create systemd service with proper setup
create_service() {
    local service_name=$1
    local config_file=$2
    local service_file="$SERVICE_DIR/${service_name}.service"
    
    echo -e "${YELLOW}[*] Creating service: $service_name${NC}"
    
    # Create service file with proper settings
    cat > "$service_file" << EOF
[Unit]
Description=Rathole Tunnel - $service_name
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$CONFIG_DIR
ExecStart=$CONFIG_DIR/rathole $config_file
Restart=always
RestartSec=5
StartLimitInterval=0
StandardOutput=append:$LOG_DIR/${service_name}.log
StandardError=append:$LOG_DIR/${service_name}-error.log

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd
    systemctl daemon-reload
    
    # Enable service
    systemctl enable "$service_name"
    
    echo -e "${GREEN}[✓] Service created: $service_name${NC}"
}

# Test service
test_service() {
    local service_name=$1
    
    echo -e "${YELLOW}[*] Testing service: $service_name${NC}"
    
    # Start service
    if systemctl start "$service_name"; then
        sleep 3
        
        # Check status
        if systemctl is-active --quiet "$service_name"; then
            echo -e "${GREEN}[✓] Service $service_name is running${NC}"
            
            # Check logs
            echo -e "${CYAN}Recent logs:${NC}"
            journalctl -u "$service_name" -n 10 --no-pager || \
            tail -n 10 "$LOG_DIR/${service_name}.log" 2>/dev/null || \
            echo "No logs available"
            
            return 0
        else
            echo -e "${RED}[ERROR] Service started but not active${NC}"
            
            # Show detailed status
            systemctl status "$service_name" --no-pager
            
            # Check for common errors
            echo -e "${YELLOW}[*] Checking for common issues...${NC}"
            
            # Check binary exists and is executable
            if [[ ! -x "$CONFIG_DIR/rathole" ]]; then
                echo -e "${RED}- Binary not executable: $CONFIG_DIR/rathole${NC}"
                ls -la "$CONFIG_DIR/rathole"
            fi
            
            # Check config file
            if [[ ! -f "$CONFIG_DIR/$config_file" ]]; then
                echo -e "${RED}- Config file missing: $CONFIG_DIR/$config_file${NC}"
            fi
            
            return 1
        fi
    else
        echo -e "${RED}[ERROR] Failed to start service${NC}"
        return 1
    fi
}

# Quick tunnel setup
quick_tunnel_setup() {
    clear
    echo -e "${CYAN}QUICK TUNNEL SETUP${NC}"
    echo -e "${YELLOW}═════════════════════════════════════════════${NC}"
    
    echo -e "Select server type:"
    echo -e "1. ${GREEN}IRAN Server${NC} (Accepts connections from outside)"
    echo -e "2. ${BLUE}FOREIGN Server${NC} (Connects to Iran server)"
    echo ''
    
    read -p "Choice [1/2]: " server_type
    
    case $server_type in
        1)
            setup_iran_server
            ;;
        2)
            setup_foreign_server
            ;;
        *)
            echo -e "${RED}Invalid choice${NC}"
            return 1
            ;;
    esac
}

# Setup Iran server
setup_iran_server() {
    echo -e "${GREEN}[*] Setting up Iran server...${NC}"
    
    # Generate token
    local token=$(openssl rand -hex 16 2>/dev/null || echo "default_token_$(date +%s)")
    
    # Get public IP (optional)
    local public_ip=$(curl -s ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")
    
    # Create config
    cat > "$CONFIG_DIR/server.toml" << EOF
[server]
bind_addr = "0.0.0.0:2333"
default_token = "$token"

[server.transport]
type = "tcp"
keepalive_secs = 7200

[server.transport.tcp]
nodelay = true

[server.services.web]
type = "tcp"
bind_addr = "0.0.0.0:8080"

[server.services.ssh]
type = "tcp"
bind_addr = "0.0.0.0:2222"
EOF
    
    echo -e "${GREEN}[✓] Iran server configuration created${NC}"
    echo -e "${CYAN}===========================================${NC}"
    echo -e "${YELLOW}IMPORTANT INFORMATION:${NC}"
    echo -e "Token: ${GREEN}$token${NC}"
    echo -e "Server IP: ${GREEN}$public_ip${NC}"
    echo -e "Tunnel Port: ${GREEN}2333${NC}"
    echo -e "Web Service: ${GREEN}8080${NC}"
    echo -e "SSH Service: ${GREEN}2222${NC}"
    echo -e "${CYAN}===========================================${NC}"
    
    # Create service
    create_service "rathole-iran" "server.toml"
    
    # Start and test
    test_service "rathole-iran"
    
    # Show firewall commands
    echo -e "${YELLOW}[*] Firewall setup (if needed):${NC}"
    echo -e "ufw allow 2333/tcp"
    echo -e "ufw allow 8080/tcp"
    echo -e "ufw allow 2222/tcp"
}

# Setup Foreign server
setup_foreign_server() {
    echo -e "${BLUE}[*] Setting up Foreign server...${NC}"
    
    read -p "Enter Iran server IP: " iran_ip
    read -p "Enter token: " token
    
    if [[ -z "$iran_ip" ]] || [[ -z "$token" ]]; then
        echo -e "${RED}IP and token are required!${NC}"
        return 1
    fi
    
    # Create config
    cat > "$CONFIG_DIR/client.toml" << EOF
[client]
remote_addr = "$iran_ip:2333"
default_token = "$token"
retry_interval = 3

[client.transport]
type = "tcp"

[client.transport.tcp]
nodelay = true

[client.services.web]
type = "tcp"
local_addr = "127.0.0.1:80"
remote_port = 8080

[client.services.ssh]
type = "tcp"
local_addr = "127.0.0.1:22"
remote_port = 2222
EOF
    
    echo -e "${GREEN}[✓] Foreign client configuration created${NC}"
    
    # Create service
    create_service "rathole-foreign" "client.toml"
    
    # Start and test
    test_service "rathole-foreign"
}

# Diagnostic function
run_diagnostics() {
    echo -e "${CYAN}[*] Running diagnostics...${NC}"
    echo -e "${YELLOW}═════════════════════════════════════════════${NC}"
    
    # Check system
    echo -e "${CYAN}1. System Information:${NC}"
    uname -a
    echo ""
    
    # Check architecture
    echo -e "${CYAN}2. Architecture:${NC}"
    uname -m
    echo ""
    
    # Check dependencies
    echo -e "${CYAN}3. Dependencies:${NC}"
    local deps="curl wget tar unzip"
    for dep in $deps; do
        if command -v "$dep" &> /dev/null; then
            echo -e "${GREEN}[✓] $dep${NC}"
        else
            echo -e "${RED}[✗] $dep${NC}"
        fi
    done
    echo ""
    
    # Check rathole binary
    echo -e "${CYAN}4. Rathole Binary:${NC}"
    if [[ -f "$CONFIG_DIR/rathole" ]]; then
        echo -e "${GREEN}[✓] Binary exists${NC}"
        ls -la "$CONFIG_DIR/rathole"
        
        # Check if executable
        if [[ -x "$CONFIG_DIR/rathole" ]]; then
            echo -e "${GREEN}[✓] Binary is executable${NC}"
            
            # Test run
            if timeout 2 "$CONFIG_DIR/rathole" --version &>/dev/null; then
                echo -e "${GREEN}[✓] Binary test PASSED${NC}"
                "$CONFIG_DIR/rathole" --version
            else
                echo -e "${RED}[✗] Binary test FAILED${NC}"
            fi
        else
            echo -e "${RED}[✗] Binary NOT executable${NC}"
            echo -e "${YELLOW}Fixing permissions...${NC}"
            chmod +x "$CONFIG_DIR/rathole"
        fi
    else
        echo -e "${RED}[✗] Binary NOT found${NC}"
    fi
    echo ""
    
    # Check services
    echo -e "${CYAN}5. Services:${NC}"
    local services=("rathole-iran" "rathole-foreign")
    for svc in "${services[@]}"; do
        if systemctl is-enabled "$svc" &>/dev/null; then
            echo -e "${GREEN}[✓] $svc: enabled${NC}"
            
            if systemctl is-active "$svc" &>/dev/null; then
                echo -e "${GREEN}     Status: ACTIVE${NC}"
            else
                echo -e "${RED}     Status: INACTIVE${NC}"
                
                # Show error
                echo "     Last error:"
                systemctl status "$svc" --no-pager -l | tail -10
            fi
        else
            echo -e "${YELLOW}[!] $svc: disabled${NC}"
        fi
    done
    echo ""
    
    # Check ports
    echo -e "${CYAN}6. Network Ports:${NC}"
    netstat -tulpn | grep -E "(rathole|2333|8080|2222)" || echo "No relevant ports found"
    echo ""
    
    # Check logs
    echo -e "${CYAN}7. Log Files:${NC}"
    if ls "$LOG_DIR"/*.log 2>/dev/null; then
        for log in "$LOG_DIR"/*.log; do
            echo -e "${YELLOW}$(basename "$log"):${NC}"
            tail -5 "$log" 2>/dev/null || echo "  (empty)"
        done
    else
        echo "No log files found"
    fi
    
    echo -e "${YELLOW}═════════════════════════════════════════════${NC}"
    echo -e "${GREEN}[✓] Diagnostics complete${NC}"
}

# Fix all problems
fix_all_problems() {
    echo -e "${RED}[*] ATTEMPTING TO FIX ALL PROBLEMS${NC}"
    echo -e "${YELLOW}═════════════════════════════════════════════${NC}"
    
    # Step 1: Stop services
    echo -e "${CYAN}[1] Stopping services...${NC}"
    systemctl stop rathole-iran 2>/dev/null || true
    systemctl stop rathole-foreign 2>/dev/null || true
    sleep 2
    
    # Step 2: Fix system
    fix_system_issues
    
    # Step 3: Reinstall dependencies
    install_dependencies
    
    # Step 4: Reinstall rathole
    install_rathole_core
    
    # Step 5: Fix permissions
    fix_permissions
    
    # Step 6: Restart services if configs exist
    if [[ -f "$CONFIG_DIR/server.toml" ]]; then
        echo -e "${CYAN}[6] Restarting Iran service...${NC}"
        systemctl restart rathole-iran 2>/dev/null && \
        echo -e "${GREEN}[✓] Iran service restarted${NC}" || \
        echo -e "${RED}[✗] Failed to restart Iran service${NC}"
    fi
    
    if [[ -f "$CONFIG_DIR/client.toml" ]]; then
        echo -e "${CYAN}[7] Restarting Foreign service...${NC}"
        systemctl restart rathole-foreign 2>/dev/null && \
        echo -e "${GREEN}[✓] Foreign service restarted${NC}" || \
        echo -e "${RED}[✗] Failed to restart Foreign service${NC}"
    fi
    
    echo -e "${YELLOW}═════════════════════════════════════════════${NC}"
    echo -e "${GREEN}[✓] Fix procedure complete${NC}"
}

# Main menu
main_menu() {
    while true; do
        clear
        display_logo
        
        echo -e "${CYAN}MAIN MENU - STABLE VERSION${NC}"
        echo -e "${YELLOW}═════════════════════════════════════════════${NC}"
        echo -e "1. ${GREEN}FULL INSTALL${NC} (Fix + Install + Configure)"
        echo -e "2. ${YELLOW}Install Rathole Core Only${NC}"
        echo -e "3. ${BLUE}Quick Tunnel Setup${NC}"
        echo -e "4. ${CYAN}Run Diagnostics${NC}"
        echo -e "5. ${RED}FIX ALL PROBLEMS${NC}"
        echo -e "6. ${MAGENTA}Service Management${NC}"
        echo -e "7. ${WHITE}Exit${NC}"
        echo -e "${YELLOW}═════════════════════════════════════════════${NC}"
        echo ""
        
        read -p "Select option [1-7]: " choice
        
        case $choice in
            1)
                echo -e "${GREEN}[*] Starting FULL INSTALL...${NC}"
                fix_system_issues
                install_dependencies
                install_rathole_core
                fix_permissions
                quick_tunnel_setup
                ;;
            2)
                install_rathole_core
                ;;
            3)
                quick_tunnel_setup
                ;;
            4)
                run_diagnostics
                read -p "Press Enter to continue..."
                ;;
            5)
                fix_all_problems
                read -p "Press Enter to continue..."
                ;;
            6)
                service_management
                ;;
            7)
                echo -e "${GREEN}Goodbye!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option!${NC}"
                sleep 1
                ;;
        esac
        
        echo ""
        read -p "Press Enter to continue..."
    done
}

# Service management submenu
service_management() {
    while true; do
        clear
        echo -e "${CYAN}SERVICE MANAGEMENT${NC}"
        echo -e "${YELLOW}═════════════════════════════════════════════${NC}"
        
        # Show status
        echo -e "${CYAN}Current Status:${NC}"
        local services=("rathole-iran" "rathole-foreign")
        
        for svc in "${services[@]}"; do
            if systemctl is-active "$svc" &>/dev/null; then
                echo -e "  ${GREEN}●${NC} $svc: ${GREEN}RUNNING${NC}"
            elif systemctl is-enabled "$svc" &>/dev/null; then
                echo -e "  ${YELLOW}●${NC} $svc: ${YELLOW}STOPPED${NC}"
            else
                echo -e "  ${RED}●${NC} $svc: ${RED}NOT INSTALLED${NC}"
            fi
        done
        
        echo -e "${YELLOW}═════════════════════════════════════════════${NC}"
        echo -e "1. Start Iran Tunnel"
        echo -e "2. Stop Iran Tunnel"
        echo -e "3. Start Foreign Tunnel"
        echo -e "4. Stop Foreign Tunnel"
        echo -e "5. View Logs"
        echo -e "6. Restart All"
        echo -e "7. Back to Main Menu"
        echo ""
        
        read -p "Select option [1-7]: " choice
        
        case $choice in
            1)
                systemctl start rathole-iran
                systemctl status rathole-iran --no-pager
                ;;
            2)
                systemctl stop rathole-iran
                echo -e "${YELLOW}Iran tunnel stopped${NC}"
                ;;
            3)
                systemctl start rathole-foreign
                systemctl status rathole-foreign --no-pager
                ;;
            4)
                systemctl stop rathole-foreign
                echo -e "${YELLOW}Foreign tunnel stopped${NC}"
                ;;
            5)
                view_logs_menu
                ;;
            6)
                systemctl restart rathole-iran rathole-foreign 2>/dev/null || true
                echo -e "${GREEN}All services restarted${NC}"
                ;;
            7)
                return
                ;;
            *)
                echo -e "${RED}Invalid option!${NC}"
                ;;
        esac
        
        echo ""
        read -p "Press Enter to continue..."
    done
}

# View logs menu
view_logs_menu() {
    echo -e "${CYAN}VIEW LOGS${NC}"
    echo -e "${YELLOW}═════════════════════════════════════════════${NC}"
    
    echo -e "1. Iran Tunnel Logs"
    echo -e "2. Foreign Tunnel Logs"
    echo -e "3. Error Logs"
    echo -e "4. Follow Logs (tail -f)"
    echo -e "5. Clear Logs"
    echo ""
    
    read -p "Select option [1-5]: " choice
    
    case $choice in
        1)
            echo -e "${CYAN}Iran Tunnel Logs:${NC}"
            tail -50 "$LOG_DIR/rathole-iran.log" 2>/dev/null || \
            journalctl -u rathole-iran -n 50 --no-pager
            ;;
        2)
            echo -e "${CYAN}Foreign Tunnel Logs:${NC}"
            tail -50 "$LOG_DIR/rathole-foreign.log" 2>/dev/null || \
            journalctl -u rathole-foreign -n 50 --no-pager
            ;;
        3)
            echo -e "${CYAN}Error Logs:${NC}"
            tail -50 "$LOG_DIR/rathole-iran-error.log" 2>/dev/null || echo "No error logs"
            echo ""
            tail -50 "$LOG_DIR/rathole-foreign-error.log" 2>/dev/null || echo "No error logs"
            ;;
        4)
            echo -e "${YELLOW}Following logs (Ctrl+C to stop)...${NC}"
            tail -f "$LOG_DIR"/*.log 2>/dev/null || \
            echo "No logs to follow"
            ;;
        5)
            rm -f "$LOG_DIR"/*.log 2>/dev/null
            echo -e "${GREEN}Logs cleared${NC}"
            ;;
        *)
            echo -e "${RED}Invalid option!${NC}"
            ;;
    esac
}

# Initialize
initialize() {
    check_root
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$BACKUP_DIR"
}

# Main execution
initialize
main_menu
