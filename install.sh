#!/bin/bash

# ============================================================================
# MTPulse v2.2 - Enhanced MTProto Proxy Manager
# With High Stability and Multi-Proxy Management
# ============================================================================

# Define colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'
RESET='\033[0m'
BOLD_GREEN='\033[1;32m'
BOLD_RED='\033[1;31m'
BOLD_CYAN='\033[1;36m'
BOLD_YELLOW='\033[1;33m'
BOLD_MAGENTA='\033[1;35m'

# Global Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="/etc/mtpulse"
PROXY_DB="$CONFIG_DIR/proxies.db"  # Database of all proxies
LOG_DIR="/var/log/mtpulse"
SETUP_MARKER="$CONFIG_DIR/.setup_complete"
SCRIPT_VERSION="2.2.0"

# Error handling
set -euo pipefail
trap 'handle_error $LINENO' ERR

handle_error() {
    local line=$1
    echo -e "${RED}❌ Error occurred at line $line${RESET}"
    exit 1
}

# --- Helper Functions ---
print_success() { echo -e "${GREEN}✅ $1${RESET}"; }
print_error() { echo -e "${RED}❌ $1${RESET}"; }
print_info() { echo -e "${CYAN}ℹ️  $1${RESET}"; }
print_warning() { echo -e "${YELLOW}⚠️  $1${RESET}"; }

draw_line() {
    local color="$1"
    local char="${2:-=}"
    local length="${3:-60}"
    printf "${color}"
    printf "%${length}s" | tr " " "$char"
    printf "${RESET}\n"
}

# --- Database Functions (For Storing Proxies) ---
init_database() {
    sudo mkdir -p "$CONFIG_DIR" "$LOG_DIR"
    
    if [ ! -f "$PROXY_DB" ]; then
        sudo cat > "$PROXY_DB" <<EOF
# MTPulse Proxies Database
# Format: NAME|PORT|SECRET|TAG|STATUS|CREATED_AT|LAST_CHECK
EOF
        sudo chmod 600 "$PROXY_DB"
    fi
}

add_proxy_to_db() {
    local name="$1"
    local port="$2"
    local secret="$3"
    local tag="${4:-}"
    local created_at=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "$name|$port|$secret|$tag|ACTIVE|$created_at|$created_at" | sudo tee -a "$PROXY_DB" > /dev/null
    print_success "Proxy $name added to database"
}

remove_proxy_from_db() {
    local name="$1"
    sudo sed -i "/^$name|/d" "$PROXY_DB"
    print_success "Proxy $name removed from database"
}

list_proxies() {
    if [ ! -s "$PROXY_DB" ]; then
        print_warning "No proxies registered"
        return 1
    fi
    
    echo -e "${BOLD_CYAN}┌─────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${BOLD_CYAN}│                    Active Proxies List                      │${RESET}"
    echo -e "${BOLD_CYAN}├──────────┬──────┬──────────────────────────────┬─────────────┤${RESET}"
    echo -e "${BOLD_CYAN}│   Name   │ Port │           Status            │ Created Date │${RESET}"
    echo -e "${BOLD_CYAN}├──────────┼──────┼──────────────────────────────┼─────────────┤${RESET}"
    
    local count=0
    while IFS='|' read -r name port secret tag status created_at last_check; do
        # Skip comment lines
        [[ "$name" =~ ^# ]] && continue
        
        local status_color=$GREEN
        [[ "$status" != "ACTIVE" ]] && status_color=$RED
        
        # Check if service is actually running
        if systemctl is-active --quiet "mtpulse-$name"; then
            status_color=$GREEN
            status="✅ Active"
        else
            status_color=$RED
            status="❌ Inactive"
        fi
        
        printf "${WHITE}│ %-8s │ %-4s │ ${status_color}%-26s${WHITE} │ %-11s │\n" \
            "$name" "$port" "$status" "$created_at"
        ((count++))
    done < "$PROXY_DB"
    
    echo -e "${BOLD_CYAN}└──────────┴──────┴──────────────────────────────┴─────────────┘${RESET}"
    echo -e "Total Proxies: ${BOLD_GREEN}$count${RESET}"
    return 0
}

# --- Stability Improvements ---
install_stability_tweaks() {
    print_info "Installing stability tweaks..."
    
    # Increase system limits
    cat <<EOF | sudo tee /etc/sysctl.d/99-mtpulse.conf > /dev/null
# MTPulse Stability Tweaks
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 65536
net.core.wmem_default = 65536
net.core.netdev_max_backlog = 4096
net.core.somaxconn = 4096
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
EOF
    
    sudo sysctl -p /etc/sysctl.d/99-mtpulse.conf
    
    # Create logrotate for better log management
    cat <<EOF | sudo tee /etc/logrotate.d/mtpulse > /dev/null
/var/log/mtpulse/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
    sharedscripts
    postrotate
        systemctl reload mtpulse-* 2>/dev/null || true
    endscript
}
EOF
    
    print_success "Stability tweaks applied"
}

# --- Install MTProxy from Source (ARM Compatible) ---
install_mtproxy_from_source() {
    print_info "Compiling MTProxy from source with ARM compatibility..."
    
    # Install compilation dependencies
    sudo apt install -y git make build-essential libssl-dev zlib1g-dev gcc
    
    # Clone repository
    local temp_dir=$(mktemp -d)
    cd "$temp_dir"
    
    git clone https://github.com/TelegramMessenger/MTProxy.git
    cd MTProxy
    
    # Apply ARM compatibility patches
    print_info "Applying ARM compatibility patches..."
    
    # Patch 1: Fix PID assertion
    if [ -f "common/pid.c" ]; then
        sed -i 's/assert (!(p & 0xffff0000));/\/\/ assert (!(p \& 0xffff0000));/g' common/pid.c
    fi
    
    # Patch 2: Remove ALL SSE/SSE2/SSE3 flags for ARM
    if [ -f "Makefile" ]; then
        # Remove all SSE and x86 specific flags
        sed -i 's/-march=core2//g' Makefile
        sed -i 's/-mfpmath=sse//g' Makefile
        sed -i 's/-mssse3//g' Makefile
        sed -i 's/-msse4.2//g' Makefile
        sed -i 's/-mpclmul//g' Makefile
        sed -i 's/-msse2//g' Makefile
        sed -i 's/-msse//g' Makefile
        sed -i 's/-msse3//g' Makefile
        
        # Add generic optimization flags for ARM
        local cpu_arch=$(uname -m)
        if [[ "$cpu_arch" == "aarch64" || "$cpu_arch" == "arm64" ]]; then
            sed -i 's/CFLAGS = /CFLAGS = -O2 -pipe -fno-strict-aliasing -fno-strict-overflow -fwrapv /' Makefile
        else
            sed -i 's/CFLAGS = /CFLAGS = -O2 -pipe -fno-strict-aliasing -fno-strict-overflow -fwrapv /' Makefile
        fi
    fi
    
    # Patch 3: COMPLETELY DISABLE SSE intrinsics in crc32c.c for ARM
    if [ -f "common/crc32c.c" ]; then
        # Create backup
        cp common/crc32c.c common/crc32c.c.backup
        
        # Disable SSE completely by commenting out the problematic function
        sed -i 's/^#ifdef __SSE4_2__$/#if 0/' common/crc32c.c
        sed -i 's/^#if defined(__SSE4_2__) \&\& defined(__PCLMUL__)$/#if 0/' common/crc32c.c
        sed -i 's/^#ifdef __x86_64__$/#if 0/' common/crc32c.c
        
        # Also disable any SSE function definitions
        sed -i 's/^.*__builtin_ia32_pclmulqdq128.*$/\/* SSE disabled for ARM compatibility *\//' common/crc32c.c
        sed -i 's/^.*_mm_crc32_u64.*$/\/* SSE disabled for ARM compatibility *\//' common/crc32c.c
        sed -i 's/^.*_mm_crc32_u32.*$/\/* SSE disabled for ARM compatibility *\//' common/crc32c.c
        sed -i 's/^.*_mm_crc32_u16.*$/\/* SSE disabled for ARM compatibility *\//' common/crc32c.c
        sed -i 's/^.*_mm_crc32_u8.*$/\/* SSE disabled for ARM compatibility *\//' common/crc32c.c
    fi
    
    # Patch 4: Fix rdtsc for ARM
    if [ -f "common/kprintf.h" ] && ! grep -q "static inline long long rdtsc" common/kprintf.h; then
        echo -e "\nstatic inline long long rdtsc (void) { return 0; }" >> common/kprintf.h
    fi
    
    # Patch 5: Fix sockaddr casting warnings
    if [ -f "net/net-tcp-rpc-ext-server.c" ]; then
        sed -i 's/connect (sockets\[i\], \&addr, sizeof (addr))/connect (sockets\[i\], (struct sockaddr *)\&addr, sizeof (addr))/g' net/net-tcp-rpc-ext-server.c
        sed -i 's/connect (sockets\[i\], \&addr6, sizeof (addr6))/connect (sockets\[i\], (struct sockaddr *)\&addr6, sizeof (addr6))/g' net/net-tcp-rpc-ext-server.c
    fi
    
    # Clean previous builds
    make clean 2>/dev/null || true
    
    # Compile with simplified flags
    print_info "Compiling MTProxy (this may take 2-3 minutes)..."
    
    # Show compilation progress
    echo -e "${YELLOW}Compilation in progress... Please wait.${RESET}"
    
    # Run make with reduced output
    if make -j$(nproc) > /tmp/mtpulse_compile.log 2>&1; then
        if [ -f "objs/bin/mtproto-proxy" ]; then
            print_success "Compilation successful!"
        else
            print_error "Compilation completed but binary not found"
            echo -e "${YELLOW}--- Compilation Log (last 30 lines) ---${RESET}"
            tail -30 /tmp/mtpulse_compile.log
            cd "$SCRIPT_DIR"
            rm -rf "$temp_dir"
            return 1
        fi
    else
        print_error "Compilation failed"
        echo -e "${YELLOW}--- Compilation Log (last 30 lines) ---${RESET}"
        tail -30 /tmp/mtpulse_compile.log
        
        # Try alternative compilation method
        print_info "Trying alternative compilation method..."
        make clean 2>/dev/null || true
        
        # Try with even simpler flags
        if make CFLAGS="-O2 -pipe" -j$(nproc) > /tmp/mtpulse_compile2.log 2>&1; then
            if [ -f "objs/bin/mtproto-proxy" ]; then
                print_success "Alternative compilation successful!"
            else
                print_error "Alternative compilation also failed"
                cd "$SCRIPT_DIR"
                rm -rf "$temp_dir"
                return 1
            fi
        else
            print_error "All compilation attempts failed"
            cd "$SCRIPT_DIR"
            rm -rf "$temp_dir"
            return 1
        fi
    fi
    
    # Install
    sudo cp objs/bin/mtproto-proxy /usr/local/bin/mtproto-proxy
    sudo chmod +x /usr/local/bin/mtproto-proxy
    
    # Cleanup
    cd "$SCRIPT_DIR"
    rm -rf "$temp_dir"
    
    print_success "MTProxy compiled and installed successfully"
    return 0
}

# --- Install Precompiled Binary or Compile ---
install_mtproxy() {
    clear
    echo ""
    draw_line "$CYAN" "=" 60
    echo -e "${BOLD_GREEN}     📥 Installing MTProto Proxy${RESET}"
    draw_line "$CYAN" "=" 60
    echo ""
    
    # Check existing installation
    if [ -f "/usr/local/bin/mtproto-proxy" ]; then
        print_info "MTProxy is already installed"
        echo -e -n "👉 ${BOLD_MAGENTA}Do you want to reinstall? (y/N): ${RESET}"
        read reinstall
        if [[ ! "$reinstall" =~ ^[Yy]$ ]]; then
            return 0
        fi
    fi
    
    # Install dependencies
    print_info "Installing prerequisites..."
    sudo apt update
    sudo apt install -y curl wget tar xxd git make build-essential libssl-dev zlib1g-dev
    
    # Try to find precompiled binary first
    local cpu_arch=$(uname -m)
    print_info "Detected architecture: $cpu_arch"
    
    # Try to download precompiled binary
    print_info "Looking for precompiled binary..."
    
    local download_url=""
    case "$cpu_arch" in
        "x86_64")
            download_url="https://github.com/TelegramMessenger/MTProxy/releases/latest/download/mtproto-proxy"
            ;;
        "aarch64"|"arm64")
            download_url="https://github.com/TelegramMessenger/MTProxy/releases/latest/download/mtproto-proxy-arm64"
            ;;
        "armv7l"|"armhf")
            download_url="https://github.com/TelegramMessenger/MTProxy/releases/latest/download/mtproto-proxy-arm"
            ;;
    esac
    
    if [ -n "$download_url" ]; then
        print_info "Downloading precompiled binary..."
        if sudo curl -L -o /usr/local/bin/mtproto-proxy "$download_url" 2>/dev/null; then
            sudo chmod +x /usr/local/bin/mtproto-proxy
            
            # Test the binary
            if /usr/local/bin/mtproto-proxy --help 2>&1 | grep -q "MTProto Proxy"; then
                print_success "Precompiled binary installed successfully"
            else
                print_warning "Precompiled binary may be corrupted, trying compilation..."
                sudo rm -f /usr/local/bin/mtproto-proxy
                install_mtproxy_from_source
            fi
        else
            print_warning "Failed to download precompiled binary, trying compilation..."
            install_mtproxy_from_source
        fi
    else
        print_warning "No precompiled binary available for $cpu_arch, compiling from source..."
        install_mtproxy_from_source
    fi
    
    # If installation succeeded, download configs
    if [ -f "/usr/local/bin/mtproto-proxy" ]; then
        # Download latest configs
        print_info "Downloading latest config files..."
        sudo mkdir -p "$CONFIG_DIR"
        sudo curl -s --max-time 30 https://core.telegram.org/getProxySecret -o "$CONFIG_DIR/proxy-secret"
        sudo curl -s --max-time 30 https://core.telegram.org/getProxyConfig -o "$CONFIG_DIR/proxy-multi.conf"
        
        # Install stability tweaks
        install_stability_tweaks
        
        return 0
    else
        print_error "MTProxy installation failed"
        return 1
    fi
}

# --- Create Proxy with Stability Features ---
create_proxy() {
    clear
    echo ""
    draw_line "$GREEN" "=" 60
    echo -e "${BOLD_GREEN}     🚀 Create New Proxy${RESET}"
    draw_line "$GREEN" "=" 60
    echo ""
    
    # First check if MTProxy is installed
    if [ ! -f "/usr/local/bin/mtproto-proxy" ]; then
        print_error "MTProxy is not installed. Please install it first (Option 1)."
        echo -e "${BOLD_MAGENTA}Press Enter to continue...${RESET}"
        read
        return 1
    fi
    
    # Proxy name
    local proxy_name
    while true; do
        echo -e -n "👉 ${BOLD_MAGENTA}Proxy name (letters, numbers, - and _ only): ${RESET}"
        read proxy_name
        if [[ "$proxy_name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
            # Check if name exists
            if grep -q "^$proxy_name|" "$PROXY_DB" 2>/dev/null; then
                print_error "This name is already used"
            else
                break
            fi
        else
            print_error "Invalid name. Use only letters, numbers, - and _"
        fi
    done
    
    # Port
    local port
    while true; do
        echo -e -n "👉 ${BOLD_MAGENTA}Port (default 443): ${RESET}"
        read port
        port=${port:-443}
        
        # Validate port
        if [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )); then
            # Check port availability
            if ss -tuln 2>/dev/null | grep -q ":$port "; then
                print_error "Port $port is already in use"
            else
                break
            fi
        else
            print_error "Invalid port. Must be 1-65535"
        fi
    done
    
    # Generate strong secret
    local secret=$(openssl rand -hex 16 2>/dev/null || head -c 32 /dev/urandom | xxd -ps)
    echo -e "Secret: ${WHITE}$secret${RESET}"
    
    # AD Tag (optional)
    local tag=""
    echo -e -n "👉 ${BOLD_MAGENTA}AD Tag (optional, press Enter to skip): ${RESET}"
    read tag
    
    # Create proxy directory
    local proxy_dir="$CONFIG_DIR/proxies/$proxy_name"
    sudo mkdir -p "$proxy_dir"
    
    # Get public IP
    local public_ip=$(curl -s --max-time 5 https://api.ipify.org || echo "127.0.0.1")
    
    # Create enhanced service file
    print_info "Creating service..."
    
    local service_file="/etc/systemd/system/mtpulse-$proxy_name.service"
    
    # Build ExecStart command
    local exec_start="/usr/local/bin/mtproto-proxy -u nobody -p 8888 -H $port -S $secret --aes-pwd $CONFIG_DIR/proxy-secret $CONFIG_DIR/proxy-multi.conf -M 1"
    
    # Add optional parameters
    if [[ -n "$tag" ]]; then
        exec_start="$exec_start -P $tag"
    fi
    
    # Add stability options
    exec_start="$exec_start --tcp-fast-open --nat-info $public_ip:$port --verbosity 0"
    
    cat <<EOF | sudo tee "$service_file" > /dev/null
[Unit]
Description=MTPulse Proxy - $proxy_name (Port: $port)
After=network.target
StartLimitIntervalSec=500
StartLimitBurst=5

[Service]
Type=exec
User=nobody
Group=nogroup
WorkingDirectory=/tmp
Environment="UV_THREADPOOL_SIZE=16"
LimitNOFILE=1048576
LimitNPROC=65536
LimitCORE=infinity
OOMScoreAdjust=-100
Nice=-5

# Stability directives
Restart=always
RestartSec=10
StartLimitInterval=0
KillSignal=SIGTERM
TimeoutStopSec=90
KillMode=process

# Logging
StandardOutput=append:$LOG_DIR/$proxy_name.log
StandardError=append:$LOG_DIR/$proxy_name-error.log
SyslogIdentifier=mtpulse-$proxy_name

# Main command
ExecStart=$exec_start

ExecReload=/bin/kill -HUP \$MAINPID

[Install]
WantedBy=multi-user.target
EOF
    
    # Create health check script
    local health_script="$proxy_dir/health-check.sh"
    cat <<'EOF' | sudo tee "$health_script" > /dev/null
#!/bin/bash
# Health check script for MTProxy

PROXY_NAME="$1"
PORT="$2"
LOG_DIR="/var/log/mtpulse"

# Check if port is listening
if ss -tln 2>/dev/null | grep -q ":$PORT "; then
    echo "$(date): Port $PORT is listening" >> "$LOG_DIR/$PROXY_NAME-health.log"
    exit 0
else
    echo "$(date): Port $PORT not listening" >> "$LOG_DIR/$PROXY_NAME-health.log"
    exit 1
fi
EOF
    
    sudo chmod +x "$health_script"
    
    # Create monitoring timer
    cat <<EOF | sudo tee "/etc/systemd/system/mtpulse-$proxy_name-monitor.timer" > /dev/null
[Unit]
Description=Health monitoring for $proxy_name
Requires=mtpulse-$proxy_name.service

[Timer]
OnUnitActiveSec=60s
OnBootSec=60s

[Install]
WantedBy=timers.target
EOF
    
    cat <<EOF | sudo tee "/etc/systemd/system/mtpulse-$proxy_name-monitor.service" > /dev/null
[Unit]
Description=Health monitor for $proxy_name
After=mtpulse-$proxy_name.service

[Service]
Type=oneshot
ExecStart=$health_script $proxy_name $port
EOF
    
    # Enable and start
    sudo systemctl daemon-reload
    sudo systemctl enable "mtpulse-$proxy_name.service"
    sudo systemctl enable "mtpulse-$proxy_name-monitor.timer"
    
    # Start service
    print_info "Starting proxy service..."
    if sudo systemctl start "mtpulse-$proxy_name.service"; then
        print_success "Proxy service started"
        sudo systemctl start "mtpulse-$proxy_name-monitor.timer"
    else
        print_error "Failed to start proxy service"
        echo -e "${YELLOW}Checking service status...${RESET}"
        sudo systemctl status "mtpulse-$proxy_name.service" --no-pager -l
        echo -e "${YELLOW}Checking binary permissions...${RESET}"
        ls -la /usr/local/bin/mtproto-proxy
        return 1
    fi
    
    # Add to database
    add_proxy_to_db "$proxy_name" "$port" "$secret" "$tag"
    
    clear
    echo ""
    draw_line "$BOLD_GREEN" "=" 60
    echo -e "${BOLD_GREEN}     🎉 Proxy Created Successfully!${RESET}"
    draw_line "$BOLD_GREEN" "=" 60
    echo ""
    echo -e "  ${CYAN}Proxy Name:${RESET} ${WHITE}$proxy_name${RESET}"
    echo -e "  ${CYAN}Server IP:${RESET} ${WHITE}$public_ip${RESET}"
    echo -e "  ${CYAN}Port:${RESET} ${WHITE}$port${RESET}"
    echo -e "  ${CYAN}Secret:${RESET} ${WHITE}$secret${RESET}"
    if [[ -n "$tag" ]]; then
        echo -e "  ${CYAN}AD Tag:${RESET} ${MAGENTA}$tag${RESET}"
    fi
    echo ""
    echo -e "${BOLD_CYAN}Connection Link:${RESET}"
    echo -e "tg://proxy?server=$public_ip&port=$port&secret=$secret"
    echo ""
    echo -e "${BOLD_CYAN}Alternative Link:${RESET}"
    echo -e "https://t.me/proxy?server=$public_ip&port=$port&secret=$secret"
    echo ""
    draw_line "$CYAN" "-" 60
    echo -e "${YELLOW}📊 Service Status:${RESET}"
    sudo systemctl status "mtpulse-$proxy_name.service" --no-pager -l | head -20
    echo ""
    
    echo -e "${BOLD_MAGENTA}Press Enter to continue...${RESET}"
    read
}

# --- Complete Uninstall ---
complete_uninstall() {
    clear
    echo ""
    draw_line "$RED" "=" 60
    echo -e "${BOLD_RED}     🗑️  Complete Uninstall MTPulse${RESET}"
    draw_line "$RED" "=" 60
    echo ""
    
    echo -e "${RED}⚠️  ⚠️  ⚠️  WARNING: This will remove ALL MTPulse components!${RESET}"
    echo ""
    echo -e "This will remove:"
    echo -e "  ${RED}•${RESET} All MTProxy services and timers"
    echo -e "  ${RED}•${RESET} All proxy configurations"
    echo -e "  ${RED}•${RESET} MTPulse database and logs"
    echo -e "  ${RED}•${RESET} MTProxy binary"
    echo -e "  ${RED}•${RESET} All configuration files"
    echo ""
    
    echo -e -n "👉 ${BOLD_MAGENTA}Are you ABSOLUTELY sure? Type 'DELETE' to confirm: ${RESET}"
    read confirmation
    
    if [ "$confirmation" != "DELETE" ]; then
        print_info "Uninstall cancelled"
        echo -e "${BOLD_MAGENTA}Press Enter to continue...${RESET}"
        read
        return
    fi
    
    print_info "Starting complete uninstall..."
    
    # Step 1: Stop and remove all proxy services
    print_info "Stopping all proxy services..."
    
    if [ -f "$PROXY_DB" ]; then
        while IFS='|' read -r name port secret tag status created_at last_check; do
            [[ "$name" =~ ^# ]] && continue
            
            sudo systemctl stop "mtpulse-$name.service" 2>/dev/null || true
            sudo systemctl stop "mtpulse-$name-monitor.timer" 2>/dev/null || true
            sudo systemctl disable "mtpulse-$name.service" 2>/dev/null || true
            sudo systemctl disable "mtpulse-$name-monitor.timer" 2>/dev/null || true
            sudo systemctl disable "mtpulse-$name-monitor.service" 2>/dev/null || true
            
            sudo rm -f "/etc/systemd/system/mtpulse-$name.service"
            sudo rm -f "/etc/systemd/system/mtpulse-$name-monitor.timer"
            sudo rm -f "/etc/systemd/system/mtpulse-$name-monitor.service"
            
            print_success "Removed service for $name"
        done < "$PROXY_DB"
    fi
    
    # Step 2: Remove MTProxy binary
    print_info "Removing MTProxy binary..."
    sudo rm -f /usr/local/bin/mtproto-proxy
    
    # Step 3: Remove all configuration files
    print_info "Removing configuration files..."
    sudo rm -rf "$CONFIG_DIR"
    
    # Step 4: Remove logs
    print_info "Removing logs..."
    sudo rm -rf "$LOG_DIR"
    
    # Step 5: Remove systemd configs
    print_info "Removing systemd configurations..."
    sudo rm -f /etc/sysctl.d/99-mtpulse.conf
    sudo rm -f /etc/logrotate.d/mtpulse
    sudo rm -f /etc/security/limits.d/99-mtpulse.conf
    sudo rm -f /etc/systemd/system.conf.d/99-mtpulse.conf
    sudo rm -f /etc/sysctl.d/98-mtpulse-network.conf
    sudo rm -f /etc/sysctl.d/97-mtpulse-kernel.conf
    
    # Step 6: Reload systemd
    sudo systemctl daemon-reload
    
    # Step 7: Apply original sysctl settings
    print_info "Restoring network settings..."
    sudo sysctl -p 2>/dev/null || true
    
    # Step 8: Clean up any leftover source directories
    print_info "Cleaning up source directories..."
    if [ -d "MTProxy" ]; then
        rm -rf MTProxy
    fi
    
    print_success "✅ MTPulse completely uninstalled!"
    echo ""
    echo -e "${YELLOW}All MTPulse components have been removed from your system.${RESET}"
    echo -e "${YELLOW}You can now reinstall fresh if needed.${RESET}"
    echo ""
    
    echo -e "${BOLD_MAGENTA}Press Enter to continue...${RESET}"
    read
}

# --- Proxy Management ---
manage_proxy() {
    clear
    echo ""
    draw_line "$CYAN" "=" 60
    echo -e "${BOLD_GREEN}     ⚙️ Proxy Management${RESET}"
    draw_line "$CYAN" "=" 60
    echo ""
    
    if ! list_proxies; then
        echo -e "${BOLD_MAGENTA}Press Enter to continue...${RESET}"
        read
        return
    fi
    
    echo ""
    echo -e "  ${BOLD_CYAN}1)${RESET} ${WHITE}View Proxy Details${RESET}"
    echo -e "  ${BOLD_CYAN}2)${RESET} ${WHITE}Restart Proxy${RESET}"
    echo -e "  ${BOLD_CYAN}3)${RESET} ${WHITE}Stop Proxy${RESET}"
    echo -e "  ${BOLD_CYAN}4)${RESET} ${WHITE}Delete Proxy${RESET}"
    echo -e "  ${BOLD_CYAN}5)${RESET} ${WHITE}View Logs${RESET}"
    echo -e "  ${BOLD_CYAN}6)${RESET} ${WHITE}View Statistics${RESET}"
    echo -e "  ${BOLD_CYAN}0)${RESET} ${WHITE}Back${RESET}"
    echo ""
    draw_line "$CYAN" "-" 60
    
    echo -e -n "👉 ${BOLD_MAGENTA}Select: ${RESET}"
    read mgmt_choice
    
    case $mgmt_choice in
        1)
            echo -e -n "👉 ${BOLD_MAGENTA}Proxy name: ${RESET}"
            read proxy_name
            show_proxy_details "$proxy_name"
            ;;
        2)
            echo -e -n "👉 ${BOLD_MAGENTA}Proxy name: ${RESET}"
            read proxy_name
            sudo systemctl restart "mtpulse-$proxy_name.service"
            print_success "Proxy $proxy_name restarted"
            ;;
        3)
            echo -e -n "👉 ${BOLD_MAGENTA}Proxy name: ${RESET}"
            read proxy_name
            sudo systemctl stop "mtpulse-$proxy_name.service"
            sudo systemctl stop "mtpulse-$proxy_name-monitor.timer"
            print_success "Proxy $proxy_name stopped"
            ;;
        4)
            echo -e -n "👉 ${BOLD_MAGENTA}Proxy name: ${RESET}"
            read proxy_name
            delete_proxy "$proxy_name"
            ;;
        5)
            echo -e -n "👉 ${BOLD_MAGENTA}Proxy name: ${RESET}"
            read proxy_name
            show_proxy_logs "$proxy_name"
            ;;
        6)
            echo -e -n "👉 ${BOLD_MAGENTA}Proxy name: ${RESET}"
            read proxy_name
            show_proxy_stats "$proxy_name"
            ;;
        0)
            return
            ;;
        *)
            print_error "Invalid selection"
            ;;
    esac
    
    echo -e "${BOLD_MAGENTA}Press Enter to continue...${RESET}"
    read
}

show_proxy_details() {
    local proxy_name="$1"
    
    # Get from database
    local proxy_info=$(grep "^$proxy_name|" "$PROXY_DB" 2>/dev/null)
    if [ -z "$proxy_info" ]; then
        print_error "Proxy not found"
        return
    fi
    
    IFS='|' read -r name port secret tag status created_at last_check <<< "$proxy_info"
    
    clear
    echo ""
    draw_line "$BOLD_CYAN" "=" 60
    echo -e "${BOLD_GREEN}     📋 Proxy Details: $name${RESET}"
    draw_line "$BOLD_CYAN" "=" 60
    echo ""
    
    # Basic info
    echo -e "  ${CYAN}📌 Basic Information:${RESET}"
    echo -e "    Name: ${WHITE}$name${RESET}"
    echo -e "    Port: ${WHITE}$port${RESET}"
    if systemctl is-active --quiet "mtpulse-$name"; then
        echo -e "    Status: ${GREEN}Active${RESET}"
    else
        echo -e "    Status: ${RED}Inactive${RESET}"
    fi
    echo -e "    Created: ${WHITE}$created_at${RESET}"
    if [ -n "$tag" ]; then
        echo -e "    AD Tag: ${MAGENTA}$tag${RESET}"
    fi
    
    echo ""
    
    # Service status
    echo -e "  ${CYAN}📊 Service Status:${RESET}"
    sudo systemctl status "mtpulse-$name" --no-pager | head -20
    
    echo ""
    
    # Connection info
    echo -e "  ${CYAN}🔗 Connection Information:${RESET}"
    local public_ip=$(curl -s --max-time 3 https://api.ipify.org || echo "Unknown")
    echo -e "    IP: ${WHITE}$public_ip${RESET}"
    echo -e "    Secret: ${WHITE}$secret${RESET}"
    echo ""
    echo -e "    ${BOLD_GREEN}Connection Link:${RESET}"
    echo -e "    tg://proxy?server=$public_ip&port=$port&secret=$secret"
    
    echo ""
    draw_line "$CYAN" "-" 60
}

delete_proxy() {
    local proxy_name="$1"
    
    echo -e "${RED}⚠️  Are you sure you want to delete proxy '$proxy_name'? (y/N): ${RESET}"
    read confirm
    
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        print_info "Deleting proxy $proxy_name..."
        
        # Stop services
        sudo systemctl stop "mtpulse-$proxy_name.service" 2>/dev/null || true
        sudo systemctl stop "mtpulse-$proxy_name-monitor.timer" 2>/dev/null || true
        sudo systemctl disable "mtpulse-$proxy_name.service" 2>/dev/null || true
        sudo systemctl disable "mtpulse-$proxy_name-monitor.timer" 2>/dev/null || true
        
        # Remove service files
        sudo rm -f "/etc/systemd/system/mtpulse-$proxy_name.service"
        sudo rm -f "/etc/systemd/system/mtpulse-$proxy_name-monitor.timer"
        sudo rm -f "/etc/systemd/system/mtpulse-$proxy_name-monitor.service"
        
        # Remove config directory
        sudo rm -rf "$CONFIG_DIR/proxies/$proxy_name"
        
        # Remove from database
        remove_proxy_from_db "$proxy_name"
        
        # Reload systemd
        sudo systemctl daemon-reload
        
        print_success "Proxy $proxy_name deleted successfully"
    else
        print_info "Deletion cancelled"
    fi
}

show_proxy_logs() {
    local proxy_name="$1"
    
    clear
    echo ""
    draw_line "$CYAN" "=" 60
    echo -e "${BOLD_GREEN}     📝 Logs for $proxy_name${RESET}"
    draw_line "$CYAN" "=" 60
    echo ""
    
    echo -e "${YELLOW}--- Service Logs (Last 50 lines) ---${RESET}"
    sudo journalctl -u "mtpulse-$proxy_name" -n 50 --no-pager
    
    echo ""
    echo -e "${YELLOW}--- Error Logs ---${RESET}"
    if [ -f "$LOG_DIR/$proxy_name-error.log" ]; then
        sudo tail -n 50 "$LOG_DIR/$proxy_name-error.log"
    else
        echo "No error logs found"
    fi
    
    echo ""
    echo -e "${YELLOW}--- Health Check Logs ---${RESET}"
    if [ -f "$LOG_DIR/$proxy_name-health.log" ]; then
        sudo tail -n 50 "$LOG_DIR/$proxy_name-health.log"
    else
        echo "No health logs found"
    fi
}

show_proxy_stats() {
    local proxy_name="$1"
    
    # Check if service exists
    if ! systemctl is-enabled "mtpulse-$proxy_name" 2>/dev/null; then
        print_error "Proxy $proxy_name not found"
        return
    fi
    
    clear
    echo ""
    draw_line "$MAGENTA" "=" 60
    echo -e "${BOLD_GREEN}     📊 Statistics for $proxy_name${RESET}"
    draw_line "$MAGENTA" "=" 60
    echo ""
    
    # Get PID
    local pid=$(systemctl show "mtpulse-$proxy_name" --property=MainPID --value 2>/dev/null)
    
    if [[ -z "$pid" || "$pid" -eq 0 ]]; then
        print_error "Proxy is not running"
        return
    fi
    
    # Memory usage
    if [ -f "/proc/$pid/status" ]; then
        local vm_size=$(grep VmSize "/proc/$pid/status" 2>/dev/null | awk '{printf "%.1f MB", $2/1024}')
        local vm_rss=$(grep VmRSS "/proc/$pid/status" 2>/dev/null | awk '{printf "%.1f MB", $2/1024}')
        echo -e "${CYAN}Memory Usage:${RESET}"
        echo -e "  Virtual Memory: ${WHITE}$vm_size${RESET}"
        echo -e "  Resident Memory: ${WHITE}$vm_rss${RESET}"
    fi
    
    # CPU usage
    echo ""
    echo -e "${CYAN}CPU Usage:${RESET}"
    ps -p "$pid" -o %cpu,etime,time --no-headers 2>/dev/null | awk '{print "  CPU: "$1"% | Uptime: "$2" | CPU Time: "$3}'
    
    # Connections
    echo ""
    echo -e "${CYAN}Network Connections:${RESET}"
    local connections=$(sudo ss -tnp 2>/dev/null | grep "pid=$pid" | wc -l)
    echo -e "  Active Connections: ${WHITE}$connections${RESET}"
    
    # Service uptime
    echo ""
    echo -e "${CYAN}Service Information:${RESET}"
    local start_time=$(systemctl show "mtpulse-$proxy_name" --property=ActiveEnterTimestamp --value 2>/dev/null)
    if [ -n "$start_time" ]; then
        echo -e "  Started: $start_time"
    else
        echo -e "  Started: Unknown"
    fi
    
    # Disk usage
    echo ""
    echo -e "${CYAN}Disk Usage:${RESET}"
    if [ -d "$CONFIG_DIR/proxies/$proxy_name" ]; then
        local disk_usage=$(sudo du -sh "$CONFIG_DIR/proxies/$proxy_name" 2>/dev/null | awk '{print $1}')
        echo -e "  Config: ${WHITE}$disk_usage${RESET}"
    else
        echo -e "  Config: Not found"
    fi
}

# --- Monitor All Proxies ---
monitor_all_proxies() {
    clear
    echo ""
    draw_line "$YELLOW" "=" 60
    echo -e "${BOLD_GREEN}     📡 Monitoring Proxy Status${RESET}"
    draw_line "$YELLOW" "=" 60
    echo ""
    
    if [ ! -s "$PROXY_DB" ]; then
        print_warning "No proxies to monitor"
        return
    fi
    
    echo -e "${CYAN}┌──────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${CYAN}│                     Live Status                              │${RESET}"
    echo -e "${CYAN}├──────────┬──────┬──────────┬────────────┬───────────────────┤${RESET}"
    echo -e "${CYAN}│   Name   │ Port │  Status  │   Memory   │      Uptime       │${RESET}"
    echo -e "${CYAN}├──────────┼──────┼──────────┼────────────┼───────────────────┤${RESET}"
    
    while IFS='|' read -r name port secret tag status created_at last_check; do
        [[ "$name" =~ ^# ]] && continue
        
        # Get PID
        local pid=$(systemctl show "mtpulse-$name" --property=MainPID --value 2>/dev/null)
        
        if [[ -n "$pid" && "$pid" -ne 0 ]]; then
            # Service is running
            local mem_usage=""
            local uptime=""
            
            # Get memory usage
            if [ -f "/proc/$pid/status" ]; then
                mem_usage=$(grep VmRSS "/proc/$pid/status" 2>/dev/null | awk '{printf "%.1f MB", $2/1024}' || echo "N/A")
            fi
            
            # Get uptime
            uptime=$(systemctl show "mtpulse-$name" --property=ActiveEnterTimestamp --value 2>/dev/null | \
                    awk '{print $2, $3}' || echo "Unknown")
            
            printf "${WHITE}│ ${GREEN}%-8s${WHITE} │ ${GREEN}%-4s${WHITE} │ ${GREEN}%-8s${WHITE} │ ${CYAN}%-10s${WHITE} │ ${YELLOW}%-17s${WHITE} │\n" \
                "$name" "$port" "Active" "$mem_usage" "$uptime"
        else
            # Service is not running
            printf "${WHITE}│ ${RED}%-8s${WHITE} │ ${RED}%-4s${WHITE} │ ${RED}%-8s${WHITE} │ ${RED}%-10s${WHITE} │ ${RED}%-17s${WHITE} │\n" \
                "$name" "$port" "Stopped" "---" "---"
        fi
    done < "$PROXY_DB"
    
    echo -e "${CYAN}└──────────┴──────┴──────────┴────────────┴───────────────────┘${RESET}"
    
    # Show system load
    echo ""
    echo -e "${CYAN}📊 System Status:${RESET}"
    echo -e "  System Load: $(uptime | awk -F'load average:' '{print $2}')"
    echo -e "  Free Memory: $(free -m | awk 'NR==2{printf "%.1f%%", $4*100/$2}')"
    echo -e "  Disk Space: $(df -h / | awk 'NR==2{print $4 " free"}')"
    
    echo ""
    echo -e "${BOLD_MAGENTA}Auto-refreshing every 10 seconds, press Ctrl+C to stop${RESET}"
    
    # Auto-refresh every 10 seconds
    for i in {1..6}; do
        echo -n "."
        sleep 10
    done
    
    monitor_all_proxies  # Recursive refresh
}

# --- Bulk Operations ---
bulk_operations() {
    clear
    echo ""
    draw_line "$MAGENTA" "=" 60
    echo -e "${BOLD_GREEN}     🔄 Bulk Operations${RESET}"
    draw_line "$MAGENTA" "=" 60
    echo ""
    
    echo -e "  ${BOLD_CYAN}1)${RESET} ${WHITE}Restart All Proxies${RESET}"
    echo -e "  ${BOLD_CYAN}2)${RESET} ${WHITE}Stop All Proxies${RESET}"
    echo -e "  ${BOLD_CYAN}3)${RESET} ${WHITE}Backup All Configs${RESET}"
    echo -e "  ${BOLD_CYAN}4)${RESET} ${WHITE}Update All Proxies${RESET}"
    echo -e "  ${BOLD_CYAN}0)${RESET} ${WHITE}Back${RESET}"
    echo ""
    
    echo -e -n "👉 ${BOLD_MAGENTA}Select: ${RESET}"
    read bulk_choice
    
    case $bulk_choice in
        1)
            restart_all_proxies
            ;;
        2)
            stop_all_proxies
            ;;
        3)
            backup_all_proxies
            ;;
        4)
            update_all_proxies
            ;;
        0)
            return
            ;;
        *)
            print_error "Invalid selection"
            ;;
    esac
}

restart_all_proxies() {
    print_info "Restarting all proxies..."
    
    while IFS='|' read -r name port secret tag status created_at last_check; do
        [[ "$name" =~ ^# ]] && continue
        
        sudo systemctl restart "mtpulse-$name" 2>/dev/null && \
            print_success "Proxy $name restarted" || \
            print_error "Error restarting $name"
    done < "$PROXY_DB"
}

stop_all_proxies() {
    print_info "Stopping all proxies..."
    
    while IFS='|' read -r name port secret tag status created_at last_check; do
        [[ "$name" =~ ^# ]] && continue
        
        sudo systemctl stop "mtpulse-$name" 2>/dev/null && \
            print_success "Proxy $name stopped" || \
            print_error "Error stopping $name"
    done < "$PROXY_DB"
}

# --- Backup and Restore ---
backup_all_proxies() {
    local backup_dir="$HOME/mtpulse-backup-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$backup_dir"
    
    print_info "Creating backup in $backup_dir..."
    
    # Backup database
    if [ -f "$PROXY_DB" ]; then
        sudo cp "$PROXY_DB" "$backup_dir/proxies.db"
    fi
    
    # Backup service files
    while IFS='|' read -r name port secret tag status created_at last_check; do
        [[ "$name" =~ ^# ]] && continue
        
        if [ -f "/etc/systemd/system/mtpulse-$name.service" ]; then
            sudo cp "/etc/systemd/system/mtpulse-$name.service" "$backup_dir/"
        fi
    done < "$PROXY_DB"
    
    # Backup configs
    if [ -d "$CONFIG_DIR" ]; then
        sudo cp -r "$CONFIG_DIR" "$backup_dir/config"
    fi
    
    # Create restore script
    cat > "$backup_dir/restore.sh" <<'EOF'
#!/bin/bash
# Restore MTPulse Proxies

set -e

echo "Starting restore process..."
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root"
    exit 1
fi

# Restore configs
if [ -d "config" ]; then
    cp -r config/* /etc/mtpulse/
    echo "Configs restored"
fi

# Restore database
if [ -f "proxies.db" ]; then
    cp proxies.db /etc/mtpulse/proxies.db
    echo "Database restored"
fi

# Restore services
for service_file in mtpulse-*.service; do
    if [ -f "$service_file" ]; then
        cp "$service_file" /etc/systemd/system/
        systemctl daemon-reload
        
        proxy_name=${service_file#mtpulse-}
        proxy_name=${proxy_name%.service}
        systemctl enable "mtpulse-$proxy_name" 2>/dev/null || true
        
        echo "Service $proxy_name restored"
    fi
done

echo ""
echo "Restore completed!"
echo "Run 'systemctl start mtpulse-<name>' to start each proxy"
EOF
    
    chmod +x "$backup_dir/restore.sh"
    
    # Create archive
    tar -czf "$backup_dir.tar.gz" -C "$backup_dir" .
    rm -rf "$backup_dir"
    
    print_success "Backup completed: $backup_dir.tar.gz"
    echo -e "${YELLOW}To restore, transfer file to new server and run restore.sh${RESET}"
    echo -e "${BOLD_MAGENTA}Press Enter to continue...${RESET}"
    read
}

update_all_proxies() {
    print_info "Updating all proxies..."
    
    # Update config files
    sudo curl -s --max-time 30 https://core.telegram.org/getProxySecret -o "$CONFIG_DIR/proxy-secret"
    sudo curl -s --max-time 30 https://core.telegram.org/getProxyConfig -o "$CONFIG_DIR/proxy-multi.conf"
    
    # Restart all proxies
    restart_all_proxies
    
    print_success "All proxies updated"
}

# --- System Optimization ---
optimize_system() {
    clear
    echo ""
    draw_line "$YELLOW" "=" 60
    echo -e "${BOLD_GREEN}     ⚡ System Optimization${RESET}"
    draw_line "$YELLOW" "=" 60
    echo ""
    
    echo -e "  ${BOLD_CYAN}1)${RESET} ${WHITE}Network Settings${RESET}"
    echo -e "  ${BOLD_CYAN}2)${RESET} ${WHITE}System Settings${RESET}"
    echo -e "  ${BOLD_CYAN}3)${RESET} ${WHITE}Firewall Configuration${RESET}"
    echo -e "  ${BOLD_CYAN}0)${RESET} ${WHITE}Back${RESET}"
    echo ""
    
    echo -e -n "👉 ${BOLD_MAGENTA}Select: ${RESET}"
    read opt_choice
    
    case $opt_choice in
        1)
            optimize_network
            ;;
        2)
            optimize_system_settings
            ;;
        3)
            configure_firewall
            ;;
        0)
            return
            ;;
        *)
            print_error "Invalid selection"
            ;;
    esac
}

optimize_network() {
    print_info "Optimizing network settings..."
    
    # Create network optimization
    cat <<EOF | sudo tee /etc/sysctl.d/98-mtpulse-network.conf > /dev/null
# Network optimization for MTProxy
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.optmem_max = 134217728
net.core.netdev_max_backlog = 100000
net.core.somaxconn = 100000
net.core.default_qdisc = fq
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 87380 134217728
net.ipv4.tcp_mtu_probing = 2
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_max_syn_backlog = 100000
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_sack = 1
EOF
    
    sudo sysctl -p /etc/sysctl.d/98-mtpulse-network.conf
    print_success "Network settings optimized"
}

optimize_system_settings() {
    print_info "Optimizing system settings..."
    
    # Increase file limits
    cat <<EOF | sudo tee /etc/security/limits.d/99-mtpulse.conf > /dev/null
# MTPulse file limits
* soft nofile 1048576
* hard nofile 1048576
* soft nproc 65536
* hard nproc 65536
root soft nofile 1048576
root hard nofile 1048576
EOF
    
    # Configure systemd for better performance
    cat <<EOF | sudo tee /etc/systemd/system.conf.d/99-mtpulse.conf > /dev/null
[Manager]
DefaultLimitNOFILE=1048576
DefaultLimitNPROC=65536
DefaultTasksMax=65536
EOF
    
    sudo systemctl daemon-reexec
    print_success "System settings optimized"
}

configure_firewall() {
    print_info "Configuring firewall..."
    
    # Get all proxy ports
    local ports=()
    while IFS='|' read -r name port secret tag status created_at last_check; do
        [[ "$name" =~ ^# ]] && continue
        ports+=("$port")
    done < "$PROXY_DB"
    
    # Configure UFW if available
    if command -v ufw &>/dev/null; then
        for port in "${ports[@]}"; do
            sudo ufw allow "$port/tcp"
        done
        sudo ufw reload
        print_success "Firewall configured for ports: ${ports[*]}"
    else
        print_warning "UFW not found. Please configure firewall manually"
    fi
}

# --- View Logs ---
view_logs() {
    clear
    echo ""
    draw_line "$MAGENTA" "=" 60
    echo -e "${BOLD_GREEN}     📝 View Logs${RESET}"
    draw_line "$MAGENTA" "=" 60
    echo ""
    
    echo -e "  ${BOLD_CYAN}1)${RESET} ${WHITE}Service Logs${RESET}"
    echo -e "  ${BOLD_CYAN}2)${RESET} ${WHITE}Error Logs${RESET}"
    echo -e "  ${BOLD_CYAN}3)${RESET} ${WHITE}Health Logs${RESET}"
    echo -e "  ${BOLD_CYAN}4)${RESET} ${WHITE}System Logs${RESET}"
    echo -e "  ${BOLD_CYAN}0)${RESET} ${WHITE}Back${RESET}"
    echo ""
    
    echo -e -n "👉 ${BOLD_MAGENTA}Select: ${RESET}"
    read log_choice
    
    case $log_choice in
        1)
            echo -e -n "👉 ${BOLD_MAGENTA}Proxy name: ${RESET}"
            read proxy_name
            sudo journalctl -u "mtpulse-$proxy_name" -n 50 --no-pager
            ;;
        2)
            echo -e -n "👉 ${BOLD_MAGENTA}Proxy name: ${RESET}"
            read proxy_name
            if [ -f "$LOG_DIR/$proxy_name-error.log" ]; then
                sudo tail -n 50 "$LOG_DIR/$proxy_name-error.log"
            else
                echo "No error logs found"
            fi
            ;;
        3)
            echo -e -n "👉 ${BOLD_MAGENTA}Proxy name: ${RESET}"
            read proxy_name
            if [ -f "$LOG_DIR/$proxy_name-health.log" ]; then
                sudo tail -n 50 "$LOG_DIR/$proxy_name-health.log"
            else
                echo "No health logs found"
            fi
            ;;
        4)
            sudo dmesg | tail -n 50
            ;;
        0)
            return
            ;;
        *)
            print_error "Invalid selection"
            ;;
    esac
    
    echo ""
    echo -e "${BOLD_MAGENTA}Press Enter to continue...${RESET}"
    read
}

# --- Main Menu ---
main_menu() {
    clear
    echo -e "${BOLD_CYAN}"
    cat << "EOF"
███╗   ███╗████████╗██████╗ ██████╗ ██╗   ██╗███████╗███████╗
████╗ ████║╚══██╔══╝██╔══██╗██╔══██╗██║   ██║██╔════╝██╔════╝
██╔████╔██║   ██║   ██████╔╝██████╔╝██║   ██║███████╗█████╗  
██║╚██╔╝██║   ██║   ██╔═══╝ ██╔═══╝ ██║   ██║╚════██║██╔══╝  
██║ ╚═╝ ██║   ██║   ██║     ██║     ╚██████╔╝███████║███████╗
╚═╝     ╚═╝   ╚═╝   ╚═╝     ╚═╝      ╚═════╝ ╚══════╝╚══════╝
EOF
    echo -e "${RESET}"
    draw_line "$CYAN" "=" 60
    echo -e "${BOLD_YELLOW}     Professional MTProto Proxy Manager with High Stability${RESET}"
    echo -e "${BOLD_YELLOW}     Developer: ErfanXRay - @Erfan_XRay${RESET}"
    draw_line "$CYAN" "=" 60
    echo ""
    
    # Show quick stats
    if [ -f "$PROXY_DB" ]; then
        local total_proxies=$(grep -v '^#' "$PROXY_DB" | wc -l)
        local active_proxies=0
        
        while IFS='|' read -r name port secret tag status created_at last_check; do
            [[ "$name" =~ ^# ]] && continue
            if systemctl is-active --quiet "mtpulse-$name"; then
                ((active_proxies++))
            fi
        done < "$PROXY_DB"
        
        echo -e "${CYAN}📊 Quick Stats:${RESET}"
        echo -e "  Total Proxies: ${WHITE}$total_proxies${RESET}"
        echo -e "  Active Proxies: ${GREEN}$active_proxies${RESET}"
        echo ""
    fi
    
    # Menu options
    echo -e "  ${BOLD_CYAN}1)${RESET} ${WHITE}Install/Update MTProxy${RESET}"
    echo -e "  ${BOLD_CYAN}2)${RESET} ${WHITE}Create New Proxy${RESET}"
    echo -e "  ${BOLD_CYAN}3)${RESET} ${WHITE}List Proxies${RESET}"
    echo -e "  ${BOLD_CYAN}4)${RESET} ${WHITE}Manage Proxy${RESET}"
    echo -e "  ${BOLD_CYAN}5)${RESET} ${WHITE}Monitor Status${RESET}"
    echo -e "  ${BOLD_CYAN}6)${RESET} ${WHITE}Bulk Operations${RESET}"
    echo -e "  ${BOLD_CYAN}7)${RESET} ${WHITE}Backup / Restore${RESET}"
    echo -e "  ${BOLD_CYAN}8)${RESET} ${WHITE}System Optimization${RESET}"
    echo -e "  ${BOLD_CYAN}9)${RESET} ${WHITE}View Logs${RESET}"
    echo -e "  ${BOLD_CYAN}10)${RESET} ${RED}Complete Uninstall${RESET}"
    echo -e "  ${BOLD_CYAN}0)${RESET} ${WHITE}Exit${RESET}"
    echo ""
    draw_line "$CYAN" "-" 60
    
    echo -e -n "👉 ${BOLD_MAGENTA}Select: ${RESET}"
}

# --- Main Program ---
main() {
    # Check OS
    if [ ! -f /etc/os-release ]; then
        print_error "Cannot detect operating system"
        exit 1
    fi
    
    source /etc/os-release
    if [[ "$ID" != "ubuntu" && "$ID" != "debian" ]]; then
        print_error "This script only supports Ubuntu and Debian"
        exit 1
    fi
    
    # Check root
    if [ "$EUID" -ne 0 ]; then 
        print_error "Please run as root: sudo bash $0"
        exit 1
    fi
    
    # Initialize
    init_database
    
    # Main loop
    while true; do
        main_menu
        read choice
        
        case $choice in
            1) install_mtproxy ;;
            2) create_proxy ;;
            3) list_proxies; echo -e "${BOLD_MAGENTA}Press Enter to continue...${RESET}"; read ;;
            4) manage_proxy ;;
            5) monitor_all_proxies ;;
            6) bulk_operations ;;
            7) backup_all_proxies ;;
            8) optimize_system ;;
            9) view_logs ;;
            10) complete_uninstall ;;
            0) 
                echo -e "${GREEN}Exiting...${RESET}"
                exit 0
                ;;
            *) 
                print_error "Invalid selection"
                sleep 1
                ;;
        esac
    done
}

# Start the script
main
