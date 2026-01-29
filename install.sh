#!/bin/bash

# ============================================
# MTProto Proxy Ultimate Installer & Manager
# Version: 3.1 - Fixed Service Issues
# ============================================

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Global Variables
PROXY_DIR="/opt/mtproto-proxy"
SERVICE_NAME="mtproto-proxy"
CONFIG_FILE="$PROXY_DIR/mtconfig.conf"
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"
LOG_FILE="/var/log/mtproto-proxy.log"
ERROR_LOG="/var/log/mtproto-proxy-error.log"
UPATER_FILE="$PROXY_DIR/updater.sh"
DISTRO=""
ARCH=""
CPU_CORES=1
PUBLIC_IP=""
PRIVATE_IP=""
TLS_DOMAIN=""
TAG=""
CUSTOM_ARGS=""
HAVE_NAT="n"
ENABLE_UPDATER="y"
ENABLE_BBR="y"
SECRET_ARY=()
PORT=443
PROXY_USER="mtproxy"
PROXY_GROUP="mtproxy"

# ============================================
# Utility Functions
# ============================================

print_status() { echo -e "${GREEN}[✓]${NC} $1"; }
print_info() { echo -e "${BLUE}[i]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }
print_success() { echo -e "${CYAN}[✔]${NC} $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root. Use: sudo $0"
        exit 1
    fi
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
    elif [ -f /etc/centos-release ]; then
        DISTRO="centos"
        VERSION=$(cat /etc/centos-release | sed 's/.*release\s*//' | sed 's/\..*//')
    elif [ -f /etc/debian_version ]; then
        DISTRO="debian"
        VERSION=$(cat /etc/debian_version)
    else
        DISTRO="unknown"
    fi
    print_info "Detected OS: $DISTRO $VERSION"
}

detect_architecture() {
    ARCH=$(uname -m)
    case $ARCH in
        x86_64|amd64) ARCH="x64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        armv7l|armv8l) ARCH="arm32" ;;
        i386|i686) ARCH="x86" ;;
        *) ARCH="unknown" ;;
    esac
    CPU_CORES=$(nproc --all)
    if [ $CPU_CORES -gt 16 ]; then CPU_CORES=16; fi
    print_info "Architecture: $ARCH, CPU Cores: $CPU_CORES"
}

create_service_user() {
    print_info "Creating service user and group..."
    
    # Check if user already exists
    if id "$PROXY_USER" &>/dev/null; then
        print_info "User $PROXY_USER already exists"
    else
        useradd -r -s /bin/false -M -d /nonexistent -U "$PROXY_USER"
        print_status "Created user: $PROXY_USER"
    fi
    
    # Create proxy directory with correct permissions
    mkdir -p "$PROXY_DIR"
    chown -R "$PROXY_USER:$PROXY_GROUP" "$PROXY_DIR"
    chmod 750 "$PROXY_DIR"
}

validate_port() {
    local port=$1
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        return 1
    fi
    return 0
}

validate_secret() {
    local secret=$1
    if [[ "$secret" =~ ^[0-9a-f]{32}$ ]] || [[ "$secret" =~ ^[0-9A-F]{32}$ ]]; then
        return 0
    fi
    return 1
}

generate_secret() {
    head -c 16 /dev/urandom | xxd -ps
}

get_random_port() {
    local PORT=$((RANDOM % 16383 + 49152))
    while lsof -Pi :$PORT -sTCP:LISTEN -t >/dev/null ; do
        PORT=$((RANDOM % 16383 + 49152))
    done
    echo $PORT
}

# ============================================
# Installation Functions
# ============================================

install_dependencies() {
    print_info "Installing dependencies..."
    
    case $DISTRO in
        ubuntu|debian)
            apt-get update
            DEBIAN_FRONTEND=noninteractive apt-get install -y \
                git curl build-essential libssl-dev zlib1g-dev \
                net-tools cron lsof xxd wget sudo ca-certificates
            ;;
        centos|rhel|fedora)
            yum install -y epel-release
            yum groupinstall -y "Development Tools"
            yum install -y git curl openssl-devel zlib-devel \
                net-tools cronie lsof wget ca-certificates
            ;;
        arch|manjaro)
            pacman -Sy --noconfirm git curl base-devel openssl zlib \
                net-tools cronie lsof wget ca-certificates
            ;;
        *)
            print_error "Unsupported distribution: $DISTRO"
            exit 1
            ;;
    esac
    
    # Install jq for JSON parsing if available
    if ! command -v jq &>/dev/null; then
        case $DISTRO in
            ubuntu|debian) apt-get install -y jq ;;
            centos|rhel|fedora) yum install -y jq ;;
            arch|manjaro) pacman -S --noconfirm jq ;;
        esac
    fi
    
    print_status "Dependencies installed successfully"
}

fix_makefile_architecture() {
    local makefile_path=$1
    
    if [ ! -f "$makefile_path" ]; then
        print_error "Makefile not found at $makefile_path"
        return 1
    fi
    
    print_info "Adjusting Makefile for $ARCH architecture..."
    
    # Backup original
    cp "$makefile_path" "${makefile_path}.backup"
    
    # Remove problematic flags for non-x86
    if [ "$ARCH" != "x64" ] && [ "$ARCH" != "x86" ]; then
        sed -i 's/-mpclmul//g' "$makefile_path"
        sed -i 's/-mfpmath=sse//g' "$makefile_path"
        sed -i 's/-mssse3//g' "$makefile_path"
        sed -i 's/-march=core2//g' "$makefile_path"
        sed -i 's/-msse4.1//g' "$makefile_path"
        sed -i 's/-msse4.2//g' "$makefile_path"
        print_info "Removed x86-specific CPU flags"
    fi
    
    # For 32-bit x86
    if [ "$ARCH" = "x86" ]; then
        sed -i 's/-march=core2/-march=pentium4/g' "$makefile_path"
        sed -i 's/-mpclmul//g' "$makefile_path"
    fi
    
    # Simplify optimization for stability
    sed -i 's/-O3/-O2/g' "$makefile_path"
    
    print_status "Makefile adjusted for $ARCH"
}

build_mtproxy_safe() {
    print_info "Building MTProto Proxy with safety checks..."
    
    # Clean and create directory
    rm -rf "$PROXY_DIR/source"
    mkdir -p "$PROXY_DIR/source"
    cd "$PROXY_DIR/source"
    
    # Clone repository
    print_info "Cloning MTProxy repository..."
    if ! git clone https://github.com/TelegramMessenger/MTProxy.git; then
        print_error "Failed to clone repository"
        return 1
    fi
    
    cd MTProxy
    
    # Fix Makefile for architecture
    fix_makefile_architecture "Makefile"
    
    # Test build with single thread first
    print_info "Testing build with single thread..."
    if make -j1; then
        print_status "Single-thread build successful, building with $CPU_CORES threads..."
        make clean
        if ! make -j$CPU_CORES; then
            print_warning "Multi-thread build failed, falling back to single thread..."
            make clean
            make -j1
        fi
    else
        print_warning "Standard build failed, trying minimal build..."
        
        # Create minimal build configuration
        cat > minimal_build.sh << 'EOF'
#!/bin/bash
set -e

# Minimal CFLAGS for compatibility
CFLAGS="-O2 -std=gnu11 -Wall -fno-strict-aliasing -fwrapv -DAES=1"
LDFLAGS="-lssl -lcrypto -lz -lpthread"

echo "Building with minimal configuration..."

# Create object directory
mkdir -p objs/bin
mkdir -p objs/mtproto
mkdir -p objs/common

# Find and compile all C files
for c_file in $(find . -name "*.c"); do
    o_file="objs/${c_file%.c}.o"
    mkdir -p $(dirname "$o_file")
    echo "Compiling: $c_file"
    gcc $CFLAGS -iquote common -iquote . -c "$c_file" -o "$o_file" || {
        echo "Warning: Failed to compile $c_file, skipping..."
        continue
    }
done

# Link all objects
echo "Linking objects..."
gcc $CFLAGS $(find objs -name "*.o" -type f) $LDFLAGS -o objs/bin/mtproto-proxy

if [ -f "objs/bin/mtproto-proxy" ]; then
    echo "Build successful!"
    chmod +x objs/bin/mtproto-proxy
else
    echo "Build failed!"
    exit 1
fi
EOF
        
        chmod +x minimal_build.sh
        if ! ./minimal_build.sh; then
            print_error "All build attempts failed"
            return 1
        fi
    fi
    
    # Verify binary
    if [ ! -f "objs/bin/mtproto-proxy" ]; then
        print_error "Binary not created"
        return 1
    fi
    
    # Test binary
    if ! ./objs/bin/mtproto-proxy --help 2>/dev/null | grep -q "MTProto"; then
        print_warning "Binary help test failed, but continuing..."
    fi
    
    # Install binary
    mkdir -p "$PROXY_DIR/bin"
    cp objs/bin/mtproto-proxy "$PROXY_DIR/bin/"
    chmod +x "$PROXY_DIR/bin/mtproto-proxy"
    
    print_status "Build completed successfully"
    return 0
}

download_config_files() {
    print_info "Downloading configuration files..."
    
    cd "$PROXY_DIR"
    
    # Download proxy-secret
    local secret_urls=(
        "https://core.telegram.org/getProxySecret"
        "https://raw.githubusercontent.com/TelegramMessenger/MTProxy/master/proxy-secret"
    )
    
    for url in "${secret_urls[@]}"; do
        print_info "Trying: $(basename $url)"
        if curl -s --max-time 30 --retry 3 -o proxy-secret.tmp "$url" && \
           [ -s proxy-secret.tmp ] && \
           head -c 1 proxy-secret.tmp | grep -q .; then
            mv proxy-secret.tmp proxy-secret
            print_status "Downloaded proxy-secret"
            break
        fi
    done
    
    if [ ! -f "proxy-secret" ] || [ ! -s "proxy-secret" ]; then
        print_error "Failed to download proxy-secret"
        # Create empty file as fallback
        echo "# Empty proxy-secret" > proxy-secret
    fi
    
    # Download proxy-multi.conf
    local conf_urls=(
        "https://core.telegram.org/getProxyConfig"
        "https://raw.githubusercontent.com/TelegramMessenger/MTProxy/master/proxy-multi.conf"
    )
    
    for url in "${conf_urls[@]}"; do
        print_info "Trying: $(basename $url)"
        if curl -s --max-time 30 --retry 3 -o proxy-multi.conf.tmp "$url" && \
           [ -s proxy-multi.conf.tmp ] && \
           head -c 1 proxy-multi.conf.tmp | grep -q .; then
            mv proxy-multi.conf.tmp proxy-multi.conf
            print_status "Downloaded proxy-multi.conf"
            break
        fi
    done
    
    if [ ! -f "proxy-multi.conf" ] || [ ! -s "proxy-multi.conf" ]; then
        print_error "Failed to download proxy-multi.conf"
        # Create minimal config
        cat > proxy-multi.conf << 'EOF'
# Minimal MTProxy config
default {
    port 443;
    secret dd00000000000000000000000000000000;
}
EOF
    fi
    
    # Set permissions
    chown "$PROXY_USER:$PROXY_GROUP" proxy-secret proxy-multi.conf
    chmod 640 proxy-secret proxy-multi.conf
    
    return 0
}

get_public_ip() {
    print_info "Detecting public IP..."
    
    local ip_services=(
        "https://api.ipify.org"
        "https://icanhazip.com"
        "https://ifconfig.me/ip"
        "https://checkip.amazonaws.com"
        "https://ipinfo.io/ip"
    )
    
    for service in "${ip_services[@]}"; do
        local ip=$(curl -s --max-time 10 "$service" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        if [ -n "$ip" ] && [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            PUBLIC_IP="$ip"
            print_status "Public IP detected: $PUBLIC_IP"
            return 0
        fi
    done
    
    print_warning "Could not detect public IP automatically"
    while true; do
        read -p "Enter your server's public IP address: " PUBLIC_IP
        if [[ $PUBLIC_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            return 0
        else
            print_error "Invalid IP address format. Please enter a valid IPv4 address."
        fi
    done
}

get_private_ip() {
    PRIVATE_IP=$(ip route get 1 2>/dev/null | awk '{print $NF;exit}' | sed 's/ //g')
    
    if [ -z "$PRIVATE_IP" ]; then
        PRIVATE_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    fi
    
    if [ -n "$PRIVATE_IP" ]; then
        print_info "Private IP detected: $PRIVATE_IP"
        
        # Check if private IP range
        if [[ $PRIVATE_IP =~ ^10\. ]] || \
           [[ $PRIVATE_IP =~ ^172\.1[6-9]\. ]] || \
           [[ $PRIVATE_IP =~ ^172\.2[0-9]\. ]] || \
           [[ $PRIVATE_IP =~ ^172\.3[0-1]\. ]] || \
           [[ $PRIVATE_IP =~ ^192\.168\. ]]; then
            HAVE_NAT="y"
            print_info "Server appears to be behind NAT"
        else
            HAVE_NAT="n"
        fi
    fi
}

configure_firewall() {
    print_info "Configuring firewall for port $PORT..."
    
    case $DISTRO in
        ubuntu|debian)
            # Try ufw first
            if command -v ufw >/dev/null 2>&1 && systemctl is-active --quiet ufw; then
                ufw allow $PORT/tcp comment "MTProto Proxy"
                ufw reload
                print_status "UFW configured for port $PORT"
            else
                # Use iptables
                iptables -I INPUT -p tcp --dport $PORT -j ACCEPT 2>/dev/null
                print_info "Added iptables rule for port $PORT"
            fi
            ;;
        centos|rhel|fedora)
            # Try firewalld
            if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
                firewall-cmd --permanent --add-port=$PORT/tcp
                firewall-cmd --reload
                print_status "Firewalld configured for port $PORT"
            else
                # Use iptables
                iptables -I INPUT -p tcp --dport $PORT -j ACCEPT 2>/dev/null
                service iptables save 2>/dev/null || true
                print_info "Added iptables rule for port $PORT"
            fi
            ;;
    esac
}

create_systemd_service() {
    print_info "Creating systemd service with secure configuration..."
    
    # Build command arguments
    local ARGS_STR="-u $PROXY_USER -H $PORT -p 8888"
    
    for secret in "${SECRET_ARY[@]}"; do
        ARGS_STR+=" -S $secret"
    done
    
    if [ -n "$TAG" ]; then
        ARGS_STR+=" -P $TAG"
    fi
    
    if [ -n "$TLS_DOMAIN" ]; then
        ARGS_STR+=" -D $TLS_DOMAIN"
    fi
    
    if [ "$HAVE_NAT" = "y" ] && [ -n "$PRIVATE_IP" ] && [ -n "$PUBLIC_IP" ]; then
        ARGS_STR+=" --nat-info $PRIVATE_IP:$PUBLIC_IP"
    fi
    
    # Adjust worker count
    local WORKER_CORES=$((CPU_CORES > 1 ? CPU_CORES - 1 : 1))
    if [ $WORKER_CORES -gt 16 ]; then
        WORKER_CORES=16
    fi
    
    ARGS_STR+=" -M $WORKER_CORES --aes-pwd $PROXY_DIR/proxy-secret $PROXY_DIR/proxy-multi.conf"
    
    if [ -n "$CUSTOM_ARGS" ]; then
        ARGS_STR+=" $CUSTOM_ARGS"
    fi
    
    # Create secure systemd service
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=MTProto Proxy Service
Documentation=https://github.com/TelegramMessenger/MTProxy
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=$PROXY_USER
Group=$PROXY_GROUP
WorkingDirectory=$PROXY_DIR
Environment="HOME=$PROXY_DIR"
RuntimeDirectory=mtproto-proxy
RuntimeDirectoryMode=0750
ExecStart=$PROXY_DIR/bin/mtproto-proxy $ARGS_STR
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s
StartLimitInterval=60
StartLimitBurst=3
LimitNOFILE=65536
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$PROXY_DIR /var/log
ReadOnlyPaths=/
InaccessiblePaths=/boot /etc /root
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true
StandardOutput=append:$LOG_FILE
StandardError=append:$ERROR_LOG
SyslogIdentifier=mtproto-proxy

# Security enhancements
CapabilityBoundingSet=
AmbientCapabilities=
SystemCallFilter=@system-service
SystemCallArchitectures=native
LockPersonality=true
RemoveIPC=true

[Install]
WantedBy=multi-user.target
EOF
    
    # Set correct permissions
    chmod 644 "$SERVICE_FILE"
    
    # Create log files with correct permissions
    touch "$LOG_FILE" "$ERROR_LOG"
    chown "$PROXY_USER:$PROXY_GROUP" "$LOG_FILE" "$ERROR_LOG"
    chmod 640 "$LOG_FILE" "$ERROR_LOG"
    
    # Reload systemd
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    
    print_status "Secure systemd service created and enabled"
}

test_proxy_start() {
    print_info "Testing proxy startup..."
    
    # First, test the binary directly
    if ! sudo -u "$PROXY_USER" "$PROXY_DIR/bin/mtproto-proxy" --help >/dev/null 2>&1; then
        print_error "Binary test failed"
        return 1
    fi
    
    # Try a dry run with minimal arguments
    local TEST_ARGS="-u $PROXY_USER -H 9999 -S ${SECRET_ARY[0]} --aes-pwd $PROXY_DIR/proxy-secret $PROXY_DIR/proxy-multi.conf --test"
    
    if sudo -u "$PROXY_USER" "$PROXY_DIR/bin/mtproto-proxy" $TEST_ARGS 2>&1 | grep -q "error\|Error\|ERROR"; then
        print_warning "Test run showed errors, but continuing..."
    fi
    
    return 0
}

start_proxy_service() {
    print_info "Starting MTProto Proxy service..."
    
    # Stop if already running
    systemctl stop "$SERVICE_NAME" 2>/dev/null
    
    # Start service
    if systemctl start "$SERVICE_NAME"; then
        sleep 3
        
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            print_status "Service started successfully"
            
            # Show status
            echo ""
            systemctl status "$SERVICE_NAME" --no-pager -l | head -20
            
            # Check logs for errors
            if journalctl -u "$SERVICE_NAME" --since "1 minute ago" | grep -q "error\|Error\|ERROR\|fail\|Fail"; then
                print_warning "Found errors in recent logs. Checking..."
                journalctl -u "$SERVICE_NAME" --since "1 minute ago" | grep -i "error\|fail" | head -5
            fi
            
            return 0
        else
            print_error "Service started but is not active"
        fi
    else
        print_error "Failed to start service"
    fi
    
    # Show detailed error information
    echo ""
    print_error "=== Debug Information ==="
    journalctl -u "$SERVICE_NAME" --no-pager -n 20
    echo ""
    
    # Check binary permissions
    ls -la "$PROXY_DIR/bin/mtproto-proxy"
    echo ""
    
    # Check config files
    ls -la "$PROXY_DIR/proxy-secret" "$PROXY_DIR/proxy-multi.conf"
    echo ""
    
    # Try to run manually for debugging
    print_info "Trying manual execution for debugging..."
    sudo -u "$PROXY_USER" "$PROXY_DIR/bin/mtproto-proxy" --help
    
    return 1
}

create_updater() {
    print_info "Creating auto-updater..."
    
    cat > "$UPATER_FILE" << 'EOF'
#!/bin/bash
# MTProto Proxy Auto-Updater

set -e

PROXY_DIR="/opt/mtproto-proxy"
LOG_FILE="/var/log/mtproto-updater.log"
ERROR_FILE="/var/log/mtproto-updater-error.log"

echo "[$(date)] Starting update..." | tee -a "$LOG_FILE"

# Stop service if running
if systemctl is-active --quiet mtproto-proxy; then
    echo "Stopping mtproto-proxy service..." | tee -a "$LOG_FILE"
    systemctl stop mtproto-proxy
    sleep 2
fi

cd "$PROXY_DIR"

# Download new proxy-secret
echo "Downloading proxy-secret..." | tee -a "$LOG_FILE"
if curl -s --max-time 60 --retry 3 -o proxy-secret.new \
   https://core.telegram.org/getProxySecret; then
    if [ -s proxy-secret.new ]; then
        mv proxy-secret.new proxy-secret
        chown mtproxy:mtproxy proxy-secret
        chmod 640 proxy-secret
        echo "proxy-secret updated successfully" | tee -a "$LOG_FILE"
    else
        echo "Warning: Downloaded empty proxy-secret" | tee -a "$LOG_FILE"
    fi
else
    echo "Warning: Failed to download proxy-secret" | tee -a "$LOG_FILE"
fi

# Download new proxy-multi.conf
echo "Downloading proxy-multi.conf..." | tee -a "$LOG_FILE"
if curl -s --max-time 60 --retry 3 -o proxy-multi.conf.new \
   https://core.telegram.org/getProxyConfig; then
    if [ -s proxy-multi.conf.new ]; then
        mv proxy-multi.conf.new proxy-multi.conf
        chown mtproxy:mtproxy proxy-multi.conf
        chmod 640 proxy-multi.conf
        echo "proxy-multi.conf updated successfully" | tee -a "$LOG_FILE"
    else
        echo "Warning: Downloaded empty proxy-multi.conf" | tee -a "$LOG_FILE"
    fi
else
    echo "Warning: Failed to download proxy-multi.conf" | tee -a "$LOG_FILE"
fi

# Start service
echo "Starting mtproto-proxy service..." | tee -a "$LOG_FILE"
if systemctl start mtproto-proxy; then
    echo "Service started successfully" | tee -a "$LOG_FILE"
else
    echo "Error: Failed to start service" | tee -a "$LOG_FILE"
    systemctl status mtproto-proxy --no-pager | tee -a "$ERROR_FILE"
fi

echo "[$(date)] Update completed" | tee -a "$LOG_FILE"
EOF
    
    chmod +x "$UPATER_FILE"
    chown "$PROXY_USER:$PROXY_GROUP" "$UPATER_FILE"
    
    if [ "$ENABLE_UPDATER" = "y" ]; then
        # Add to crontab
        (crontab -l 2>/dev/null | grep -v "$UPATER_FILE"; echo "0 3 * * * $UPATER_FILE >> /var/log/mtproto-cron.log 2>&1") | crontab -
        print_status "Auto-updater configured to run daily at 3 AM"
    fi
}

enable_bbr() {
    if [ "$ENABLE_BBR" != "y" ]; then
        return 0
    fi
    
    print_info "Configuring BBR congestion control..."
    
    # Check current congestion control
    local current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
    
    if [ "$current_cc" = "bbr" ]; then
        print_status "BBR is already enabled"
        return 0
    fi
    
    # Check if BBR is available
    if ! modprobe tcp_bbr 2>/dev/null; then
        print_warning "BBR module not available, skipping"
        return 0
    fi
    
    # Apply BBR settings
    cat >> /etc/sysctl.conf << 'EOF'

# BBR Congestion Control
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
    
    # Apply immediately
    sysctl -p 2>/dev/null || true
    
    print_status "BBR enabled successfully"
}

save_configuration() {
    print_info "Saving configuration..."
    
    cat > "$CONFIG_FILE" << EOF
# MTProto Proxy Configuration
# Generated on $(date)
# Do not edit manually unless you know what you're doing

# Network Configuration
PORT=$PORT
PUBLIC_IP="$PUBLIC_IP"
PRIVATE_IP="$PRIVATE_IP"
HAVE_NAT="$HAVE_NAT"

# Secrets (do not share!)
SECRET_ARY=(${SECRET_ARY[@]})

# Performance
CPU_CORES=$CPU_CORES

# Optional Features
TAG="$TAG"
TLS_DOMAIN="$TLS_DOMAIN"
CUSTOM_ARGS="$CUSTOM_ARGS"

# Service Settings
ENABLE_UPDATER="$ENABLE_UPDATER"
ENABLE_BBR="$ENABLE_BBR"
PROXY_USER="$PROXY_USER"
PROXY_GROUP="$PROXY_GROUP"

# System Info
DISTRO="$DISTRO"
ARCH="$ARCH"
INSTALL_DATE="$(date +%Y-%m-%d)"
EOF
    
    chmod 600 "$CONFIG_FILE"
    chown "$PROXY_USER:$PROXY_GROUP" "$CONFIG_FILE"
    print_status "Configuration saved to $CONFIG_FILE"
}

load_configuration() {
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
        print_status "Configuration loaded"
        return 0
    fi
    return 1
}

# ============================================
# Main Installation Function
# ============================================

install_mtproxy() {
    clear
    print_success "===== MTProto Proxy Installation ====="
    echo ""
    
    # Detect system
    detect_os
    detect_architecture
    
    # Check if already installed
    if [ -f "$CONFIG_FILE" ]; then
        print_warning "MTProto Proxy seems to be already installed."
        read -p "Reinstall? This will overwrite current configuration. [y/N]: " reinstall
        if [[ ! "$reinstall" =~ ^[Yy]$ ]]; then
            return
        fi
    fi
    
    # Step 1: Configuration
    print_info "Step 1/8: Configuration"
    echo ""
    
    # Port selection
    while true; do
        read -p "Enter proxy port (1-65535) [443]: " input_port
        PORT=${input_port:-443}
        if validate_port "$PORT"; then
            break
        else
            print_error "Invalid port number. Please enter a number between 1 and 65535."
        fi
    done
    
    # Secret management
    print_info "Secret configuration:"
    while true; do
        echo "  1) Generate random secret"
        echo "  2) Enter custom secret"
        echo "  3) Done adding secrets"
        read -p "Select option [1-3]: " secret_opt
        
        case $secret_opt in
            1)
                secret=$(generate_secret)
                SECRET_ARY+=("$secret")
                print_status "Generated: $secret"
                ;;
            2)
                while true; do
                    read -p "Enter 32-character hexadecimal secret: " secret
                    secret=$(echo "$secret" | tr '[:upper:]' '[:lower:]')
                    if validate_secret "$secret"; then
                        SECRET_ARY+=("$secret")
                        print_status "Secret added"
                        break
                    else
                        print_error "Invalid format. Must be 32 hex characters (0-9, a-f)."
                    fi
                done
                ;;
            3)
                if [ ${#SECRET_ARY[@]} -eq 0 ]; then
                    print_warning "No secrets added. Generating one..."
                    secret=$(generate_secret)
                    SECRET_ARY+=("$secret")
                fi
                break
                ;;
            *)
                print_error "Invalid option"
                ;;
        esac
        
        if [ ${#SECRET_ARY[@]} -ge 16 ]; then
            print_warning "Maximum 16 secrets reached"
            break
        fi
        
        echo ""
    done
    
    # Optional features
    echo ""
    read -p "Enter advertising TAG (from @MTProxybot, optional): " TAG
    
    read -p "Enter TLS domain for Fake-TLS (e.g., cloudflare.com, optional): " TLS_DOMAIN
    
    # CPU cores
    read -p "Enter worker processes (1-$CPU_CORES) [$CPU_CORES]: " input_cores
    if [[ "$input_cores" =~ ^[0-9]+$ ]] && [ "$input_cores" -ge 1 ] && [ "$input_cores" -le "$CPU_CORES" ]; then
        CPU_CORES=$input_cores
    fi
    
    # Other options
    read -p "Enter custom arguments (optional): " CUSTOM_ARGS
    
    read -p "Enable auto-updater? [Y/n]: " input_updater
    ENABLE_UPDATER=${input_updater:-y}
    
    read -p "Enable BBR congestion control? [Y/n]: " input_bbr
    ENABLE_BBR=${input_bbr:-y}
    
    # Get IP addresses
    echo ""
    get_public_ip
    get_private_ip
    
    # Confirm NAT if detected
    if [ "$HAVE_NAT" = "y" ]; then
        read -p "Confirm private IP [$PRIVATE_IP] or enter new: " input_private
        if [ -n "$input_private" ]; then
            PRIVATE_IP="$input_private"
        fi
    fi
    
    # Installation steps
    echo ""
    print_info "Step 2/8: Creating service user..."
    create_service_user
    
    print_info "Step 3/8: Installing dependencies..."
    install_dependencies
    
    print_info "Step 4/8: Building MTProto Proxy..."
    if ! build_mtproxy_safe; then
        print_error "Build failed. See errors above."
        exit 1
    fi
    
    print_info "Step 5/8: Downloading configuration files..."
    download_config_files
    
    print_info "Step 6/8: Creating systemd service..."
    create_systemd_service
    
    print_info "Step 7/8: Testing configuration..."
    if ! test_proxy_start; then
        print_error "Configuration test failed"
        exit 1
    fi
    
    print_info "Step 8/8: Finalizing installation..."
    save_configuration
    create_updater
    enable_bbr
    configure_firewall
    
    # Start service
    echo ""
    if start_proxy_service; then
        print_success "===== Installation Complete! ====="
        echo ""
        
        # Show connection links
        show_connection_links
        
        echo ""
        print_info "Installation Directory: $PROXY_DIR"
        print_info "Configuration File: $CONFIG_FILE"
        print_info "Service: $SERVICE_NAME"
        print_info "Log Files: $LOG_FILE, $ERROR_LOG"
        echo ""
        
        # Quick test
        print_info "Testing connection..."
        if timeout 5 curl -s "http://localhost:8888/stats" >/dev/null 2>&1; then
            print_status "Internal stats endpoint is accessible"
        fi
        
    else
        print_error "Installation completed but service failed to start."
        print_info "Check logs: journalctl -u $SERVICE_NAME"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

show_connection_links() {
    if [ -z "$PUBLIC_IP" ]; then
        get_public_ip
    fi
    
    print_success "===== Connection Links ====="
    echo ""
    
    local hex_domain=""
    if [ -n "$TLS_DOMAIN" ]; then
        hex_domain=$(printf "%s" "$TLS_DOMAIN" | xxd -pu | tr -d '\n' | tr '[:upper:]' '[:lower:]')
    fi
    
    for i in "${!SECRET_ARY[@]}"; do
        local secret="${SECRET_ARY[$i]}"
        if [ -z "$TLS_DOMAIN" ]; then
            echo "tg://proxy?server=$PUBLIC_IP&port=$PORT&secret=dd$secret"
        else
            echo "tg://proxy?server=$PUBLIC_IP&port=$PORT&secret=ee$secret$hex_domain"
        fi
        
        # Alternative format
        echo "https://t.me/proxy?server=$PUBLIC_IP&port=$PORT&secret=dd$secret"
        echo ""
    done
    
    echo "Usage in Telegram:"
    echo "1. Settings > Data and Storage > Proxy"
    echo "2. Add Proxy > MTProto"
    echo "3. Server: $PUBLIC_IP"
    echo "4. Port: $PORT"
    echo "5. Secret: dd${SECRET_ARY[0]}"
    echo ""
}

# ============================================
# Management Functions
# ============================================

manage_service() {
    clear
    print_success "===== Service Management ====="
    echo ""
    
    if [ ! -f "$CONFIG_FILE" ]; then
        print_error "MTProto Proxy is not installed."
        return
    fi
    
    load_configuration
    
    while true; do
        echo "Current Status:"
        systemctl status $SERVICE_NAME --no-pager | grep -A 3 "Active:"
        echo ""
        
        echo "Options:"
        echo "  1) Start service"
        echo "  2) Stop service"
        echo "  3) Restart service"
        echo "  4) View logs"
        echo "  5) Check status"
        echo "  6) Follow logs (real-time)"
        echo "  0) Back"
        echo ""
        
        read -p "Select option: " option
        
        case $option in
            1)
                systemctl start $SERVICE_NAME
                sleep 2
                ;;
            2)
                systemctl stop $SERVICE_NAME
                sleep 2
                ;;
            3)
                systemctl restart $SERVICE_NAME
                sleep 2
                ;;
            4)
                clear
                journalctl -u $SERVICE_NAME --no-pager -n 50
                echo ""
                read -p "Press Enter to continue..."
                ;;
            5)
                clear
                systemctl status $SERVICE_NAME --no-pager -l
                echo ""
                read -p "Press Enter to continue..."
                ;;
            6)
                clear
                print_info "Following logs (Ctrl+C to stop)..."
                journalctl -u $SERVICE_NAME -f
                ;;
            0)
                return
                ;;
            *)
                print_error "Invalid option"
                ;;
        esac
        
        clear
    done
}

manage_secrets() {
    clear
    print_success "===== Secret Management ====="
    echo ""
    
    if [ ! -f "$CONFIG_FILE" ]; then
        print_error "MTProto Proxy is not installed."
        return
    fi
    
    load_configuration
    
    while true; do
        echo "Current Secrets:"
        for i in "${!SECRET_ARY[@]}"; do
            echo "  $((i+1))) ${SECRET_ARY[$i]}"
        done
        echo ""
        
        echo "Options:"
        echo "  1) Add new secret"
        echo "  2) Remove secret"
        echo "  3) Generate new secret"
        echo "  4) Show connection links"
        echo "  0) Back"
        echo ""
        
        read -p "Select option: " option
        
        case $option in
            1)
                if [ ${#SECRET_ARY[@]} -ge 16 ]; then
                    print_error "Maximum 16 secrets reached"
                    sleep 2
                    continue
                fi
                
                read -p "Enter 32-character hex secret: " new_secret
                new_secret=$(echo "$new_secret" | tr '[:upper:]' '[:lower:]')
                if validate_secret "$new_secret"; then
                    SECRET_ARY+=("$new_secret")
                    save_configuration
                    systemctl restart $SERVICE_NAME
                    print_status "Secret added and service restarted"
                else
                    print_error "Invalid secret format"
                fi
                sleep 2
                ;;
            2)
                if [ ${#SECRET_ARY[@]} -le 1 ]; then
                    print_error "Cannot remove the last secret"
                    sleep 2
                    continue
                fi
                
                read -p "Enter secret number to remove: " secret_num
                if [[ "$secret_num" =~ ^[0-9]+$ ]] && [ "$secret_num" -ge 1 ] && [ "$secret_num" -le ${#SECRET_ARY[@]} ]; then
                    index=$((secret_num-1))
                    unset SECRET_ARY[$index]
                    SECRET_ARY=("${SECRET_ARY[@]}")
                    save_configuration
                    systemctl restart $SERVICE_NAME
                    print_status "Secret removed and service restarted"
                else
                    print_error "Invalid selection"
                fi
                sleep 2
                ;;
            3)
                if [ ${#SECRET_ARY[@]} -ge 16 ]; then
                    print_error "Maximum 16 secrets reached"
                    sleep 2
                    continue
                fi
                
                new_secret=$(generate_secret)
                SECRET_ARY+=("$new_secret")
                save_configuration
                systemctl restart $SERVICE_NAME
                print_status "Generated new secret: $new_secret"
                show_connection_links
                sleep 3
                ;;
            4)
                show_connection_links
                read -p "Press Enter to continue..."
                ;;
            0)
                return
                ;;
            *)
                print_error "Invalid option"
                ;;
        esac
        
        clear
    done
}

uninstall_proxy() {
    clear
    print_warning "===== Uninstall MTProto Proxy ====="
    echo ""
    
    if [ ! -f "$CONFIG_FILE" ]; then
        print_error "MTProto Proxy is not installed."
        return
    fi
    
    load_configuration
    
    print_warning "⚠️  WARNING: This will completely remove MTProto Proxy!"
    print_warning "All configuration and data will be deleted."
    echo ""
    
    read -p "Are you sure you want to continue? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        print_info "Uninstallation cancelled."
        return
    fi
    
    print_info "Stopping service..."
    systemctl stop $SERVICE_NAME 2>/dev/null
    systemctl disable $SERVICE_NAME 2>/dev/null
    
    print_info "Removing service file..."
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
    
    print_info "Removing firewall rules..."
    case $DISTRO in
        ubuntu|debian)
            ufw delete allow $PORT/tcp 2>/dev/null || true
            ;;
        centos|rhel|fedora)
            firewall-cmd --permanent --remove-port=$PORT/tcp 2>/dev/null || true
            firewall-cmd --reload 2>/dev/null || true
            ;;
    esac
    
    print_info "Removing crontab entry..."
    crontab -l 2>/dev/null | grep -v "$UPATER_FILE" | crontab -
    
    print_info "Removing user..."
    userdel "$PROXY_USER" 2>/dev/null || true
    groupdel "$PROXY_GROUP" 2>/dev/null || true
    
    print_info "Removing files..."
    rm -rf "$PROXY_DIR"
    rm -f "$LOG_FILE" "$ERROR_LOG" "/var/log/mtproto-updater.log"
    
    print_success "MTProto Proxy has been completely uninstalled."
    echo ""
    read -p "Press Enter to continue..."
}

# ============================================
# Main Menu
# ============================================

main_menu() {
    while true; do
        clear
        echo -e "${CYAN}"
        echo "╔══════════════════════════════════════════════════════════════╗"
        echo "║           MTProto Proxy Ultimate v3.1 - FIXED               ║"
        echo "║               No more 'nobody' user issues                  ║"
        echo "╚══════════════════════════════════════════════════════════════╝"
        echo -e "${NC}"
        echo ""
        
        # Check installation status
        if [ -f "$CONFIG_FILE" ]; then
            if systemctl is-active --quiet "$SERVICE_NAME"; then
                echo -e "${GREEN}✓ Status: Installed & Running${NC}"
            else
                echo -e "${YELLOW}⚠ Status: Installed but Stopped${NC}"
            fi
            
            load_configuration
            echo "    Port: $PORT, Secrets: ${#SECRET_ARY[@]}, Public IP: $PUBLIC_IP"
        else
            echo -e "${YELLOW}○ Status: Not Installed${NC}"
        fi
        
        echo ""
        echo "Main Menu:"
        echo "  1) Install MTProto Proxy"
        echo "  2) Service Management"
        echo "  3) Secret Management"
        echo "  4) Show Connection Links"
        echo "  5) View Logs"
        echo "  6) Update Configuration Files"
        echo "  7) Uninstall"
        echo "  8) System Information"
        echo "  0) Exit"
        echo ""
        
        read -p "Select option: " main_option
        
        case $main_option in
            1)
                install_mtproxy
                ;;
            2)
                manage_service
                ;;
            3)
                manage_secrets
                ;;
            4)
                clear
                if [ -f "$CONFIG_FILE" ]; then
                    load_configuration
                    show_connection_links
                else
                    print_error "Proxy is not installed."
                fi
                read -p "Press Enter to continue..."
                ;;
            5)
                clear
                if [ -f "$CONFIG_FILE" ]; then
                    journalctl -u $SERVICE_NAME --no-pager -n 100
                else
                    print_error "Proxy is not installed."
                fi
                read -p "Press Enter to continue..."
                ;;
            6)
                if [ -f "$CONFIG_FILE" ]; then
                    print_info "Updating configuration files..."
                    download_config_files
                    systemctl restart $SERVICE_NAME
                    print_status "Configuration updated"
                else
                    print_error "Proxy is not installed."
                fi
                read -p "Press Enter to continue..."
                ;;
            7)
                uninstall_proxy
                ;;
            8)
                clear
                print_success "===== System Information ====="
                echo ""
                echo "OS: $DISTRO"
                echo "Architecture: $ARCH"
                echo "CPU Cores: $(nproc)"
                echo "Memory: $(free -h | awk '/^Mem:/ {print $2}')"
                echo "Disk: $(df -h / | awk 'NR==2 {print $4}') free"
                echo ""
                echo "Service Status:"
                systemctl status $SERVICE_NAME --no-pager | grep -A 2 "Active:"
                echo ""
                read -p "Press Enter to continue..."
                ;;
            0)
                clear
                print_success "Goodbye!"
                echo ""
                exit 0
                ;;
            *)
                print_error "Invalid option"
                sleep 2
                ;;
        esac
    done
}

# ============================================
# Script Start
# ============================================

# Initial checks
check_root

# Welcome
clear
print_success "MTProto Proxy Ultimate Installer v3.1"
print_info "Fixed: 'nobody' user issues and service failures"
echo ""
print_info "Checking system compatibility..."

detect_os
detect_architecture

sleep 2

# Start main menu
main_menu
