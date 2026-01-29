#!/bin/bash

# Colors for script output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Proxy information
PROXY_DIR="/opt/mtproto-proxy"
SERVICE_NAME="mtproto-proxy"
CONFIG_FILE="$PROXY_DIR/config.env"
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"
LOG_FILE="/var/log/mtproto-proxy.log"
MAKEFILE_PATCH="$PROXY_DIR/makefile.patch"

# Function to display banner
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║           MTProto Proxy Management Script                   ║"
    echo "║                 For Ubuntu/Debian Systems                   ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${YELLOW}GitHub: https://github.com/TelegramMessenger/MTProxy${NC}"
    echo -e "${YELLOW}Telegram Proxy: https://core.telegram.org/mtproto/mtproto-proxy${NC}"
    echo ""
}

# Function to display error
show_error() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
}

# Function to display success
show_success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}"
}

# Function to display info
show_info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

# Function to display warning
show_warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        show_error "This script must be run as root. Use sudo or run as root user."
        exit 1
    fi
}

# Function to detect system architecture
detect_architecture() {
    ARCH=$(uname -m)
    DISTRO=$(lsb_release -si 2>/dev/null || echo "Unknown")
    DISTRO_VERSION=$(lsb_release -sr 2>/dev/null || echo "Unknown")
    
    show_info "Detected: $DISTRO $DISTRO_VERSION ($ARCH)"
    
    case $ARCH in
        x86_64|amd64)
            ARCH_TYPE="x64"
            ARCH_FLAGS="-mpclmul -mfpmath=sse -mssse3 -march=core2"
            ;;
        aarch64|arm64)
            ARCH_TYPE="arm64"
            ARCH_FLAGS=""
            ;;
        armv7l|armv8l)
            ARCH_TYPE="arm32"
            ARCH_FLAGS=""
            ;;
        i386|i686)
            ARCH_TYPE="x86"
            ARCH_FLAGS="-msse2 -mfpmath=sse"
            ;;
        *)
            ARCH_TYPE="generic"
            ARCH_FLAGS=""
            show_warning "Unknown architecture: $ARCH"
            show_warning "Using generic build flags"
            ;;
    esac
    
    export ARCH_TYPE
    export ARCH_FLAGS
}

# Function to check GCC version
check_gcc_version() {
    if command -v gcc >/dev/null 2>&1; then
        GCC_VERSION=$(gcc --version | head -n1 | awk '{print $NF}')
        show_info "GCC version: $GCC_VERSION"
        
        # Check if GCC is too old
        if [[ $(echo "$GCC_VERSION 4.9" | awk '{if ($1 < $2) print 1; else print 0}') -eq 1 ]]; then
            show_warning "GCC version $GCC_VERSION is quite old"
            show_warning "Consider upgrading GCC for better performance"
        fi
    else
        show_error "GCC not found. Please install build-essential package."
        return 1
    fi
}

# Function to update system
update_system() {
    show_info "Updating system packages..."
    
    # Update package lists
    apt-get update
    if [[ $? -eq 0 ]]; then
        show_success "Package lists updated"
    else
        show_error "Failed to update package lists"
        return 1
    fi
    
    # Upgrade existing packages
    show_info "Upgrading existing packages..."
    apt-get upgrade -y
    if [[ $? -eq 0 ]]; then
        show_success "System upgraded successfully"
    else
        show_warning "Some packages failed to upgrade, continuing anyway..."
    fi
}

# Function to install dependencies
install_dependencies() {
    show_info "Installing required dependencies..."
    
    # Check if we need to install build-essential
    if ! dpkg -l | grep -q "build-essential"; then
        show_info "Installing build-essential..."
        apt-get install -y build-essential
        if [[ $? -ne 0 ]]; then
            show_error "Failed to install build-essential"
            return 1
        fi
    fi
    
    # List of required packages
    DEPENDENCIES=(
        git
        curl
        libssl-dev
        zlib1g-dev
        xxd
        net-tools
        pkg-config
        make
        gcc
        g++
    )
    
    # Install each dependency
    for pkg in "${DEPENDENCIES[@]}"; do
        if ! dpkg -l | grep -q "^ii  $pkg "; then
            show_info "Installing $pkg..."
            apt-get install -y "$pkg"
            if [[ $? -ne 0 ]]; then
                show_error "Failed to install $pkg"
                return 1
            fi
        else
            show_info "$pkg is already installed"
        fi
    done
    
    # Install jq if available
    if ! command -v jq >/dev/null 2>&1; then
        show_info "Installing jq for JSON processing..."
        apt-get install -y jq || show_warning "Failed to install jq, continuing without it..."
    fi
    
    show_success "All dependencies installed successfully"
}

# Function to create Makefile patch for non-x86 architectures
create_makefile_patch() {
    show_info "Creating Makefile patch for $ARCH_TYPE architecture..."
    
    # Read current Makefile to understand its structure
    if [[ ! -f "Makefile" ]]; then
        show_error "Makefile not found"
        return 1
    fi
    
    # Create a backup of the original Makefile
    cp Makefile Makefile.original
    
    # Create a patch that removes problematic flags for non-x86 architectures
    if [[ "$ARCH_TYPE" != "x64" && "$ARCH_TYPE" != "x86" ]]; then
        # For ARM and generic architectures, remove problematic flags
        sed -i 's/-mpclmul//g' Makefile
        sed -i 's/-mfpmath=sse//g' Makefile
        sed -i 's/-mssse3//g' Makefile
        sed -i 's/-march=core2//g' Makefile
        show_info "Removed x86-specific compiler flags for $ARCH_TYPE"
    elif [[ "$ARCH_TYPE" == "x86" ]]; then
        # For 32-bit x86, use appropriate flags
        sed -i 's/-march=core2/-march=pentium4/g' Makefile
        sed -i 's/-mpclmul//g' Makefile  # Remove pclmul for 32-bit
        show_info "Adjusted compiler flags for 32-bit x86"
    fi
    
    # Also check for any other architecture-specific issues
    if ! grep -q "CFLAGS" Makefile; then
        show_warning "CFLAGS not found in Makefile"
    fi
    
    show_success "Makefile patched for $ARCH_TYPE architecture"
}

# Function to clone and build MTProto Proxy
build_mtproto() {
    show_info "Building MTProto Proxy for $ARCH_TYPE architecture..."
    
    # Check if directory exists
    if [[ -d "$PROXY_DIR/source" ]]; then
        show_warning "Source directory already exists. Cleaning..."
        rm -rf "$PROXY_DIR/source"
    fi
    
    # Create directory
    mkdir -p "$PROXY_DIR/source"
    cd "$PROXY_DIR/source"
    
    # Clone repository
    show_info "Cloning MTProto Proxy repository..."
    git clone https://github.com/TelegramMessenger/MTProxy.git
    if [[ $? -ne 0 ]]; then
        show_error "Failed to clone repository"
        return 1
    fi
    
    cd MTProxy
    
    # Patch Makefile for current architecture
    create_makefile_patch
    
    # Show current compiler flags
    show_info "Compiler flags to be used:"
    grep "CFLAGS" Makefile | head -5
    
    # Build with multiple jobs for faster compilation
    show_info "Building MTProto Proxy (this may take a few minutes)..."
    
    # Try building with adaptive approach
    if [[ "$ARCH_TYPE" == "arm32" ]]; then
        show_info "Using conservative build settings for ARM32..."
        make CFLAGS="-O2 -std=gnu11 -Wall -fno-strict-aliasing -fwrapv"
    elif [[ "$ARCH_TYPE" == "generic" ]]; then
        show_info "Using generic build settings..."
        make CFLAGS="-O2 -std=gnu11 -Wall -fno-strict-aliasing -fwrapv"
    else
        # Try regular build first
        show_info "Attempting standard build..."
        make -j$(nproc)
    fi
    
    # Check if build succeeded
    if [[ $? -ne 0 ]]; then
        show_warning "Standard build failed, trying alternative approach..."
        
        # Try simpler build
        if [[ -f "Makefile.original" ]]; then
            cp Makefile.original Makefile
        fi
        
        # Try building with minimal flags
        show_info "Trying minimal build configuration..."
        make clean
        
        # Create minimal Makefile override
        cat > Makefile.custom << 'EOF'
CC = gcc
CFLAGS = -O2 -std=gnu11 -Wall -Wno-array-bounds -fno-strict-aliasing -fno-strict-overflow -fwrapv -DAES=1 -D_GNU_SOURCE=1 -D_FILE_OFFSET_BITS=64
LDFLAGS = -lssl -lcrypto -lz -lpthread

# Common includes
COMMON_INCLUDES = -iquote common -iquote .

# Object files
OBJS = objs/mtproto/mtproto-proxy.o objs/mtproto/mtproto-common.o objs/mtproto/mtproto-proxy-functions.o \
       objs/mtproto/mtproxy-engine.o objs/mtproto/mtproto-crypto.o objs/mtproto/mtproto-endian.o \
       objs/mtproto/mtproto-utils.o objs/mtproto/mtproto-session.o objs/mtproto/mtproto-conn.o \
       objs/mtproto/mtproto-timer.o objs/mtproto/mtproto-dh.o objs/mtproto/mtproto-ack.o \
       objs/mtproto/mtproto-ping.o objs/mtproto/mtproto-rpc.o objs/mtproto/mtproto-socks.o \
       objs/mtproto/mtproto-stats.o objs/mtproto/mtproto-datacenter.o objs/mtproto/mtproto-message.o \
       objs/mtproto/mtproto-encrypted-msg.o objs/mtproto/mtproto-message-container.o \
       objs/common/aesni.o objs/common/crypto-aesni.o objs/common/crypto-poly1305.o \
       objs/common/crypto-sha256.o objs/common/crypto.o objs/common/digest.o \
       objs/common/io.o objs/common/net.o objs/common/pid.o objs/common/port.o \
       objs/common/prepare.o objs/common/process.o objs/common/random.o objs/common/rwm.o \
       objs/common/sha256.o objs/common/timer.o objs/common/url.o objs/common/version.o

# Default target
all: objs/bin/mtproto-proxy

# Main binary
objs/bin/mtproto-proxy: $(OBJS)
	@mkdir -p objs/bin
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

# Pattern rule for object files
objs/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(COMMON_INCLUDES) -c -o $@ $<

clean:
	rm -rf objs

.PHONY: all clean
EOF
        
        # Try building with custom Makefile
        cp Makefile.custom Makefile
        make
        
        if [[ $? -ne 0 ]]; then
            show_error "Build failed with both standard and custom methods"
            
            # Try one more time with even simpler flags
            show_info "Attempting ultra-simple build..."
            make clean
            gcc -O2 -std=gnu11 -o objs/bin/mtproto-proxy mtproto/mtproto-proxy.c \
                -lssl -lcrypto -lz -lpthread -lm
            
            if [[ $? -ne 0 ]]; then
                show_error "All build attempts failed"
                return 1
            fi
        fi
    fi
    
    # Check if binary was created
    if [[ ! -f "objs/bin/mtproto-proxy" ]]; then
        show_error "Binary not created after build"
        return 1
    fi
    
    # Make binary executable
    chmod +x objs/bin/mtproto-proxy
    
    # Copy binary to installation directory
    mkdir -p "$PROXY_DIR/bin"
    cp objs/bin/mtproto-proxy "$PROXY_DIR/bin/"
    
    # Verify binary works
    if "$PROXY_DIR/bin/mtproto-proxy" --help >/dev/null 2>&1; then
        show_success "MTProto Proxy built and verified successfully"
    else
        show_warning "Binary created but help test failed (may still work)"
    fi
    
    show_info "Binary location: $PROXY_DIR/bin/mtproto-proxy"
    show_info "Binary size: $(du -h "$PROXY_DIR/bin/mtproto-proxy" | cut -f1)"
}

# Alternative build method using pre-compiled binaries
try_alternative_build() {
    show_info "Trying alternative build methods..."
    
    # Method 1: Try to find pre-built binary for architecture
    case $ARCH_TYPE in
        x64)
            # x86_64 should have worked with patched Makefile
            show_error "x64 build should have worked with patched Makefile"
            return 1
            ;;
        arm64)
            show_info "Looking for ARM64 pre-built solutions..."
            # Could add URL to pre-built binaries here
            ;;
        arm32)
            show_info "Looking for ARM32 pre-built solutions..."
            ;;
    esac
    
    # Method 2: Try Docker-based build
    if command -v docker >/dev/null 2>&1; then
        show_info "Attempting Docker-based build..."
        docker run --rm -v "$PROXY_DIR:/build" alpine:latest sh -c "
            apk add build-base git openssl-dev zlib-dev curl &&
            cd /build &&
            git clone https://github.com/TelegramMessenger/MTProxy.git &&
            cd MTProxy &&
            sed -i 's/-mpclmul//g' Makefile &&
            sed -i 's/-mfpmath=sse//g' Makefile &&
            sed -i 's/-mssse3//g' Makefile &&
            make &&
            cp objs/bin/mtproto-proxy /build/bin/"
        
        if [[ $? -eq 0 && -f "$PROXY_DIR/bin/mtproto-proxy" ]]; then
            show_success "Docker build succeeded"
            return 0
        fi
    fi
    
    return 1
}

# Function to generate random secret key
generate_secret() {
    show_info "Generating secret key..."
    
    # Generate 16 random bytes and convert to hex
    SECRET_KEY=$(head -c 16 /dev/urandom | xxd -ps)
    
    # Save secret to config file
    echo "SECRET_KEY=$SECRET_KEY" > "$CONFIG_FILE"
    
    # Download proxy configuration files
    show_info "Downloading proxy configuration files..."
    
    cd "$PROXY_DIR"
    
    # Try multiple URLs for proxy-secret
    PROXY_SECRET_URLS=(
        "https://core.telegram.org/getProxySecret"
        "https://raw.githubusercontent.com/TelegramMessenger/MTProxy/master/proxy-secret"
    )
    
    for url in "${PROXY_SECRET_URLS[@]}"; do
        show_info "Trying $url..."
        if curl -s --max-time 10 "$url" -o proxy-secret && [[ -s proxy-secret ]]; then
            show_success "Downloaded proxy-secret"
            break
        fi
    done
    
    if [[ ! -f proxy-secret ]] || [[ ! -s proxy-secret ]]; then
        show_error "Failed to download proxy-secret"
        return 1
    fi
    
    # Try multiple URLs for proxy-multi.conf
    PROXY_CONF_URLS=(
        "https://core.telegram.org/getProxyConfig"
        "https://raw.githubusercontent.com/TelegramMessenger/MTProxy/master/proxy-multi.conf"
    )
    
    for url in "${PROXY_CONF_URLS[@]}"; do
        show_info "Trying $url..."
        if curl -s --max-time 10 "$url" -o proxy-multi.conf && [[ -s proxy-multi.conf ]]; then
            show_success "Downloaded proxy-multi.conf"
            break
        fi
    done
    
    if [[ ! -f proxy-multi.conf ]] || [[ ! -s proxy-multi.conf ]]; then
        show_error "Failed to download proxy-multi.conf"
        return 1
    fi
    
    show_success "Secret key generated and configuration files downloaded"
    echo -e "${YELLOW}Secret Key: $SECRET_KEY${NC}"
}

# Function to get server IP
get_server_ip() {
    show_info "Detecting server IP address..."
    
    # Try multiple methods to get public IP
    IP_METHODS=(
        "curl -s --max-time 5 ifconfig.me"
        "curl -s --max-time 5 icanhazip.com"
        "curl -s --max-time 5 ipinfo.io/ip"
        "curl -s --max-time 5 api.ipify.org"
        "curl -s --max-time 5 checkip.amazonaws.com"
    )
    
    for cmd in "${IP_METHODS[@]}"; do
        show_info "Trying: $(echo "$cmd" | awk '{print $2}')"
        SERVER_IP=$(eval $cmd 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
        if [[ -n "$SERVER_IP" ]]; then
            show_success "Detected IP: $SERVER_IP"
            echo "$SERVER_IP"
            return 0
        fi
    done
    
    # If all methods fail, ask user
    show_warning "Could not automatically detect server IP"
    while true; do
        read -p "Enter server IP address or domain: " SERVER_IP
        if [[ -n "$SERVER_IP" ]]; then
            echo "$SERVER_IP"
            return 0
        fi
    done
}

# Function to configure proxy
configure_proxy() {
    show_info "Configuring MTProto Proxy..."
    
    # Ask for configuration parameters
    echo ""
    echo -e "${CYAN}Proxy Configuration${NC}"
    echo "========================================"
    
    # Get server IP
    SERVER_IP=$(get_server_ip)
    echo ""
    
    # Port configuration
    read -p "Enter proxy port (default: 443): " PROXY_PORT
    PROXY_PORT=${PROXY_PORT:-443}
    
    # Validate port
    if [[ ! "$PROXY_PORT" =~ ^[0-9]+$ ]] || [[ "$PROXY_PORT" -lt 1 ]] || [[ "$PROXY_PORT" -gt 65535 ]]; then
        show_error "Invalid port number. Using default 443."
        PROXY_PORT=443
    fi
    
    # Internal port for metrics
    read -p "Enter internal port for stats (default: 8888): " INTERNAL_PORT
    INTERNAL_PORT=${INTERNAL_PORT:-8888}
    
    # Worker processes based on architecture
    case $ARCH_TYPE in
        x64)
            DEFAULT_WORKERS=2
            MAX_WORKERS=4
            ;;
        arm64)
            DEFAULT_WORKERS=1
            MAX_WORKERS=2
            ;;
        *)
            DEFAULT_WORKERS=1
            MAX_WORKERS=1
            ;;
    esac
    
    read -p "Enter number of worker processes ($DEFAULT_WORKERS-$MAX_WORKERS) [default: $DEFAULT_WORKERS]: " WORKER_COUNT
    WORKER_COUNT=${WORKER_COUNT:-$DEFAULT_WORKERS}
    
    # Max connections based on architecture
    case $ARCH_TYPE in
        x64)
            DEFAULT_MAX_CONN=5000
            ;;
        arm64)
            DEFAULT_MAX_CONN=2000
            ;;
        *)
            DEFAULT_MAX_CONN=1000
            ;;
    esac
    
    read -p "Enter maximum connections (default: $DEFAULT_MAX_CONN): " MAX_CONNECTIONS
    MAX_CONNECTIONS=${MAX_CONNECTIONS:-$DEFAULT_MAX_CONN}
    
    # Update config file
    {
        echo "# MTProto Proxy Configuration"
        echo "ARCH_TYPE=$ARCH_TYPE"
        echo "SERVER_IP=$SERVER_IP"
        echo "PROXY_PORT=$PROXY_PORT"
        echo "INTERNAL_PORT=$INTERNAL_PORT"
        echo "WORKER_COUNT=$WORKER_COUNT"
        echo "MAX_CONNECTIONS=$MAX_CONNECTIONS"
        echo "# Generated on $(date)"
    } > "$CONFIG_FILE"
    
    # Load secret key or generate new one
    if [[ -f "$CONFIG_FILE" ]] && grep -q "SECRET_KEY" "$CONFIG_FILE"; then
        source "$CONFIG_FILE"
    else
        show_info "Generating new secret key..."
        generate_secret
        source "$CONFIG_FILE"
    fi
    
    show_success "Proxy configuration saved to $CONFIG_FILE"
}

# Function to create systemd service
create_service() {
    show_info "Creating systemd service..."
    
    # Load configuration
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
    else
        show_error "Config file not found at $CONFIG_FILE"
        return 1
    fi
    
    # Create service file with appropriate settings for architecture
    case $ARCH_TYPE in
        x64)
            RESTART_SEC=5
            LIMIT_NOFILE=65536
            ;;
        arm64)
            RESTART_SEC=10
            LIMIT_NOFILE=32768
            ;;
        *)
            RESTART_SEC=15
            LIMIT_NOFILE=16384
            ;;
    esac
    
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=MTProto Proxy Service
After=network.target
Wants=network.target

[Service]
Type=simple
User=nobody
Group=nogroup
WorkingDirectory=$PROXY_DIR
Environment="PROXY_PORT=$PROXY_PORT"
Environment="INTERNAL_PORT=$INTERNAL_PORT"
Environment="SECRET_KEY=$SECRET_KEY"
ExecStart=$PROXY_DIR/bin/mtproto-proxy \\
    -u nobody \\
    -p $INTERNAL_PORT \\
    -H $PROXY_PORT \\
    -S $SECRET_KEY \\
    --aes-pwd $PROXY_DIR/proxy-secret \\
    --allow-skip-dh \\
    --max-special-connections $MAX_CONNECTIONS \\
    -M $WORKER_COUNT \\
    --slaves $WORKER_COUNT \\
    --stats-log "$LOG_FILE"
Restart=always
RestartSec=$RESTART_SEC
StandardOutput=append:$LOG_FILE
StandardError=append:$LOG_FILE
LimitNOFILE=$LIMIT_NOFILE
Nice=10
CPUSchedulingPolicy=idle

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    
    show_success "Systemd service created and enabled"
    show_info "Service file: $SERVICE_FILE"
}

# Function to start proxy
start_proxy() {
    show_info "Starting MTProto Proxy..."
    
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        show_warning "Service is already running. Restarting instead..."
        restart_proxy
        return
    fi
    
    systemctl start "$SERVICE_NAME"
    
    if [[ $? -eq 0 ]]; then
        show_success "MTProto Proxy started successfully"
        sleep 3
        check_status
    else
        show_error "Failed to start MTProto Proxy"
        journalctl -u "$SERVICE_NAME" -n 20 --no-pager
    fi
}

# Function to stop proxy
stop_proxy() {
    show_info "Stopping MTProto Proxy..."
    
    if ! systemctl is-active --quiet "$SERVICE_NAME"; then
        show_warning "Service is not running"
        return
    fi
    
    systemctl stop "$SERVICE_NAME"
    
    if [[ $? -eq 0 ]]; then
        show_success "MTProto Proxy stopped successfully"
    else
        show_error "Failed to stop MTProto Proxy"
    fi
}

# Function to restart proxy
restart_proxy() {
    show_info "Restarting MTProto Proxy..."
    
    systemctl restart "$SERVICE_NAME"
    
    if [[ $? -eq 0 ]]; then
        show_success "MTProto Proxy restarted successfully"
        sleep 2
        check_status
    else
        show_error "Failed to restart MTProto Proxy"
        journalctl -u "$SERVICE_NAME" -n 20 --no-pager
    fi
}

# Function to check proxy status
check_status() {
    show_info "Checking MTProto Proxy status..."
    
    echo -e "${CYAN}Service Status:${NC}"
    systemctl status "$SERVICE_NAME" --no-pager -l
    
    # Check if proxy is listening
    echo ""
    echo -e "${CYAN}Network Connections:${NC}"
    if command -v ss >/dev/null 2>&1; then
        ss -tulpn | grep -E ":$PROXY_PORT|:$INTERNAL_PORT" | grep -v grep || echo "No proxy ports found listening"
    else
        netstat -tulpn 2>/dev/null | grep -E ":$PROXY_PORT|:$INTERNAL_PORT" | grep -v grep || echo "No proxy ports found listening"
    fi
    
    # Show logs
    echo ""
    echo -e "${CYAN}Recent Logs (last 10 lines):${NC}"
    if [[ -f "$LOG_FILE" ]]; then
        tail -10 "$LOG_FILE"
    else
        journalctl -u "$SERVICE_NAME" -n 10 --no-pager
    fi
    
    # Show memory usage
    echo ""
    echo -e "${CYAN}Memory Usage:${NC}"
    ps aux | grep mtproto-proxy | grep -v grep | awk '{print "Memory: "$6/1024" MB"}'
}

# Function to show proxy information
show_proxy_info() {
    show_info "MTProto Proxy Information"
    echo "========================================"
    
    if [[ -f "$CONFIG_FILE" ]]; then
        # Source config file
        source "$CONFIG_FILE"
        
        echo -e "${CYAN}System Information:${NC}"
        echo "Architecture: $ARCH_TYPE"
        echo "Server IP: $SERVER_IP"
        
        echo ""
        echo -e "${CYAN}Proxy Configuration:${NC}"
        echo "External Port: $PROXY_PORT"
        echo "Internal Port: $INTERNAL_PORT"
        echo "Worker Processes: $WORKER_COUNT"
        echo "Max Connections: $MAX_CONNECTIONS"
        echo "Secret Key: $SECRET_KEY"
        
        echo ""
        echo -e "${CYAN}Connection URLs:${NC}"
        
        # Create tg:// URL
        TG_URL="tg://proxy?server=$SERVER_IP&port=$PROXY_PORT&secret=$SECRET_KEY"
        echo "Telegram URL:"
        echo "  $TG_URL"
        
        # Create https:// URL
        HTTPS_URL="https://t.me/proxy?server=$SERVER_IP&port=$PROXY_PORT&secret=$SECRET_KEY"
        echo "HTTPS URL:"
        echo "  $HTTPS_URL"
        
        echo ""
        echo -e "${CYAN}Usage Instructions:${NC}"
        echo "1. Open Telegram"
        echo "2. Go to Settings > Data and Storage > Proxy"
        echo "3. Add Proxy"
        echo "4. Select 'MTProto Proxy'"
        echo "5. Enter the following:"
        echo "   - Server: $SERVER_IP"
        echo "   - Port: $PROXY_PORT"
        echo "   - Secret: $SECRET_KEY"
        
        echo ""
        echo -e "${YELLOW}To share this proxy:${NC}"
        echo "Server: $SERVER_IP"
        echo "Port: $PROXY_PORT"
        echo "Secret: $SECRET_KEY"
        
        echo ""
        echo -e "${GREEN}Configuration file: $CONFIG_FILE${NC}"
        
    else
        show_error "Configuration file not found at $CONFIG_FILE"
        show_info "Please install the proxy first using option 1"
    fi
}

# Function to uninstall proxy
uninstall_proxy() {
    show_warning "⚠️  WARNING: This will completely remove MTProto Proxy and all its data!"
    read -p "Are you sure you want to continue? (yes/NO): " -r
    echo
    
    if [[ "$REPLY" =~ ^[Yy][Ee][Ss]$ ]]; then
        show_info "Stopping and disabling service..."
        systemctl stop "$SERVICE_NAME" 2>/dev/null
        systemctl disable "$SERVICE_NAME" 2>/dev/null
        rm -f "$SERVICE_FILE"
        systemctl daemon-reload
        
        show_info "Removing proxy files..."
        rm -rf "$PROXY_DIR"
        
        show_info "Cleaning up logs..."
        rm -f "$LOG_FILE"
        journalctl --vacuum-time=1d 2>/dev/null || true
        
        show_success "✅ MTProto Proxy completely uninstalled"
    else
        show_info "Uninstallation cancelled"
    fi
}

# Function to check for updates
check_updates() {
    show_info "Checking for MTProto Proxy updates..."
    
    cd "$PROXY_DIR/source/MTProxy" 2>/dev/null || {
        show_error "Source directory not found"
        return 1
    }
    
    git fetch origin
    LOCAL_COMMIT=$(git rev-parse HEAD)
    REMOTE_COMMIT=$(git rev-parse origin/master)
    
    if [[ "$LOCAL_COMMIT" != "$REMOTE_COMMIT" ]]; then
        show_warning "Update available!"
        show_info "Local:  $LOCAL_COMMIT"
        show_info "Remote: $REMOTE_COMMIT"
        return 0
    else
        show_success "You have the latest version"
        return 1
    fi
}

# Function to install proxy
install_proxy() {
    show_banner
    show_info "Starting MTProto Proxy installation..."
    
    # Check prerequisites
    check_root
    
    # Detect architecture
    detect_architecture
    check_gcc_version
    
    # Update system
    update_system
    
    # Install dependencies
    install_dependencies
    if [[ $? -ne 0 ]]; then
        show_error "Failed to install dependencies"
        exit 1
    fi
    
    # Create proxy directory
    mkdir -p "$PROXY_DIR"
    mkdir -p "$PROXY_DIR/bin"
    
    # Build MTProto Proxy
    build_mtproto
    if [[ $? -ne 0 ]]; then
        show_warning "Standard build failed, trying alternative methods..."
        try_alternative_build
        
        if [[ $? -ne 0 ]] || [[ ! -f "$PROXY_DIR/bin/mtproto-proxy" ]]; then
            show_error "All build methods failed"
            show_info "Consider using a different machine architecture or installing manually"
            exit 1
        fi
    fi
    
    # Generate secret and download config
    generate_secret
    if [[ $? -ne 0 ]]; then
        show_error "Failed to generate secret or download config"
        exit 1
    fi
    
    # Configure proxy
    configure_proxy
    
    # Create systemd service
    create_service
    if [[ $? -ne 0 ]]; then
        show_error "Failed to create systemd service"
        exit 1
    fi
    
    # Start proxy
    start_proxy
    
    echo ""
    show_success "✅ Installation completed successfully!"
    echo ""
    
    # Show proxy information
    show_proxy_info
}

# Function to show main menu
show_menu() {
    show_banner
    
    echo -e "${CYAN}Main Menu${NC}"
    echo "========================================"
    echo "1. Install MTProto Proxy"
    echo "2. Start Proxy"
    echo "3. Stop Proxy"
    echo "4. Restart Proxy"
    echo "5. Check Status"
    echo "6. Show Proxy Info"
    echo "7. Update System Packages"
    echo "8. Check for Updates"
    echo "9. Uninstall Proxy"
    echo "0. Exit"
    echo "========================================"
}

# Main script execution
main() {
    # Check if running as root
    check_root
    
    while true; do
        show_menu
        
        read -p "Select an option (0-9): " choice
        echo ""
        
        case $choice in
            1)
                install_proxy
                ;;
            2)
                start_proxy
                ;;
            3)
                stop_proxy
                ;;
            4)
                restart_proxy
                ;;
            5)
                check_status
                ;;
            6)
                show_proxy_info
                ;;
            7)
                update_system
                ;;
            8)
                check_updates
                ;;
            9)
                uninstall_proxy
                ;;
            0)
                show_info "Exiting... Goodbye!"
                exit 0
                ;;
            *)
                show_error "Invalid option. Please try again."
                ;;
        esac
        
        echo ""
        read -p "Press Enter to continue..."
    done
}

# Run the main function
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
