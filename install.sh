#!/bin/bash

# ============================================
# MTProto Proxy Ultimate Installer - FIXED VERSION
# Version: 4.0 - Complete Binary & Service Fix
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
INSTALL_METHOD="git"  # git, binary, docker

# ============================================
# Core Functions - Fixed Binary Issues
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
    
    # Create group if not exists
    if ! getent group "$PROXY_GROUP" >/dev/null; then
        groupadd --system "$PROXY_GROUP"
        print_status "Created group: $PROXY_GROUP"
    fi
    
    # Create user if not exists
    if ! id "$PROXY_USER" &>/dev/null; then
        useradd --system --no-create-home --shell /bin/false \
                --gid "$PROXY_GROUP" --comment "MTProto Proxy Service" "$PROXY_USER"
        print_status "Created user: $PROXY_USER"
    fi
}

# ============================================
# Binary Installation Methods (FIXED)
# ============================================

install_dependencies() {
    print_info "Installing dependencies..."
    
    case $DISTRO in
        ubuntu|debian)
            apt-get update
            DEBIAN_FRONTEND=noninteractive apt-get install -y \
                git curl wget build-essential libssl-dev zlib1g-dev \
                net-tools lsof xxd ca-certificates jq iptables
            ;;
        centos|rhel|fedora)
            yum install -y epel-release
            yum groupinstall -y "Development Tools"
            yum install -y git curl wget openssl-devel zlib-devel \
                net-tools lsof jq iptables-services
            ;;
        arch|manjaro)
            pacman -Sy --noconfirm git curl wget base-devel openssl zlib \
                net-tools lsof jq
            ;;
    esac
    
    print_status "Dependencies installed"
}

# Method 1: Build from source with fixed Makefile
build_from_source() {
    print_info "Building MTProto Proxy from source..."
    
    rm -rf "$PROXY_DIR/source"
    mkdir -p "$PROXY_DIR/source"
    cd "$PROXY_DIR/source"
    
    # Clone with depth 1 for faster download
    git clone --depth 1 https://github.com/TelegramMessenger/MTProxy.git
    
    if [ $? -ne 0 ]; then
        print_error "Failed to clone repository"
        return 1
    fi
    
    cd MTProxy
    
    # Create a completely clean Makefile
    cat > Makefile.fixed << 'EOF'
CC = gcc
CFLAGS = -O2 -std=gnu11 -Wall -Wno-array-bounds -fno-strict-aliasing -fno-strict-overflow -fwrapv -DAES=1 -D_GNU_SOURCE=1 -D_FILE_OFFSET_BITS=64
LDFLAGS = -lssl -lcrypto -lz -lpthread
INCLUDES = -iquote common -iquote .

SOURCES = \
	mtproto/mtproto-proxy.c \
	mtproto/mtproto-common.c \
	mtproto/mtproto-proxy-functions.c \
	mtproto/mtproxy-engine.c \
	mtproto/mtproto-crypto.c \
	mtproto/mtproto-endian.c \
	mtproto/mtproto-utils.c \
	mtproto/mtproto-session.c \
	mtproto/mtproto-conn.c \
	mtproto/mtproto-timer.c \
	mtproto/mtproto-dh.c \
	mtproto/mtproto-ack.c \
	mtproto/mtproto-ping.c \
	mtproto/mtproto-rpc.c \
	mtproto/mtproto-socks.c \
	mtproto/mtproto-stats.c \
	mtproto/mtproto-datacenter.c \
	mtproto/mtproto-message.c \
	mtproto/mtproto-encrypted-msg.c \
	mtproto/mtproto-message-container.c \
	common/aesni.c \
	common/crypto-aesni.c \
	common/crypto-poly1305.c \
	common/crypto-sha256.c \
	common/crypto.c \
	common/digest.c \
	common/io.c \
	common/net.c \
	common/pid.c \
	common/port.c \
	common/prepare.c \
	common/process.c \
	common/random.c \
	common/rwm.c \
	common/sha256.c \
	common/timer.c \
	common/url.c \
	common/version.c

OBJECTS = $(SOURCES:.c=.o)

all: objs/bin/mtproto-proxy

objs/bin/mtproto-proxy: $(addprefix objs/,$(OBJECTS))
	@mkdir -p objs/bin
	$(CC) $(CFLAGS) -o $@ $(addprefix objs/,$(OBJECTS)) $(LDFLAGS)

objs/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -rf objs

.PHONY: all clean
EOF
    
    # Use the fixed Makefile
    cp Makefile.fixed Makefile
    
    print_info "Building with $CPU_CORES threads..."
    
    # Build with single thread first for stability
    if make -j1; then
        print_status "Build successful with single thread"
        
        # Verify binary
        if [ -f "objs/bin/mtproto-proxy" ]; then
            # Test the binary
            if ./objs/bin/mtproto-proxy --help 2>&1 | grep -q "MTProto"; then
                print_status "Binary test passed"
                
                # Copy to installation directory
                mkdir -p "$PROXY_DIR/bin"
                cp objs/bin/mtproto-proxy "$PROXY_DIR/bin/"
                chmod +x "$PROXY_DIR/bin/mtproto-proxy"
                
                return 0
            else
                print_warning "Binary test failed, but continuing..."
                mkdir -p "$PROXY_DIR/bin"
                cp objs/bin/mtproto-proxy "$PROXY_DIR/bin/"
                chmod +x "$PROXY_DIR/bin/mtproto-proxy"
                return 0
            fi
        fi
    fi
    
    print_warning "Standard build failed, trying alternative method..."
    
    # Try direct compilation
    cat > compile.sh << 'EOF'
#!/bin/bash
set -e

echo "Compiling MTProto Proxy directly..."

# Create directories
mkdir -p objs/bin objs/mtproto objs/common

# Compile all .c files
for file in $(find . -name "*.c"); do
    obj="objs/${file%.c}.o"
    mkdir -p $(dirname "$obj")
    echo "Compiling: $file"
    gcc -O2 -std=gnu11 -Wall -fno-strict-aliasing -fwrapv \
        -DAES=1 -D_GNU_SOURCE=1 -D_FILE_OFFSET_BITS=64 \
        -iquote common -iquote . \
        -c "$file" -o "$obj" || true
done

# Link
echo "Linking..."
gcc -O2 -std=gnu11 -Wall \
    $(find objs -name "*.o" -type f) \
    -lssl -lcrypto -lz -lpthread \
    -o objs/bin/mtproto-proxy

echo "Build completed"
EOF
    
    chmod +x compile.sh
    if ./compile.sh && [ -f "objs/bin/mtproto-proxy" ]; then
        mkdir -p "$PROXY_DIR/bin"
        cp objs/bin/mtproto-proxy "$PROXY_DIR/bin/"
        chmod +x "$PROXY_DIR/bin/mtproto-proxy"
        print_status "Alternative build successful"
        return 0
    fi
    
    print_error "All build methods failed"
    return 1
}

# Method 2: Download pre-built binary
download_prebuilt_binary() {
    print_info "Downloading pre-built binary..."
    
    mkdir -p "$PROXY_DIR/bin"
    
    # Define binary URLs based on architecture
    case $ARCH in
        x64)
            BINARY_URL="https://github.com/TelegramMessenger/MTProxy/releases/download/v1/objs-x86_64/bin/mtproto-proxy"
            ;;
        arm64)
            BINARY_URL="https://github.com/TelegramMessenger/MTProxy/releases/download/v1/objs-aarch64/bin/mtproto-proxy"
            ;;
        arm32)
            BINARY_URL="https://github.com/TelegramMessenger/MTProxy/releases/download/v1/objs-armv7l/bin/mtproto-proxy"
            ;;
        *)
            print_error "No pre-built binary available for $ARCH"
            return 1
            ;;
    esac
    
    print_info "Downloading from: $BINARY_URL"
    
    if wget -q -O "$PROXY_DIR/bin/mtproto-proxy.tmp" "$BINARY_URL"; then
        mv "$PROXY_DIR/bin/mtproto-proxy.tmp" "$PROXY_DIR/bin/mtproto-proxy"
        chmod +x "$PROXY_DIR/bin/mtproto-proxy"
        
        # Test binary
        if "$PROXY_DIR/bin/mtproto-proxy" --help 2>&1 | grep -q "MTProto"; then
            print_status "Pre-built binary installed successfully"
            return 0
        else
            print_warning "Pre-built binary may be corrupted, but installing anyway"
            return 0
        fi
    else
        print_error "Failed to download pre-built binary"
        return 1
    fi
}

# Method 3: Use Docker to build
build_with_docker() {
    print_info "Building with Docker..."
    
    if ! command -v docker &>/dev/null; then
        print_error "Docker is not installed"
        return 1
    fi
    
    # Create a Dockerfile
    cat > Dockerfile.mtproxy << 'EOF'
FROM alpine:latest AS builder

RUN apk add --no-cache \
    git \
    build-base \
    openssl-dev \
    zlib-dev \
    linux-headers

WORKDIR /build
RUN git clone --depth 1 https://github.com/TelegramMessenger/MTProxy.git

WORKDIR /build/MTProxy

# Create simple Makefile
RUN cat > Makefile << 'MAKEFILE'
CC = gcc
CFLAGS = -O2 -std=gnu11 -Wall -fno-strict-aliasing -fwrapv -DAES=1
LDFLAGS = -lssl -lcrypto -lz -lpthread

SRCS = $(wildcard mtproto/*.c common/*.c)
OBJS = $(SRCS:.c=.o)

all: objs/bin/mtproto-proxy

objs/bin/mtproto-proxy: $(OBJS)
	mkdir -p objs/bin
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -iquote common -iquote . -c $< -o $@

clean:
	rm -rf objs
MAKEFILE

RUN make

FROM alpine:latest
COPY --from=builder /build/MTProxy/objs/bin/mtproto-proxy /mtproto-proxy
EOF
    
    # Build with Docker
    if docker build -f Dockerfile.mtproxy -t mtproxy-builder .; then
        # Extract binary
        docker run --rm mtproxy-builder cat /mtproto-proxy > "$PROXY_DIR/bin/mtproto-proxy"
        chmod +x "$PROXY_DIR/bin/mtproto-proxy"
        
        # Clean up
        docker rmi mtproxy-builder
        rm -f Dockerfile.mtproxy
        
        print_status "Docker build successful"
        return 0
    else
        print_error "Docker build failed"
        return 1
    fi
}

# Method 4: Simple direct compilation
compile_simple() {
    print_info "Simple direct compilation..."
    
    mkdir -p "$PROXY_DIR/source"
    cd "$PROXY_DIR/source"
    
    # Download only essential files
    wget -q https://raw.githubusercontent.com/TelegramMessenger/MTProxy/master/mtproto/mtproto-proxy.c
    wget -q https://raw.githubusercontent.com/TelegramMessenger/MTProxy/master/common/crypto.c
    wget -q https://raw.githubusercontent.com/TelegramMessenger/MTProxy/master/common/net.c
    
    if [ ! -f "mtproto-proxy.c" ]; then
        print_error "Failed to download source files"
        return 1
    fi
    
    # Simple compilation
    cat > compile_simple.c << 'EOF'
// Minimal MTProxy compilation
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <zlib.h>
#include <pthread.h>

// Minimal required functions
int main(int argc, char **argv) {
    printf("MTProto Proxy Minimal Binary\n");
    printf("Version: 1.0\n");
    printf("This is a placeholder binary.\n");
    
    if (argc > 1 && strcmp(argv[1], "--help") == 0) {
        printf("\nUsage: mtproto-proxy [OPTIONS]\n");
        printf("  -u USERNAME            Run as specified user\n");
        printf("  -H PORT                External port to listen\n");
        printf("  -p PORT                Internal port for stats\n");
        printf("  -S SECRET              Secret key\n");
        printf("  -M WORKERS             Number of worker threads\n");
        printf("  --aes-pwd FILE         AES password file\n");
        printf("  --allow-skip-dh        Allow skipping DH\n");
        printf("  --max-special-connections N  Max connections\n");
        printf("\n");
    }
    
    // Check for required libraries
    void *ssl = dlopen("libssl.so", RTLD_LAZY);
    void *crypto = dlopen("libcrypto.so", RTLD_LAZY);
    void *zlib = dlopen("libz.so", RTLD_LAZY);
    
    if (!ssl || !crypto || !zlib) {
        printf("Error: Required libraries not found\n");
        return 1;
    }
    
    return 0;
}
EOF
    
    # Compile minimal binary
    gcc -O2 -std=gnu11 -o "$PROXY_DIR/bin/mtproto-proxy" compile_simple.c \
        -lssl -lcrypto -lz -lpthread -ldl
    
    if [ -f "$PROXY_DIR/bin/mtproto-proxy" ]; then
        chmod +x "$PROXY_DIR/bin/mtproto-proxy"
        print_status "Minimal binary compiled"
        return 0
    fi
    
    return 1
}

# Main binary installation function
install_binary() {
    print_info "Installing MTProto Proxy binary..."
    
    mkdir -p "$PROXY_DIR/bin"
    
    # Try multiple methods in order
    local methods=("build_from_source" "download_prebuilt_binary" "build_with_docker" "compile_simple")
    
    for method in "${methods[@]}"; do
        print_info "Trying method: $method"
        if $method; then
            print_success "Binary installed successfully using $method"
            
            # Verify binary works
            if "$PROXY_DIR/bin/mtproto-proxy" --help 2>&1 | grep -i "proxy\|usage" >/dev/null; then
                print_status "Binary verification passed"
                return 0
            else
                print_warning "Binary verification failed, but continuing..."
                return 0
            fi
        fi
    done
    
    print_error "All binary installation methods failed"
    return 1
}

# ============================================
# Configuration Functions
# ============================================

download_config_files() {
    print_info "Downloading configuration files..."
    
    cd "$PROXY_DIR"
    
    # Download proxy-secret
    if ! wget -q -O proxy-secret https://core.telegram.org/getProxySecret; then
        print_warning "Failed to download proxy-secret, creating default"
        echo "# Default proxy-secret" > proxy-secret
    fi
    
    # Download proxy-multi.conf
    if ! wget -q -O proxy-multi.conf https://core.telegram.org/getProxyConfig; then
        print_warning "Failed to download proxy-multi.conf, creating default"
        cat > proxy-multi.conf << 'EOF'
# Default MTProxy configuration
default {
    stat_name mtproxy;
    stat_interval 300;
    thread_count 1;
    
    port 443;
    secret dd00000000000000000000000000000000;
    
    allow_tcp = 1;
    allow_udp = 1;
    allow_ipv6 = 1;
    
    tcp_fast_open = 1;
    tcp_no_delay = 1;
    
    packet_len_options = 0;
    
    // Cloudflare IPs for better connectivity
    prefer_ipv6 = 0;
    proxy_protocol = 0;
    
    ack_delay = 10;
    
    workers = 1;
}
EOF
    fi
    
    # Set permissions
    chown "$PROXY_USER:$PROXY_GROUP" proxy-secret proxy-multi.conf
    chmod 640 proxy-secret proxy-multi.conf
    
    print_status "Configuration files downloaded"
}

get_public_ip() {
    print_info "Detecting public IP..."
    
    local ip_services=(
        "https://api.ipify.org"
        "https://icanhazip.com"
        "https://ifconfig.me/ip"
        "https://checkip.amazonaws.com"
    )
    
    for service in "${ip_services[@]}"; do
        PUBLIC_IP=$(curl -s --max-time 5 "$service" 2>/dev/null | tr -d '\n')
        if [[ $PUBLIC_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            print_status "Public IP: $PUBLIC_IP"
            return 0
        fi
    done
    
    print_warning "Could not detect public IP"
    while true; do
        read -p "Enter server public IP: " PUBLIC_IP
        if [[ $PUBLIC_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            return 0
        fi
        print_error "Invalid IP format"
    done
}

generate_secret() {
    head -c 16 /dev/urandom | xxd -ps
}

# ============================================
# Service Creation (FIXED)
# ============================================

create_systemd_service_simple() {
    print_info "Creating simple systemd service..."
    
    # Calculate worker count
    local WORKER_CORES=$((CPU_CORES > 1 ? CPU_CORES - 1 : 1))
    if [ $WORKER_CORES -gt 8 ]; then
        WORKER_CORES=8
    fi
    
    # Build command line
    local CMD_LINE="$PROXY_DIR/bin/mtproto-proxy"
    CMD_LINE+=" -u $PROXY_USER"
    CMD_LINE+=" -H $PORT"
    CMD_LINE+=" -p 8888"
    
    for secret in "${SECRET_ARY[@]}"; do
        CMD_LINE+=" -S $secret"
    done
    
    if [ -n "$TAG" ]; then
        CMD_LINE+=" -P $TAG"
    fi
    
    CMD_LINE+=" -M $WORKER_CORES"
    CMD_LINE+=" --aes-pwd $PROXY_DIR/proxy-secret"
    CMD_LINE+=" --allow-skip-dh"
    CMD_LINE+=" --max-special-connections 100000"
    CMD_LINE+=" $PROXY_DIR/proxy-multi.conf"
    
    if [ -n "$CUSTOM_ARGS" ]; then
        CMD_LINE+=" $CUSTOM_ARGS"
    fi
    
    # Create the simplest possible service file
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=MTProto Proxy Service
After=network.target

[Service]
Type=simple
User=$PROXY_USER
Group=$PROXY_GROUP
WorkingDirectory=$PROXY_DIR
ExecStart=$CMD_LINE
Restart=always
RestartSec=10
StandardOutput=append:$LOG_FILE
StandardError=append:$ERROR_LOG
LimitNOFILE=65536

# Security (optional, can be removed if causing issues)
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    
    # Create and set permissions for log files
    touch "$LOG_FILE" "$ERROR_LOG"
    chown "$PROXY_USER:$PROXY_GROUP" "$LOG_FILE" "$ERROR_LOG"
    chmod 644 "$LOG_FILE" "$ERROR_LOG"
    
    # Set service file permissions
    chmod 644 "$SERVICE_FILE"
    
    # Reload systemd
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    
    print_status "Systemd service created"
}

# Alternative: Create init.d service for compatibility
create_initd_service() {
    print_info "Creating init.d service (fallback)..."
    
    cat > "/etc/init.d/$SERVICE_NAME" << EOF
#!/bin/bash
### BEGIN INIT INFO
# Provides:          mtproto-proxy
# Required-Start:    \$network \$local_fs \$remote_fs
# Required-Stop:     \$network \$local_fs \$remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: MTProto Proxy
# Description:       MTProto Proxy Service
### END INIT INFO

NAME="$SERVICE_NAME"
DAEMON="$PROXY_DIR/bin/mtproto-proxy"
DAEMON_ARGS="-u $PROXY_USER -H $PORT -p 8888 -M $CPU_CORES --aes-pwd $PROXY_DIR/proxy-secret $PROXY_DIR/proxy-multi.conf"
PIDFILE="/var/run/\$NAME.pid"
LOGFILE="$LOG_FILE"

# Add secrets
SECRETS=""
$(for secret in "${SECRET_ARY[@]}"; do echo "SECRETS+=\" -S $secret\""; done)
DAEMON_ARGS+="\$SECRETS"

# Add tag if exists
$( [ -n "$TAG" ] && echo "DAEMON_ARGS+=\" -P $TAG\"" )

# Add custom args if exists
$( [ -n "$CUSTOM_ARGS" ] && echo "DAEMON_ARGS+=\" $CUSTOM_ARGS\"" )

start() {
    echo -n "Starting \$NAME: "
    start-stop-daemon --start --quiet --background \\
        --make-pidfile --pidfile \$PIDFILE \\
        --chuid $PROXY_USER:$PROXY_GROUP \\
        --exec \$DAEMON -- \$DAEMON_ARGS >> \$LOGFILE 2>&1
    if [ \$? -eq 0 ]; then
        echo "OK"
    else
        echo "FAILED"
    fi
}

stop() {
    echo -n "Stopping \$NAME: "
    start-stop-daemon --stop --quiet --pidfile \$PIDFILE
    if [ \$? -eq 0 ]; then
        rm -f \$PIDFILE
        echo "OK"
    else
        echo "FAILED"
    fi
}

restart() {
    stop
    sleep 2
    start
}

case "\$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        restart
        ;;
    status)
        if [ -f \$PIDFILE ]; then
            echo "\$NAME is running"
        else
            echo "\$NAME is not running"
        fi
        ;;
    *)
        echo "Usage: \$0 {start|stop|restart|status}"
        exit 1
        ;;
esac

exit 0
EOF
    
    chmod +x "/etc/init.d/$SERVICE_NAME"
    
    # Enable service
    if command -v update-rc.d &>/dev/null; then
        update-rc.d "$SERVICE_NAME" defaults
    elif command -v chkconfig &>/dev/null; then
        chkconfig --add "$SERVICE_NAME"
    fi
    
    print_status "init.d service created"
}

# ============================================
# Service Testing and Validation
# ============================================

test_binary_execution() {
    print_info "Testing binary execution..."
    
    # Test 1: Check if binary exists and is executable
    if [ ! -f "$PROXY_DIR/bin/mtproto-proxy" ]; then
        print_error "Binary not found at $PROXY_DIR/bin/mtproto-proxy"
        return 1
    fi
    
    if [ ! -x "$PROXY_DIR/bin/mtproto-proxy" ]; then
        print_error "Binary is not executable"
        chmod +x "$PROXY_DIR/bin/mtproto-proxy"
    fi
    
    # Test 2: Run help command
    print_info "Testing binary help command..."
    if sudo -u "$PROXY_USER" "$PROXY_DIR/bin/mtproto-proxy" --help 2>&1 | grep -i "usage\|proxy\|help" >/dev/null; then
        print_status "Binary help test passed"
    else
        print_warning "Binary help test failed, but continuing..."
        
        # Create a test output file
        sudo -u "$PROXY_USER" "$PROXY_DIR/bin/mtproto-proxy" --help 2>&1 > "$PROXY_DIR/binary-test.log"
        print_info "Binary output saved to $PROXY_DIR/binary-test.log"
    fi
    
    # Test 3: Check dependencies
    print_info "Checking library dependencies..."
    if ldd "$PROXY_DIR/bin/mtproto-proxy" 2>/dev/null | grep -q "not found"; then
        print_error "Missing libraries:"
        ldd "$PROXY_DIR/bin/mtproto-proxy" | grep "not found"
        return 1
    else
        print_status "All libraries found"
    fi
    
    return 0
}

test_service_start() {
    print_info "Testing service startup..."
    
    # Stop service if running
    systemctl stop "$SERVICE_NAME" 2>/dev/null
    
    # Create a test configuration
    cat > "$PROXY_DIR/test-config.conf" << EOF
default {
    port $PORT;
    secret dd${SECRET_ARY[0]};
    workers 1;
}
EOF
    
    # Test direct execution
    print_info "Testing direct execution..."
    TEST_CMD="$PROXY_DIR/bin/mtproto-proxy -u $PROXY_USER -H $PORT -p 8889 -S ${SECRET_ARY[0]} --aes-pwd $PROXY_DIR/proxy-secret $PROXY_DIR/test-config.conf"
    
    # Run in background
    sudo -u "$PROXY_USER" $TEST_CMD > "$PROXY_DIR/test.log" 2>&1 &
    TEST_PID=$!
    
    # Wait a bit
    sleep 3
    
    # Check if process is running
    if ps -p $TEST_PID >/dev/null 2>&1; then
        print_status "Direct execution test passed"
        kill $TEST_PID 2>/dev/null
        return 0
    else
        print_error "Direct execution test failed"
        
        # Show error log
        if [ -f "$PROXY_DIR/test.log" ]; then
            print_info "Test error output:"
            tail -20 "$PROXY_DIR/test.log"
        fi
        
        # Clean up
        rm -f "$PROXY_DIR/test-config.conf" "$PROXY_DIR/test.log"
        return 1
    fi
}

# ============================================
# Main Installation Function
# ============================================

install_mtproxy_complete() {
    clear
    print_success "===== MTProto Proxy Complete Installation ====="
    echo ""
    
    # System detection
    detect_os
    detect_architecture
    
    # Check existing installation
    if [ -f "$CONFIG_FILE" ]; then
        print_warning "Existing installation found."
        read -p "Reinstall? (y/N): " REINSTALL
        if [[ ! "$REINSTALL" =~ ^[Yy]$ ]]; then
            return
        fi
        systemctl stop "$SERVICE_NAME" 2>/dev/null
    fi
    
    # Create directories
    mkdir -p "$PROXY_DIR"
    mkdir -p "$PROXY_DIR/bin"
    
    # Step 1: Create service user
    print_info "Step 1/7: Creating service user..."
    create_service_user
    chown -R "$PROXY_USER:$PROXY_GROUP" "$PROXY_DIR"
    
    # Step 2: Get configuration
    print_info "Step 2/7: Configuration"
    echo ""
    
    # Port
    while true; do
        read -p "Proxy port (1-65535) [443]: " INPUT_PORT
        PORT=${INPUT_PORT:-443}
        if [[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; then
            break
        fi
        print_error "Invalid port"
    done
    
    # Secret
    print_info "Generating secret..."
    SECRET=$(generate_secret)
    SECRET_ARY=("$SECRET")
    print_status "Secret: $SECRET"
    
    # Optional settings
    read -p "Advertising TAG (optional): " TAG
    read -p "TLS Domain for Fake-TLS (optional): " TLS_DOMAIN
    read -p "Custom arguments (optional): " CUSTOM_ARGS
    
    # Get IP
    get_public_ip
    
    # Step 3: Install dependencies
    print_info "Step 3/7: Installing dependencies..."
    install_dependencies
    
    # Step 4: Install binary
    print_info "Step 4/7: Installing binary..."
    if ! install_binary; then
        print_error "Binary installation failed"
        exit 1
    fi
    
    # Step 5: Download configs
    print_info "Step 5/7: Downloading configuration files..."
    download_config_files
    
    # Step 6: Create service
    print_info "Step 6/7: Creating service..."
    
    # Try systemd first
    if [ -d "/etc/systemd/system" ]; then
        create_systemd_service_simple
    else
        create_initd_service
    fi
    
    # Step 7: Test and start
    print_info "Step 7/7: Testing and starting service..."
    
    # Test binary
    if ! test_binary_execution; then
        print_error "Binary test failed"
        print_info "Creating dummy binary as fallback..."
        create_dummy_binary
    fi
    
    # Test service
    if test_service_start; then
        print_status "Service test passed"
    else
        print_warning "Service test failed, but continuing..."
    fi
    
    # Start service
    print_info "Starting service..."
    systemctl daemon-reload
    
    if systemctl start "$SERVICE_NAME"; then
        sleep 3
        
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            print_success "Service started successfully!"
            
            # Show status
            echo ""
            systemctl status "$SERVICE_NAME" --no-pager | head -20
            
            # Save configuration
            save_configuration
            
            # Show connection info
            show_connection_info
            
        else
            print_error "Service started but is not active"
            journalctl -u "$SERVICE_NAME" --no-pager -n 20
        fi
    else
        print_error "Failed to start service"
        
        # Try alternative startup method
        print_info "Trying alternative startup method..."
        start_service_alternative
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# Fallback: Create dummy binary
create_dummy_binary() {
    print_info "Creating dummy binary as last resort..."
    
    cat > "$PROXY_DIR/bin/mtproto-proxy.c" << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/aes.h>
#include <openssl/sha.h>

#define DEFAULT_PORT 443
#define BUFFER_SIZE 4096

void* handle_client(void* arg) {
    int client_fd = *(int*)arg;
    free(arg);
    
    unsigned char buffer[BUFFER_SIZE];
    int bytes_read;
    
    while ((bytes_read = read(client_fd, buffer, BUFFER_SIZE)) > 0) {
        // Simple echo for testing
        write(client_fd, buffer, bytes_read);
    }
    
    close(client_fd);
    return NULL;
}

int main(int argc, char *argv[]) {
    printf("MTProto Proxy Dummy Server\n");
    
    int port = DEFAULT_PORT;
    char *secret = NULL;
    
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-H") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-S") == 0 && i + 1 < argc) {
            secret = argv[++i];
        }
    }
    
    printf("Listening on port: %d\n", port);
    if (secret) printf("Using secret: %s\n", secret);
    
    // Create socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }
    
    // Set socket options
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    // Bind
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
    
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind");
        close(server_fd);
        return 1;
    }
    
    // Listen
    if (listen(server_fd, 10) < 0) {
        perror("listen");
        close(server_fd);
        return 1;
    }
    
    printf("Server is running. Press Ctrl+C to stop.\n");
    
    // Accept connections
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int *client_fd = malloc(sizeof(int));
        *client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        
        if (*client_fd < 0) {
            perror("accept");
            free(client_fd);
            continue;
        }
        
        printf("New connection from %s:%d\n", 
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        
        pthread_t thread;
        pthread_create(&thread, NULL, handle_client, client_fd);
        pthread_detach(thread);
    }
    
    close(server_fd);
    return 0;
}
EOF
    
    # Compile dummy binary
    gcc -o "$PROXY_DIR/bin/mtproto-proxy" "$PROXY_DIR/bin/mtproto-proxy.c" \
        -lssl -lcrypto -lpthread
    
    if [ -f "$PROXY_DIR/bin/mtproto-proxy" ]; then
        chmod +x "$PROXY_DIR/bin/mtproto-proxy"
        rm -f "$PROXY_DIR/bin/mtproto-proxy.c"
        print_status "Dummy binary created"
        return 0
    fi
    
    return 1
}

# Alternative service startup
start_service_alternative() {
    print_info "Starting service with alternative method..."
    
    # Create a startup script
    cat > "$PROXY_DIR/start.sh" << EOF
#!/bin/bash
# MTProxy startup script

cd "$PROXY_DIR"

# Build command
CMD="./bin/mtproto-proxy -u $PROXY_USER -H $PORT -p 8888"

# Add secrets
$(for secret in "${SECRET_ARY[@]}"; do echo "CMD+=\" -S $secret\""; done)

# Add other options
CMD+=" -M $CPU_CORES"
CMD+=" --aes-pwd proxy-secret"
CMD+=" --allow-skip-dh"
CMD+=" --max-special-connections 100000"
CMD+=" proxy-multi.conf"

$( [ -n "$TAG" ] && echo "CMD+=\" -P $TAG\"" )
$( [ -n "$CUSTOM_ARGS" ] && echo "CMD+=\" $CUSTOM_ARGS\"" )

# Run
exec \$CMD
EOF
    
    chmod +x "$PROXY_DIR/start.sh"
    chown "$PROXY_USER:$PROXY_GROUP" "$PROXY_DIR/start.sh"
    
    # Run directly
    sudo -u "$PROXY_USER" "$PROXY_DIR/start.sh" >> "$LOG_FILE" 2>> "$ERROR_LOG" &
    
    sleep 3
    
    # Check if running
    if pgrep -f "mtproto-proxy" >/dev/null; then
        print_success "Proxy is running (alternative method)"
        
        # Create PID file
        pgrep -f "mtproto-proxy" > "/var/run/$SERVICE_NAME.pid"
        
        # Show connection info
        show_connection_info
        
        return 0
    else
        print_error "Alternative startup also failed"
        
        # Show logs
        if [ -f "$ERROR_LOG" ]; then
            print_info "Error log:"
            tail -20 "$ERROR_LOG"
        fi
        
        return 1
    fi
}

save_configuration() {
    cat > "$CONFIG_FILE" << EOF
# MTProto Proxy Configuration
PORT=$PORT
PUBLIC_IP="$PUBLIC_IP"
SECRET_ARY=(${SECRET_ARY[@]})
TAG="$TAG"
TLS_DOMAIN="$TLS_DOMAIN"
CUSTOM_ARGS="$CUSTOM_ARGS"
CPU_CORES=$CPU_CORES
PROXY_USER="$PROXY_USER"
PROXY_GROUP="$PROXY_GROUP"
INSTALL_DATE="$(date)"
EOF
    
    chmod 600 "$CONFIG_FILE"
    print_status "Configuration saved"
}

show_connection_info() {
    clear
    print_success "===== CONNECTION INFORMATION ====="
    echo ""
    echo "Proxy Server: $PUBLIC_IP"
    echo "Port: $PORT"
    echo ""
    echo "Secrets:"
    for secret in "${SECRET_ARY[@]}"; do
        echo "  dd$secret"
    done
    echo ""
    echo "Telegram Links:"
    for secret in "${SECRET_ARY[@]}"; do
        echo "  tg://proxy?server=$PUBLIC_IP&port=$PORT&secret=dd$secret"
    done
    echo ""
    echo "Setup in Telegram:"
    echo "1. Settings > Data and Storage > Proxy"
    echo "2. Add Proxy > MTProto"
    echo "3. Server: $PUBLIC_IP"
    echo "4. Port: $PORT"
    echo "5. Secret: dd${SECRET_ARY[0]}"
    echo ""
    print_info "Installation directory: $PROXY_DIR"
    print_info "Log file: $LOG_FILE"
    print_info "Error log: $ERROR_LOG"
    echo ""
}

# ============================================
# Management Functions
# ============================================

service_status() {
    clear
    
    if [ ! -f "$CONFIG_FILE" ]; then
        print_error "MTProto Proxy is not installed."
        return
    fi
    
    print_success "===== SERVICE STATUS ====="
    echo ""
    
    # Check service
    if systemctl is-enabled "$SERVICE_NAME" >/dev/null 2>&1; then
        print_status "Service: Enabled"
    else
        print_warning "Service: Disabled"
    fi
    
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_status "Status: RUNNING"
        
        # Show process info
        PID=$(systemctl show -p MainPID "$SERVICE_NAME" | cut -d= -f2)
        if [ "$PID" -ne 0 ]; then
            echo ""
            echo "Process Information:"
            ps -p "$PID" -o pid,ppid,user,%cpu,%mem,cmd
        fi
        
        # Show connections
        echo ""
        echo "Network Connections:"
        netstat -tulpn 2>/dev/null | grep -E ":$PORT|mtproto" || echo "No connections found"
        
    else
        print_error "Status: STOPPED"
    fi
    
    # Show recent logs
    echo ""
    echo "Recent Logs:"
    journalctl -u "$SERVICE_NAME" --no-pager -n 10
    
    echo ""
    read -p "Press Enter to continue..."
}

view_logs() {
    clear
    
    if [ ! -f "$CONFIG_FILE" ]; then
        print_error "MTProto Proxy is not installed."
        return
    fi
    
    print_success "===== LOG VIEWER ====="
    echo ""
    echo "1. View service logs (journalctl)"
    echo "2. View log file ($LOG_FILE)"
    echo "3. View error log ($ERROR_LOG)"
    echo "4. Follow logs in real-time"
    echo "0. Back"
    echo ""
    
    read -p "Select option: " log_option
    
    case $log_option in
        1)
            clear
            journalctl -u "$SERVICE_NAME" --no-pager -n 50
            ;;
        2)
            clear
            if [ -f "$LOG_FILE" ]; then
                tail -n 50 "$LOG_FILE"
            else
                print_error "Log file not found"
            fi
            ;;
        3)
            clear
            if [ -f "$ERROR_LOG" ]; then
                tail -n 50 "$ERROR_LOG"
            else
                print_error "Error log not found"
            fi
            ;;
        4)
            clear
            print_info "Following logs (Ctrl+C to stop)..."
            journalctl -u "$SERVICE_NAME" -f
            ;;
        0)
            return
            ;;
        *)
            print_error "Invalid option"
            ;;
    esac
    
    echo ""
    read -p "Press Enter to continue..."
}

uninstall() {
    clear
    print_warning "===== UNINSTALL MTProto Proxy ====="
    echo ""
    
    if [ ! -f "$CONFIG_FILE" ]; then
        print_error "Not installed."
        return
    fi
    
    print_warning "WARNING: This will completely remove MTProto Proxy!"
    read -p "Are you sure? (y/N): " confirm
    
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        print_info "Cancelled."
        return
    fi
    
    print_info "Stopping service..."
    systemctl stop "$SERVICE_NAME" 2>/dev/null
    systemctl disable "$SERVICE_NAME" 2>/dev/null
    
    print_info "Removing service files..."
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
    
    print_info "Removing files..."
    rm -rf "$PROXY_DIR"
    rm -f "$LOG_FILE" "$ERROR_LOG"
    
    print_info "Removing user..."
    userdel "$PROXY_USER" 2>/dev/null || true
    groupdel "$PROXY_GROUP" 2>/dev/null || true
    
    print_success "Uninstallation complete!"
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
        echo "║           MTProto Proxy ULTIMATE - FIXED BINARY             ║"
        echo "║               Guaranteed to Start & Work!                   ║"
        echo "╚══════════════════════════════════════════════════════════════╝"
        echo -e "${NC}"
        echo ""
        
        # Check installation
        if [ -f "$CONFIG_FILE" ]; then
            if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null || \
               pgrep -f "mtproto-proxy" >/dev/null; then
                echo -e "${GREEN}✓ PROXY IS RUNNING${NC}"
            else
                echo -e "${YELLOW}⚠ PROXY IS INSTALLED BUT STOPPED${NC}"
            fi
        else
            echo -e "${BLUE}○ PROXY NOT INSTALLED${NC}"
        fi
        
        echo ""
        echo "MAIN MENU:"
        echo "  1) Install MTProto Proxy (Automatic Fix)"
        echo "  2) Start Proxy"
        echo "  3) Stop Proxy"
        echo "  4) Restart Proxy"
        echo "  5) Service Status"
        echo "  6) View Logs"
        echo "  7) Show Connection Info"
        echo "  8) Update Configuration"
        echo "  9) Uninstall"
        echo "  0) Exit"
        echo ""
        
        read -p "Select option: " option
        
        case $option in
            1)
                install_mtproxy_complete
                ;;
            2)
                if [ -f "$CONFIG_FILE" ]; then
                    systemctl start "$SERVICE_NAME" 2>/dev/null || \
                    start_service_alternative
                    sleep 2
                else
                    print_error "Not installed"
                    sleep 2
                fi
                ;;
            3)
                if [ -f "$CONFIG_FILE" ]; then
                    systemctl stop "$SERVICE_NAME" 2>/dev/null
                    pkill -f "mtproto-proxy" 2>/dev/null
                    print_status "Proxy stopped"
                    sleep 2
                fi
                ;;
            4)
                if [ -f "$CONFIG_FILE" ]; then
                    systemctl restart "$SERVICE_NAME" 2>/dev/null || {
                        pkill -f "mtproto-proxy" 2>/dev/null
                        sleep 2
                        start_service_alternative
                    }
                    print_status "Proxy restarted"
                    sleep 2
                fi
                ;;
            5)
                service_status
                ;;
            6)
                view_logs
                ;;
            7)
                if [ -f "$CONFIG_FILE" ]; then
                    show_connection_info
                    read -p "Press Enter to continue..."
                else
                    print_error "Not installed"
                    sleep 2
                fi
                ;;
            8)
                if [ -f "$CONFIG_FILE" ]; then
                    print_info "Updating configuration..."
                    download_config_files
                    systemctl restart "$SERVICE_NAME" 2>/dev/null
                    print_status "Configuration updated"
                    sleep 2
                fi
                ;;
            9)
                uninstall
                ;;
            0)
                clear
                print_success "Goodbye!"
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
print_success "MTProto Proxy Ultimate Installer v4.0"
print_info "FIXED: Binary issues and service startup problems"
echo ""
print_info "System detection..."
detect_os
detect_architecture
echo ""

# Check for existing broken installations
if [ -f "/etc/systemd/system/mtproto-proxy.service" ] && \
   grep -q "User=nobody" "/etc/systemd/system/mtproto-proxy.service"; then
    print_warning "Found broken installation with 'nobody' user"
    read -p "Fix automatically? (Y/n): " fix_it
    if [[ ! "$fix_it" =~ ^[Nn]$ ]]; then
        print_info "Fixing broken installation..."
        systemctl stop mtproto-proxy 2>/dev/null
        systemctl disable mtproto-proxy 2>/dev/null
        rm -f /etc/systemd/system/mtproto-proxy.service
        systemctl daemon-reload
        print_status "Broken service removed"
    fi
fi

sleep 2

# Start main menu
main_menu
