#!/bin/bash

# ============================================
# MTProto Proxy Ultimate Installer & Manager
# Version: 3.0
# Supports: Ubuntu/Debian/CentOS/Arch Linux
# Architectures: x86_64, ARM64, ARM32
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
BRANCH="master"

# ============================================
# Utility Functions
# ============================================

# Function to print colored output
print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_success() {
    echo -e "${CYAN}[✔]${NC} $1"
}

# Function to check root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root. Use: sudo $0"
        exit 1
    fi
}

# Function to detect OS
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

# Function to detect architecture
detect_architecture() {
    ARCH=$(uname -m)
    case $ARCH in
        x86_64|amd64)
            ARCH="x64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        armv7l|armv8l)
            ARCH="arm32"
            ;;
        i386|i686)
            ARCH="x86"
            ;;
        *)
            ARCH="unknown"
            print_warning "Unknown architecture: $ARCH, using generic build"
            ;;
    esac
    
    # Get CPU cores
    CPU_CORES=$(nproc --all)
    if [ $CPU_CORES -gt 16 ]; then
        CPU_CORES=16
        print_warning "Limiting to 16 CPU cores for stability"
    fi
    
    print_info "Architecture: $ARCH, CPU Cores: $CPU_CORES"
}

# Function to get random port
get_random_port() {
    local PORT=$((RANDOM % 16383 + 49152))
    while lsof -Pi :$PORT -sTCP:LISTEN -t >/dev/null ; do
        PORT=$((RANDOM % 16383 + 49152))
    done
    echo $PORT
}

# Function to validate port
validate_port() {
    local port=$1
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        return 1
    fi
    return 0
}

# Function to validate secret
validate_secret() {
    local secret=$1
    if [[ "$secret" =~ ^[0-9a-f]{32}$ ]] || [[ "$secret" =~ ^[0-9A-F]{32}$ ]]; then
        return 0
    fi
    return 1
}

# Function to generate random secret
generate_secret() {
    local secret=$(head -c 16 /dev/urandom | xxd -ps)
    echo "$secret"
}

# Function to install dependencies
install_dependencies() {
    print_info "Installing dependencies..."
    
    case $DISTRO in
        ubuntu|debian)
            apt-get update
            apt-get install -y git curl build-essential libssl-dev zlib1g-dev \
                net-tools cron lsof xxd wget sudo ufw iptables ca-certificates
            ;;
        centos|rhel|fedora)
            yum install -y epel-release
            yum groupinstall -y "Development Tools"
            yum install -y git curl openssl-devel zlib-devel \
                net-tools cronie lsof vim-common wget iptables-services ca-certificates
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
    
    print_status "Dependencies installed successfully"
}

# Function to fix Makefile for architecture
fix_makefile() {
    local makefile_path=$1
    
    if [ ! -f "$makefile_path" ]; then
        print_error "Makefile not found at $makefile_path"
        return 1
    fi
    
    print_info "Fixing Makefile for $ARCH architecture..."
    
    # Backup original Makefile
    cp "$makefile_path" "${makefile_path}.backup"
    
    # Remove problematic flags for non-x86 architectures
    if [ "$ARCH" != "x64" ] && [ "$ARCH" != "x86" ]; then
        sed -i 's/-mpclmul//g' "$makefile_path"
        sed -i 's/-mfpmath=sse//g' "$makefile_path"
        sed -i 's/-mssse3//g' "$makefile_path"
        sed -i 's/-march=core2//g' "$makefile_path"
        print_info "Removed x86-specific flags for $ARCH"
    fi
    
    # For ARM, use appropriate optimization
    if [ "$ARCH" = "arm64" ] || [ "$ARCH" = "arm32" ]; then
        # Add ARM optimization flags
        if grep -q "CFLAGS" "$makefile_path"; then
            sed -i 's/CFLAGS = /CFLAGS = -O2 /' "$makefile_path"
        fi
    fi
    
    # For 32-bit x86
    if [ "$ARCH" = "x86" ]; then
        sed -i 's/-march=core2/-march=pentium4/' "$makefile_path"
        sed -i 's/-mpclmul//g' "$makefile_path"
    fi
    
    print_status "Makefile fixed for $ARCH"
}

# Function to build MTProto Proxy
build_mtproxy() {
    print_info "Building MTProto Proxy..."
    
    # Clone repository
    if [ -d "$PROXY_DIR/source" ]; then
        rm -rf "$PROXY_DIR/source"
    fi
    
    mkdir -p "$PROXY_DIR/source"
    cd "$PROXY_DIR/source"
    
    print_info "Cloning MTProxy repository..."
    git clone https://github.com/TelegramMessenger/MTProxy.git
    if [ $? -ne 0 ]; then
        print_error "Failed to clone repository"
        return 1
    fi
    
    cd MTProxy
    
    # Fix Makefile
    fix_makefile "Makefile"
    
    # Build with adaptive settings
    print_info "Building with $CPU_CORES threads..."
    
    # Try standard build first
    make -j$CPU_CORES
    
    if [ $? -ne 0 ]; then
        print_warning "Standard build failed, trying alternative method..."
        
        # Try with simplified flags
        make clean
        
        # Create a minimal build script
        cat > build.sh << 'EOF'
#!/bin/bash
CFLAGS="-O2 -std=gnu11 -Wall -fno-strict-aliasing -fwrapv"
LDFLAGS="-lssl -lcrypto -lz -lpthread"

# Compile all source files
for dir in mtproto common; do
    for file in $(find $dir -name "*.c"); do
        obj="objs/${file%.c}.o"
        mkdir -p $(dirname $obj)
        gcc $CFLAGS -iquote common -iquote . -c $file -o $obj
    done
done

# Link
mkdir -p objs/bin
gcc $CFLAGS $(find objs -name "*.o") $LDFLAGS -o objs/bin/mtproto-proxy
EOF
        
        chmod +x build.sh
        ./build.sh
        
        if [ $? -ne 0 ]; then
            print_error "All build methods failed"
            return 1
        fi
    fi
    
    # Check if binary was created
    if [ ! -f "objs/bin/mtproto-proxy" ]; then
        print_error "Binary not created"
        return 1
    fi
    
    # Copy binary
    mkdir -p "$PROXY_DIR/bin"
    cp objs/bin/mtproto-proxy "$PROXY_DIR/bin/"
    chmod +x "$PROXY_DIR/bin/mtproto-proxy"
    
    print_status "Build successful"
    return 0
}

# Function to download config files
download_configs() {
    print_info "Downloading configuration files..."
    
    cd "$PROXY_DIR"
    
    # Try multiple sources for proxy-secret
    local sources=(
        "https://core.telegram.org/getProxySecret"
        "https://raw.githubusercontent.com/TelegramMessenger/MTProxy/master/proxy-secret"
    )
    
    for src in "${sources[@]}"; do
        print_info "Trying: $src"
        if curl -s --max-time 10 -o proxy-secret.tmp "$src" && [ -s proxy-secret.tmp ]; then
            mv proxy-secret.tmp proxy-secret
            print_status "Downloaded proxy-secret"
            break
        fi
    done
    
    if [ ! -f "proxy-secret" ] || [ ! -s "proxy-secret" ]; then
        print_error "Failed to download proxy-secret"
        return 1
    fi
    
    # Try multiple sources for proxy-multi.conf
    for src in "${sources[@]}"; do
        src="${src/proxy-secret/proxy-multi.conf}"
        print_info "Trying: $src"
        if curl -s --max-time 10 -o proxy-multi.conf.tmp "$src" && [ -s proxy-multi.conf.tmp ]; then
            mv proxy-multi.conf.tmp proxy-multi.conf
            print_status "Downloaded proxy-multi.conf"
            break
        fi
    done
    
    if [ ! -f "proxy-multi.conf" ] || [ ! -s "proxy-multi.conf" ]; then
        print_error "Failed to download proxy-multi.conf"
        return 1
    fi
    
    return 0
}

# Function to configure firewall
configure_firewall() {
    print_info "Configuring firewall..."
    
    case $DISTRO in
        ubuntu|debian)
            # Check if UFW is installed
            if command -v ufw >/dev/null 2>&1; then
                ufw allow $PORT/tcp comment "MTProto Proxy"
                ufw reload
                print_status "UFW configured for port $PORT"
            else
                # Use iptables
                iptables -A INPUT -p tcp --dport $PORT -j ACCEPT
                print_info "IPTables rule added. Save manually if needed."
            fi
            ;;
        centos|rhel|fedora)
            # Check if firewalld is installed
            if command -v firewall-cmd >/dev/null 2>&1; then
                firewall-cmd --permanent --add-port=$PORT/tcp
                firewall-cmd --reload
                print_status "Firewalld configured for port $PORT"
            else
                # Use iptables
                iptables -A INPUT -p tcp --dport $PORT -j ACCEPT
                service iptables save 2>/dev/null || true
            fi
            ;;
        arch|manjaro)
            # Use iptables
            iptables -A INPUT -p tcp --dport $PORT -j ACCEPT
            print_info "IPTables rule added for Arch Linux"
            ;;
    esac
}

# Function to generate service file
generate_service_file() {
    print_info "Generating systemd service file..."
    
    # Build arguments string
    local ARGS_STR="-u nobody -H $PORT -p 8888"
    
    # Add secrets
    for secret in "${SECRET_ARY[@]}"; do
        ARGS_STR+=" -S $secret"
    done
    
    # Add tag if exists
    if [ -n "$TAG" ]; then
        ARGS_STR+=" -P $TAG"
    fi
    
    # Add TLS domain if exists
    if [ -n "$TLS_DOMAIN" ]; then
        ARGS_STR+=" -D $TLS_DOMAIN"
    fi
    
    # Add NAT info if needed
    if [ "$HAVE_NAT" = "y" ]; then
        ARGS_STR+=" --nat-info $PRIVATE_IP:$PUBLIC_IP"
    fi
    
    # Add custom args
    if [ -n "$CUSTOM_ARGS" ]; then
        ARGS_STR+=" $CUSTOM_ARGS"
    fi
    
    # Add core count (minus 1 for main thread)
    local WORKER_CORES=$((CPU_CORES - 1))
    if [ $WORKER_CORES -lt 1 ]; then
        WORKER_CORES=1
    fi
    
    ARGS_STR+=" -M $WORKER_CORES --aes-pwd $PROXY_DIR/proxy-secret $PROXY_DIR/proxy-multi.conf"
    
    # Create service file
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
ExecStart=$PROXY_DIR/bin/mtproto-proxy $ARGS_STR
Restart=on-failure
RestartSec=10
StartLimitInterval=60
StartLimitBurst=5
LimitNOFILE=65536
Nice=10
CPUSchedulingPolicy=idle
StandardOutput=append:$LOG_FILE
StandardError=append:$LOG_FILE

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd
    systemctl daemon-reload
    systemctl enable $SERVICE_NAME
    
    print_status "Service file generated and enabled"
}

# Function to create updater script
create_updater_script() {
    print_info "Creating auto-updater script..."
    
    cat > "$UPATER_FILE" << 'EOF'
#!/bin/bash
# Auto-updater for MTProto Proxy

echo "[$(date)] Starting update..." >> $PROXY_DIR/updater.log

# Stop service
systemctl stop mtproto-proxy

# Download new configs
cd $PROXY_DIR

# Try to download proxy-secret
curl -s --max-time 20 https://core.telegram.org/getProxySecret -o proxy-secret.new
if [ $? -eq 0 ] && [ -s proxy-secret.new ]; then
    mv proxy-secret.new proxy-secret
    echo "[$(date)] proxy-secret updated" >> $PROXY_DIR/updater.log
else
    echo "[$(date)] Failed to update proxy-secret" >> $PROXY_DIR/updater.log
fi

# Try to download proxy-multi.conf
curl -s --max-time 20 https://core.telegram.org/getProxyConfig -o proxy-multi.conf.new
if [ $? -eq 0 ] && [ -s proxy-multi.conf.new ]; then
    mv proxy-multi.conf.new proxy-multi.conf
    echo "[$(date)] proxy-multi.conf updated" >> $PROXY_DIR/updater.log
else
    echo "[$(date)] Failed to update proxy-multi.conf" >> $PROXY_DIR/updater.log
fi

# Start service
systemctl start mtproto-proxy

echo "[$(date)] Update completed" >> $PROXY_DIR/updater.log
EOF
    
    chmod +x "$UPATER_FILE"
    
    # Add to crontab if enabled
    if [ "$ENABLE_UPDATER" = "y" ]; then
        (crontab -l 2>/dev/null; echo "0 3 * * * $UPATER_FILE") | crontab -
        print_status "Auto-updater configured to run daily at 3 AM"
    fi
}

# Function to save configuration
save_configuration() {
    print_info "Saving configuration..."
    
    cat > "$CONFIG_FILE" << EOF
# MTProto Proxy Configuration
# Generated on $(date)

# Network
PORT=$PORT
PUBLIC_IP="$PUBLIC_IP"
PRIVATE_IP="$PRIVATE_IP"
HAVE_NAT="$HAVE_NAT"

# Secrets
SECRET_ARY=(${SECRET_ARY[@]})

# Performance
CPU_CORES=$CPU_CORES

# Features
TAG="$TAG"
TLS_DOMAIN="$TLS_DOMAIN"
CUSTOM_ARGS="$CUSTOM_ARGS"
ENABLE_UPDATER="$ENABLE_UPDATER"
ENABLE_BBR="$ENABLE_BBR"

# System
DISTRO="$DISTRO"
ARCH="$ARCH"
PROXY_DIR="$PROXY_DIR"
EOF
    
    chmod 600 "$CONFIG_FILE"
    print_status "Configuration saved to $CONFIG_FILE"
}

# Function to load configuration
load_configuration() {
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
        print_status "Configuration loaded from $CONFIG_FILE"
        return 0
    fi
    return 1
}

# Function to get public IP
get_public_ip() {
    print_info "Detecting public IP..."
    
    local ip_services=(
        "https://api.ipify.org"
        "https://icanhazip.com"
        "https://ifconfig.me"
        "https://checkip.amazonaws.com"
    )
    
    for service in "${ip_services[@]}"; do
        PUBLIC_IP=$(curl -s --max-time 5 "$service")
        if [ $? -eq 0 ] && [[ $PUBLIC_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            print_status "Public IP detected: $PUBLIC_IP"
            return 0
        fi
    done
    
    print_warning "Could not detect public IP automatically"
    read -p "Enter your server's public IP address: " PUBLIC_IP
    return 0
}

# Function to get private IP
get_private_ip() {
    PRIVATE_IP=$(ip route get 1 | awk '{print $NF;exit}')
    if [ -z "$PRIVATE_IP" ]; then
        PRIVATE_IP=$(hostname -I | awk '{print $1}')
    fi
    
    if [ -n "$PRIVATE_IP" ]; then
        print_info "Private IP detected: $PRIVATE_IP"
        
        # Check if it's a private IP
        if [[ $PRIVATE_IP =~ ^10\. ]] || \
           [[ $PRIVATE_IP =~ ^172\.1[6-9]\. ]] || \
           [[ $PRIVATE_IP =~ ^172\.2[0-9]\. ]] || \
           [[ $PRIVATE_IP =~ ^172\.3[0-1]\. ]] || \
           [[ $PRIVATE_IP =~ ^192\.168\. ]]; then
            HAVE_NAT="y"
            print_info "Server is behind NAT"
        else
            HAVE_NAT="n"
        fi
    fi
}

# Function to enable BBR
enable_bbr() {
    if [ "$ENABLE_BBR" != "y" ]; then
        return 0
    fi
    
    print_info "Enabling BBR congestion control..."
    
    # Check if BBR is already enabled
    if sysctl net.ipv4.tcp_congestion_control | grep -q bbr; then
        print_status "BBR is already enabled"
        return 0
    fi
    
    # Enable BBR
    cat >> /etc/sysctl.conf << EOF
# BBR Congestion Control
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
    
    sysctl -p
    print_status "BBR enabled successfully"
}

# Function to show connection links
show_links() {
    print_success "===== MTProto Proxy Connection Links ====="
    
    if [ -z "$PUBLIC_IP" ]; then
        get_public_ip
    fi
    
    local hex_domain=""
    if [ -n "$TLS_DOMAIN" ]; then
        hex_domain=$(printf "%s" "$TLS_DOMAIN" | xxd -pu | tr -d '\n')
        hex_domain=$(echo "$hex_domain" | tr '[:upper:]' '[:lower:]')
    fi
    
    for secret in "${SECRET_ARY[@]}"; do
        if [ -z "$TLS_DOMAIN" ]; then
            echo "tg://proxy?server=$PUBLIC_IP&port=$PORT&secret=dd$secret"
        else
            echo "tg://proxy?server=$PUBLIC_IP&port=$PORT&secret=ee$secret$hex_domain"
        fi
    done
    
    echo ""
    print_info "To use in Telegram:"
    print_info "1. Open Telegram Settings"
    print_info "2. Go to Data and Storage > Proxy"
    print_info "3. Add Proxy > MTProto"
    print_info "4. Enter: Server=$PUBLIC_IP, Port=$PORT"
    print_info "5. Enter one of the secrets above"
}

# Function to install proxy
install_proxy() {
    clear
    print_success "===== MTProto Proxy Installation ====="
    
    # Detect system
    detect_os
    detect_architecture
    
    # Get configuration
    print_info "Step 1/7: Configuration"
    
    # Port selection
    read -p "Enter proxy port [443]: " input_port
    PORT=${input_port:-443}
    if ! validate_port "$PORT"; then
        print_error "Invalid port, using 443"
        PORT=443
    fi
    
    # Secret management
    print_info "Add secrets (up to 16):"
    while true; do
        echo "  1) Generate random secret"
        echo "  2) Enter custom secret"
        echo "  3) Done adding secrets"
        read -p "Select option [1-3]: " secret_option
        
        case $secret_option in
            1)
                secret=$(generate_secret)
                SECRET_ARY+=("$secret")
                print_status "Generated secret: $secret"
                ;;
            2)
                read -p "Enter 32-character hex secret: " secret
                secret=$(echo "$secret" | tr '[:upper:]' '[:lower:]')
                if validate_secret "$secret"; then
                    SECRET_ARY+=("$secret")
                    print_status "Secret added"
                else
                    print_error "Invalid secret format"
                fi
                ;;
            3)
                if [ ${#SECRET_ARY[@]} -eq 0 ]; then
                    print_warning "No secrets added, generating one..."
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
    done
    
    # TAG
    read -p "Enter advertising TAG (from @MTProxybot, leave empty to skip): " TAG
    
    # TLS Domain
    read -p "Enter TLS domain for Fake-TLS (e.g., cloudflare.com, leave empty to disable): " TLS_DOMAIN
    
    # CPU Cores
    read -p "Enter number of worker processes (1-$CPU_CORES) [$CPU_CORES]: " input_cores
    if [ -n "$input_cores" ] && [[ "$input_cores" =~ ^[0-9]+$ ]] && [ "$input_cores" -ge 1 ] && [ "$input_cores" -le "$CPU_CORES" ]; then
        CPU_CORES=$input_cores
    fi
    
    # Custom arguments
    read -p "Enter custom arguments (leave empty if none): " CUSTOM_ARGS
    
    # Updater
    read -p "Enable auto-updater? [Y/n]: " input_updater
    ENABLE_UPDATER=${input_updater:-y}
    
    # BBR
    read -p "Enable BBR congestion control? [Y/n]: " input_bbr
    ENABLE_BBR=${input_bbr:-y}
    
    # Get IP addresses
    get_public_ip
    get_private_ip
    
    # Confirm NAT if needed
    if [ "$HAVE_NAT" = "y" ]; then
        print_info "Server appears to be behind NAT"
        read -p "Is $PRIVATE_IP your private IP? [Y/n]: " confirm_nat
        if [[ "$confirm_nat" =~ ^[Nn]$ ]]; then
            read -p "Enter your private IP: " PRIVATE_IP
        fi
    fi
    
    # Installation
    print_info "Step 2/7: Installing dependencies..."
    install_dependencies
    
    print_info "Step 3/7: Building MTProto Proxy..."
    if ! build_mtproxy; then
        print_error "Build failed. See logs above for details."
        exit 1
    fi
    
    print_info "Step 4/7: Downloading configuration files..."
    download_configs
    
    print_info "Step 5/7: Configuring firewall..."
    configure_firewall
    
    print_info "Step 6/7: Creating service..."
    generate_service_file
    
    print_info "Step 7/7: Finalizing installation..."
    save_configuration
    create_updater_script
    enable_bbr
    
    # Start service
    systemctl start $SERVICE_NAME
    if systemctl is-active --quiet $SERVICE_NAME; then
        print_status "Service started successfully"
    else
        print_warning "Service started but may have issues. Check: systemctl status $SERVICE_NAME"
    fi
    
    # Show results
    clear
    print_success "===== Installation Complete ====="
    show_links
    
    echo ""
    print_info "Installation directory: $PROXY_DIR"
    print_info "Configuration file: $CONFIG_FILE"
    print_info "Service: $SERVICE_NAME"
    print_info "Log file: $LOG_FILE"
    echo ""
    
    read -p "Press Enter to continue..."
}

# Function to manage proxy
manage_proxy() {
    if [ ! -f "$CONFIG_FILE" ]; then
        print_error "MTProto Proxy is not installed."
        read -p "Would you like to install it now? [Y/n]: " choice
        if [[ "$choice" =~ ^[Yy]$ ]] || [ -z "$choice" ]; then
            install_proxy
        fi
        return
    fi
    
    # Load configuration
    load_configuration
    
    while true; do
        clear
        print_success "===== MTProto Proxy Management ====="
        echo ""
        print_info "Current Status:"
        systemctl status $SERVICE_NAME --no-pager -l | head -20
        
        echo ""
        print_info "Management Options:"
        echo "  1) Show connection links"
        echo "  2) Start proxy"
        echo "  3) Stop proxy"
        echo "  4) Restart proxy"
        echo "  5) View logs"
        echo "  6) Add new secret"
        echo "  7) Remove secret"
        echo "  8) Change port"
        echo "  9) Change TAG"
        echo "  10) Update configuration files"
        echo "  11) Uninstall proxy"
        echo "  0) Back to main menu"
        
        read -p "Select option [0-11]: " option
        
        case $option in
            1)
                show_links
                read -p "Press Enter to continue..."
                ;;
            2)
                systemctl start $SERVICE_NAME
                print_status "Proxy started"
                sleep 2
                ;;
            3)
                systemctl stop $SERVICE_NAME
                print_status "Proxy stopped"
                sleep 2
                ;;
            4)
                systemctl restart $SERVICE_NAME
                print_status "Proxy restarted"
                sleep 2
                ;;
            5)
                clear
                print_success "===== Proxy Logs ====="
                journalctl -u $SERVICE_NAME -n 50 --no-pager
                read -p "Press Enter to continue..."
                ;;
            6)
                if [ ${#SECRET_ARY[@]} -ge 16 ]; then
                    print_error "Maximum 16 secrets reached"
                    sleep 2
                    continue
                fi
                
                echo "  1) Generate random secret"
                echo "  2) Enter custom secret"
                read -p "Select option [1-2]: " secret_opt
                
                case $secret_opt in
                    1)
                        new_secret=$(generate_secret)
                        SECRET_ARY+=("$new_secret")
                        print_status "Generated secret: $new_secret"
                        ;;
                    2)
                        read -p "Enter 32-character hex secret: " new_secret
                        new_secret=$(echo "$new_secret" | tr '[:upper:]' '[:lower:]')
                        if validate_secret "$new_secret"; then
                            SECRET_ARY+=("$new_secret")
                            print_status "Secret added"
                        else
                            print_error "Invalid secret"
                            sleep 2
                            continue
                        fi
                        ;;
                    *)
                        print_error "Invalid option"
                        sleep 2
                        continue
                        ;;
                esac
                
                # Update configuration and restart
                save_configuration
                systemctl stop $SERVICE_NAME
                generate_service_file
                systemctl start $SERVICE_NAME
                print_status "Configuration updated and proxy restarted"
                sleep 2
                ;;
            7)
                if [ ${#SECRET_ARY[@]} -le 1 ]; then
                    print_error "Cannot remove the last secret"
                    sleep 2
                    continue
                fi
                
                echo "Select secret to remove:"
                for i in "${!SECRET_ARY[@]}"; do
                    echo "  $((i+1))) ${SECRET_ARY[$i]}"
                done
                
                read -p "Enter number: " remove_num
                if [[ "$remove_num" =~ ^[0-9]+$ ]] && [ "$remove_num" -ge 1 ] && [ "$remove_num" -le ${#SECRET_ARY[@]} ]; then
                    index=$((remove_num-1))
                    removed_secret=${SECRET_ARY[$index]}
                    unset SECRET_ARY[$index]
                    SECRET_ARY=("${SECRET_ARY[@]}") # Re-index array
                    
                    print_status "Removed secret: $removed_secret"
                    
                    # Update configuration and restart
                    save_configuration
                    systemctl stop $SERVICE_NAME
                    generate_service_file
                    systemctl start $SERVICE_NAME
                    print_status "Configuration updated and proxy restarted"
                else
                    print_error "Invalid selection"
                fi
                sleep 2
                ;;
            8)
                read -p "Enter new port: " new_port
                if validate_port "$new_port"; then
                    PORT=$new_port
                    save_configuration
                    configure_firewall
                    systemctl stop $SERVICE_NAME
                    generate_service_file
                    systemctl start $SERVICE_NAME
                    print_status "Port changed to $PORT and proxy restarted"
                else
                    print_error "Invalid port"
                fi
                sleep 2
                ;;
            9)
                read -p "Enter new TAG (leave empty to remove): " new_tag
                TAG="$new_tag"
                save_configuration
                systemctl stop $SERVICE_NAME
                generate_service_file
                systemctl start $SERVICE_NAME
                print_status "TAG updated and proxy restarted"
                sleep 2
                ;;
            10)
                print_info "Updating configuration files..."
                download_configs
                systemctl restart $SERVICE_NAME
                print_status "Configuration files updated and proxy restarted"
                sleep 2
                ;;
            11)
                echo ""
                print_warning "⚠️  WARNING: This will completely remove MTProto Proxy!"
                read -p "Are you sure? [y/N]: " confirm
                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    uninstall_proxy
                    return
                fi
                ;;
            0)
                return
                ;;
            *)
                print_error "Invalid option"
                sleep 2
                ;;
        esac
    done
}

# Function to uninstall proxy
uninstall_proxy() {
    clear
    print_warning "===== Uninstalling MTProto Proxy ====="
    
    if [ ! -f "$CONFIG_FILE" ]; then
        print_error "MTProto Proxy is not installed."
        return
    fi
    
    # Load configuration to get port
    load_configuration
    
    # Stop and disable service
    systemctl stop $SERVICE_NAME 2>/dev/null
    systemctl disable $SERVICE_NAME 2>/dev/null
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
    
    # Remove firewall rules
    case $DISTRO in
        ubuntu|debian)
            if command -v ufw >/dev/null 2>&1; then
                ufw delete allow $PORT/tcp
            fi
            ;;
        centos|rhel|fedora)
            if command -v firewall-cmd >/dev/null 2>&1; then
                firewall-cmd --permanent --remove-port=$PORT/tcp
                firewall-cmd --reload
            fi
            ;;
    esac
    
    # Remove crontab entry
    crontab -l | grep -v "$UPATER_FILE" | crontab -
    
    # Remove files
    rm -rf "$PROXY_DIR"
    rm -f "$LOG_FILE"
    
    # Remove from configuration file
    if [ -f "$CONFIG_FILE" ]; then
        rm -f "$CONFIG_FILE"
    fi
    
    print_success "MTProto Proxy has been completely uninstalled."
    read -p "Press Enter to continue..."
}

# Function to show about
show_about() {
    clear
    print_success "===== About MTProto Proxy Ultimate ====="
    echo ""
    echo "Version: 3.0"
    echo "Author: Based on Hirbod Behnam's script with improvements"
    echo ""
    echo "Features:"
    echo "  • Multi-architecture support (x64, ARM64, ARM32)"
    echo "  • Multi-distro support (Ubuntu, Debian, CentOS, Arch)"
    echo "  • Multiple secret management (up to 16)"
    echo "  • Fake-TLS support"
    echo "  • NAT support"
    echo "  • Auto-updater"
    echo "  • BBR congestion control"
    echo "  • Systemd service management"
    echo "  • Firewall auto-configuration"
    echo "  • Comprehensive logging"
    echo ""
    echo "GitHub Repositories:"
    echo "  • MTProxy: https://github.com/TelegramMessenger/MTProxy"
    echo "  • Original Script: https://github.com/HirbodBehnam/MTProtoProxyInstaller"
    echo ""
    read -p "Press Enter to continue..."
}

# Main menu
main_menu() {
    while true; do
        clear
        echo -e "${CYAN}"
        echo "╔══════════════════════════════════════════════════════════════╗"
        echo "║           MTProto Proxy Ultimate Installer v3.0             ║"
        echo "║                    Complete Management                       ║"
        echo "╚══════════════════════════════════════════════════════════════╝"
        echo -e "${NC}"
        echo ""
        
        # Check if installed
        if [ -f "$CONFIG_FILE" ]; then
            print_success "Status: Installed ✓"
            systemctl is-active --quiet $SERVICE_NAME && print_success "Service: Running ✓" || print_error "Service: Stopped ✗"
        else
            print_warning "Status: Not installed"
        fi
        
        echo ""
        echo "Main Menu:"
        echo "  1) Install MTProto Proxy"
        echo "  2) Manage Proxy"
        echo "  3) Show Connection Links"
        echo "  4) Check Service Status"
        echo "  5) View Logs"
        echo "  6) Update Configuration Files"
        echo "  7) Uninstall Proxy"
        echo "  8) About"
        echo "  0) Exit"
        echo ""
        
        read -p "Select option [0-8]: " main_option
        
        case $main_option in
            1)
                install_proxy
                ;;
            2)
                manage_proxy
                ;;
            3)
                if [ -f "$CONFIG_FILE" ]; then
                    load_configuration
                    show_links
                else
                    print_error "Proxy is not installed."
                fi
                read -p "Press Enter to continue..."
                ;;
            4)
                if [ -f "$CONFIG_FILE" ]; then
                    clear
                    print_success "===== Service Status ====="
                    systemctl status $SERVICE_NAME --no-pager -l
                else
                    print_error "Proxy is not installed."
                fi
                read -p "Press Enter to continue..."
                ;;
            5)
                if [ -f "$CONFIG_FILE" ]; then
                    clear
                    print_success "===== Recent Logs ====="
                    journalctl -u $SERVICE_NAME -n 100 --no-pager | tail -50
                else
                    print_error "Proxy is not installed."
                fi
                read -p "Press Enter to continue..."
                ;;
            6)
                if [ -f "$CONFIG_FILE" ]; then
                    print_info "Updating configuration files..."
                    download_configs
                    systemctl restart $SERVICE_NAME
                    print_status "Configuration files updated and proxy restarted"
                else
                    print_error "Proxy is not installed."
                fi
                read -p "Press Enter to continue..."
                ;;
            7)
                uninstall_proxy
                ;;
            8)
                show_about
                ;;
            0)
                clear
                print_success "Thank you for using MTProto Proxy Ultimate!"
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

# Check root
check_root

# Welcome message
clear
print_success "MTProto Proxy Ultimate Installer v3.0"
print_info "Starting installation and management script..."
sleep 2

# Start main menu
main_menu
