#!/bin/bash

# ============================================
# MTProto Proxy Ultimate Manager
# Version: 6.0 - Complete Menu & Sponsor Tag
# ============================================

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Global Variables
PROXY_DIR="/opt/MTProxy"
SERVICE_NAME="MTProxy"
CONFIG_FILE="$PROXY_DIR/objs/bin/mtconfig.conf"
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"
LOG_FILE="/var/log/MTProxy.log"
SCRIPT_VERSION="6.0"
BOT_URL="https://t.me/MTProxybot"
REPO_URL="https://github.com/TelegramMessenger/MTProxy"

# Current Configuration
PORT=""
PUBLIC_IP=""
PRIVATE_IP=""
TLS_DOMAIN=""
TAG=""
CUSTOM_ARGS=""
HAVE_NAT="n"
CPU_CORES=1
SECRET_ARY=()
PROXY_INSTALLED=false
PROXY_RUNNING=false

# ============================================
# Utility Functions
# ============================================

print_status() { echo -e "${GREEN}[✓]${NC} $1"; }
print_info() { echo -e "${BLUE}[i]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }
print_success() { echo -e "${CYAN}[✔]${NC} $1"; }
print_menu_title() { echo -e "${MAGENTA}$1${NC}"; }
print_menu_item() { echo -e "${WHITE}$1${NC}"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root. Use: sudo $0"
        exit 1
    fi
}

clear_screen() {
    clear
}

show_banner() {
    clear_screen
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                  MTProto Proxy Manager v6.0                 ║"
    echo "║           Build & Manage Telegram Proxies Fast!             ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

show_loading() {
    local pid=$!
    local spin='-\|/'
    local i=0
    while kill -0 $pid 2>/dev/null; do
        i=$(( (i+1) %4 ))
        printf "\r[${spin:$i:1}] $1"
        sleep 0.1
    done
    printf "\r[✓] $1\n"
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
    else
        DISTRO="unknown"
        VERSION="unknown"
    fi
}

detect_architecture() {
    ARCH=$(uname -m)
    CPU_CORES=$(nproc --all)
    if [ $CPU_CORES -gt 16 ]; then
        CPU_CORES=16
    fi
}

# ============================================
# Random Generator Functions
# ============================================

generate_random_port() {
    local RANDOM_PORT=$((RANDOM % 40000 + 20000))
    while lsof -Pi :$RANDOM_PORT -sTCP:LISTEN -t >/dev/null ; do
        RANDOM_PORT=$((RANDOM % 40000 + 20000))
    done
    echo $RANDOM_PORT
}

generate_random_secret() {
    head -c 16 /dev/urandom | xxd -ps
}

generate_random_tag() {
    cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 24 | head -n 1
}

get_sponsor_tag() {
    clear_screen
    print_menu_title "=== Get Sponsor Tag from @MTProxybot ==="
    echo ""
    print_info "To get a sponsor tag:"
    echo ""
    echo "1. Visit @MTProxybot on Telegram"
    echo "2. Send /newproxy command"
    echo "3. Enter your server IP: $(get_public_ip)"
    echo "4. Enter proxy port: ${PORT:-443}"
    echo "5. Enter secret: ${SECRET_ARY[0]:-will be generated}"
    echo "6. Bot will give you a sponsor tag"
    echo "7. Enter that tag here"
    echo ""
    echo -e "${YELLOW}Note: Sponsor tag enables ads in proxy${NC}"
    echo ""
    
    read -p "Do you want to get tag now? (y/N): " get_now
    if [[ "$get_now" =~ ^[Yy]$ ]]; then
        print_info "Your server IP: $(get_public_ip)"
        print_info "Please visit @MTProxybot"
        echo ""
        read -p "After receiving, enter tag here (or Enter to skip): " tag_input
        
        if [ -n "$tag_input" ]; then
            TAG="$tag_input"
            print_success "Sponsor tag saved: $TAG"
        else
            print_warning "Tag retrieval cancelled"
        fi
    fi
    
    read -p "Press Enter to continue..."
}

# ============================================
# Configuration Management
# ============================================

load_configuration() {
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE" 2>/dev/null
        PROXY_INSTALLED=true
        
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            PROXY_RUNNING=true
        else
            PROXY_RUNNING=false
        fi
        return 0
    else
        PROXY_INSTALLED=false
        PROXY_RUNNING=false
        return 1
    fi
}

save_configuration() {
    mkdir -p "$(dirname "$CONFIG_FILE")"
    
    cat > "$CONFIG_FILE" << EOF
PORT=$PORT
PUBLIC_IP="$PUBLIC_IP"
PRIVATE_IP="$PRIVATE_IP"
TLS_DOMAIN="$TLS_DOMAIN"
TAG="$TAG"
CUSTOM_ARGS="$CUSTOM_ARGS"
HAVE_NAT="$HAVE_NAT"
CPU_CORES=$CPU_CORES
SECRET_ARY=(${SECRET_ARY[@]})
INSTALL_DATE="$(date)"
EOF
    
    chmod 600 "$CONFIG_FILE"
}

get_public_ip() {
    if [ -z "$PUBLIC_IP" ]; then
        PUBLIC_IP=$(curl -s --max-time 5 https://api.ipify.org || \
                    curl -s --max-time 5 https://icanhazip.com || \
                    curl -s --max-time 5 https://ifconfig.me/ip || \
                    echo "IP not found")
    fi
    echo "$PUBLIC_IP"
}

# ============================================
# Proxy Installation Functions
# ============================================

install_dependencies() {
    print_info "Installing system dependencies..."
    
    detect_os
    
    case $DISTRO in
        ubuntu|debian)
            apt-get update > /dev/null 2>&1 &
            show_loading "Updating package lists"
            
            apt-get install -y git curl build-essential libssl-dev zlib1g-dev \
                net-tools lsof xxd jq iptables > /dev/null 2>&1 &
            show_loading "Installing required packages"
            ;;
        centos|rhel|fedora)
            yum install -y epel-release > /dev/null 2>&1 &
            show_loading "Adding EPEL repository"
            
            yum groupinstall -y "Development Tools" > /dev/null 2>&1 &
            show_loading "Installing development tools"
            
            yum install -y git curl openssl-devel zlib-devel \
                net-tools lsof jq iptables > /dev/null 2>&1 &
            show_loading "Installing required packages"
            ;;
        *)
            print_error "Unsupported distribution: $DISTRO"
            return 1
            ;;
    esac
    
    print_status "Dependencies installed"
    return 0
}

build_mtproxy() {
    print_info "Building MTProto Proxy..."
    
    rm -rf "$PROXY_DIR" 2>/dev/null
    
    git clone -b gcc10 https://github.com/krepver/MTProxy.git "$PROXY_DIR" > /dev/null 2>&1 &
    show_loading "Downloading source code"
    
    if [ $? -ne 0 ]; then
        print_error "Failed to download source code"
        return 1
    fi
    
    cd "$PROXY_DIR"
    
    detect_architecture
    if [[ "$ARCH" != "x86_64" ]] && [[ "$ARCH" != "x64" ]]; then
        sed -i 's/-mpclmul//g' Makefile
        sed -i 's/-mfpmath=sse//g' Makefile
        sed -i 's/-mssse3//g' Makefile
        sed -i 's/-march=core2//g' Makefile
        print_info "Fixed Makefile for $ARCH architecture"
    fi
    
    make -j$CPU_CORES > /dev/null 2>&1 &
    show_loading "Compiling MTProto Proxy"
    
    if [ $? -ne 0 ]; then
        print_warning "Compilation failed, retrying..."
        make clean
        make > /dev/null 2>&1 &
        show_loading "Recompiling"
    fi
    
    if [ ! -f "objs/bin/mtproto-proxy" ]; then
        print_error "Failed to create binary"
        return 1
    fi
    
    print_status "Build successful"
    return 0
}

download_config_files() {
    print_info "Downloading configuration files..."
    
    cd "$PROXY_DIR/objs/bin"
    
    curl -s https://core.telegram.org/getProxySecret -o proxy-secret > /dev/null 2>&1 &
    show_loading "Downloading proxy-secret"
    
    curl -s https://core.telegram.org/getProxyConfig -o proxy-multi.conf > /dev/null 2>&1 &
    show_loading "Downloading proxy-multi.conf"
    
    print_status "Configuration files downloaded"
}

configure_firewall() {
    if [ -z "$PORT" ]; then
        return
    fi
    
    print_info "Configuring firewall for port $PORT..."
    
    case $DISTRO in
        ubuntu|debian)
            if command -v ufw >/dev/null 2>&1; then
                ufw allow $PORT/tcp > /dev/null 2>&1
                ufw reload > /dev/null 2>&1
            else
                iptables -A INPUT -p tcp --dport $PORT -j ACCEPT 2>/dev/null
            fi
            ;;
        centos|rhel|fedora)
            if command -v firewall-cmd >/dev/null 2>&1; then
                firewall-cmd --permanent --add-port=$PORT/tcp > /dev/null 2>&1
                firewall-cmd --reload > /dev/null 2>&1
            else
                iptables -A INPUT -p tcp --dport $PORT -j ACCEPT 2>/dev/null
            fi
            ;;
    esac
    
    print_status "Firewall configured"
}

create_systemd_service() {
    print_info "Creating systemd service..."
    
    local ARGS_STR="-u nobody -H $PORT"
    
    for secret in "${SECRET_ARY[@]}"; do
        ARGS_STR+=" -S $secret"
    done
    
    if [ -n "$TAG" ]; then
        ARGS_STR+=" -P $TAG"
    fi
    
    if [ -n "$TLS_DOMAIN" ]; then
        ARGS_STR+=" -D $TLS_DOMAIN"
    fi
    
    if [ "$HAVE_NAT" == "y" ] && [ -n "$PRIVATE_IP" ] && [ -n "$PUBLIC_IP" ]; then
        ARGS_STR+=" --nat-info $PRIVATE_IP:$PUBLIC_IP"
    fi
    
    local WORKER_CORES=$((CPU_CORES > 1 ? CPU_CORES - 1 : 1))
    if [ $WORKER_CORES -gt 16 ]; then
        WORKER_CORES=16
    fi
    
    ARGS_STR+=" -M $WORKER_CORES --aes-pwd proxy-secret proxy-multi.conf"
    
    if [ -n "$CUSTOM_ARGS" ]; then
        ARGS_STR+=" $CUSTOM_ARGS"
    fi
    
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=MTProxy Service
After=network.target

[Service]
Type=simple
WorkingDirectory=$PROXY_DIR/objs/bin
ExecStart=$PROXY_DIR/objs/bin/mtproto-proxy $ARGS_STR
Restart=on-failure
RestartSec=10
StandardOutput=append:$LOG_FILE
StandardError=append:$LOG_FILE
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
    
    touch "$LOG_FILE"
    chmod 644 "$LOG_FILE"
    
    systemctl daemon-reload > /dev/null 2>&1
    systemctl enable "$SERVICE_NAME" > /dev/null 2>&1
    
    print_status "Systemd service created"
}

start_proxy_service() {
    print_info "Starting proxy service..."
    
    systemctl start "$SERVICE_NAME" > /dev/null 2>&1
    sleep 3
    
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        PROXY_RUNNING=true
        print_success "Service started successfully"
        return 0
    else
        PROXY_RUNNING=false
        print_error "Failed to start service"
        journalctl -u "$SERVICE_NAME" --no-pager -n 10
        return 1
    fi
}

# ============================================
# Installation Wizard
# ============================================

installation_wizard() {
    clear_screen
    show_banner
    
    print_menu_title "=== MTProto Proxy Installation Wizard ==="
    echo ""
    
    # Step 1: Port selection
    while true; do
        echo -e "${WHITE}Port Configuration:${NC}"
        echo "  1) Use default port (443)"
        echo "  2) Generate random port"
        echo "  3) Enter custom port"
        echo ""
        read -p "Your choice (1-3): " port_choice
        
        case $port_choice in
            1)
                PORT=443
                break
                ;;
            2)
                PORT=$(generate_random_port)
                print_info "Random port generated: $PORT"
                break
                ;;
            3)
                while true; do
                    read -p "Enter port (1-65535): " input_port
                    if [[ "$input_port" =~ ^[0-9]+$ ]] && [ "$input_port" -ge 1 ] && [ "$input_port" -le 65535 ]; then
                        PORT=$input_port
                        break
                    else
                        print_error "Invalid port"
                    fi
                done
                break
                ;;
            *)
                print_error "Invalid choice"
                ;;
        esac
    done
    
    echo ""
    
    # Step 2: Secret configuration
    print_info "Secret Configuration:"
    echo "  1) Generate random secret"
    echo "  2) Enter custom secret"
    read -p "Your choice (1-2): " secret_choice
    
    if [ "$secret_choice" == "1" ]; then
        SECRET=$(generate_random_secret)
        SECRET_ARY=("$SECRET")
        print_info "Random secret generated: $SECRET"
    else
        while true; do
            read -p "Enter secret (32 hex characters): " input_secret
            if [[ "$input_secret" =~ ^[0-9a-fA-F]{32}$ ]]; then
                SECRET_ARY=("$input_secret")
                break
            else
                print_error "Invalid secret. Must be 32 hex characters."
            fi
        done
    fi
    
    echo ""
    
    # Step 3: Sponsor Tag
    print_info "Sponsor Tag (Optional):"
    echo "  1) Get sponsor tag from @MTProxybot"
    echo "  2) Generate random tag"
    echo "  3) No tag"
    read -p "Your choice (1-3): " tag_choice
    
    case $tag_choice in
        1)
            get_sponsor_tag
            ;;
        2)
            TAG="3$(generate_random_tag)"
            print_info "Random tag generated: $TAG"
            ;;
        3)
            TAG=""
            print_info "Continuing without tag"
            ;;
    esac
    
    echo ""
    
    # Step 4: Fake-TLS
    print_info "Enable Fake-TLS (Optional):"
    echo "  1) Enable with cloudflare.com"
    echo "  2) Enable with custom domain"
    echo "  3) Disable Fake-TLS"
    read -p "Your choice (1-3): " tls_choice
    
    case $tls_choice in
        1)
            TLS_DOMAIN="www.cloudflare.com"
            print_info "Fake-TLS enabled with cloudflare.com"
            ;;
        2)
            read -p "Enter domain: " tls_domain
            TLS_DOMAIN="$tls_domain"
            print_info "Fake-TLS enabled with $TLS_DOMAIN"
            ;;
        3)
            TLS_DOMAIN=""
            print_info "Fake-TLS disabled"
            ;;
    esac
    
    echo ""
    
    # Step 5: Advanced settings
    print_info "Advanced Settings:"
    read -p "Number of worker processes (default: $CPU_CORES): " workers_input
    if [[ "$workers_input" =~ ^[0-9]+$ ]] && [ "$workers_input" -ge 1 ] && [ "$workers_input" -le $CPU_CORES ]; then
        CPU_CORES=$workers_input
    fi
    
    read -p "Custom arguments (optional): " custom_args
    CUSTOM_ARGS="$custom_args"
    
    echo ""
    
    # Step 6: Get IP addresses
    print_info "Getting IP addresses..."
    PUBLIC_IP=$(get_public_ip)
    PRIVATE_IP=$(hostname -I | awk '{print $1}')
    
    # Detect NAT
    if [[ $PRIVATE_IP =~ ^10\. ]] || \
       [[ $PRIVATE_IP =~ ^172\.1[6-9]\. ]] || \
       [[ $PRIVATE_IP =~ ^172\.2[0-9]\. ]] || \
       [[ $PRIVATE_IP =~ ^172\.3[0-1]\. ]] || \
       [[ $PRIVATE_IP =~ ^192\.168\. ]]; then
        HAVE_NAT="y"
        print_info "Server behind NAT detected"
    fi
    
    # Step 7: Confirm installation
    clear_screen
    print_menu_title "=== Configuration Summary ==="
    echo ""
    echo "Port: $PORT"
    echo "Secret: ${SECRET_ARY[0]}"
    echo "Tag: ${TAG:-No tag}"
    echo "TLS Domain: ${TLS_DOMAIN:-Disabled}"
    echo "Public IP: $PUBLIC_IP"
    echo "Private IP: $PRIVATE_IP"
    echo "Worker Processes: $CPU_CORES"
    echo "NAT: $HAVE_NAT"
    echo ""
    
    read -p "Start installation? (Y/n): " confirm_install
    
    if [[ "$confirm_install" =~ ^[Nn]$ ]]; then
        print_warning "Installation cancelled"
        return 1
    fi
    
    # Start installation
    if ! install_dependencies; then
        print_error "Failed to install dependencies"
        return 1
    fi
    
    if ! build_mtproxy; then
        print_error "Failed to build proxy"
        return 1
    fi
    
    download_config_files
    configure_firewall
    create_systemd_service
    save_configuration
    
    if start_proxy_service; then
        show_installation_result
    else
        print_error "Installation complete but service failed to start"
    fi
    
    return 0
}

show_installation_result() {
    clear_screen
    print_success "=== Installation Successful ==="
    echo ""
    
    if [ -n "$TLS_DOMAIN" ]; then
        HEX_DOMAIN=$(printf "%s" "$TLS_DOMAIN" | xxd -pu | tr '[:upper:]' '[:lower:]')
        echo -e "${GREEN}Connection Links (with Fake-TLS):${NC}"
        for secret in "${SECRET_ARY[@]}"; do
            echo "tg://proxy?server=$PUBLIC_IP&port=$PORT&secret=ee${secret}${HEX_DOMAIN}"
        done
    else
        echo -e "${GREEN}Connection Links:${NC}"
        for secret in "${SECRET_ARY[@]}"; do
            echo "tg://proxy?server=$PUBLIC_IP&port=$PORT&secret=dd${secret}"
        done
    fi
    
    echo ""
    echo -e "${YELLOW}Connection Guide:${NC}"
    echo "1. Go to Settings > Data and Storage > Proxy"
    echo "2. Select Add Proxy > MTProto"
    echo "3. Enter:"
    echo "   Server: $PUBLIC_IP"
    echo "   Port: $PORT"
    echo "   Secret: dd${SECRET_ARY[0]}"
    
    echo ""
    echo -e "${BLUE}Management Info:${NC}"
    echo "   Service status: systemctl status $SERVICE_NAME"
    echo "   View logs: journalctl -u $SERVICE_NAME -f"
    echo "   Restart: systemctl restart $SERVICE_NAME"
    
    echo ""
    read -p "Press Enter to continue..."
}

# ============================================
# Proxy Management Functions
# ============================================

show_proxy_status() {
    clear_screen
    print_menu_title "=== Proxy Status ==="
    echo ""
    
    if ! load_configuration; then
        print_error "Proxy not installed"
        return
    fi
    
    echo -e "${WHITE}Proxy Details:${NC}"
    echo "  Port: $PORT"
    echo "  Public IP: $PUBLIC_IP"
    echo "  Secrets count: ${#SECRET_ARY[@]}"
    echo "  Sponsor Tag: ${TAG:-None}"
    echo "  TLS Domain: ${TLS_DOMAIN:-None}"
    echo ""
    
    echo -e "${WHITE}Service Status:${NC}"
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_success "  Running ✓"
        echo ""
        echo "  Process Info:"
        systemctl status "$SERVICE_NAME" --no-pager | grep -A 3 "Active:"
        echo ""
        echo "  Network Connections:"
        netstat -tulpn 2>/dev/null | grep ":$PORT" || echo "  No connections found"
    else
        print_error "  Stopped ✗"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

manage_secrets() {
    clear_screen
    print_menu_title "=== Secrets Management ==="
    echo ""
    
    if ! load_configuration; then
        print_error "Proxy not installed"
        return
    fi
    
    while true; do
        clear_screen
        print_menu_title "Secrets Management"
        echo ""
        
        echo -e "${WHITE}Current Secrets (${#SECRET_ARY[@]}/16):${NC}"
        for i in "${!SECRET_ARY[@]}"; do
            echo "  $((i+1)). ${SECRET_ARY[$i]}"
        done
        
        echo ""
        echo "  1) Add new secret"
        echo "  2) Remove secret"
        echo "  3) Generate random secret"
        echo "  4) Back"
        echo ""
        
        read -p "Your choice: " secret_action
        
        case $secret_action in
            1)
                if [ ${#SECRET_ARY[@]} -ge 16 ]; then
                    print_error "Maximum 16 secrets allowed"
                    sleep 2
                    continue
                fi
                
                read -p "Enter secret (32 hex characters): " new_secret
                if [[ "$new_secret" =~ ^[0-9a-fA-F]{32}$ ]]; then
                    SECRET_ARY+=("$new_secret")
                    save_configuration
                    systemctl restart "$SERVICE_NAME"
                    print_success "Secret added and service restarted"
                else
                    print_error "Invalid secret"
                fi
                sleep 2
                ;;
            2)
                if [ ${#SECRET_ARY[@]} -le 1 ]; then
                    print_error "At least one secret must remain"
                    sleep 2
                    continue
                fi
                
                read -p "Secret number to remove: " secret_num
                if [[ "$secret_num" =~ ^[0-9]+$ ]] && [ "$secret_num" -ge 1 ] && [ "$secret_num" -le ${#SECRET_ARY[@]} ]; then
                    index=$((secret_num-1))
                    removed_secret=${SECRET_ARY[$index]}
                    unset SECRET_ARY[$index]
                    SECRET_ARY=("${SECRET_ARY[@]}")
                    save_configuration
                    systemctl restart "$SERVICE_NAME"
                    print_success "Secret removed and service restarted"
                else
                    print_error "Invalid number"
                fi
                sleep 2
                ;;
            3)
                if [ ${#SECRET_ARY[@]} -ge 16 ]; then
                    print_error "Maximum 16 secrets allowed"
                    sleep 2
                    continue
                fi
                
                new_secret=$(generate_random_secret)
                SECRET_ARY+=("$new_secret")
                save_configuration
                systemctl restart "$SERVICE_NAME"
                print_success "Random secret generated: $new_secret"
                sleep 2
                ;;
            4)
                return
                ;;
            *)
                print_error "Invalid choice"
                sleep 2
                ;;
        esac
    done
}

manage_sponsor_tag() {
    clear_screen
    print_menu_title "=== Sponsor Tag Management ==="
    echo ""
    
    if ! load_configuration; then
        print_error "Proxy not installed"
        return
    fi
    
    echo "Current tag: ${TAG:-None}"
    echo ""
    echo "  1) Get new tag from @MTProxybot"
    echo "  2) Change tag manually"
    echo "  3) Remove tag"
    echo "  4) Back"
    echo ""
    
    read -p "Your choice: " tag_action
    
    case $tag_action in
        1)
            get_sponsor_tag
            if [ -n "$TAG" ]; then
                save_configuration
                systemctl restart "$SERVICE_NAME"
                print_success "Tag updated and service restarted"
            fi
            ;;
        2)
            read -p "Enter new tag: " new_tag
            TAG="$new_tag"
            save_configuration
            systemctl restart "$SERVICE_NAME"
            print_success "Tag changed and service restarted"
            ;;
        3)
            TAG=""
            save_configuration
            systemctl restart "$SERVICE_NAME"
            print_success "Tag removed and service restarted"
            ;;
        4)
            return
            ;;
    esac
    
    sleep 2
}

view_logs() {
    clear_screen
    print_menu_title "=== View Logs ==="
    echo ""
    
    if ! load_configuration; then
        print_error "Proxy not installed"
        return
    fi
    
    echo "  1) View recent logs"
    echo "  2) View logs in real-time"
    echo "  3) View log file"
    echo "  4) Clear logs"
    echo "  5) Back"
    echo ""
    
    read -p "Your choice: " log_choice
    
    case $log_choice in
        1)
            clear_screen
            journalctl -u "$SERVICE_NAME" --no-pager -n 30
            ;;
        2)
            clear_screen
            print_info "Viewing logs in real-time (Ctrl+C to exit)..."
            journalctl -u "$SERVICE_NAME" -f
            ;;
        3)
            clear_screen
            if [ -f "$LOG_FILE" ]; then
                tail -n 50 "$LOG_FILE"
            else
                print_error "Log file not found"
            fi
            ;;
        4)
            journalctl --vacuum-time=1d > /dev/null 2>&1
            > "$LOG_FILE" 2>/dev/null
            print_success "Logs cleared"
            sleep 2
            return
            ;;
        5)
            return
            ;;
    esac
    
    echo ""
    read -p "Press Enter to continue..."
}

quick_install() {
    clear_screen
    print_menu_title "=== Quick Proxy Installation ==="
    echo ""
    
    print_info "Installing with default settings..."
    
    # Set default values
    PORT=$(generate_random_port)
    SECRET=$(generate_random_secret)
    SECRET_ARY=("$SECRET")
    TAG=""
    TLS_DOMAIN="www.cloudflare.com"
    PUBLIC_IP=$(get_public_ip)
    PRIVATE_IP=$(hostname -I | awk '{print $1}')
    CPU_CORES=$(nproc --all)
    if [ $CPU_CORES -gt 8 ]; then
        CPU_CORES=8
    fi
    
    print_info "Port: $PORT"
    print_info "Secret: $SECRET"
    print_info "TLS Domain: $TLS_DOMAIN"
    
    # Install
    if ! install_dependencies; then
        print_error "Failed to install dependencies"
        return 1
    fi
    
    if ! build_mtproxy; then
        print_error "Failed to build proxy"
        return 1
    fi
    
    download_config_files
    configure_firewall
    create_systemd_service
    save_configuration
    
    if start_proxy_service; then
        clear_screen
        print_success "=== Quick Installation Complete ==="
        echo ""
        echo "Connection Link:"
        HEX_DOMAIN=$(printf "%s" "$TLS_DOMAIN" | xxd -pu | tr '[:upper:]' '[:lower:]')
        echo "tg://proxy?server=$PUBLIC_IP&port=$PORT&secret=ee${SECRET}${HEX_DOMAIN}"
        echo ""
        echo "https://t.me/proxy?server=$PUBLIC_IP&port=$PORT&secret=ee${SECRET}${HEX_DOMAIN}"
        echo ""
        read -p "Press Enter to continue..."
    else
        print_error "Installation complete but service failed to start"
    fi
}

update_configuration() {
    clear_screen
    print_menu_title "=== Update Configuration ==="
    echo ""
    
    if ! load_configuration; then
        print_error "Proxy not installed"
        return
    fi
    
    print_info "Downloading new configuration files..."
    
    cd "$PROXY_DIR/objs/bin"
    
    # Backup old files
    cp proxy-secret proxy-secret.backup 2>/dev/null
    cp proxy-multi.conf proxy-multi.conf.backup 2>/dev/null
    
    # Download new files
    curl -s https://core.telegram.org/getProxySecret -o proxy-secret.tmp && \
    mv proxy-secret.tmp proxy-secret
    
    curl -s https://core.telegram.org/getProxyConfig -o proxy-multi.conf.tmp && \
    mv proxy-multi.conf.tmp proxy-multi.conf
    
    systemctl restart "$SERVICE_NAME"
    
    print_success "Configuration updated and service restarted"
    sleep 2
}

uninstall_proxy() {
    clear_screen
    print_menu_title "=== Uninstall Proxy ==="
    echo ""
    
    if ! load_configuration; then
        print_error "Proxy not installed"
        return
    fi
    
    print_warning "⚠️  Warning: This will completely remove the proxy!"
    echo ""
    read -p "Are you sure? (y/N): " confirm_uninstall
    
    if [[ ! "$confirm_uninstall" =~ ^[Yy]$ ]]; then
        print_info "Uninstall cancelled"
        return
    fi
    
    print_info "Stopping service..."
    systemctl stop "$SERVICE_NAME" 2>/dev/null
    systemctl disable "$SERVICE_NAME" 2>/dev/null
    
    print_info "Removing service file..."
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
    
    print_info "Removing proxy files..."
    rm -rf "$PROXY_DIR"
    
    print_info "Removing log files..."
    rm -f "$LOG_FILE"
    journalctl --vacuum-time=1d > /dev/null 2>&1
    
    print_success "Proxy completely removed"
    sleep 2
}

# ============================================
# Main Menu
# ============================================

show_main_menu() {
    while true; do
        clear_screen
        show_banner
        
        load_configuration
        
        echo -e "${WHITE}System Status:${NC}"
        if $PROXY_INSTALLED; then
            if $PROXY_RUNNING; then
                echo -e "  ${GREEN}✓ Proxy installed and running${NC}"
            else
                echo -e "  ${YELLOW}⚠ Proxy installed but stopped${NC}"
            fi
        else
            echo -e "  ${BLUE}○ Proxy not installed${NC}"
        fi
        
        if $PROXY_INSTALLED; then
            echo "  Port: $PORT | Secrets: ${#SECRET_ARY[@]} | Tag: ${TAG:[:20]}..."
        fi
        
        echo ""
        print_menu_title "Main Menu:"
        echo ""
        
        if ! $PROXY_INSTALLED; then
            print_menu_item "  1) New Proxy Installation (Wizard)"
            print_menu_item "  2) Quick Proxy Installation (Default)"
        else
            print_menu_item "  1) View Proxy Status"
            print_menu_item "  2) Manage Secrets"
            print_menu_item "  3) Manage Sponsor Tag"
            print_menu_item "  4) Service Control"
            print_menu_item "  5) View Logs"
            print_menu_item "  6) Update Configuration"
            print_menu_item "  7) Show Connection Links"
        fi
        
        echo ""
        print_menu_item "  8) Advanced Settings"
        print_menu_item "  9) Uninstall Proxy"
        print_menu_item "  0) Exit"
        echo ""
        
        read -p "Your choice: " main_choice
        
        case $main_choice in
            1)
                if ! $PROXY_INSTALLED; then
                    installation_wizard
                else
                    show_proxy_status
                fi
                ;;
            2)
                if ! $PROXY_INSTALLED; then
                    quick_install
                else
                    manage_secrets
                fi
                ;;
            3)
                if $PROXY_INSTALLED; then
                    manage_sponsor_tag
                else
                    print_error "Proxy not installed"
                    sleep 2
                fi
                ;;
            4)
                if $PROXY_INSTALLED; then
                    service_control_menu
                else
                    print_error "Proxy not installed"
                    sleep 2
                fi
                ;;
            5)
                if $PROXY_INSTALLED; then
                    view_logs
                else
                    print_error "Proxy not installed"
                    sleep 2
                fi
                ;;
            6)
                if $PROXY_INSTALLED; then
                    update_configuration
                else
                    print_error "Proxy not installed"
                    sleep 2
                fi
                ;;
            7)
                if $PROXY_INSTALLED; then
                    show_connection_links
                else
                    print_error "Proxy not installed"
                    sleep 2
                fi
                ;;
            8)
                advanced_settings_menu
                ;;
            9)
                uninstall_proxy
                ;;
            0)
                clear_screen
                print_success "Thank you for using MTProto Proxy Manager! Goodbye"
                echo ""
                exit 0
                ;;
            *)
                print_error "Invalid choice"
                sleep 2
                ;;
        esac
    done
}

service_control_menu() {
    clear_screen
    print_menu_title "=== Service Control ==="
    echo ""
    
    echo "  1) Start Service"
    echo "  2) Stop Service"
    echo "  3) Restart Service"
    echo "  4) View Full Status"
    echo "  5) Enable Auto-start"
    echo "  6) Disable Auto-start"
    echo "  7) Back"
    echo ""
    
    read -p "Your choice: " service_choice
    
    case $service_choice in
        1)
            systemctl start "$SERVICE_NAME"
            print_success "Service started"
            sleep 2
            ;;
        2)
            systemctl stop "$SERVICE_NAME"
            print_success "Service stopped"
            sleep 2
            ;;
        3)
            systemctl restart "$SERVICE_NAME"
            print_success "Service restarted"
            sleep 2
            ;;
        4)
            clear_screen
            systemctl status "$SERVICE_NAME" --no-pager -l
            echo ""
            read -p "Press Enter to continue..."
            ;;
        5)
            systemctl enable "$SERVICE_NAME"
            print_success "Auto-start enabled"
            sleep 2
            ;;
        6)
            systemctl disable "$SERVICE_NAME"
            print_success "Auto-start disabled"
            sleep 2
            ;;
        7)
            return
            ;;
    esac
}

show_connection_links() {
    clear_screen
    print_menu_title "=== Connection Links ==="
    echo ""
    
    if ! load_configuration; then
        print_error "Proxy not installed"
        return
    fi
    
    get_public_ip > /dev/null
    
    if [ -n "$TLS_DOMAIN" ]; then
        HEX_DOMAIN=$(printf "%s" "$TLS_DOMAIN" | xxd -pu | tr '[:upper:]' '[:lower:]')
        echo -e "${GREEN}Links with Fake-TLS:${NC}"
        for i in "${!SECRET_ARY[@]}"; do
            echo "tg://proxy?server=$PUBLIC_IP&port=$PORT&secret=ee${SECRET_ARY[$i]}${HEX_DOMAIN}"
            echo "https://t.me/proxy?server=$PUBLIC_IP&port=$PORT&secret=ee${SECRET_ARY[$i]}${HEX_DOMAIN}"
            echo ""
        done
    else
        echo -e "${GREEN}Normal Links:${NC}"
        for i in "${!SECRET_ARY[@]}"; do
            echo "tg://proxy?server=$PUBLIC_IP&port=$PORT&secret=dd${SECRET_ARY[$i]}"
            echo "https://t.me/proxy?server=$PUBLIC_IP&port=$PORT&secret=dd${SECRET_ARY[$i]}"
            echo ""
        done
    fi
    
    echo ""
    echo -e "${YELLOW}Connection Guide:${NC}"
    echo "Server: $PUBLIC_IP"
    echo "Port: $PORT"
    echo "Secret: dd${SECRET_ARY[0]}"
    echo ""
    
    read -p "Press Enter to continue..."
}

advanced_settings_menu() {
    clear_screen
    print_menu_title "=== Advanced Settings ==="
    echo ""
    
    if ! load_configuration; then
        print_error "Proxy not installed"
        return
    fi
    
    echo "  1) Change Port"
    echo "  2) Change TLS Domain"
    echo "  3) Set Custom Arguments"
    echo "  4) Set Worker Processes"
    echo "  5) Configure NAT"
    echo "  6) Update Proxy Binary"
    echo "  7) Test Connection"
    echo "  8) Backup Configuration"
    echo "  9) Restore Configuration"
    echo "  10) Back"
    echo ""
    
    read -p "Your choice: " advanced_choice
    
    case $advanced_choice in
        1)
            read -p "New port: " new_port
            if [[ "$new_port" =~ ^[0-9]+$ ]] && [ "$new_port" -ge 1 ] && [ "$new_port" -le 65535 ]; then
                PORT=$new_port
                save_configuration
                systemctl restart "$SERVICE_NAME"
                print_success "Port changed"
            else
                print_error "Invalid port"
            fi
            sleep 2
            ;;
        2)
            read -p "New TLS Domain (empty to disable): " new_tls
            TLS_DOMAIN="$new_tls"
            save_configuration
            systemctl restart "$SERVICE_NAME"
            print_success "TLS Domain changed"
            sleep 2
            ;;
        3)
            read -p "Custom arguments: " custom_args
            CUSTOM_ARGS="$custom_args"
            save_configuration
            systemctl restart "$SERVICE_NAME"
            print_success "Custom arguments saved"
            sleep 2
            ;;
        4)
            detect_architecture
            read -p "Number of Worker Processes (1-$CPU_CORES): " workers
            if [[ "$workers" =~ ^[0-9]+$ ]] && [ "$workers" -ge 1 ] && [ "$workers" -le $CPU_CORES ]; then
                CPU_CORES=$workers
                save_configuration
                systemctl restart "$SERVICE_NAME"
                print_success "Worker Processes changed"
            else
                print_error "Invalid number"
            fi
            sleep 2
            ;;
        5)
            read -p "Is server behind NAT? (y/N): " nat_choice
            if [[ "$nat_choice" =~ ^[Yy]$ ]]; then
                HAVE_NAT="y"
                read -p "Public IP: " public_ip
                read -p "Private IP: " private_ip
                PUBLIC_IP="$public_ip"
                PRIVATE_IP="$private_ip"
            else
                HAVE_NAT="n"
            fi
            save_configuration
            systemctl restart "$SERVICE_NAME"
            print_success "NAT settings updated"
            sleep 2
            ;;
        6)
            print_info "Updating proxy binary..."
            build_mtproxy
            systemctl restart "$SERVICE_NAME"
            print_success "Binary updated"
            sleep 2
            ;;
        7)
            print_info "Testing connection to port $PORT..."
            if timeout 5 nc -z localhost $PORT; then
                print_success "Port $PORT is open"
            else
                print_error "Port $PORT is closed"
            fi
            sleep 2
            ;;
        8)
            backup_file="$PROXY_DIR/config-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
            tar -czf "$backup_file" -C "$PROXY_DIR" objs/bin/mtconfig.conf objs/bin/proxy-secret objs/bin/proxy-multi.conf
            print_success "Backup saved to $backup_file"
            sleep 2
            ;;
        9)
            read -p "Backup file path: " backup_file
            if [ -f "$backup_file" ]; then
                tar -xzf "$backup_file" -C "$PROXY_DIR"
                systemctl restart "$SERVICE_NAME"
                print_success "Configuration restored"
            else
                print_error "Backup file not found"
            fi
            sleep 2
            ;;
        10)
            return
            ;;
    esac
}

# ============================================
# Script Start
# ============================================

main() {
    check_root
    detect_os
    detect_architecture
    show_main_menu
}

main "$@"
