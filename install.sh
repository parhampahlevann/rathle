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

# Function to check architecture
check_architecture() {
    ARCH=$(uname -m)
    show_info "System Architecture: $ARCH"
    
    case $ARCH in
        x86_64)
            show_info "64-bit x86 architecture detected"
            ;;
        aarch64|arm64)
            show_info "ARM64 architecture detected"
            ;;
        armv7l|armv8l)
            show_info "ARM32 architecture detected"
            ;;
        i386|i686)
            show_info "32-bit x86 architecture detected"
            show_warning "32-bit systems might have performance limitations"
            ;;
        *)
            show_warning "Unknown architecture: $ARCH"
            show_warning "The script will try to proceed but compatibility is not guaranteed"
            ;;
    esac
}

# Function to update system
update_system() {
    show_info "Updating system packages..."
    apt-get update
    if [[ $? -eq 0 ]]; then
        show_success "System updated successfully"
    else
        show_error "Failed to update system"
        return 1
    fi
}

# Function to install dependencies
install_dependencies() {
    show_info "Installing required dependencies..."
    
    # List of required packages
    DEPENDENCIES=(
        git
        curl
        build-essential
        libssl-dev
        zlib1g-dev
        xxd
        jq
        net-tools
    )
    
    # Check and install missing dependencies
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
    
    show_success "All dependencies installed successfully"
}

# Function to clone and build MTProto Proxy
build_mtproto() {
    show_info "Cloning MTProto Proxy repository..."
    
    # Check if directory exists
    if [[ -d "$PROXY_DIR/source" ]]; then
        show_warning "Source directory already exists. Removing..."
        rm -rf "$PROXY_DIR/source"
    fi
    
    # Create directory
    mkdir -p "$PROXY_DIR/source"
    cd "$PROXY_DIR/source"
    
    # Clone repository
    git clone https://github.com/TelegramMessenger/MTProxy.git
    if [[ $? -ne 0 ]]; then
        show_error "Failed to clone repository"
        return 1
    fi
    
    cd MTProxy
    
    show_info "Building MTProto Proxy..."
    make
    if [[ $? -ne 0 ]]; then
        show_error "Failed to build MTProto Proxy"
        return 1
    fi
    
    # Copy binary to installation directory
    mkdir -p "$PROXY_DIR/bin"
    cp objs/bin/mtproto-proxy "$PROXY_DIR/bin/"
    
    show_success "MTProto Proxy built successfully"
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
    curl -s https://core.telegram.org/getProxySecret -o proxy-secret
    if [[ $? -ne 0 ]]; then
        show_error "Failed to download proxy-secret file"
        return 1
    fi
    
    curl -s https://core.telegram.org/getProxyConfig -o proxy-multi.conf
    if [[ $? -ne 0 ]]; then
        show_error "Failed to download proxy-multi.conf file"
        return 1
    fi
    
    show_success "Secret key generated and configuration files downloaded"
    echo -e "${YELLOW}Secret Key: $SECRET_KEY${NC}"
}

# Function to get server IP
get_server_ip() {
    # Try multiple methods to get public IP
    IP_METHODS=(
        "curl -s ifconfig.me"
        "curl -s icanhazip.com"
        "curl -s ipinfo.io/ip"
        "curl -s api.ipify.org"
    )
    
    for cmd in "${IP_METHODS[@]}"; do
        SERVER_IP=$(eval $cmd 2>/dev/null)
        if [[ -n "$SERVER_IP" && "$SERVER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$SERVER_IP"
            return 0
        fi
    done
    
    # If all methods fail, ask user
    show_warning "Could not automatically detect server IP"
    read -p "Enter server IP address: " SERVER_IP
    echo "$SERVER_IP"
}

# Function to configure proxy
configure_proxy() {
    show_info "Configuring MTProto Proxy..."
    
    # Ask for configuration parameters
    echo ""
    echo -e "${CYAN}Proxy Configuration${NC}"
    echo "=" * 40
    
    # Get server IP
    SERVER_IP=$(get_server_ip)
    echo "Server IP: $SERVER_IP"
    
    # Port configuration
    read -p "Enter proxy port [443]: " PROXY_PORT
    PROXY_PORT=${PROXY_PORT:-443}
    
    # Internal port for metrics
    read -p "Enter internal port [8888]: " INTERNAL_PORT
    INTERNAL_PORT=${INTERNAL_PORT:-8888}
    
    # Worker processes
    read -p "Enter number of worker processes (1-10) [1]: " WORKER_COUNT
    WORKER_COUNT=${WORKER_COUNT:-1}
    
    # Max connections
    read -p "Enter maximum connections (100-100000) [1000]: " MAX_CONNECTIONS
    MAX_CONNECTIONS=${MAX_CONNECTIONS:-1000}
    
    # Update config file
    {
        echo "SERVER_IP=$SERVER_IP"
        echo "PROXY_PORT=$PROXY_PORT"
        echo "INTERNAL_PORT=$INTERNAL_PORT"
        echo "WORKER_COUNT=$WORKER_COUNT"
        echo "MAX_CONNECTIONS=$MAX_CONNECTIONS"
    } >> "$CONFIG_FILE"
    
    # Load secret key
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
    else
        show_error "Config file not found. Generating new secret..."
        generate_secret
        source "$CONFIG_FILE"
    fi
    
    show_success "Proxy configuration saved"
}

# Function to create systemd service
create_service() {
    show_info "Creating systemd service..."
    
    # Load configuration
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
    else
        show_error "Config file not found"
        return 1
    fi
    
    # Create service file
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=MTProto Proxy Service
After=network.target

[Service]
Type=simple
User=nobody
Group=nogroup
WorkingDirectory=$PROXY_DIR
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
Restart=on-failure
RestartSec=10
StandardOutput=append:$LOG_FILE
StandardError=append:$LOG_FILE
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    
    show_success "Systemd service created and enabled"
}

# Function to start proxy
start_proxy() {
    show_info "Starting MTProto Proxy..."
    
    systemctl start "$SERVICE_NAME"
    
    if [[ $? -eq 0 ]]; then
        show_success "MTProto Proxy started successfully"
        sleep 2
        check_status
    else
        show_error "Failed to start MTProto Proxy"
        journalctl -u "$SERVICE_NAME" -n 20
    fi
}

# Function to stop proxy
stop_proxy() {
    show_info "Stopping MTProto Proxy..."
    
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
    fi
}

# Function to check proxy status
check_status() {
    show_info "Checking MTProto Proxy status..."
    
    # Check service status
    systemctl status "$SERVICE_NAME" --no-pager -l
    
    # Check if proxy is listening
    echo ""
    show_info "Network connections:"
    netstat -tulpn | grep -E ":$PROXY_PORT|:$INTERNAL_PORT" | grep -v grep || echo "No active proxy connections found"
    
    # Show logs
    echo ""
    show_info "Recent logs (last 10 lines):"
    journalctl -u "$SERVICE_NAME" -n 10 --no-pager
}

# Function to show proxy information
show_proxy_info() {
    show_info "MTProto Proxy Information"
    echo "=" * 40
    
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
        
        echo -e "${CYAN}Configuration:${NC}"
        echo "Server IP: $SERVER_IP"
        echo "Proxy Port: $PROXY_PORT"
        echo "Internal Port: $INTERNAL_PORT"
        echo "Worker Processes: $WORKER_COUNT"
        echo "Max Connections: $MAX_CONNECTIONS"
        echo "Secret Key: $SECRET_KEY"
        
        echo ""
        echo -e "${CYAN}Connection URLs:${NC}"
        
        # Create tg:// URL
        TG_URL="tg://proxy?server=$SERVER_IP&port=$PROXY_PORT&secret=$SECRET_KEY"
        echo "Telegram URL: $TG_URL"
        
        # Create https:// URL
        HTTPS_URL="https://t.me/proxy?server=$SERVER_IP&port=$PROXY_PORT&secret=$SECRET_KEY"
        echo "HTTPS URL: $HTTPS_URL"
        
        echo ""
        echo -e "${CYAN}Usage Instructions:${NC}"
        echo "1. Open Telegram"
        echo "2. Go to Settings > Data and Storage > Proxy"
        echo "3. Add Proxy > SOCKS5/MTProto"
        echo "4. Use the information above"
        
        echo ""
        echo -e "${YELLOW}To share this proxy, use this format:${NC}"
        echo "Server: $SERVER_IP"
        echo "Port: $PROXY_PORT"
        echo "Secret: $SECRET_KEY"
        
    else
        show_error "Configuration file not found. Please install the proxy first."
    fi
}

# Function to uninstall proxy
uninstall_proxy() {
    show_warning "This will completely remove MTProto Proxy and all its data!"
    read -p "Are you sure? (y/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        show_info "Stopping and disabling service..."
        systemctl stop "$SERVICE_NAME" 2>/dev/null
        systemctl disable "$SERVICE_NAME" 2>/dev/null
        rm -f "$SERVICE_FILE"
        systemctl daemon-reload
        
        show_info "Removing proxy files..."
        rm -rf "$PROXY_DIR"
        
        show_info "Cleaning up logs..."
        rm -f "$LOG_FILE"
        journalctl --vacuum-time=1d
        
        show_success "MTProto Proxy completely uninstalled"
    else
        show_info "Uninstallation cancelled"
    fi
}

# Function to install proxy
install_proxy() {
    show_banner
    show_info "Starting MTProto Proxy installation..."
    
    # Check prerequisites
    check_root
    check_architecture
    
    # Update system
    update_system
    if [[ $? -ne 0 ]]; then
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    # Install dependencies
    install_dependencies
    if [[ $? -ne 0 ]]; then
        show_error "Failed to install dependencies"
        exit 1
    fi
    
    # Create proxy directory
    mkdir -p "$PROXY_DIR"
    
    # Build MTProto Proxy
    build_mtproto
    if [[ $? -ne 0 ]]; then
        show_error "Failed to build MTProto Proxy"
        exit 1
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
    show_success "Installation completed successfully!"
    echo ""
    
    # Show proxy information
    show_proxy_info
}

# Function to show main menu
show_menu() {
    show_banner
    
    echo -e "${CYAN}Main Menu${NC}"
    echo "=" * 40
    echo "1. Install MTProto Proxy"
    echo "2. Start Proxy"
    echo "3. Stop Proxy"
    echo "4. Restart Proxy"
    echo "5. Check Status"
    echo "6. Show Proxy Info"
    echo "7. Update Proxy (Reinstall)"
    echo "8. Uninstall Proxy"
    echo "9. Update System Packages"
    echo "0. Exit"
    echo "=" * 40
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
                show_info "Updating/Reinstalling MTProto Proxy..."
                stop_proxy 2>/dev/null
                install_proxy
                ;;
            8)
                uninstall_proxy
                ;;
            9)
                update_system
                ;;
            0)
                show_info "Exiting..."
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

# Check if script is being sourced or run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
