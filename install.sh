#!/bin/bash

# ============================================
# MTPulse - MTProto Proxy Installer
# Version: 2.1.0
# Author: Parham Pahlevan
# Telegram: @ParhamPahlevan
# GitHub: https://github.com/ParhamPahlevan/MTPulse
# ============================================

# Terminal colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'
BOLD='\033[1m'
RESET='\033[0m'

# Global variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/usr/local/mtpulse"
SERVICE_FILE="/etc/systemd/system/mtpulse.service"
CONFIG_DIR="/etc/mtpulse"
CONFIG_FILE="$CONFIG_DIR/mtpulse.conf"
LOG_FILE="/var/log/mtpulse.log"
VERSION="2.1.0"

# Function to display banner
show_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "╔══════════════════════════════════════════════╗"
    echo "║         MTPulse MTProto Proxy                ║"
    echo "║           Version: $VERSION                   ║"
    echo "╚══════════════════════════════════════════════╝"
    echo -e "${RESET}"
    echo -e "${YELLOW}Developer: Parham Pahlevan${RESET}"
    echo -e "${YELLOW}Telegram: @ParhamPahlevan${RESET}"
    echo -e "${YELLOW}GitHub: https://github.com/ParhamPahlevan/MTPulse${RESET}"
    echo -e "${GREEN}----------------------------------------------${RESET}"
}

# Function to draw line
draw_line() {
    echo -e "${GREEN}==============================================${RESET}"
}

# Function to show success message
print_success() {
    echo -e "${GREEN}✅ $1${RESET}"
}

# Function to show error message
print_error() {
    echo -e "${RED}❌ $1${RESET}"
}

# Function to show info message
print_info() {
    echo -e "${CYAN}ℹ️  $1${RESET}"
}

# Function to show warning message
print_warning() {
    echo -e "${YELLOW}⚠️  $1${RESET}"
}

# Function to check root privileges
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root!"
        echo -e "${YELLOW}Please run: sudo bash $0${RESET}"
        exit 1
    fi
}

# Function to check OS compatibility
check_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    else
        print_error "Cannot detect OS!"
        exit 1
    fi
    
    if [[ "$ID" != "ubuntu" && "$ID" != "debian" ]]; then
        print_warning "This script is optimized for Ubuntu/Debian"
        echo -e "${YELLOW}Detected OS: $OS $VER${RESET}"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Function to install prerequisites
install_prerequisites() {
    print_info "Installing prerequisites..."
    
    apt-get update -y
    
    # Install essential packages
    local packages=(
        git
        build-essential
        libssl-dev
        zlib1g-dev
        curl
        wget
        tar
        gzip
        make
        cmake
        gcc
        g++
        jq
        xxd
        net-tools
        lsof
        ufw
    )
    
    for pkg in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $pkg "; then
            echo -n "Installing $pkg... "
            apt-get install -y -qq "$pkg" > /dev/null 2>&1
            print_success "Done"
        fi
    done
}

# Function to compile MTProxy
compile_mtproxy() {
    print_info "Downloading MTProxy source code..."
    
    # Remove old directory if exists
    if [ -d "/tmp/MTProxy" ]; then
        rm -rf /tmp/MTProxy
    fi
    
    # Try different repository sources
    local repo_sources=(
        "https://github.com/TelegramMessenger/MTProxy.git"
        "https://gitlab.com/TelegramMessenger/MTProxy.git"
        "https://github.com/alexbers/mtprotoproxy.git"
    )
    
    local clone_success=false
    for repo in "${repo_sources[@]}"; do
        print_info "Trying: $repo"
        if git clone --depth=1 "$repo" /tmp/MTProxy 2>/dev/null; then
            clone_success=true
            print_success "Repository cloned successfully!"
            break
        fi
    done
    
    if [ "$clone_success" = false ]; then
        print_error "Failed to clone repository!"
        return 1
    fi
    
    cd /tmp/MTProxy || return 1
    
    # Apply PID fix patch
    if [ -f "common/pid.c" ]; then
        sed -i 's/assert (!(p & 0xffff0000));/\/\/ assert (!(p \& 0xffff0000));/g' common/pid.c
        print_success "PID patch applied"
    fi
    
    print_info "Compiling MTProxy..."
    
    # Compile
    if make 2>&1 | tee /tmp/mtproxy_compile.log; then
        if [ -f "objs/bin/mtproto-proxy" ]; then
            # Install binary
            cp objs/bin/mtproto-proxy /usr/local/bin/mtproto-proxy
            chmod +x /usr/local/bin/mtproto-proxy
            print_success "MTProxy compiled and installed successfully!"
            return 0
        fi
    fi
    
    print_error "Compilation failed!"
    echo -e "${YELLOW}Log saved to: /tmp/mtproxy_compile.log${RESET}"
    return 1
}

# Function to download configuration files
download_configs() {
    print_info "Downloading configuration files..."
    
    mkdir -p "$CONFIG_DIR"
    
    # Download proxy-secret
    local secret_sources=(
        "https://core.telegram.org/getProxySecret"
        "https://raw.githubusercontent.com/TelegramMessenger/MTProxy/master/proxy-secret"
    )
    
    for source in "${secret_sources[@]}"; do
        if wget -q --timeout=10 --tries=2 -O "$CONFIG_DIR/proxy-secret" "$source"; then
            print_success "proxy-secret downloaded"
            break
        fi
    done
    
    # Create default if download failed
    if [ ! -f "$CONFIG_DIR/proxy-secret" ]; then
        echo "default" > "$CONFIG_DIR/proxy-secret"
        print_warning "Created default proxy-secret"
    fi
    
    # Download proxy-multi.conf
    local config_sources=(
        "https://core.telegram.org/getProxyConfig"
        "https://raw.githubusercontent.com/TelegramMessenger/MTProxy/master/proxy-multi.conf"
    )
    
    for source in "${config_sources[@]}"; do
        if wget -q --timeout=10 --tries=2 -O "$CONFIG_DIR/proxy-multi.conf" "$source"; then
            print_success "proxy-multi.conf downloaded"
            break
        fi
    done
    
    # Create default if download failed
    if [ ! -f "$CONFIG_DIR/proxy-multi.conf" ]; then
        cat > "$CONFIG_DIR/proxy-multi.conf" << 'EOF'
default 0.0.0.0:443
stat 127.0.0.1:80
syslog
user nobody
workers 2
proxy 0.0.0.0:443 {
    secret 00000000000000000000000000000000
    backlog 16384
    tcp_fastopen
    nat_info
}
EOF
        print_warning "Created default proxy-multi.conf"
    fi
}

# Function to generate random secret
generate_secret() {
    local secret=$(head -c 16 /dev/urandom | xxd -ps)
    echo "$secret"
}

# Function to get public IP
get_public_ip() {
    local ip_services=(
        "https://api.ipify.org"
        "https://icanhazip.com"
        "https://checkip.amazonaws.com"
        "https://ifconfig.me/ip"
    )
    
    for service in "${ip_services[@]}"; do
        local ip=$(curl -s --max-time 5 "$service" 2>/dev/null)
        if [[ -n "$ip" && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$ip"
            return 0
        fi
    done
    
    echo "YOUR_SERVER_IP"
}

# Function to save configuration
save_config() {
    local port=$1
    local secret=$2
    local sponsor_tag=$3
    
    mkdir -p "$CONFIG_DIR"
    
    cat > "$CONFIG_FILE" << EOF
# MTPulse Configuration File
# Generated on: $(date)

PORT=$port
SECRET=$secret
SPONSOR_TAG=${sponsor_tag:-}
INSTALL_DATE=$(date +%Y-%m-%d_%H:%M:%S)
VERSION=$VERSION
EOF
    
    chmod 600 "$CONFIG_FILE"
    print_success "Configuration saved to $CONFIG_FILE"
}

# Function to load configuration
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE" 2>/dev/null
        return 0
    else
        return 1
    fi
}

# Function to create systemd service
create_service() {
    local port=$1
    local secret=$2
    local sponsor_tag=$3
    
    print_info "Creating systemd service..."
    
    # Build execution command
    local exec_command="/usr/local/bin/mtproto-proxy"
    exec_command="$exec_command -u nobody"
    exec_command="$exec_command -H $port"
    exec_command="$exec_command -S $secret"
    
    if [ -n "$sponsor_tag" ]; then
        exec_command="$exec_command -P $sponsor_tag"
    fi
    
    exec_command="$exec_command --aes-pwd $CONFIG_DIR/proxy-secret $CONFIG_DIR/proxy-multi.conf"
    exec_command="$exec_command -M 1"
    
    # Create service file
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=MTPulse MTProto Proxy Service
After=network.target
Wants=network-online.target
StartLimitIntervalSec=500
StartLimitBurst=5

[Service]
Type=simple
User=nobody
Group=nogroup
ExecStart=$exec_command
WorkingDirectory=/tmp
Restart=always
RestartSec=5
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=mtpulse
LimitNOFILE=999999

# Security
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$CONFIG_DIR /tmp

# Resource limits
LimitCORE=infinity
LimitNOFILE=1048576
LimitNPROC=1048576

[Install]
WantedBy=multi-user.target
EOF
    
    # Set appropriate permissions
    chmod 644 "$SERVICE_FILE"
    
    systemctl daemon-reload
    systemctl enable mtpulse > /dev/null 2>&1
    
    print_success "Service created successfully!"
}

# Function to check port availability
check_port() {
    local port=$1
    
    # Check with lsof
    if lsof -i ":$port" > /dev/null 2>&1; then
        print_warning "Port $port is already in use by:"
        lsof -i ":$port" | tail -5
        return 1
    fi
    
    # Check with ss
    if ss -tulpn | grep -q ":$port "; then
        print_warning "Port $port is busy according to ss"
        return 1
    fi
    
    return 0
}

# Main installation function
install_mtpulse() {
    show_banner
    
    print_info "Starting MTPulse installation..."
    draw_line
    
    # Check previous installation
    if [ -f "$CONFIG_FILE" ]; then
        print_warning "MTPulse seems to be already installed!"
        echo -e "${YELLOW}Loading existing configuration...${RESET}"
        load_config
    fi
    
    # Check prerequisites
    check_root
    check_os
    install_prerequisites
    
    # Compile MTProxy
    if ! compile_mtproxy; then
        print_error "Failed to compile MTProxy!"
        echo -e "${YELLOW}Trying to download pre-compiled binary...${RESET}"
        
        # Download pre-compiled binary
        if wget -q -O /usr/local/bin/mtproto-proxy "https://github.com/TelegramMessenger/MTProxy/releases/latest/download/mtproxy-proxy-linux-amd64"; then
            chmod +x /usr/local/bin/mtproto-proxy
            print_success "Pre-compiled binary installed!"
        else
            print_error "Failed to download binary!"
            exit 1
        fi
    fi
    
    # Download configs
    download_configs
    
    # Get user input
    draw_line
    print_info "Proxy Configuration"
    
    # Port
    local port
    if [ -n "$PORT" ]; then
        echo -e "Detected previous port: ${GREEN}$PORT${RESET}"
        read -p "Use same port? (Y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Nn]$ ]]; then
            port=""
        else
            port="$PORT"
        fi
    fi
    
    if [ -z "$port" ]; then
        while true; do
            read -p "Enter port number (default 443): " port
            port=${port:-443}
            
            if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
                # Check port
                if ! check_port "$port"; then
                    print_error "Port $port is busy! Please choose another."
                    continue
                fi
                break
            else
                print_error "Invalid port! Must be between 1-65535"
            fi
        done
    fi
    
    # Secret
    local secret
    if [ -n "$SECRET" ]; then
        echo -e "Detected previous secret"
        read -p "Generate new secret? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            secret=$(generate_secret)
        else
            secret="$SECRET"
        fi
    else
        secret=$(generate_secret)
    fi
    
    # Sponsor tag
    local sponsor_tag=""
    if [ -n "$SPONSOR_TAG" ]; then
        echo -e "Detected sponsor tag: ${GREEN}...${SPONSOR_TAG: -8}${RESET}"
        read -p "Keep current sponsor tag? (Y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Nn]$ ]]; then
            read -p "Enter new sponsor tag (32 hex, empty to skip): " sponsor_tag
        else
            sponsor_tag="$SPONSOR_TAG"
        fi
    else
        echo -e "${YELLOW}Sponsor tag is optional. Get it from @MTProxybot${RESET}"
        read -p "Enter sponsor tag (32 hex, empty to skip): " sponsor_tag
    fi
    
    # Validate sponsor tag
    if [ -n "$sponsor_tag" ]; then
        if [[ ! "$sponsor_tag" =~ ^[a-fA-F0-9]{32}$ ]]; then
            print_error "Invalid sponsor tag! Must be 32 hex characters."
            sponsor_tag=""
        fi
    fi
    
    # Save configuration
    save_config "$port" "$secret" "$sponsor_tag"
    
    # Create service
    create_service "$port" "$secret" "$sponsor_tag"
    
    # Configure firewall
    if command -v ufw > /dev/null 2>&1; then
        ufw allow "$port"/tcp > /dev/null 2>&1
        print_success "Firewall rule added for port $port"
    fi
    
    # Start service
    print_info "Starting proxy service..."
    if systemctl restart mtpulse; then
        print_success "Proxy service started!"
        
        # Check status
        sleep 3
        if systemctl is-active --quiet mtpulse; then
            print_success "Service is running properly!"
        else
            print_warning "Service started but might have issues"
            journalctl -u mtpulse -n 20 --no-pager
        fi
    else
        print_error "Failed to start service!"
        journalctl -u mtpulse -n 20 --no-pager
        print_info "Trying to debug..."
        /usr/local/bin/mtproto-proxy -u nobody -H "$port" -S "$secret" ${sponsor_tag:+-P "$sponsor_tag"} --aes-pwd "$CONFIG_DIR/proxy-secret" "$CONFIG_DIR/proxy-multi.conf" -M 1 --test
    fi
    
    # Display connection info
    draw_line
    print_success "Installation Completed!"
    echo ""
    
    local public_ip=$(get_public_ip)
    
    echo -e "${BOLD}${CYAN}📊 Connection Details:${RESET}"
    echo -e "  ${WHITE}Server IP:${RESET} ${GREEN}$public_ip${RESET}"
    echo -e "  ${WHITE}Port:${RESET} ${GREEN}$port${RESET}"
    echo -e "  ${WHITE}Secret:${RESET} ${GREEN}$secret${RESET}"
    if [ -n "$sponsor_tag" ]; then
        echo -e "  ${WHITE}Sponsor Tag:${RESET} ${GREEN}$sponsor_tag${RESET}"
    fi
    echo ""
    
    echo -e "${BOLD}${CYAN}🔗 Proxy Links:${RESET}"
    echo -e "  ${YELLOW}Standard:${RESET} tg://proxy?server=$public_ip&port=$port&secret=$secret"
    echo -e "  ${YELLOW}With DD:${RESET} tg://proxy?server=$public_ip&port=$port&secret=dd$secret"
    echo ""
    
    echo -e "${BOLD}${CYAN}📝 For MTProto Bot:${RESET}"
    echo -e "  ${WHITE}$public_ip:$port${RESET}"
    echo -e "  ${WHITE}dd$secret${RESET}"
    echo ""
    
    # Save info to file
    cat > "$CONFIG_DIR/proxy-info.txt" << EOF
=========================================
MTPulse Proxy Information
=========================================
Installation Date: $(date)
Server IP: $public_ip
Port: $port
Secret: $secret
Secret with DD: dd$secret
Sponsor Tag: ${sponsor_tag:-Not set}
Proxy Link: tg://proxy?server=$public_ip&port=$port&secret=$secret
Proxy Link (DD): tg://proxy?server=$public_ip&port=$port&secret=dd$secret
=========================================
EOF
    
    print_success "Installation complete! Configuration saved."
    print_info "View config: cat $CONFIG_DIR/proxy-info.txt"
    print_info "Service logs: journalctl -u mtpulse -f"
}

# Function for service management
service_management() {
    while true; do
        clear
        show_banner
        
        echo -e "${BOLD}${CYAN}Service Management${RESET}"
        draw_line
        
        # Show service status
        local status=$(systemctl is-active mtpulse 2>/dev/null)
        if [ "$status" = "active" ]; then
            echo -e "Status: ${GREEN}✅ Running${RESET}"
        elif [ "$status" = "inactive" ]; then
            echo -e "Status: ${RED}❌ Stopped${RESET}"
        elif [ "$status" = "failed" ]; then
            echo -e "Status: ${RED}🔥 Failed${RESET}"
        else
            echo -e "Status: ${YELLOW}⚠️  Not installed${RESET}"
        fi
        
        echo ""
        echo -e "${BOLD}${WHITE}Options:${RESET}"
        echo -e "  1) Start Service"
        echo -e "  2) Stop Service"
        echo -e "  3) Restart Service"
        echo -e "  4) View Service Status"
        echo -e "  5) View Service Logs"
        echo -e "  6) Enable Auto-start"
        echo -e "  7) Disable Auto-start"
        echo -e "  0) Back to Main Menu"
        echo ""
        
        read -p "Select option: " choice
        
        case $choice in
            1)
                systemctl start mtpulse
                print_success "Service started!"
                sleep 2
                ;;
            2)
                systemctl stop mtpulse
                print_success "Service stopped!"
                sleep 2
                ;;
            3)
                systemctl restart mtpulse
                print_success "Service restarted!"
                sleep 2
                ;;
            4)
                clear
                systemctl status mtpulse --no-pager
                echo ""
                read -p "Press Enter to continue..."
                ;;
            5)
                clear
                journalctl -u mtpulse -n 50 --no-pager
                echo ""
                read -p "Press Enter to continue..."
                ;;
            6)
                systemctl enable mtpulse
                print_success "Auto-start enabled!"
                sleep 2
                ;;
            7)
                systemctl disable mtpulse
                print_success "Auto-start disabled!"
                sleep 2
                ;;
            0)
                return
                ;;
            *)
                print_error "Invalid option!"
                sleep 2
                ;;
        esac
    done
}

# Function to add sponsor tag
add_sponsor_tag() {
    clear
    show_banner
    
    echo -e "${BOLD}${CYAN}Add Sponsor Tag${RESET}"
    draw_line
    
    if [ ! -f "$SERVICE_FILE" ]; then
        print_error "MTPulse is not installed!"
        read -p "Press Enter to continue..."
        return
    fi
    
    # Extract current tag
    local current_exec=$(grep "ExecStart=" "$SERVICE_FILE" | cut -d= -f2-)
    local current_tag=""
    
    if [[ "$current_exec" =~ -P\ ([a-f0-9]+) ]]; then
        current_tag="${BASH_REMATCH[1]}"
        echo -e "Current Tag: ${GREEN}$current_tag${RESET}"
        echo ""
        read -p "Do you want to change it? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            return
        fi
    fi
    
    echo ""
    echo -e "${YELLOW}To get a sponsor tag:${RESET}"
    echo -e "1. Open Telegram and go to ${GREEN}@MTProxybot${RESET}"
    echo -e "2. Register your proxy"
    echo -e "3. Bot will give you a 32-character hex tag"
    echo ""
    
    read -p "Enter sponsor tag (32 hex chars, empty to remove): " sponsor_tag
    
    # Validate tag
    if [[ -n "$sponsor_tag" ]]; then
        if [[ ! "$sponsor_tag" =~ ^[a-fA-F0-9]{32}$ ]]; then
            print_error "Invalid tag format! Must be 32 hex characters."
            read -p "Press Enter to continue..."
            return
        fi
    fi
    
    # Update configuration file
    if load_config; then
        save_config "$PORT" "$SECRET" "$sponsor_tag"
    fi
    
    # Rebuild service with new tag
    if [ -n "$PORT" ] && [ -n "$SECRET" ]; then
        create_service "$PORT" "$SECRET" "$sponsor_tag"
        systemctl daemon-reload
        systemctl restart mtpulse
        
        if [[ -n "$sponsor_tag" ]]; then
            print_success "Sponsor tag added successfully!"
        else
            print_success "Sponsor tag removed!"
        fi
    else
        print_error "Cannot update service. Configuration missing."
    fi
    
    sleep 2
}

# Function to show proxy information
show_proxy_info() {
    clear
    show_banner
    
    echo -e "${BOLD}${CYAN}Proxy Information${RESET}"
    draw_line
    
    if [ ! -f "$CONFIG_DIR/proxy-info.txt" ]; then
        print_error "No proxy information found!"
        read -p "Press Enter to continue..."
        return
    fi
    
    cat "$CONFIG_DIR/proxy-info.txt"
    echo ""
    
    # Show current status
    echo -e "${BOLD}${CYAN}Current Status:${RESET}"
    systemctl status mtpulse --no-pager | head -20
    
    echo ""
    read -p "Press Enter to continue..."
}

# Function to rebuild service
rebuild_service() {
    print_info "Rebuilding service from saved configuration..."
    
    if load_config; then
        create_service "$PORT" "$SECRET" "$SPONSOR_TAG"
        systemctl daemon-reload
        
        if systemctl restart mtpulse; then
            print_success "Service rebuilt and restarted successfully!"
        else
            print_error "Failed to restart service!"
        fi
    else
        print_error "No saved configuration found!"
    fi
}

# Function to uninstall MTPulse
uninstall_mtpulse() {
    clear
    show_banner
    
    echo -e "${BOLD}${RED}⚠️  Uninstall MTPulse ⚠️${RESET}"
    draw_line
    
    # Show current installation info
    if [ -f "$CONFIG_FILE" ]; then
        echo -e "${YELLOW}Current installation:${RESET}"
        cat "$CONFIG_FILE"
        echo ""
    fi
    
    read -p "Are you sure you want to uninstall MTPulse? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        return
    fi
    
    print_info "Stopping service..."
    systemctl stop mtpulse 2>/dev/null
    systemctl disable mtpulse 2>/dev/null
    
    print_info "Removing firewall rule..."
    if command -v ufw > /dev/null 2>&1 && [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE" 2>/dev/null
        ufw delete allow "$PORT"/tcp 2>/dev/null
    fi
    
    print_info "Removing files..."
    rm -f "$SERVICE_FILE"
    rm -f /usr/local/bin/mtproto-proxy 2>/dev/null
    
    # Ask about keeping config files
    read -p "Keep configuration files? (Y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        rm -rf "$CONFIG_DIR"
        rm -rf "$INSTALL_DIR"
        print_success "All files removed!"
    else
        print_info "Configuration kept in $CONFIG_DIR"
    fi
    
    print_info "Reloading systemd..."
    systemctl daemon-reload
    
    print_success "MTPulse has been uninstalled!"
    echo ""
    read -p "Press Enter to continue..."
}

# Main menu function
main_menu() {
    while true; do
        clear
        show_banner
        
        # Show status
        local status=$(systemctl is-active mtpulse 2>/dev/null)
        if [ "$status" = "active" ]; then
            echo -e "Proxy Status: ${GREEN}✅ Active${RESET}"
        else
            echo -e "Proxy Status: ${RED}❌ Inactive${RESET}"
        fi
        
        echo ""
        echo -e "${BOLD}${CYAN}Main Menu${RESET}"
        draw_line
        
        echo -e "${BOLD}${WHITE}Options:${RESET}"
        echo -e "  1) 📥 Install MTPulse"
        echo -e "  2) ⚙️  Service Management"
        echo -e "  3) 🏷️  Add Sponsor Tag"
        echo -e "  4) 📊 View Proxy Info"
        echo -e "  5) 🔧 Rebuild Service"
        echo -e "  6) 🗑️  Uninstall MTPulse"
        echo -e "  0) 🚪 Exit"
        echo ""
        
        read -p "Select option: " choice
        
        case $choice in
            1)
                install_mtpulse
                read -p "Press Enter to continue..."
                ;;
            2)
                service_management
                ;;
            3)
                add_sponsor_tag
                ;;
            4)
                show_proxy_info
                ;;
            5)
                rebuild_service
                read -p "Press Enter to continue..."
                ;;
            6)
                uninstall_mtpulse
                ;;
            0)
                echo ""
                print_success "Goodbye!"
                exit 0
                ;;
            *)
                print_error "Invalid option!"
                sleep 2
                ;;
        esac
    done
}

# Help function
show_help() {
    echo -e "${BOLD}${CYAN}MTPulse - MTProto Proxy Installer${RESET}"
    echo ""
    echo -e "${BOLD}Usage:${RESET}"
    echo "  ./mtpulse.sh           # Interactive menu"
    echo "  ./mtpulse.sh install   # Auto install"
    echo "  ./mtpulse.sh status    # Check status"
    echo "  ./mtpulse.sh rebuild   # Rebuild service"
    echo "  ./mtpulse.sh uninstall # Uninstall"
    echo ""
    echo -e "${BOLD}Options:${RESET}"
    echo "  install    - Install MTPulse with default settings"
    echo "  status     - Check proxy status"
    echo "  rebuild    - Rebuild service from saved config"
    echo "  uninstall  - Remove MTPulse completely"
    echo "  help       - Show this help message"
    echo ""
}

# Quick install function
quick_install() {
    check_root
    show_banner
    print_info "Starting quick installation..."
    install_mtpulse
}

# Status check function
check_status() {
    if [ -f "$SERVICE_FILE" ]; then
        systemctl status mtpulse --no-pager
        echo ""
        echo -e "${BOLD}${CYAN}Configuration:${RESET}"
        if [ -f "$CONFIG_FILE" ]; then
            cat "$CONFIG_FILE"
        else
            echo "No configuration found"
        fi
    else
        print_error "MTPulse is not installed!"
    fi
}

# Script entry point
if [ $# -eq 0 ]; then
    # Interactive mode
    main_menu
else
    # Command mode
    case $1 in
        "install")
            quick_install
            ;;
        "status")
            check_status
            ;;
        "uninstall")
            check_root
            uninstall_mtpulse
            ;;
        "rebuild")
            check_root
            rebuild_service
            ;;
        "help"|"-h"|"--help")
            show_help
            ;;
        *)
            print_error "Unknown command: $1"
            show_help
            exit 1
            ;;
    esac
fi
