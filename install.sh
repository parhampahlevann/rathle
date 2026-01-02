#!/bin/bash

# ============================================
# MTPulse - MTProto Proxy Installer
# Version: 2.0.0
# Author: ErfanXRay
# Telegram: @Erfan_XRay
# GitHub: https://github.com/Erfan-XRay/MTPulse
# ============================================

# رنگ‌های ترمینال
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'
BOLD='\033[1m'
RESET='\033[0m'

# متغیرهای جهانی
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/usr/local/mtpulse"
SERVICE_FILE="/etc/systemd/system/mtpulse.service"
CONFIG_DIR="/etc/mtpulse"
LOG_FILE="/var/log/mtpulse.log"
VERSION="2.0.0"

# تابع نمایش بنر
show_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "╔══════════════════════════════════════════════╗"
    echo "║         MTPulse MTProto Proxy                ║"
    echo "║           Version: $VERSION                   ║"
    echo "╚══════════════════════════════════════════════╝"
    echo -e "${RESET}"
    echo -e "${YELLOW}Developer: ErfanXRay${RESET}"
    echo -e "${YELLOW}Telegram: @Erfan_XRay${RESET}"
    echo -e "${YELLOW}GitHub: https://github.com/Erfan-XRay/MTPulse${RESET}"
    echo -e "${GREEN}----------------------------------------------${RESET}"
}

# تابع نمایش خط
draw_line() {
    echo -e "${GREEN}==============================================${RESET}"
}

# تابع نمایش پیام موفقیت
print_success() {
    echo -e "${GREEN}✅ $1${RESET}"
}

# تابع نمایش پیام خطا
print_error() {
    echo -e "${RED}❌ $1${RESET}"
}

# تابع نمایش پیام اطلاعات
print_info() {
    echo -e "${CYAN}ℹ️  $1${RESET}"
}

# تابع نمایش پیام هشدار
print_warning() {
    echo -e "${YELLOW}⚠️  $1${RESET}"
}

# تابع بررسی روت بودن
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root!"
        echo -e "${YELLOW}Please run: sudo bash $0${RESET}"
        exit 1
    fi
}

# تابع بررسی سیستم عامل
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

# تابع نصب پیش‌نیازها
install_prerequisites() {
    print_info "Installing prerequisites..."
    
    apt-get update -y
    
    # نصب بسته‌های ضروری
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
    )
    
    for pkg in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $pkg "; then
            echo -n "Installing $pkg... "
            apt-get install -y -qq "$pkg" > /dev/null 2>&1
            print_success "Done"
        fi
    done
}

# تابع دانلود و کامپایل MTProxy
compile_mtproxy() {
    print_info "Downloading MTProxy source code..."
    
    # حذف پوشه قدیمی اگر وجود دارد
    if [ -d "/tmp/MTProxy" ]; then
        rm -rf /tmp/MTProxy
    fi
    
    # تلاش برای کلون از منابع مختلف
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
    
    # اعمال پچ برای رفع مشکل PID
    if [ -f "common/pid.c" ]; then
        sed -i 's/assert (!(p & 0xffff0000));/\/\/ assert (!(p \& 0xffff0000));/g' common/pid.c
        print_success "PID patch applied"
    fi
    
    print_info "Compiling MTProxy..."
    
    # کامپایل
    if make 2>&1 | tee /tmp/mtproxy_compile.log; then
        if [ -f "objs/bin/mtproto-proxy" ]; then
            # نصب باینری
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

# تابع دانلود فایل‌های کانفیگ
download_configs() {
    print_info "Downloading configuration files..."
    
    mkdir -p "$CONFIG_DIR"
    
    # دانلود proxy-secret
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
    
    # اگر دانلود نشد، یک فایل پیش‌فرض ایجاد کن
    if [ ! -f "$CONFIG_DIR/proxy-secret" ]; then
        echo "default" > "$CONFIG_DIR/proxy-secret"
        print_warning "Created default proxy-secret"
    fi
    
    # دانلود proxy-multi.conf
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
    
    # اگر دانلود نشد، یک فایل پیش‌فرض ایجاد کن
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

# تابع تولید سکرت رندوم
generate_secret() {
    local secret=$(head -c 16 /dev/urandom | xxd -ps)
    echo "$secret"
}

# تابع دریافت IP عمومی
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

# تابع ایجاد سرویس systemd
create_service() {
    local port=$1
    local secret=$2
    
    print_info "Creating systemd service..."
    
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=MTPulse MTProto Proxy Service
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=nobody
Group=nogroup
ExecStart=/usr/local/bin/mtproto-proxy -u nobody -p 8888 -H $port -S $secret --aes-pwd $CONFIG_DIR/proxy-secret $CONFIG_DIR/proxy-multi.conf -M 1
Restart=on-failure
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
ReadWritePaths=$CONFIG_DIR

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable mtpulse > /dev/null 2>&1
    
    print_success "Service created successfully!"
}

# تابع نصب اصلی
install_mtpulse() {
    show_banner
    
    print_info "Starting MTPulse installation..."
    draw_line
    
    # بررسی پیش‌نیازها
    check_root
    check_os
    install_prerequisites
    
    # کامپایل MTProxy
    if ! compile_mtproxy; then
        print_error "Failed to compile MTProxy!"
        echo -e "${YELLOW}Trying to download pre-compiled binary...${RESET}"
        
        # دانلود باینری از پیش کامپایل شده
        if wget -q -O /usr/local/bin/mtproto-proxy "https://github.com/TelegramMessenger/MTProxy/releases/latest/download/mtproxy-proxy-linux-amd64"; then
            chmod +x /usr/local/bin/mtproto-proxy
            print_success "Pre-compiled binary installed!"
        else
            print_error "Failed to download binary!"
            exit 1
        fi
    fi
    
    # دانلود کانفیگ‌ها
    download_configs
    
    # دریافت اطلاعات از کاربر
    draw_line
    print_info "Proxy Configuration"
    
    # پورت
    local port
    while true; do
        read -p "Enter port number (default 443): " port
        port=${port:-443}
        
        if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
            break
        else
            print_error "Invalid port! Must be between 1-65535"
        fi
    done
    
    # بررسی اینکه پورت استفاده نشده باشد
    if lsof -i ":$port" > /dev/null 2>&1; then
        print_warning "Port $port is already in use!"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    # تولید سکرت
    local secret=$(generate_secret)
    
    # ایجاد سرویس
    create_service "$port" "$secret"
    
    # شروع سرویس
    print_info "Starting proxy service..."
    if systemctl start mtpulse; then
        print_success "Proxy service started!"
    else
        print_error "Failed to start service!"
        journalctl -u mtpulse -n 20 --no-pager
    fi
    
    # نمایش اطلاعات
    draw_line
    print_success "Installation Completed!"
    echo ""
    
    local public_ip=$(get_public_ip)
    
    echo -e "${BOLD}${CYAN}📊 Connection Details:${RESET}"
    echo -e "  ${WHITE}Server IP:${RESET} ${GREEN}$public_ip${RESET}"
    echo -e "  ${WHITE}Port:${RESET} ${GREEN}$port${RESET}"
    echo -e "  ${WHITE}Secret:${RESET} ${GREEN}$secret${RESET}"
    echo ""
    
    echo -e "${BOLD}${CYAN}🔗 Proxy Links:${RESET}"
    echo -e "  ${YELLOW}Standard:${RESET} tg://proxy?server=$public_ip&port=$port&secret=$secret"
    echo -e "  ${YELLOW}With DD:${RESET} tg://proxy?server=$public_ip&port=$port&secret=dd$secret"
    echo ""
    
    echo -e "${BOLD}${CYAN}📝 For MTProto Bot:${RESET}"
    echo -e "  ${WHITE}$public_ip:$port${RESET}"
    echo -e "  ${WHITE}dd$secret${RESET}"
    echo ""
    
    echo -e "${BOLD}${GREEN}✅ Installation complete!${RESET}"
    echo -e "${YELLOW}You can now connect to your MTProto proxy.${RESET}"
    echo ""
    
    # ذخیره اطلاعات در فایل
    cat > "$CONFIG_DIR/proxy-info.txt" << EOF
=========================================
MTPulse Proxy Information
=========================================
Installation Date: $(date)
Server IP: $public_ip
Port: $port
Secret: $secret
Secret with DD: dd$secret
Proxy Link: tg://proxy?server=$public_ip&port=$port&secret=$secret
Proxy Link (DD): tg://proxy?server=$public_ip&port=$port&secret=dd$secret
=========================================
EOF
    
    print_info "Configuration saved to: $CONFIG_DIR/proxy-info.txt"
}

# تابع مدیریت سرویس
service_management() {
    while true; do
        clear
        show_banner
        
        echo -e "${BOLD}${CYAN}Service Management${RESET}"
        draw_line
        
        # نمایش وضعیت سرویس
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

# تابع اضافه کردن تگ اسپانسر
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
    
    # استخراج تگ فعلی
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
    
    # اعتبارسنجی تگ
    if [[ -n "$sponsor_tag" ]]; then
        if [[ ! "$sponsor_tag" =~ ^[a-fA-F0-9]{32}$ ]]; then
            print_error "Invalid tag format! Must be 32 hex characters."
            read -p "Press Enter to continue..."
            return
        fi
    fi
    
    # حذف تگ قبلی از دستور
    local new_exec=$(echo "$current_exec" | sed -E 's/ -P [a-f0-9]+//')
    
    # اضافه کردن تگ جدید
    if [[ -n "$sponsor_tag" ]]; then
        new_exec="$new_exec -P $sponsor_tag"
    fi
    
    # آپدیت فایل سرویس
    sed -i "s|^ExecStart=.*|ExecStart=$new_exec|" "$SERVICE_FILE"
    
    systemctl daemon-reload
    systemctl restart mtpulse
    
    if [[ -n "$sponsor_tag" ]]; then
        print_success "Sponsor tag added successfully!"
    else
        print_success "Sponsor tag removed!"
    fi
    
    sleep 2
}

# تابع نمایش اطلاعات پروکسی
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
    
    # نمایش وضعیت فعلی
    echo -e "${BOLD}${CYAN}Current Status:${RESET}"
    systemctl status mtpulse --no-pager | head -20
    
    echo ""
    read -p "Press Enter to continue..."
}

# تابع حذف نصب
uninstall_mtpulse() {
    clear
    show_banner
    
    echo -e "${BOLD}${RED}⚠️  Uninstall MTPulse ⚠️${RESET}"
    draw_line
    
    read -p "Are you sure you want to uninstall MTPulse? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        return
    fi
    
    print_info "Stopping service..."
    systemctl stop mtpulse 2>/dev/null
    systemctl disable mtpulse 2>/dev/null
    
    print_info "Removing files..."
    rm -f "$SERVICE_FILE"
    rm -f /usr/local/bin/mtproto-proxy
    rm -rf "$CONFIG_DIR"
    rm -rf "$INSTALL_DIR"
    
    print_info "Reloading systemd..."
    systemctl daemon-reload
    
    print_success "MTPulse has been completely uninstalled!"
    echo ""
    read -p "Press Enter to continue..."
}

# تابع نمایش منوی اصلی
main_menu() {
    while true; do
        clear
        show_banner
        
        # نمایش وضعیت
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
        echo -e "  5) 🗑️  Uninstall MTPulse"
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

# تابع نمایش کمک
show_help() {
    echo -e "${BOLD}${CYAN}MTPulse - MTProto Proxy Installer${RESET}"
    echo ""
    echo -e "${BOLD}Usage:${RESET}"
    echo "  ./mtpulse-install.sh           # Interactive menu"
    echo "  ./mtpulse-install.sh install   # Auto install"
    echo "  ./mtpulse-install.sh status    # Check status"
    echo "  ./mtpulse-install.sh uninstall # Uninstall"
    echo ""
    echo -e "${BOLD}Options:${RESET}"
    echo "  install    - Install MTPulse with default settings"
    echo "  status     - Check proxy status"
    echo "  uninstall  - Remove MTPulse completely"
    echo "  help       - Show this help message"
    echo ""
}

# تابع نصب سریع
quick_install() {
    check_root
    show_banner
    print_info "Starting quick installation..."
    install_mtpulse
}

# تابع بررسی وضعیت
check_status() {
    if [ -f "$SERVICE_FILE" ]; then
        systemctl status mtpulse --no-pager
    else
        print_error "MTPulse is not installed!"
    fi
}

# نقطه شروع اسکریپت
if [ $# -eq 0 ]; then
    # حالت تعاملی
    main_menu
else
    # حالت دستوری
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
