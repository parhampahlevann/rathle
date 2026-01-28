#!/usr/bin/env bash
set -e

### ===== Colors =====
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

### ===== FUNCTIONS =====
show_menu() {
    clear
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════╗"
    echo "║     MTG Proxy Manager (Iran Stable)      ║"
    echo "╠══════════════════════════════════════════╣"
    echo "║  1. Install/Update MTG Proxy             ║"
    echo "║  2. Change Port                          ║"
    echo "║  3. Show Connection Info                 ║"
    echo "║  4. Restart Service                      ║"
    echo "║  5. Stop Service                         ║"
    echo "║  6. View Logs                            ║"
    echo "║  7. Uninstall MTG Proxy                  ║"
    echo "║  8. Enable/Disable BBR Optimizations     ║"
    echo "║  0. Exit                                 ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"
}

check_root() {
    [[ $EUID -ne 0 ]] && { 
        echo -e "${RED}Error: Run as root (use sudo)${NC}" 
        exit 1
    }
}

install_dependencies() {
    echo -e "${YELLOW}[*] Updating system...${NC}"
    apt update -y
    
    echo -e "${YELLOW}[*] Installing dependencies...${NC}"
    apt install -y curl jq ca-certificates xxd net-tools
}

configure_bbr() {
    echo -e "${YELLOW}[*] Configuring BBR and network optimizations...${NC}"
    
    cat > /etc/sysctl.d/99-mtg-iran.conf <<'EOF'
# BBR TCP Congestion Control
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3

# Network Performance
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_rfc1337 = 1

# Connection Limits
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 65535
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_synack_retries = 2

# Timeouts
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_syn_retries = 3

# Memory
net.ipv4.tcp_mem = 10240 87380 134217728
net.ipv4.udp_mem = 10240 87380 134217728

# IPv4 Settings
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
EOF
    
    sysctl -p /etc/sysctl.d/99-mtg-iran.conf >/dev/null 2>&1
    echo -e "${GREEN}[+] BBR optimization enabled${NC}"
}

disable_bbr() {
    echo -e "${YELLOW}[*] Disabling BBR optimizations...${NC}"
    rm -f /etc/sysctl.d/99-mtg-iran.conf
    sysctl -p /etc/sysctl.conf >/dev/null 2>&1
    echo -e "${GREEN}[+] BBR optimization disabled${NC}"
}

download_mtg() {
    BIN="/usr/local/bin/mtg"
    ARCH=$(uname -m)
    
    case "$ARCH" in
        x86_64) ARCH_TYPE="linux-amd64" ;;
        aarch64|arm64) ARCH_TYPE="linux-arm64" ;;
        armv7l) ARCH_TYPE="linux-armv7" ;;
        *) 
            echo -e "${RED}Error: Unsupported architecture: $ARCH${NC}"
            exit 1
            ;;
    esac
    
    echo -e "${YELLOW}[*] Detected architecture: $ARCH ($ARCH_TYPE)${NC}"
    
    # Get latest version
    LATEST_URL=$(curl -s https://api.github.com/repos/9seconds/mtg/releases/latest | grep -o "https://.*mtg-${ARCH_TYPE}" | head -1)
    
    if [[ -z "$LATEST_URL" ]]; then
        LATEST_URL="https://github.com/9seconds/mtg/releases/latest/download/mtg-${ARCH_TYPE}"
    fi
    
    echo -e "${YELLOW}[*] Downloading MTG from: $LATEST_URL${NC}"
    curl -L -f -s -S "$LATEST_URL" -o "$BIN"
    
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}Error: Download failed${NC}"
        exit 1
    fi
    
    chmod +x "$BIN"
    
    # Verify binary
    if "$BIN" --version >/dev/null 2>&1; then
        echo -e "${GREEN}[+] MTG installed successfully${NC}"
    else
        echo -e "${RED}Error: Binary verification failed${NC}"
        exit 1
    fi
}

generate_secret() {
    # Generate secure random secret
    SECRET=$(head -c 32 /dev/urandom | base64 | tr -d '+/=' | head -c 32)
    echo "dd$SECRET"
}

setup_config() {
    CONF_DIR="/etc/mtg"
    CONF="$CONF_DIR/config.toml"
    PORT=$1
    
    mkdir -p "$CONF_DIR"
    
    # Check if config exists and preserve secret if changing port
    OLD_SECRET=""
    if [[ -f "$CONF" ]]; then
        OLD_SECRET=$(grep 'secret =' "$CONF" | cut -d '"' -f 2)
    fi
    
    if [[ -z "$OLD_SECRET" ]]; then
        OLD_SECRET=$(generate_secret)
    fi
    
    cat > "$CONF" <<EOF
bind = "0.0.0.0:$PORT"
secret = "$OLD_SECRET"
workers = 0
stats-bind = "127.0.0.1:8080"
dd-only = true
clock-skew = 1s
EOF
    
    echo -e "${GREEN}[+] Configuration saved to $CONF${NC}"
    echo "$OLD_SECRET"
}

setup_service() {
    SERVICE="/etc/systemd/system/mtg.service"
    BIN="/usr/local/bin/mtg"
    CONF="/etc/mtg/config.toml"
    
    cat > "$SERVICE" <<EOF
[Unit]
Description=MTG MTProto Proxy (Iran Stable)
After=network-online.target
Wants=network-online.target
Documentation=https://github.com/9seconds/mtg

[Service]
Type=simple
User=root
WorkingDirectory=/etc/mtg
ExecStart=$BIN run $CONF
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=3
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE

# Security
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=mtg

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable mtg --now
    
    # Wait for service to start
    sleep 2
    
    if systemctl is-active --quiet mtg; then
        echo -e "${GREEN}[+] MTG service started successfully${NC}"
    else
        echo -e "${RED}[!] Service failed to start. Check: journalctl -u mtg${NC}"
        journalctl -u mtg -n 20 --no-pager
    fi
}

show_info() {
    CONF="/etc/mtg/config.toml"
    
    if [[ ! -f "$CONF" ]]; then
        echo -e "${RED}Error: MTG is not installed${NC}"
        return
    fi
    
    SECRET=$(grep 'secret =' "$CONF" | cut -d '"' -f 2)
    PORT=$(grep 'bind =' "$CONF" | grep -oE '[0-9]+' | tail -1)
    
    # Try multiple IP services
    IP_SERVICES=(
        "https://api.ipify.org"
        "https://icanhazip.com"
        "https://ifconfig.me/ip"
        "https://checkip.amazonaws.com"
    )
    
    IP=""
    for service in "${IP_SERVICES[@]}"; do
        IP=$(curl -s -4 --connect-timeout 3 "$service" 2>/dev/null)
        [[ -n "$IP" && "$IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && break
    done
    
    [[ -z "$IP" ]] && IP="YOUR_SERVER_IP"
    
    echo ""
    echo -e "${BLUE}══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}✅ MTG Proxy Information${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════════════════${NC}"
    echo -e "Server IP : ${YELLOW}$IP${NC}"
    echo -e "Port      : ${YELLOW}${PORT:-443}${NC}"
    echo -e "Secret    : ${YELLOW}$SECRET${NC}"
    echo ""
    echo -e "${GREEN}📱 Quick Connection Links:${NC}"
    echo -e "${BLUE}Telegram:${NC}"
    echo "tg://proxy?server=$IP&port=${PORT:-443}&secret=$SECRET"
    echo ""
    echo -e "${BLUE}MTProto Link:${NC}"
    echo "https://t.me/proxy?server=$IP&port=${PORT:-443}&secret=$SECRET"
    echo ""
    echo -e "${BLUE}Raw Config:${NC}"
    echo "server: $IP"
    echo "port: ${PORT:-443}"
    echo "secret: $SECRET"
    echo -e "${BLUE}══════════════════════════════════════════════════════════${NC}"
    
    # Show firewall status
    if command -v ufw >/dev/null; then
        echo -e "\n${YELLOW}Firewall Status:${NC}"
        ufw status | grep -w "$PORT" || echo "Port $PORT not in UFW rules"
    fi
    
    # Show service status
    echo -e "\n${YELLOW}Service Status:${NC}"
    systemctl status mtg --no-pager | head -10
}

change_port() {
    read -p "Enter new port [443]: " NEW_PORT
    NEW_PORT=${NEW_PORT:-443}
    
    # Validate port
    if ! [[ "$NEW_PORT" =~ ^[0-9]+$ ]] || [ "$NEW_PORT" -lt 1 ] || [ "$NEW_PORT" -gt 65535 ]; then
        echo -e "${RED}Error: Invalid port number${NC}"
        return
    fi
    
    systemctl stop mtg 2>/dev/null
    
    SECRET=$(setup_config "$NEW_PORT")
    
    systemctl start mtg
    
    echo -e "${GREEN}[+] Port changed to $NEW_PORT${NC}"
    show_info
}

uninstall_mtg() {
    echo -e "${YELLOW}[!] This will completely remove MTG Proxy${NC}"
    read -p "Are you sure? (y/N): " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Uninstall cancelled."
        return
    fi
    
    systemctl stop mtg 2>/dev/null
    systemctl disable mtg 2>/dev/null
    rm -f /etc/systemd/system/mtg.service
    rm -f /usr/local/bin/mtg
    rm -rf /etc/mtg
    rm -f /etc/sysctl.d/99-mtg-iran.conf
    systemctl daemon-reload
    
    echo -e "${GREEN}[+] MTG Proxy completely removed${NC}"
}

### ===== MAIN INSTALLATION =====
install_mtg() {
    check_root
    
    echo -e "${BLUE}╔══════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║      MTG Proxy Installation              ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════╝${NC}"
    
    # Get port
    read -p "Enter port number [443]: " PORT
    PORT=${PORT:-443}
    
    # Validate port
    if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
        echo -e "${RED}Error: Invalid port number${NC}"
        exit 1
    fi
    
    # Check if port is in use
    if netstat -tuln | grep -q ":$PORT "; then
        echo -e "${RED}Error: Port $PORT is already in use${NC}"
        exit 1
    fi
    
    install_dependencies
    configure_bbr
    download_mtg
    SECRET=$(setup_config "$PORT")
    setup_service
    
    show_info
    
    echo ""
    echo -e "${GREEN}✅ Installation Complete!${NC}"
    echo -e "Use this script again to manage your proxy:"
    echo -e "${YELLOW}sudo bash $(basename "$0")${NC}"
}

### ===== MAIN MENU LOOP =====
main() {
    check_root
    
    while true; do
        show_menu
        read -p "Select option [0-8]: " choice
        
        case $choice in
            1)
                install_mtg
                ;;
            2)
                change_port
                ;;
            3)
                show_info
                ;;
            4)
                systemctl restart mtg
                echo -e "${GREEN}[+] Service restarted${NC}"
                sleep 2
                systemctl status mtg --no-pager | head -5
                ;;
            5)
                systemctl stop mtg
                echo -e "${YELLOW}[!] Service stopped${NC}"
                ;;
            6)
                journalctl -u mtg -f --no-pager
                ;;
            7)
                uninstall_mtg
                ;;
            8)
                echo -e "${YELLOW}[1] Enable BBR Optimizations${NC}"
                echo -e "${YELLOW}[2] Disable BBR Optimizations${NC}"
                read -p "Choose [1-2]: " bbr_choice
                case $bbr_choice in
                    1) configure_bbr ;;
                    2) disable_bbr ;;
                    *) echo "Invalid choice" ;;
                esac
                ;;
            0)
                echo "Goodbye!"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option${NC}"
                ;;
        esac
        
        echo ""
        read -p "Press Enter to continue..."
    done
}

# If script called with install parameter
if [[ "$1" == "install" ]]; then
    install_mtg
    exit 0
fi

# Start menu
main
