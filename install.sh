#!/usr/bin/env bash
set -e

### ===== Colors =====
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

### ===== CONFIG =====
BIN="/usr/local/bin/mtg"
CONF_DIR="/etc/mtg"
CONF="$CONF_DIR/config.toml"
SERVICE="/etc/systemd/system/mtg.service"
LOG_FILE="/var/log/mtg.log"

### ===== FUNCTIONS =====
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: Run with sudo${NC}"
        exit 1
    fi
}

show_banner() {
    clear
    echo -e "${BLUE}"
    echo "┌──────────────────────────────────────────┐"
    echo "│         MTG Proxy Installer              │"
    echo "└──────────────────────────────────────────┘"
    echo -e "${NC}"
}

check_port() {
    local port=$1
    if command -v ss &> /dev/null; then
        if ss -tuln | grep -q ":$port "; then
            echo -e "${RED}Error: Port $port is in use!${NC}"
            echo "Ports in use:"
            ss -tuln | grep ":$port" || true
            return 1
        fi
    elif command -v netstat &> /dev/null; then
        if netstat -tuln | grep -q ":$port "; then
            echo -e "${RED}Error: Port $port is in use!${NC}"
            return 1
        fi
    fi
    return 0
}

get_public_ip() {
    echo -e "${YELLOW}[*] Getting public IP...${NC}"
    local ip_services=(
        "https://api.ipify.org"
        "https://icanhazip.com"
        "https://ifconfig.me/ip"
        "https://checkip.amazonaws.com"
        "https://ipinfo.io/ip"
    )
    
    for service in "${ip_services[@]}"; do
        echo -e "${YELLOW}   Trying: $service${NC}"
        IP=$(timeout 5 curl -s -4 "$service" 2>/dev/null | tr -d '\n')
        if [[ -n "$IP" && "$IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            echo -e "${GREEN}   ✓ Success: $IP${NC}"
            return 0
        fi
        sleep 1
    done
    
    IP="YOUR_SERVER_IP"
    echo -e "${RED}   ⚠️ Could not get public IP${NC}"
    return 1
}

install_deps() {
    echo -e "${YELLOW}[*] Updating system...${NC}"
    apt-get update -y
    
    echo -e "${YELLOW}[*] Installing dependencies...${NC}"
    apt-get install -y curl wget net-tools iproute2 jq ca-certificates \
                       xxd build-essential pkg-config libssl-dev \
                       software-properties-common ufw 2>/dev/null || true
}

configure_firewall() {
    local port=$1
    echo -e "${YELLOW}[*] Configuring firewall...${NC}"
    
    # Try UFW first
    if command -v ufw &> /dev/null; then
        ufw --force enable 2>/dev/null || true
        ufw allow "$port"/tcp
        ufw allow 22/tcp  # SSH
        echo -e "${GREEN}[+] Firewall configured${NC}"
    elif command -v iptables &> /dev/null; then
        echo -e "${YELLOW}[!] Using iptables${NC}"
        iptables -I INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || true
        iptables -I INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || true
        # Save rules if iptables-persistent is installed
        if command -v iptables-save &> /dev/null && [ -d /etc/iptables ]; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        fi
    else
        echo -e "${YELLOW}[!] No firewall manager found, skipping${NC}"
    fi
}

configure_bbr() {
    echo -e "${YELLOW}[*] Enabling BBR...${NC}"
    
    cat > /etc/sysctl.d/60-mtg.conf <<'EOF'
# BBR TCP
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# Performance
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192

# Connection settings
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_slow_start_after_idle = 0

# Timeouts
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 60
EOF
    
    sysctl -p /etc/sysctl.d/60-mtg.conf 2>/dev/null
    echo -e "${GREEN}[+] BBR enabled${NC}"
}

download_mtg() {
    echo -e "${YELLOW}[*] Downloading MTG...${NC}"
    
    # Detect architecture
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) ARCH_TYPE="amd64" ;;
        aarch64|arm64) ARCH_TYPE="arm64" ;;
        armv7l|armv8l) ARCH_TYPE="armv7" ;;
        *) 
            echo -e "${RED}Error: Architecture $ARCH not supported${NC}"
            exit 1
            ;;
    esac
    
    # Get latest version from GitHub
    echo -e "${YELLOW}   Fetching latest version...${NC}"
    LATEST_URL=$(curl -s https://api.github.com/repos/9seconds/mtg/releases/latest | grep -o "https://.*mtg-linux-${ARCH_TYPE}" | head -1)
    
    if [[ -z "$LATEST_URL" ]]; then
        LATEST_URL="https://github.com/9seconds/mtg/releases/latest/download/mtg-linux-${ARCH_TYPE}"
    fi
    
    echo -e "${YELLOW}   Architecture: $ARCH_TYPE${NC}"
    echo -e "${YELLOW}   Download URL: $LATEST_URL${NC}"
    
    # Download with retry
    for i in {1..3}; do
        echo -e "${YELLOW}   Attempt $i/3...${NC}"
        if wget -q --timeout=30 -O "$BIN" "$LATEST_URL"; then
            break
        fi
        sleep 2
    done
    
    if [[ ! -f "$BIN" ]]; then
        echo -e "${RED}Error: Download failed${NC}"
        exit 1
    fi
    
    # Make executable
    chmod +x "$BIN"
    
    # Verify file
    if [[ ! -s "$BIN" ]]; then
        echo -e "${RED}Error: Binary file is empty${NC}"
        exit 1
    fi
    
    # Test binary
    if "$BIN" --version &>/dev/null || "$BIN" -h &>/dev/null; then
        echo -e "${GREEN}[+] MTG downloaded successfully${NC}"
    else
        echo -e "${YELLOW}[!] Binary test failed, but continuing...${NC}"
    fi
}

generate_config() {
    local port=$1
    echo -e "${YELLOW}[*] Generating configuration...${NC}"
    
    # Create directory
    mkdir -p "$CONF_DIR"
    
    # Generate strong secret
    if command -v openssl &> /dev/null; then
        SECRET=$(openssl rand -hex 16)
    else
        SECRET=$(head -c 32 /dev/urandom | base64 | tr -d '+/=' | head -c 32)
    fi
    FULL_SECRET="ee${SECRET}"  # Using ee for new protocol
    
    # Create config
    cat > "$CONF" <<EOF
# MTG Configuration
bind = "0.0.0.0:$port"
secret = "$FULL_SECRET"
workers = 2
stats-bind = "127.0.0.1:8080"
dd-only = true
clock-skew = 2s
tcp-fast-open = true
tcp-buffer = 64kb
EOF
    
    echo -e "${GREEN}[+] Configuration generated${NC}"
    echo "$FULL_SECRET"
}

create_service() {
    echo -e "${YELLOW}[*] Creating Systemd service...${NC}"
    
    # Stop existing service
    systemctl stop mtg 2>/dev/null || true
    
    # Create service file
    cat > "$SERVICE" <<EOF
[Unit]
Description=MTG MTProto Proxy
After=network.target network-online.target
Wants=network-online.target
StartLimitIntervalSec=500
StartLimitBurst=5

[Service]
Type=simple
User=root
Group=root
ExecStart=$BIN run $CONF
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
TimeoutSec=30
StandardOutput=append:$LOG_FILE
StandardError=append:$LOG_FILE
SyslogIdentifier=mtg
LimitNOFILE=65535

# Security
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
    
    # Create log file
    touch "$LOG_FILE" 2>/dev/null || true
    chmod 644 "$LOG_FILE" 2>/dev/null || true
    
    # Reload systemd
    systemctl daemon-reload
    systemctl enable mtg
    
    echo -e "${GREEN}[+] Service created${NC}"
}

start_service() {
    echo -e "${YELLOW}[*] Starting service...${NC}"
    
    # Stop if running
    systemctl stop mtg 2>/dev/null || true
    
    # Wait for port release
    sleep 2
    
    # Start service
    if ! systemctl start mtg; then
        echo -e "${RED}[!] Failed to start service${NC}"
        journalctl -u mtg -n 20 --no-pager
        return 1
    fi
    
    echo -e "${GREEN}[+] Service started${NC}"
    
    # Check status
    sleep 3
    if systemctl is-active --quiet mtg; then
        echo -e "${GREEN}[✅] Service is running${NC}"
        
        # Check port
        if command -v ss &> /dev/null && ss -tuln | grep -q ":$PORT "; then
            echo -e "${GREEN}[✅] Port $PORT is listening${NC}"
        else
            echo -e "${YELLOW}[⚠️] Port $PORT not active yet, waiting...${NC}"
            sleep 5
            if command -v ss &> /dev/null; then
                ss -tuln | grep ":$PORT " && echo -e "${GREEN}[✅] Port is now active${NC}" || echo -e "${YELLOW}[⚠️] Port still not active${NC}"
            fi
        fi
    else
        echo -e "${RED}[❌] Service is not running${NC}"
        return 1
    fi
    
    return 0
}

show_connection_info() {
    local port=$1
    local secret=$2
    
    get_public_ip
    
    clear
    echo -e "${BLUE}"
    echo "┌─────────────────────────────────────────────────────┐"
    echo "│            🚀 MTG Proxy Installed!                  │"
    echo "└─────────────────────────────────────────────────────┘"
    echo -e "${NC}"
    
    echo -e "${GREEN}✅ Installation completed successfully${NC}"
    echo ""
    echo -e "${YELLOW}📊 Connection Information:${NC}"
    echo -e "  ${BLUE}•${NC} Server IP: ${GREEN}$IP${NC}"
    echo -e "  ${BLUE}•${NC} Port: ${GREEN}$port${NC}"
    echo -e "  ${BLUE}•${NC} Secret: ${GREEN}$secret${NC}"
    echo ""
    
    echo -e "${YELLOW}🔗 Connection Links:${NC}"
    echo ""
    
    # Telegram link
    TELEGRAM_LINK="tg://proxy?server=$IP&port=$port&secret=$secret"
    echo -e "  ${BLUE}📱 Telegram Link:${NC}"
    echo "  $TELEGRAM_LINK"
    echo ""
    
    # Web link
    WEB_LINK="https://t.me/proxy?server=$IP&port=$port&secret=$secret"
    echo -e "  ${BLUE}🌐 Web Link:${NC}"
    echo "  $WEB_LINK"
    echo ""
    
    # Manual config
    echo -e "  ${BLUE}⚙️ Manual Configuration:${NC}"
    echo "  Server: $IP"
    echo "  Port: $port"
    echo "  Secret: $secret"
    echo ""
    
    echo -e "${YELLOW}📋 Management Commands:${NC}"
    echo "  sudo systemctl status mtg    # View status"
    echo "  sudo systemctl restart mtg   # Restart service"
    echo "  sudo journalctl -u mtg -f    # View logs"
    echo ""
    
    echo -e "${BLUE}─────────────────────────────────────────────────────${NC}"
    
    # Save info to file
    INFO_FILE="/root/mtg-info.txt"
    cat > "$INFO_FILE" <<EOF
MTG Proxy Information
=====================
Server: $IP
Port: $port
Secret: $secret

Telegram Link: $TELEGRAM_LINK
Web Link: $WEB_LINK

Generated on: $(date)
EOF
    
    echo -e "${YELLOW}💾 Information saved to $INFO_FILE${NC}"
}

check_installation() {
    echo -e "\n${YELLOW}[*] Checking installation...${NC}"
    
    local errors=0
    
    # Check files
    if [[ ! -f "$BIN" ]]; then
        echo -e "${RED}  ❌ MTG binary not found${NC}"
        errors=$((errors+1))
    else
        echo -e "${GREEN}  ✅ Binary exists${NC}"
    fi
    
    if [[ ! -f "$CONF" ]]; then
        echo -e "${RED}  ❌ Configuration file not found${NC}"
        errors=$((errors+1))
    else
        echo -e "${GREEN}  ✅ Configuration exists${NC}"
        # Show secret (first few chars)
        SECRET=$(grep 'secret =' "$CONF" | cut -d '"' -f 2 | head -c 20)
        echo -e "${YELLOW}  Secret: ${SECRET}...${NC}"
    fi
    
    if [[ ! -f "$SERVICE" ]]; then
        echo -e "${RED}  ❌ Service file not found${NC}"
        errors=$((errors+1))
    else
        echo -e "${GREEN}  ✅ Service file exists${NC}"
    fi
    
    # Check service
    if systemctl is-enabled mtg &>/dev/null; then
        echo -e "${GREEN}  ✅ Service is enabled${NC}"
    else
        echo -e "${YELLOW}  ⚠️ Service is not enabled${NC}"
    fi
    
    if systemctl is-active mtg &>/dev/null; then
        echo -e "${GREEN}  ✅ Service is active${NC}"
    else
        echo -e "${RED}  ❌ Service is not active${NC}"
        errors=$((errors+1))
    fi
    
    # Check port
    if command -v ss &> /dev/null && ss -tuln | grep -q ":$PORT "; then
        echo -e "${GREEN}  ✅ Port $PORT is listening${NC}"
    else
        echo -e "${RED}  ❌ Port $PORT is not listening${NC}"
        errors=$((errors+1))
    fi
    
    # Check process
    if pgrep -x "mtg" >/dev/null; then
        echo -e "${GREEN}  ✅ MTG process is running${NC}"
    else
        echo -e "${RED}  ❌ No MTG process found${NC}"
        errors=$((errors+1))
    fi
    
    return $errors
}

main_install() {
    show_banner
    check_root
    
    echo -e "${YELLOW}[*] Starting MTG Proxy installation${NC}"
    echo ""
    
    # Get port
    while true; do
        read -p "Enter port (default: 443): " PORT
        PORT=${PORT:-443}
        
        if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
            echo -e "${RED}Invalid port (1-65535)${NC}"
            continue
        fi
        
        if check_port "$PORT"; then
            break
        else
            echo -e "${RED}Please choose another port${NC}"
        fi
    done
    
    # Installation steps
    echo ""
    install_deps
    echo ""
    configure_bbr
    echo ""
    configure_firewall "$PORT"
    echo ""
    download_mtg
    echo ""
    SECRET=$(generate_config "$PORT")
    echo ""
    create_service
    echo ""
    
    # Start service
    if start_service; then
        echo ""
        show_connection_info "$PORT" "$SECRET"
        echo ""
        
        # Final check
        echo -e "${YELLOW}[*] Final verification...${NC}"
        check_installation
        local status=$?
        
        echo ""
        if [ $status -eq 0 ]; then
            echo -e "${GREEN}🎉 Installation completed successfully!${NC}"
            echo -e "${YELLOW}📌 Use the commands above to manage your proxy${NC}"
            
            # Show status
            echo ""
            echo -e "${YELLOW}📊 Current Status:${NC}"
            systemctl status mtg --no-pager | head -15
        else
            echo -e "${YELLOW}⚠️ Installation has issues, check above${NC}"
        fi
    else
        echo -e "${RED}❌ Installation failed${NC}"
        echo -e "${YELLOW}Check logs with:${NC}"
        echo "sudo journalctl -u mtg -n 50 --no-pager"
        exit 1
    fi
}

### ===== Main Execution =====
if [[ "$1" == "help" ]] || [[ "$1" == "-h" ]]; then
    echo "Usage:"
    echo "  sudo bash $0        # Normal installation"
    echo "  sudo bash $0 check  # Check status"
    echo "  sudo bash $0 repair # Repair installation"
    exit 0
fi

if [[ "$1" == "check" ]]; then
    check_installation
    exit 0
fi

if [[ "$1" == "repair" ]]; then
    echo -e "${YELLOW}[*] Repairing installation...${NC}"
    systemctl daemon-reload
    systemctl restart mtg
    check_installation
    exit 0
fi

# Run installation
main_install
