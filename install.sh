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
    echo -e "${YELLOW}[*] Checking port $port...${NC}"
    
    if command -v ss &> /dev/null; then
        if ss -tuln | grep -q ":$port "; then
            echo -e "${RED}Error: Port $port is in use!${NC}"
            ss -tuln | grep ":$port" || true
            return 1
        fi
    elif command -v netstat &> /dev/null; then
        if netstat -tuln | grep -q ":$port "; then
            echo -e "${RED}Error: Port $port is in use!${NC}"
            return 1
        fi
    fi
    
    echo -e "${GREEN}[+] Port $port is available${NC}"
    return 0
}

get_public_ip() {
    echo -e "${YELLOW}[*] Getting public IP...${NC}"
    
    # Try multiple services
    local services=(
        "https://api.ipify.org"
        "https://icanhazip.com"
        "https://ifconfig.me/ip"
        "https://checkip.amazonaws.com"
        "https://ipinfo.io/ip"
        "http://whatismyip.akamai.com"
    )
    
    for service in "${services[@]}"; do
        echo -ne "${YELLOW}   Trying $service...${NC} "
        IP=$(timeout 5 curl -s -4 "$service" 2>/dev/null | tr -d '\n\r')
        if [[ -n "$IP" && "$IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            echo -e "${GREEN}$IP${NC}"
            return 0
        fi
        echo -e "${RED}failed${NC}"
        sleep 1
    done
    
    # Get local IP as fallback
    IP=$(hostname -I | awk '{print $1}' 2>/dev/null || echo "YOUR_SERVER_IP")
    echo -e "${YELLOW}[!] Using local IP: $IP${NC}"
    return 1
}

install_deps() {
    echo -e "${YELLOW}[*] Updating system packages...${NC}"
    apt-get update -y || yum update -y || dnf update -y || true
    
    echo -e "${YELLOW}[*] Installing dependencies...${NC}"
    
    # Detect package manager
    if command -v apt-get &> /dev/null; then
        apt-get install -y curl wget net-tools iproute2 jq ca-certificates \
                           openssl coreutils build-essential 2>/dev/null || true
    elif command -v yum &> /dev/null; then
        yum install -y curl wget net-tools iproute jq ca-certificates \
                       openssl coreutils gcc make 2>/dev/null || true
    elif command -v dnf &> /dev/null; then
        dnf install -y curl wget net-tools iproute jq ca-certificates \
                       openssl coreutils gcc make 2>/dev/null || true
    else
        echo -e "${RED}[!] Cannot detect package manager${NC}"
    fi
}

configure_firewall() {
    local port=$1
    echo -e "${YELLOW}[*] Configuring firewall for port $port...${NC}"
    
    # Check current firewall rules
    if command -v ufw &> /dev/null; then
        echo -e "${YELLOW}   Configuring UFW...${NC}"
        ufw --force enable 2>/dev/null || true
        ufw allow "$port"/tcp comment "MTG Proxy"
        ufw allow 22/tcp comment "SSH"
        echo -e "${GREEN}[+] UFW configured${NC}"
    elif command -v firewall-cmd &> /dev/null; then
        echo -e "${YELLOW}   Configuring firewalld...${NC}"
        firewall-cmd --permanent --add-port="$port"/tcp
        firewall-cmd --permanent --add-port=22/tcp
        firewall-cmd --reload
        echo -e "${GREEN}[+] Firewalld configured${NC}"
    elif command -v iptables &> /dev/null; then
        echo -e "${YELLOW}   Configuring iptables...${NC}"
        iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
        iptables -A INPUT -p tcp --dport 22 -j ACCEPT
        echo -e "${GREEN}[+] iptables configured${NC}"
    else
        echo -e "${YELLOW}[!] No firewall manager found, skipping${NC}"
    fi
}

configure_bbr() {
    echo -e "${YELLOW}[*] Optimizing network settings...${NC}"
    
    # Check if BBR is available
    if modprobe tcp_bbr 2>/dev/null; then
        cat > /etc/sysctl.d/99-mtg-optimize.conf <<'EOF'
# BBR TCP Congestion Control
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# Network performance
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192

# Connection management
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_slow_start_after_idle = 0

# Timeouts
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 5
EOF
        sysctl -p /etc/sysctl.d/99-mtg-optimize.conf 2>/dev/null
        echo -e "${GREEN}[+] BBR enabled${NC}"
    else
        echo -e "${YELLOW}[!] BBR not available, using default TCP${NC}"
    fi
}

download_mtg_binary() {
    echo -e "${YELLOW}[*] Downloading MTG binary...${NC}"
    
    # Detect architecture
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) 
            ARCH_TYPE="amd64"
            ARCH_ALT="x86_64"
            ;;
        aarch64|arm64) 
            ARCH_TYPE="arm64"
            ARCH_ALT="aarch64"
            ;;
        armv7l|armv8l) 
            ARCH_TYPE="armv7"
            ARCH_ALT="arm"
            ;;
        *) 
            echo -e "${RED}Error: Unsupported architecture: $ARCH${NC}"
            echo -e "${YELLOW}Supported: x86_64, aarch64, armv7l${NC}"
            exit 1
            ;;
    esac
    
    echo -e "${YELLOW}   Architecture detected: $ARCH ($ARCH_TYPE)${NC}"
    
    # Multiple download URLs (mirrors)
    local urls=(
        "https://github.com/9seconds/mtg/releases/latest/download/mtg-linux-$ARCH_TYPE"
        "https://github.com/9seconds/mtg/releases/latest/download/mtg-$ARCH_TYPE"
        "https://github.com/9seconds/mtg/releases/latest/download/mtg"
        "https://dl.mtgproxy.org/mtg-linux-$ARCH_TYPE"
    )
    
    # Try to get latest version from GitHub API
    echo -e "${YELLOW}   Fetching latest version info...${NC}"
    LATEST_TAG=$(curl -s https://api.github.com/repos/9seconds/mtg/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' 2>/dev/null || echo "v2.1.7")
    
    if [[ -n "$LATEST_TAG" ]]; then
        urls+=(
            "https://github.com/9seconds/mtg/releases/download/$LATEST_TAG/mtg-linux-$ARCH_TYPE"
            "https://github.com/9seconds/mtg/releases/download/$LATEST_TAG/mtg-$ARCH_TYPE"
        )
    fi
    
    echo -e "${YELLOW}   Latest version: ${LATEST_TAG:-unknown}${NC}"
    
    # Try each URL
    local downloaded=false
    
    for i in "${!urls[@]}"; do
        url="${urls[$i]}"
        echo -ne "${YELLOW}   Trying source $((i+1))/${#urls[@]}: $url...${NC} "
        
        # Download with timeout and retry
        if wget --timeout=20 --tries=2 -q -O "$BIN.tmp" "$url" 2>/dev/null || \
           curl -s -L --max-time 20 --retry 2 -o "$BIN.tmp" "$url" 2>/dev/null; then
            
            # Check if file is not empty
            if [[ -s "$BIN.tmp" ]]; then
                mv "$BIN.tmp" "$BIN"
                chmod +x "$BIN"
                echo -e "${GREEN}success${NC}"
                
                # Verify binary works
                if "$BIN" --version &>/dev/null || "$BIN" -h &>/dev/null; then
                    echo -e "${GREEN}[+] Binary verified${NC}"
                    downloaded=true
                    break
                else
                    echo -e "${YELLOW}   Binary verification failed, trying next...${NC}"
                    rm -f "$BIN"
                fi
            else
                echo -e "${RED}empty file${NC}"
                rm -f "$BIN.tmp"
            fi
        else
            echo -e "${RED}failed${NC}"
        fi
    done
    
    # Fallback: Build from source if download fails
    if [[ "$downloaded" == false ]]; then
        echo -e "${YELLOW}[!] All downloads failed, trying to install from package manager...${NC}"
        
        # Try to install from package manager
        if command -v apt-get &> /dev/null; then
            echo -e "${YELLOW}   Trying to install via apt...${NC}"
            apt-get install -y mtg 2>/dev/null || true
        fi
        
        # Check if binary exists now
        if command -v mtg &> /dev/null; then
            BIN=$(command -v mtg)
            echo -e "${GREEN}[+] MTG installed from package manager${NC}"
        else
            echo -e "${RED}Error: Cannot download or install MTG binary${NC}"
            echo -e "${YELLOW}Manual steps:${NC}"
            echo "1. Download manually from: https://github.com/9seconds/mtg/releases"
            echo "2. Copy to /usr/local/bin/mtg"
            echo "3. Run: chmod +x /usr/local/bin/mtg"
            exit 1
        fi
    fi
    
    # Final verification
    if [[ -f "$BIN" ]]; then
        FILESIZE=$(stat -c%s "$BIN" 2>/dev/null || wc -c < "$BIN")
        echo -e "${GREEN}[+] Binary downloaded: $BIN (${FILESIZE} bytes)${NC}"
    else
        echo -e "${RED}Error: Binary not found after installation${NC}"
        exit 1
    fi
}

generate_secret() {
    echo -e "${YELLOW}[*] Generating secure secret...${NC}"
    
    # Try different methods to generate random secret
    if command -v openssl &> /dev/null; then
        SECRET=$(openssl rand -hex 16)
    elif [[ -f /dev/urandom ]]; then
        SECRET=$(head -c 32 /dev/urandom | base64 | tr -d '+/=' | head -c 32)
    else
        # Fallback to date + random
        SECRET=$(date +%s%N | sha256sum | head -c 32)
    fi
    
    # MTG requires secret to start with "dd" or "ee"
    echo "ee$SECRET"
}

create_config() {
    local port=$1
    echo -e "${YELLOW}[*] Creating configuration...${NC}"
    
    # Create config directory
    mkdir -p "$CONF_DIR"
    
    # Generate secret
    SECRET=$(generate_secret)
    
    # Create config file
    cat > "$CONF" <<EOF
# MTG Proxy Configuration
# Generated on $(date)

# Server binding
bind = "0.0.0.0:$port"

# Secret for Telegram connection
secret = "$SECRET"

# Number of worker processes (0 = auto)
workers = 2

# Stats server (for monitoring)
stats-bind = "127.0.0.1:8080"

# Domain fronting only
dd-only = true

# Time synchronization tolerance
clock-skew = "2s"

# TCP Fast Open
tcp-fast-open = true

# Buffer size
tcp-buffer = "64kb"

# Domain for domain fronting
fake-tls = "www.google.com"
EOF
    
    echo -e "${GREEN}[+] Configuration created: $CONF${NC}"
    echo -e "${YELLOW}   Secret: ${SECRET:0:20}...${NC}"
    
    # Return secret for display
    echo "$SECRET"
}

create_systemd_service() {
    echo -e "${YELLOW}[*] Creating systemd service...${NC}"
    
    # Create log directory
    mkdir -p /var/log/
    
    # Create service file
    cat > "$SERVICE" <<EOF
[Unit]
Description=MTG MTProto Proxy
After=network.target
Wants=network-online.target
StartLimitIntervalSec=500
StartLimitBurst=5

[Service]
Type=simple
User=root
WorkingDirectory=/etc/mtg
ExecStart=$BIN run $CONF
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
TimeoutStopSec=30
StandardOutput=append:$LOG_FILE
StandardError=append:$LOG_FILE
SyslogIdentifier=mtg
LimitNOFILE=infinity

# Security
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes

[Install]
WantedBy=multi-user.target
EOF
    
    # Create log file
    touch "$LOG_FILE"
    chmod 644 "$LOG_FILE"
    
    # Reload systemd and enable service
    systemctl daemon-reload
    systemctl enable mtg
    
    echo -e "${GREEN}[+] Systemd service created${NC}"
}

start_mtg_service() {
    echo -e "${YELLOW}[*] Starting MTG service...${NC}"
    
    # Stop if already running
    systemctl stop mtg 2>/dev/null || true
    pkill -9 mtg 2>/dev/null || true
    
    # Wait a bit
    sleep 2
    
    # Start service
    if systemctl start mtg; then
        echo -e "${GREEN}[+] Service started${NC}"
    else
        echo -e "${RED}[!] Failed to start service${NC}"
        return 1
    fi
    
    # Wait and check status
    echo -e "${YELLOW}[*] Checking service status...${NC}"
    sleep 3
    
    if systemctl is-active --quiet mtg; then
        echo -e "${GREEN}[✅] Service is running${NC}"
        
        # Check if listening on port
        local attempts=0
        while [[ $attempts -lt 10 ]]; do
            if ss -tuln 2>/dev/null | grep -q ":$PORT "; then
                echo -e "${GREEN}[✅] Listening on port $PORT${NC}"
                return 0
            fi
            attempts=$((attempts + 1))
            echo -ne "${YELLOW}   Waiting for port $PORT ($attempts/10)...${NC}\r"
            sleep 2
        done
        echo -e "\n${YELLOW}[⚠️] Port $PORT not listening yet${NC}"
    else
        echo -e "${RED}[❌] Service failed to start${NC}"
        return 1
    fi
    
    return 0
}

show_connection_details() {
    local port=$1
    local secret=$2
    
    # Get public IP
    get_public_ip
    
    echo -e "\n${BLUE}══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}          🎉 MTG Proxy Installed Successfully!          ${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${YELLOW}📊 CONNECTION DETAILS:${NC}"
    echo ""
    echo -e "  ${BLUE}•${NC} Server IP:   ${GREEN}$IP${NC}"
    echo -e "  ${BLUE}•${NC} Port:        ${GREEN}$port${NC}"
    echo -e "  ${BLUE}•${NC} Secret:      ${GREEN}$secret${NC}"
    echo ""
    echo -e "${YELLOW}🔗 QUICK LINKS:${NC}"
    echo ""
    
    # Telegram proxy link
    TELEGRAM_LINK="tg://proxy?server=$IP&port=$port&secret=$secret"
    echo -e "  ${BLUE}📱 Telegram App:${NC}"
    echo "  $TELEGRAM_LINK"
    echo ""
    
    # Web link
    WEB_LINK="https://t.me/proxy?server=$IP&port=$port&secret=$secret"
    echo -e "  ${BLUE}🌐 Web Browser:${NC}"
    echo "  $WEB_LINK"
    echo ""
    
    # Manual config
    echo -e "${YELLOW}⚙️ MANUAL CONFIGURATION:${NC}"
    echo ""
    echo "  Server: $IP"
    echo "  Port: $port"
    echo "  Secret: $secret"
    echo ""
    
    echo -e "${YELLOW}📋 MANAGEMENT COMMANDS:${NC}"
    echo ""
    echo "  sudo systemctl status mtg      # Check status"
    echo "  sudo systemctl restart mtg     # Restart proxy"
    echo "  sudo systemctl stop mtg        # Stop proxy"
    echo "  sudo journalctl -u mtg -f      # View logs"
    echo "  sudo tail -f $LOG_FILE         # View log file"
    echo ""
    
    echo -e "${BLUE}══════════════════════════════════════════════════════════${NC}"
    
    # Save to file
    INFO_FILE="/root/mtg-connection.txt"
    cat > "$INFO_FILE" <<EOF
========================================
MTG Proxy Connection Details
========================================
Date: $(date)
Server IP: $IP
Port: $port
Secret: $secret

Quick Links:
Telegram: $TELEGRAM_LINK
Web: $WEB_LINK

Management:
- Check status: systemctl status mtg
- View logs: journalctl -u mtg -f
- Restart: systemctl restart mtg
========================================
EOF
    
    echo -e "${YELLOW}💾 Details saved to: $INFO_FILE${NC}"
    echo -e "${GREEN}📋 You can copy the link above and paste it in Telegram${NC}"
}

verify_installation() {
    echo -e "\n${YELLOW}[*] Verifying installation...${NC}"
    
    local errors=0
    local warnings=0
    
    # Check binary
    if [[ -f "$BIN" ]]; then
        echo -e "${GREEN}✅ Binary: $BIN${NC}"
        if [[ -x "$BIN" ]]; then
            echo -e "   Executable: ${GREEN}Yes${NC}"
        else
            echo -e "   Executable: ${RED}No${NC}"
            errors=$((errors+1))
        fi
    else
        echo -e "${RED}❌ Binary missing: $BIN${NC}"
        errors=$((errors+1))
    fi
    
    # Check config
    if [[ -f "$CONF" ]]; then
        echo -e "${GREEN}✅ Config: $CONF${NC}"
        if grep -q "secret = " "$CONF"; then
            echo -e "   Has secret: ${GREEN}Yes${NC}"
        else
            echo -e "   Has secret: ${RED}No${NC}"
            errors=$((errors+1))
        fi
    else
        echo -e "${RED}❌ Config missing: $CONF${NC}"
        errors=$((errors+1))
    fi
    
    # Check service
    if [[ -f "$SERVICE" ]]; then
        echo -e "${GREEN}✅ Service file: $SERVICE${NC}"
    else
        echo -e "${RED}❌ Service file missing${NC}"
        errors=$((errors+1))
    fi
    
    # Check service status
    if systemctl is-active mtg &>/dev/null; then
        echo -e "${GREEN}✅ Service: Active${NC}"
    else
        echo -e "${RED}❌ Service: Not active${NC}"
        errors=$((errors+1))
    fi
    
    # Check port
    if ss -tuln 2>/dev/null | grep -q ":$PORT "; then
        echo -e "${GREEN}✅ Port $PORT: Listening${NC}"
    else
        echo -e "${YELLOW}⚠️ Port $PORT: Not listening${NC}"
        warnings=$((warnings+1))
    fi
    
    # Summary
    if [[ $errors -eq 0 ]]; then
        if [[ $warnings -eq 0 ]]; then
            echo -e "\n${GREEN}🎉 All checks passed! Installation is successful.${NC}"
        else
            echo -e "\n${YELLOW}⚠️ Installation completed with $warnings warning(s)${NC}"
        fi
    else
        echo -e "\n${RED}❌ Installation has $errors error(s)${NC}"
        return 1
    fi
    
    return 0
}

main_installation() {
    show_banner
    check_root
    
    echo -e "${YELLOW}[*] Starting MTG Proxy Installation${NC}"
    echo ""
    
    # Get port
    read -p "Enter port number (default: 443): " PORT
    PORT=${PORT:-443}
    
    # Validate port
    if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [[ "$PORT" -lt 1 ]] || [[ "$PORT" -gt 65535 ]]; then
        echo -e "${RED}Error: Invalid port number. Must be 1-65535${NC}"
        exit 1
    fi
    
    # Check port availability
    if ! check_port "$PORT"; then
        echo -e "${RED}Please choose a different port or stop the service using port $PORT${NC}"
        exit 1
    fi
    
    echo ""
    echo -e "${YELLOW}[*] Installation Steps:${NC}"
    echo "  1. Install dependencies"
    echo "  2. Configure firewall"
    echo "  3. Optimize network (BBR)"
    echo "  4. Download MTG binary"
    echo "  5. Create configuration"
    echo "  6. Setup systemd service"
    echo "  7. Start service"
    echo ""
    
    # Step 1: Dependencies
    echo -e "${BLUE}[1/7] Installing dependencies...${NC}"
    install_deps
    
    # Step 2: Firewall
    echo -e "${BLUE}[2/7] Configuring firewall...${NC}"
    configure_firewall "$PORT"
    
    # Step 3: Network optimization
    echo -e "${BLUE}[3/7] Optimizing network...${NC}"
    configure_bbr
    
    # Step 4: Download binary
    echo -e "${BLUE}[4/7] Downloading MTG...${NC}"
    download_mtg_binary
    
    # Step 5: Configuration
    echo -e "${BLUE}[5/7] Creating configuration...${NC}"
    SECRET=$(create_config "$PORT")
    
    # Step 6: Service
    echo -e "${BLUE}[6/7] Creating service...${NC}"
    create_systemd_service
    
    # Step 7: Start
    echo -e "${BLUE}[7/7] Starting service...${NC}"
    if start_mtg_service; then
        echo ""
        show_connection_details "$PORT" "$SECRET"
        echo ""
        
        # Final verification
        verify_installation
    else
        echo -e "${RED}❌ Failed to start service${NC}"
        echo -e "${YELLOW}Troubleshooting steps:${NC}"
        echo "1. Check logs: sudo journalctl -u mtg"
        echo "2. Test manually: sudo $BIN run $CONF"
        echo "3. Check port: sudo netstat -tulpn | grep :$PORT"
        exit 1
    fi
}

### ===== Main =====
if [[ "$1" == "help" || "$1" == "-h" ]]; then
    echo "MTG Proxy Installer"
    echo "Usage:"
    echo "  sudo bash $0          # Install MTG Proxy"
    echo "  sudo bash $0 status   # Check installation status"
    echo "  sudo bash $0 repair   # Repair installation"
    echo "  sudo bash $0 remove   # Remove MTG Proxy"
    exit 0
fi

if [[ "$1" == "status" ]]; then
    echo -e "${YELLOW}[*] Checking MTG Proxy status...${NC}"
    systemctl status mtg --no-pager
    echo ""
    echo -e "${YELLOW}[*] Listening ports:${NC}"
    ss -tuln | grep ":${PORT:-443} " || echo "Port ${PORT:-443} not listening"
    exit 0
fi

if [[ "$1" == "repair" ]]; then
    echo -e "${YELLOW}[*] Repairing MTG installation...${NC}"
    systemctl stop mtg 2>/dev/null || true
    systemctl daemon-reload
    systemctl reset-failed mtg 2>/dev/null || true
    systemctl start mtg
    systemctl status mtg --no-pager | head -20
    exit 0
fi

if [[ "$1" == "remove" ]]; then
    echo -e "${YELLOW}[*] Removing MTG Proxy...${NC}"
    systemctl stop mtg 2>/dev/null || true
    systemctl disable mtg 2>/dev/null || true
    rm -f "$SERVICE" "$BIN"
    rm -rf "$CONF_DIR"
    systemctl daemon-reload
    echo -e "${GREEN}[+] MTG Proxy removed${NC}"
    exit 0
fi

# Run main installation
main_installation
