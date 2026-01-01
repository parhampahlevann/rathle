#!/bin/bash
# Complete Backhaul Tunnel Manager
# SSH Reverse Tunnel + HAProxy + WebSocket Anti-DPI
# Version: 3.0

# ==============================================
# CONFIGURATION
# ==============================================
CONFIG="/etc/backhaul.conf"
LOG_DIR="/var/log/backhaul"
BACKUP_DIR="/etc/backhaul/backups"
INSTALL_DIR="/usr/local/share/backhaul"
PID_DIR="/var/run/backhaul"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# ==============================================
# INITIALIZATION FUNCTIONS
# ==============================================

init_directories() {
    mkdir -p $LOG_DIR
    mkdir -p $BACKUP_DIR
    mkdir -p $INSTALL_DIR/scripts
    mkdir -p $PID_DIR
    chmod 700 $BACKUP_DIR
    touch $LOG_DIR/install.log
    touch $LOG_DIR/tunnel.log
    chmod 600 $LOG_DIR/*
}

log() {
    echo -e "${CYAN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a $LOG_DIR/install.log
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a $LOG_DIR/install.log
    exit 1
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a $LOG_DIR/install.log
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a $LOG_DIR/install.log
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a $LOG_DIR/install.log
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
    fi
}

check_os() {
    if [[ -f /etc/debian_version ]]; then
        OS="debian"
    elif [[ -f /etc/centos-release ]]; then
        OS="centos"
    elif [[ -f /etc/redhat-release ]]; then
        OS="centos"
    elif [[ -f /etc/alpine-release ]]; then
        OS="alpine"
    else
        warning "Unknown OS. Trying to proceed anyway..."
        OS="unknown"
    fi
    log "Detected OS: $OS"
}

install_dependencies() {
    log "Installing dependencies..."
    
    case $OS in
        debian|ubuntu)
            apt-get update -y
            apt-get install -y \
                autossh \
                haproxy \
                openssh-server \
                openssh-client \
                socat \
                curl \
                wget \
                net-tools \
                nginx \
                certbot \
                python3-certbot-nginx \
                fail2ban \
                iptables-persistent \
                cron \
                dnsutils \
                jq \
                bc \
                screen \
                tmux \
                iftop \
                htop \
                vnstat
            ;;
        centos|rhel|fedora)
            yum update -y
            yum install -y \
                epel-release \
                autossh \
                haproxy \
                openssh-server \
                openssh-clients \
                socat \
                curl \
                wget \
                net-tools \
                nginx \
                certbot \
                python3-certbot-nginx \
                fail2ban \
                iptables-services \
                cronie \
                bind-utils \
                jq \
                bc \
                screen \
                tmux \
                iftop \
                htop \
                vnstat
            ;;
        *)
            warning "Please manually install required packages"
            ;;
    esac
    
    success "Dependencies installed"
}

# ==============================================
# BANNER & MENU
# ==============================================

show_banner() {
    clear
    cat << "EOF"
╔══════════════════════════════════════════════════════════╗
║    ██████╗  █████╗  ██████╗██╗  ██╗██╗  ██╗ █████╗ ██╗   ██╗██╗     
║    ██╔══██╗██╔══██╗██╔════╝██║  ██║██║  ██║██╔══██╗██║   ██║██║     
║    ██████╔╝███████║██║     ███████║███████║███████║██║   ██║██║     
║    ██╔══██╗██╔══██║██║     ██╔══██║██╔══██║██╔══██║██║   ██║██║     
║    ██████╔╝██║  ██║╚██████╗██║  ██║██║  ██║██║  ██║╚██████╔╝███████╗
║    ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
║          Ultra-Stable Backhaul Tunnel System v3.0         ║
║           SSH + WebSocket + TLS + HAProxy + Anti-DPI      ║
╚══════════════════════════════════════════════════════════╝
EOF
    echo ""
}

show_menu() {
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                     MAIN MENU                            ║"
    echo "╠══════════════════════════════════════════════════════════╣"
    echo "║  1) Install Master Server (Foreign Datacenter)           ║"
    echo "║  2) Install Client Node (Iran Server)                    ║"
    echo "║  3) Install WebSocket + TLS Anti-DPI Tunnel              ║"
    echo "║  4) Install Load Balancer (Multiple Tunnels)             ║"
    echo "║  5) Advanced Configuration                               ║"
    echo "║                                                          ║"
    echo "║  ════════════════════════════════════════════════════    ║"
    echo "║  6) Start Tunnel                                         ║"
    echo "║  7) Stop Tunnel                                          ║"
    echo "║  8) Restart Tunnel                                       ║"
    echo "║  9) Check Status                                         ║"
    echo "║  10) Monitor Connections                                 ║"
    echo "║  11) Run Diagnostic Tests                                ║"
    echo "║                                                          ║"
    echo "║  ════════════════════════════════════════════════════    ║"
    echo "║  12) Backup Configuration                                ║"
    echo "║  13) Restore Configuration                               ║"
    echo "║  14) Update Script                                       ║"
    echo "║  15) Uninstall                                           ║"
    echo "║                                                          ║"
    echo "║  0) Exit                                                 ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo ""
    read -p "Select option [0-15]: " choice
    echo ""
}

# ==============================================
# INSTALL MASTER SERVER (FOREIGN)
# ==============================================

install_master_server() {
    show_banner
    log "Starting Master Server installation..."
    
    # Get server details
    read -p "Enter SSH username for tunnels [tunnel]: " SERVER_USER
    SERVER_USER=${SERVER_USER:-tunnel}
    
    read -p "Enter SSH port [22]: " SSH_PORT
    SSH_PORT=${SSH_PORT:-22}
    
    read -p "Enter tunnel ports (comma separated, e.g. 7000,7001,9000): " PORTS
    
    # Create user
    if id "$SERVER_USER" &>/dev/null; then
        warning "User $SERVER_USER already exists"
    else
        useradd -m -s /bin/bash $SERVER_USER
        success "User $SERVER_USER created"
    fi
    
    # Setup SSH directory
    mkdir -p /home/$SERVER_USER/.ssh
    chmod 700 /home/$SERVER_USER/.ssh
    touch /home/$SERVER_USER/.ssh/authorized_keys
    chmod 600 /home/$SERVER_USER/.ssh/authorized_keys
    chown -R $SERVER_USER:$SERVER_USER /home/$SERVER_USER/.ssh
    
    # Configure SSH for tunneling
    backup_file "/etc/ssh/sshd_config"
    
    # Add tunnel-specific configuration
    cat >> /etc/ssh/sshd_config << EOF

# Backhaul Tunnel Configuration
Match User $SERVER_USER
    PasswordAuthentication no
    PubkeyAuthentication yes
    PermitEmptyPasswords no
    PermitRootLogin no
    AllowTcpForwarding yes
    GatewayPorts yes
    X11Forwarding no
    AllowAgentForwarding no
    PermitOpen localhost:* 127.0.0.1:*
    ForceCommand /bin/false
    ClientAliveInterval 30
    ClientAliveCountMax 3
EOF
    
    # Restart SSH
    systemctl restart sshd
    
    # Setup firewall
    setup_firewall_master $PORTS $SSH_PORT
    
    # Generate SSH key pair for server
    if [ ! -f /root/.ssh/backhaul_server_key ]; then
        ssh-keygen -t ed25519 -f /root/.ssh/backhaul_server_key -N "" -C "backhaul-server-$(hostname)"
    fi
    
    # Save configuration
    save_config "MASTER" "$SERVER_USER" "$SSH_PORT" "$PORTS"
    
    # Create monitoring script
    create_monitoring_script
    
    log "Master Server installation completed!"
    echo ""
    info "=================================================="
    info "MASTER SERVER READY"
    info "=================================================="
    info "SSH User: $SERVER_USER"
    info "SSH Port: $SSH_PORT"
    info "Tunnel Ports: $PORTS"
    info ""
    info "On the client server, run:"
    info "ssh-copy-id -i ~/.ssh/backhaul_client_key.pub $SERVER_USER@$(get_public_ip)"
    info ""
    info "To test connection:"
    info "ssh -p $SSH_PORT $SERVER_USER@$(get_public_ip)"
    info "=================================================="
    
    sleep 5
    main_menu
}

# ==============================================
# INSTALL CLIENT NODE (IRAN SERVER)
# ==============================================

install_client_node() {
    show_banner
    log "Starting Client Node installation..."
    
    # Check if config exists
    if [ -f $CONFIG ]; then
        source $CONFIG
        info "Found existing configuration"
        read -p "Use existing config? (y/n): " use_existing
        if [[ $use_existing != "y" ]]; then
            rm -f $CONFIG
        fi
    fi
    
    if [ ! -f $CONFIG ]; then
        # Get configuration from user
        read -p "Enter Master Server IP/Hostname: " SERVER_IP
        read -p "Enter SSH username on master [$SERVER_USER]: " MASTER_USER
        MASTER_USER=${MASTER_USER:-$SERVER_USER}
        read -p "Enter SSH port [22]: " SSH_PORT
        SSH_PORT=${SSH_PORT:-22}
        read -p "Enter tunnel ports (comma separated, e.g. 7000,7001,9000): " TUNNEL_PORTS
        
        # Save initial config
        save_config "CLIENT" "$MASTER_USER" "$SSH_PORT" "$TUNNEL_PORTS" "$SERVER_IP"
    fi
    
    source $CONFIG
    
    # Generate SSH key if not exists
    if [ ! -f /root/.ssh/backhaul_client_key ]; then
        ssh-keygen -t ed25519 -f /root/.ssh/backhaul_client_key -N "" -C "backhaul-client-$(hostname)"
        chmod 600 /root/.ssh/backhaul_client_key
    fi
    
    # Display public key
    echo ""
    info "Your public key:"
    cat /root/.ssh/backhaul_client_key.pub
    echo ""
    info "Add this key to /home/$MASTER_USER/.ssh/authorized_keys on the master server"
    read -p "Press Enter after adding the key..."
    
    # Test SSH connection
    info "Testing SSH connection..."
    if ssh -i /root/.ssh/backhaul_client_key -p $SSH_PORT -o BatchMode=yes -o ConnectTimeout=5 \
        $MASTER_USER@$SERVER_IP "echo 'SSH connection successful'"; then
        success "SSH connection successful"
    else
        error "SSH connection failed. Please check key and firewall settings."
    fi
    
    # Install autossh tunnels
    install_autossh_tunnels
    
    # Configure HAProxy
    configure_haproxy
    
    # Configure systemd services
    configure_systemd_services
    
    # Setup firewall
    setup_firewall_client "$TUNNEL_PORTS"
    
    # Enable and start services
    systemctl daemon-reload
    systemctl enable backhaul-tunnel
    systemctl enable haproxy
    systemctl start backhaul-tunnel
    systemctl start haproxy
    
    # Setup monitoring
    setup_monitoring
    
    success "Client Node installation completed!"
    
    # Run quick test
    run_quick_test
    
    sleep 3
    main_menu
}

# ==============================================
# AUTOSSH TUNNEL SETUP
# ==============================================

install_autossh_tunnels() {
    log "Configuring AutoSSH tunnels..."
    
    # Create tunnel script
    cat > /usr/local/bin/backhaul-tunnel.sh << EOF
#!/bin/bash
# AutoSSH Tunnel Manager
# Generated by Backhaul Installer

CONFIG="$CONFIG"
source \$CONFIG

LOG_FILE="$LOG_DIR/tunnel.log"
PID_DIR="$PID_DIR"

# Function to start tunnel
start_tunnel() {
    local port=\$1
    local local_port=\$2
    
    # Kill existing tunnel if any
    if [ -f \$PID_DIR/tunnel-\$port.pid ]; then
        kill -9 \$(cat \$PID_DIR/tunnel-\$port.pid) 2>/dev/null
        rm -f \$PID_DIR/tunnel-\$port.pid
    fi
    
    # Start new tunnel
    AUTOSSH_PIDFILE=\$PID_DIR/tunnel-\$port.pid \
    AUTOSSH_LOGFILE=\$LOG_DIR/tunnel-\$port.log \
    AUTOSSH_POLL=30 \
    autossh -M 0 \
        -o "ServerAliveInterval=15" \
        -o "ServerAliveCountMax=3" \
        -o "ExitOnForwardFailure=yes" \
        -o "StrictHostKeyChecking=no" \
        -o "BatchMode=yes" \
        -i /root/.ssh/backhaul_client_key \
        -p \$SSH_PORT \
        -N \
        -R \$port:localhost:\${local_port:-\$port} \
        \$MASTER_USER@\$SERVER_IP \
        2>> \$LOG_DIR/autossh-\$port.error.log &
    
    echo \$! > \$PID_DIR/tunnel-\$port.pid
    echo "[\$(date)] Started tunnel on port \$port" >> \$LOG_FILE
}

# Function to stop tunnel
stop_tunnel() {
    local port=\$1
    if [ -f \$PID_DIR/tunnel-\$port.pid ]; then
        kill -9 \$(cat \$PID_DIR/tunnel-\$port.pid) 2>/dev/null
        rm -f \$PID_DIR/tunnel-\$port.pid
        echo "[\$(date)] Stopped tunnel on port \$port" >> \$LOG_FILE
    fi
}

# Function to check tunnel status
check_tunnel() {
    local port=\$1
    if [ -f \$PID_DIR/tunnel-\$port.pid ] && kill -0 \$(cat \$PID_DIR/tunnel-\$port.pid) 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Main execution
case "\$1" in
    start)
        IFS=',' read -ra PORTS <<< "\$TUNNEL_PORTS"
        for port in "\${PORTS[@]}"; do
            start_tunnel "\$port"
            sleep 1
        done
        ;;
    stop)
        IFS=',' read -ra PORTS <<< "\$TUNNEL_PORTS"
        for port in "\${PORTS[@]}"; do
            stop_tunnel "\$port"
        done
        ;;
    restart)
        \$0 stop
        sleep 2
        \$0 start
        ;;
    status)
        IFS=',' read -ra PORTS <<< "\$TUNNEL_PORTS"
        for port in "\${PORTS[@]}"; do
            if check_tunnel "\$port"; then
                echo "Port \$port: \$(ps -p \$(cat \$PID_DIR/tunnel-\$port.pid) -o comm=) (PID: \$(cat \$PID_DIR/tunnel-\$port.pid))"
            else
                echo "Port \$port: NOT RUNNING"
            fi
        done
        ;;
    *)
        echo "Usage: \$0 {start|stop|restart|status}"
        exit 1
        ;;
esac
EOF
    
    chmod +x /usr/local/bin/backhaul-tunnel.sh
    
    success "AutoSSH tunnels configured"
}

# ==============================================
# HAPROXY CONFIGURATION
# ==============================================

configure_haproxy() {
    log "Configuring HAProxy..."
    
    # Backup original config
    backup_file "/etc/haproxy/haproxy.cfg"
    
    # Generate HAProxy config
    cat > /etc/haproxy/haproxy.cfg << EOF
global
    log /dev/log local0
    log /dev/log local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
    stats timeout 30s
    user haproxy
    group haproxy
    daemon
    maxconn 50000
    tune.ssl.default-dh-param 2048
    
defaults
    log global
    mode tcp
    option tcplog
    option dontlognull
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms
    retries 3
    maxconn 50000
    
# Stats endpoint
listen stats
    bind *:1936
    mode http
    stats enable
    stats hide-version
    stats realm HAProxy\ Statistics
    stats uri /
    stats auth admin:$(generate_password 12)
    
EOF
    
    # Add frontend/backend for each port
    IFS=',' read -ra PORTS <<< "$TUNNEL_PORTS"
    for port in "${PORTS[@]}"; do
        cat >> /etc/haproxy/haproxy.cfg << EOF
# Tunnel port $port
frontend frontend_$port
    bind *:$port
    mode tcp
    default_backend backend_$port
    option tcplog
    tcp-request inspect-delay 5s
    tcp-request content accept if { req.ssl_hello_type 1 }
    
backend backend_$port
    mode tcp
    balance roundrobin
    option tcp-check
    server tunnel_local 127.0.0.1:$port check fall 3 rise 2
    timeout server 30s
    timeout connect 5s
    
EOF
    done
    
    # Enable and start HAProxy
    systemctl enable haproxy
    
    success "HAProxy configured"
}

# ==============================================
# WEBSOCKET + TLS ANTI-DPI
# ==============================================

install_websocket_tunnel() {
    show_banner
    log "Installing WebSocket + TLS Anti-DPI tunnel..."
    
    source $CONFIG 2>/dev/null || warning "Config not found, continuing anyway..."
    
    # Get domain
    read -p "Enter domain name for WebSocket (e.g., tunnel.example.com): " DOMAIN
    if [ -z "$DOMAIN" ]; then
        error "Domain name is required"
    fi
    
    # Install required packages
    apt-get install -y nginx certbot python3-certbot-nginx
    
    # Get Let's Encrypt certificate
    info "Obtaining SSL certificate..."
    if certbot --nginx -d $DOMAIN --non-interactive --agree-tos --register-unsafely-without-email; then
        success "SSL certificate obtained"
    else
        warning "Failed to get SSL certificate. Using self-signed..."
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /etc/ssl/private/$DOMAIN.key \
            -out /etc/ssl/certs/$DOMAIN.crt \
            -subj "/CN=$DOMAIN"
    fi
    
    # Configure Nginx
    cat > /etc/nginx/sites-available/backhaul-ws << EOF
server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $DOMAIN;
    
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    
    # WebSocket endpoint
    location /ws/ {
        proxy_pass http://127.0.0.1:8888;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
    
    # Obfuscation - fake page
    location / {
        root /var/www/html;
        index index.html;
        try_files \$uri \$uri/ =404;
    }
}
EOF
    
    # Enable site
    ln -sf /etc/nginx/sites-available/backhaul-ws /etc/nginx/sites-enabled/
    nginx -t && systemctl reload nginx
    
    # Create WebSocket to TCP bridge
    cat > /etc/systemd/system/backhaul-ws.service << EOF
[Unit]
Description=Backhaul WebSocket Bridge
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/socat TCP-LISTEN:8888,reuseaddr,fork,keepalive \
    SYSTEM:'socat - "TCP:localhost:7000"',nofork
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    
    # Create client configuration
    cat > $INSTALL_DIR/ws-client-config.json << EOF
{
    "server": "wss://$DOMAIN/ws/",
    "local_port": 7000,
    "remote_port": 7000,
    "password": "$(generate_password 16)",
    "obfuscation": "tls",
    "protocol": "websocket",
    "timeout": 300
}
EOF
    
    systemctl daemon-reload
    systemctl enable backhaul-ws
    systemctl start backhaul-ws
    
    # Update main config
    echo "WEBSOCKET_DOMAIN=\"$DOMAIN\"" >> $CONFIG
    echo "WEBSOCKET_ENABLED=true" >> $CONFIG
    
    success "WebSocket + TLS tunnel installed!"
    info ""
    info "WebSocket URL: wss://$DOMAIN/ws/"
    info "Local bridge port: 8888"
    info "Client config: $INSTALL_DIR/ws-client-config.json"
    info ""
    info "Use a WebSocket client to connect through this tunnel"
    
    sleep 5
    main_menu
}

# ==============================================
# LOAD BALANCER SETUP
# ==============================================

install_load_balancer() {
    show_banner
    log "Installing Load Balancer (multiple tunnels)..."
    
    read -p "Number of parallel tunnels [3]: " TUNNEL_COUNT
    TUNNEL_COUNT=${TUNNEL_COUNT:-3}
    
    read -p "Base port number [7000]: " BASE_PORT
    BASE_PORT=${BASE_PORT:-7000}
    
    # Generate port list
    PORTS=""
    for i in $(seq 0 $((TUNNEL_COUNT-1))); do
        PORT=$((BASE_PORT + i))
        PORTS="$PORTS$PORT,"
    done
    PORTS=${PORTS%,}
    
    echo "TUNNEL_PORTS=\"$PORTS\"" >> $CONFIG
    echo "LOAD_BALANCED=true" >> $CONFIG
    echo "TUNNEL_COUNT=$TUNNEL_COUNT" >> $CONFIG
    
    # Configure HAProxy for load balancing
    backup_file "/etc/haproxy/haproxy.cfg"
    
    cat > /etc/haproxy/haproxy.cfg << EOF
global
    log /dev/log local0
    daemon
    maxconn 100000
    
defaults
    log global
    mode tcp
    timeout connect 5s
    timeout client 50s
    timeout server 50s
    
frontend main_frontend
    bind *:$BASE_PORT
    mode tcp
    default_backend tunnel_backends
    
backend tunnel_backends
    mode tcp
    balance leastconn
    option tcp-check
EOF
    
    # Add each tunnel as a backend server
    IFS=',' read -ra PORT_ARRAY <<< "$PORTS"
    for port in "${PORT_ARRAY[@]}"; do
        echo "    server tunnel_$port 127.0.0.1:$port check" >> /etc/haproxy/haproxy.cfg
    done
    
    systemctl restart haproxy
    
    success "Load balancer configured with $TUNNEL_COUNT parallel tunnels"
    info "Main port: $BASE_PORT"
    info "Tunnel ports: $PORTS"
    
    sleep 3
    main_menu
}

# ==============================================
# ADVANCED CONFIGURATION
# ==============================================

advanced_configuration() {
    show_banner
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                 ADVANCED CONFIGURATION                   ║"
    echo "╠══════════════════════════════════════════════════════════╣"
    echo "║  1) Configure SSH Tuning                                 ║"
    echo "║  2) Configure Kernel Parameters                          ║"
    echo "║  3) Setup Traffic Shaping (QoS)                          ║"
    echo "║  4) Configure Monitoring & Alerts                        ║"
    echo "║  5) Setup Automatic Failover                             ║"
    echo "║  6) Configure Backup Server                              ║"
    echo "║  7) Setup GeoIP Routing                                  ║"
    echo "║  8) Configure Connection Multiplexing                    ║"
    echo "║                                                          ║"
    echo "║  0) Back to Main Menu                                    ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo ""
    read -p "Select option: " adv_choice
    
    case $adv_choice in
        1) configure_ssh_tuning ;;
        2) configure_kernel_params ;;
        3) setup_traffic_shaping ;;
        4) configure_monitoring_alerts ;;
        5) setup_automatic_failover ;;
        6) configure_backup_server ;;
        7) setup_geoip_routing ;;
        8) configure_connection_multiplexing ;;
        0) main_menu ;;
        *) advanced_configuration ;;
    esac
}

configure_ssh_tuning() {
    log "Configuring SSH tuning..."
    
    # Backup SSH config
    backup_file "/etc/ssh/sshd_config"
    backup_file "/etc/ssh/ssh_config"
    
    # Server side tuning
    cat >> /etc/ssh/sshd_config << EOF

# Performance tuning
MaxSessions 100
MaxStartups 100:30:200
TCPKeepAlive yes
ClientAliveInterval 30
ClientAliveCountMax 3
Compression delayed
AllowTcpForwarding yes
GatewayPorts yes
EOF
    
    # Client side tuning
    cat >> /etc/ssh/ssh_config << EOF

# Performance tuning
Host *
    ServerAliveInterval 30
    ServerAliveCountMax 3
    TCPKeepAlive yes
    Compression yes
    ControlMaster auto
    ControlPath ~/.ssh/control-%h-%p-%r
    ControlPersist 10m
    ConnectTimeout 10
EOF
    
    systemctl restart sshd
    success "SSH tuning configured"
    sleep 2
    advanced_configuration
}

configure_kernel_params() {
    log "Configuring kernel parameters..."
    
    # Backup sysctl
    backup_file "/etc/sysctl.conf"
    
    cat >> /etc/sysctl.conf << EOF

# Network performance tuning
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_fastopen = 3
net.core.default_qdisc = fq
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
EOF
    
    # Apply changes
    sysctl -p
    success "Kernel parameters configured"
    sleep 2
    advanced_configuration
}

# ==============================================
# MONITORING & DIAGNOSTICS
# ==============================================

check_status() {
    show_banner
    log "Checking system status..."
    
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                   SYSTEM STATUS                          ║"
    echo "╠══════════════════════════════════════════════════════════╣"
    
    # Check services
    echo "║ Services Status:                                         ║"
    check_service "backhaul-tunnel" "Tunnel Service"
    check_service "haproxy" "HAProxy"
    check_service "nginx" "Nginx"
    check_service "fail2ban" "Fail2Ban"
    
    # Check tunnels
    echo "║                                                          ║"
    echo "║ Tunnel Status:                                           ║"
    if [ -f /usr/local/bin/backhaul-tunnel.sh ]; then
        /usr/local/bin/backhaul-tunnel.sh status
    else
        echo "║   Tunnel script not found                               ║"
    fi
    
    # Check ports
    echo "║                                                          ║"
    echo "║ Port Status:                                             ║"
    if [ -f $CONFIG ]; then
        source $CONFIG
        IFS=',' read -ra PORTS <<< "$TUNNEL_PORTS"
        for port in "${PORTS[@]}"; do
            if ss -ltn | grep -q ":$port "; then
                echo "║   Port $port: LISTENING                              ║"
            else
                echo "║   Port $port: CLOSED                                 ║"
            fi
        done
    fi
    
    # Check connections
    echo "║                                                          ║"
    echo "║ Active Connections:                                      ║"
    CONN_COUNT=$(ss -tn | grep -c ESTAB)
    echo "║   ESTABLISHED: $CONN_COUNT connections                    ║"
    
    # Check resource usage
    echo "║                                                          ║"
    echo "║ Resource Usage:                                          ║"
    CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    MEM_USAGE=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
    echo "║   CPU: ${CPU_USAGE}%                                       ║"
    echo "║   Memory: ${MEM_USAGE}%                                    ║"
    
    echo "╚══════════════════════════════════════════════════════════╝"
    
    echo ""
    read -p "Press Enter to continue..."
    main_menu
}

check_service() {
    local service=$1
    local name=$2
    if systemctl is-active --quiet $service; then
        echo "║   ✓ $name: RUNNING                                 ║"
    else
        echo "║   ✗ $name: STOPPED                                 ║"
    fi
}

monitor_connections() {
    show_banner
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                LIVE CONNECTION MONITOR                   ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo ""
    info "Press Ctrl+C to stop monitoring"
    echo ""
    
    watch -n 2 '
        echo "╔══════════════════════════════════════════════════════════╗"
        echo "║                    Live Status - $(date "+%H:%M:%S")                 ║"
        echo "╠══════════════════════════════════════════════════════════╣"
        
        # Tunnel processes
        echo "║ Tunnel Processes:                                       ║"
        ps aux | grep autossh | grep -v grep | while read line; do
            pid=$(echo $line | awk "{print \$2}")
            cmd=$(echo $line | awk "{\$1=\$2=\$3=\$4=\$5=\$6=\$7=\$8=\$9=\$10=\"\"; print}")
            echo "║   PID: $pid - $cmd"
        done
        
        # Active connections
        echo "║                                                          ║"
        echo "║ Active Tunnel Connections:                               ║"
        netstat -tn | grep ESTABLISHED | grep -E ":7000|:7001|:9000" | \
            awk "{print \"║   \" \$4 \" -> \" \$5}" | head -10
        
        # HAProxy stats
        echo "║                                                          ║"
        echo "║ HAProxy Connections:                                     ║"
        echo "║   $(echo "show info" | socat /var/run/haproxy.sock stdio 2>/dev/null | grep CurrConns | cut -d: -f2) active connections"
        
        # Bandwidth
        echo "║                                                          ║"
        echo "║ Bandwidth Usage:                                         ║"
        ifstat -i eth0 -b 0.5 1 | tail -1 | awk "{printf \"║   In: %.2f Mbps | Out: %.2f Mbps\\n\", \$1/1000, \$2/1000}"
        
        echo "╚══════════════════════════════════════════════════════════╝"
    '
    
    main_menu
}

run_diagnostic_tests() {
    show_banner
    log "Running diagnostic tests..."
    
    TESTS=(
        "Test 1: Checking configuration files"
        "Test 2: Testing SSH connectivity"
        "Test 3: Verifying tunnel ports"
        "Test 4: Testing HAProxy configuration"
        "Test 5: Checking firewall rules"
        "Test 6: Testing end-to-end connectivity"
        "Test 7: Checking DNS resolution"
        "Test 8: Verifying service dependencies"
    )
    
    PASS=0
    FAIL=0
    
    for test in "${TESTS[@]}"; do
        echo -n "$test... "
        
        case $test in
            "Test 1:"*)
                if [ -f $CONFIG ] && [ -f "/usr/local/bin/backhaul-tunnel.sh" ]; then
                    echo -e "${GREEN}PASS${NC}"
                    ((PASS++))
                else
                    echo -e "${RED}FAIL${NC}"
                    ((FAIL++))
                fi
                ;;
            "Test 2:"*)
                source $CONFIG 2>/dev/null
                if timeout 5 ssh -o BatchMode=yes -o ConnectTimeout=3 \
                    -i /root/.ssh/backhaul_client_key \
                    $MASTER_USER@$SERVER_IP "echo connected" 2>/dev/null; then
                    echo -e "${GREEN}PASS${NC}"
                    ((PASS++))
                else
                    echo -e "${RED}FAIL${NC}"
                    ((FAIL++))
                fi
                ;;
            "Test 3:"*)
                source $CONFIG 2>/dev/null
                IFS=',' read -ra PORTS <<< "$TUNNEL_PORTS"
                local all_ok=true
                for port in "${PORTS[@]}"; do
                    if ! ss -ltn | grep -q ":$port "; then
                        all_ok=false
                        break
                    fi
                done
                if $all_ok; then
                    echo -e "${GREEN}PASS${NC}"
                    ((PASS++))
                else
                    echo -e "${RED}FAIL${NC}"
                    ((FAIL++))
                fi
                ;;
            "Test 4:"*)
                if haproxy -c -f /etc/haproxy/haproxy.cfg 2>/dev/null; then
                    echo -e "${GREEN}PASS${NC}"
                    ((PASS++))
                else
                    echo -e "${RED}FAIL${NC}"
                    ((FAIL++))
                fi
                ;;
            "Test 5:"*)
                if command -v ufw >/dev/null; then
                    if ufw status | grep -q "Status: active"; then
                        echo -e "${GREEN}PASS${NC}"
                        ((PASS++))
                    else
                        echo -e "${YELLOW}SKIP${NC}"
                    fi
                else
                    echo -e "${YELLOW}SKIP${NC}"
                fi
                ;;
            "Test 6:"*)
                # Simple echo server test
                source $CONFIG 2>/dev/null
                IFS=',' read -ra PORTS <<< "$TUNNEL_PORTS"
                TEST_PORT=${PORTS[0]}
                if timeout 5 bash -c "echo test | nc localhost $TEST_PORT" 2>/dev/null; then
                    echo -e "${GREEN}PASS${NC}"
                    ((PASS++))
                else
                    echo -e "${RED}FAIL${NC}"
                    ((FAIL++))
                fi
                ;;
            "Test 7:"*)
                if dig +short google.com >/dev/null; then
                    echo -e "${GREEN}PASS${NC}"
                    ((PASS++))
                else
                    echo -e "${RED}FAIL${NC}"
                    ((FAIL++))
                fi
                ;;
            "Test 8:"*)
                if systemctl is-active haproxy >/dev/null && \
                   systemctl is-active ssh >/dev/null; then
                    echo -e "${GREEN}PASS${NC}"
                    ((PASS++))
                else
                    echo -e "${RED}FAIL${NC}"
                    ((FAIL++))
                fi
                ;;
        esac
    done
    
    echo ""
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                   DIAGNOSTIC RESULTS                     ║"
    echo "╠══════════════════════════════════════════════════════════╣"
    echo "║ Tests Passed:  $PASS                                       ║"
    echo "║ Tests Failed:  $FAIL                                       ║"
    
    if [ $FAIL -eq 0 ]; then
        echo "║ Status:        ${GREEN}ALL SYSTEMS OPERATIONAL${NC}               ║"
    elif [ $FAIL -le 2 ]; then
        echo "║ Status:        ${YELLOW}MINOR ISSUES DETECTED${NC}                ║"
    else
        echo "║ Status:        ${RED}CRITICAL ISSUES DETECTED${NC}               ║"
    fi
    echo "╚══════════════════════════════════════════════════════════╝"
    
    echo ""
    read -p "Press Enter to continue..."
    main_menu
}

# ==============================================
# UTILITY FUNCTIONS
# ==============================================

backup_file() {
    local file=$1
    if [ -f "$file" ]; then
        local backup="$BACKUP_DIR/$(basename $file).backup.$(date +%Y%m%d_%H%M%S)"
        cp "$file" "$backup"
        log "Backed up $file to $backup"
    fi
}

save_config() {
    local mode=$1
    local user=$2
    local port=$3
    local ports=$4
    local server_ip=${5:-}
    
    cat > $CONFIG << EOF
# Backhaul Tunnel Configuration
# Generated on $(date)
MODE="$mode"
SERVER_USER="$user"
SSH_PORT="$port"
TUNNEL_PORTS="$ports"
SERVER_IP="$server_ip"
INSTALL_DATE="$(date +%Y-%m-%d)"
VERSION="3.0"
EOF
    
    chmod 600 $CONFIG
}

setup_firewall_master() {
    local ports=$1
    local ssh_port=$2
    
    log "Configuring firewall for Master Server..."
    
    # UFW (Ubuntu/Debian)
    if command -v ufw >/dev/null; then
        ufw --force reset
        ufw default deny incoming
        ufw default allow outgoing
        ufw allow $ssh_port/tcp
        ufw allow 80/tcp
        ufw allow 443/tcp
        
        # Allow tunnel ports
        IFS=',' read -ra PORT_ARRAY <<< "$ports"
        for port in "${PORT_ARRAY[@]}"; do
            ufw allow $port/tcp
        done
        
        ufw --force enable
        success "UFW firewall configured"
        
    # Firewalld (CentOS/RHEL)
    elif command -v firewall-cmd >/dev/null; then
        firewall-cmd --permanent --add-port=$ssh_port/tcp
        firewall-cmd --permanent --add-service=http
        firewall-cmd --permanent --add-service=https
        
        IFS=',' read -ra PORT_ARRAY <<< "$ports"
        for port in "${PORT_ARRAY[@]}"; do
            firewall-cmd --permanent --add-port=$port/tcp
        done
        
        firewall-cmd --reload
        success "Firewalld configured"
    fi
}

setup_firewall_client() {
    local ports=$1
    
    log "Configuring firewall for Client..."
    
    if command -v ufw >/dev/null; then
        ufw --force reset
        ufw default deny incoming
        ufw default allow outgoing
        ufw allow 22/tcp
        
        # Allow local tunnel ports
        IFS=',' read -ra PORT_ARRAY <<< "$ports"
        for port in "${PORT_ARRAY[@]}"; do
            ufw allow $port/tcp comment "Backhaul tunnel port"
        done
        
        # Allow HAProxy stats
        ufw allow 1936/tcp comment "HAProxy stats"
        
        ufw --force enable
        
    elif command -v firewall-cmd >/dev/null; then
        firewall-cmd --permanent --add-service=ssh
        
        IFS=',' read -ra PORT_ARRAY <<< "$ports"
        for port in "${PORT_ARRAY[@]}"; do
            firewall-cmd --permanent --add-port=$port/tcp
        done
        
        firewall-cmd --permanent --add-port=1936/tcp
        firewall-cmd --reload
    fi
    
    success "Client firewall configured"
}

generate_password() {
    local length=${1:-16}
    tr -dc 'A-Za-z0-9!@#$%^&*()' < /dev/urandom | head -c $length
}

get_public_ip() {
    curl -s --max-time 5 https://api.ipify.org || \
    curl -s --max-time 5 https://checkip.amazonaws.com || \
    curl -s --max-time 5 https://icanhazip.com || \
    echo "UNKNOWN"
}

configure_systemd_services() {
    log "Configuring systemd services..."
    
    # Main tunnel service
    cat > /etc/systemd/system/backhaul-tunnel.service << EOF
[Unit]
Description=Backhaul Reverse SSH Tunnel
After=network-online.target ssh.service
Wants=network-online.target
Requires=network-online.target

[Service]
Type=forking
User=root
WorkingDirectory=/root
ExecStart=/usr/local/bin/backhaul-tunnel.sh start
ExecStop=/usr/local/bin/backhaul-tunnel.sh stop
ExecReload=/usr/local/bin/backhaul-tunnel.sh restart
Restart=always
RestartSec=10
StartLimitInterval=60
StartLimitBurst=5

# Security
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=backhaul-tunnel

[Install]
WantedBy=multi-user.target
EOF
    
    # HAProxy service (ensure it's enabled)
    systemctl enable haproxy
    
    success "Systemd services configured"
}

setup_monitoring() {
    log "Setting up monitoring..."
    
    # Create monitoring script
    cat > /usr/local/bin/backhaul-monitor.sh << EOF
#!/bin/bash
# Backhaul Monitoring Script

CONFIG="$CONFIG"
LOG_FILE="$LOG_DIR/monitor.log"

check_and_restart() {
    local service=\$1
    if ! systemctl is-active --quiet \$service; then
        echo "[\$(date)] Service \$service is down, restarting..." >> \$LOG_FILE
        systemctl restart \$service
    fi
}

check_ports() {
    source \$CONFIG 2>/dev/null || return
    IFS=',' read -ra PORTS <<< "\$TUNNEL_PORTS"
    for port in "\${PORTS[@]}"; do
        if ! ss -ltn | grep -q ":\$port "; then
            echo "[\$(date)] Port \$port is not listening" >> \$LOG_FILE
            # Try to restart tunnel
            systemctl restart backhaul-tunnel
            break
        fi
    done
}

# Run checks
check_and_restart backhaul-tunnel
check_and_restart haproxy
check_ports

# Log system stats
echo "[\$(date)] CPU: \$(top -bn1 | grep "Cpu(s)" | awk '{print \$2}')% | \
Mem: \$(free | grep Mem | awk '{printf "%.1f", \$3/\$2 * 100.0}')% | \
Connections: \$(ss -tn state established | wc -l)" >> \$LOG_FILE
EOF
    
    chmod +x /usr/local/bin/backhaul-monitor.sh
    
    # Add to crontab
    (crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/backhaul-monitor.sh") | crontab -
    
    # Setup log rotation
    cat > /etc/logrotate.d/backhaul << EOF
$LOG_DIR/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 640 root root
}
EOF
    
    success "Monitoring configured"
}

create_monitoring_script() {
    cat > $INSTALL_DIR/scripts/monitor.sh << EOF
#!/bin/bash
# Real-time tunnel monitor

watch -n 1 '
    clear
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║               BACKHAUL TUNNEL MONITOR                    ║"
    echo "╠══════════════════════════════════════════════════════════╣"
    
    # Tunnel status
    echo "║ Tunnel Status:                                           ║"
    if systemctl is-active backhaul-tunnel >/dev/null; then
        echo "║   ✓ Main Tunnel: RUNNING                               ║"
    else
        echo "║   ✗ Main Tunnel: STOPPED                               ║"
    fi
    
    # Port status
    echo "║                                                          ║"
    echo "║ Port Status:                                             ║"
    if [ -f $CONFIG ]; then
        source $CONFIG 2>/dev/null
        IFS=',' read -ra PORTS <<< "\$TUNNEL_PORTS"
        for port in "\${PORTS[@]}"; do
            if ss -ltn | grep -q ":\$port "; then
                echo "║   ✓ Port \$port: LISTENING                         ║"
            else
                echo "║   ✗ Port \$port: CLOSED                            ║"
            fi
        done
    fi
    
    # Active connections
    echo "║                                                          ║"
    echo "║ Active Connections:                                      ║"
    ss -tn state established | grep -E ":(${PORTS//,/|})" | head -5 | \
        while read line; do
            echo "║   \$line"
        done
    
    # Resource usage
    echo "║                                                          ║"
    echo "║ Resource Usage:                                          ║"
    echo "║   CPU: \$(top -bn1 | grep "Cpu(s)" | awk "{print \$2}")%"
    echo "║   Memory: \$(free | grep Mem | awk "{printf \"%.1f\", \$3/\$2 * 100.0}")%"
    
    echo "╚══════════════════════════════════════════════════════════╝"
'
EOF
    
    chmod +x $INSTALL_DIR/scripts/monitor.sh
}

run_quick_test() {
    log "Running quick connection test..."
    
    if [ -f $CONFIG ]; then
        source $CONFIG
        IFS=',' read -ra PORTS <<< "$TUNNEL_PORTS"
        TEST_PORT=${PORTS[0]}
        
        echo ""
        info "Testing connection on port $TEST_PORT..."
        
        # Start simple test server
        timeout 3 nc -l -p 9999 -c "echo TEST_SUCCESS" &
        sleep 1
        
        # Test through tunnel
        RESPONSE=$(timeout 3 bash -c "echo test | nc localhost $TEST_PORT 2>/dev/null" || echo "FAILED")
        
        if [ "$RESPONSE" == "TEST_SUCCESS" ]; then
            success "✓ Tunnel is working correctly!"
        else
            warning "⚠ Tunnel test failed. Checking configuration..."
            
            # Run diagnostics
            echo ""
            echo "Running diagnostics..."
            echo "1. Checking SSH connection..."
            ssh -o BatchMode=yes -o ConnectTimeout=3 \
                -i /root/.ssh/backhaul_client_key \
                $MASTER_USER@$SERVER_IP "echo SSH_OK" 2>/dev/null || echo "SSH failed"
            
            echo "2. Checking tunnel processes..."
            ps aux | grep autossh | grep -v grep
            
            echo "3. Checking listening ports..."
            ss -ltn | grep -E ":(${PORTS//,/|})"
        fi
    fi
}

# ==============================================
# BACKUP & RESTORE
# ==============================================

backup_configuration() {
    show_banner
    log "Backing up configuration..."
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_file="$BACKUP_DIR/backhaul_backup_$timestamp.tar.gz"
    
    # Create backup
    tar -czf "$backup_file" \
        $CONFIG \
        /etc/haproxy/haproxy.cfg \
        /etc/nginx/sites-available/backhaul-ws 2>/dev/null \
        /root/.ssh/backhaul_* \
        $LOG_DIR/*.log 2>/dev/null \
        /usr/local/bin/backhaul-*.sh \
        /etc/systemd/system/backhaul-*.service \
        $INSTALL_DIR
    
    if [ -f "$backup_file" ]; then
        success "Backup created: $backup_file"
        echo "Backup size: $(du -h "$backup_file" | cut -f1)"
        echo "Contents:"
        tar -tzf "$backup_file"
    else
        error "Backup failed"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
    main_menu
}

restore_configuration() {
    show_banner
    log "Restoring configuration..."
    
    # List available backups
    echo "Available backups:"
    ls -lh $BACKUP_DIR/*.tar.gz 2>/dev/null | nl
    
    if [ $? -ne 0 ]; then
        error "No backups found in $BACKUP_DIR"
    fi
    
    read -p "Select backup number: " backup_num
    
    local backups=($BACKUP_DIR/*.tar.gz)
    local selected_backup="${backups[$((backup_num-1))]}"
    
    if [ ! -f "$selected_backup" ]; then
        error "Invalid selection"
    fi
    
    # Confirm restore
    read -p "Restore from $selected_backup? This will overwrite current config. (y/n): " confirm
    if [[ $confirm != "y" ]]; then
        main_menu
    fi
    
    # Stop services
    systemctl stop backhaul-tunnel 2>/dev/null
    systemctl stop haproxy 2>/dev/null
    systemctl stop backhaul-ws 2>/dev/null
    
    # Extract backup
    tar -xzf "$selected_backup" -C /
    
    # Restore permissions
    chmod 600 /root/.ssh/backhaul_*
    chmod +x /usr/local/bin/backhaul-*.sh
    
    # Restart services
    systemctl daemon-reload
    systemctl start backhaul-tunnel 2>/dev/null
    systemctl start haproxy 2>/dev/null
    systemctl start backhaul-ws 2>/dev/null
    
    success "Configuration restored from $selected_backup"
    
    sleep 2
    main_menu
}

# ==============================================
# UPDATE & UNINSTALL
# ==============================================

update_script() {
    show_banner
    log "Updating Backhaul script..."
    
    # Backup current version
    local current_script=$(readlink -f "$0")
    cp "$current_script" "$BACKUP_DIR/backhaul_script_$(date +%Y%m%d_%H%M%S).sh"
    
    # Download latest version (placeholder - would be from your repo)
    info "This would download the latest version from the repository"
    info "Currently running local version"
    
    # For now, just reload
    success "Update functionality ready for implementation"
    
    sleep 2
    main_menu
}

uninstall() {
    show_banner
    warning "UNINSTALL BACKHAUL SYSTEM"
    echo ""
    echo "This will:"
    echo "1. Stop all tunnel services"
    echo "2. Remove configuration files"
    echo "3. Remove installed packages"
    echo "4. Clean up system"
    echo ""
    read -p "Are you sure? (type 'YES' to confirm): " confirm
    
    if [ "$confirm" != "YES" ]; then
        info "Uninstall cancelled"
        sleep 2
        main_menu
    fi
    
    log "Starting uninstallation..."
    
    # Stop services
    systemctl stop backhaul-tunnel 2>/dev/null
    systemctl stop backhaul-ws 2>/dev/null
    systemctl stop haproxy 2>/dev/null
    
    # Disable services
    systemctl disable backhaul-tunnel 2>/dev/null
    systemctl disable backhaul-ws 2>/dev/null
    
    # Remove systemd services
    rm -f /etc/systemd/system/backhaul-*.service
    systemctl daemon-reload
    
    # Remove configuration files
    rm -f $CONFIG
    rm -f /usr/local/bin/backhaul-*.sh
    rm -rf $INSTALL_DIR
    
    # Remove cron jobs
    crontab -l | grep -v backhaul-monitor.sh | crontab -
    
    # Remove log rotation
    rm -f /etc/logrotate.d/backhaul
    
    # Ask about removing packages
    read -p "Remove installed packages? (y/n): " remove_pkgs
    if [[ $remove_pkgs == "y" ]]; then
        apt-get remove -y autossh haproxy socat nginx certbot python3-certbot-nginx fail2ban
        apt-get autoremove -y
    fi
    
    # Clean up logs
    rm -rf $LOG_DIR
    rm -rf $PID_DIR
    
    success "Backhaul system has been uninstalled"
    echo ""
    info "Note: SSH keys and HAProxy configs were NOT removed"
    info "Manual cleanup may be required"
    
    sleep 3
    exit 0
}

# ==============================================
# MAIN MENU & EXECUTION
# ==============================================

main_menu() {
    while true; do
        show_banner
        show_menu
        
        case $choice in
            1) install_master_server ;;
            2) install_client_node ;;
            3) install_websocket_tunnel ;;
            4) install_load_balancer ;;
            5) advanced_configuration ;;
            6) systemctl start backhaul-tunnel ;;
            7) systemctl stop backhaul-tunnel ;;
            8) systemctl restart backhaul-tunnel ;;
            9) check_status ;;
            10) monitor_connections ;;
            11) run_diagnostic_tests ;;
            12) backup_configuration ;;
            13) restore_configuration ;;
            14) update_script ;;
            15) uninstall ;;
            0)
                echo ""
                info "Exiting Backhaul Manager"
                exit 0
                ;;
            *)
                warning "Invalid option"
                sleep 1
                ;;
        esac
    done
}

# ==============================================
# INITIALIZATION
# ==============================================

# Check if running as root
check_root

# Initialize
init_directories
check_os

# Check if installed
if [ -f $CONFIG ]; then
    source $CONFIG
    info "Backhaul v$VERSION detected (installed: $INSTALL_DATE)"
    sleep 2
fi

# Main execution
trap 'echo ""; error "Interrupted"; exit 1' INT
main_menu
