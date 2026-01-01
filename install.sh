#!/bin/bash

CONFIG="/etc/backhaul.conf"

banner() {
    clear
    echo "=========================================="
    echo " Ultra-Stable Backhaul System Installer"
    echo " SSH + WebSocket + TLS + HAProxy"
    echo "=========================================="
}

menu() {
    banner
    echo "1) Install Server (Foreign Datacenter)"
    echo "2) Install Client (Iran Server)"
    echo "3) Install Anti-DPI WebSocket+TLS Mode"
    echo "4) Show Status"
    echo "5) Exit"
    echo "=========================================="
    read -p "Select: " m
    case $m in
        1) install_server ;;
        2) install_client ;;
        3) install_websocket ;;
        4) show_status ;;
        5) exit 0 ;;
        *) menu ;;
    esac
}

install_base() {
    apt update -y
    apt install -y autossh haproxy openssh-server socat curl gnupg nginx certbot python3-certbot-nginx
}

###############################################
### SERVER INSTALLER (FOREIGN SERVER)
###############################################
install_server() {
    install_base

    read -p "Enter SSH username for tunnel: " USERNAME
    read -p "Enter reverse ports (comma separated, e.g. 7000,7001,9000): " PORTS

    useradd -m -s /bin/bash $USERNAME 2>/dev/null
    mkdir -p /home/$USERNAME/.ssh
    chmod 700 /home/$USERNAME/.ssh

    echo "SERVER_USER=\"$USERNAME\"" > $CONFIG
    echo "SERVER_PORTS=\"$PORTS\"" >> $CONFIG

    echo ""
    echo "[✔] Server is ready."
    echo "Run this on the Iran server:"
    echo "ssh-copy-id $USERNAME@YOUR_FOREIGN_IP"
    sleep 2
    menu
}

###############################################
### CLIENT INSTALLER (IRAN SERVER)
###############################################
install_client() {
    install_base
    source $CONFIG

    read -p "Enter Foreign Server IP: " SERVER_IP
    echo "SERVER_IP=\"$SERVER_IP\"" >> $CONFIG

    read -p "Enter ports to tunnel (e.g. 7000,7001,9000): " PORTS
    echo "TUNNEL_PORTS=\"$PORTS\"" >> $CONFIG

    #########################
    # AUTOSSH START SCRIPT
    #########################
    cat >/usr/local/bin/backhaul-run.sh <<EOF
#!/bin/bash
source /etc/backhaul.conf
EOF

    for p in $(echo $PORTS | sed 's/,/ /g'); do
        echo "/usr/bin/autossh -M 0 -o ServerAliveInterval=20 -o ServerAliveCountMax=3 -R $p:localhost:$p \$SERVER_USER@\${SERVER_IP} -N" >> /usr/local/bin/backhaul-run.sh
    done
    chmod +x /usr/local/bin/backhaul-run.sh

    #########################
    # SYSTEMD SERVICE
    #########################
    cat >/etc/systemd/system/backhaul.service <<EOF
[Unit]
Description=Reverse Backhaul Tunnel
After=network.target

[Service]
ExecStart=/usr/local/bin/backhaul-run.sh
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable backhaul
    systemctl restart backhaul

    #########################
    # HAPROXY AUTO-CONFIG
    #########################
    cat >/etc/haproxy/haproxy.cfg <<EOF
global
    log /dev/log local0
    maxconn 4096

defaults
    log global
    mode tcp
    option tcplog
    timeout connect 5s
    timeout client 50s
    timeout server 50s
EOF

    for p in $(echo $PORTS | sed 's/,/ /g'); do
        cat >>/etc/haproxy/haproxy.cfg <<EOF

frontend fwd_$p
    bind *:$p
    default_backend bkd_$p

backend bkd_$p
    server backhaul 127.0.0.1:$p
EOF
    done

    systemctl restart haproxy

    echo ""
    echo "[✔] Client Installed"
    echo "[✔] HAProxy configured automatically"
    echo "[✔] Backhaul tunneling active"
    sleep 2
    menu
}

###############################################
### ANTI-DPI: WebSocket + TLS Tunnel
###############################################
install_websocket() {
    install_base
    source $CONFIG

    read -p "Enter WebSocket TLS domain: " DOMAIN
    echo "WEBSOCKET_DOMAIN=\"$DOMAIN\"" >> $CONFIG

    # TLS cert
    certbot --nginx -d $DOMAIN --non-interactive --agree-tos -m admin@$DOMAIN

    # NGINX CONFIG
    cat >/etc/nginx/sites-available/ws-tunnel.conf <<EOF
server {
    listen 443 ssl;
    server_name $DOMAIN;

    ssl_certificate     /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;

    location /ws/ {
        proxy_pass http://127.0.0.1:7777/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF

    ln -sf /etc/nginx/sites-available/ws-tunnel.conf /etc/nginx/sites-enabled/ws-tunnel.conf
    systemctl restart nginx

    # SOCAT WS BRIDGE
    cat >/etc/systemd/system/ws-bridge.service <<EOF
[Unit]
Description=SSH over WebSocket Bridge
After=network.target

[Service]
ExecStart=/usr/bin/socat TCP-LISTEN:7777,reuseaddr,fork SYSTEM:"socat - TCP:localhost:22"
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable ws-bridge
    systemctl restart ws-bridge

    echo ""
    echo "==============================="
    echo " WebSocket Anti-DPI Enabled ✔"
    echo "==============================="
    echo "Client must use:"
    echo "   wss://$DOMAIN/ws/"
    sleep 3
    menu
}

###############################################
### STATUS CHECKER
###############################################
show_status() {
    banner
    echo "--- AUTOSSH ---"
    systemctl status backhaul --no-pager

    echo ""
    echo "--- HAProxy ---"
    systemctl status haproxy --no-pager

    echo ""
    echo "--- WebSocket Anti-DPI ---"
    systemctl status ws-bridge --no-pager 2>/dev/null || echo "Not Installed"

    echo ""
    read -p "Press Enter..."
    menu
}

menu
