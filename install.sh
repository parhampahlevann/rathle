#!/bin/bash

CONFIG="/etc/backhaul.conf"

banner() {
    clear
    echo "=============================================="
    echo "     Ultra Stable Reverse Backhaul System"
    echo " SSH + WebSocket + TLS + HAProxy (Anti-DPI)"
    echo "=============================================="
}

menu() {
    banner
    echo "1) Install Server (Foreign)"
    echo "2) Install Client (Iran)"
    echo "3) Show Tunnel Status"
    echo "4) Install Anti-DPI WebSocket+TLS Mode"
    echo "5) Exit"
    echo "=============================================="
    read -p "Select: " m
    case $m in
        1) install_server ;;
        2) install_client ;;
        3) show_status ;;
        4) install_websocket ;;
        5) exit 0 ;;
        *) menu ;;
    esac
}

install_deps() {
    apt update -y
    apt install -y autossh haproxy openssh-server socat certbot python3-certbot-nginx
}

install_server() {
    install_deps

    read -p "Enter SSH username for tunnel: " USR
    read -p "Open ports for reverse tunnel (e.g. 8000,8001,9000): " PORTS

    useradd -m -s /bin/bash $USR 2>/dev/null
    mkdir -p /home/$USR/.ssh
    chmod 700 /home/$USR/.ssh

    echo "SERVER_USER=\"$USR\"" > $CONFIG
    echo "SERVER_PORTS=\"$PORTS\"" >> $CONFIG

    echo "Server installed."
    echo "Now run: ssh-copy-id $USR@SERVER_IP on Iran server."
    sleep 2
    menu
}

install_client() {
    install_deps
    source $CONFIG

    read -p "Enter Server IP: " SERVER_IP
    echo "SERVER_IP=\"$SERVER_IP\"" >> $CONFIG

    # AUTOSSH SERVICE
    cat >/etc/systemd/system/backhaul.service <<EOF
[Unit]
Description=Reverse Backhaul SSH Tunnel
After=network.target

[Service]
User=root
Environment="AUTOSSH_GATETIME=0"
ExecStart=/bin/bash /usr/local/bin/backhaul-run.sh
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    # RUN SCRIPT
    cat >/usr/local/bin/backhaul-run.sh <<EOF
#!/bin/bash
EOF

    for p in $(echo $SERVER_PORTS | sed 's/,/ /g'); do
        echo "/usr/bin/autossh -M 0 -o ServerAliveInterval=20 -o ServerAliveCountMax=3 -R $p:localhost:$p $SERVER_USER@$SERVER_IP -N" >> /usr/local/bin/backhaul-run.sh
    done

    chmod +x /usr/local/bin/backhaul-run.sh

    # HAPROXY
    cat >/etc/haproxy/haproxy.cfg <<EOF
global
    log /dev/log local0
    maxconn 2000
defaults
    log global
    mode tcp
    option tcplog
    timeout connect 5s
    timeout client  50s
    timeout server  50s
EOF

    for p in $(echo $SERVER_PORTS | sed 's/,/ /g'); do
        cat >>/etc/haproxy/haproxy.cfg <<EOF

frontend port_$p
    bind *:$p
    default_backend back_$p

backend back_$p
    server s1 127.0.0.1:$p
EOF
    done

    systemctl daemon-reload
    systemctl enable backhaul
    systemctl restart backhaul
    systemctl restart haproxy

    echo "Client installed successfully."
    sleep 1
    menu
}

install_websocket() {
    banner
    echo "[ Anti-DPI WebSocket + TLS Mode Installing... ]"

    read -p "Enter domain for TLS (must point to server IP): " DOMAIN
    echo "WEBSOCKET_DOMAIN=\"$DOMAIN\"" >> $CONFIG

    apt install -y nginx

    # GET TLS CERT
    certbot --nginx -d $DOMAIN --non-interactive --agree-tos -m admin@$DOMAIN

    # NGINX WEBSOCKET REVERSE PROXY
    cat >/etc/nginx/sites-available/ws-tunnel.conf <<EOF
server {
    listen 443 ssl;
    server_name $DOMAIN;

    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;

    location /ws/ {
        proxy_pass http://127.0.0.1:7000/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }
}
EOF

    ln -sf /etc/nginx/sites-available/ws-tunnel.conf /etc/nginx/sites-enabled/ws-tunnel.conf
    systemctl restart nginx

    # START WEBSOCKET TCP BRIDGE
    cat >/etc/systemd/system/ws-tunnel.service <<EOF
[Unit]
Description=TCP over WebSocket Tunnel
After=network.target

[Service]
ExecStart=/usr/bin/socat TCP-LISTEN:7000,reuseaddr,fork SYSTEM:'socat - TCP:localhost:22'
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable ws-tunnel
    systemctl restart ws-tunnel

    echo ""
    echo "======================"
    echo "ANTI-DPI MODE ENABLED!"
    echo "======================"
    echo ""
    echo "Client must connect using WSTunnel to:"
    echo "  wss://$DOMAIN/ws/"
    echo ""

    sleep 2
    menu
}

show_status() {
    banner

    echo "----- BACKHAUL (SSH Tunnel) -----"
    systemctl status backhaul --no-pager
    echo ""

    echo "----- HAProxy -----"
    systemctl status haproxy --no-pager
    echo ""

    echo "----- WebSocket Anti-DPI -----"
    systemctl status ws-tunnel --no-pager 2>/dev/null || echo "Not installed"
    echo ""

    source $CONFIG
    echo "----- PORT CHECK -----"
    for p in $(echo $SERVER_PORTS | sed 's/,/ /g'); do
        echo -n "Port $p: "
        nc -zv $SERVER_IP $p >/dev/null 2>&1 && echo "OK ✓" || echo "FAIL ✗"
    done

    read -p "Press Enter..." x
    menu
}

menu
