#!/bin/bash

# ==========================================================
#  Multiport Reverse Tunnel Manager (Server & Client)
#  Auto Install + Status Monitoring + Encryption (SSH-based)
# ==========================================================

CONFIG_FILE="/etc/backhaul.conf"

menu() {
    clear
    echo "=============================================="
    echo "     Multiport Secure Reverse Tunnel Setup"
    echo "=============================================="
    echo "1) Install Server (Foreign Server)"
    echo "2) Install Client (Iran Server)"
    echo "3) Show Status & Ping Test"
    echo "4) Exit"
    echo "=============================================="
    read -p "Choose an option: " opt

    case $opt in
        1) install_server ;;
        2) install_client ;;
        3) show_status ;;
        4) exit 0 ;;
        *) echo "Invalid option"; sleep 1; menu ;;
    esac
}

install_dependencies() {
    apt update -y
    apt install -y autossh openssh-server
}

install_server() {
    install_dependencies

    echo ""
    read -p "Enter tunnel ports (comma separated, e.g. 8000,8001,8002): " ports
    read -p "Enter SSH username to be used: " ssh_user

    # Create system user
    useradd -m -s /bin/bash $ssh_user

    # Enable SSH access
    mkdir -p /home/$ssh_user/.ssh
    chmod 700 /home/$ssh_user/.ssh

    echo "SERVER_PORTS=\"$ports\"" > $CONFIG_FILE
    echo "SERVER_USER=\"$ssh_user\"" >> $CONFIG_FILE

    echo "Server installation completed."
    echo "Use 'ssh-copy-id $ssh_user@SERVER_IP' from client machine."
    sleep 2
    menu
}

install_client() {
    install_dependencies

    source $CONFIG_FILE

    read -p "Enter Server Public IP: " server_ip

    echo "SERVER_IP=\"$server_ip\"" >> $CONFIG_FILE

    # Create autossh service
    cat >/etc/systemd/system/backhaul.service <<EOF
[Unit]
Description=Encrypted Multiport Reverse Backhaul Tunnel
After=network.target

[Service]
User=root
Environment="AUTOSSH_GATETIME=0"
ExecStart=/usr/bin/autossh -M 0 \\
EOF

    for p in $(echo $SERVER_PORTS | sed "s/,/ /g"); do
        echo " -R ${p}:localhost:${p} ${SERVER_USER}@${SERVER_IP} -N \\" >> /etc/systemd/system/backhaul.service
    done

    sed -i '$ s/ \\$//' /etc/systemd/system/backhaul.service

    cat >>/etc/systemd/system/backhaul.service <<EOF

Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable backhaul
    systemctl start backhaul

    echo "Client setup completed and tunnel activated."
    sleep 2
    menu
}

show_status() {
    clear
    source $CONFIG_FILE

    echo "=============================================="
    echo "         Backhaul Connection Status"
    echo "=============================================="

    systemctl is-active --quiet backhaul
    if [ $? -eq 0 ]; then
        echo "Tunnel Status: ACTIVE ✓"
    else
        echo "Tunnel Status: INACTIVE ✗"
    fi

    echo ""
    echo "Ping Test:"
    ping -c 4 $SERVER_IP

    echo ""
    echo "Open Reverse Ports on Server:"
    for p in $(echo $SERVER_PORTS | sed "s/,/ /g"); do
        echo -n "Port $p: "
        nc -zv $SERVER_IP $p >/dev/null 2>&1 && echo "Open ✓" || echo "Closed ✗"
    done

    echo ""
    read -p "Press Enter to return to menu..."
    menu
}

menu
