#!/bin/bash
clear

CONFIG_PATH="/root/config.toml"
SERVICE="/etc/systemd/system/backhaul.service"
BIN="/usr/local/bin/backhaul"

# ---------------- COLORS ----------------
RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
CYAN='\e[36m'
NC='\e[0m'

# ---------------- MENU ----------------
show_menu() {
clear
echo -e "${CYAN}=========== Backhaul Installer Menu ===========${NC}"
echo -e "1) Install Backhaul SERVER"
echo -e "2) Install Backhaul CLIENT"
echo -e "3) Enable BBR"
echo -e "4) Reset Backhaul"
echo -e "5) Change DNS"
echo -e "6) Change MTU"
echo -e "7) Reboot"
echo -e "0) Exit"
echo -e "${CYAN}===============================================${NC}"
read -p "Select: " CH
case $CH in
1) install_server ;;
2) install_client ;;
3) enable_bbr ;;
4) reset_backhaul ;;
5) change_dns ;;
6) change_mtu ;;
7) reboot_system ;;
0) exit 0 ;;
*) show_menu ;;
esac
}

# ---------------- INSTALL SERVER ----------------
install_server() {
clear
echo -e "${CYAN}=== Backhaul Server Install ===${NC}"

read -p "Enter Token: " TOKEN
read -p "Transport (tcp/tcpmux/ws/wss/wsmux/wssmux): " TRANSPORT
read -p "Listen Port: " PORT

# Download binary
curl -L -o $BIN https://raw.githubusercontent.com/backhaul-labs/backhaul/master/backhaul-linux-amd64
chmod +x $BIN

cat <<EOF > $CONFIG_PATH
[server]
bind_addr = "0.0.0.0:${PORT}"
transport = "${TRANSPORT}"
token = "${TOKEN}"
accept_udp = true
keepalive_period = 75
heartbeat = 40
nodelay = true
channel_size = 2048
mux_con = 4
mux_version = 1
mux_framesize = 32768
mux_recievebuffer = 4194304
mux_streambuffer = 65536
sniffer = false
web_port = 2060
log_level = "info"

ports = ["443", "4000=5000"]
EOF

cat <<EOF > $SERVICE
[Unit]
Description=Backhaul Server
After=network.target

[Service]
ExecStart=${BIN} -c ${CONFIG_PATH}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable backhaul
systemctl restart backhaul

echo -e "${GREEN}Backhaul SERVER installed successfully.${NC}"
sleep 2
show_menu
}

# ---------------- INSTALL CLIENT ----------------
install_client() {
clear
echo -e "${CYAN}=== Backhaul Client Install ===${NC}"

read -p "Server Address: " HOST
read -p "Server Port: " PORT
read -p "Token: " TOKEN
read -p "Transport: " TRANSPORT

curl -L -o $BIN https://raw.githubusercontent.com/backhaul-labs/backhaul/master/backhaul-linux-amd64
chmod +x $BIN

cat <<EOF > $CONFIG_PATH
[client]
server_addr = "${HOST}:${PORT}"
transport = "${TRANSPORT}"
token = "${TOKEN}"
keepalive_period = 75
channel_size = 2048
mux_con = 4
mux_framesize = 32768
log_level = "info"

forwards = [
"8080=localhost:80"
]
EOF

cat <<EOF > $SERVICE
[Unit]
Description=Backhaul Client
After=network.target

[Service]
ExecStart=${BIN} -c ${CONFIG_PATH}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable backhaul
systemctl restart backhaul

echo -e "${GREEN}Backhaul CLIENT installed successfully.${NC}"
sleep 2
show_menu
}

# ---------------- ENABLE BBR ----------------
enable_bbr() {
echo -e "${CYAN}Enabling BBR...${NC}"
echo "net.core.default_qdisc=fq" > /etc/sysctl.d/bbr.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.d/bbr.conf
sysctl --system
echo -e "${GREEN}BBR enabled.${NC}"
sleep 1
show_menu
}

# ---------------- RESET BACKHAUL ----------------
reset_backhaul() {
systemctl stop backhaul
rm -f $CONFIG_PATH
rm -f $SERVICE
systemctl daemon-reload
echo -e "${YELLOW}Backhaul reset completed.${NC}"
sleep 1
show_menu
}

# ---------------- CHANGE DNS ----------------
change_dns() {
read -p "Enter new DNS (example: 1.1.1.1): " DNS
echo "nameserver $DNS" > /etc/resolv.conf
echo -e "${GREEN}DNS updated.${NC}"
sleep 1
show_menu
}

# ---------------- CHANGE MTU ----------------
change_mtu() {
read -p "Enter MTU value: " MTU
ip link set dev eth0 mtu $MTU
echo -e "${GREEN}MTU updated.${NC}"
sleep 1
show_menu
}

# ---------------- REBOOT ----------------
reboot_system() {
read -p "Reboot now? (y/n): " A
[[ $A == "y" ]] && reboot
show_menu
}

show_menu
