install_mtproxy_action() {
  clear
  echo ""
  draw_line "$CYAN" "=" 40
  echo -e "${BOLD_GREEN}     📥 Install MTProto Proxy (Official)${RESET}"
  draw_line "$CYAN" "=" 40
  echo ""

  # 1. آپدیت سیستم
  echo -e "${CYAN}Updating system packages...${RESET}"
  sudo apt update
  sudo apt install -y git make build-essential libssl-dev zlib1g-dev curl wget tar gzip xxd

  # 2. بررسی باینری موجود
  local skip_compile=false
  if [ -f "/usr/local/bin/mtproto-proxy" ]; then
      echo -e "${YELLOW}Existing MTProxy binary found.${RESET}"
      echo -e -n "👉 ${BOLD_MAGENTA}Do you want to use the existing binary? (Y/n): ${RESET}"
      read use_existing
      if [[ -z "$use_existing" || "$use_existing" =~ ^[Yy]$ ]]; then
          skip_compile=true
          print_success "Skipping compilation."
      fi
  fi

  if [ "$skip_compile" = false ]; then
      echo -e "${CYAN}Cloning official MTProxy repository...${RESET}"
      if [ -d "MTProxy" ]; then
        rm -rf MTProxy
      fi
      
      # استفاده از گیت‌هاب با لینک جایگزین
      git clone https://github.com/TelegramMessenger/MTProxy.git
      
      if [ ! -d "MTProxy" ]; then
          print_error "Failed to clone repository. Trying alternative..."
          git clone https://gitlab.com/TelegramMessenger/MTProxy.git
      fi
      
      if [ ! -d "MTProxy" ]; then
          print_error "Cannot clone MTProxy repository. Check your internet connection."
          echo -e "${BOLD_MAGENTA}Press Enter to return...${RESET}"
          read
          return 1
      fi
      
      cd MTProxy
    
      # Patch برای PIDs بزرگ
      echo -e "${CYAN}Patching source for large PIDs...${RESET}"
      if [ -f "common/pid.c" ]; then
        sed -i 's/assert (!(p & 0xffff0000));/\/\/ assert (!(p \& 0xffff0000));/g' common/pid.c
      fi
    
      echo -e "${CYAN}Compiling source code...${RESET}"
      
      # کامپایل در پس‌زمینه با نمایش پیشرفت
      make clean > /dev/null 2>&1
      make > /tmp/mtpulse_make.log 2>&1 &
      local make_pid=$!
      local counter=1
      
      # مخفی کردن کرسر
      tput civis
      
      while kill -0 $make_pid 2>/dev/null; do
          printf "\r${BOLD_MAGENTA}Compiling... ${WHITE}[ %d ]${RESET}" "$counter"
          ((counter++))
          sleep 0.5
      done
      
      # بازیابی کرسر
      tput cnorm
      echo ""
      
      wait $make_pid
      local make_status=$?
      
      if [ $make_status -ne 0 ] || [ ! -f "objs/bin/mtproto-proxy" ]; then
        print_error "Compilation failed."
        echo -e "${YELLOW}--- Last 20 lines of error log ---${RESET}"
        tail -n 20 /tmp/mtpulse_make.log
        
        echo -e "\n${CYAN}Trying alternative compilation method...${RESET}"
        echo -e "${YELLOW}Installing dependencies...${RESET}"
        sudo apt install -y cmake
        
        if [ -f "CMakeLists.txt" ]; then
            mkdir -p build
            cd build
            cmake .. > /tmp/mtpulse_cmake.log 2>&1
            make >> /tmp/mtpulse_cmake.log 2>&1
            
            if [ -f "mtproto-proxy" ]; then
                sudo cp mtproto-proxy /usr/local/bin/mtproto-proxy
                cd ../..
                skip_compile=true
                print_success "Compilation successful with CMake!"
            else
                cd ..
                echo -e "${YELLOW}--- CMake error log ---${RESET}"
                tail -n 20 /tmp/mtpulse_cmake.log
                cd ..
                echo -e "${BOLD_MAGENTA}Press Enter to return...${RESET}"
                read
                return 1
            fi
        else
            cd ..
            echo -e "${BOLD_MAGENTA}Press Enter to return...${RESET}"
            read
            return 1
        fi
      else
        echo -e "${CYAN}Installing binary...${RESET}"
        sudo cp objs/bin/mtproto-proxy /usr/local/bin/mtproto-proxy
        sudo chmod +x /usr/local/bin/mtproto-proxy
        cd ..
        rm -rf MTProxy
        print_success "MTProxy installed to /usr/local/bin/mtproto-proxy"
      fi
  fi

  # 3. دانلود فایل‌های کانفیگ
  echo -e "${CYAN}Downloading configuration files...${RESET}"
  sudo mkdir -p /etc/mtpulse
  
  # تلاش برای دانلود با چندین منبع
  echo -e "${YELLOW}Trying to download proxy-secret...${RESET}"
  
  # لیست منابع مختلف
  local sources=(
    "https://core.telegram.org/getProxySecret"
    "https://raw.githubusercontent.com/TelegramMessenger/MTProxy/master/proxy-secret"
    "https://gitlab.com/TelegramMessenger/MTProxy/-/raw/master/proxy-secret"
  )
  
  local downloaded=false
  for source in "${sources[@]}"; do
    echo -e "Trying: $source"
    if sudo curl -s --max-time 10 -f -o /etc/mtpulse/proxy-secret "$source"; then
      print_success "proxy-secret downloaded successfully!"
      downloaded=true
      break
    fi
  done
  
  if [ "$downloaded" = false ]; then
    print_error "Failed to download proxy-secret. Creating default..."
    echo "default" | sudo tee /etc/mtpulse/proxy-secret > /dev/null
  fi
  
  echo -e "${YELLOW}Trying to download proxy-multi.conf...${RESET}"
  downloaded=false
  local multi_sources=(
    "https://core.telegram.org/getProxyConfig"
    "https://raw.githubusercontent.com/TelegramMessenger/MTProxy/master/proxy-multi.conf"
    "https://gitlab.com/TelegramMessenger/MTProxy/-/raw/master/proxy-multi.conf"
  )
  
  for source in "${multi_sources[@]}"; do
    echo -e "Trying: $source"
    if sudo curl -s --max-time 10 -f -o /etc/mtpulse/proxy-multi.conf "$source"; then
      print_success "proxy-multi.conf downloaded successfully!"
      downloaded=true
      break
    fi
  done
  
  if [ "$downloaded" = false ]; then
    print_error "Failed to download proxy-multi.conf. Creating default..."
    cat << 'EOF' | sudo tee /etc/mtpulse/proxy-multi.conf > /dev/null
default 0.0.0.0:443
stat 127.0.0.1:80
syslog
user nobody
workers 4
proxy 0.0.0.0:443 {
    secret 00000000000000000000000000000000
    backlog 16384
    tcp_fastopen
    nat_info
}
EOF
  fi

  # 4. دریافت اطلاعات از کاربر
  echo ""
  echo -e "${CYAN}--- Configuration ---${RESET}"
  
  # پورت
  local port
  while true; do
    echo -e -n "👉 ${BOLD_MAGENTA}Enter port (default 443): ${RESET}"
    read port
    port=${port:-443}
    if [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )); then
      break
    else
      print_error "Invalid port."
    fi
  done

  # سکرت
  echo -e "${CYAN}Generating secret...${RESET}"
  local secret=$(head -c 16 /dev/urandom | xxd -ps)
  echo -e "Generated Secret: ${WHITE}$secret${RESET}"
  
  # 5. ایجاد سرویس سیستم
  echo -e "${CYAN}Creating systemd service...${RESET}"
  
  local exec_start="/usr/local/bin/mtproto-proxy -u nobody -p 8888 -H $port -S $secret --aes-pwd /etc/mtpulse/proxy-secret /etc/mtpulse/proxy-multi.conf -M 1 --allow-skip-dh"
  
  cat <<EOF | sudo tee /etc/systemd/system/mtpulse.service
[Unit]
Description=MTPulse MTProto Proxy (Official)
After=network.target

[Service]
Type=simple
ExecStart=$exec_start
Restart=on-failure
RestartSec=5
User=nobody
Group=nogroup
LimitNOFILE=999999
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=mtpulse

# Security
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/etc/mtpulse

[Install]
WantedBy=multi-user.target
EOF

  sudo systemctl daemon-reload
  sudo systemctl enable mtpulse
  sudo systemctl start mtpulse

  sleep 2
  
  # بررسی وضعیت سرویس
  if systemctl is-active --quiet mtpulse; then
    print_success "MTPulse service started successfully!"
  else
    print_error "Service failed to start. Checking logs..."
    sudo journalctl -u mtpulse -n 20 --no-pager
    echo -e "${YELLOW}Press Enter to continue...${RESET}"
    read
  fi

  # نمایش اطلاعات
  local public_ip=""
  local ip_services=(
    "https://api.ipify.org"
    "https://icanhazip.com"
    "https://checkip.amazonaws.com"
    "https://ifconfig.me/ip"
  )
  
  for service in "${ip_services[@]}"; do
    public_ip=$(curl -s --max-time 5 "$service" 2>/dev/null)
    if [[ -n "$public_ip" && "$public_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      break
    fi
  done
  
  if [[ -z "$public_ip" ]]; then
    public_ip="YOUR_SERVER_IP"
  else
    # ذخیره IP برای استفاده بعدی
    echo "$public_ip" | sudo tee /etc/mtpulse/public_ip > /dev/null
  fi
  
  echo ""
  draw_line "$GREEN" "=" 50
  echo -e "${BOLD_GREEN}     🚀 Proxy Installation Complete${RESET}"
  draw_line "$GREEN" "=" 50
  echo ""
  echo -e "${BOLD_CYAN}📊 Connection Details:${RESET}"
  echo -e "  ${WHITE}IP Address:${RESET} ${BOLD_GREEN}$public_ip${RESET}"
  echo -e "  ${WHITE}Port:${RESET} ${BOLD_GREEN}$port${RESET}"
  echo -e "  ${WHITE}Secret:${RESET} ${BOLD_GREEN}$secret${RESET}"
  echo ""
  echo -e "${BOLD_CYAN}🔗 Proxy Link:${RESET}"
  echo -e "  tg://proxy?server=$public_ip&port=$port&secret=$secret"
  echo ""
  echo -e "${BOLD_CYAN}🔗 Alternative Link (with dd):${RESET}"
  echo -e "  tg://proxy?server=$public_ip&port=$port&secret=dd$secret"
  echo ""
  echo -e "${BOLD_CYAN}📝 For MTProto Bot:${RESET}"
  echo -e "  $public_ip:$port\ndd$secret"
  echo ""
  draw_line "$GREEN" "=" 50
  
  echo -e "\n${YELLOW}⚠️  Important Notes:${RESET}"
  echo -e "1. Make sure port $port is open in firewall"
  echo -e "2. Use service management menu to check status"
  echo -e "3. Add AD tag via option 3 in main menu"
  
  echo -e "\n${BOLD_MAGENTA}Press Enter to return to main menu...${RESET}"
  read
}
