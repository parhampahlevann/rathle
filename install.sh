sudo bash -c 'cat > /tmp/rathole-install.sh << "EOF"
#!/bin/bash
set -e

# Colors
RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"; BLUE="\033[0;34m"; CYAN="\033[0;36m"; NC="\033[0m"
ok(){ echo -e "${GREEN}[✓] $1${NC}"; }
err(){ echo -e "${RED}[✗] $1${NC}"; }
warn(){ echo -e "${YELLOW}[!] $1${NC}"; }

# Banner
banner(){
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════╗"
    echo "║     Rathole Tunnel Manager - Direct      ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Fix system issues
fix_system(){
    warn "Preparing system..."
    for lock in /var/lib/apt/lists/lock /var/lib/dpkg/lock; do
        [ -f "$lock" ] && rm -f "$lock" 2>/dev/null
    done
    apt-get update 2>/dev/null || true
}

# Install dependencies
install_deps(){
    warn "Installing tools..."
    for tool in curl wget tar openssl; do
        if ! command -v $tool >/dev/null 2>&1; then
            apt-get install -y $tool 2>/dev/null || true
        fi
    done
}

# Install Rathole - Multiple Methods
install_rathole(){
    local VERSION="0.5.0"
    local CONFIG_DIR="/root/rathole-core"
    local BIN_SYSTEM="/usr/local/bin/rathole"
    
    mkdir -p "$CONFIG_DIR"
    
    # Detect architecture
    case $(uname -m) in
        x86_64|amd64) ARCH="x86_64" ;;
        aarch64|arm64) ARCH="aarch64" ;;
        armv7l) ARCH="armv7" ;;
        *) ARCH="x86_64" ;;
    esac
    
    ok "System: $(uname -m) -> $ARCH"
    
    # Method 1: Direct download from rathole-org
    warn "Method 1: Downloading from official repo..."
    URL1="https://github.com/rathole-org/rathole/releases/download/v$VERSION/rathole-$VERSION-$ARCH-unknown-linux-gnu.tar.gz"
    URL2="https://github.com/rathole-org/rathole/releases/download/v0.4.8/rathole-0.4.8-$ARCH-unknown-linux-gnu.tar.gz"
    
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"
    
    if curl -fsSL "$URL1" -o rathole.tar.gz || curl -fsSL "$URL2" -o rathole.tar.gz; then
        tar -xzf rathole.tar.gz 2>/dev/null || true
        BIN=$(find . -name rathole -type f | head -1)
        if [ -f "$BIN" ]; then
            cp "$BIN" "$CONFIG_DIR/rathole"
            cp "$BIN" "$BIN_SYSTEM" 2>/dev/null
            chmod +x "$CONFIG_DIR/rathole"
            ok "Rathole installed to $CONFIG_DIR/rathole"
            cd /
            rm -rf "$TEMP_DIR"
            return 0
        fi
    fi
    
    # Method 2: Try Musixal repository
    warn "Method 2: Trying Musixal repo..."
    if curl -fsSL "https://github.com/Musixal/rathole-tunnel/raw/main/core/rathole.zip" -o rathole.zip; then
        if command -v unzip >/dev/null 2>&1; then
            unzip -q rathole.zip -d "$CONFIG_DIR" 2>/dev/null
            chmod +x "$CONFIG_DIR/rathole" 2>/dev/null || true
            ok "Installed from Musixal repo"
            return 0
        fi
    fi
    
    err "All download methods failed"
    return 1
}

# Create tunnel configuration
create_tunnel(){
    local CONFIG_DIR="/root/rathole-core"
    
    echo -e "${CYAN}"
    echo "Select tunnel type:"
    echo "1) Iran Server (Accepts connections)"
    echo "2) Foreign Client (Connects to Iran)"
    echo -e "${NC}"
    
    read -p "Choice [1-2]: " choice
    
    if [ "$choice" = "1" ]; then
        read -p "Port [2333]: " port
        port=${port:-2333}
        token=$(openssl rand -hex 32 2>/dev/null || echo "default_$(date +%s)")
        
        cat > "$CONFIG_DIR/server.toml" << CFG
[server]
bind_addr = "0.0.0.0:$port"
default_token = "$token"

[server.services.tunnel]
bind_addr = "0.0.0.0:$port"
type = "tcp+udp"
nodelay = true
CFG
        
        ok "Iran server config created!"
        echo -e "${YELLOW}Token: $token${NC}"
        
    elif [ "$choice" = "2" ]; then
        read -p "Iran server IP: " ip
        read -p "Port [2333]: " port
        port=${port:-2333}
        read -p "Token from Iran server: " token
        
        cat > "$CONFIG_DIR/client.toml" << CFG
[client]
remote_addr = "$ip:$port"
default_token = "$token"

[client.services.tunnel]
local_addr = "127.0.0.1:$port"
type = "tcp+udp"
nodelay = true
CFG
        
        ok "Foreign client config created!"
    else
        err "Invalid choice"
    fi
}

# Main menu
main_menu(){
    while true; do
        banner
        
        echo -e "${CYAN}Main Menu:${NC}"
        echo -e "1) ${GREEN}Install Rathole Core${NC}"
        echo -e "2) ${YELLOW}Create Tunnel${NC}"
        echo -e "3) ${BLUE}Show Status${NC}"
        echo -e "4) ${RED}Exit${NC}"
        echo ""
        
        read -p "Select option: " option
        
        case $option in
            1)
                fix_system
                install_deps
                install_rathole
                ;;
            2)
                create_tunnel
                ;;
            3)
                echo -e "${CYAN}Status:${NC}"
                if [ -f "/root/rathole-core/rathole" ]; then
                    ok "Rathole: INSTALLED"
                else
                    err "Rathole: NOT INSTALLED"
                fi
                if [ -f "/root/rathole-core/server.toml" ]; then
                    ok "Iran config: PRESENT"
                fi
                if [ -f "/root/rathole-core/client.toml" ]; then
                    ok "Foreign config: PRESENT"
                fi
                ;;
            4)
                ok "Goodbye!"
                exit 0
                ;;
            *)
                err "Invalid option"
                ;;
        esac
        
        echo ""
        read -p "Press Enter to continue..."
    done
}

# Start
[ "$EUID" -ne 0 ] && { err "Run with sudo"; exit 1; }
main_menu
EOF
chmod +x /tmp/rathole-install.sh
/tmp/rathole-install.sh'
