#!/bin/bash
# ============================================
# Rathole Installer - No Process Substitution
# Version: 5.1-fixed
# ============================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Main Configuration
RATHOLE_VERSION="0.5.0"
CONFIG_DIR="/root/rathole-core"
INSTALL_DIR="/usr/local/bin"

# Banner
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════╗"
    echo "║     Rathole Installer - Simple v5.1      ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${YELLOW}Simple installation without complex commands${NC}"
    echo -e "${BLUE}==============================================${NC}"
}

# Check root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR] Please run with sudo${NC}"
        echo -e "${YELLOW}Usage: sudo bash ./rathole-install.sh${NC}"
        exit 1
    fi
}

# Install dependencies
install_deps() {
    echo -e "${YELLOW}[*] Installing required tools...${NC}"
    
    # Fix apt locks (best-effort)
    for lock in /var/lib/apt/lists/lock /var/lib/dpkg/lock /var/lib/apt/lists/lock-frontend /var/lib/dpkg/lock-frontend; do
        if [[ -e $lock ]]; then
            rm -f $lock 2>/dev/null || true
        fi
    done
    
    # Update and install (best-effort)
    apt-get update 2>/dev/null || true
    
    # Ensure these tools exist (including openssl)
    for tool in curl wget tar openssl; do
        if ! command -v $tool >/dev/null 2>&1; then
            echo -e "${YELLOW}[-] Installing $tool...${NC}"
            apt-get install -y $tool 2>/dev/null || {
                echo -e "${RED}[WARN] Could not install $tool via apt-get. Please install it manually.${NC}"
            }
        fi
    done
    
    echo -e "${GREEN}[✓] Tools ready (curl/wget/tar/openssl checked)${NC}"
}

# Download helper (tries wget then curl)
download_file() {
    local url="$1"
    local out="$2"

    if command -v wget >/dev/null 2>&1; then
        wget -q "$url" -O "$out" && return 0
    fi

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$out" && return 0
    fi

    return 1
}

# Download and install Rathole
install_rathole() {
    echo -e "${GREEN}[*] Installing Rathole v${RATHOLE_VERSION}${NC}"
    
    # Clean old install
    rm -rf "$CONFIG_DIR" 2>/dev/null || true
    mkdir -p "$CONFIG_DIR"

    # Ensure INSTALL_DIR exists
    mkdir -p "$INSTALL_DIR" 2>/dev/null || true
    
    # Detect architecture
    ARCH=$(uname -m)
    case $ARCH in
        x86_64|amd64) BIN_ARCH="x86_64" ;;
        aarch64|arm64) BIN_ARCH="aarch64" ;;
        armv7l) BIN_ARCH="armv7" ;;
        *) BIN_ARCH="x86_64" ;;
    esac
    
    echo -e "${YELLOW}[-] Architecture: $BIN_ARCH${NC}"
    
    # Primary and fallback URLs
    URL_PRIMARY="https://github.com/rathole-org/rathole/releases/download/v${RATHOLE_VERSION}/rathole-${RATHOLE_VERSION}-${BIN_ARCH}-unknown-linux-gnu.tar.gz"
    URL_FALLBACK="https://github.com/rathole-org/rathole/releases/download/v0.4.8/rathole-0.4.8-${BIN_ARCH}-unknown-linux-gnu.tar.gz"

    echo -e "${YELLOW}[-] Downloading from: $URL_PRIMARY${NC}"
    
    TEMP_DIR=$(mktemp -d)
    # Ensure cleanup on exit
    trap 'rm -rf "$TEMP_DIR"' EXIT INT TERM

    cd "$TEMP_DIR" || { echo -e "${RED}[ERROR] Could not enter temp dir${NC}"; return 1; }
    
    # Try primary then fallback
    if ! download_file "$URL_PRIMARY" rathole.tar.gz; then
        echo -e "${RED}[!] Primary download failed, trying fallback...${NC}"
        if ! download_file "$URL_FALLBACK" rathole.tar.gz; then
            echo -e "${RED}[ERROR] All downloads failed. Check network or URL.${NC}"
            return 1
        fi
    fi
    
    # Extract and install
    if [[ -f "rathole.tar.gz" ]]; then
        tar -xzf rathole.tar.gz 2>/dev/null || {
            echo -e "${RED}[ERROR] Failed to extract archive${NC}"
            return 1
        }
        
        # Find binary (search deeper too)
        BINARY=$(find . -type f -name "rathole" | head -n 1 || true)
        
        if [[ -n "$BINARY" && -f "$BINARY" ]]; then
            # Copy into config dir and system dir using install for proper perms
            install -Dm755 "$BINARY" "$CONFIG_DIR/rathole" || cp "$BINARY" "$CONFIG_DIR/rathole"
            chmod +x "$CONFIG_DIR/rathole" || true
            
            # Also copy to /usr/local/bin for easy access (best-effort)
            if install -Dm755 "$BINARY" "$INSTALL_DIR/rathole" 2>/dev/null; then
                chmod +x "$INSTALL_DIR/rathole" 2>/dev/null || true
            else
                cp "$BINARY" "$INSTALL_DIR/rathole" 2>/dev/null || true
            fi
            
            echo -e "${GREEN}[✓] Rathole installed successfully!${NC}"
            echo -e "${YELLOW}Main binary: $CONFIG_DIR/rathole${NC}"
            echo -e "${YELLOW}System binary: $INSTALL_DIR/rathole${NC}"
        else
            echo -e "${RED}[ERROR] Could not find rathole binary inside archive${NC}"
            return 1
        fi
    else
        echo -e "${RED}[ERROR] Download failed completely${NC}"
        return 1
    fi

    # Cleanup handled by trap
    cd / || true
}

# Create tunnel configuration
create_config() {
    echo -e "${CYAN}[Tunnel Setup]${NC}"
    
    if [[ ! -f "$CONFIG_DIR/rathole" ]]; then
        echo -e "${RED}[ERROR] Install Rathole first!${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}Select server type:${NC}"
    echo "1) Iran Server (Accepts connections)"
    echo "2) Foreign Server (Connects to Iran)"
    
    read -p "Choice [1-2]: " choice
    
    if [[ $choice == "1" ]]; then
        # Iran server config
        read -p "Port [2333]: " port
        port=${port:-2333}
        
        token=$(openssl rand -hex 32 2>/dev/null || echo "default_token_$(date +%s)")
        
        cat > "$CONFIG_DIR/server.toml" << EOF
[server]
bind_addr = "0.0.0.0:$port"
default_token = "$token"

[server.services.main_tunnel]
bind_addr = "0.0.0.0:$port"
type = "tcp+udp"
nodelay = true
EOF
        
        echo -e "${GREEN}[✓] Iran server config created${NC}"
        echo -e "${YELLOW}Config file: $CONFIG_DIR/server.toml${NC}"
        echo -e "${YELLOW}Token: $token${NC}"
        
    elif [[ $choice == "2" ]]; then
        # Foreign server config
        read -p "Iran server IP: " ip
        read -p "Port [2333]: " port
        port=${port:-2333}
        
        token=$(openssl rand -hex 32 2>/dev/null || echo "default_token_$(date +%s)")
        
        cat > "$CONFIG_DIR/client.toml" << EOF
[client]
remote_addr = "$ip:$port"
default_token = "$token"
retry_interval = 1

[client.services.main_tunnel]
local_addr = "127.0.0.1:$port"
type = "tcp+udp"
nodelay = true
EOF
        
        echo -e "${GREEN}[✓] Foreign server config created${NC}"
        echo -e "${YELLOW}Config file: $CONFIG_DIR/client.toml${NC}"
    else
        echo -e "${RED}[ERROR] Invalid choice${NC}"
    fi
}

# Show status
show_status() {
    echo -e "${CYAN}[System Status]${NC}"
    
    if [[ -f "$CONFIG_DIR/rathole" ]]; then
        echo -e "${GREEN}✓ Rathole: INSTALLED${NC}"
        echo -e "  Location: $CONFIG_DIR/rathole"
        
        if [[ -f "$INSTALL_DIR/rathole" ]]; then
            echo -e "  System: $INSTALL_DIR/rathole"
        fi
    else
        echo -e "${RED}✗ Rathole: NOT INSTALLED${NC}"
    fi
    
    echo -e "\n${YELLOW}Configuration:${NC}"
    if [[ -f "$CONFIG_DIR/server.toml" ]]; then
        echo -e "  ${GREEN}✓ server.toml (Iran)${NC}"
    fi
    if [[ -f "$CONFIG_DIR/client.toml" ]]; then
        echo -e "  ${GREEN}✓ client.toml (Foreign)${NC}"
    fi
}

# Main menu
main_menu() {
    while true; do
        show_banner
        
        echo -e "${CYAN}Main Menu:${NC}"
        echo -e "1) Install Rathole Core"
        echo -e "2) Create Tunnel Configuration"
        echo -e "3) Show Status"
        echo -e "4) Exit"
        echo -e "${BLUE}=========================${NC}"
        
        read -p "Select option: " choice
        
        case $choice in
            1)
                install_deps
                if ! install_rathole; then
                    echo -e "${RED}[ERROR] Installation failed. See messages above.${NC}"
                fi
                ;;
            2)
                create_config
                ;;
            3)
                show_status
                ;;
            4)
                echo -e "${GREEN}Goodbye!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option${NC}"
                ;;
        esac
        
        echo -e "\n${YELLOW}Press Enter to continue...${NC}"
        read -r
    done
}

# Start installation
start_install() {
    check_root
    show_banner
    
    echo -e "${GREEN}[*] Starting automatic installation...${NC}"
    install_deps
    if ! install_rathole; then
        echo -e "${RED}[ERROR] Automatic installation failed. You can try the menu options to retry.${NC}"
    else
        echo -e "\n${GREEN}════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}✅ Installation Complete!${NC}"
        echo -e "${GREEN}════════════════════════════════════════════════${NC}"
        echo -e "\n${YELLOW}Quick commands:${NC}"
        echo -e "  Test: $CONFIG_DIR/rathole --version"
        echo -e "  Run: $CONFIG_DIR/rathole /path/to/config.toml"
    fi

    echo -e "\n${YELLOW}Now starting interactive menu...${NC}"
    sleep 1
    main_menu
}

# ============================================
# START HERE - Simple and direct
# ============================================
start_install
