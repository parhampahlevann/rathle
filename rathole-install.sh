sudo bash -c 'cat > /tmp/rathole-manager-en.sh <<'\''EOF'\'''
# <<< PASTE THE SCRIPT CONTENT BELOW THIS LINE >>>
#!/usr/bin/env bash
# rathole-manager-en.sh
# Combined auto-diagnose, optional install, tunnel-config creation, and systemd service creation.
# Usage:
#   Interactive: sudo ./rathole-manager-en.sh
#   Diagnose only: ./rathole-manager-en.sh [VERSION]
#   Diagnose + install: sudo ./rathole-manager-en.sh [VERSION] --install

set -euo pipefail

# -----------------------
# Configuration defaults
# -----------------------
VERSION_DEFAULT="0.5.0"
VERSION="${1:-$VERSION_DEFAULT}"
INSTALL_FLAG="no"
if [[ "${2:-}" == "--install" || "${3:-}" == "--install" ]]; then
  INSTALL_FLAG="yes"
fi

CONFIG_DIR="/root/rathole-core"
INSTALL_DIR="/usr/local/bin"

# -----------------------
# Colors / helpers
# -----------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'
info(){ printf "%b%s%b\n" "$CYAN" "$1" "$NC"; }
ok(){ printf "%b%s%b\n" "$GREEN" "$1" "$NC"; }
warn(){ printf "%b%s%b\n" "$YELLOW" "$1" "$NC"; }
err(){ printf "%b%s%b\n" "$RED" "$1" "$NC"; }
ech(){ printf "%b\n" "$1"; }

# -----------------------
# Utility functions
# -----------------------
check_root_or_warn() {
  if [[ $EUID -ne 0 ]]; then
    warn "You are not running as root. Some operations (install, write to /root or /usr/local/bin, systemd) require sudo/root."
  fi
}

ensure_dirs() {
  mkdir -p "$CONFIG_DIR" 2>/dev/null || true
  mkdir -p "$INSTALL_DIR" 2>/dev/null || true
}

detect_sys_arch() {
  local u
  u="$(uname -m || true)"
  case "$u" in
    x86_64|amd64) echo "x86_64" ;;
    aarch64|arm64) echo "aarch64" ;;
    armv7l) echo "armv7" ;;
    i386|i686) echo "i386" ;;
    *) echo "$u" ;;
  esac
}

download_file() {
  local url="$1" out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 --max-time 60 -o "$out" "$url" && return 0
  fi
  if command -v wget >/dev/null 2>&1; then
    wget -q -O "$out" "$url" && return 0
  fi
  return 1
}

# -----------------------
# Diagnose / Download / Extract / (optional) Install
# -----------------------
run_diagnose_and_optional_install() {
  local ver="${1:-$VERSION}"
  local install_mode="${2:-$INSTALL_FLAG}"

  local TMPDIR
  TMPDIR="$(mktemp -d)"
  trap 'rm -rf "$TMPDIR"' EXIT INT TERM

  local SYS_ARCH
  SYS_ARCH="$(detect_sys_arch)"

  info "System detection: uname -> $(uname -m)  mapped to -> $SYS_ARCH"
  info "Requested rathole version: $ver"
  info "Working temp dir: $TMPDIR"

  local URL_PRIMARY="https://github.com/rathole-org/rathole/releases/download/v${ver}/rathole-${ver}-${SYS_ARCH}-unknown-linux-gnu.tar.gz"
  local URL_FALLBACK="https://github.com/rathole-org/rathole/releases/download/v0.4.8/rathole-0.4.8-${SYS_ARCH}-unknown-linux-gnu.tar.gz"

  cd "$TMPDIR" || return 1
  local ARCHIVE="rathole.tar.gz"

  ok "Starting download..."
  if ! download_file "$URL_PRIMARY" "$ARCHIVE"; then
    warn "Primary download failed; trying fallback..."
    if ! download_file "$URL_FALLBACK" "$ARCHIVE"; then
      err "Both primary and fallback downloads failed. Check network or release availability."
      ls -l "$TMPDIR" || true
      return 2
    fi
  fi

  if [[ ! -s "$ARCHIVE" ]]; then
    err "Downloaded archive is empty or missing."
    return 3
  fi
  ok "Downloaded archive size: $(stat -c%s "$ARCHIVE") bytes"

  # Check for HTML content (common if GitHub returned a 404 page)
  if grep -I -m1 -E '<!DOCTYPE|<html|<title>' "$ARCHIVE" >/dev/null 2>&1; then
    warn "Downloaded file contains HTML -> likely a 404/HTML error page instead of tar.gz."
    echo "---- excerpt ----"
    head -c 200 "$ARCHIVE" || true
    echo
    echo "---- end excerpt ----"
    err "Aborting: archive appears to be HTML. Verify the release URL or network access."
    return 4
  fi

  ech
  ok "Archive contents (first 200 lines):"
  tar -tzf "$ARCHIVE" | sed -n '1,200p' || { err "tar could not list archive."; return 5; }

  local EXTRACT_DIR="$TMPDIR/extracted"
  mkdir -p "$EXTRACT_DIR"
  ok "Extracting archive..."
  tar -xzf "$ARCHIVE" -C "$EXTRACT_DIR" || { err "Extraction failed."; return 6; }

  find "$EXTRACT_DIR" -maxdepth 4 -ls || true

  local BIN_PATH
  BIN_PATH="$(find "$EXTRACT_DIR" -type f -iname 'rathole' -print -quit || true)"
  if [[ -z "$BIN_PATH" ]]; then
    err "No file named 'rathole' found inside the archive."
    return 7
  fi

  ok "Candidate binary found: $BIN_PATH"
  if command -v file >/dev/null 2>&1; then
    file "$BIN_PATH" || true
  fi
  stat -c "%A %U %G %s bytes %n" "$BIN_PATH" || true

  if [[ ! -x "$BIN_PATH" ]]; then
    warn "Executable bit not set; attempting chmod +x..."
    chmod +x "$BIN_PATH" || true
  fi

  if command -v ldd >/dev/null 2>&1; then
    ech
    warn "ldd output (may error for static or incompatible-arch binaries):"
    ldd "$BIN_PATH" 2>&1 | sed -n '1,200p' || true
  else
    warn "ldd not available; cannot show linked libraries."
  fi

  ech
  warn "Trying to run '--version' (best-effort):"
  if "$BIN_PATH" --version >/dev/null 2>&1; then
    ok "Binary ran with --version successfully:"
    "$BIN_PATH" --version 2>&1 | sed -n '1,200p'
  else
    warn "Running --version failed or produced no output (can be normal if arch mismatch)."
  fi

  # Install if requested
  if [[ "$install_mode" == "yes" ]]; then
    if [[ $EUID -ne 0 ]]; then
      err "Install requested but not running as root. Re-run with sudo."
      return 8
    fi

    ensure_dirs

    if install -Dm755 "$BIN_PATH" "$CONFIG_DIR/rathole"; then
      ok "Installed to $CONFIG_DIR/rathole"
    else
      warn "install failed; trying cp..."
      cp "$BIN_PATH" "$CONFIG_DIR/rathole" && chmod +x "$CONFIG_DIR/rathole" && ok "Copied to $CONFIG_DIR/rathole" || err "Failed to place binary in $CONFIG_DIR"
    fi

    if install -Dm755 "$BIN_PATH" "$INSTALL_DIR/rathole"; then
      ok "Installed system binary to $INSTALL_DIR/rathole"
    else
      warn "install to $INSTALL_DIR failed; trying cp..."
      cp "$BIN_PATH" "$INSTALL_DIR/rathole" && chmod +x "$INSTALL_DIR/rathole" && ok "Copied to $INSTALL_DIR/rathole" || err "Failed to place binary in $INSTALL_DIR"
    fi

    ok "Suggested test: $CONFIG_DIR/rathole --version"
  fi

  ok "Diagnosis complete."
  return 0
}

# -----------------------
# Tunnel config creation (interactive)
# -----------------------
create_tunnel_config_interactive() {
  ensure_dirs
  if [[ ! -f "$CONFIG_DIR/rathole" ]]; then
    warn "rathole binary not found at $CONFIG_DIR/rathole. If not installed yet, consider using the install option first."
  fi

  echo
  info "Choose tunnel type:"
  echo "1) Iran Server (accept incoming connections)"
  echo "2) Foreign Client (connect to Iran server)"
  read -rp "Choice [1-2]: " choice

  if [[ "$choice" == "1" ]]; then
    read -rp "Port [2333]: " port
    port=${port:-2333}
    if command -v openssl >/dev/null 2>&1; then
      token="$(openssl rand -hex 32 2>/dev/null || echo "default_token_$(date +%s)")"
    else
      token="default_token_$(date +%s)"
    fi

    cat > "$CONFIG_DIR/server.toml" <<EOF
[server]
bind_addr = "0.0.0.0:$port"
default_token = "$token"

[server.services.main_tunnel]
bind_addr = "0.0.0.0:$port"
type = "tcp+udp"
nodelay = true
EOF

    ok "Iran server config created: $CONFIG_DIR/server.toml"
    ech "Token: $token"

  elif [[ "$choice" == "2" ]]; then
    read -rp "Iran server IP: " ip
    read -rp "Port [2333]: " port
    port=${port:-2333}
    if command -v openssl >/dev/null 2>&1; then
      token="$(openssl rand -hex 32 2>/dev/null || echo "default_token_$(date +%s)")"
    else
      token="default_token_$(date +%s)"
    fi

    cat > "$CONFIG_DIR/client.toml" <<EOF
[client]
remote_addr = "$ip:$port"
default_token = "$token"
retry_interval = 1

[client.services.main_tunnel]
local_addr = "127.0.0.1:$port"
type = "tcp+udp"
nodelay = true
EOF

    ok "Foreign client config created: $CONFIG_DIR/client.toml"
    ech "Token: $token"

  else
    err "Invalid choice."
    return 1
  fi
  return 0
}

# -----------------------
# Create systemd service for server or client
# -----------------------
create_and_enable_systemd() {
  if [[ $EUID -ne 0 ]]; then
    err "Systemd creation requires root. Rerun with sudo."
    return 1
  fi

  ensure_dirs

  echo
  info "Create systemd service for:"
  echo "1) Iran Server (uses server.toml)"
  echo "2) Foreign Client (uses client.toml)"
  read -rp "Choice [1-2]: " svc_choice

  if [[ "$svc_choice" == "1" ]]; then
    conf="$CONFIG_DIR/server.toml"
    svc_name="rathole-server.service"
    svc_desc="Rathole Server (Iran)"
  elif [[ "$svc_choice" == "2" ]]; then
    conf="$CONFIG_DIR/client.toml"
    svc_name="rathole-client.service"
    svc_desc="Rathole Client (Foreign)"
  else
    err "Invalid choice."
    return 2
  fi

  if [[ ! -f "$conf" ]]; then
    err "Configuration file $conf not found. Create it first."
    return 3
  fi

  if [[ ! -x "$CONFIG_DIR/rathole" && ! -x "$INSTALL_DIR/rathole" ]]; then
    warn "rathole binary not found in $CONFIG_DIR or $INSTALL_DIR. Proceeding will likely fail—ensure binary is installed."
  fi

  # Prefer system binary if exists
  if [[ -x "$INSTALL_DIR/rathole" ]]; then
    exec_path="$INSTALL_DIR/rathole"
  else
    exec_path="$CONFIG_DIR/rathole"
  fi

  # Create unit content
  unit_path="/etc/systemd/system/$svc_name"
  cat > "$unit_path" <<EOF
[Unit]
Description=$svc_desc
After=network.target

[Service]
Type=simple
ExecStart=$exec_path $conf
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

  ok "Created systemd unit: $unit_path"

  # Reload systemd, enable and start
  systemctl daemon-reload || warn "daemon-reload failed"
  systemctl enable "$svc_name" || warn "enable may have failed"
  systemctl restart "$svc_name" || warn "start/restart may have failed; check logs with: journalctl -u $svc_name -n 200 --no-pager"

  ok "Service $svc_name enabled and restarted (check status with: systemctl status $svc_name)"
  return 0
}

# -----------------------
# Uninstall core / remove config / remove systemd
# -----------------------
uninstall_core() {
  if [[ $EUID -ne 0 ]]; then
    err "Uninstall core requires root. Re-run with sudo."
    return 1
  fi
  warn "Stopping services first (if any)..."
  systemctl stop rathole-server.service rathole-client.service 2>/dev/null || true
  systemctl.disable rathole-server.service rathole-client.service 2>/dev/null || true

# <<< TRUNCATED FOR MESSAGE SIZE - PASTE THE REMAINING SCRIPT FROM THE PREVIOUS MESSAGE >>>
# <<< If you want, I will paste the rest now. >>>
# <<< After the script, close the here-doc with EOF on its own line. >>>
# End of pasted script
'\''EOF'\'''
