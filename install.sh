#!/bin/bash
# MTProto Proxy Official Installer
# Auto-generates random parameters when xxxx is used

# Download and run the main script
SCRIPT_URL="https://raw.githubusercontent.com/TelegramMessenger/MTProxy/master/scripts/install.sh"
TEMP_SCRIPT="/tmp/mtproto_installer.sh"

# Detect if parameters contain xxxx and replace with random values
ORIGINAL_ARGS=("$@")
NEW_ARGS=()

for arg in "${ORIGINAL_ARGS[@]}"; do
    case "$arg" in
        --port=xxxx|--port=XXXX)
            RANDOM_PORT=$((RANDOM % 40000 + 20000))
            NEW_ARGS+=("--port=$RANDOM_PORT")
            ;;
        --secret=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx)
            RANDOM_SECRET=$(head -c 16 /dev/urandom | xxd -ps)
            NEW_ARGS+=("--secret=$RANDOM_SECRET")
            ;;
        --tag=xxxxxxxxxxxxxxxxxxxxxxxxxx)
            RANDOM_TAG="3$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 20 | head -n 1)"
            NEW_ARGS+=("--tag=$RANDOM_TAG")
            ;;
        --tls=xxxxxxxxxxxxxxxxxxxxxxx)
            DOMAINS=("www.cloudflare.com" "www.google.com" "www.youtube.com" "www.facebook.com")
            RANDOM_DOMAIN=${DOMAINS[$RANDOM % ${#DOMAINS[@]}]}
            NEW_ARGS+=("--tls=$RANDOM_DOMAIN")
            ;;
        --tls)
            # Next argument is xxxx
            for i in "${!ORIGINAL_ARGS[@]}"; do
                if [ "${ORIGINAL_ARGS[$i]}" = "--tls" ] && [ "${ORIGINAL_ARGS[$i+1]}" = "xxxxxxxxxxxxxxxxxxxxxxx" ]; then
                    DOMAINS=("www.cloudflare.com" "www.google.com" "www.youtube.com" "www.facebook.com")
                    RANDOM_DOMAIN=${DOMAINS[$RANDOM % ${#DOMAINS[@]}]}
                    NEW_ARGS+=("--tls=$RANDOM_DOMAIN")
                    break
                fi
            done
            ;;
        *)
            NEW_ARGS+=("$arg")
            ;;
    esac
done

echo "Original command: $0 ${ORIGINAL_ARGS[*]}"
echo "Processed command: $0 ${NEW_ARGS[*]}"

# Download the installer script
echo "Downloading MTProto Proxy installer..."
curl -s -o "$TEMP_SCRIPT" "$SCRIPT_URL" || {
    echo "Failed to download installer. Using built-in installer."
    # Use the script above as fallback
    exec bash -c "$(cat << 'EOF'
'"$(cat << 'SCRIPT_CONTENT'
# Paste the entire script from above here
SCRIPT_CONTENT
)"'
EOF
)" "${NEW_ARGS[@]}"
}

# Make executable and run
chmod +x "$TEMP_SCRIPT"
exec "$TEMP_SCRIPT" "${NEW_ARGS[@]}"
