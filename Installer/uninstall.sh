#!/bin/bash
#
# SeKretSauce Security Agent Uninstaller
# Must be run as root
#

set -e

# Configuration
INSTALL_DIR="/Library/Application Support/SeKretSauce"
LOG_DIR="/Library/Logs/SeKretSauce"
LAUNCH_DAEMON_DIR="/Library/LaunchDaemons"
PLIST_NAME="com.sekretsauce.daemon.plist"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check root
if [ "$EUID" -ne 0 ]; then
    log_error "This uninstaller must be run as root"
    echo "Usage: sudo ./uninstall.sh"
    exit 1
fi

echo ""
echo "========================================"
echo "  SeKretSauce Security Agent Uninstaller"
echo "========================================"
echo ""

# Confirm
read -p "This will remove SeKretSauce completely. Continue? (y/N): " confirm
if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
    echo "Uninstall cancelled."
    exit 0
fi

# Stop daemon
log_info "Stopping daemon..."
if launchctl list | grep -q "com.sekretsauce.daemon"; then
    launchctl unload "$LAUNCH_DAEMON_DIR/$PLIST_NAME" 2>/dev/null || true
    sleep 2
fi

# Remove LaunchDaemon
log_info "Removing LaunchDaemon..."
rm -f "$LAUNCH_DAEMON_DIR/$PLIST_NAME"

# Ask about logs
read -p "Remove log files? (y/N): " remove_logs
if [ "$remove_logs" = "y" ] || [ "$remove_logs" = "Y" ]; then
    log_info "Removing log directory..."
    rm -rf "$LOG_DIR"
fi

# Ask about recordings
if [ -d "$INSTALL_DIR/recordings" ]; then
    read -p "Remove SSH recordings? (y/N): " remove_recordings
    if [ "$remove_recordings" != "y" ] && [ "$remove_recordings" != "Y" ]; then
        log_info "Preserving recordings..."
        mkdir -p "/tmp/sekretsauce-recordings-backup"
        cp -r "$INSTALL_DIR/recordings" "/tmp/sekretsauce-recordings-backup/"
        log_info "Recordings backed up to /tmp/sekretsauce-recordings-backup"
    fi
fi

# Remove installation directory
log_info "Removing installation directory..."
rm -rf "$INSTALL_DIR"

# Remove from Keychain (optional)
log_info "Note: Keychain items are preserved. Remove manually if needed."

echo ""
log_info "SeKretSauce has been uninstalled."
echo ""
