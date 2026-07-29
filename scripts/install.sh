#!/bin/bash
#
# SeKretSauce Security Agent Installer
# Must be run as root
#

set -e
umask 077

# Configuration
INSTALL_DIR="/Library/Application Support/SeKretSauce"
LOG_DIR="/Library/Logs/SeKretSauce"
LAUNCH_DAEMON_DIR="/Library/LaunchDaemons"
PLIST_NAME="com.sekretsauce.daemon.plist"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging
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
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This installer must be run as root"
        echo "Usage: sudo ./install.sh"
        exit 1
    fi
}

# Check macOS version
check_macos_version() {
    local version=$(sw_vers -productVersion)
    local major=$(echo "$version" | cut -d. -f1)

    if [ "$major" -lt 13 ]; then
        log_error "SeKretSauce requires macOS 13 (Ventura) or later"
        log_error "Current version: $version"
        exit 1
    fi

    log_info "macOS version: $version"
}

# Stop existing daemon
stop_existing_daemon() {
    if launchctl list | grep -q "com.sekretsauce.daemon"; then
        log_info "Stopping existing daemon..."
        launchctl unload "$LAUNCH_DAEMON_DIR/$PLIST_NAME" 2>/dev/null || true
        sleep 2
    fi
}

# Create directories
create_directories() {
    log_info "Creating directories..."

    mkdir -p "$INSTALL_DIR"
    mkdir -p "$INSTALL_DIR/recordings"
    mkdir -p "$LOG_DIR"

    # Set permissions
    chmod 755 "$INSTALL_DIR"
    chmod 700 "$INSTALL_DIR/recordings"
    chmod 700 "$LOG_DIR"
}

# Install binaries
install_binaries() {
    log_info "Installing binaries..."

    local script_dir="$(cd "$(dirname "$0")" && pwd)"
    local build_dir="$script_dir/../.build/release"

    # Check if built
    if [ ! -f "$build_dir/sekretsauced" ]; then
        log_error "Binaries not found. Please build first:"
        echo "  swift build -c release"
        exit 1
    fi

    # Copy daemon
    cp "$build_dir/sekretsauced" "$INSTALL_DIR/"
    chmod 755 "$INSTALL_DIR/sekretsauced"

    # Copy SSH wrapper
    cp "$build_dir/ssh-wrapper" "$INSTALL_DIR/"
    chmod 755 "$INSTALL_DIR/ssh-wrapper"

    log_info "Binaries installed to $INSTALL_DIR"
}

# Install LaunchDaemon
install_launch_daemon() {
    log_info "Installing LaunchDaemon..."

    local script_dir="$(cd "$(dirname "$0")" && pwd)"
    cp "$script_dir/../Resources/com.sekretsauce.daemon.plist" "$LAUNCH_DAEMON_DIR/"

    # Set permissions
    chown root:wheel "$LAUNCH_DAEMON_DIR/$PLIST_NAME"
    chmod 644 "$LAUNCH_DAEMON_DIR/$PLIST_NAME"
}

# Install SSH wrapper (optional)
install_ssh_wrapper() {
    log_info "SSH wrapper installation..."
    log_warn "SSH wrapper installation requires disabling SIP or using a different approach"
    log_warn "Skipping automatic SSH wrapper installation"

    echo ""
    echo "To manually set up SSH recording, you can:"
    echo "1. Create an alias: alias ssh='$INSTALL_DIR/ssh-wrapper'"
    echo "2. Or add to PATH before /usr/bin"
    echo ""
}

# Configure initial setup
initial_setup() {
    log_info "Initial configuration..."

    # Check if already configured
    if [ -f "$INSTALL_DIR/.configured" ]; then
        log_info "Already configured, skipping setup"
        return
    fi

    echo ""
    echo "=== SeKretSauce Initial Setup ==="
    echo ""

    read -p "Enter server URL (or press Enter to skip): " server_url
    if [ -n "$server_url" ]; then
        read -s -p "Enter API key: " api_key
        echo ""

        # Run setup
        "$INSTALL_DIR/sekretsauced" --setup <<EOF
$server_url
$api_key
EOF

        touch "$INSTALL_DIR/.configured"
    else
        log_warn "Skipping server configuration. Run setup later with:"
        echo "  sudo $INSTALL_DIR/sekretsauced --setup"
    fi
}

# Start daemon
start_daemon() {
    log_info "Starting daemon..."

    launchctl load "$LAUNCH_DAEMON_DIR/$PLIST_NAME"

    sleep 2

    # Check if running
    if launchctl list | grep -q "com.sekretsauce.daemon"; then
        log_info "Daemon started successfully"
    else
        log_error "Failed to start daemon. Check logs:"
        echo "  tail -f $LOG_DIR/daemon.log"
        exit 1
    fi
}

# Show status
show_status() {
    echo ""
    echo "=== Installation Complete ==="
    echo ""
    echo "Installation directory: $INSTALL_DIR"
    echo "Log directory:          $LOG_DIR"
    echo ""
    echo "Commands:"
    echo "  Status:     sudo $INSTALL_DIR/sekretsauced --status"
    echo "  Setup:      sudo $INSTALL_DIR/sekretsauced --setup"
    echo "  Logs:       tail -f $LOG_DIR/daemon.log"
    echo ""
    echo "To uninstall:"
    echo "  sudo $script_dir/uninstall.sh"
    echo ""
}

# Main
main() {
    echo ""
    echo "========================================"
    echo "  SeKretSauce Security Agent Installer"
    echo "========================================"
    echo ""

    check_root
    check_macos_version
    stop_existing_daemon
    create_directories
    install_binaries
    install_launch_daemon
    install_ssh_wrapper
    initial_setup
    start_daemon
    show_status
}

main "$@"
