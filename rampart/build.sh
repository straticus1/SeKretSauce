#!/bin/bash
# Rampart Build Script
# "One Place to Rule Them All"

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
APP_NAME="Rampart"
BUNDLE_ID="com.rampart.Rampart"
HELPER_ID="com.rampart.FirewallHelper"

echo "================================"
echo "  Rampart Build Script"
echo "  One Place to Rule Them All"
echo "================================"
echo ""

# Clean build directory
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Build FirewallKit
echo "[1/4] Building FirewallKit..."
cd "$SCRIPT_DIR/FirewallKit"
swift build -c release 2>&1 | grep -E "^(Building|Build complete)" || true

# Build FirewallHelper
echo "[2/4] Building FirewallHelper..."
cd "$SCRIPT_DIR/FirewallHelper"
swift build -c release 2>&1 | grep -E "^(Building|Build complete)" || true

# Build CLI
echo "[3/4] Building CLI..."
cd "$SCRIPT_DIR/CLI"
swift build -c release 2>&1 | grep -E "^(Building|Build complete)" || true

# Build GUI
echo "[4/4] Building GUI..."
cd "$SCRIPT_DIR/GUI"
swift build -c release 2>&1 | grep -E "^(Building|Build complete)" || true

# Create .app bundle structure
echo ""
echo "Creating Rampart.app bundle..."
APP_BUNDLE="$BUILD_DIR/$APP_NAME.app"
mkdir -p "$APP_BUNDLE/Contents/MacOS"
mkdir -p "$APP_BUNDLE/Contents/Resources"
mkdir -p "$APP_BUNDLE/Contents/Library/LaunchServices"

# Copy executables
cp "$SCRIPT_DIR/GUI/.build/release/Rampart" "$APP_BUNDLE/Contents/MacOS/Rampart"
cp "$SCRIPT_DIR/FirewallHelper/.build/release/com.rampart.FirewallHelper" "$APP_BUNDLE/Contents/Library/LaunchServices/"

# Copy Info.plist
cp "$SCRIPT_DIR/GUI/Resources/Info.plist" "$APP_BUNDLE/Contents/Info.plist"

# Copy CLI to build directory
cp "$SCRIPT_DIR/CLI/.build/release/rampart" "$BUILD_DIR/rampart"

# Copy helper resources
mkdir -p "$BUILD_DIR/LaunchDaemons"
cp "$SCRIPT_DIR/FirewallHelper/Resources/com.rampart.FirewallHelper.plist" "$BUILD_DIR/LaunchDaemons/"

# Create PkgInfo
echo "APPL????" > "$APP_BUNDLE/Contents/PkgInfo"

echo ""
echo "================================"
echo "  Build Complete!"
echo "================================"
echo ""
echo "Output:"
echo "  App:    $APP_BUNDLE"
echo "  CLI:    $BUILD_DIR/rampart"
echo "  Helper: $APP_BUNDLE/Contents/Library/LaunchServices/com.rampart.FirewallHelper"
echo ""
echo "Installation:"
echo "  1. Copy Rampart.app to /Applications"
echo "  2. The helper will be installed via SMJobBless on first run"
echo "  3. Or manually: sudo cp $BUILD_DIR/LaunchDaemons/*.plist /Library/LaunchDaemons/"
echo ""
echo "CLI Usage:"
echo "  $BUILD_DIR/rampart --help"
echo ""
