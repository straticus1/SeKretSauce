#!/bin/bash
# ADS ProtectX Build Script
# "One Place to Rule Them All"

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
APP_NAME="ProtectX"
BUNDLE_ID="com.afterdark.protectx"
HELPER_ID="com.afterdark.protectx.helper"

echo "================================"
echo "  ADS ProtectX Build Script"
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
echo "Creating ProtectX.app bundle..."
APP_BUNDLE="$BUILD_DIR/$APP_NAME.app"
mkdir -p "$APP_BUNDLE/Contents/MacOS"
mkdir -p "$APP_BUNDLE/Contents/Resources"
mkdir -p "$APP_BUNDLE/Contents/Library/LaunchServices"

# Copy executables
cp "$SCRIPT_DIR/GUI/.build/release/ProtectX" "$APP_BUNDLE/Contents/MacOS/ProtectX"
cp "$SCRIPT_DIR/FirewallHelper/.build/release/$HELPER_ID" "$APP_BUNDLE/Contents/Library/LaunchServices/"

# Copy Info.plist
cp "$SCRIPT_DIR/GUI/Resources/Info.plist" "$APP_BUNDLE/Contents/Info.plist"

# Copy CLI to build directory
cp "$SCRIPT_DIR/CLI/.build/release/adsp" "$BUILD_DIR/adsp"

# Copy helper resources
mkdir -p "$BUILD_DIR/LaunchDaemons"
cp "$SCRIPT_DIR/FirewallHelper/Resources/$HELPER_ID.plist" "$BUILD_DIR/LaunchDaemons/"

# Create PkgInfo
echo "APPL????" > "$APP_BUNDLE/Contents/PkgInfo"

echo ""
echo "================================"
echo "  Build Complete!"
echo "================================"
echo ""
echo "Output:"
echo "  App:    $APP_BUNDLE"
echo "  CLI:    $BUILD_DIR/adsp"
echo "  Helper: $APP_BUNDLE/Contents/Library/LaunchServices/$HELPER_ID"
echo ""
echo "Installation:"
echo "  1. Copy ProtectX.app to /Applications"
echo "  2. The helper will be installed via SMJobBless on first run"
echo "  3. Or manually: sudo cp $BUILD_DIR/LaunchDaemons/*.plist /Library/LaunchDaemons/"
echo ""
echo "CLI Usage:"
echo "  $BUILD_DIR/adsp --help"
echo ""
