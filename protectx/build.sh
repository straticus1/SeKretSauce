#!/bin/bash
# ADS ProtectX Build Script
# "One Place to Rule Them All"

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
APP_NAME="ProtectX"
BUNDLE_ID="com.afterdark.protectx"
HELPER_ID="com.afterdark.protectx.helper"
SIGN_IDENTITY="${CODE_SIGN_IDENTITY:--}"

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
swift build -c release

# Build FirewallHelper
echo "[2/4] Building FirewallHelper..."
cd "$SCRIPT_DIR/FirewallHelper"
swift build -c release

# Build CLI
echo "[3/4] Building CLI..."
cd "$SCRIPT_DIR/CLI"
swift build -c release

# Build GUI
echo "[4/4] Building GUI..."
cd "$SCRIPT_DIR/GUI"
swift build -c release

# Create .app bundle structure
echo ""
echo "Creating ProtectX.app bundle..."
APP_BUNDLE="$BUILD_DIR/$APP_NAME.app"
mkdir -p "$APP_BUNDLE/Contents/MacOS"
mkdir -p "$APP_BUNDLE/Contents/Resources"
mkdir -p "$APP_BUNDLE/Contents/Library/LaunchServices"
mkdir -p "$APP_BUNDLE/Contents/Library/LaunchDaemons"

# Copy executables
cp "$SCRIPT_DIR/GUI/.build/release/ProtectX" "$APP_BUNDLE/Contents/MacOS/ProtectX"
cp "$SCRIPT_DIR/FirewallHelper/.build/release/$HELPER_ID" "$APP_BUNDLE/Contents/Library/LaunchServices/"
cp "$SCRIPT_DIR/FirewallHelper/Resources/$HELPER_ID.plist" "$APP_BUNDLE/Contents/Library/LaunchDaemons/"

# Copy Info.plist
cp "$SCRIPT_DIR/GUI/Resources/Info.plist" "$APP_BUNDLE/Contents/Info.plist"

# Copy CLI to build directory
cp "$SCRIPT_DIR/CLI/.build/release/adsp" "$BUILD_DIR/adsp"

# Create PkgInfo
echo "APPL????" > "$APP_BUNDLE/Contents/PkgInfo"

# SMAppService requires a signed containing app and helper. Ad-hoc signing keeps
# local builds launchable; distribution builds must provide a Developer ID
# identity and be notarized before the LaunchDaemon can be approved.
codesign --force --sign "$SIGN_IDENTITY" \
    --identifier "$HELPER_ID" \
    "$APP_BUNDLE/Contents/Library/LaunchServices/$HELPER_ID"
codesign --force --sign "$SIGN_IDENTITY" \
    --identifier "$BUNDLE_ID" \
    --entitlements "$SCRIPT_DIR/GUI/Resources/Rampart.entitlements" \
    "$APP_BUNDLE"

if [[ "$SIGN_IDENTITY" == "-" ]]; then
    echo "WARNING: Ad-hoc signed build. Set CODE_SIGN_IDENTITY to a Developer ID"
    echo "         and notarize the app to register the privileged helper."
fi

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
echo "  2. Open ProtectX and click Install Helper"
echo "  3. Approve ProtectX in System Settings > General > Login Items"
echo ""
echo "CLI Usage:"
echo "  $BUILD_DIR/adsp --help"
echo ""
