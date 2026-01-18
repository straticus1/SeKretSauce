#!/bin/bash
#
# Build SeKretSauce Installer App
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/.build/release"
APP_NAME="SeKretSauce Installer.app"
OUTPUT_DIR="$PROJECT_DIR/dist"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}Building SeKretSauce Installer...${NC}"

# Step 1: Build the main daemon and SSH wrapper
echo -e "${YELLOW}Step 1: Building daemon and tools...${NC}"
cd "$PROJECT_DIR"
swift build -c release

# Step 2: Create app bundle structure
echo -e "${YELLOW}Step 2: Creating app bundle...${NC}"
mkdir -p "$OUTPUT_DIR/$APP_NAME/Contents/MacOS"
mkdir -p "$OUTPUT_DIR/$APP_NAME/Contents/Resources"

# Step 3: Build the installer app
echo -e "${YELLOW}Step 3: Building installer app...${NC}"
cd "$SCRIPT_DIR"

# Use swiftc directly for a simple build
swiftc \
    -O \
    -target arm64-apple-macos13 \
    -sdk $(xcrun --sdk macosx --show-sdk-path) \
    -framework SwiftUI \
    -framework AppKit \
    -framework Security \
    -framework ServiceManagement \
    -parse-as-library \
    -o "$OUTPUT_DIR/$APP_NAME/Contents/MacOS/SeKretSauceInstaller" \
    SeKretSauceInstaller/SeKretSauceInstallerApp.swift \
    SeKretSauceInstaller/Views/InstallerView.swift \
    SeKretSauceInstaller/Helpers/InstallerManager.swift

# Step 4: Copy Info.plist
echo -e "${YELLOW}Step 4: Copying resources...${NC}"
cp SeKretSauceInstaller/Info.plist "$OUTPUT_DIR/$APP_NAME/Contents/"

# Step 5: Copy built binaries to app resources
cp "$BUILD_DIR/sekretsauced" "$OUTPUT_DIR/$APP_NAME/Contents/Resources/" 2>/dev/null || \
    cp "$PROJECT_DIR/sekretsauced" "$OUTPUT_DIR/$APP_NAME/Contents/Resources/" 2>/dev/null || \
    echo "Warning: sekretsauced not found, will use system build"

cp "$BUILD_DIR/ssh-wrapper" "$OUTPUT_DIR/$APP_NAME/Contents/Resources/" 2>/dev/null || \
    echo "Warning: ssh-wrapper not found"

# Step 6: Create PkgInfo
echo -n "APPL????" > "$OUTPUT_DIR/$APP_NAME/Contents/PkgInfo"

# Step 7: Set executable permissions
chmod +x "$OUTPUT_DIR/$APP_NAME/Contents/MacOS/SeKretSauceInstaller"

echo ""
echo -e "${GREEN}Build complete!${NC}"
echo "App bundle: $OUTPUT_DIR/$APP_NAME"
echo ""
echo "To run: open \"$OUTPUT_DIR/$APP_NAME\""
