#!/bin/bash
# Build script for SeKretSauce macOS app

set -e

APP_NAME="SeKretSauce"
BUILD_DIR="build"
APP_BUNDLE="${BUILD_DIR}/${APP_NAME}.app"

echo "Building ${APP_NAME}..."

# Clean previous build
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

# Create app bundle structure
mkdir -p "${APP_BUNDLE}/Contents/MacOS"
mkdir -p "${APP_BUNDLE}/Contents/Resources"

# Copy Info.plist
cp Info.plist "${APP_BUNDLE}/Contents/"

# Build the Swift executable
echo "Compiling Swift code..."
swiftc -O \
    -sdk $(xcrun --sdk macosx --show-sdk-path) \
    -target arm64-apple-macos14.0 \
    -o "${APP_BUNDLE}/Contents/MacOS/${APP_NAME}" \
    SeKretSauceApp.swift \
    ContentView.swift \
    ViewModel.swift \
    -framework SwiftUI \
    -framework Foundation

# Copy CLI tool to Resources
if [ -f "../sekretsauce" ]; then
    cp "../sekretsauce" "${APP_BUNDLE}/Contents/Resources/"
    chmod +x "${APP_BUNDLE}/Contents/Resources/sekretsauce"
    echo "Included CLI tool in app bundle"
fi

# Create a simple icon (placeholder)
# In production, you'd want a proper .icns file
echo "Note: Add AppIcon.icns to Resources for a proper icon"

# Sign the app (ad-hoc for development)
echo "Signing app bundle..."
codesign --force --deep --sign - "${APP_BUNDLE}"

echo ""
echo "Build complete!"
echo "App bundle: ${APP_BUNDLE}"
echo ""
echo "To run: open ${APP_BUNDLE}"
echo "To install: cp -r ${APP_BUNDLE} /Applications/"
