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
swift build -c release
cp .build/release/SeKretSauceGUI "${APP_BUNDLE}/Contents/MacOS/${APP_NAME}"

# Copy CLI tool to Resources
if [ -f "../../bin/sekretsauce" ]; then
    cp "../../bin/sekretsauce" "${APP_BUNDLE}/Contents/Resources/"
    chmod +x "${APP_BUNDLE}/Contents/Resources/sekretsauce"
    echo "Included CLI tool in app bundle"
fi

# Create a simple icon (placeholder)
# In production, you'd want a proper .icns file
echo "Note: Add AppIcon.icns to Resources for a proper icon"

# Sign the app (ad-hoc for development)
echo "Signing app bundle..."
codesign --force --sign "${CODE_SIGN_IDENTITY:--}" --identifier com.afterdarktech.sekretsauce "${APP_BUNDLE}"

echo ""
echo "Build complete!"
echo "App bundle: ${APP_BUNDLE}"
echo ""
echo "To run: open ${APP_BUNDLE}"
echo "To install: cp -r ${APP_BUNDLE} /Applications/"
