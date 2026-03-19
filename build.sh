#!/bin/bash
# SeKretSauce Build Script
# Build different components for testing

set -e

VERSION="${VERSION:-1.0.0}"
BUILD_DIR="build"

show_help() {
    cat << EOF
SeKretSauce Build Script

Usage: ./build.sh [component]

Components:
  cli              Build the SeKretSauce CLI tool (Go)
  cli-all          Build CLI for all architectures (amd64, arm64)
  rampart          Build Rampart firewall module (Swift)
  gui              Build the GUI app (Swift/SwiftUI)
  installer        Build the GUI installer app (Swift)
  daemon           Build the security agent daemon (Swift)
  all              Build all components
  clean            Clean all build artifacts
  help             Show this help message

Examples:
  ./build.sh cli           # Quick CLI build for testing
  ./build.sh rampart       # Build Rampart firewall module
  ./build.sh all           # Build everything

EOF
}

build_cli() {
    echo "🔨 Building SeKretSauce CLI..."
    cd sekretsauce-cli
    go build -ldflags "-X main.Version=${VERSION}" -o ../bin/sekretsauce ./cmd/sekretsauce
    cd ..
    echo "✅ CLI built: ./bin/sekretsauce"
}

build_cli_all() {
    echo "🔨 Building CLI for all architectures..."
    mkdir -p "${BUILD_DIR}"

    echo "  Building for darwin/amd64..."
    cd sekretsauce-cli
    GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.Version=${VERSION}" \
        -o ../${BUILD_DIR}/sekretsauce-darwin-amd64 ./cmd/sekretsauce

    echo "  Building for darwin/arm64..."
    GOOS=darwin GOARCH=arm64 go build -ldflags "-X main.Version=${VERSION}" \
        -o ../${BUILD_DIR}/sekretsauce-darwin-arm64 ./cmd/sekretsauce
    cd ..

    echo "✅ Multi-arch builds complete:"
    echo "   ${BUILD_DIR}/sekretsauce-darwin-amd64"
    echo "   ${BUILD_DIR}/sekretsauce-darwin-arm64"
}

build_rampart() {
    echo "🔨 Building Rampart firewall module..."
    cd rampart
    ./build.sh
    cd ..
    echo "✅ Rampart built: rampart/build/"
}

build_gui() {
    echo "🔨 Building GUI app..."
    cd gui-apps/app
    ./build.sh
    cd ../..
    echo "✅ GUI app built: gui-apps/app/build/SeKretSauce.app"
}

build_installer() {
    echo "🔨 Building installer app..."
    echo "  First building Swift daemon..."
    swift build -c release

    echo "  Now building installer..."
    cd gui-apps/installer
    ./build.sh
    cd ../..
    echo "✅ Installer built: gui-apps/installer/dist/SeKretSauce Installer.app"
}

build_daemon() {
    echo "🔨 Building Swift security agent daemon..."
    swift build -c release
    echo "✅ Daemon built: .build/release/"
}

clean_all() {
    echo "🧹 Cleaning build artifacts..."
    rm -rf bin
    rm -rf "${BUILD_DIR}"
    rm -rf gui-apps/*/build
    rm -rf gui-apps/*/dist
    rm -rf rampart/build
    rm -rf .build
    echo "✅ Clean complete"
}

build_all() {
    echo "🚀 Building all components..."
    echo ""
    build_cli
    echo ""
    build_rampart
    echo ""
    build_daemon
    echo ""
    build_gui
    echo ""
    build_installer
    echo ""
    echo "✅ All components built successfully!"
}

# Main script
case "${1:-help}" in
    cli)
        build_cli
        ;;
    cli-all)
        build_cli_all
        ;;
    rampart)
        build_rampart
        ;;
    gui)
        build_gui
        ;;
    installer)
        build_installer
        ;;
    daemon)
        build_daemon
        ;;
    all)
        build_all
        ;;
    clean)
        clean_all
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo "❌ Unknown component: $1"
        echo ""
        show_help
        exit 1
        ;;
esac
