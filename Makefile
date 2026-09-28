# SeKretSauce Makefile
# Security Swiss Army Knife for macOS

.PHONY: all build install clean test gui release homebrew swift-build installer

VERSION := 1.0.0
BUILD_DIR := build
CLI_NAME := sekretsauce
GUI_NAME := SeKretSauce
INSTALL_PATH := /usr/local/bin

# Build targets
all: build

build:
	@echo "Building SeKretSauce CLI..."
	@mkdir -p bin
	@cd sekretsauce-cli && go build -ldflags "-X github.com/straticus1/SeKretSauce/sekretsauce-cli/cmd/sekretsauce/cmd.Version=$(VERSION)" -o ../bin/$(CLI_NAME) ./cmd/sekretsauce
	@echo "Build complete: ./bin/$(CLI_NAME)"

install: build
	@echo "Installing to $(INSTALL_PATH)..."
	@cp bin/$(CLI_NAME) $(INSTALL_PATH)/
	@chmod +x $(INSTALL_PATH)/$(CLI_NAME)
	@echo "Installed: $(INSTALL_PATH)/$(CLI_NAME)"

uninstall:
	@echo "Removing from $(INSTALL_PATH)..."
	@rm -f $(INSTALL_PATH)/$(CLI_NAME)
	@echo "Uninstalled"

clean:
	@echo "Cleaning..."
	@rm -rf bin
	@rm -rf $(BUILD_DIR)
	@rm -rf gui-apps/*/build
	@echo "Clean complete"

test:
	@echo "Running tests..."
	@cd sekretsauce-cli && go test -v ./...

# GUI build (requires Xcode/Swift)
gui: build
	@echo "Building macOS GUI app..."
	@cd gui-apps/app && ./build.sh
	@echo "GUI build complete: gui-apps/app/build/$(GUI_NAME).app"

# Install GUI to Applications
install-gui: gui
	@echo "Installing GUI to /Applications..."
	@cp -r gui-apps/app/build/$(GUI_NAME).app /Applications/
	@echo "Installed: /Applications/$(GUI_NAME).app"

# Build release artifacts
release: clean build gui
	@echo "Creating release artifacts..."
	@mkdir -p $(BUILD_DIR)/release
	@cp bin/$(CLI_NAME) $(BUILD_DIR)/release/
	@cp -r gui-apps/app/build/$(GUI_NAME).app $(BUILD_DIR)/release/
	@cd $(BUILD_DIR)/release && zip -r ../$(CLI_NAME)-$(VERSION)-macos.zip .
	@echo "Release artifact: $(BUILD_DIR)/$(CLI_NAME)-$(VERSION)-macos.zip"

# Generate Homebrew formula
homebrew:
	@echo "Preparing Homebrew formula..."
	@mkdir -p $(BUILD_DIR)
	@cp homebrew/sekretsauce.rb $(BUILD_DIR)/sekretsauce.rb
	@echo "Homebrew formula: $(BUILD_DIR)/sekretsauce.rb"

# Build for both architectures
release-all: clean
	@echo "Building for all architectures..."
	@mkdir -p $(BUILD_DIR)
	@cd sekretsauce-cli && GOOS=darwin GOARCH=amd64 go build -ldflags "-X github.com/straticus1/SeKretSauce/sekretsauce-cli/cmd/sekretsauce/cmd.Version=$(VERSION)" -o ../$(BUILD_DIR)/$(CLI_NAME)-darwin-amd64 ./cmd/sekretsauce
	@cd sekretsauce-cli && GOOS=darwin GOARCH=arm64 go build -ldflags "-X github.com/straticus1/SeKretSauce/sekretsauce-cli/cmd/sekretsauce/cmd.Version=$(VERSION)" -o ../$(BUILD_DIR)/$(CLI_NAME)-darwin-arm64 ./cmd/sekretsauce
	@echo "Built: $(BUILD_DIR)/$(CLI_NAME)-darwin-amd64"
	@echo "Built: $(BUILD_DIR)/$(CLI_NAME)-darwin-arm64"

# Development helpers
dev: build
	@./bin/$(CLI_NAME) --help

scan: build
	@./bin/$(CLI_NAME) scan

# Run specific scans
scan-keychain: build
	@./bin/$(CLI_NAME) scan keychain

scan-hidden: build
	@./bin/$(CLI_NAME) scan hidden

scan-secrets: build
	@./bin/$(CLI_NAME) scan secrets --path .

scan-wallets: build
	@./bin/$(CLI_NAME) scan wallets

scan-cas: build
	@./bin/$(CLI_NAME) scan cas

# Swift security agent build
swift-build:
	@echo "Building Swift security agent..."
	@swift build -c release
	@echo "Swift build complete"

# Build GUI installer
installer: swift-build
	@echo "Building GUI installer..."
	@cd gui-apps/installer && ./build.sh
	@echo "Installer build complete: gui-apps/installer/dist/SeKretSauce Installer.app"

# Install Swift daemon
install-daemon: swift-build
	@echo "Installing security agent daemon..."
	@sudo ./scripts/install.sh
	@echo "Daemon installed"

# Uninstall Swift daemon
uninstall-daemon:
	@echo "Uninstalling security agent daemon..."
	@sudo ./scripts/uninstall.sh
	@echo "Daemon uninstalled"

# Help
help:
	@echo "SeKretSauce - Security Swiss Army Knife"
	@echo ""
	@echo "Usage:"
	@echo "  make build       - Build CLI tool"
	@echo "  make install     - Install CLI to /usr/local/bin"
	@echo "  make gui         - Build macOS GUI app"
	@echo "  make install-gui - Install GUI to /Applications"
	@echo "  make release     - Create release artifacts"
	@echo "  make homebrew    - Generate Homebrew formula"
	@echo "  make clean       - Remove build artifacts"
	@echo "  make test        - Run tests"
	@echo ""
	@echo "Security Agent:"
	@echo "  make swift-build     - Build Swift security agent"
	@echo "  make installer       - Build GUI installer app"
	@echo "  make install-daemon  - Install security agent daemon"
	@echo "  make uninstall-daemon - Uninstall security agent daemon"
	@echo ""
	@echo "Scan shortcuts:"
	@echo "  make scan            - Run full scan"
	@echo "  make scan-keychain   - Scan Keychain"
	@echo "  make scan-hidden     - Hunt hidden processes"
	@echo "  make scan-secrets    - Scan for secrets"
	@echo "  make scan-wallets    - Find crypto wallets"
	@echo "  make scan-cas        - Audit CA certificates"
