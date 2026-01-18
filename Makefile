# SeKretSauce Makefile
# Security Swiss Army Knife for macOS

.PHONY: all build install clean test gui release homebrew

VERSION := 1.0.0
BUILD_DIR := build
CLI_NAME := sekretsauce
GUI_NAME := SeKretSauce
INSTALL_PATH := /usr/local/bin

# Build targets
all: build

build:
	@echo "Building SeKretSauce CLI..."
	@go build -ldflags "-X main.Version=$(VERSION)" -o $(CLI_NAME) ./cmd/sekretsauce
	@echo "Build complete: ./$(CLI_NAME)"

install: build
	@echo "Installing to $(INSTALL_PATH)..."
	@cp $(CLI_NAME) $(INSTALL_PATH)/
	@chmod +x $(INSTALL_PATH)/$(CLI_NAME)
	@echo "Installed: $(INSTALL_PATH)/$(CLI_NAME)"

uninstall:
	@echo "Removing from $(INSTALL_PATH)..."
	@rm -f $(INSTALL_PATH)/$(CLI_NAME)
	@echo "Uninstalled"

clean:
	@echo "Cleaning..."
	@rm -f $(CLI_NAME)
	@rm -rf $(BUILD_DIR)
	@rm -rf gui/build
	@echo "Clean complete"

test:
	@echo "Running tests..."
	@go test -v ./...

# GUI build (requires Xcode/Swift)
gui: build
	@echo "Building macOS GUI app..."
	@cd gui && ./build.sh
	@echo "GUI build complete: gui/build/$(GUI_NAME).app"

# Install GUI to Applications
install-gui: gui
	@echo "Installing GUI to /Applications..."
	@cp -r gui/build/$(GUI_NAME).app /Applications/
	@echo "Installed: /Applications/$(GUI_NAME).app"

# Build release artifacts
release: clean build gui
	@echo "Creating release artifacts..."
	@mkdir -p $(BUILD_DIR)/release
	@cp $(CLI_NAME) $(BUILD_DIR)/release/
	@cp -r gui/build/$(GUI_NAME).app $(BUILD_DIR)/release/
	@cd $(BUILD_DIR)/release && zip -r ../$(CLI_NAME)-$(VERSION)-macos.zip .
	@echo "Release artifact: $(BUILD_DIR)/$(CLI_NAME)-$(VERSION)-macos.zip"

# Generate Homebrew formula
homebrew:
	@echo "Generating Homebrew formula..."
	@cat > $(BUILD_DIR)/sekretsauce.rb <<'EOF'
class Sekretsauce < Formula
  desc "Security Swiss Army Knife for macOS"
  homepage "https://github.com/afterdarktech/sekretsauce"
  version "$(VERSION)"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/afterdarktech/sekretsauce/releases/download/v$(VERSION)/sekretsauce-$(VERSION)-macos-arm64.tar.gz"
      sha256 "REPLACE_WITH_SHA256"
    else
      url "https://github.com/afterdarktech/sekretsauce/releases/download/v$(VERSION)/sekretsauce-$(VERSION)-macos-amd64.tar.gz"
      sha256 "REPLACE_WITH_SHA256"
    end
  end

  def install
    bin.install "sekretsauce"
  end

  test do
    system "#{bin}/sekretsauce", "--version"
  end
end
EOF
	@echo "Homebrew formula: $(BUILD_DIR)/sekretsauce.rb"

# Build for both architectures
release-all: clean
	@echo "Building for all architectures..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.Version=$(VERSION)" -o $(BUILD_DIR)/$(CLI_NAME)-darwin-amd64 ./cmd/sekretsauce
	@GOOS=darwin GOARCH=arm64 go build -ldflags "-X main.Version=$(VERSION)" -o $(BUILD_DIR)/$(CLI_NAME)-darwin-arm64 ./cmd/sekretsauce
	@echo "Built: $(BUILD_DIR)/$(CLI_NAME)-darwin-amd64"
	@echo "Built: $(BUILD_DIR)/$(CLI_NAME)-darwin-arm64"

# Development helpers
dev: build
	@./$(CLI_NAME) --help

scan: build
	@./$(CLI_NAME) scan

# Run specific scans
scan-keychain: build
	@./$(CLI_NAME) scan keychain

scan-hidden: build
	@./$(CLI_NAME) scan hidden

scan-secrets: build
	@./$(CLI_NAME) scan secrets --path .

scan-wallets: build
	@./$(CLI_NAME) scan wallets

scan-cas: build
	@./$(CLI_NAME) scan cas

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
	@echo "Scan shortcuts:"
	@echo "  make scan            - Run full scan"
	@echo "  make scan-keychain   - Scan Keychain"
	@echo "  make scan-hidden     - Hunt hidden processes"
	@echo "  make scan-secrets    - Scan for secrets"
	@echo "  make scan-wallets    - Find crypto wallets"
	@echo "  make scan-cas        - Audit CA certificates"
