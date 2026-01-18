# Homebrew formula for SeKretSauce
# Security Swiss Army Knife for macOS
#
# To install from local tap:
#   brew tap afterdarktech/sekretsauce https://github.com/afterdarktech/homebrew-sekretsauce
#   brew install sekretsauce
#
# Or install directly:
#   brew install --build-from-source /path/to/sekretsauce.rb

class Sekretsauce < Formula
  desc "Security Swiss Army Knife for macOS - scan for secrets, wallets, suspicious processes"
  homepage "https://github.com/afterdarktech/sekretsauce"
  version "1.0.0"
  license "MIT"

  # For local development, use the head version
  head "https://github.com/afterdarktech/sekretsauce.git", branch: "main"

  # Release URLs (update SHA256 after creating releases)
  on_macos do
    on_arm do
      url "https://github.com/afterdarktech/sekretsauce/releases/download/v1.0.0/sekretsauce-1.0.0-darwin-arm64.tar.gz"
      sha256 "REPLACE_WITH_ACTUAL_SHA256_FOR_ARM64"
    end
    on_intel do
      url "https://github.com/afterdarktech/sekretsauce/releases/download/v1.0.0/sekretsauce-1.0.0-darwin-amd64.tar.gz"
      sha256 "REPLACE_WITH_ACTUAL_SHA256_FOR_AMD64"
    end
  end

  depends_on "go" => :build
  depends_on :macos

  def install
    # Build from source if head or if building locally
    if build.head? || !File.exist?("sekretsauce")
      system "go", "build", *std_go_args(ldflags: "-s -w -X main.Version=#{version}"), "./cmd/sekretsauce"
    else
      bin.install "sekretsauce"
    end

    # Generate shell completions
    generate_completions_from_executable(bin/"sekretsauce", "completion")
  end

  def caveats
    <<~EOS
      SeKretSauce has been installed!

      Quick start:
        sekretsauce scan              # Run full security scan
        sekretsauce scan keychain     # Scan macOS Keychain
        sekretsauce scan secrets      # Find exposed API keys
        sekretsauce scan wallets      # Find crypto wallets
        sekretsauce scan hidden       # Hunt hidden processes
        sekretsauce scan cas          # Audit CA certificates

      For JSON output, add --json flag:
        sekretsauce scan --json > report.json

      For help:
        sekretsauce --help

      GUI app available separately (not included in Homebrew):
        https://github.com/afterdarktech/sekretsauce/releases
    EOS
  end

  test do
    # Test that the binary runs
    assert_match "SeKretSauce", shell_output("#{bin}/sekretsauce --help")
    assert_match version.to_s, shell_output("#{bin}/sekretsauce --version")

    # Test keychain scan (should work without errors)
    output = shell_output("#{bin}/sekretsauce scan keychain --json 2>&1", 0)
    assert_match "total_items", output
  end
end
