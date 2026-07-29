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
  license :cannot_represent

  # A stable stanza must not be published until release archives and their
  # real SHA-256 digests exist. Install this source formula with --HEAD.
  head "https://github.com/afterdarktech/sekretsauce.git", branch: "main"

  depends_on "go" => :build
  depends_on :macos

  def install
    cd "sekretsauce-cli" do
      system "go", "build", *std_go_args(ldflags: "-s -w -X github.com/afterdarktech/sekretsauce/cmd/sekretsauce/cmd.Version=#{version}"), "./cmd/sekretsauce"
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
    assert_match "SeKretSauce", shell_output("#{bin}/sekretsauce --help")
  end
end
