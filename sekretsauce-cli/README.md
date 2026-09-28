# SeKretSauce

**A SecretServer.io product of After Dark Systems, LLC**

A comprehensive security Swiss Army knife for network and security professionals on macOS.

```
███████╗███████╗██╗  ██╗██████╗ ███████╗████████╗███████╗ █████╗ ██╗   ██╗ ██████╗███████╗
██╔════╝██╔════╝██║ ██╔╝██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔══██╗██║   ██║██╔════╝██╔════╝
███████╗█████╗  █████╔╝ ██████╔╝█████╗     ██║   ███████╗███████║██║   ██║██║     █████╗
╚════██║██╔══╝  ██╔═██╗ ██╔══██╗██╔══╝     ██║   ╚════██║██╔══██║██║   ██║██║     ██╔══╝
███████║███████╗██║  ██╗██║  ██║███████╗   ██║   ███████║██║  ██║╚██████╔╝╚██████╗███████╗
╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝╚══════╝
```

## Features

### Browser Export
- **Firefox** - Export settings, bookmarks, history, and passwords
- **Chrome** - Export settings, bookmarks, history, and passwords
- **Safari** - Export bookmarks and history
- JSON output support for automation

### Security Scanning
- **Keychain** - Scan macOS Keychain for stored credentials and weak items
- **Certificates** - Check certificate transparency logs for domains
- **Hidden Processes** - Hunt for suspicious processes and launch agents
- **Applications** - Inspect app bundles for security issues
- **Breach Detection** - Check credentials against known data breaches (HaveIBeenPwned)
- **Secrets** - Find exposed API keys, passwords, and credentials in files
- **Wallets** - Locate cryptocurrency wallets and seed phrases
- **Certificate Authorities** - Audit installed CA certificates

## Installation

### From Source

```bash
# Clone and build
cd sekretsauce-cli
go build -o sekretsauce ./cmd/sekretsauce

# Install to /usr/local/bin
sudo cp sekretsauce /usr/local/bin/
```

### Using Make

```bash
make build
sudo make install
```

## Usage

### Browser Export

Export browser data to JSON:

```bash
# Export all browsers
sekretsauce export --json

# Export specific browser
sekretsauce export firefox --json
sekretsauce export chrome --json
sekretsauce export safari --json

# Include passwords (requires authorization)
sekretsauce export firefox --passwords --json
```

### Security Scanning

Run a full security scan:

```bash
sekretsauce scan
```

Or run specific scans:

```bash
# Keychain scan
sekretsauce scan keychain --json

# Certificate transparency check
sekretsauce scan certs --domain example.com

# Hunt for hidden processes
sekretsauce scan hidden --deep

# Inspect applications
sekretsauce scan apps --all

# Check for breaches
sekretsauce scan breach --email user@example.com
sekretsauce scan breach --domain example.com

# Scan for exposed secrets
sekretsauce scan secrets --path /path/to/scan

# Find cryptocurrency wallets
sekretsauce scan wallets --home --deep

# Audit CA certificates
sekretsauce scan cas
```

### Output Options

```bash
# JSON output
sekretsauce scan --json

# Save to file
sekretsauce scan -o report.json --json

# Verbose output
sekretsauce scan -v
```

## GUI Application

A native macOS GUI application is also available in `gui-apps/app/`. The GUI provides:

- Visual dashboard with security statistics
- One-click full system scan
- Interactive browser export
- Real-time scan progress
- Detailed findings view

Build the GUI:

```bash
cd gui-apps/app
swift build
```

## Examples

### Export Firefox passwords to JSON
```bash
sekretsauce export firefox --passwords --json -o firefox-data.json
```

### Full security scan with JSON output
```bash
sekretsauce scan --deep --json -o security-report.json
```

### Check if domain has breached credentials
```bash
sekretsauce scan breach --domain company.com --json
```

### Find all cryptocurrency wallets
```bash
sekretsauce scan wallets --home --deep --json
```

## Architecture

```
sekretsauce-cli/
├── cmd/sekretsauce/        # Main CLI entry point
│   ├── cmd/                # Cobra commands
│   │   ├── root.go         # Root command
│   │   ├── export.go       # Browser export commands
│   │   └── scan.go         # Security scan commands
│   └── main.go
├── pkg/                    # Core packages
│   ├── browser/            # Browser data extraction
│   ├── keychain/           # macOS Keychain scanning
│   ├── certs/              # Certificate transparency
│   ├── hunter/             # Hidden process detection
│   ├── inspector/          # App security inspection
│   ├── breach/             # Breach detection (HIBP)
│   ├── secrets/            # Secret scanning
│   ├── wallet/             # Cryptocurrency wallet detection
│   └── ca/                 # CA certificate auditing
└── internal/
    └── output/             # Output formatting
```

## Permissions

Some features require special permissions:

- **Keychain** - May prompt for keychain access
- **Passwords** - Requires explicit `--passwords` flag and authorization
- **System Files** - Some scans may require elevated privileges

## Output Format

All commands support JSON output with `--json`:

```json
{
  "total_items": 150,
  "password_items": 120,
  "weak_items": [
    {
      "item": {
        "service": "example.com",
        "account": "user@example.com"
      },
      "reason": "Password may be compromised",
      "severity": "high"
    }
  ]
}
```

## Contributing

Internal use only - After Dark Systems, LLC

## License

MIT. See [LICENSE](../LICENSE).

## Support

For support and questions:
- Website: https://secretserver.io
- Company: After Dark Systems, LLC

---

© 2024 After Dark Systems, LLC. All rights reserved.
