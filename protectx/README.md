# ADS ProtectX

**"One Place to Rule Them All"**

Unified macOS Firewall Control - GUI + CLI for managing pf (packet filter) and Application Firewall.

## Components

```
protectx/
├── FirewallKit/      # Core library (Swift)
│   ├── PFManager         - Packet filter management (pfctl wrapper)
│   ├── AppFirewallManager - Application firewall (socketfilterfw wrapper)
│   └── NetStateMonitor   - Network connection monitoring
│
├── FirewallHelper/   # Privileged XPC helper (runs as root)
│   └── XPC service for firewall operations requiring elevation
│
├── CLI/              # Command-line interface
│   └── adsp             - Unified firewall CLI
│
├── GUI/              # SwiftUI application
│   ├── Dashboard        - Status overview
│   ├── PF View          - pf rule management
│   ├── App Firewall     - Per-app rules
│   ├── Network View     - Live connections
│   └── Menu Bar         - Quick access
│
└── build/            # Built artifacts
    ├── ProtectX.app     - macOS application
    └── adsp             - CLI binary
```

## Building

```bash
./build.sh
```

Output:
- `build/ProtectX.app` - GUI application
- `build/adsp` - CLI tool

## CLI Usage

```bash
# Overall status
adsp status

# Packet Filter
adsp pf status
adsp pf enable
adsp pf disable
adsp pf rules
adsp pf reload

# Application Firewall
adsp app status
adsp app enable
adsp app disable
adsp app list
adsp app allow /path/to/app
adsp app block /path/to/app
adsp app stealth on|off

# Network Monitoring
adsp net connections
adsp net listeners
adsp net summary
adsp net watch

# Quick Actions
adsp block 1.2.3.4       # Block IP via pf
adsp allow /path/to/app  # Allow app via App Firewall
```

## Installation

### GUI App
```bash
cp -r build/ProtectX.app /Applications/
```

### CLI
```bash
sudo cp build/adsp /usr/local/bin/
```

### Privileged Helper (for root operations)
The helper is installed automatically via SMJobBless when the GUI app first runs, or manually:
```bash
sudo cp build/ProtectX.app/Contents/Library/LaunchServices/com.afterdark.protectx.helper /Library/PrivilegedHelperTools/
sudo cp build/LaunchDaemons/com.afterdark.protectx.helper.plist /Library/LaunchDaemons/
sudo launchctl load /Library/LaunchDaemons/com.afterdark.protectx.helper.plist
```

## Requirements

- macOS 14.0+
- Swift 5.9+
- Root/admin access for firewall operations

## Part of SeKretSauce

ADS ProtectX is a component of the SeKretSauce macOS security suite by AfterDark Security.

---
*"Blind guy makes software for Blind Spots" -RyCat*
