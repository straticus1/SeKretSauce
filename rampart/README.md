# Rampart

**"One Place to Rule Them All"**

Unified macOS Firewall Control - GUI + CLI for managing pf (packet filter) and Application Firewall.

## Components

```
rampart/
├── FirewallKit/      # Core library (Swift)
│   ├── PFManager         - Packet filter management (pfctl wrapper)
│   ├── AppFirewallManager - Application firewall (socketfilterfw wrapper)
│   └── NetStateMonitor   - Network connection monitoring
│
├── FirewallHelper/   # Privileged XPC helper (runs as root)
│   └── XPC service for firewall operations requiring elevation
│
├── CLI/              # Command-line interface
│   └── rampart          - Unified firewall CLI
│
├── GUI/              # SwiftUI application
│   ├── Dashboard        - Status overview
│   ├── PF View          - pf rule management
│   ├── App Firewall     - Per-app rules
│   ├── Network View     - Live connections
│   └── Menu Bar         - Quick access
│
└── build/            # Built artifacts
    ├── Rampart.app      - macOS application
    └── rampart          - CLI binary
```

## Building

```bash
./build.sh
```

Output:
- `build/Rampart.app` - GUI application
- `build/rampart` - CLI tool

## CLI Usage

```bash
# Overall status
rampart status

# Packet Filter
rampart pf status
rampart pf enable
rampart pf disable
rampart pf rules
rampart pf reload

# Application Firewall
rampart app status
rampart app enable
rampart app disable
rampart app list
rampart app allow /path/to/app
rampart app block /path/to/app
rampart app stealth on|off

# Network Monitoring
rampart net connections
rampart net listeners
rampart net summary
rampart net watch

# Quick Actions
rampart block 1.2.3.4       # Block IP via pf
rampart allow /path/to/app  # Allow app via App Firewall
```

## Installation

### GUI App
```bash
cp -r build/Rampart.app /Applications/
```

### CLI
```bash
sudo cp build/rampart /usr/local/bin/
```

### Privileged Helper (for root operations)
The helper is installed automatically via SMJobBless when the GUI app first runs, or manually:
```bash
sudo cp build/Rampart.app/Contents/Library/LaunchServices/com.rampart.FirewallHelper /Library/PrivilegedHelperTools/
sudo cp build/LaunchDaemons/com.rampart.FirewallHelper.plist /Library/LaunchDaemons/
sudo launchctl load /Library/LaunchDaemons/com.rampart.FirewallHelper.plist
```

## Requirements

- macOS 14.0+
- Swift 5.9+
- Root/admin access for firewall operations

## Part of SeKretSauce

Rampart is a component of the SeKretSauce macOS security suite.

---
*"Blind guy makes software for Blind Spots" -RyCat*
