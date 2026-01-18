# SeKretSauce

A comprehensive macOS security agent for monitoring SSH sessions, detecting tunneling activity, and providing network visibility for compliance and security auditing.

## Features

### SSH Session Recording
- Full session capture in Asciicast v2 format (compatible with asciinema player)
- Tunnel flag detection (-L, -R, -D, -w)
- Real-time audit logging

### Tunnel Detection
- **Cloudflare Tunnel** (cloudflared, trycloudflare.com)
- **ngrok** (ngrok.io)
- **Tailscale** (ts.net)
- **SSH tunnels** (local/remote/dynamic forwards)
- **DNS tunneling** (entropy analysis, suspicious query patterns)
- **HTTP CONNECT tunnels**
- **WebSocket tunnels**
- Generic tunnel service detection (serveo, localhost.run, bore, frp, chisel, etc.)

### Network Monitoring
- DNS query logging and analysis
- Transparent proxy for connection metadata
- TLS SNI extraction
- Content filtering (WebKit-based traffic)

### Process Monitoring
- Endpoint Security framework integration
- Process execution tracking
- Sensitive file access monitoring
- Kernel extension load detection

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Launch Daemon (root)                      │
│              Authenticates on boot, manages agents           │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ SSH Wrapper │  │ Network Ext │  │ Tunnel Detection    │  │
│  │ + Recording │  │ (DNS/Proxy) │  │ Engine              │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ Endpoint    │  │ File        │  │ Audit Logger        │  │
│  │ Security    │  │ Monitor     │  │ (JSONL format)      │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                   Secure Log Storage + API                   │
└─────────────────────────────────────────────────────────────┘
```

## Requirements

- macOS 13 (Ventura) or later
- Apple Developer account (for code signing)
- Endpoint Security entitlement (requires Apple approval)
- Root privileges for daemon

## Building

```bash
# Build release version
swift build -c release

# Build debug version
swift build
```

## Installation

```bash
# Build first
swift build -c release

# Install (requires root)
sudo ./Installer/install.sh
```

## Configuration

### Initial Setup

```bash
sudo /Library/Application\ Support/SeKretSauce/sekretsauced --setup
```

You'll be prompted for:
- Server URL (for centralized logging)
- API key

### Check Status

```bash
sudo /Library/Application\ Support/SeKretSauce/sekretsauced --status
```

## Logs

- **Daemon logs**: `/Library/Logs/SeKretSauce/daemon.log`
- **Audit logs**: `/Library/Application Support/SeKretSauce/logs/audit-YYYY-MM-DD.jsonl`
- **SSH recordings**: `/Library/Application Support/SeKretSauce/recordings/`

### Audit Log Format (JSONL)

```json
{
  "id": "uuid",
  "timestamp": "2024-01-15T10:30:00Z",
  "eventType": "TUNNEL_ALERT",
  "severity": "HIGH",
  "source": "TunnelDetection",
  "message": "SSH tunnel detected: SSH Tunnel",
  "metadata": {
    "process_path": "/usr/bin/ssh",
    "tunnel_type": "Local Forward (-L)"
  }
}
```

## Components

### Daemon (`sekretsauced`)
Main daemon that runs at boot with root privileges. Manages all other components.

### SSH Wrapper (`ssh-wrapper`)
Intercepts SSH commands to:
- Record sessions in asciicast format
- Detect and log tunnel flags
- Alert on connections to known tunnel services

### Network Extension
System extension providing:
- **DNS Proxy**: Intercepts all DNS queries for analysis
- **Transparent Proxy**: Monitors TCP connections
- **Content Filter**: Deep packet inspection for WebKit traffic

### Endpoint Security Monitor
Uses Apple's Endpoint Security framework to monitor:
- Process execution (exec events)
- File access (open/write events)
- System changes (kext loading, mounts)

## Entitlements Required

```xml
<!-- Main daemon -->
<key>com.apple.developer.endpoint-security.client</key>
<true/>

<!-- Network Extension -->
<key>com.apple.developer.networking.networkextension</key>
<array>
    <string>dns-proxy</string>
    <string>app-proxy-provider</string>
    <string>content-filter-provider</string>
</array>

<!-- System Extension host -->
<key>com.apple.developer.system-extension.install</key>
<true/>
```

## Uninstallation

```bash
sudo ./Installer/uninstall.sh
```

## Development

### Project Structure

```
SeKretSauce/
├── Sources/
│   ├── Common/           # Shared models and utilities
│   ├── Daemon/           # Main daemon
│   ├── SSHRecorder/      # SSH wrapper and recording
│   ├── NetworkExtension/ # DNS/Proxy providers
│   ├── TunnelDetection/  # Detection engine
│   └── EndpointSecurity/ # Process monitoring
├── Tests/
├── Resources/            # Plists, entitlements
├── Installer/            # Install/uninstall scripts
└── Package.swift
```

### Running Tests

```bash
swift test
```

## Security Considerations

- Runs as root for full system access
- Credentials stored in macOS Keychain
- Logs encrypted at rest (implement based on your requirements)
- Requires MDM deployment for enterprise use

## Known Tunnel Services Detected

| Service | Detection Method |
|---------|------------------|
| Cloudflare Tunnel | Process, DNS, ports |
| ngrok | Process, DNS |
| Tailscale | Process, DNS, ports |
| WireGuard | Process, ports |
| OpenVPN | Process, ports |
| serveo.net | DNS |
| localhost.run | DNS |
| bore.pub | DNS, process |
| frp | Process, ports |
| chisel | Process |

## License

Proprietary - All rights reserved.

## Contributing

Internal use only.
