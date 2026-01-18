import Foundation

/// Parses SSH command line arguments to extract connection details and tunnel configurations
public struct SSHArgumentParser {

    public struct ParsedSSHCommand {
        public let user: String?
        public let host: String
        public let port: UInt16
        public let identityFile: String?
        public let configFile: String?
        public let command: String?
        public let tunnels: [SSHTunnelFlag]
        public let originalArguments: [String]
        public let forwardAgent: Bool
        public let forwardX11: Bool
        public let quietMode: Bool
        public let verboseMode: Bool
        public let batchMode: Bool

        public var destination: String {
            if let user = user {
                return "\(user)@\(host):\(port)"
            }
            return "\(host):\(port)"
        }
    }

    public init() {}

    /// Parse SSH command line arguments
    public func parse(_ arguments: [String]) -> ParsedSSHCommand? {
        var args = Array(arguments.dropFirst()) // Remove 'ssh' or wrapper name
        var user: String?
        var host: String?
        var port: UInt16 = 22
        var identityFile: String?
        var configFile: String?
        var command: String?
        var tunnels: [SSHTunnelFlag] = []
        var forwardAgent = false
        var forwardX11 = false
        var quietMode = false
        var verboseMode = false
        var batchMode = false

        var i = 0
        while i < args.count {
            let arg = args[i]

            switch arg {
            // Port
            case "-p":
                if i + 1 < args.count {
                    port = UInt16(args[i + 1]) ?? 22
                    i += 1
                }

            // User
            case "-l":
                if i + 1 < args.count {
                    user = args[i + 1]
                    i += 1
                }

            // Identity file
            case "-i":
                if i + 1 < args.count {
                    identityFile = args[i + 1]
                    i += 1
                }

            // Config file
            case "-F":
                if i + 1 < args.count {
                    configFile = args[i + 1]
                    i += 1
                }

            // Local forward: -L [bind_address:]port:host:hostport
            case "-L":
                if i + 1 < args.count {
                    if let tunnel = parseLocalForward(args[i + 1]) {
                        tunnels.append(tunnel)
                    }
                    i += 1
                }

            // Remote forward: -R [bind_address:]port:host:hostport
            case "-R":
                if i + 1 < args.count {
                    if let tunnel = parseRemoteForward(args[i + 1]) {
                        tunnels.append(tunnel)
                    }
                    i += 1
                }

            // Dynamic (SOCKS) forward: -D [bind_address:]port
            case "-D":
                if i + 1 < args.count {
                    if let tunnel = parseDynamicForward(args[i + 1]) {
                        tunnels.append(tunnel)
                    }
                    i += 1
                }

            // TUN/TAP device: -w local_tun[:remote_tun]
            case "-w":
                if i + 1 < args.count {
                    if let tunnel = parseTunDevice(args[i + 1]) {
                        tunnels.append(tunnel)
                    }
                    i += 1
                }

            // Agent forwarding
            case "-A":
                forwardAgent = true

            // No agent forwarding
            case "-a":
                forwardAgent = false

            // X11 forwarding
            case "-X", "-Y":
                forwardX11 = true

            // No X11 forwarding
            case "-x":
                forwardX11 = false

            // Quiet mode
            case "-q":
                quietMode = true

            // Verbose mode
            case "-v", "-vv", "-vvv":
                verboseMode = true

            // Batch mode
            case "-B":
                batchMode = true

            // Options: -o key=value
            case "-o":
                if i + 1 < args.count {
                    // Could parse specific options here if needed
                    i += 1
                }

            // Combined options like -L8080:localhost:80
            default:
                if arg.hasPrefix("-L") && arg.count > 2 {
                    let spec = String(arg.dropFirst(2))
                    if let tunnel = parseLocalForward(spec) {
                        tunnels.append(tunnel)
                    }
                } else if arg.hasPrefix("-R") && arg.count > 2 {
                    let spec = String(arg.dropFirst(2))
                    if let tunnel = parseRemoteForward(spec) {
                        tunnels.append(tunnel)
                    }
                } else if arg.hasPrefix("-D") && arg.count > 2 {
                    let spec = String(arg.dropFirst(2))
                    if let tunnel = parseDynamicForward(spec) {
                        tunnels.append(tunnel)
                    }
                } else if arg.hasPrefix("-p") && arg.count > 2 {
                    let portStr = String(arg.dropFirst(2))
                    port = UInt16(portStr) ?? 22
                } else if !arg.hasPrefix("-") {
                    // This is either the destination or a remote command
                    if host == nil {
                        // Parse user@host or just host
                        let (parsedUser, parsedHost) = parseDestination(arg)
                        if let pu = parsedUser { user = pu }
                        host = parsedHost
                    } else {
                        // Everything else is the remote command
                        command = args[i...].joined(separator: " ")
                        break
                    }
                }
            }

            i += 1
        }

        guard let finalHost = host else {
            return nil
        }

        return ParsedSSHCommand(
            user: user,
            host: finalHost,
            port: port,
            identityFile: identityFile,
            configFile: configFile,
            command: command,
            tunnels: tunnels,
            originalArguments: arguments,
            forwardAgent: forwardAgent,
            forwardX11: forwardX11,
            quietMode: quietMode,
            verboseMode: verboseMode,
            batchMode: batchMode
        )
    }

    // MARK: - Destination Parsing

    private func parseDestination(_ destination: String) -> (user: String?, host: String) {
        if destination.contains("@") {
            let parts = destination.split(separator: "@", maxSplits: 1)
            if parts.count == 2 {
                return (String(parts[0]), String(parts[1]))
            }
        }
        return (nil, destination)
    }

    // MARK: - Tunnel Parsing

    /// Parse local forward: [bind_address:]port:host:hostport
    private func parseLocalForward(_ spec: String) -> SSHTunnelFlag? {
        let parts = spec.split(separator: ":").map(String.init)

        switch parts.count {
        case 3:
            // port:host:hostport
            guard let bindPort = UInt16(parts[0]),
                  let targetPort = UInt16(parts[2]) else { return nil }
            return SSHTunnelFlag(
                type: .localForward,
                bindAddress: nil,
                bindPort: bindPort,
                targetHost: parts[1],
                targetPort: targetPort
            )
        case 4:
            // bind_address:port:host:hostport
            guard let bindPort = UInt16(parts[1]),
                  let targetPort = UInt16(parts[3]) else { return nil }
            return SSHTunnelFlag(
                type: .localForward,
                bindAddress: parts[0],
                bindPort: bindPort,
                targetHost: parts[2],
                targetPort: targetPort
            )
        default:
            return nil
        }
    }

    /// Parse remote forward: [bind_address:]port:host:hostport
    private func parseRemoteForward(_ spec: String) -> SSHTunnelFlag? {
        let parts = spec.split(separator: ":").map(String.init)

        switch parts.count {
        case 3:
            guard let bindPort = UInt16(parts[0]),
                  let targetPort = UInt16(parts[2]) else { return nil }
            return SSHTunnelFlag(
                type: .remoteForward,
                bindAddress: nil,
                bindPort: bindPort,
                targetHost: parts[1],
                targetPort: targetPort
            )
        case 4:
            guard let bindPort = UInt16(parts[1]),
                  let targetPort = UInt16(parts[3]) else { return nil }
            return SSHTunnelFlag(
                type: .remoteForward,
                bindAddress: parts[0],
                bindPort: bindPort,
                targetHost: parts[2],
                targetPort: targetPort
            )
        default:
            return nil
        }
    }

    /// Parse dynamic forward: [bind_address:]port
    private func parseDynamicForward(_ spec: String) -> SSHTunnelFlag? {
        let parts = spec.split(separator: ":").map(String.init)

        switch parts.count {
        case 1:
            guard let port = UInt16(parts[0]) else { return nil }
            return SSHTunnelFlag(
                type: .dynamicSOCKS,
                bindAddress: nil,
                bindPort: port,
                targetHost: nil,
                targetPort: nil
            )
        case 2:
            guard let port = UInt16(parts[1]) else { return nil }
            return SSHTunnelFlag(
                type: .dynamicSOCKS,
                bindAddress: parts[0],
                bindPort: port,
                targetHost: nil,
                targetPort: nil
            )
        default:
            return nil
        }
    }

    /// Parse TUN device: local_tun[:remote_tun]
    private func parseTunDevice(_ spec: String) -> SSHTunnelFlag? {
        // TUN device numbers can be "any" or a number
        let parts = spec.split(separator: ":").map(String.init)
        let localTun = parts.first ?? "any"

        // Using bindPort to store local tun number (0 for "any")
        let tunNum = UInt16(localTun) ?? 0

        return SSHTunnelFlag(
            type: .tunDevice,
            bindAddress: nil,
            bindPort: tunNum,
            targetHost: nil,
            targetPort: parts.count > 1 ? UInt16(parts[1]) : nil
        )
    }
}
