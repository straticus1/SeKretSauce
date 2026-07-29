import Foundation

public enum SensitiveDataRedactor {
    private static let sensitiveKeys = [
        "password", "passwd", "pwd", "token", "secret", "api-key", "apikey",
        "access-key", "private-key", "authorization"
    ]

    public static func redact(arguments: [String]) -> [String] {
        var result: [String] = []
        var redactNext = false

        for argument in arguments {
            if redactNext {
                result.append("<redacted>")
                redactNext = false
                continue
            }

            let lowercased = argument.lowercased()
            if sensitiveKeys.contains(where: {
                lowercased == "--\($0)" || lowercased == "-\($0)"
            }) {
                result.append(argument)
                redactNext = true
                continue
            }

            if let separator = argument.firstIndex(of: "=") {
                let key = String(argument[..<separator]).lowercased()
                if sensitiveKeys.contains(where: { key.contains($0) }) {
                    result.append("\(argument[..<separator])=<redacted>")
                    continue
                }
            }

            if lowercased.hasPrefix("bearer ") {
                result.append("Bearer <redacted>")
                continue
            }

            if var components = URLComponents(string: argument),
               components.user != nil || components.password != nil {
                components.user = components.user == nil ? nil : "<redacted>"
                components.password = components.password == nil ? nil : "<redacted>"
                result.append(components.string ?? "<redacted-url>")
                continue
            }

            result.append(argument)
        }
        return result
    }
}
