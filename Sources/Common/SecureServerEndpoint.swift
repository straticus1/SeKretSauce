import Foundation

public struct SecureServerEndpoint: Equatable {
    public let baseURL: URL

    public init(_ value: String) throws {
        guard var components = URLComponents(string: value),
              components.scheme?.lowercased() == "https",
              let host = components.host,
              !host.isEmpty,
              components.user == nil,
              components.password == nil,
              components.query == nil,
              components.fragment == nil else {
            throw SecureServerEndpointError.invalidHTTPSURL
        }

        components.scheme = "https"
        components.host = host.lowercased()
        while components.path.count > 1 && components.path.hasSuffix("/") {
            components.path.removeLast()
        }

        guard let url = components.url else {
            throw SecureServerEndpointError.invalidHTTPSURL
        }
        self.baseURL = url
    }

    public func appending(path: String) -> URL {
        path.split(separator: "/").reduce(baseURL) { url, component in
            url.appendingPathComponent(String(component), isDirectory: false)
        }
    }
}

public enum SecureServerEndpointError: Error, LocalizedError {
    case invalidHTTPSURL

    public var errorDescription: String? {
        "Server URL must be an HTTPS URL with a valid host and no embedded credentials"
    }
}
