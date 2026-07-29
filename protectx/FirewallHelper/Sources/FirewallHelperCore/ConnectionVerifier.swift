import Foundation
import Security

public struct CodeSigningIdentity: Equatable {
    public let bundleIdentifier: String?
    public let teamIdentifier: String?

    public init(bundleIdentifier: String?, teamIdentifier: String?) {
        self.bundleIdentifier = bundleIdentifier
        self.teamIdentifier = teamIdentifier
    }
}

public struct ClientCodeSigningPolicy {
    private let allowedBundleIdentifiers: Set<String>

    public init(allowedBundleIdentifiers: Set<String>) {
        self.allowedBundleIdentifiers = allowedBundleIdentifiers
    }

    public func allows(
        client: CodeSigningIdentity,
        helperTeamIdentifier: String?
    ) -> Bool {
        guard let helperTeamIdentifier,
              !helperTeamIdentifier.isEmpty,
              let clientTeamIdentifier = client.teamIdentifier,
              clientTeamIdentifier == helperTeamIdentifier,
              let bundleIdentifier = client.bundleIdentifier,
              allowedBundleIdentifiers.contains(bundleIdentifier) else {
            return false
        }
        return true
    }
}

public final class ConnectionVerifier {
    private let policy: ClientCodeSigningPolicy

    public init(
        allowedBundleIdentifiers: Set<String> = [
            "com.rampart.Rampart",
            "com.afterdark.protectx"
        ]
    ) {
        self.policy = ClientCodeSigningPolicy(
            allowedBundleIdentifiers: allowedBundleIdentifiers
        )
    }

    public func verify(processIdentifier: pid_t) -> Bool {
        guard processIdentifier > 0,
              let clientCode = staticCode(for: processIdentifier),
              validateSignature(clientCode),
              let helperCode = ownStaticCode() else {
            return false
        }

        return policy.allows(
            client: identity(for: clientCode),
            helperTeamIdentifier: identity(for: helperCode).teamIdentifier
        )
    }

    private func staticCode(for processIdentifier: pid_t) -> SecStaticCode? {
        let attributes = [
            kSecGuestAttributePid as String: NSNumber(value: processIdentifier)
        ] as CFDictionary

        var dynamicCode: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &dynamicCode) == errSecSuccess,
              let dynamicCode else {
            return nil
        }

        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(dynamicCode, [], &staticCode) == errSecSuccess else {
            return nil
        }
        return staticCode
    }

    private func ownStaticCode() -> SecStaticCode? {
        var dynamicCode: SecCode?
        guard SecCodeCopySelf([], &dynamicCode) == errSecSuccess,
              let dynamicCode else {
            return nil
        }

        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(dynamicCode, [], &staticCode) == errSecSuccess else {
            return nil
        }
        return staticCode
    }

    private func validateSignature(_ code: SecStaticCode) -> Bool {
        let flags = SecCSFlags(
            rawValue: UInt32(kSecCSStrictValidate | kSecCSCheckAllArchitectures)
        )
        return SecStaticCodeCheckValidity(code, flags, nil) == errSecSuccess
    }

    private func identity(for code: SecStaticCode) -> CodeSigningIdentity {
        var signingInformation: CFDictionary?
        guard SecCodeCopySigningInformation(code, [], &signingInformation) == errSecSuccess,
              let information = signingInformation as? [String: Any] else {
            return CodeSigningIdentity(bundleIdentifier: nil, teamIdentifier: nil)
        }

        return CodeSigningIdentity(
            bundleIdentifier: information[kSecCodeInfoIdentifier as String] as? String,
            teamIdentifier: information[kSecCodeInfoTeamIdentifier as String] as? String
        )
    }
}
