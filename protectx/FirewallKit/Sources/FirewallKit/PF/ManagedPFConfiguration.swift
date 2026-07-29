import Foundation

enum ManagedPFConfiguration {
    static let anchorName = "com.afterdark.protectx"
    static let anchorPath = "/etc/pf.anchors/\(anchorName)"

    private static let startMarker = "# BEGIN ProtectX managed anchor"
    private static let endMarker = "# END ProtectX managed anchor"

    static func installAnchorReferences(in configuration: String) -> String {
        guard !configuration.contains(startMarker) else {
            return configuration
        }

        let separator = configuration.hasSuffix("\n") ? "" : "\n"
        return configuration + separator + """
        \(startMarker)
        anchor "\(anchorName)"
        load anchor "\(anchorName)" from "\(anchorPath)"
        \(endMarker)

        """
    }
}
