import Foundation

@MainActor
final class RansomwareShieldControls: ObservableObject {
    @Published private(set) var canaryInstalled = false
    @Published private(set) var statusMessage = ""

    private let canaryDirectoryName = ".sekretsauce-canary"
    private let canaryFiles = ["important-documents.txt", "family-photos.txt"]

    init() {
        refresh()
    }

    func refresh() {
        canaryInstalled = canaryFiles.allSatisfy {
            FileManager.default.fileExists(
                atPath: canaryDirectory.appendingPathComponent($0).path
            )
        }
    }

    func installCanaries() {
        do {
            try FileManager.default.createDirectory(
                at: canaryDirectory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            for name in canaryFiles {
                let file = canaryDirectory.appendingPathComponent(name)
                let content = Data(
                    "SeKretSauce ransomware detection canary. Do not edit.\n".utf8
                )
                try content.write(to: file, options: [.atomic])
                try FileManager.default.setAttributes(
                    [.posixPermissions: 0o400],
                    ofItemAtPath: file.path
                )
            }
            statusMessage = "Canaries installed. Unexpected modification triggers immediate containment."
        } catch {
            statusMessage = "Could not install canaries: \(error.localizedDescription)"
        }
        refresh()
    }

    private var canaryDirectory: URL {
        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
            ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Documents")
        return documents.appendingPathComponent(canaryDirectoryName, isDirectory: true)
    }
}
