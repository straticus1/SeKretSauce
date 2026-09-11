import Darwin
import Foundation

struct ScanChanges {
    let added: [ScanReport.ReportFinding]
    let continuing: [ScanReport.ReportFinding]
    let resolved: [ScanReport.ReportFinding]
    let unobserved: [ScanReport.ReportFinding]

    // Use each scanner's latest successful run so an unavailable scan cannot erase its baseline.
    static func compare(history: [ScanReport], current: ScanReport) -> ScanChanges? {
        let matching = history.filter { $0.target == current.target && $0.profile == current.profile }
        guard !matching.isEmpty else { return nil }
        var components: [ScanReport.Component] = []
        var findings: [ScanReport.ReportFinding] = []
        let scannerIDs = Set(matching.flatMap { $0.components.map(\.scannerID) })
        for id in scannerIDs {
            let baseline =
                matching.first { $0.components.contains { $0.scannerID == id && $0.status == "completed" } }
                ?? matching.first { $0.components.contains { $0.scannerID == id } }
            if let baseline, let component = baseline.components.first(where: { $0.scannerID == id }) {
                components.append(component)
                findings += baseline.findings.filter { $0.scannerID == id }
            }
        }
        let previous = ScanReport(
            target: current.target, schemaVersion: 1, runID: "baseline", profile: current.profile,
            startedAt: "", finishedAt: "", status: "completed", components: components, findings: findings
        )
        return compare(previous: previous, current: current)
    }

    static func compare(previous: ScanReport, current: ScanReport) -> ScanChanges {
        let before = Dictionary(uniqueKeysWithValues: previous.findings.map { ($0.id, $0) })
        let after = Dictionary(uniqueKeysWithValues: current.findings.map { ($0.id, $0) })
        let previousVersions = Dictionary(
            uniqueKeysWithValues: previous.components.map { ($0.scannerID, $0.version) })
        let comparable = Set(
            current.components.filter { component in
                component.status == "completed"
                    && previous.components.contains(where: {
                        $0.scannerID == component.scannerID && $0.status == "completed"
                    }) && previousVersions[component.scannerID] == component.version
                    && previous.target == current.target && previous.profile == current.profile
            }.map(\.scannerID))
        let removed = previous.findings.filter { after[$0.id] == nil }
        return ScanChanges(
            added: current.findings.filter { before[$0.id] == nil },
            continuing: current.findings.filter { before[$0.id] != nil },
            resolved: removed.filter { comparable.contains($0.scannerID) },
            unobserved: removed.filter { !comparable.contains($0.scannerID) })
    }
}

/// Stores only the normalized report, never scanner raw data or secret matches.
final class ScanHistory {
    private let directory: URL
    private let retention: Int
    init(directory: URL? = nil, retention: Int = 20) {
        self.directory =
            directory
            ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("SeKretSauce/scan-history")
        self.retention = max(1, min(retention, 100))
    }
    func load() throws -> [ScanReport] {
        let fd = try openDirectory()
        defer { close(fd) }
        var reports: [ScanReport] = []
        for name in try FileManager.default.contentsOfDirectory(atPath: directory.path)
        where name.hasSuffix(".json") {
            let file = openat(fd, name, O_RDONLY | O_NOFOLLOW)
            guard file >= 0 else { throw CLIError.invalidResponse }
            let handle = FileHandle(fileDescriptor: file, closeOnDealloc: true)
            var info = stat()
            guard fstat(file, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG, info.st_uid == getuid(),
                info.st_size <= 4 * 1024 * 1024
            else { throw CLIError.invalidResponse }
            reports.append(try ScanReport.decode(handle.readToEnd() ?? Data()))
        }
        return reports.sorted { $0.finishedAt > $1.finishedAt }
    }
    func save(_ report: ScanReport) throws {
        guard report.runID.range(of: "^[A-Za-z0-9_-]{1,100}$", options: .regularExpression) != nil
        else { throw CLIError.invalidResponse }
        let fd = try openDirectory()
        defer { close(fd) }
        let name = report.runID + ".json"
        let temporary = ".pending-" + UUID().uuidString
        let file = openat(fd, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard file >= 0 else { throw CLIError.invalidResponse }
        defer {
            close(file)
            unlinkat(fd, temporary, 0)
        }
        let data = try JSONEncoder().encode(report)
        try data.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let n = Darwin.write(file, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
                if n < 0 && errno == EINTR { continue }
                guard n > 0 else { throw CLIError.invalidResponse }
                offset += n
            }
        }
        guard fsync(file) == 0, renameat(fd, temporary, fd, name) == 0, fsync(fd) == 0 else {
            throw CLIError.invalidResponse
        }
        for old in try load().dropFirst(retention) {
            guard old.runID.range(of: "^[A-Za-z0-9_-]{1,100}$", options: .regularExpression) != nil else {
                continue
            }
            if unlinkat(fd, old.runID + ".json", 0) != 0 { throw CLIError.invalidResponse }
        }
    }
    private func openDirectory() throws -> Int32 {
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let fd = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        guard fd >= 0 else { throw CLIError.invalidResponse }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_uid == getuid(), fchmod(fd, 0o700) == 0 else {
            close(fd)
            throw CLIError.invalidResponse
        }
        return fd
    }
}
