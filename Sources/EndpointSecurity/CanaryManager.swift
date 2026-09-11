import Common
import Darwin
import Foundation

/// Only the daemon writes canaries. Paths are derived from the authenticated UID;
/// directory-relative descriptors prevent user-controlled symlink traversal.
public enum CanaryManager {
    private static let contents = Data("SeKretSauce ransomware detection canary. Do not edit.\n".utf8)
    private static let names = ["important-documents.txt", "family-photos.txt"]
    public static func install(for uid: uid_t) throws {
        guard let entry = getpwuid(uid) else { throw ControlError.unavailable("User home unavailable") }
        let home = String(cString: entry.pointee.pw_dir)
        try install(home: home, uid: uid)
    }
    static func install(home: String, uid: uid_t) throws {
        let homeFD = open(home, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        guard homeFD >= 0 else { throw ControlError.unavailable("Cannot open user home") }
        defer { close(homeFD) }
        let docs = openat(homeFD, "Documents", O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        guard docs >= 0 else {
            throw ControlError.unavailable("Documents directory must exist and cannot be a symbolic link")
        }
        defer { close(docs) }
        if mkdirat(docs, ".sekretsauce-canary", 0o700) != 0 && errno != EEXIST {
            throw ControlError.unavailable("Cannot create canary directory")
        }
        let directory = openat(docs, ".sekretsauce-canary", O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        guard directory >= 0 else { throw ControlError.unavailable("Invalid canary directory") }
        defer { close(directory) }
        // The directory belongs to the user; only these fixed files are replaced.
        for name in names {
            let temporary = ".install-" + UUID().uuidString
            let fd = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o400)
            guard fd >= 0 else { throw ControlError.unavailable("Cannot stage canary") }
            defer {
                close(fd)
                unlinkat(directory, temporary, 0)
            }
            let data = contents
            guard data.withUnsafeBytes({ Darwin.write(fd, $0.baseAddress, $0.count) }) == data.count,
                fchmod(fd, 0o400) == 0, fchown(fd, uid, gid_t.max) == 0, fsync(fd) == 0,
                renameat(directory, temporary, directory, name) == 0
            else { throw ControlError.unavailable("Cannot install canary") }
        }
        guard fchown(directory, uid, gid_t.max) == 0, fchmod(directory, 0o700) == 0,
            fsync(directory) == 0
        else { throw ControlError.unavailable("Cannot secure canaries") }
    }
    public static func installed(for uid: uid_t) -> Bool {
        guard let entry = getpwuid(uid) else { return false }
        let home = String(cString: entry.pointee.pw_dir)
        return installed(home: home, uid: uid)
    }
    static func installed(home: String, uid: uid_t) -> Bool {
        let homeFD = open(home, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        guard homeFD >= 0 else { return false }
        defer { close(homeFD) }
        let docs = openat(homeFD, "Documents", O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        guard docs >= 0 else { return false }
        defer { close(docs) }
        let directory = openat(docs, ".sekretsauce-canary", O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        guard directory >= 0 else { return false }
        defer { close(directory) }
        return names.allSatisfy { name in
            let fd = openat(directory, name, O_RDONLY | O_NOFOLLOW)
            guard fd >= 0 else { return false }
            defer { close(fd) }
            var info = stat()
            guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG, info.st_uid == uid,
                info.st_size == contents.count, (info.st_mode & 0o777) == 0o400
            else { return false }
            let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: false)
            return (try? handle.readToEnd()) == contents
        }
    }
}
