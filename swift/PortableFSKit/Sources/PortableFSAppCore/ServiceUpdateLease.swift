import Darwin
import Foundation

enum PortableFSDUpdatePhase: String, Codable, CaseIterable, Sendable {
    case preparingOld = "preparing-old"
    case oldAbsent = "old-absent"
    case targetReady = "target-ready"
    case targetActive = "target-active"
    case rollbackAbsent = "rollback-absent"
    case rollbackReady = "rollback-ready"
    case rollbackActive = "rollback-active"
    case targetComplete = "target-complete"
    case rollbackComplete = "rollback-complete"
}

struct PortableFSDUpdateLease: Codable, Equatable, Sendable {
    static let schemaVersion = 1
    static let lifetimeMilliseconds: Int64 = 5 * 60 * 1_000

    let schemaVersion: Int
    let phase: PortableFSDUpdatePhase
    let tokenSHA256: String
    let oldRelease: PortableFSDReleaseIdentity
    let targetRelease: PortableFSDReleaseIdentity
    let createdAtUnixMs: Int64
    let deadlineUnixMs: Int64

    func validate() throws {
        guard schemaVersion == Self.schemaVersion,
              tokenSHA256.utf8.count == 64,
              tokenSHA256.utf8.allSatisfy({
                  ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
              }),
              createdAtUnixMs > 0,
              deadlineUnixMs > createdAtUnixMs,
              deadlineUnixMs - createdAtUnixMs == Self.lifetimeMilliseconds else {
            throw PortableFSDUpdateLeaseError.invalidContract
        }
        try oldRelease.validate()
        try targetRelease.validate()
    }

    enum CodingKeys: String, CodingKey {
        case schemaVersion
        case phase
        case tokenSHA256
        case oldRelease
        case targetRelease
        case createdAtUnixMs
        case deadlineUnixMs
    }
}

enum PortableFSDUpdateLeaseError: Error, Equatable {
    case invalidDirectory(String)
    case inspect(path: String, errno: Int32)
    case unsafePath(String)
    case invalidContract
    case invalidEncoding
    case alreadyExists
    case stateChanged
}

/// Exact durable transaction state shared by the old host, new host, restored
/// old host, and installer. The parent directory is private and descriptor-
/// pinned. Every state transition is temp-write + fsync + rename + dir-fsync;
/// the plaintext installer token is never stored here. Completion is another
/// exact persisted phase, not deletion of the only durable transaction proof.
final class PortableFSDUpdateLeaseStore: @unchecked Sendable {
    static let filename = "activation.json"
    static let socketFilename = "update.sock"
    static let maximumBytes = 4_096

    let directoryURL: URL
    private let directoryDescriptor: Int32
    private let directoryDevice: dev_t
    private let directoryInode: ino_t
    private let directorySync: (Int32) -> Int32

    init(
        directoryURL: URL,
        directorySync: @escaping (Int32) -> Int32 = Darwin.fsync
    ) throws {
        let path = directoryURL.path
        let descriptor = Darwin.open(
            path,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else {
            throw PortableFSDUpdateLeaseError.inspect(path: path, errno: errno)
        }
        var status = stat()
        guard Darwin.fstat(descriptor, &status) == 0 else {
            let code = errno
            Darwin.close(descriptor)
            throw PortableFSDUpdateLeaseError.inspect(path: path, errno: code)
        }
        guard status.st_mode & S_IFMT == S_IFDIR,
              status.st_uid == geteuid(),
              status.st_mode & 0o777 == 0o700 else {
            Darwin.close(descriptor)
            throw PortableFSDUpdateLeaseError.invalidDirectory(path)
        }
        self.directoryURL = directoryURL
        self.directoryDescriptor = descriptor
        self.directoryDevice = status.st_dev
        self.directoryInode = status.st_ino
        self.directorySync = directorySync
    }

    deinit {
        Darwin.close(directoryDescriptor)
    }

    static func production() throws -> PortableFSDUpdateLeaseStore {
        let home = try PortableFSAccountHome.resolve()
        var descriptor = Darwin.open(
            home,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else {
            throw PortableFSDUpdateLeaseError.inspect(path: home, errno: errno)
        }
        var path = home
        do {
            for (index, component) in [".local", "state", "portablefs", "host"].enumerated() {
                if Darwin.mkdirat(descriptor, component, 0o700) == 0 {
                    guard Darwin.fsync(descriptor) == 0 else {
                        throw PortableFSDUpdateLeaseError.inspect(
                            path: path,
                            errno: errno
                        )
                    }
                } else if errno != EEXIST {
                    throw PortableFSDUpdateLeaseError.inspect(
                        path: path + "/" + component,
                        errno: errno
                    )
                }
                let next = Darwin.openat(
                    descriptor,
                    component,
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
                )
                guard next >= 0 else {
                    throw PortableFSDUpdateLeaseError.inspect(
                        path: path + "/" + component,
                        errno: errno
                    )
                }
                var status = stat()
                guard Darwin.fstat(next, &status) == 0 else {
                    let code = errno
                    Darwin.close(next)
                    throw PortableFSDUpdateLeaseError.inspect(
                        path: path + "/" + component,
                        errno: code
                    )
                }
                guard status.st_mode & S_IFMT == S_IFDIR,
                      status.st_uid == geteuid(),
                      status.st_mode & 0o022 == 0 else {
                    Darwin.close(next)
                    throw PortableFSDUpdateLeaseError.unsafePath(
                        path + "/" + component
                    )
                }
                if index == 3 {
                    guard Darwin.fchmod(next, 0o700) == 0,
                          Darwin.fstat(next, &status) == 0,
                          status.st_mode & 0o777 == 0o700 else {
                        let code = errno
                        Darwin.close(next)
                        throw PortableFSDUpdateLeaseError.inspect(
                            path: path + "/" + component,
                            errno: code
                        )
                    }
                }
                Darwin.close(descriptor)
                descriptor = next
                path += "/" + component
            }
            Darwin.close(descriptor)
            descriptor = -1
            return try PortableFSDUpdateLeaseStore(
                directoryURL: URL(fileURLWithPath: path, isDirectory: true)
            )
        } catch {
            if descriptor >= 0 {
                Darwin.close(descriptor)
            }
            throw error
        }
    }

    func load() throws -> PortableFSDUpdateLease? {
        let descriptor = Darwin.openat(
            directoryDescriptor,
            Self.filename,
            O_RDONLY | O_NOFOLLOW | O_CLOEXEC
        )
        if descriptor < 0, errno == ENOENT {
            return nil
        }
        guard descriptor >= 0 else {
            throw PortableFSDUpdateLeaseError.inspect(
                path: leasePath,
                errno: errno
            )
        }
        defer { Darwin.close(descriptor) }
        var status = stat()
        guard Darwin.fstat(descriptor, &status) == 0 else {
            throw PortableFSDUpdateLeaseError.inspect(
                path: leasePath,
                errno: errno
            )
        }
        guard status.st_mode & S_IFMT == S_IFREG,
              status.st_uid == geteuid(),
              status.st_nlink == 1,
              status.st_mode & 0o777 == 0o600,
              status.st_size > 0,
              status.st_size <= Self.maximumBytes else {
            throw PortableFSDUpdateLeaseError.unsafePath(leasePath)
        }
        var data = Data(count: Int(status.st_size))
        var offset = 0
        while offset < data.count {
            let remaining = data.count - offset
            let count = data.withUnsafeMutableBytes { bytes in
                Darwin.read(
                    descriptor,
                    bytes.baseAddress!.advanced(by: offset),
                    remaining
                )
            }
            if count < 0, errno == EINTR { continue }
            guard count > 0 else {
                throw PortableFSDUpdateLeaseError.invalidEncoding
            }
            offset += count
        }
        var trailing: UInt8 = 0
        let trailingCount = Darwin.read(descriptor, &trailing, 1)
        guard trailingCount == 0 else {
            throw PortableFSDUpdateLeaseError.invalidEncoding
        }
        try Self.validateExactJSON(data)
        let lease: PortableFSDUpdateLease
        do {
            lease = try JSONDecoder().decode(PortableFSDUpdateLease.self, from: data)
        } catch {
            throw PortableFSDUpdateLeaseError.invalidEncoding
        }
        try lease.validate()
        return lease
    }

    func create(_ lease: PortableFSDUpdateLease) throws {
        guard try load() == nil else {
            throw PortableFSDUpdateLeaseError.alreadyExists
        }
        try replace(expected: nil, with: lease)
    }

    func transition(
        from expected: PortableFSDUpdateLease,
        to replacement: PortableFSDUpdateLease
    ) throws {
        try replace(expected: expected, with: replacement)
    }

    private func replace(
        expected: PortableFSDUpdateLease?,
        with replacement: PortableFSDUpdateLease
    ) throws {
        try replacement.validate()
        guard try load() == expected else {
            throw PortableFSDUpdateLeaseError.stateChanged
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(replacement)
        guard data.count <= Self.maximumBytes else {
            throw PortableFSDUpdateLeaseError.invalidEncoding
        }
        let suffix = String(UInt64.random(in: UInt64.min...UInt64.max), radix: 16)
        let temporary = ".activation.json.\(getpid()).\(suffix).tmp"
        let descriptor = Darwin.openat(
            directoryDescriptor,
            temporary,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            0o600
        )
        guard descriptor >= 0 else {
            throw PortableFSDUpdateLeaseError.inspect(
                path: directoryURL.appendingPathComponent(temporary).path,
                errno: errno
            )
        }
        var renamed = false
        defer {
            Darwin.close(descriptor)
            if !renamed {
                _ = Darwin.unlinkat(directoryDescriptor, temporary, 0)
            }
        }
        var offset = 0
        while offset < data.count {
            let count = data.withUnsafeBytes { bytes in
                Darwin.write(
                    descriptor,
                    bytes.baseAddress!.advanced(by: offset),
                    data.count - offset
                )
            }
            if count < 0, errno == EINTR { continue }
            guard count > 0 else {
                throw PortableFSDUpdateLeaseError.inspect(
                    path: directoryURL.appendingPathComponent(temporary).path,
                    errno: errno
                )
            }
            offset += count
        }
        guard Self.sync(Darwin.fsync, descriptor: descriptor) == 0 else {
            throw PortableFSDUpdateLeaseError.inspect(
                path: directoryURL.appendingPathComponent(temporary).path,
                errno: errno
            )
        }
        guard try load() == expected else {
            throw PortableFSDUpdateLeaseError.stateChanged
        }
        guard Darwin.renameat(
            directoryDescriptor,
            temporary,
            directoryDescriptor,
            Self.filename
        ) == 0 else {
            throw PortableFSDUpdateLeaseError.inspect(path: leasePath, errno: errno)
        }
        renamed = true
        guard Self.sync(directorySync, descriptor: directoryDescriptor) == 0 else {
            throw PortableFSDUpdateLeaseError.inspect(
                path: directoryURL.path,
                errno: errno
            )
        }
    }

    private static func sync(
        _ operation: (Int32) -> Int32,
        descriptor: Int32
    ) -> Int32 {
        while true {
            let result = operation(descriptor)
            if result < 0, errno == EINTR { continue }
            return result
        }
    }

    private static func validateExactJSON(_ data: Data) throws {
        do {
            try PortableFSDStrictJSON.validate(data)
        } catch {
            throw PortableFSDUpdateLeaseError.invalidEncoding
        }
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(root.keys) == [
                "schemaVersion", "phase", "tokenSHA256", "oldRelease",
                "targetRelease", "createdAtUnixMs", "deadlineUnixMs",
              ],
              let old = root["oldRelease"] as? [String: Any],
              let target = root["targetRelease"] as? [String: Any] else {
            throw PortableFSDUpdateLeaseError.invalidEncoding
        }
        let releaseKeys: Set<String> = [
            "codeDirectoryHash", "executableSHA256", "daemonVersion",
            "identitySchema", "controlProtocol", "pfslocalMajor", "pfslocalMinor",
        ]
        guard Set(old.keys) == releaseKeys, Set(target.keys) == releaseKeys else {
            throw PortableFSDUpdateLeaseError.invalidEncoding
        }
    }

    private var leasePath: String {
        directoryURL.appendingPathComponent(Self.filename).path
    }

    func requireDirectoryPathPinned() throws {
        var status = stat()
        guard Darwin.lstat(directoryURL.path, &status) == 0 else {
            throw PortableFSDUpdateLeaseError.inspect(
                path: directoryURL.path,
                errno: errno
            )
        }
        guard status.st_mode & S_IFMT == S_IFDIR,
              status.st_uid == geteuid(),
              status.st_mode & 0o777 == 0o700,
              status.st_dev == directoryDevice,
              status.st_ino == directoryInode else {
            throw PortableFSDUpdateLeaseError.invalidDirectory(directoryURL.path)
        }
    }
}
