import AppKit
import CryptoKit
import Darwin
import Foundation

private let configurationLimit = 4_096
private let gateLimit = 64
private let gateTimeout: Duration = .seconds(120)
private let expectedFileSystemType = "pfs"
private let expectedSourcePrefix = "dev.portablefs.oss://"

private enum QualificationFailure: Error, CustomStringConvertible {
    case invalid(String)
    case posix(String, Int32)

    var description: String {
        switch self {
        case let .invalid(message):
            return message
        case let .posix(operation, code):
            return "\(operation): errno \(code) (\(String(cString: strerror(code))))"
        }
    }
}

private func failPOSIX(_ operation: String, _ code: Int32 = errno) -> QualificationFailure {
    .posix(operation, code)
}

private struct QualificationConfiguration: Decodable, Sendable {
    enum Mode: String, Decodable, Sendable {
        case basic
        case dataRefresh = "data-refresh"

        init(from decoder: Decoder) throws {
            let container = try decoder.singleValueContainer()
            let value = try container.decode(String.self)
            switch value {
            case Self.basic.rawValue:
                self = .basic
            case Self.dataRefresh.rawValue:
                self = .dataRefresh
            case "namespace", "namespace-coherence", "attribute", "attribute-coherence":
                throw DecodingError.dataCorruptedError(
                    in: container,
                    debugDescription: "namespace and attribute cross-client qualification is intentionally unsupported"
                )
            default:
                throw DecodingError.dataCorruptedError(
                    in: container,
                    debugDescription: "unsupported qualification mode"
                )
            }
        }
    }

    let schemaVersion: Int
    let mode: Mode
    let runID: String
    let mountPath: String
    let attachRef: String
    let relativePath: String?
    let initialSHA256: String?
    let finalSHA256: String?

    static let baseKeys: Set<String> = [
        "schemaVersion", "mode", "runID", "mountPath", "attachRef",
    ]
    static let dataRefreshKeys: Set<String> = baseKeys.union([
        "relativePath", "initialSHA256", "finalSHA256",
    ])

    func validate(keys: Set<String>) throws {
        guard schemaVersion == 1 else {
            throw QualificationFailure.invalid("configuration schemaVersion must be exactly 1")
        }
        guard isLowerHex(runID, count: 32) else {
            throw QualificationFailure.invalid("runID must be exactly 32 lowercase hexadecimal characters")
        }
        guard attachRef.hasPrefix("att_"), attachRef.utf8.count == 26,
              attachRef.dropFirst(4).unicodeScalars.allSatisfy({ scalar in
                  scalar.isASCII && (
                      (scalar.value >= 48 && scalar.value <= 57)
                          || (scalar.value >= 65 && scalar.value <= 90)
                          || (scalar.value >= 97 && scalar.value <= 122)
                          || scalar.value == 45 || scalar.value == 95
                  )
              })
        else {
            throw QualificationFailure.invalid("attachRef is not a canonical PortableFS attach reference")
        }
        guard mountPath.hasPrefix("/"), mountPath.utf8.count <= 1_024,
              URL(fileURLWithPath: mountPath).standardized.path == mountPath
        else {
            throw QualificationFailure.invalid("mountPath must be an absolute standardized path")
        }
        guard try canonicalPath(mountPath) == mountPath else {
            throw QualificationFailure.invalid("mountPath must already be canonical and may not traverse symlinks")
        }

        switch mode {
        case .basic:
            guard keys == Self.baseKeys,
                  relativePath == nil, initialSHA256 == nil, finalSHA256 == nil
            else {
                throw QualificationFailure.invalid("basic mode has an invalid field set")
            }
        case .dataRefresh:
            guard keys == Self.dataRefreshKeys,
                  let relativePath, let initialSHA256, let finalSHA256
            else {
                throw QualificationFailure.invalid("data-refresh mode requires its exact field set")
            }
            guard relativePath == "portablefs-data-refresh-\(runID).bin" else {
                throw QualificationFailure.invalid("data-refresh relativePath must be derived exactly from runID")
            }
            guard isLowerHex(initialSHA256, count: 64), isLowerHex(finalSHA256, count: 64),
                  initialSHA256 != finalSHA256
            else {
                throw QualificationFailure.invalid(
                    "data-refresh hashes must be distinct lowercase SHA-256 values"
                )
            }
        }
    }
}

private func isLowerHex(_ value: String, count: Int) -> Bool {
    value.utf8.count == count && value.utf8.allSatisfy {
        ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
    }
}

private struct StrictJSONObject {
    let keys: Set<String>

    init(data: Data) throws {
        var parser = StrictJSONParser(bytes: Array(data))
        keys = try parser.parseFlatObject()
    }
}

private struct StrictJSONParser {
    let bytes: [UInt8]
    var index = 0

    mutating func parseFlatObject() throws -> Set<String> {
        skipWhitespace()
        try consume(123, "configuration must be one JSON object")
        skipWhitespace()
        var keys = Set<String>()
        if peek() == 125 {
            index += 1
        } else {
            while true {
                let key = try parseJSONString()
                guard keys.insert(key).inserted else {
                    throw QualificationFailure.invalid("configuration contains duplicate key \(key)")
                }
                skipWhitespace()
                try consume(58, "configuration key is missing ':'")
                skipWhitespace()
                try parseScalarValue()
                skipWhitespace()
                if peek() == 44 {
                    index += 1
                    skipWhitespace()
                    continue
                }
                try consume(125, "configuration object is not terminated")
                break
            }
        }
        skipWhitespace()
        guard index == bytes.count else {
            throw QualificationFailure.invalid("configuration has trailing data")
        }
        return keys
    }

    mutating func parseScalarValue() throws {
        if peek() == 34 {
            _ = try parseJSONString()
            return
        }
        let start = index
        if peek() == 45 { index += 1 }
        guard let first = peek(), first >= 48, first <= 57 else {
            throw QualificationFailure.invalid("configuration values must be strings or integers")
        }
        if first == 48 {
            index += 1
            if let next = peek(), next >= 48, next <= 57 {
                throw QualificationFailure.invalid("configuration integer has a leading zero")
            }
        } else {
            while let current = peek(), current >= 48, current <= 57 { index += 1 }
        }
        guard index > start else {
            throw QualificationFailure.invalid("configuration integer is empty")
        }
    }

    mutating func parseJSONString() throws -> String {
        let start = index
        try consume(34, "configuration key or value must be a JSON string")
        while let current = peek() {
            switch current {
            case 34:
                index += 1
                let encoded = Data(bytes[start..<index])
                guard let decoded = try JSONSerialization.jsonObject(
                    with: Data("[".utf8) + encoded + Data("]".utf8)
                ) as? [String], decoded.count == 1, let value = decoded.first else {
                    throw QualificationFailure.invalid("configuration contains an invalid JSON string")
                }
                return value
            case 92:
                index += 1
                guard let escaped = peek() else {
                    throw QualificationFailure.invalid("configuration contains an incomplete JSON escape")
                }
                if escaped == 117 {
                    index += 1
                    for _ in 0..<4 {
                        guard let digit = peek(),
                              (digit >= 48 && digit <= 57)
                                  || (digit >= 65 && digit <= 70)
                                  || (digit >= 97 && digit <= 102)
                        else {
                            throw QualificationFailure.invalid("configuration contains an invalid Unicode escape")
                        }
                        index += 1
                    }
                } else {
                    guard [34, 47, 92, 98, 102, 110, 114, 116].contains(escaped) else {
                        throw QualificationFailure.invalid("configuration contains an invalid JSON escape")
                    }
                    index += 1
                }
            case 0...31:
                throw QualificationFailure.invalid("configuration contains a control byte in a JSON string")
            default:
                index += 1
            }
        }
        throw QualificationFailure.invalid("configuration contains an unterminated JSON string")
    }

    mutating func consume(_ expected: UInt8, _ message: String) throws {
        guard peek() == expected else { throw QualificationFailure.invalid(message) }
        index += 1
    }

    mutating func skipWhitespace() {
        while let current = peek(), [9, 10, 13, 32].contains(current) { index += 1 }
    }

    func peek() -> UInt8? {
        index < bytes.count ? bytes[index] : nil
    }
}

private final class LocalControlDirectory {
    let fd: Int32
    let config: QualificationConfiguration

    init(configPath: String) throws {
        guard configPath.hasPrefix("/"), URL(fileURLWithPath: configPath).standardized.path == configPath else {
            throw QualificationFailure.invalid("--config must name an absolute standardized path")
        }
        let parent = URL(fileURLWithPath: configPath).deletingLastPathComponent().path
        let name = URL(fileURLWithPath: configPath).lastPathComponent
        guard isSafeComponent(name), try canonicalPath(parent) == parent else {
            throw QualificationFailure.invalid("configuration parent must be canonical and the file name must be safe")
        }

        var directoryStatus = stat()
        guard lstat(parent, &directoryStatus) == 0 else { throw failPOSIX("lstat configuration parent") }
        guard (directoryStatus.st_mode & S_IFMT) == S_IFDIR,
              directoryStatus.st_uid == geteuid(),
              (directoryStatus.st_mode & 0o777) == 0o700
        else {
            throw QualificationFailure.invalid(
                "configuration parent must be a real directory owned by this user with mode 0700"
            )
        }
        let openedDirectory = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard openedDirectory >= 0 else { throw failPOSIX("open configuration parent") }
        fd = openedDirectory

        do {
            var pinnedStatus = stat()
            guard fstat(fd, &pinnedStatus) == 0 else { throw failPOSIX("fstat configuration parent") }
            guard sameObject(directoryStatus, pinnedStatus) else {
                throw QualificationFailure.invalid("configuration parent changed while it was opened")
            }
            let data = try Self.readOwnedFile(directoryFD: fd, name: name, maximumBytes: configurationLimit)
            let strict = try StrictJSONObject(data: data)
            let decoder = JSONDecoder()
            let decoded: QualificationConfiguration
            do {
                decoded = try decoder.decode(QualificationConfiguration.self, from: data)
            } catch {
                throw QualificationFailure.invalid("configuration does not match schema 1: \(error)")
            }
            try decoded.validate(keys: strict.keys)
            config = decoded
            try requireAbsent(resultName)
            if config.mode == .dataRefresh {
                try requireAbsent(readyName)
                try requireAbsent(continueName)
            }
        } catch {
            close(fd)
            throw error
        }
    }

    deinit { close(fd) }

    var resultName: String { "\(config.runID).result.json" }
    var readyName: String { "\(config.runID).ready" }
    var continueName: String { "\(config.runID).continue" }

    func requireAbsent(_ name: String) throws {
        var status = stat()
        if fstatat(fd, name, &status, AT_SYMLINK_NOFOLLOW) == 0 {
            throw QualificationFailure.invalid("local control file already exists: \(name)")
        }
        guard errno == ENOENT else { throw failPOSIX("lstat local control file \(name)") }
    }

    func publish(_ data: Data, as name: String) throws {
        guard data.count <= configurationLimit else {
            throw QualificationFailure.invalid("local result frame exceeds \(configurationLimit) bytes")
        }
        try requireAbsent(name)
        let temporaryName = ".\(name).tmp"
        try requireAbsent(temporaryName)
        let output = openat(fd, temporaryName, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0o600)
        guard output >= 0 else { throw failPOSIX("create local result temporary file") }
        var temporaryExists = true
        defer {
            close(output)
            if temporaryExists { _ = unlinkat(fd, temporaryName, 0) }
        }
        try writeAll(output, bytes: Array(data))
        guard fsync(output) == 0 else { throw failPOSIX("fsync local result") }
        guard linkat(fd, temporaryName, fd, name, 0) == 0 else {
            throw failPOSIX("publish local result")
        }
        guard unlinkat(fd, temporaryName, 0) == 0 else {
            throw failPOSIX("remove local result temporary link")
        }
        temporaryExists = false
        guard fsync(fd) == 0 else { throw failPOSIX("fsync local control directory") }
    }

    func waitForContinue() throws {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: gateTimeout)
        while clock.now < deadline {
            var status = stat()
            if fstatat(fd, continueName, &status, AT_SYMLINK_NOFOLLOW) == 0 {
                let data = try Self.readOwnedFile(
                    directoryFD: fd,
                    name: continueName,
                    maximumBytes: gateLimit
                )
                guard data == Data("continue\n".utf8) else {
                    throw QualificationFailure.invalid("data-refresh continue gate has invalid contents")
                }
                return
            }
            guard errno == ENOENT else { throw failPOSIX("lstat data-refresh continue gate") }
            usleep(50_000)
        }
        throw QualificationFailure.invalid("data-refresh continue gate was not published within 120 seconds")
    }

    static func readOwnedFile(directoryFD: Int32, name: String, maximumBytes: Int) throws -> Data {
        var before = stat()
        guard fstatat(directoryFD, name, &before, AT_SYMLINK_NOFOLLOW) == 0 else {
            throw failPOSIX("lstat local input \(name)")
        }
        guard (before.st_mode & S_IFMT) == S_IFREG,
              before.st_uid == geteuid(),
              (before.st_mode & 0o777) == 0o600,
              before.st_nlink == 1,
              before.st_size > 0,
              before.st_size <= maximumBytes
        else {
            throw QualificationFailure.invalid(
                "local input \(name) must be an owned, single-link 0600 regular file within its size limit"
            )
        }
        let input = openat(directoryFD, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard input >= 0 else { throw failPOSIX("open local input \(name)") }
        defer { close(input) }
        var pinned = stat()
        guard fstat(input, &pinned) == 0 else { throw failPOSIX("fstat local input \(name)") }
        guard sameObject(before, pinned) else {
            throw QualificationFailure.invalid("local input \(name) changed while it was opened")
        }
        let bytes = try readExactly(input, count: Int(pinned.st_size))
        var after = stat()
        guard fstatat(directoryFD, name, &after, AT_SYMLINK_NOFOLLOW) == 0,
              sameObject(pinned, after)
        else {
            throw QualificationFailure.invalid("local input \(name) changed while it was read")
        }
        return Data(bytes)
    }
}

private struct MountIdentity: Equatable, Sendable {
    let type: String
    let source: String
    let mountPoint: String
    let fileSystemID: String
}

private struct QualificationResult: Encodable, Sendable {
    let schemaVersion = 1
    let runID: String
    let mode: String
    let state: String
    let phase: String
    let message: String
    let observedSHA256: String?
}

private struct QualificationOutcome: Sendable {
    let succeeded: Bool
    let message: String
}

private struct QualificationRunner {
    func run(configPath: String) -> QualificationOutcome {
        var control: LocalControlDirectory?
        do {
            let opened = try LocalControlDirectory(configPath: configPath)
            control = opened
            let observed: String
            switch opened.config.mode {
            case .basic:
                observed = try runBasic(opened.config)
            case .dataRefresh:
                observed = try runDataRefresh(opened)
            }
            try publishResult(
                control: opened,
                state: "passed",
                phase: "complete",
                message: "qualification completed",
                observedSHA256: observed
            )
            return QualificationOutcome(succeeded: true, message: "Qualification passed")
        } catch {
            let message = String(describing: error)
            if let control {
                try? publishResult(
                    control: control,
                    state: "failed",
                    phase: "qualification",
                    message: message,
                    observedSHA256: nil
                )
            }
            return QualificationOutcome(succeeded: false, message: message)
        }
    }

    private func runBasic(_ config: QualificationConfiguration) throws -> String {
        let root = try openVerifiedMount(config)
        defer { close(root.fd) }
        let runDirectoryName = ".portablefs-qualification-\(config.runID)"
        guard mkdirat(root.fd, runDirectoryName, 0o700) == 0 else {
            throw failPOSIX("create qualification directory")
        }
        var cleanupNeeded = true
        defer {
            if cleanupNeeded { cleanupBasic(rootFD: root.fd, runDirectoryName: runDirectoryName) }
        }
        let directory = openat(root.fd, runDirectoryName, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard directory >= 0 else { throw failPOSIX("open qualification directory") }
        defer { close(directory) }

        let payload = deterministicPayload(runID: config.runID, count: 128 * 1_024)
        let expectedHash = sha256(payload)
        let original = "original.bin"
        let renamed = "renamed.bin"
        let output = openat(
            directory,
            original,
            O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            0o600
        )
        guard output >= 0 else { throw failPOSIX("create qualification file") }
        defer { close(output) }
        try writeAll(output, bytes: payload)
        guard fsync(output) == 0 else { throw failPOSIX("fsync qualification file") }

        let openedStatus = try regularFileStatus(fd: output, operation: "fstat qualification file")
        guard openedStatus.st_size == payload.count, (openedStatus.st_mode & 0o777) == 0o600 else {
            throw QualificationFailure.invalid("created qualification file has unexpected size or mode")
        }
        let namedStatus = try regularFileStatus(
            directoryFD: directory,
            name: original,
            operation: "stat qualification file"
        )
        guard sameObject(openedStatus, namedStatus) else {
            throw QualificationFailure.invalid("opened and named qualification files differ")
        }
        guard try readExactlyAt(output, count: payload.count) == payload else {
            throw QualificationFailure.invalid("qualification pread did not return the written bytes")
        }
        guard try directoryEntries(directory) == Set([".", "..", original]) else {
            throw QualificationFailure.invalid("qualification directory enumeration was not exact")
        }
        guard renameat(directory, original, directory, renamed) == 0 else {
            throw failPOSIX("rename qualification file")
        }
        try requirePathAbsent(directoryFD: directory, name: original)
        let renamedStatus = try regularFileStatus(
            directoryFD: directory,
            name: renamed,
            operation: "stat renamed qualification file"
        )
        guard sameObject(openedStatus, renamedStatus) else {
            throw QualificationFailure.invalid("rename changed qualification file identity")
        }
        let reopened = openat(directory, renamed, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard reopened >= 0 else { throw failPOSIX("reopen renamed qualification file") }
        defer { close(reopened) }
        guard sha256(try readExactlyAt(reopened, count: payload.count)) == expectedHash else {
            throw QualificationFailure.invalid("reopened qualification file has unexpected data")
        }
        guard unlinkat(directory, renamed, 0) == 0 else { throw failPOSIX("unlink open qualification file") }
        try requirePathAbsent(directoryFD: directory, name: renamed)
        guard sha256(try readExactlyAt(reopened, count: payload.count)) == expectedHash else {
            throw QualificationFailure.invalid("open-unlinked qualification file lost its data")
        }
        guard unlinkat(root.fd, runDirectoryName, AT_REMOVEDIR) == 0 else {
            throw failPOSIX("remove qualification directory")
        }
        cleanupNeeded = false
        try verifyUnchangedMount(root, config: config)
        return expectedHash
    }

    private func runDataRefresh(_ control: LocalControlDirectory) throws -> String {
        let config = control.config
        guard let relativePath = config.relativePath,
              let initialSHA256 = config.initialSHA256,
              let finalSHA256 = config.finalSHA256
        else {
            throw QualificationFailure.invalid("data-refresh configuration was not fully validated")
        }
        let root = try openVerifiedMount(config)
        defer { close(root.fd) }
        let input = openat(root.fd, relativePath, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard input >= 0 else { throw failPOSIX("open data-refresh file") }
        defer { close(input) }
        let initialStatus = try regularFileStatus(fd: input, operation: "fstat data-refresh file")
        guard initialStatus.st_size >= 0, initialStatus.st_size <= 16 * 1_024 * 1_024 else {
            throw QualificationFailure.invalid("data-refresh file must be at most 16 MiB")
        }
        let initial = try readExactlyAt(input, count: Int(initialStatus.st_size))
        guard sha256(initial) == initialSHA256 else {
            throw QualificationFailure.invalid("data-refresh initial bytes do not match initialSHA256")
        }

        let ready = QualificationResult(
            runID: config.runID,
            mode: config.mode.rawValue,
            state: "ready",
            phase: "initial-read",
            message: "same open file descriptor is waiting for the external writer",
            observedSHA256: initialSHA256
        )
        try control.publish(try encodeFrame(ready), as: control.readyName)
        try control.waitForContinue()

        // Keep the split matrix data-only: changing or revalidating file size would
        // also exercise attribute coherence, which SDK 27 cannot repair natively.
        let final = try readExactlyAt(input, count: Int(initialStatus.st_size))
        guard sha256(final) == finalSHA256 else {
            throw QualificationFailure.invalid(
                "same open file descriptor did not observe the expected refreshed data"
            )
        }
        try verifyUnchangedMount(root, config: config)
        return finalSHA256
    }

    private func publishResult(
        control: LocalControlDirectory,
        state: String,
        phase: String,
        message: String,
        observedSHA256: String?
    ) throws {
        let result = QualificationResult(
            runID: control.config.runID,
            mode: control.config.mode.rawValue,
            state: state,
            phase: phase,
            message: String(message.prefix(1_024)),
            observedSHA256: observedSHA256
        )
        try control.publish(try encodeFrame(result), as: control.resultName)
    }
}

private struct VerifiedMount {
    let fd: Int32
    let identity: MountIdentity
}

private func openVerifiedMount(_ config: QualificationConfiguration) throws -> VerifiedMount {
    let pathIdentity = try mountIdentity(path: config.mountPath)
    try validateMountIdentity(pathIdentity, config: config)
    let fd = open(config.mountPath, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    guard fd >= 0 else { throw failPOSIX("open verified mount root") }
    do {
        let descriptorIdentity = try mountIdentity(fd: fd)
        try validateMountIdentity(descriptorIdentity, config: config)
        guard descriptorIdentity == pathIdentity else {
            throw QualificationFailure.invalid("mount identity changed while its root was opened")
        }
        return VerifiedMount(fd: fd, identity: descriptorIdentity)
    } catch {
        close(fd)
        throw error
    }
}

private func verifyUnchangedMount(
    _ mount: VerifiedMount,
    config: QualificationConfiguration
) throws {
    let descriptorIdentity = try mountIdentity(fd: mount.fd)
    try validateMountIdentity(descriptorIdentity, config: config)
    let pathIdentity = try mountIdentity(path: config.mountPath)
    try validateMountIdentity(pathIdentity, config: config)
    guard descriptorIdentity == mount.identity, pathIdentity == mount.identity else {
        throw QualificationFailure.invalid("kernel mount identity changed during qualification")
    }
}

private func validateMountIdentity(
    _ identity: MountIdentity,
    config: QualificationConfiguration
) throws {
    guard identity.type == expectedFileSystemType,
          identity.source == expectedSourcePrefix + config.attachRef,
          identity.mountPoint == config.mountPath
    else {
        throw QualificationFailure.invalid(
            "kernel mount identity does not match the exact PortableFS attach"
        )
    }
}

private func mountIdentity(path: String) throws -> MountIdentity {
    var status = statfs()
    guard statfs(path, &status) == 0 else { throw failPOSIX("statfs mount path") }
    return decodeMountIdentity(status)
}

private func mountIdentity(fd: Int32) throws -> MountIdentity {
    var status = statfs()
    guard fstatfs(fd, &status) == 0 else { throw failPOSIX("fstatfs mount root") }
    return decodeMountIdentity(status)
}

private func decodeMountIdentity(_ status: statfs) -> MountIdentity {
    MountIdentity(
        type: fixedCString(status.f_fstypename),
        source: fixedCString(status.f_mntfromname),
        mountPoint: fixedCString(status.f_mntonname),
        fileSystemID: withUnsafeBytes(of: status.f_fsid) { bytes in
            bytes.map { String(format: "%02x", $0) }.joined()
        }
    )
}

private func fixedCString<T>(_ value: T) -> String {
    withUnsafeBytes(of: value) { raw in
        let bytes = raw.prefix { $0 != 0 }
        return String(decoding: bytes, as: UTF8.self)
    }
}

private func canonicalPath(_ path: String) throws -> String {
    let pointer = path.withCString { realpath($0, nil) }
    guard let pointer else { throw failPOSIX("resolve canonical path") }
    defer { free(pointer) }
    return String(cString: pointer)
}

private func sameObject(_ left: stat, _ right: stat) -> Bool {
    left.st_dev == right.st_dev && left.st_ino == right.st_ino
}

private func isSafeComponent(_ name: String) -> Bool {
    !name.isEmpty && name != "." && name != ".." && name.utf8.count <= 255
        && name.utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 90)
                || ($0 >= 97 && $0 <= 122) || $0 == 45 || $0 == 46 || $0 == 95
        }
}

private func regularFileStatus(fd: Int32, operation: String) throws -> stat {
    var status = stat()
    guard fstat(fd, &status) == 0 else { throw failPOSIX(operation) }
    guard (status.st_mode & S_IFMT) == S_IFREG else {
        throw QualificationFailure.invalid("\(operation): object is not a regular file")
    }
    return status
}

private func regularFileStatus(directoryFD: Int32, name: String, operation: String) throws -> stat {
    var status = stat()
    guard fstatat(directoryFD, name, &status, AT_SYMLINK_NOFOLLOW) == 0 else {
        throw failPOSIX(operation)
    }
    guard (status.st_mode & S_IFMT) == S_IFREG else {
        throw QualificationFailure.invalid("\(operation): object is not a regular file")
    }
    return status
}

private func requirePathAbsent(directoryFD: Int32, name: String) throws {
    var status = stat()
    if fstatat(directoryFD, name, &status, AT_SYMLINK_NOFOLLOW) == 0 {
        throw QualificationFailure.invalid("expected path to be absent after operation: \(name)")
    }
    guard errno == ENOENT else { throw failPOSIX("verify absent path \(name)") }
}

private func directoryEntries(_ fd: Int32) throws -> Set<String> {
    let duplicate = dup(fd)
    guard duplicate >= 0 else { throw failPOSIX("duplicate directory descriptor") }
    guard let directory = fdopendir(duplicate) else {
        close(duplicate)
        throw failPOSIX("open directory stream")
    }
    defer { closedir(directory) }
    rewinddir(directory)
    var entries = Set<String>()
    while true {
        errno = 0
        guard let entry = readdir(directory) else {
            guard errno == 0 else { throw failPOSIX("enumerate qualification directory") }
            return entries
        }
        entries.insert(fixedCString(entry.pointee.d_name))
    }
}

private func writeAll(_ fd: Int32, bytes: [UInt8]) throws {
    var offset = 0
    while offset < bytes.count {
        let written = bytes.withUnsafeBytes { raw -> Int in
            guard let base = raw.baseAddress else { return 0 }
            return Darwin.write(fd, base.advanced(by: offset), bytes.count - offset)
        }
        if written < 0 {
            if errno == EINTR { continue }
            throw failPOSIX("write file")
        }
        guard written > 0 else { throw QualificationFailure.invalid("write file made no progress") }
        offset += written
    }
}

private func readExactly(_ fd: Int32, count: Int) throws -> [UInt8] {
    var result = [UInt8](repeating: 0, count: count)
    var offset = 0
    while offset < count {
        let amount = result.withUnsafeMutableBytes { raw -> Int in
            guard let base = raw.baseAddress else { return 0 }
            return Darwin.read(fd, base.advanced(by: offset), count - offset)
        }
        if amount < 0 {
            if errno == EINTR { continue }
            throw failPOSIX("read file")
        }
        guard amount > 0 else { throw QualificationFailure.invalid("file ended before its declared size") }
        offset += amount
    }
    var extra: UInt8 = 0
    while true {
        let amount = Darwin.read(fd, &extra, 1)
        if amount < 0, errno == EINTR { continue }
        if amount < 0 { throw failPOSIX("read file boundary") }
        guard amount == 0 else { throw QualificationFailure.invalid("file grew while it was read") }
        return result
    }
}

private func readExactlyAt(_ fd: Int32, count: Int) throws -> [UInt8] {
    var result = [UInt8](repeating: 0, count: count)
    var offset = 0
    while offset < count {
        let amount = result.withUnsafeMutableBytes { raw -> Int in
            guard let base = raw.baseAddress else { return 0 }
            return Darwin.pread(fd, base.advanced(by: offset), count - offset, off_t(offset))
        }
        if amount < 0 {
            if errno == EINTR { continue }
            throw failPOSIX("pread file")
        }
        guard amount > 0 else { throw QualificationFailure.invalid("file ended before its attested size") }
        offset += amount
    }
    var extra: UInt8 = 0
    while true {
        let amount = Darwin.pread(fd, &extra, 1, off_t(count))
        if amount < 0, errno == EINTR { continue }
        if amount < 0 { throw failPOSIX("pread file boundary") }
        guard amount == 0 else { throw QualificationFailure.invalid("file grew while it was read") }
        return result
    }
}

private func deterministicPayload(runID: String, count: Int) -> [UInt8] {
    var result = [UInt8]()
    result.reserveCapacity(count)
    var counter: UInt64 = 0
    while result.count < count {
        var input = Data(runID.utf8)
        var bigEndianCounter = counter.bigEndian
        withUnsafeBytes(of: &bigEndianCounter) { input.append(contentsOf: $0) }
        result.append(contentsOf: SHA256.hash(data: input))
        counter += 1
    }
    return Array(result.prefix(count))
}

private func sha256(_ bytes: [UInt8]) -> String {
    SHA256.hash(data: Data(bytes)).map { String(format: "%02x", $0) }.joined()
}

private func encodeFrame<T: Encodable>(_ value: T) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    var data = try encoder.encode(value)
    data.append(10)
    return data
}

private func cleanupBasic(rootFD: Int32, runDirectoryName: String) {
    let directory = openat(rootFD, runDirectoryName, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    if directory >= 0 {
        _ = unlinkat(directory, "original.bin", 0)
        _ = unlinkat(directory, "renamed.bin", 0)
        close(directory)
    }
    _ = unlinkat(rootFD, runDirectoryName, AT_REMOVEDIR)
}

@main
@MainActor
private final class QualificationAppDelegate: NSObject, NSApplicationDelegate {
    private var window: NSWindow?
    private var statusLabel: NSTextField?

    static func main() {
        let app = NSApplication.shared
        let delegate = QualificationAppDelegate()
        app.delegate = delegate
        withExtendedLifetime(delegate) { app.run() }
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApplication.shared.setActivationPolicy(.regular)
        let label = NSTextField(wrappingLabelWithString: "PortableFS macOS 27 I/O qualification is running.")
        label.alignment = .center
        label.translatesAutoresizingMaskIntoConstraints = false
        let content = NSView(frame: NSRect(x: 0, y: 0, width: 560, height: 180))
        content.addSubview(label)
        NSLayoutConstraint.activate([
            label.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 24),
            label.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -24),
            label.centerYAnchor.constraint(equalTo: content.centerYAnchor),
        ])
        let window = NSWindow(
            contentRect: content.bounds,
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )
        window.title = "PortableFS I/O Qualification"
        window.contentView = content
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApplication.shared.activate()
        self.window = window
        statusLabel = label

        let arguments = CommandLine.arguments
        guard arguments.count == 3, arguments[1] == "--config" else {
            finish(QualificationOutcome(
                succeeded: false,
                message: "usage: PortableFSKitMacOS27IOQualification --config <absolute-path>"
            ))
            return
        }
        let configPath = arguments[2]
        Task { [weak self] in
            let outcome = await Task.detached(priority: .userInitiated) {
                QualificationRunner().run(configPath: configPath)
            }.value
            self?.finish(outcome)
        }
    }

    private func finish(_ outcome: QualificationOutcome) {
        statusLabel?.stringValue = outcome.succeeded
            ? "Qualification passed. The result was written to the private control directory."
            : "Qualification failed: \(outcome.message)"
        let exitCode: Int32 = outcome.succeeded ? 0 : 1
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
            Darwin.exit(exitCode)
        }
    }
}
