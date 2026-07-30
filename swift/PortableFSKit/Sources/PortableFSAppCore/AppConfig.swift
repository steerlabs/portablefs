import Darwin
import Foundation

/// One saved credential set in `~/.config/portablefs/config.json`.
///
/// The JSON keys are shared with the Go CLI (`vcs/cmd/portablefs/internal/cli/config.go`);
/// both tools read and write the same file, so every shared field is preserved.
public struct PortableFSProfile: Codable, Equatable, Sendable {
    public var apiUrl: String
    public var apiToken: String
    public var managerUrl: String
    public var managerToken: String

    public init(
        apiUrl: String = "",
        apiToken: String = "",
        managerUrl: String = "",
        managerToken: String = ""
    ) {
        self.apiUrl = apiUrl
        self.apiToken = apiToken
        self.managerUrl = managerUrl
        self.managerToken = managerToken
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        apiUrl = try container.decodeIfPresent(String.self, forKey: .apiUrl) ?? ""
        apiToken = try container.decodeIfPresent(String.self, forKey: .apiToken) ?? ""
        managerUrl = try container.decodeIfPresent(String.self, forKey: .managerUrl) ?? ""
        managerToken = try container.decodeIfPresent(String.self, forKey: .managerToken) ?? ""
    }
}

/// On-disk shape of the shared CLI/app config file.
public struct PortableFSConfig: Codable, Equatable, Sendable {
    public var currentProfile: String
    public var profiles: [String: PortableFSProfile]

    public init(currentProfile: String = "default", profiles: [String: PortableFSProfile] = [:]) {
        self.currentProfile = currentProfile
        self.profiles = profiles
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let profileName = try container.decodeIfPresent(String.self, forKey: .currentProfile) ?? ""
        currentProfile = profileName.isEmpty ? "default" : profileName
        profiles = try container.decodeIfPresent([String: PortableFSProfile].self, forKey: .profiles) ?? [:]
    }
}

public enum PortableFSConfigError: Error, Equatable, CustomStringConvertible {
    case unreadable(path: String, detail: String)
    case malformed(path: String, detail: String)
    case unwritable(path: String, detail: String)

    public var description: String {
        switch self {
        case let .unreadable(path, detail):
            return "read config \(path): \(detail)"
        case let .malformed(path, detail):
            return "parse config \(path): \(detail)"
        case let .unwritable(path, detail):
            return "write config \(path): \(detail)"
        }
    }
}

/// Reads and writes the CLI-shared config file with the same semantics as the
/// Go implementation: a missing file is an empty config. Unsafe existing
/// directories/files are rejected rather than repaired. Saves use a private
/// lock, a unique 0600 temp file, fsync, atomic rename, and directory fsync.
public enum PortableFSConfigFile {
    public static func defaultPath() throws -> String {
        defaultPath(homeDirectory: try PortableFSAccountHome.resolve())
    }

    public static func defaultPath(homeDirectory: String) -> String {
        return (homeDirectory as NSString).appendingPathComponent(".config/portablefs/config.json")
    }

    public static func load(
        path: String,
        canonicalHomeDirectory: String? = nil
    ) throws -> PortableFSConfig {
        if let canonicalHomeDirectory {
            do {
                try validateCanonicalConfigComponents(
                    path: path,
                    home: canonicalHomeDirectory,
                    create: false
                )
            } catch {
                throw PortableFSConfigError.unreadable(path: path, detail: String(describing: error))
            }
        }
        let directory = (path as NSString).deletingLastPathComponent
        if fileExistsWithoutFollowingSymlink(directory) {
            do {
                try validateDirectory(directory, exactMode: 0o700)
            } catch {
                throw PortableFSConfigError.unreadable(path: path, detail: String(describing: error))
            }
        }
        let descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        if descriptor < 0 {
            if errno == ENOENT {
                return PortableFSConfig()
            }
            throw PortableFSConfigError.unreadable(path: path, detail: posixError())
        }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        let data: Data
        do {
            try validateRegularFile(descriptor: descriptor, path: path, exactMode: 0o600)
            data = try handle.readToEnd() ?? Data()
            try handle.close()
        } catch {
            try? handle.close()
            throw PortableFSConfigError.unreadable(path: path, detail: String(describing: error))
        }
        do {
            return try JSONDecoder().decode(PortableFSConfig.self, from: data)
        } catch {
            throw PortableFSConfigError.malformed(path: path, detail: String(describing: error))
        }
    }

    public static func save(
        _ config: PortableFSConfig,
        path: String,
        canonicalHomeDirectory: String? = nil
    ) throws {
        let directory = (path as NSString).deletingLastPathComponent
        do {
            if let canonicalHomeDirectory {
                try validateCanonicalConfigComponents(
                    path: path,
                    home: canonicalHomeDirectory,
                    create: true
                )
            }
            try prepareConfigDirectory(directory)
        } catch {
            throw PortableFSConfigError.unwritable(path: path, detail: String(describing: error))
        }

        let lockDescriptor: Int32
        do {
            lockDescriptor = try openConfigLock(directory: directory)
        } catch {
            throw PortableFSConfigError.unwritable(path: path, detail: String(describing: error))
        }
        defer {
            _ = flock(lockDescriptor, LOCK_UN)
            _ = close(lockDescriptor)
        }
        guard flock(lockDescriptor, LOCK_EX) == 0 else {
            throw PortableFSConfigError.unwritable(path: path, detail: "lock config: \(posixError())")
        }
        do {
            try validateExistingConfigFile(path)
        } catch {
            throw PortableFSConfigError.unwritable(path: path, detail: String(describing: error))
        }

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        var data: Data
        do {
            data = try encoder.encode(config)
        } catch {
            throw PortableFSConfigError.unwritable(path: path, detail: String(describing: error))
        }
        data.append(0x0A)

        var template = Array(
            (directory as NSString)
                .appendingPathComponent(".config.json.XXXXXX.tmp")
                .utf8CString
        )
        let temporaryDescriptor = template.withUnsafeMutableBufferPointer { buffer in
            mkstemps(buffer.baseAddress, 4)
        }
        guard temporaryDescriptor >= 0 else {
            throw PortableFSConfigError.unwritable(path: path, detail: "create unique temporary file: \(posixError())")
        }
        let temporaryPath = String(
            decoding: template.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) },
            as: UTF8.self
        )
        var temporaryOpen = true
        defer {
            if temporaryOpen {
                _ = close(temporaryDescriptor)
            }
            _ = unlink(temporaryPath)
        }
        guard fchmod(temporaryDescriptor, 0o600) == 0 else {
            throw PortableFSConfigError.unwritable(path: path, detail: "set temporary file permissions: \(posixError())")
        }
        do {
            try writeAll(data, to: temporaryDescriptor)
        } catch {
            throw PortableFSConfigError.unwritable(path: path, detail: String(describing: error))
        }
        guard fsync(temporaryDescriptor) == 0 else {
            throw PortableFSConfigError.unwritable(path: path, detail: "sync temporary config: \(posixError())")
        }
        guard close(temporaryDescriptor) == 0 else {
            temporaryOpen = false
            throw PortableFSConfigError.unwritable(path: path, detail: "close temporary config: \(posixError())")
        }
        temporaryOpen = false
        guard rename(temporaryPath, path) == 0 else {
            throw PortableFSConfigError.unwritable(path: path, detail: "publish config: \(posixError())")
        }
        let directoryDescriptor = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard directoryDescriptor >= 0 else {
            throw PortableFSConfigError.unwritable(path: path, detail: "open config directory for sync: \(posixError())")
        }
        defer { _ = close(directoryDescriptor) }
        guard fsync(directoryDescriptor) == 0 else {
            throw PortableFSConfigError.unwritable(path: path, detail: "sync config directory: \(posixError())")
        }
    }

    private static func prepareConfigDirectory(_ directory: String) throws {
        if !fileExistsWithoutFollowingSymlink(directory) {
            do {
                try FileManager.default.createDirectory(
                    atPath: directory,
                    withIntermediateDirectories: true,
                    attributes: [.posixPermissions: 0o700]
                )
            } catch {
                throw POSIXValidationError("create config directory \(directory): \(error.localizedDescription)")
            }
        }
        try validateDirectory(directory, exactMode: 0o700)
    }

    private static func validateCanonicalConfigComponents(
        path: String,
        home: String,
        create: Bool
    ) throws {
        let expected = defaultPath(homeDirectory: home)
        guard path == expected else {
            throw POSIXValidationError(
                "config path \(path) is not the canonical account path \(expected)"
            )
        }
        try validateOwnedDirectory(home, exactMode: nil, rejectGroupWorldWrite: true)

        let configRoot = (home as NSString).appendingPathComponent(".config")
        let portableFSRoot = (configRoot as NSString).appendingPathComponent("portablefs")
        let components: [(String, mode_t?)] = [
            (configRoot, nil),
            (portableFSRoot, mode_t(0o700)),
        ]
        for (component, exactMode) in components {
            var info = stat()
            if lstat(component, &info) != 0 {
                guard errno == ENOENT else {
                    throw POSIXValidationError("inspect config ancestor \(component): \(posixError())")
                }
                guard create else {
                    return
                }
                guard mkdir(component, exactMode ?? 0o700) == 0 else {
                    throw POSIXValidationError("create config ancestor \(component): \(posixError())")
                }
            }
            try validateOwnedDirectory(
                component,
                exactMode: exactMode,
                rejectGroupWorldWrite: true
            )
        }
    }

    private static func validateOwnedDirectory(
        _ path: String,
        exactMode: mode_t?,
        rejectGroupWorldWrite: Bool
    ) throws {
        var info = stat()
        guard lstat(path, &info) == 0 else {
            throw POSIXValidationError("inspect directory \(path): \(posixError())")
        }
        guard info.st_mode & S_IFMT == S_IFDIR else {
            throw POSIXValidationError("config ancestor \(path) is not a real directory")
        }
        guard info.st_uid == geteuid() else {
            throw POSIXValidationError("config ancestor \(path) is not owned by uid \(geteuid())")
        }
        let mode = info.st_mode & 0o777
        if let exactMode, mode != exactMode {
            throw POSIXValidationError(
                "config ancestor \(path) has permissions \(String(mode, radix: 8)), expected \(String(exactMode, radix: 8))"
            )
        }
        if rejectGroupWorldWrite && mode & 0o022 != 0 {
            throw POSIXValidationError("config ancestor \(path) is group/world writable")
        }
    }

    private static func validateDirectory(_ path: String, exactMode: mode_t) throws {
        var info = stat()
        guard lstat(path, &info) == 0 else {
            throw POSIXValidationError("inspect directory \(path): \(posixError())")
        }
        guard info.st_mode & S_IFMT == S_IFDIR else {
            throw POSIXValidationError("config directory \(path) is not a real directory")
        }
        guard info.st_uid == geteuid() else {
            throw POSIXValidationError("config directory \(path) is not owned by uid \(geteuid())")
        }
        let mode = info.st_mode & 0o777
        guard mode == exactMode else {
            throw POSIXValidationError(
                "config directory \(path) has permissions \(String(mode, radix: 8)), expected \(String(exactMode, radix: 8)); refusing to repair it"
            )
        }
    }

    private static func validateExistingConfigFile(_ path: String) throws {
        var info = stat()
        if lstat(path, &info) != 0 {
            if errno == ENOENT {
                return
            }
            throw POSIXValidationError("inspect existing config \(path): \(posixError())")
        }
        try validateRegularFile(info: info, path: path, exactMode: 0o600)
    }

    private static func validateRegularFile(descriptor: Int32, path: String, exactMode: mode_t) throws {
        var info = stat()
        guard fstat(descriptor, &info) == 0 else {
            throw POSIXValidationError("inspect config \(path): \(posixError())")
        }
        try validateRegularFile(info: info, path: path, exactMode: exactMode)
    }

    private static func validateRegularFile(info: stat, path: String, exactMode: mode_t) throws {
        guard info.st_mode & S_IFMT == S_IFREG else {
            throw POSIXValidationError("config \(path) is not a regular file")
        }
        guard info.st_uid == geteuid() else {
            throw POSIXValidationError("config \(path) is not owned by uid \(geteuid())")
        }
        guard info.st_nlink == 1 else {
            throw POSIXValidationError("config \(path) has \(info.st_nlink) hard links, expected one")
        }
        let mode = info.st_mode & 0o777
        guard mode == exactMode else {
            throw POSIXValidationError(
                "config \(path) has permissions \(String(mode, radix: 8)), expected \(String(exactMode, radix: 8)); refusing to repair it"
            )
        }
    }

    private static func openConfigLock(directory: String) throws -> Int32 {
        let path = (directory as NSString).appendingPathComponent(".config.lock")
        var descriptor = open(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0o600)
        let created = descriptor >= 0
        if descriptor < 0 && errno == EEXIST {
            descriptor = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW)
        }
        guard descriptor >= 0 else {
            throw POSIXValidationError("open config lock \(path): \(posixError())")
        }
        do {
            if created && fchmod(descriptor, 0o600) != 0 {
                throw POSIXValidationError("set config lock permissions: \(posixError())")
            }
            try validateRegularFile(descriptor: descriptor, path: path, exactMode: 0o600)
            return descriptor
        } catch {
            _ = close(descriptor)
            throw error
        }
    }

    private static func writeAll(_ data: Data, to descriptor: Int32) throws {
        try data.withUnsafeBytes { buffer in
            guard var cursor = buffer.baseAddress else {
                return
            }
            var remaining = buffer.count
            while remaining > 0 {
                let written = Darwin.write(descriptor, cursor, remaining)
                if written < 0 {
                    if errno == EINTR {
                        continue
                    }
                    throw POSIXValidationError("write temporary config: \(posixError())")
                }
                cursor = cursor.advanced(by: written)
                remaining -= written
            }
        }
    }

    private static func fileExistsWithoutFollowingSymlink(_ path: String) -> Bool {
        var info = stat()
        return lstat(path, &info) == 0
    }

    private static func posixError() -> String {
        String(cString: strerror(errno))
    }
}

private struct POSIXValidationError: Error, CustomStringConvertible {
    let description: String

    init(_ description: String) {
        self.description = description
    }
}

/// Fully resolved connection settings for one profile, applying the CLI's
/// documented precedence: environment overrides beat config file values.
/// (The app has no flag layer.)
public struct ResolvedControlPlaneSettings: Equatable, Sendable {
    public var apiURL: String
    public var apiToken: String
    public var managerURL: String
    public var managerToken: String

    public init(apiURL: String = "", apiToken: String = "", managerURL: String = "", managerToken: String = "") {
        self.apiURL = apiURL
        self.apiToken = apiToken
        self.managerURL = managerURL
        self.managerToken = managerToken
    }

    public static func resolve(
        config: PortableFSConfig,
        profileName: String = "",
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) -> ResolvedControlPlaneSettings {
        let name = profileName.isEmpty ? config.currentProfile : profileName
        let profile = config.profiles[name] ?? PortableFSProfile()
        func pick(_ envName: String, _ fileValue: String) -> String {
            if let value = environment[envName], !value.isEmpty {
                return value
            }
            return fileValue
        }
        return ResolvedControlPlaneSettings(
            apiURL: pick("PORTABLEFS_API_URL", profile.apiUrl),
            apiToken: pick("PORTABLEFS_API_TOKEN", profile.apiToken),
            managerURL: pick("PORTABLEFS_MANAGER_URL", profile.managerUrl),
            managerToken: pick("PORTABLEFS_MANAGER_TOKEN", profile.managerToken)
        )
    }

    /// URL and bearer token for manager-dependent calls. Hosted cloud serves
    /// the manager surface from the API origin, so an unset managerUrl falls
    /// back to apiUrl (and managerToken to apiToken).
    public func managerEndpoint() -> (url: String, token: String) {
        var url = managerURL
        var token = managerToken
        if url.isEmpty {
            url = apiURL
        }
        if token.isEmpty {
            token = apiToken
        }
        return (url, token)
    }

    public var hasAPICredentials: Bool {
        !apiURL.isEmpty && !apiToken.isEmpty
    }
}
