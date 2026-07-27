import Foundation

/// One saved credential set in `~/.config/portablefs/config.json`.
///
/// The JSON keys are shared with the Go CLI (`vcs/cmd/portablefs/internal/cli/config.go`);
/// both tools read and write the same file, so every field is always emitted
/// (Go structs have no `omitempty` here) and unknown keys must round-trip as
/// absent rather than fail decoding.
public struct PortableFSProfile: Codable, Equatable, Sendable {
    public var apiUrl: String
    public var apiToken: String
    public var managerUrl: String
    public var managerToken: String

    public init(apiUrl: String = "", apiToken: String = "", managerUrl: String = "", managerToken: String = "") {
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
/// Go implementation: a missing file is an empty config, saves are atomic
/// (temp file + rename) and always end up mode 0600 because the file holds
/// bearer tokens.
public enum PortableFSConfigFile {
    public static func defaultPath(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        homeDirectory: String = NSHomeDirectory()
    ) -> String {
        if let xdg = environment["XDG_CONFIG_HOME"], !xdg.isEmpty {
            return (xdg as NSString).appendingPathComponent("portablefs/config.json")
        }
        return (homeDirectory as NSString).appendingPathComponent(".config/portablefs/config.json")
    }

    public static func load(path: String) throws -> PortableFSConfig {
        let data: Data
        do {
            data = try Data(contentsOf: URL(fileURLWithPath: path))
        } catch let error as NSError {
            if error.domain == NSCocoaErrorDomain && error.code == NSFileReadNoSuchFileError {
                return PortableFSConfig()
            }
            if let posix = error.userInfo[NSUnderlyingErrorKey] as? NSError,
               posix.domain == NSPOSIXErrorDomain, posix.code == Int(ENOENT) {
                return PortableFSConfig()
            }
            throw PortableFSConfigError.unreadable(path: path, detail: error.localizedDescription)
        }
        do {
            return try JSONDecoder().decode(PortableFSConfig.self, from: data)
        } catch {
            throw PortableFSConfigError.malformed(path: path, detail: String(describing: error))
        }
    }

    public static func save(_ config: PortableFSConfig, path: String) throws {
        let directory = (path as NSString).deletingLastPathComponent
        do {
            try FileManager.default.createDirectory(
                atPath: directory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        } catch {
            throw PortableFSConfigError.unwritable(path: path, detail: "create config directory: \(error.localizedDescription)")
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

        let temporaryPath = path + ".tmp"
        let created = FileManager.default.createFile(
            atPath: temporaryPath,
            contents: data,
            attributes: [.posixPermissions: 0o600]
        )
        guard created else {
            throw PortableFSConfigError.unwritable(path: path, detail: "create temporary file \(temporaryPath)")
        }
        guard rename(temporaryPath, path) == 0 else {
            let detail = String(cString: strerror(errno))
            unlink(temporaryPath)
            throw PortableFSConfigError.unwritable(path: path, detail: "rename: \(detail)")
        }
        // Existing files created loose by another tool are tightened, matching Go.
        guard chmod(path, 0o600) == 0 else {
            throw PortableFSConfigError.unwritable(path: path, detail: "chmod: \(String(cString: strerror(errno)))")
        }
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
