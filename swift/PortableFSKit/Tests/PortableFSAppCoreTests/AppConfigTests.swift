import Foundation
import Testing
@testable import PortableFSAppCore

private func temporaryDirectory() throws -> String {
    let template = "/tmp/pfs-appcore-XXXXXX"
    var bytes = Array(template.utf8CString)
    let created = bytes.withUnsafeMutableBufferPointer { buffer -> String? in
        guard let base = buffer.baseAddress, mkdtemp(base) != nil else {
            return nil
        }
        return String(cString: base)
    }
    guard let created else {
        throw CocoaError(.fileWriteUnknown)
    }
    return created
}

@Test func configDecodesGoCLIProducedFile() throws {
    // Byte-for-byte what `portablefs login` writes (config.go saveConfig).
    let goProduced = """
    {
      "currentProfile": "staging",
      "profiles": {
        "default": {
          "apiUrl": "https://portablefs.com",
          "apiToken": "tok-default",
          "managerUrl": "",
          "managerToken": ""
        },
        "staging": {
          "apiUrl": "https://staging.portablefs.com",
          "apiToken": "tok-staging",
          "managerUrl": "https://manager.staging.portablefs.com",
          "managerToken": "mgr-staging",
          "dataPlaneCaPem": "-----BEGIN CERTIFICATE-----\\nY2VydA==\\n-----END CERTIFICATE-----\\n"
        }
      }
    }

    """
    let config = try JSONDecoder().decode(PortableFSConfig.self, from: Data(goProduced.utf8))
    #expect(config.currentProfile == "staging")
    #expect(config.profiles.count == 2)
    #expect(config.profiles["staging"]?.managerUrl == "https://manager.staging.portablefs.com")
    #expect(config.profiles["default"]?.managerToken == "")
    #expect(!String(decoding: try JSONEncoder().encode(config), as: UTF8.self).contains("dataPlaneCaPem"))
}

@Test func configDefaultsMissingFieldsLikeGo() throws {
    let sparse = #"{"profiles":{"p":{"apiUrl":"https://x"}}}"#
    let config = try JSONDecoder().decode(PortableFSConfig.self, from: Data(sparse.utf8))
    #expect(config.currentProfile == "default")
    #expect(config.profiles["p"]?.apiUrl == "https://x")
    #expect(config.profiles["p"]?.apiToken == "")

    let empty = try JSONDecoder().decode(PortableFSConfig.self, from: Data("{}".utf8))
    #expect(empty.currentProfile == "default")
    #expect(empty.profiles.isEmpty)
}

@Test func configMissingFileIsEmptyConfig() throws {
    let config = try PortableFSConfigFile.load(path: "/nonexistent/portablefs/config.json")
    #expect(config.currentProfile == "default")
    #expect(config.profiles.isEmpty)
}

@Test func configSaveRoundTripsAndUsesTightPermissions() throws {
    let directory = try temporaryDirectory()
    defer { try? FileManager.default.removeItem(atPath: directory) }
    let path = directory + "/nested/config.json"

    var config = PortableFSConfig()
    config.currentProfile = "work"
    config.profiles["work"] = PortableFSProfile(
        apiUrl: "https://api.example.com",
        apiToken: "secret-token",
        managerUrl: "https://manager.example.com",
        managerToken: "manager-secret"
    )
    try PortableFSConfigFile.save(config, path: path)

    let reloaded = try PortableFSConfigFile.load(path: path)
    #expect(reloaded == config)

    let attributes = try FileManager.default.attributesOfItem(atPath: path)
    let permissions = (attributes[.posixPermissions] as? NSNumber)?.uint16Value ?? 0
    #expect(permissions == 0o600)

    let raw = try String(contentsOfFile: path, encoding: .utf8)
    #expect(raw.hasSuffix("\n"))
    // Every profile key the Go CLI expects must be present, even when empty.
    for key in ["\"apiUrl\"", "\"apiToken\"", "\"managerUrl\"", "\"managerToken\"", "\"currentProfile\"", "\"profiles\""] {
        #expect(raw.contains(key), "missing \(key) in saved config: \(raw)")
    }
    // URLs must not be escaped as https:\/\/ (Go writes them plain).
    #expect(raw.contains("https://api.example.com"))

    // The Go CLI must be able to parse what the app wrote.
    let decoded = try JSONDecoder().decode(PortableFSConfig.self, from: Data(raw.utf8))
    #expect(decoded == config)
}

@Test func configSaveRefusesLooseExistingFileRatherThanRepairingIt() throws {
    let directory = try temporaryDirectory()
    defer { try? FileManager.default.removeItem(atPath: directory) }
    let path = directory + "/config.json"
    FileManager.default.createFile(atPath: path, contents: Data("{}".utf8), attributes: [.posixPermissions: 0o644])

    #expect(throws: PortableFSConfigError.self) {
        try PortableFSConfigFile.save(PortableFSConfig(), path: path)
    }
    let attributes = try FileManager.default.attributesOfItem(atPath: path)
    let permissions = (attributes[.posixPermissions] as? NSNumber)?.uint16Value ?? 0
    #expect(permissions == 0o644)
}

@Test func configDefaultPathUsesFixedAccountHomeLocation() {
    let plain = PortableFSConfigFile.defaultPath(homeDirectory: "/home/u")
    #expect(plain == "/home/u/.config/portablefs/config.json")
}

@Test func canonicalConfigRefusesSymlinkedConfigAncestor() throws {
    let home = try temporaryDirectory()
    defer { try? FileManager.default.removeItem(atPath: home) }
    let outside = try temporaryDirectory()
    defer { try? FileManager.default.removeItem(atPath: outside) }
    try FileManager.default.createSymbolicLink(
        atPath: home + "/.config",
        withDestinationPath: outside
    )
    let path = PortableFSConfigFile.defaultPath(homeDirectory: home)
    #expect(throws: PortableFSConfigError.self) {
        try PortableFSConfigFile.save(
            PortableFSConfig(),
            path: path,
            canonicalHomeDirectory: home
        )
    }
    #expect(!FileManager.default.fileExists(atPath: outside + "/portablefs/config.json"))
}

@Test func canonicalConfigCreatesAndValidatesEachOwnedComponent() throws {
    let home = try temporaryDirectory()
    defer { try? FileManager.default.removeItem(atPath: home) }
    let path = PortableFSConfigFile.defaultPath(homeDirectory: home)
    try PortableFSConfigFile.save(
        PortableFSConfig(),
        path: path,
        canonicalHomeDirectory: home
    )
    _ = try PortableFSConfigFile.load(
        path: path,
        canonicalHomeDirectory: home
    )
    for component in [home + "/.config", home + "/.config/portablefs"] {
        var info = stat()
        #expect(lstat(component, &info) == 0)
        #expect(info.st_mode & S_IFMT == S_IFDIR)
        #expect(info.st_uid == geteuid())
    }
}

@Test func resolvedSettingsPrecedenceAndManagerFallback() {
    var config = PortableFSConfig()
    config.currentProfile = "main"
    config.profiles["main"] = PortableFSProfile(apiUrl: "https://file-api", apiToken: "file-token")

    let fromFile = ResolvedControlPlaneSettings.resolve(config: config, environment: [:])
    #expect(fromFile.apiURL == "https://file-api")
    let manager = fromFile.managerEndpoint()
    #expect(manager.url == "https://file-api")
    #expect(manager.token == "file-token")

    let fromEnv = ResolvedControlPlaneSettings.resolve(
        config: config,
        environment: ["PORTABLEFS_API_URL": "https://env-api", "PORTABLEFS_MANAGER_TOKEN": "env-mgr"]
    )
    #expect(fromEnv.apiURL == "https://env-api")
    #expect(fromEnv.managerEndpoint().token == "env-mgr")

    let explicitProfile = ResolvedControlPlaneSettings.resolve(config: config, profileName: "missing", environment: [:])
    #expect(explicitProfile.apiURL.isEmpty)
    #expect(!explicitProfile.hasAPICredentials)
}
