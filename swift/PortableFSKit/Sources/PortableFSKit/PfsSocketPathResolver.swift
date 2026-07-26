import Foundation

/// Resolves the daemon socket path advertised by the embedding app extension.
///
/// Resolution order is intentionally explicit:
/// 1. `PFSDaemonSocketPath` in the extension Info.plist. This must be an
///    absolute path; the embedding app is responsible for choosing a path the
///    sandboxed extension can read and write.
/// 2. `PFSAppGroupIdentifier` in the Info.plist. The resolver asks
///    `FileManager.containerURL(forSecurityApplicationGroupIdentifier:)` and
///    appends `portablefsd/pfs.sock` inside that shared container.
public struct PfsSocketPathResolver: @unchecked Sendable {
    public typealias AppGroupContainerResolver = @Sendable (String) -> URL?

    public let infoDictionary: [String: Any]
    public let appGroupContainerResolver: AppGroupContainerResolver

    public init(
        infoDictionary: [String: Any],
        appGroupContainerResolver: @escaping AppGroupContainerResolver = { identifier in
            FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: identifier)
        }
    ) {
        self.infoDictionary = infoDictionary
        self.appGroupContainerResolver = appGroupContainerResolver
    }

    public init(
        bundle: Bundle = .main,
        appGroupContainerResolver: @escaping AppGroupContainerResolver = { identifier in
            FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: identifier)
        }
    ) {
        var dictionary: [String: Any] = [:]
        for (key, value) in bundle.infoDictionary ?? [:] {
            dictionary[key] = value
        }
        self.init(infoDictionary: dictionary, appGroupContainerResolver: appGroupContainerResolver)
    }

    public func resolve() throws -> String {
        if let explicitPath = infoDictionary["PFSDaemonSocketPath"] as? String,
           !explicitPath.isEmpty {
            guard explicitPath.hasPrefix("/") else {
                throw PfsLocalClientError.socketPath("PFSDaemonSocketPath must be absolute")
            }
            return explicitPath
        }

        if let appGroup = infoDictionary["PFSAppGroupIdentifier"] as? String,
           !appGroup.isEmpty {
            guard let container = appGroupContainerResolver(appGroup) else {
                throw PfsLocalClientError.socketPath("no container URL for app group \(appGroup)")
            }
            return container
                .appendingPathComponent("portablefsd", isDirectory: true)
                .appendingPathComponent("pfs.sock", isDirectory: false)
                .path
        }

        throw PfsLocalClientError.socketPath("missing PFSDaemonSocketPath or PFSAppGroupIdentifier")
    }
}
