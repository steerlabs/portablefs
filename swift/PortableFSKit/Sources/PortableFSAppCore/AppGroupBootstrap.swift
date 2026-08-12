import Darwin
import Foundation

public enum PortableFSAppGroupBootstrapError: Error, CustomStringConvertible {
    case missingIdentifier
    case containerUnavailable(String)
    case invalidContainer(URL)
    case createDirectory(path: String, errno: Int32)
    case openDirectory(path: String, errno: Int32)
    case inspectDirectory(path: String, errno: Int32)
    case unsafeDirectory(path: String)
    case secureDirectory(path: String, errno: Int32)

    public var description: String {
        switch self {
        case .missingIdentifier:
            "missing PFSAppGroupIdentifier in the signed app bundle"
        case let .containerUnavailable(identifier):
            "no signed app-group container is available for \(identifier)"
        case let .invalidContainer(url):
            "app-group container is not an absolute file URL: \(url)"
        case let .createDirectory(path, code):
            "create app-group socket directory \(path): \(String(cString: strerror(code)))"
        case let .openDirectory(path, code):
            "open app-group socket directory \(path) without following links: \(String(cString: strerror(code)))"
        case let .inspectDirectory(path, code):
            "inspect app-group socket directory \(path): \(String(cString: strerror(code)))"
        case let .unsafeDirectory(path):
            "app-group socket directory \(path) is not an owned private directory"
        case let .secureDirectory(path, code):
            "secure app-group socket directory \(path): \(String(cString: strerror(code)))"
        }
    }
}

/// Prepares the one directory shared by the unsandboxed daemon and sandboxed
/// FSKit extension. The app-group container URL is supplied by the signed
/// entitlement. The final directory is opened with O_NOFOLLOW and secured by
/// descriptor so an existing symlink or replacement cannot redirect chmod.
public enum PortableFSAppGroupBootstrap {
    public typealias ContainerResolver = @Sendable (String) -> URL?

    @discardableResult
    public static func prepare(
        bundle: Bundle = .main,
        containerResolver: @escaping ContainerResolver = { identifier in
            FileManager.default.containerURL(
                forSecurityApplicationGroupIdentifier: identifier
            )
        }
    ) throws -> URL {
        try prepare(
            infoDictionary: bundle.infoDictionary ?? [:],
            containerResolver: containerResolver
        )
    }

    @discardableResult
    public static func prepare(
        infoDictionary: [String: Any],
        containerResolver: @escaping ContainerResolver
    ) throws -> URL {
        guard let identifier = infoDictionary["PFSAppGroupIdentifier"] as? String,
              !identifier.isEmpty else {
            throw PortableFSAppGroupBootstrapError.missingIdentifier
        }
        guard let container = containerResolver(identifier) else {
            throw PortableFSAppGroupBootstrapError.containerUnavailable(identifier)
        }
        guard container.isFileURL, container.path.hasPrefix("/") else {
            throw PortableFSAppGroupBootstrapError.invalidContainer(container)
        }

        let directory = container.appendingPathComponent(
            "portablefsd",
            isDirectory: true
        )
        let path = directory.path
        if Darwin.mkdir(path, 0o700) != 0 {
            let code = errno
            guard code == EEXIST else {
                throw PortableFSAppGroupBootstrapError.createDirectory(
                    path: path,
                    errno: code
                )
            }
        }

        let descriptor = Darwin.open(
            path,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else {
            throw PortableFSAppGroupBootstrapError.openDirectory(
                path: path,
                errno: errno
            )
        }
        defer { Darwin.close(descriptor) }

        var status = stat()
        guard Darwin.fstat(descriptor, &status) == 0 else {
            throw PortableFSAppGroupBootstrapError.inspectDirectory(
                path: path,
                errno: errno
            )
        }
        guard status.st_mode & S_IFMT == S_IFDIR,
              status.st_uid == geteuid() else {
            throw PortableFSAppGroupBootstrapError.unsafeDirectory(path: path)
        }
        if status.st_mode & 0o777 != 0o700 {
            guard Darwin.fchmod(descriptor, 0o700) == 0 else {
                throw PortableFSAppGroupBootstrapError.secureDirectory(
                    path: path,
                    errno: errno
                )
            }
            guard Darwin.fstat(descriptor, &status) == 0 else {
                throw PortableFSAppGroupBootstrapError.inspectDirectory(
                    path: path,
                    errno: errno
                )
            }
            guard status.st_mode & S_IFMT == S_IFDIR,
                  status.st_uid == geteuid(),
                  status.st_mode & 0o777 == 0o700 else {
                throw PortableFSAppGroupBootstrapError.unsafeDirectory(path: path)
            }
        }
        return directory
    }
}
