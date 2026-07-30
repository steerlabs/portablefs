import Darwin
import Foundation

public enum PortableFSAccountHomeError: Error, CustomStringConvertible {
    case invalid(String)

    public var description: String {
        switch self {
        case let .invalid(detail):
            return "resolve canonical account home: \(detail)"
        }
    }
}

/// Resolves the effective uid's account-database home independently of HOME
/// and XDG environment overrides, then proves it is one real owned directory.
public enum PortableFSAccountHome {
    public static func resolve() throws -> String {
        let path = FileManager.default.homeDirectoryForCurrentUser.path
        guard path.hasPrefix("/") else {
            throw PortableFSAccountHomeError.invalid("account database returned non-absolute path \(path)")
        }
        let clean = URL(fileURLWithPath: path, isDirectory: true).standardizedFileURL.path
        guard clean == path else {
            throw PortableFSAccountHomeError.invalid("account database returned non-clean path \(path)")
        }

        var metadata = stat()
        guard lstat(path, &metadata) == 0 else {
            throw PortableFSAccountHomeError.invalid(
                "inspect \(path): \(String(cString: strerror(errno)))"
            )
        }
        guard metadata.st_mode & S_IFMT == S_IFDIR else {
            throw PortableFSAccountHomeError.invalid("\(path) is not a real directory")
        }
        guard metadata.st_uid == geteuid() else {
            throw PortableFSAccountHomeError.invalid(
                "\(path) is owned by uid \(metadata.st_uid), expected \(geteuid())"
            )
        }
        guard let resolvedPointer = realpath(path, nil) else {
            throw PortableFSAccountHomeError.invalid(
                "canonicalize \(path): \(String(cString: strerror(errno)))"
            )
        }
        defer { free(resolvedPointer) }
        let resolved = String(cString: resolvedPointer)
        guard resolved == path else {
            throw PortableFSAccountHomeError.invalid(
                "\(path) resolves through another path to \(resolved)"
            )
        }
        return path
    }
}
