import Foundation

/// Default filesystem locations shared by the menu-bar app, the FSKit
/// extension Info.plist, and the docs.
///
/// The daemon sockets live in the `B47U2LLKHW.pfsoss` app-group container.
/// This is not a style choice: the macOS app sandbox only allows
/// `network-outbound` (which `connect(2)` on a unix socket requires) on
/// app-group container paths, so a socket anywhere else — /tmp included —
/// is unreachable from the sandboxed FSKit extension no matter what file
/// exceptions it holds. The group id is team-prefixed and product-specific,
/// so it never collides with another PortableFS embedder (each uses its own
/// group container) on the same machine. Forks building
/// under a different team id change `appGroupIdentifier` here and in the
/// extension Info.plist/entitlements, or set PORTABLEFS_FSKIT_SOCKET.
public enum PortableFSAppPaths {
    public static let appGroupIdentifier = "B47U2LLKHW.pfsoss"

    public static var devSocketDirectory: String {
        groupContainerPath().appending("/portablefsd")
    }

    public static var devFrontendSocketPath: String {
        devSocketDirectory.appending("/pfs.sock")
    }

    public static var devControlSocketPath: String {
        devSocketDirectory.appending("/control.sock")
    }

    /// The group container root. `containerURL` both resolves and creates
    /// the container for entitled processes; for the unsandboxed daemon it
    /// resolves to the same well-known path.
    public static func groupContainerPath(homeDirectory: String = NSHomeDirectory()) -> String {
        if let container = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: appGroupIdentifier
        ) {
            return container.path
        }
        return (homeDirectory as NSString)
            .appendingPathComponent("Library/Group Containers/\(appGroupIdentifier)")
    }

    public static func defaultStateDirectory(homeDirectory: String = NSHomeDirectory()) -> String {
        (homeDirectory as NSString).appendingPathComponent("Library/Application Support/PortableFS/portablefsd")
    }

    public static func defaultMountBaseDirectory(homeDirectory: String = NSHomeDirectory()) -> String {
        (homeDirectory as NSString).appendingPathComponent("PortableFS")
    }

    /// Mount point for one volume under the configured base directory.
    /// Volume ids are constrained server-side to `[A-Za-z0-9_-]{1,220}`, so
    /// they are path-safe; the guard is defense in depth for hand-edited
    /// configs pointed at untrusted servers.
    public static func mountPoint(baseDirectory: String, volumeID: String) -> String {
        let safe = volumeID.map { character -> Character in
            if character.isLetter || character.isNumber || character == "-" || character == "_" {
                return character
            }
            return "_"
        }
        return (baseDirectory as NSString).appendingPathComponent(String(safe))
    }
}
