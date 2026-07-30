import Foundation

/// Presentation-only filesystem paths used by the menu-bar app.
public enum PortableFSAppPaths {
    public static func defaultMountBaseDirectory() throws -> String {
        defaultMountBaseDirectory(homeDirectory: try PortableFSAccountHome.resolve())
    }

    public static func defaultMountBaseDirectory(homeDirectory: String) -> String {
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
