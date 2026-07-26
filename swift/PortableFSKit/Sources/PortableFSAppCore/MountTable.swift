import Foundation
@preconcurrency import Darwin

/// One live kernel mount, as read from `getfsstat(2)`.
public struct MountedFilesystem: Equatable, Sendable {
    public var fsTypeName: String
    public var mountPoint: String
    public var mountedFrom: String

    public init(fsTypeName: String, mountPoint: String, mountedFrom: String) {
        self.fsTypeName = fsTypeName
        self.mountPoint = mountPoint
        self.mountedFrom = mountedFrom
    }

    /// For PortableFS mounts, `mountedFrom` is the `pfs://<attachRef>`
    /// resource passed to `mount -t portablefs`.
    public var attachRef: String? {
        MountTable.attachRef(fromMountedFrom: mountedFrom)
    }
}

public enum MountTable {
    // The product-namespaced FSKit mount type (matches FSShortName in the
    // extension Info.plist). Distinct from any other PortableFS embedder's
    // type (another embedder may register its own type) so both can coexist on one host.
    public static let portableFSTypeName = "pfs"

    /// Extracts the attach ref from a `pfs://<ref>` device spec, tolerating
    /// trailing slashes appended by mount tooling.
    public static func attachRef(fromMountedFrom device: String) -> String? {
        let prefix = "pfs://"
        guard device.hasPrefix(prefix) else {
            return nil
        }
        var ref = String(device.dropFirst(prefix.count))
        while ref.hasSuffix("/") {
            ref.removeLast()
        }
        return ref.isEmpty ? nil : ref
    }

    /// Snapshot of all current kernel mounts (`MNT_NOWAIT`, no daemon round
    /// trips), used to reconcile the menu with reality.
    public static func current() -> [MountedFilesystem] {
        var count = getfsstat(nil, 0, MNT_NOWAIT)
        guard count > 0 else {
            return []
        }
        // Leave headroom for mounts appearing between the two calls.
        count += 8
        var stats = [Darwin.statfs](repeating: Darwin.statfs.init(), count: Int(count))
        let bufferSize = Int32(Int(count) * MemoryLayout<Darwin.statfs>.stride)
        let filled = stats.withUnsafeMutableBufferPointer { buffer in
            getfsstat(buffer.baseAddress, bufferSize, MNT_NOWAIT)
        }
        guard filled > 0 else {
            return []
        }
        return stats.prefix(Int(filled)).map { entry in
            MountedFilesystem(
                fsTypeName: string(fromFixedSizeCString: entry.f_fstypename),
                mountPoint: string(fromFixedSizeCString: entry.f_mntonname),
                mountedFrom: string(fromFixedSizeCString: entry.f_mntfromname)
            )
        }
    }

    public static func portableFSMounts() -> [MountedFilesystem] {
        current().filter { $0.fsTypeName == portableFSTypeName }
    }

    private static func string<T>(fromFixedSizeCString tuple: T) -> String {
        withUnsafeBytes(of: tuple) { raw in
            guard let base = raw.baseAddress else {
                return ""
            }
            return String(cString: base.assumingMemoryBound(to: CChar.self))
        }
    }
}
