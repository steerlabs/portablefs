import Foundation

/// Logical sizes are conservative even when APFS clones or sparse files save blocks.
public struct WorkspaceDiskSpace: Sendable {
    public static let initialDataReserveBytes: UInt64 = 1 << 30
    public let imageBytes: UInt64

    public init(artifact: WorkspaceArtifact) throws {
        guard artifact.byteCount <= UInt64.max - Self.initialDataReserveBytes else { throw WorkspaceVMError("image size overflow") }
        imageBytes = artifact.byteCount
    }

    /// Additional free space while retaining the installed image and user data.
    /// The caller adds any installer archive or other app files it still needs.
    public var extractionRequiredBytes: UInt64 { imageBytes + Self.initialDataReserveBytes }

    public static func preflight(at directory: URL, requiredBytes: UInt64) throws {
        let attributes = try FileManager.default.attributesOfFileSystem(forPath: directory.path)
        guard let free = attributes[.systemFreeSize] as? NSNumber else {
            throw WorkspaceVMError("cannot determine workspace free space")
        }
        guard free.uint64Value >= requiredBytes else {
            throw WorkspaceVMError("Not enough disk space: need \(requiredBytes) bytes; available \(free.uint64Value)")
        }
    }
}
