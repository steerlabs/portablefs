import Foundation
import FSKit
@preconcurrency import Darwin

public enum PfsErrorMapper {
    public static func invalidDirectoryCookieError() -> NSError {
        NSError(domain: FSKitErrorDomain, code: FSError.Code.invalidDirectoryCookie.rawValue)
    }

    public static func fsKitError(for error: Error) -> NSError {
        if let localError = error as? PfsLocalClientError {
            return fs_errorForPOSIXError(localError.posixErrno) as NSError
        }
        let nsError = error as NSError
        if nsError.domain == NSPOSIXErrorDomain || nsError.domain == FSKitErrorDomain {
            return nsError
        }
        return fs_errorForPOSIXError(EIO) as NSError
    }
}

public enum PfsFSKitMapping {
    /// FSKit reserves identifiers 0, 1, and 2 for invalid, parent-of-root,
    /// and root respectively. PortableFS uses authority inode 1 for its root,
    /// so expose the complete pfslocal identity space through one checked
    /// offset at the platform boundary. VolumeCore and portablefsd continue
    /// to use the unmodified durable identity.
    public static func itemIdentifier(from itemID: UInt64) throws -> FSItem.Identifier {
        guard itemID > 0, itemID < UInt64.max,
              let identifier = FSItem.Identifier(rawValue: itemID + 1) else {
            throw PfsLocalClientError.daemon(
                errno: EOVERFLOW,
                message: "pfslocal item identifier cannot be represented by FSKit"
            )
        }
        return identifier
    }

    /// FSKit reserves verifier zero for the initial request and requires every
    /// successful enumeration to return a nonzero current verifier. Daemon
    /// directory versions may legitimately be zero, so translate them through
    /// the same checked successor scheme instead of leaking the sentinel.
    public static func directoryVerifier(from version: UInt64) throws -> FSDirectoryVerifier {
        guard version < UInt64.max else {
            throw PfsLocalClientError.daemon(
                errno: EOVERFLOW,
                message: "directory verifier cannot be represented by FSKit"
            )
        }
        return FSDirectoryVerifier(version + 1)
    }

    public static func itemType(from kind: PfsItemKind) -> FSItem.ItemType {
        switch kind {
        case .file:
            return .file
        case .directory:
            return .directory
        case .symlink:
            return .symlink
        case .unspecified, .UNRECOGNIZED:
            return .unknown
        }
    }

    public static func openMode(from modes: FSVolume.OpenModes) -> PfsOpenMode {
        let reads = modes.contains(.read)
        let writes = modes.contains(.write)
        switch (reads, writes) {
        case (true, true):
            return .readWrite
        case (false, true):
            return .write
        case (true, false):
            return .read
        case (false, false):
            return .unspecified
        }
    }

    private static func includes(
        _ attribute: FSItem.Attribute,
        in requested: FSItem.Attribute?
    ) -> Bool {
        requested?.contains(attribute) ?? true
    }

    private static func parentIdentifier(from attr: PfsAttr) throws -> FSItem.Identifier {
        if attr.item.itemID == 1 {
            return .parentOfRoot
        }
        guard attr.hasParent else {
            return .invalid
        }
        return try itemIdentifier(from: attr.parent.itemID)
    }

    /// Builds one atomic FSKit snapshot. Get-attribute and readdir-plus callers
    /// pass the exact wanted mask so the reply contains neither missing
    /// requested properties nor unrelated valid properties.
    public static func attributes(
        from attr: PfsAttr,
        requested: FSItem.Attribute? = nil
    ) throws -> FSItem.Attributes {
        if let requested,
           requested.contains(.addedTime) || requested.contains(.backupTime) {
            throw PfsLocalClientError.daemon(
                errno: ENOTSUP,
                message: "PortableFS does not expose added-time or backup-time metadata"
            )
        }
        let attributes = FSItem.Attributes()
        if includes(.uid, in: requested) {
            attributes.uid = attr.uid
        }
        if includes(.gid, in: requested) {
            attributes.gid = attr.gid
        }
        if includes(.mode, in: requested) {
            attributes.mode = attr.mode
        }
        if includes(.type, in: requested) {
            attributes.type = itemType(from: attr.kind)
        }
        if includes(.linkCount, in: requested) {
            attributes.linkCount = attr.nlink
        }
        if includes(.flags, in: requested) {
            attributes.flags = attr.flags
        }
        if includes(.size, in: requested) {
            attributes.size = attr.size
        }
        if includes(.allocSize, in: requested) {
            attributes.allocSize = attr.allocSize
        }
        if includes(.fileID, in: requested) {
            attributes.fileID = try itemIdentifier(from: attr.item.itemID)
        }
        if includes(.parentID, in: requested) {
            attributes.parentID = try parentIdentifier(from: attr)
        }
        if includes(.modifyTime, in: requested) {
            attributes.modifyTime = timespec(milliseconds: attr.mtimeMs)
        }
        if includes(.changeTime, in: requested) {
            attributes.changeTime = timespec(milliseconds: attr.ctimeMs)
        }
        if includes(.accessTime, in: requested) {
            attributes.accessTime = timespec(milliseconds: attr.atimeMs)
        }
        if includes(.birthTime, in: requested) {
            attributes.birthTime = timespec(milliseconds: attr.birthtimeMs)
        }
        if includes(.supportsLimitedXAttrs, in: requested) {
            attributes.supportsLimitedXAttrs = false
        }
        if includes(.inhibitKernelOffloadedIO, in: requested) {
            attributes.inhibitKernelOffloadedIO = false
        }
        return attributes
    }

    public static func setAttributes(from request: FSItem.SetAttributesRequest) -> PfsSetAttributes {
        var attributes = PfsSetAttributes()
        if request.isValid(.mode) {
            attributes.mode = request.mode
            request.consumedAttributes.insert(.mode)
        }
        if request.isValid(.uid) {
            attributes.uid = request.uid
            request.consumedAttributes.insert(.uid)
        }
        if request.isValid(.gid) {
            attributes.gid = request.gid
            request.consumedAttributes.insert(.gid)
        }
        if request.isValid(.size) {
            attributes.size = request.size
            request.consumedAttributes.insert(.size)
        }
        if request.isValid(.modifyTime) {
            attributes.mtimeMilliseconds = milliseconds(from: request.modifyTime)
            request.consumedAttributes.insert(.modifyTime)
        }
        if request.isValid(.accessTime) {
            attributes.atimeMilliseconds = milliseconds(from: request.accessTime)
            request.consumedAttributes.insert(.accessTime)
        }
        return attributes
    }

    public static func fileName(from data: Data) -> FSFileName {
        FSFileName(data: data)
    }

    public static func bytes(from fileName: FSFileName) -> Data {
        let data = fileName.data
        if !data.isEmpty {
            return data
        }
        if let string = fileName.string, !string.isEmpty {
            return Data(string.utf8)
        }
        return data
    }

    public static func xattrName(from fileName: FSFileName) throws -> String {
        if let string = fileName.string, !string.isEmpty {
            return string
        }
        if let string = String(data: fileName.data, encoding: .utf8) {
            return string
        }
        throw PfsLocalClientError.daemon(errno: EINVAL, message: "xattr name is not valid UTF-8")
    }

    public static func statfs(
        from reply: PfsStatfsReply,
        capabilities: PfsCapabilities,
        fileSystemTypeName: String = PortableFSIdentity.fileSystemTypeName
    ) -> FSStatFSResult {
        let result = FSStatFSResult(fileSystemTypeName: fileSystemTypeName)
        let blockSize = reply.blockSize == 0 ? 4096 : reply.blockSize
        let totalBlocks = reply.totalBlocks == 0 ? 1_000_000 : reply.totalBlocks
        let freeBlocks = reply.freeBlocks == 0 ? totalBlocks / 2 : reply.freeBlocks
        result.blockSize = Int(blockSize)
        result.ioSize = Int(capabilities.preferredIoBytes == 0 ? blockSize : UInt64(capabilities.preferredIoBytes))
        result.totalBlocks = totalBlocks
        result.availableBlocks = freeBlocks
        result.freeBlocks = freeBlocks
        result.totalFiles = reply.totalFiles == 0 ? 1_000_000 : reply.totalFiles
        result.freeFiles = reply.freeFiles == 0 ? 500_000 : reply.freeFiles
        return result
    }

    public static func supportedCapabilities(from capabilities: PfsCapabilities) -> FSVolume.SupportedCapabilities {
        let supported = FSVolume.SupportedCapabilities()
        supported.supportsPersistentObjectIDs = true
        supported.supportsSymbolicLinks = capabilities.symlinks
        supported.supportsHardLinks = capabilities.hardLinks
        supported.supports64BitObjectIDs = true
        supported.supports2TBFiles = true
        supported.supportsFastStatFS = true
        supported.supportsSparseFiles = true
        supported.caseFormat = capabilities.caseSensitive ? .sensitive : .insensitiveCasePreserving
        return supported
    }

    public static func timespec(milliseconds: Int64) -> timespec {
        let seconds = milliseconds / 1000
        let remainder = milliseconds % 1000
        return Darwin.timespec(tv_sec: Int(seconds), tv_nsec: Int(remainder * 1_000_000))
    }

    public static func milliseconds(from value: timespec) -> Int64 {
        (Int64(value.tv_sec) * 1000) + (Int64(value.tv_nsec) / 1_000_000)
    }
}
