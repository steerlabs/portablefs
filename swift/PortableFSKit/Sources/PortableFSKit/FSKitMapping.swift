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

    /// Maps an xattr refusal at the macOS VFS boundary.
    ///
    /// Darwin gives `ENOTSUP` a filesystem-private meaning here: `vn_setxattr`
    /// and `vn_removexattr` treat it as permission to invoke their AppleDouble
    /// fallback unless the original caller supplied `XATTR_NODEFAULT`. A
    /// normal `setxattr(2)` caller does not, so returning the authority's
    /// honest `ENOTSUP` creates a durable `._name` sidecar and reports success
    /// even though this volume declares user xattrs read-only. Darwin's
    /// distinct `EOPNOTSUPP` is the authority's public refusal and, unlike
    /// `ENOTSUP`, is terminal at the VFS boundary. Other failures retain their
    /// exact errno. Linux exposes the same `EOPNOTSUPP` contract directly.
    public static func fsKitXattrError(for error: Error) -> NSError {
        let mapped = fsKitError(for: error)
        if mapped.domain == NSPOSIXErrorDomain && mapped.code == Int(ENOTSUP) {
            return fs_errorForPOSIXError(EOPNOTSUPP) as NSError
        }
        return mapped
    }
}

public enum PfsFSKitMapping {
    /// FSKit reserves identifiers 0, 1, and 2 for invalid, parent-of-root,
    /// and root respectively. pfslocal assigns file ID 1 to the volume root
    /// and an XFS inode number in [2, UInt64.max) to every other object, so
    /// the checked successor `fileID + 1` maps the root to FSKit's root and
    /// every ordinary object above the reserved values. Zero and UInt64.max
    /// have no FSKit identifier and are refused rather than wrapped. File IDs
    /// are independent of ownership handles: the whole UInt64 range below the
    /// overflow belongs to daemon objects, with no frontend-minted partition.
    public static func itemIdentifier(from fileID: UInt64) throws -> FSItem.Identifier {
        guard fileID > 0, fileID < UInt64.max,
              let identifier = FSItem.Identifier(rawValue: fileID + 1) else {
            throw PfsLocalClientError.daemon(
                errno: EOVERFLOW,
                message: "pfslocal file ID cannot be represented by FSKit"
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
        if attr.fileID == 1 {
            return .parentOfRoot
        }
        guard attr.parentFileID != 0 else {
            return .invalid
        }
        return try itemIdentifier(from: attr.parentFileID)
    }

    /// The identifier the synthetic `".."` entry carries during enumeration.
    /// Unlike `parentID`, this is a packed directory entry and must name a
    /// real item: POSIX makes the root its own parent, and a retained item
    /// whose last name is gone has no live parent to name, so both resolve to
    /// the enumerated directory itself.
    public static func parentDirectoryIdentifier(from attr: PfsAttr) throws -> FSItem.Identifier {
        guard attr.fileID != 1, attr.parentFileID != 0 else {
            return try itemIdentifier(from: attr.fileID)
        }
        return try itemIdentifier(from: attr.parentFileID)
    }

    /// Builds one atomic FSKit snapshot. Get-attribute and readdir-plus callers
    /// pass the exact wanted mask so the reply contains neither missing
    /// requested properties nor unrelated valid properties.
    ///
    /// The mask may name properties PortableFS does not model at all — Finder
    /// and Spotlight ask for `ATTR_CMN_ADDEDTIME` unconditionally and FSKit
    /// offers no capability bit to suppress it. Those stay invalid rather than
    /// failing the operation: FSKit's contract is that every requested
    /// *supported* property is valid, and `FSItemAttributes.isValid` exists
    /// precisely so a genuinely absent property can be reported as absent.
    public static func attributes(
        from attr: PfsAttr,
        requested: FSItem.Attribute? = nil
    ) throws -> FSItem.Attributes {
        let fileIdentifier = try itemIdentifier(from: attr.fileID)
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
            attributes.fileID = fileIdentifier
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

    /// Translates a kernel SETATTR into the pfslocal request.
    ///
    /// A BSD flags change is always forwarded with `set_flags`. Whether an
    /// object can take a flag word is the daemon's per-request decision, and
    /// it refuses the entire compound SetAttr before applying any of it, so
    /// an unsupported flags change can never become a partial success here.
    public static func setAttributes(
        from request: FSItem.SetAttributesRequest
    ) -> PfsSetAttributes {
        var attributes = PfsSetAttributes()
        if request.isValid(.flags) {
            attributes.flags = request.flags
            request.consumedAttributes.insert(.flags)
        }
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

    /// The volume's static FSKit capabilities. Symlinks, hard links and
    /// case-sensitive names are baseline pfslocal semantics, not negotiated
    /// options. Immutable-file support stays declared because a flag change
    /// must reach the daemon, whose explicit atomic refusal is the actual
    /// per-object answer; a static volume refusal would replace it with a
    /// kernel-side outcome this frontend does not own.
    public static func supportedCapabilities() -> FSVolume.SupportedCapabilities {
        let supported = FSVolume.SupportedCapabilities()
        supported.supportsPersistentObjectIDs = false
        supported.supportsSymbolicLinks = true
        supported.supportsHardLinks = true
        supported.supports64BitObjectIDs = true
        supported.supports2TBFiles = true
        supported.supportsFastStatFS = true
        supported.supportsSparseFiles = true
        supported.doesNotSupportImmutableFiles = false
        supported.caseFormat = .sensitive
        return supported
    }

    public static func timespec(milliseconds: Int64) -> timespec {
        var seconds = milliseconds / 1000
        var nanoseconds = (milliseconds % 1000) * 1_000_000
        if nanoseconds < 0 {
            // Go's and C's truncating division give a negative remainder for
            // pre-1970 times; timespec requires tv_nsec in [0, 1e9).
            nanoseconds += 1_000_000_000
            seconds -= 1
        }
        return Darwin.timespec(tv_sec: Int(seconds), tv_nsec: Int(nanoseconds))
    }

    public static func milliseconds(from value: timespec) -> Int64 {
        (Int64(value.tv_sec) * 1000) + (Int64(value.tv_nsec) / 1_000_000)
    }
}
