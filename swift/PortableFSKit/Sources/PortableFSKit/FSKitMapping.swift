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
    ///
    /// The top of the identifier space is minted locally for macOS 26 repair
    /// scratch items, which the daemon must never know about. Refusing a daemon
    /// item that lands here is what makes the two spaces provably disjoint
    /// rather than merely unlikely to collide.
    public static let localRepairIdentifierFloor: UInt64 = UInt64.max - 4096

    public static func itemIdentifier(from itemID: UInt64) throws -> FSItem.Identifier {
        guard itemID > 0, itemID < localRepairIdentifierFloor,
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

    /// The identifier the synthetic `".."` entry carries during enumeration.
    /// Unlike `parentID`, this is a packed directory entry and must name a
    /// real item: POSIX makes the root its own parent, and a retained item
    /// whose last name is gone has no live parent to name, so both resolve to
    /// the enumerated directory itself.
    public static func parentDirectoryIdentifier(from attr: PfsAttr) throws -> FSItem.Identifier {
        guard attr.item.itemID != 1, attr.hasParent else {
            return try itemIdentifier(from: attr.item.itemID)
        }
        return try itemIdentifier(from: attr.parent.itemID)
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

    /// Translates a kernel SETATTR into the pfslocal request.
    ///
    /// A BSD flags change is forwarded exactly when the daemon on this
    /// connection COMPREHENDS the request — `flagsUnderstood` from the resolve
    /// reply — and not otherwise. That is the only question this layer is
    /// positioned to answer.
    ///
    /// The refusal cannot be delegated to the daemon. `set_flags`/`flags` are
    /// APPENDED pfslocal fields at the same protocol minor, so a daemon built
    /// before them proto3-discards both and applies the rest of the setattr
    /// perfectly — a refusal it never had the chance to make, and a chflags(2)
    /// that returns success while nothing changed. Such a daemon also predates
    /// `flagsUnderstood`, so it decodes false and this gate closes on its own.
    ///
    /// What this gate must NOT be is `flagsSupported`. That field describes
    /// the attached AUTHORITY's durable flag storage, and an attach's
    /// namespace is not all authority: a machine-local graft is backed by a
    /// real host inode, so chflags(2) on it persists with no authority feature
    /// involved. Refusing volume-wide on `flagsSupported` breaks graft chflags
    /// on every attach whose authority lacks FeatureFlagPersistence. The
    /// per-target decision is the daemon's, and it comes back as an errno on
    /// the request that asked for it.
    public static func setAttributes(
        from request: FSItem.SetAttributesRequest,
        flagsUnderstood: Bool
    ) throws -> PfsSetAttributes {
        var attributes = PfsSetAttributes()
        if request.isValid(.flags) {
            guard flagsUnderstood else {
                throw PfsLocalClientError.daemon(
                    errno: ENOTSUP,
                    message: "this PortableFS daemon does not understand BSD file flags"
                )
            }
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

    public static func supportedCapabilities(from capabilities: PfsCapabilities) -> FSVolume.SupportedCapabilities {
        let supported = FSVolume.SupportedCapabilities()
        supported.supportsPersistentObjectIDs = true
        supported.supportsSymbolicLinks = capabilities.symlinks
        supported.supportsHardLinks = capabilities.hardLinks
        supported.supports64BitObjectIDs = true
        supported.supports2TBFiles = true
        supported.supportsFastStatFS = true
        supported.supportsSparseFiles = true
        // A MOUNT-TIME static capability, and therefore a statement about the
        // WHOLE volume — which is why it follows `flagsUnderstood` and not
        // `flagsSupported`. Flag support on this volume is per-object: a
        // machine-local graft persists chflags(2) on its host inode while an
        // authority without FeatureFlagPersistence cannot, and both live in
        // one namespace. A volume that supports flags on SOME objects must not
        // declare blanket non-support, because the kernel would then refuse
        // changes that would have succeeded and never let the extension speak.
        // Objects that genuinely cannot take a flag word refuse per request,
        // as an errno.
        //
        // Declaring support against a daemon that does not even parse
        // `set_flags` would be the opposite lie — a chflags(2) reported
        // successful while nothing changed — so the capability is not
        // hardcoded either.
        supported.doesNotSupportImmutableFiles = !capabilities.flagsUnderstood
        supported.caseFormat = capabilities.caseSensitive ? .sensitive : .insensitiveCasePreserving
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
