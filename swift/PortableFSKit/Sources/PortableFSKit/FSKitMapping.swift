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

    public static func attributes(from attr: PfsAttr) -> FSItem.Attributes {
        let attributes = FSItem.Attributes()
        attributes.uid = attr.uid
        attributes.gid = attr.gid
        attributes.mode = attr.mode
        attributes.type = itemType(from: attr.kind)
        attributes.linkCount = attr.nlink == 0 ? 1 : attr.nlink
        attributes.size = attr.size
        attributes.allocSize = attr.size
        attributes.fileID = FSItem.Identifier(rawValue: attr.item.itemID) ?? .invalid
        attributes.modifyTime = timespec(milliseconds: attr.mtimeMs)
        attributes.changeTime = timespec(milliseconds: attr.ctimeMs)
        attributes.accessTime = timespec(milliseconds: attr.atimeMs)
        attributes.birthTime = timespec(milliseconds: attr.birthtimeMs)
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

    public static func statfs(from reply: PfsStatfsReply, capabilities: PfsCapabilities) -> FSStatFSResult {
        let result = FSStatFSResult(fileSystemTypeName: "portablefs")
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
