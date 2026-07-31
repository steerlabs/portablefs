import Foundation
import FSKit
import CryptoKit
import os
@preconcurrency import Darwin

private final class PfsUncheckedSendableBox<Value>: @unchecked Sendable {
    let value: Value

    init(_ value: Value) {
        self.value = value
    }
}

struct PfsSyntheticDirectoryEntry: Sendable, Equatable {
    var name: Data
    var nextCookie: UInt64
    /// `".."` must be packed with the parent's identifier, not the enumerated
    /// directory's own. The name is the only thing distinguishing them, so the
    /// planner records the distinction rather than making the packer re-parse.
    var isParentEntry: Bool = false
}

enum PfsEnumerationCookies {
    static let daemonPageSize: UInt32 = 256
    private static let dotCookie: UInt64 = 0
    static let dotDotCookie: UInt64 = 1
    static let entriesStartCookie: UInt64 = 2
    static let daemonCookieMarker: UInt64 = 1 << 63
    static let terminalCookie = UInt64.max

    /// FSKit enumeration cookie state machine.
    ///
    /// The daemon owns all real enumeration cookies. They are opaque to this adapter
    /// and must be passed through unchanged; the daemon-side encoding guarantees
    /// every real cookie has `daemonCookieMarker` set, so real cookies cannot collide
    /// with the adapter's synthetic positions 0, 1, and 2. `terminalCookie` is the
    /// adapter-only end-of-directory sentinel and is guarded before high-bit dispatch.
    ///
    /// For attribute-free enumerations, cookie 0 emits "." then "..", cookie 1 emits
    /// only "..", and cookie 2 skips synthetics and starts daemon enumeration at 0.
    /// Attribute-requesting enumerations do not emit synthetics, so only cookie 0 or
    /// an opaque high-bit daemon cookie is valid. Daemon entry cookie 0 means EOF and
    /// is translated to `terminalCookie`; every other daemon cookie is returned to
    /// FSKit verbatim.
    static func daemonCookie(for cookie: UInt64, attributesRequested: Bool) throws -> UInt64 {
        if isTerminal(cookie) {
            throw PfsLocalClientError.daemon(errno: EINVAL, message: "terminal directory cookie has no daemon position")
        }
        if cookie == dotCookie {
            return 0
        }
        if !attributesRequested, cookie == dotDotCookie || cookie == entriesStartCookie {
            return 0
        }
        if isDaemonCookie(cookie) {
            return cookie
        }
        throw PfsLocalClientError.daemon(errno: ESTALE, message: "invalid directory cookie")
    }

    /// FSKit's `enumerateDirectory` documentation is explicit that `"."` and
    /// `".."` belong to attribute-free enumerations only: "Don't pack `.` and
    /// `..` if `attributes` isn't `nil`." Readdir-plus therefore stays
    /// synthetic-free and FSKit supplies the two entries itself.
    static func syntheticEntries(for cookie: UInt64, attributesRequested: Bool) throws -> [PfsSyntheticDirectoryEntry] {
        guard !attributesRequested else {
            return []
        }
        switch cookie {
        case dotCookie:
            return [
                PfsSyntheticDirectoryEntry(name: Data(".".utf8), nextCookie: dotDotCookie),
                PfsSyntheticDirectoryEntry(
                    name: Data("..".utf8), nextCookie: entriesStartCookie, isParentEntry: true
                )
            ]
        case dotDotCookie:
            return [
                PfsSyntheticDirectoryEntry(
                    name: Data("..".utf8), nextCookie: entriesStartCookie, isParentEntry: true
                )
            ]
        case entriesStartCookie:
            return []
        default:
            return []
        }
    }

    static func fskitCookie(for daemonCookie: UInt64, attributesRequested _: Bool) throws -> UInt64 {
        if daemonCookie == 0 {
            return terminalCookie
        }
        guard isDaemonCookie(daemonCookie) else {
            throw PfsLocalClientError.daemon(errno: EPROTO, message: "daemon returned non-opaque directory cookie")
        }
        return daemonCookie
    }

    static func isTerminal(_ cookie: UInt64) -> Bool {
        cookie == terminalCookie
    }

    static func isDaemonCookie(_ cookie: UInt64) -> Bool {
        cookie != terminalCookie && (cookie & daemonCookieMarker) != 0
    }
}

/// macOS 26 FSKit entry point backed by `VolumeCore`.
@available(macOS 26.0, *)
public final class PortableFSFileSystem: FSUnaryFileSystem, FSUnaryFileSystemOperations, @unchecked Sendable {
    private let logger = Logger(subsystem: "dev.portablefs.fskit", category: "PortableFSFileSystem")
    private let volumeLock = NSLock()
    private var volumes: [String: PortableFSVolume] = [:]
    private let moduleIdentity: PortableFSModuleIdentity
    private let resolverFactory: @Sendable () -> PfsSocketPathResolver

    public override convenience init() {
        self.init(moduleIdentity: Self.mainBundleIdentity())
    }

    /// Source-compatible initializer for embedders that customize only
    /// daemon socket discovery. Identity still comes from the running
    /// extension's signed metadata; there is no OSS-identity assumption.
    public convenience init(
        resolverFactory: @escaping @Sendable () -> PfsSocketPathResolver
    ) {
        self.init(
            moduleIdentity: Self.mainBundleIdentity(),
            resolverFactory: resolverFactory
        )
    }

    public init(
        moduleIdentity: PortableFSModuleIdentity,
        resolverFactory: @escaping @Sendable () -> PfsSocketPathResolver = {
            PfsSocketPathResolver(bundle: .main)
        }
    ) {
        self.moduleIdentity = moduleIdentity
        self.resolverFactory = resolverFactory
        super.init()
    }

    public func probeResource(
        resource: FSResource,
        replyHandler: @escaping (FSProbeResult?, (any Error)?) -> Void
    ) {
        do {
            let attachRef = try attachRef(from: resource)
            let result = FSProbeResult.usable(
                name: "PortableFS",
                containerID: FSContainerIdentifier(
                    uuid: Self.stableEntityUUID(
                        kind: "container",
                        stableID: attachRef,
                        moduleIdentity: moduleIdentity
                    )
                )
            )
            replyHandler(result, nil)
        } catch {
            logger.debug("probeResource rejected resource: \(String(describing: error), privacy: .public)")
            replyHandler(.notRecognized, nil)
        }
    }

    public func loadResource(
        resource: FSResource,
        options: FSTaskOptions,
        replyHandler: @escaping (FSVolume?, (any Error)?) -> Void
    ) {
        let reply = PfsLoadResourceReply(replyHandler)
        do {
            let attachRef = try attachRef(from: resource)
            Task {
                do {
                    let socketPath = try resolverFactory().resolve()
                    logger.info("loadResource resolving via socket \(socketPath, privacy: .public) for ref \(attachRef, privacy: .public)")
                    let core = try await VolumeCore.connect(socketPath: socketPath, attachRef: attachRef)
                    let volume = try await PortableFSVolume.make(
                        core: core,
                        attachRef: attachRef,
                        moduleIdentity: moduleIdentity
                    )
                    storeVolume(volume, attachRef: attachRef)
                    containerStatus = .ready
                    reply.call(volume, nil)
                } catch {
                    logger.error("loadResource failed: \(String(describing: error), privacy: .public)")
                    reply.call(nil, PfsErrorMapper.fsKitError(for: error))
                }
            }
        } catch {
            reply.call(nil, PfsErrorMapper.fsKitError(for: error))
        }
    }

    public func unloadResource(
        resource: FSResource,
        options: FSTaskOptions,
        replyHandler reply: @escaping ((any Error)?) -> Void
    ) {
        let reply = PfsUnloadResourceReply(reply)
        do {
            let attachRef = try attachRef(from: resource)
            if let volume = removeVolume(attachRef: attachRef) {
                Task {
                    await volume.shutdown()
                    reply.call(nil)
                }
            } else {
                reply.call(nil)
            }
        } catch {
            reply.call(PfsErrorMapper.fsKitError(for: error))
        }
    }

    public func didFinishLoading() {
        containerStatus = .ready
    }

    private func storeVolume(_ volume: PortableFSVolume, attachRef: String) {
        volumeLock.lock()
        volumes[attachRef] = volume
        volumeLock.unlock()
    }

    private func removeVolume(attachRef: String) -> PortableFSVolume? {
        volumeLock.lock()
        let volume = volumes.removeValue(forKey: attachRef)
        volumeLock.unlock()
        return volume
    }

    private final class PfsLoadResourceReply: @unchecked Sendable {
        private let reply: (FSVolume?, (any Error)?) -> Void

        init(_ reply: @escaping (FSVolume?, (any Error)?) -> Void) {
            self.reply = reply
        }

        func call(_ volume: FSVolume?, _ error: (any Error)?) {
            reply(volume, error)
        }
    }

    private final class PfsUnloadResourceReply: @unchecked Sendable {
        private let reply: ((any Error)?) -> Void

        init(_ reply: @escaping ((any Error)?) -> Void) {
            self.reply = reply
        }

        func call(_ error: (any Error)?) {
            reply(error)
        }
    }

    private static func mainBundleIdentity() -> PortableFSModuleIdentity {
        do {
            return try PortableFSModuleIdentity(bundle: .main)
        } catch {
            fatalError("invalid FSKit module identity: \(error.localizedDescription)")
        }
    }

    private func attachRef(from resource: FSResource) throws -> String {
        guard let urlResource = resource as? FSGenericURLResource else {
            throw PfsLocalClientError.daemon(errno: ENXIO, message: "resource is not a generic URL")
        }
        let url = urlResource.url
        guard url.scheme?.lowercased() == moduleIdentity.resourceScheme else {
            throw PfsLocalClientError.daemon(
                errno: ENXIO,
                message: "resource scheme is not \(moduleIdentity.resourceScheme)"
            )
        }
        if let host = url.host, !host.isEmpty {
            return host
        }
        let prefix = moduleIdentity.resourcePrefix
        let absolute = url.absoluteString
        guard absolute.hasPrefix(prefix), absolute.count > prefix.count else {
            throw PfsLocalClientError.daemon(errno: ENXIO, message: "missing attachRef")
        }
        return String(absolute.dropFirst(prefix.count))
    }

    /// Derives a deterministic UUIDv8 while preserving the global FSKit
    /// namespace boundary between products that embed this shared adapter.
    ///
    /// FSKit requires each container and volume identifier to uniquely
    /// identify that entity. Backend identifiers are only unique inside one
    /// PortableFS product, so hashing one without the signed module identity
    /// lets two installed products alias the same LiveFS settings entry.
    static func stableEntityUUID(
        kind: String,
        stableID: String,
        moduleIdentity: PortableFSModuleIdentity
    ) -> UUID {
        var input = Data()
        for component in [
            "portablefs-fskit-entity-v1",
            moduleIdentity.fileSystemTypeName,
            moduleIdentity.resourceScheme,
            kind,
            stableID
        ] {
            let data = Data(component.utf8)
            var byteCount = UInt64(data.count).bigEndian
            withUnsafeBytes(of: &byteCount) { input.append(contentsOf: $0) }
            input.append(data)
        }
        var bytes = Array(SHA256.hash(data: input).prefix(16))
        // RFC 9562 UUIDv8: application-defined payload plus the RFC variant.
        bytes[6] = (bytes[6] & 0x0f) | 0x80
        bytes[8] = (bytes[8] & 0x3f) | 0x80
        return UUID(uuid: (
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
            bytes[8], bytes[9], bytes[10], bytes[11],
            bytes[12], bytes[13], bytes[14], bytes[15]
        ))
    }
}

@available(macOS 26.0, *)
public final class PortableFSVolume: FSVolume, FSVolume.Operations, FSVolume.OpenCloseOperations, FSVolume.ReadWriteOperations, FSVolume.XattrOperations, FSVolume.PathConfOperations, @unchecked Sendable {
    public let core: VolumeCore
    public let capabilities: PfsCapabilities
    private let logger = Logger(subsystem: "dev.portablefs.fskit", category: "PortableFSVolume")
    private let fileSystemTypeName: String
    private let statLock = NSLock()
    private var cachedStatistics: FSStatFSResult

    public static func make(
        core: VolumeCore,
        attachRef: String,
        moduleIdentity: PortableFSModuleIdentity = PortableFSIdentity.moduleIdentity
    ) async throws -> PortableFSVolume {
        guard let resolved = await core.resolvedVolume else {
            throw PfsLocalClientError.unexpectedReply("volume has not been resolved")
        }
        let statReply = try await core.statfs()
        return PortableFSVolume(
            core: core,
            attachRef: attachRef,
            resolved: resolved,
            statReply: statReply,
            moduleIdentity: moduleIdentity
        )
    }

    private init(
        core: VolumeCore,
        attachRef: String,
        resolved: PfsResolvedVolume,
        statReply: PfsStatfsReply,
        moduleIdentity: PortableFSModuleIdentity
    ) {
        self.core = core
        self.capabilities = resolved.capabilities
        self.fileSystemTypeName = moduleIdentity.fileSystemTypeName
        self.cachedStatistics = PfsFSKitMapping.statfs(
            from: statReply,
            capabilities: resolved.capabilities,
            fileSystemTypeName: moduleIdentity.fileSystemTypeName
        )
        let volumeID = FSVolume.Identifier(
            uuid: PortableFSFileSystem.stableEntityUUID(
                kind: "volume",
                stableID: resolved.volumeID.isEmpty ? attachRef : resolved.volumeID,
                moduleIdentity: moduleIdentity
            )
        )
        let volumeName = FSFileName(string: resolved.volumeName)
        super.init(volumeID: volumeID, volumeName: volumeName)
    }

    public var maximumLinkCount: Int {
        Int(Int32.max)
    }

    public var maximumNameLength: Int {
        let value = capabilities.maxNameBytes
        return value == 0 ? 255 : Int(value)
    }

    public var restrictsOwnershipChanges: Bool {
        true
    }

    public var truncatesLongNames: Bool {
        false
    }

    public var maximumXattrSize: Int {
        1 * 1024 * 1024
    }

    public var maximumFileSize: UInt64 {
        capabilities.maxFileSize == 0 ? UInt64.max : capabilities.maxFileSize
    }

    public var supportedVolumeCapabilities: FSVolume.SupportedCapabilities {
        PfsFSKitMapping.supportedCapabilities(from: capabilities)
    }

    public var volumeStatistics: FSStatFSResult {
        statLock.lock()
        let statistics = cachedStatistics
        statLock.unlock()
        return statistics
    }

    public func activate(options: FSTaskOptions) async throws -> FSItem {
        do {
            return try await core.rootItem()
        } catch {
            throw PfsErrorMapper.fsKitError(for: error)
        }
    }

    public func deactivate(options: FSDeactivateOptions = []) async throws {
        await core.shutdown()
    }

    public func mount(options: FSTaskOptions) async throws {
        do {
            _ = try await core.rootItem()
        } catch {
            throw PfsErrorMapper.fsKitError(for: error)
        }
    }

    public func unmount() async {
        await core.shutdown()
    }

    public func synchronize(flags: FSSyncFlags) async throws {
        do {
            // The REAL volume barrier: the daemon drains outstanding
            // write-back to the authority and waits for every live protocol
            // subscriber's supported acknowledgment boundary. On macOS 26,
            // the daemon refreshes known regular-file data and size before
            // acknowledging content changes; cached namespace bindings and
            // other attributes remain outside FSKit's public cache-control
            // surface. Failure (unreachable/slow/fenced authority) throws —
            // never a silent local-only outcome. Local WAL sync failure
            // throws as well and seals later mutation admission.
            try await core.syncVolume()
            if let stat = try? await core.statfs() {
                setCachedStatistics(PfsFSKitMapping.statfs(
                    from: stat,
                    capabilities: capabilities,
                    fileSystemTypeName: fileSystemTypeName
                ))
            }
        } catch {
            throw PfsErrorMapper.fsKitError(for: error)
        }
    }

    private func publishAfterReply<Value>(
        _ operation: @escaping () async throws -> Value,
        reply: @escaping (Result<Value, Error>) -> Void
    ) {
        let operation = PfsUncheckedSendableBox(operation)
        let reply = PfsUncheckedSendableBox(reply)
        Task {
            let (result, complete) = await core.client.withDeferredPublication {
                try await operation.value()
            }
            // FSKit's callback is the framework publication boundary. Invoke
            // it first; only after it returns may the daemon let Checkin and a
            // competing peer mutation proceed.
            reply.value(result)
            await complete()
        }
    }

    @nonobjc
    public func attributes(_ desiredAttributes: FSItem.GetAttributesRequest, of item: FSItem) async throws -> FSItem.Attributes {
        try await core.client.withPublicationBoundary {
            do {
                let attr = try await core.getattr(item: try portableItem(item))
                return try PfsFSKitMapping.attributes(
                    from: attr,
                    requested: desiredAttributes.wantedAttributes
                )
            } catch {
                throw PfsErrorMapper.fsKitError(for: error)
            }
        }
    }

    public func getAttributes(
        _ desiredAttributes: FSItem.GetAttributesRequest,
        of item: FSItem,
        replyHandler reply: @escaping (FSItem.Attributes?, Error?) -> Void
    ) {
        publishAfterReply({
            try await self.attributes(desiredAttributes, of: item)
        }, reply: { result in
            switch result {
            case let .success(attributes):
                reply(attributes, nil)
            case let .failure(error):
                reply(nil, error)
            }
        })
    }

    @nonobjc
    public func setAttributes(_ newAttributes: FSItem.SetAttributesRequest, on item: FSItem) async throws -> FSItem.Attributes {
        try await core.client.withPublicationBoundary {
            do {
                let request = try PfsFSKitMapping.setAttributes(from: newAttributes)
                let attr = try await core.setattr(item: try portableItem(item), attributes: request)
                return try PfsFSKitMapping.attributes(from: attr)
            } catch {
                throw PfsErrorMapper.fsKitError(for: error)
            }
        }
    }

    @nonobjc
    public func lookupItem(named name: FSFileName, inDirectory directory: FSItem) async throws -> (FSItem, FSFileName) {
        try await core.client.withPublicationBoundary {
            do {
                let result = try await core.lookup(in: try portableItem(directory), name: name.data)
                return (result.item, PfsFSKitMapping.fileName(from: result.canonicalName))
            } catch {
                throw PfsErrorMapper.fsKitError(for: error)
            }
        }
    }

    @nonobjc
    public func reclaimItem(_ item: FSItem) async throws {
        try await core.client.withPublicationBoundary {
            do {
                try await core.reclaim(item: try portableItem(item))
            } catch {
                throw PfsErrorMapper.fsKitError(for: error)
            }
        }
    }

    @nonobjc
    public func readSymbolicLink(_ item: FSItem) async throws -> FSFileName {
        try await core.client.withPublicationBoundary {
            do {
                let target = try await core.readlink(item: try portableItem(item))
                return PfsFSKitMapping.fileName(from: target)
            } catch {
                logger.error("readlink failed: \(String(describing: error), privacy: .private)")
                throw PfsErrorMapper.fsKitError(for: error)
            }
        }
    }

    @nonobjc
    public func createItem(
        named name: FSFileName,
        type: FSItem.ItemType,
        inDirectory directory: FSItem,
        attributes newAttributes: FSItem.SetAttributesRequest
    ) async throws -> (FSItem, FSFileName) {
        try await core.client.withPublicationBoundary {
          do {
            let mode = newAttributes.isValid(.mode) ? newAttributes.mode : 0o644
            let result: PfsCreateResult
            switch type {
            case .file:
                result = try await core.createFile(in: try portableItem(directory), name: name.data, mode: mode)
            case .directory:
                result = try await core.mkdir(in: try portableItem(directory), name: name.data, mode: mode == 0o644 ? 0o755 : mode)
            default:
                throw PfsLocalClientError.daemon(errno: ENOTSUP, message: "unsupported create item type")
            }
            return (result.item, PfsFSKitMapping.fileName(from: result.canonicalName))
          } catch {
              throw PfsErrorMapper.fsKitError(for: error)
          }
        }
    }

    @nonobjc
    public func createSymbolicLink(
        named name: FSFileName,
        inDirectory directory: FSItem,
        attributes newAttributes: FSItem.SetAttributesRequest,
        linkContents contents: FSFileName
    ) async throws -> (FSItem, FSFileName) {
        try await core.client.withPublicationBoundary {
          do {
            let targetBytes = PfsFSKitMapping.bytes(from: contents)
            let result = try await core.symlink(
                in: try portableItem(directory),
                name: name.data,
                target: targetBytes
            )
            return (result.item, PfsFSKitMapping.fileName(from: result.canonicalName))
          } catch {
              logger.error("symlink create failed: \(String(describing: error), privacy: .private)")
              throw PfsErrorMapper.fsKitError(for: error)
          }
        }
    }

    @nonobjc
    public func createLink(to item: FSItem, named name: FSFileName, inDirectory directory: FSItem) async throws -> FSFileName {
        try await core.client.withPublicationBoundary {
            do {
                let canonicalName = try await core.hardLink(item: try portableItem(item), in: try portableItem(directory), name: name.data)
                return PfsFSKitMapping.fileName(from: canonicalName)
            } catch {
                throw PfsErrorMapper.fsKitError(for: error)
            }
        }
    }

    @nonobjc
    public func removeItem(_ item: FSItem, named name: FSFileName, fromDirectory directory: FSItem) async throws {
        try await core.client.withPublicationBoundary {
          do {
            let portable = try portableItem(item)
            let attr = try await core.getattr(item: portable)
            try await core.remove(
                item: portable,
                named: name.data,
                from: try portableItem(directory),
                isDirectory: attr.kind == .directory
            )
          } catch {
              throw PfsErrorMapper.fsKitError(for: error)
          }
        }
    }

    @nonobjc
    public func renameItem(
        _ item: FSItem,
        inDirectory sourceDirectory: FSItem,
        named sourceName: FSFileName,
        to destinationName: FSFileName,
        inDirectory destinationDirectory: FSItem,
        overItem: FSItem?
    ) async throws -> FSFileName {
        try await core.client.withPublicationBoundary {
          do {
            let sourceItem = try portableItem(item)
            try await core.rename(
                item: sourceItem,
                from: try portableItem(sourceDirectory),
                sourceName: sourceName.data,
                to: try portableItem(destinationDirectory),
                destinationName: destinationName.data,
                noReplace: false
            )
            if let overItem, let replacedItem = overItem as? PortableFSItem, replacedItem !== sourceItem {
                try await core.recordRenameReplacement(replacedItem: replacedItem)
            }
            return destinationName
          } catch {
              throw PfsErrorMapper.fsKitError(for: error)
          }
        }
    }

    @nonobjc
    public func enumerateDirectory(
        _ directory: FSItem,
        startingAt cookie: FSDirectoryCookie,
        verifier: FSDirectoryVerifier,
        attributes: FSItem.GetAttributesRequest?,
        packer: FSDirectoryEntryPacker
    ) async throws -> FSDirectoryVerifier {
        return try await core.client.withPublicationBoundary {
          do {
            let portableDirectory = try portableItem(directory)
            let attributesRequested = attributes != nil
            logger.debug("enumerate dir=\(portableDirectory.identity.itemID) cookie=\(cookie.rawValue) verifier=\(verifier.rawValue) attrs=\(attributesRequested)")
            if PfsEnumerationCookies.isTerminal(cookie.rawValue) {
                return verifier
            }
            var daemonCookie = try PfsEnumerationCookies.daemonCookie(
                for: cookie.rawValue,
                attributesRequested: attributesRequested
            )
            var result = try await core.enumerate(
                directory: portableDirectory,
                startingAt: daemonCookie,
                wantAttributes: attributesRequested,
                maxEntries: PfsEnumerationCookies.daemonPageSize
            )
            let currentVerifier = try PfsFSKitMapping.directoryVerifier(
                from: result.verifier
            )

            let synthetics = try PfsEnumerationCookies.syntheticEntries(
                for: cookie.rawValue,
                attributesRequested: attributesRequested
            )
            let selfIdentifier = try PfsFSKitMapping.itemIdentifier(
                from: portableDirectory.identity.itemID
            )
            var parentIdentifier = selfIdentifier
            if synthetics.contains(where: { $0.isParentEntry }),
               let directoryAttr = try? await core.getattr(item: portableDirectory) {
                // A retained-but-unlinked directory still enumerates through
                // its open reference but has no live parent to name; POSIX
                // offers no better answer than itself, so a failed lookup
                // must not fail the enumeration.
                parentIdentifier = try PfsFSKitMapping.parentDirectoryIdentifier(
                    from: directoryAttr
                )
            }
            for entry in synthetics {
                let packed = packer.packEntry(
                    name: PfsFSKitMapping.fileName(from: entry.name),
                    itemType: .directory,
                    itemID: entry.isParentEntry ? parentIdentifier : selfIdentifier,
                    nextCookie: FSDirectoryCookie(entry.nextCookie),
                    attributes: nil
                )
                if !packed {
                    return currentVerifier
                }
            }

            while true {
                for entry in result.entries {
                    let packed = packer.packEntry(
                        name: PfsFSKitMapping.fileName(from: entry.name),
                        itemType: PfsFSKitMapping.itemType(from: entry.attr.kind),
                        itemID: try PfsFSKitMapping.itemIdentifier(
                            from: entry.attr.item.itemID
                        ),
                        nextCookie: FSDirectoryCookie(
                            try PfsEnumerationCookies.fskitCookie(
                                for: entry.nextCookie,
                                attributesRequested: attributesRequested
                            )
                        ),
                        attributes: attributes == nil
                            ? nil
                            : try PfsFSKitMapping.attributes(
                                from: entry.attr,
                                requested: attributes?.wantedAttributes
                            )
                    )
                    if !packed {
                        return currentVerifier
                    }
                }

                daemonCookie = result.nextCookie
                if daemonCookie == 0 {
                    break
                }
                result = try await core.enumerate(
                    directory: portableDirectory,
                    startingAt: daemonCookie,
                    wantAttributes: attributesRequested,
                    maxEntries: PfsEnumerationCookies.daemonPageSize
                )
            }
            return currentVerifier
          } catch let error as PfsLocalClientError where error.posixErrno == ESTALE {
            // The daemon signals an unknown/expired/pre-restart enumeration cookie with
            // ESTALE (its documented fail-safe). Surface FSKit's invalid-directory-cookie
            // error so the kernel restarts the enumeration from scratch instead of
            // bubbling a raw POSIX ESTALE to readdir callers.
            throw PfsErrorMapper.invalidDirectoryCookieError()
          } catch {
              throw PfsErrorMapper.fsKitError(for: error)
          }
        }
    }

    @nonobjc
    public func openItem(_ item: FSItem, modes: FSVolume.OpenModes) async throws {
        try await core.client.withPublicationBoundary {
            do {
                try await core.open(item: try portableItem(item), mode: PfsFSKitMapping.openMode(from: modes))
            } catch {
                throw PfsErrorMapper.fsKitError(for: error)
            }
        }
    }

    @nonobjc
    public func closeItem(_ item: FSItem, modes: FSVolume.OpenModes) async throws {
        try await core.client.withPublicationBoundary {
            do {
                try await core.close(item: try portableItem(item), retainingModes: PfsFSKitMapping.openMode(from: modes))
            } catch {
                throw PfsErrorMapper.fsKitError(for: error)
            }
        }
    }

    @nonobjc
    public func read(from item: FSItem, at offset: off_t, length: Int, into buffer: FSMutableFileDataBuffer) async throws -> Int {
        try await core.client.withPublicationBoundary {
          do {
            let pit = try portableItem(item)
            let data = try await core.read(item: pit, offset: UInt64(offset), length: UInt32(clamping: length))
            let copied = min(data.count, buffer.length)
            data.withUnsafeBytes { source in
                buffer.withUnsafeMutableBytes { destination in
                    if let src = source.baseAddress, let dst = destination.baseAddress {
                        memcpy(dst, src, copied)
                    }
                }
            }
            return copied
          } catch {
              throw PfsErrorMapper.fsKitError(for: error)
          }
        }
    }

    @nonobjc
    public func write(contents: Data, to item: FSItem, at offset: off_t) async throws -> Int {
        try await core.client.withPublicationBoundary {
            do {
                let result = try await core.write(item: try portableItem(item), offset: UInt64(offset), data: contents)
                return Int(result.written)
            } catch {
                throw PfsErrorMapper.fsKitError(for: error)
            }
        }
    }

    @nonobjc
    public func xattr(named name: FSFileName, of item: FSItem) async throws -> Data {
        try await core.client.withPublicationBoundary {
            do {
                return try await core.xattrGet(item: try portableItem(item), name: try PfsFSKitMapping.xattrName(from: name))
            } catch {
                throw PfsErrorMapper.fsKitError(for: error)
            }
        }
    }

    @nonobjc
    public func setXattr(named name: FSFileName, to value: Data?, on item: FSItem, policy: FSVolume.SetXattrPolicy) async throws {
        try await core.client.withPublicationBoundary {
          do {
            let portable = try portableItem(item)
            let xattrName = try PfsFSKitMapping.xattrName(from: name)
            switch policy {
            case .delete:
                try await core.xattrRemove(item: portable, name: xattrName)
            case .mustCreate:
                try await core.xattrSet(item: portable, name: xattrName, value: value ?? Data(), createOnly: true, replaceOnly: false)
            case .mustReplace:
                try await core.xattrSet(item: portable, name: xattrName, value: value ?? Data(), createOnly: false, replaceOnly: true)
            case .alwaysSet:
                try await core.xattrSet(item: portable, name: xattrName, value: value ?? Data(), createOnly: false, replaceOnly: false)
            @unknown default:
                throw PfsLocalClientError.daemon(errno: EINVAL, message: "unknown xattr policy")
            }
          } catch {
              throw PfsErrorMapper.fsKitError(for: error)
          }
        }
    }

    @nonobjc
    public func xattrs(of item: FSItem) async throws -> [FSFileName] {
        try await core.client.withPublicationBoundary {
            do {
                let names = try await core.xattrList(item: try portableItem(item))
                return names.map { FSFileName(string: $0) }
            } catch {
                throw PfsErrorMapper.fsKitError(for: error)
            }
        }
    }

    public func setAttributes(
        _ newAttributes: FSItem.SetAttributesRequest,
        on item: FSItem,
        replyHandler reply: @escaping (FSItem.Attributes?, Error?) -> Void
    ) {
        publishAfterReply({
            try await self.setAttributes(newAttributes, on: item)
        }, reply: { result in
            switch result {
            case let .success(attributes): reply(attributes, nil)
            case let .failure(error): reply(nil, error)
            }
        })
    }

    public func lookupItem(
        named name: FSFileName,
        inDirectory directory: FSItem,
        replyHandler reply: @escaping (FSItem?, FSFileName?, Error?) -> Void
    ) {
        publishAfterReply({
            try await self.lookupItem(named: name, inDirectory: directory)
        }, reply: { result in
            switch result {
            case let .success((item, canonicalName)): reply(item, canonicalName, nil)
            case let .failure(error): reply(nil, nil, error)
            }
        })
    }

    public func reclaimItem(
        _ item: FSItem,
        replyHandler reply: @escaping (Error?) -> Void
    ) {
        publishAfterReply({
            try await self.reclaimItem(item)
        }, reply: { result in
            switch result {
            case .success: reply(nil)
            case let .failure(error): reply(error)
            }
        })
    }

    public func readSymbolicLink(
        _ item: FSItem,
        replyHandler reply: @escaping (FSFileName?, Error?) -> Void
    ) {
        publishAfterReply({
            try await self.readSymbolicLink(item)
        }, reply: { result in
            switch result {
            case let .success(contents): reply(contents, nil)
            case let .failure(error): reply(nil, error)
            }
        })
    }

    public func createItem(
        named name: FSFileName,
        type: FSItem.ItemType,
        inDirectory directory: FSItem,
        attributes newAttributes: FSItem.SetAttributesRequest,
        replyHandler reply: @escaping (FSItem?, FSFileName?, Error?) -> Void
    ) {
        publishAfterReply({
            try await self.createItem(
                named: name,
                type: type,
                inDirectory: directory,
                attributes: newAttributes
            )
        }, reply: { result in
            switch result {
            case let .success((item, canonicalName)): reply(item, canonicalName, nil)
            case let .failure(error): reply(nil, nil, error)
            }
        })
    }

    public func createSymbolicLink(
        named name: FSFileName,
        inDirectory directory: FSItem,
        attributes newAttributes: FSItem.SetAttributesRequest,
        linkContents contents: FSFileName,
        replyHandler reply: @escaping (FSItem?, FSFileName?, Error?) -> Void
    ) {
        publishAfterReply({
            try await self.createSymbolicLink(
                named: name,
                inDirectory: directory,
                attributes: newAttributes,
                linkContents: contents
            )
        }, reply: { result in
            switch result {
            case let .success((item, canonicalName)): reply(item, canonicalName, nil)
            case let .failure(error): reply(nil, nil, error)
            }
        })
    }

    public func createLink(
        to item: FSItem,
        named name: FSFileName,
        inDirectory directory: FSItem,
        replyHandler reply: @escaping (FSFileName?, Error?) -> Void
    ) {
        publishAfterReply({
            try await self.createLink(to: item, named: name, inDirectory: directory)
        }, reply: { result in
            switch result {
            case let .success(canonicalName): reply(canonicalName, nil)
            case let .failure(error): reply(nil, error)
            }
        })
    }

    public func removeItem(
        _ item: FSItem,
        named name: FSFileName,
        fromDirectory directory: FSItem,
        replyHandler reply: @escaping (Error?) -> Void
    ) {
        publishAfterReply({
            try await self.removeItem(item, named: name, fromDirectory: directory)
        }, reply: { result in
            switch result {
            case .success: reply(nil)
            case let .failure(error): reply(error)
            }
        })
    }

    public func renameItem(
        _ item: FSItem,
        inDirectory sourceDirectory: FSItem,
        named sourceName: FSFileName,
        to destinationName: FSFileName,
        inDirectory destinationDirectory: FSItem,
        overItem: FSItem?,
        replyHandler reply: @escaping (FSFileName?, Error?) -> Void
    ) {
        publishAfterReply({
            try await self.renameItem(
                item,
                inDirectory: sourceDirectory,
                named: sourceName,
                to: destinationName,
                inDirectory: destinationDirectory,
                overItem: overItem
            )
        }, reply: { result in
            switch result {
            case let .success(canonicalName): reply(canonicalName, nil)
            case let .failure(error): reply(nil, error)
            }
        })
    }

    public func enumerateDirectory(
        _ directory: FSItem,
        startingAt cookie: FSDirectoryCookie,
        verifier: FSDirectoryVerifier,
        attributes: FSItem.GetAttributesRequest?,
        packer: FSDirectoryEntryPacker,
        replyHandler reply: @escaping (FSDirectoryVerifier, Error?) -> Void
    ) {
        publishAfterReply({
            try await self.enumerateDirectory(
                directory,
                startingAt: cookie,
                verifier: verifier,
                attributes: attributes,
                packer: packer
            )
        }, reply: { result in
            switch result {
            case let .success(currentVerifier): reply(currentVerifier, nil)
            case let .failure(error): reply(.initial, error)
            }
        })
    }

    public func openItem(
        _ item: FSItem,
        modes: FSVolume.OpenModes,
        replyHandler reply: @escaping (Error?) -> Void
    ) {
        publishAfterReply({
            try await self.openItem(item, modes: modes)
        }, reply: { result in
            switch result {
            case .success: reply(nil)
            case let .failure(error): reply(error)
            }
        })
    }

    public func closeItem(
        _ item: FSItem,
        modes: FSVolume.OpenModes,
        replyHandler reply: @escaping (Error?) -> Void
    ) {
        publishAfterReply({
            try await self.closeItem(item, modes: modes)
        }, reply: { result in
            switch result {
            case .success: reply(nil)
            case let .failure(error): reply(error)
            }
        })
    }

    public func read(
        from item: FSItem,
        at offset: off_t,
        length: Int,
        into buffer: FSMutableFileDataBuffer,
        replyHandler reply: @escaping (Int, Error?) -> Void
    ) {
        publishAfterReply({
            try await self.read(from: item, at: offset, length: length, into: buffer)
        }, reply: { result in
            switch result {
            case let .success(count): reply(count, nil)
            case let .failure(error): reply(0, error)
            }
        })
    }

    public func write(
        contents: Data,
        to item: FSItem,
        at offset: off_t,
        replyHandler reply: @escaping (Int, Error?) -> Void
    ) {
        publishAfterReply({
            try await self.write(contents: contents, to: item, at: offset)
        }, reply: { result in
            switch result {
            case let .success(count): reply(count, nil)
            case let .failure(error): reply(0, error)
            }
        })
    }

    public func getXattr(
        named name: FSFileName,
        of item: FSItem,
        replyHandler reply: @escaping (Data?, Error?) -> Void
    ) {
        publishAfterReply({
            try await self.xattr(named: name, of: item)
        }, reply: { result in
            switch result {
            case let .success(value): reply(value, nil)
            case let .failure(error): reply(nil, error)
            }
        })
    }

    public func setXattr(
        named name: FSFileName,
        to value: Data?,
        on item: FSItem,
        policy: FSVolume.SetXattrPolicy,
        replyHandler reply: @escaping (Error?) -> Void
    ) {
        publishAfterReply({
            try await self.setXattr(named: name, to: value, on: item, policy: policy)
        }, reply: { result in
            switch result {
            case .success: reply(nil)
            case let .failure(error): reply(error)
            }
        })
    }

    public func listXattrs(
        of item: FSItem,
        replyHandler reply: @escaping ([FSFileName]?, Error?) -> Void
    ) {
        publishAfterReply({
            try await self.xattrs(of: item)
        }, reply: { result in
            switch result {
            case let .success(names): reply(names, nil)
            case let .failure(error): reply(nil, error)
            }
        })
    }

    public func shutdown() async {
        await core.shutdown()
    }

    private func setCachedStatistics(_ statistics: FSStatFSResult) {
        statLock.lock()
        cachedStatistics = statistics
        statLock.unlock()
    }

    private func portableItem(_ item: FSItem) throws -> PortableFSItem {
        guard let portable = item as? PortableFSItem else {
            throw PfsLocalClientError.daemon(errno: ESTALE, message: "unknown FSItem")
        }
        return portable
    }
}
