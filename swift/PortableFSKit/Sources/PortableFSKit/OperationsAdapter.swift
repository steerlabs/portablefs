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
    /// `FSDirectoryVerifierInitial`, the value FSKit passes on a fresh walk.
    @available(macOS 26.0, *)
    static var initialVerifier: UInt64 { FSDirectoryVerifier.initial.rawValue }

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

    /// A fresh walk is one FSKit starts from `FSDirectoryCookieInitial`, or one
    /// whose verifier is still `FSDirectoryVerifierInitial` (the synthetic "."
    /// and ".." positions are the same walk, but the kernel has not been given
    /// a verifier to echo back yet). Everything else is a continuation whose
    /// verifier must stay exactly as issued.
    @available(macOS 26.0, *)
    static func isFreshStart(cookie: UInt64, verifier: UInt64) -> Bool {
        cookie == FSDirectoryCookie.initial.rawValue || verifier == initialVerifier
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
    /// The macOS 26 repair gate, when one is installed.
    ///
    /// `nil` — the legacy (non-v3) configuration — does not disable the
    /// reserved-namespace check; it makes it absolute. Every reserved name is
    /// then refused with EPERM, which is the fail-closed end of the contract:
    /// no repair can run, and no user file can occupy a name the repair
    /// machinery would later claim.
    private let repairGate: (any PfsMacOS26RepairGate)?
    /// The composed strict-v3 coherence stack, installed exactly when the
    /// resolve contract declared the macOS 26 compatibility cache policy.
    /// With it installed, every cache-producing callback passes publication
    /// admission and populates the namespace/live-object indexes; without it,
    /// the volume is a legacy mount and records nothing. Internal so the
    /// offline suite can witness what a composed mount installed.
    let coherence: PfsMacOSV3VolumeCoherence?
    private let attachRef: String

    public static func make(
        core: VolumeCore,
        attachRef: String,
        moduleIdentity: PortableFSModuleIdentity = PortableFSIdentity.moduleIdentity,
        repairGate: (any PfsMacOS26RepairGate)? = nil,
        coherence: PfsMacOSV3VolumeCoherence? = nil
    ) async throws -> PortableFSVolume {
        guard let resolved = await core.resolvedVolume else {
            throw PfsLocalClientError.unexpectedReply("volume has not been resolved")
        }
        var installedCoherence = coherence
        if installedCoherence == nil,
           let strictReply = await core.strictV3ResolveReply,
           let strictContract = await core.strictV3Contract {
            do {
                installedCoherence = try await PfsMacOSV3VolumeCoherence.compose(
                    client: core.client,
                    resolved: strictReply,
                    contract: strictContract
                )
            } catch {
                // The resolve accepted a policy this adapter then failed to
                // install. Serving without the stack it promised would ignore
                // every visibility event, so the mount fails closed instead.
                await core.shutdown()
                throw error
            }
        }
        let statReply = try await core.statfs()
        return PortableFSVolume(
            core: core,
            attachRef: attachRef,
            resolved: resolved,
            statReply: statReply,
            moduleIdentity: moduleIdentity,
            repairGate: installedCoherence?.repairGate ?? repairGate,
            coherence: installedCoherence
        )
    }

    private init(
        core: VolumeCore,
        attachRef: String,
        resolved: PfsResolvedVolume,
        statReply: PfsStatfsReply,
        moduleIdentity: PortableFSModuleIdentity,
        repairGate: (any PfsMacOS26RepairGate)?,
        coherence: PfsMacOSV3VolumeCoherence?
    ) {
        self.core = core
        self.capabilities = resolved.capabilities
        self.repairGate = repairGate
        self.coherence = coherence
        self.attachRef = attachRef
        self.fileSystemTypeName = moduleIdentity.fileSystemTypeName
        self.cachedStatistics = PfsFSKitMapping.statfs(
            from: statReply,
            capabilities: resolved.capabilities,
            fileSystemTypeName: moduleIdentity.fileSystemTypeName
        )
        // The FSKit volume identity is scoped to the ATTACH, not the backend
        // volume, exactly like the container identity above. A v3 mount is one
        // incarnation: a fenced or abnormally-ended incarnation never comes
        // back, and its successor registers as a new one. Deriving this UUID
        // from the backend volume ID gave every incarnation the same FSKit
        // identity, so a volume record left in fskitd by an incarnation that
        // died before completing deactivateVolume collided with every future
        // mount of that volume — "a file with the same name already exists"
        // at the final mount step, curable only by restarting fskitd. fskitd's
        // record of a dead incarnation must never be able to name a live one.
        let volumeID = FSVolume.Identifier(
            uuid: PortableFSFileSystem.stableEntityUUID(
                kind: "volume",
                stableID: attachRef,
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
        coherence?.shutdown()
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
        coherence?.shutdown()
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

    /// Whether one callback passes the strict publication-admission gate or is
    /// routed around it. Only two things may bypass a closed gate: the repair
    /// machinery's own re-entrant callbacks (reserved operand names, the local
    /// scratch item, or the armed data-invalidation isolation item), which the
    /// closed gate exists to serve, and nothing else. The initiating mutation
    /// callback is NOT an exemption here — it is admitted normally before the
    /// barrier closes and exempted from the drain by its operation ID.
    private func admissionExemption(
        reservedNames: [Data] = [],
        items: [FSItem?] = []
    ) -> @Sendable () async -> Bool {
        let items = PfsUncheckedSendableBox(items)
        return { [weak self] in
            guard let self else { return true }
            for name in reservedNames where PfsMacOS26RepairAuthenticator.isReserved(name) {
                return true
            }
            for case let portable as PortableFSItem in items.value.compactMap({ $0 }) {
                if await self.core.isLocalRepairItem(portable) {
                    return true
                }
                if let repairGate = self.repairGate,
                   await repairGate.isArmedTruncateItem(
                       itemIdentity: portable.identity.stableIdentity
                   ) {
                    return true
                }
            }
            return false
        }
    }

    private func publishAfterReply<Value>(
        exemptFromAdmission: @escaping @Sendable () async -> Bool = { false },
        _ operation: @escaping () async throws -> Value,
        reply: @escaping (Result<Value, Error>) -> Void
    ) {
        let operation = PfsUncheckedSendableBox(operation)
        let reply = PfsUncheckedSendableBox(reply)
        Task {
            // Publication admission comes first: while a coherence barrier is
            // closed, an ordinary cache-producing callback must not even begin
            // issuing requests, or it could publish an old result across the
            // repair. Repair-owned callbacks bypass the gate — the gate is
            // closed FOR them. A terminally failed barrier refuses admission
            // outright; the mount's coherence session is over.
            var ticket: PfsMacOSAdmittedCallbackTicket?
            if let coherence = self.coherence {
                if await !exemptFromAdmission() {
                    do {
                        ticket = try await coherence.barrier.admit()
                    } catch {
                        reply.value(.failure(PfsErrorMapper.fsKitError(for: error)))
                        return
                    }
                }
                // The kernel mount-table entry exists only once the volume is
                // being served; the first served callback is the earliest
                // sound moment to bind the deferred actuator to it.
                self.scheduleRepairRootInstall()
            }
            // `withDeferredPublication` has already applied the daemon's
            // retraction verdict to `result`: a crossed operation comes back
            // as a thrown EINTR, never as values. The check is therefore
            // strictly BEFORE the line below, which is the only ordering that
            // helps — the whole point of retraction is that the framework
            // must not install what the daemon has withdrawn, and once
            // `reply.value` has run the install has happened.
            //
            // Reporting EINTR for a mutating callback (removeItem, rename,
            // write) is not a lie: the daemon refuses a retracted
            // operation's unanswered requests without executing them, so
            // nothing this callback failed to observe has landed. See
            // `PfsLocalClient.runPublicationBoundary`.
            let (result, complete) = await PfsMacOSCallbackAdmission.$ticket.withValue(ticket) {
                await core.client.withDeferredPublication {
                    try await operation.value()
                }
            }
            // FSKit's callback is the framework publication boundary. Invoke
            // it first; only after it returns may the daemon let Checkin and a
            // competing peer mutation proceed. A retracted operation still
            // reaches `complete()`: the daemon's gate is released either way,
            // because the frontend having thrown away its values is exactly
            // what the daemon is waiting to hear.
            // Every adapter method maps its own failures, but the publication
            // boundary can fail the operation on its own account — a
            // retraction is not raised by any request — and that failure
            // reaches no adapter catch block. Map here so FSKit always sees a
            // POSIX/FSKit error. The mapping is idempotent for errors that
            // were already mapped.
            reply.value(result.mapError { PfsErrorMapper.fsKitError(for: $0) as Error })
            // The reply above IS the publication boundary the coherence
            // barrier drains to; marking it published before the daemon's
            // completion ack is what lets a deferred source COMPLETE observe
            // it in order.
            if let ticket, let coherence = self.coherence {
                await coherence.barrier.published(ticket)
            }
            await complete()
        }
    }

    @nonobjc
    public func attributes(_ desiredAttributes: FSItem.GetAttributesRequest, of item: FSItem) async throws -> FSItem.Attributes {
        if let portable = item as? PortableFSItem, await core.isLocalRepairItem(portable) {
            return try Self.localRepairAttributes(
                for: portable,
                requested: desiredAttributes.wantedAttributes
            )
        }
        return try await core.client.withPublicationBoundary {
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
        publishAfterReply(exemptFromAdmission: admissionExemption(items: [item]), {
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
        // A setattr carries an item and a value but no name, so it carries no
        // repair token; the scratch item refuses them outright rather than
        // offering a nameless mutation channel.
        if let portable = item as? PortableFSItem, await core.isLocalRepairItem(portable) {
            throw Self.reservedNamespaceError()
        }
        // The armed-truncate table is the declared macOS 26 provenance channel
        // for the one nameless callback a data-invalidation repair needs. A
        // size change is consumed locally exactly when every coordinate the
        // platform can bind matches an armed isolation window: the item's
        // stable identity, the authoritative post-repair size, and the window
        // itself — which exists only between the authenticated hidden rename
        // and the removal of the hidden name, never on a clock. Everything
        // else — any other size, any other item, any request that also
        // carries ownership/mode/flag changes, any moment outside the window —
        // flows through to the daemon unchanged.
        //
        // The exact residual race, accepted by the declared policy: a process
        // that, during the isolation window, addresses the hidden operand and
        // truncates it to exactly the authoritative post-state size has its
        // metadata-only effect coalesced with the repair. The file was about
        // to hold precisely that size and XFS already does, so nothing
        // diverges — but the process observed success for a syscall the
        // authority never saw, which is why macOS 26 is a compatibility
        // policy rather than the exact contract.
        if let repairGate,
           let portable = item as? PortableFSItem,
           newAttributes.isValid(.size),
           !newAttributes.isValid(.mode),
           !newAttributes.isValid(.uid),
           !newAttributes.isValid(.gid),
           !newAttributes.isValid(.flags),
           let consumed = await repairGate.consumeArmedTruncate(
               itemIdentity: portable.identity.stableIdentity,
               size: newAttributes.size
           ) {
            newAttributes.consumedAttributes.insert(.size)
            if newAttributes.isValid(.modifyTime) {
                newAttributes.consumedAttributes.insert(.modifyTime)
            }
            if newAttributes.isValid(.accessTime) {
                newAttributes.consumedAttributes.insert(.accessTime)
            }
            return try Self.armedTruncateAttributes(for: consumed)
        }
        return try await core.client.withPublicationBoundary {
            do {
                let request = try PfsFSKitMapping.setAttributes(
                    from: newAttributes,
                    flagsUnderstood: capabilities.flagsUnderstood
                )
                let attr = try await core.setattr(item: try portableItem(item), attributes: request)
                return try PfsFSKitMapping.attributes(from: attr)
            } catch {
                throw PfsErrorMapper.fsKitError(for: error)
            }
        }
    }

    @nonobjc
    public func lookupItem(named name: FSFileName, inDirectory directory: FSItem) async throws -> (FSItem, FSFileName) {
        if PfsMacOS26RepairAuthenticator.isReserved(name.data) {
            // Reserved names are not part of the user namespace, and every
            // other callback already refuses them locally; forwarding a lookup
            // would leak the control namespace to the daemon and let a probe
            // observe it. The one legal resolution is the repair's own: while
            // a data-invalidation isolation transaction holds a user's file at
            // this exact authenticated hidden name, the actuator's open must
            // be able to address it, so the gate answers with that one item.
            // Everything else is ENOENT, deliberately outside the publication
            // boundary — no pfslocal request is ever emitted.
            if let repairGate,
               let isolated = await repairGate.isolatedRepairItem(operand: name.data) {
                return (isolated, name)
            }
            throw PfsErrorMapper.fsKitError(
                for: PfsLocalClientError.daemon(
                    errno: ENOENT,
                    message: "the reserved repair namespace is not part of the user namespace"
                )
            )
        }
        return try await core.client.withPublicationBoundary {
            do {
                let result = try await core.lookup(in: try portableItem(directory), name: name.data)
                try await recordPublishedBinding(
                    parent: directory,
                    name: result.canonicalName,
                    child: result.item
                )
                return (result.item, PfsFSKitMapping.fileName(from: result.canonicalName))
            } catch {
                throw PfsErrorMapper.fsKitError(for: error)
            }
        }
    }

    @nonobjc
    public func reclaimItem(_ item: FSItem) async throws {
        if let portable = item as? PortableFSItem, await core.isLocalRepairItem(portable) {
            await core.releaseLocalRepairItem(portable)
            return
        }
        return try await core.client.withPublicationBoundary {
            do {
                let portable = try portableItem(item)
                // Reclaim is the kernel dropping its last object reference —
                // the one boundary that retires a live-object obligation, and
                // it retires it whatever the daemon answers, because the index
                // mirrors KERNEL state and the kernel's reference is already
                // gone. The namespace records stay: dropping a coordinate on
                // reclaim would be an unproven inference about the name cache,
                // and an extra exact record is only ever an extra local repair.
                await forgetLiveObject(portable)
                try await core.reclaim(item: portable)
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
        if PfsMacOS26RepairAuthenticator.isReserved(name.data) {
            // Deliberately outside `withPublicationBoundary`: a consumed repair
            // callback is local by construction, so it must not enter the
            // daemon's publication gate — the barrier it belongs to is the one
            // holding that gate closed.
            guard type == .file else { throw Self.reservedNamespaceError() }
            try await consumeRepairCallback(
                .createScratch,
                operand: name.data,
                sourceName: nil,
                directory: directory
            )
            let item = try await core.mintLocalRepairItem()
            return (item, name)
        }
        return try await core.client.withPublicationBoundary {
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
            try await recordPublishedBinding(
                parent: directory,
                name: result.canonicalName,
                child: result.item
            )
            if type == .file {
                // A create hands the kernel a live object as well as a name.
                try await recordLiveObject(result.item)
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
        // No repair plan creates a symlink, so the reserved form is always a
        // user operation here and is always refused.
        guard !PfsMacOS26RepairAuthenticator.isReserved(name.data) else {
            throw Self.reservedNamespaceError()
        }
        return try await core.client.withPublicationBoundary {
          do {
            let targetBytes = PfsFSKitMapping.bytes(from: contents)
            let result = try await core.symlink(
                in: try portableItem(directory),
                name: name.data,
                target: targetBytes
            )
            try await recordPublishedBinding(
                parent: directory,
                name: result.canonicalName,
                child: result.item
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
        // Likewise: a hard link is never a repair step, so a reserved name here
        // could only be a user process trying to occupy the control namespace.
        guard !PfsMacOS26RepairAuthenticator.isReserved(name.data) else {
            throw Self.reservedNamespaceError()
        }
        return try await core.client.withPublicationBoundary {
            do {
                let portable = try portableItem(item)
                let canonicalName = try await core.hardLink(item: portable, in: try portableItem(directory), name: name.data)
                // Every hard-link alias the kernel learns is a distinct
                // cache obligation; the reverse index keeps them all.
                try await recordPublishedBinding(
                    parent: directory,
                    name: canonicalName,
                    child: portable
                )
                return PfsFSKitMapping.fileName(from: canonicalName)
            } catch {
                throw PfsErrorMapper.fsKitError(for: error)
            }
        }
    }

    @nonobjc
    public func removeItem(_ item: FSItem, named name: FSFileName, fromDirectory directory: FSItem) async throws {
        if PfsMacOS26RepairAuthenticator.isReserved(name.data) {
            try await consumeRepairCallback(
                .removeOperand,
                operand: name.data,
                sourceName: nil,
                directory: directory
            )
            if let portable = item as? PortableFSItem {
                await core.releaseLocalRepairItem(portable)
            }
            return
        }
        return try await core.client.withPublicationBoundary {
          do {
            let portable = try portableItem(item)
            let attr = try await core.getattr(item: portable)
            try await core.remove(
                item: portable,
                named: name.data,
                from: try portableItem(directory),
                isDirectory: attr.kind == .directory
            )
            // Unlink retires exactly this coordinate. The live-object record
            // survives: an open-but-unlinked vnode is precisely what the
            // separate index exists to keep addressable.
            try await forgetPublishedBinding(parent: directory, name: name.data)
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
        let sourceIsReserved = PfsMacOS26RepairAuthenticator.isReserved(sourceName.data)
        let destinationIsReserved = PfsMacOS26RepairAuthenticator.isReserved(destinationName.data)
        if sourceIsReserved || destinationIsReserved {
            // Both sides reserved is not any step of any plan.
            guard sourceIsReserved != destinationIsReserved else {
                throw Self.reservedNamespaceError()
            }
            if destinationIsReserved {
                try await consumeRepairCallback(
                    .renameIntoOperand,
                    operand: destinationName.data,
                    sourceName: sourceName.data,
                    directory: destinationDirectory,
                    item: item as? PortableFSItem
                )
                // The kernel just retired the user-visible source binding and
                // learned the hidden one. The hidden name is the repair's own
                // and is never a repair target, but the source coordinate must
                // stop claiming to be published.
                try await forgetPublishedBinding(parent: sourceDirectory, name: sourceName.data)
            } else {
                try await consumeRepairCallback(
                    .rollbackRename,
                    operand: sourceName.data,
                    sourceName: destinationName.data,
                    directory: sourceDirectory,
                    item: item as? PortableFSItem
                )
                if let portable = item as? PortableFSItem {
                    // Rollback restored the user's binding the isolating
                    // rename had retired.
                    try await recordPublishedBinding(
                        parent: destinationDirectory,
                        name: destinationName.data,
                        child: portable
                    )
                }
            }
            return destinationName
        }
        return try await core.client.withPublicationBoundary {
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
            // Both edges of the rename are published coordinates: the source
            // binding is retired, the destination binding (replacing any
            // rename-over victim at that exact coordinate) is published.
            try await forgetPublishedBinding(parent: sourceDirectory, name: sourceName.data)
            try await recordPublishedBinding(
                parent: destinationDirectory,
                name: destinationName.data,
                child: sourceItem
            )
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
            // The verifier must change only when a genuine restart is required.
            // Daemon cookies are name-keyed resumption points, so a directory
            // that gains or loses entries between pages is still resumable
            // exactly where the last page stopped. Reporting the directory's
            // current version on every page would instead tell FSKit the
            // directory changed underneath a live walk — the invitation to
            // abandon or restart it, which is how a several-hundred-entry
            // listing comes back silently short under concurrent mutation.
            // A continuation therefore echoes the verifier FSKit handed us and
            // only a fresh walk (cookie 0, or an initial verifier) mints one.
            let currentVerifier: FSDirectoryVerifier
            if PfsEnumerationCookies.isFreshStart(cookie: cookie.rawValue, verifier: verifier.rawValue) {
                currentVerifier = try PfsFSKitMapping.directoryVerifier(
                    from: result.verifier
                )
            } else {
                currentVerifier = verifier
            }

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
                    // A packed directory entry is a published binding exactly
                    // like a lookup hit; the kernel may cache it. Recording
                    // one the packer then declines is harmless in the safe
                    // direction — an extra exact record is at worst an extra
                    // local repair — while the reverse would break the
                    // absent-means-uncached claim.
                    try await recordPublishedBinding(
                        parent: directory,
                        name: entry.name,
                        child: entry.item
                    )
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
        if let portable = item as? PortableFSItem, await core.isLocalRepairItem(portable) {
            return
        }
        if let repairGate,
           let portable = item as? PortableFSItem,
           await repairGate.isArmedTruncateItem(itemIdentity: portable.identity.stableIdentity) {
            // The actuator's own open of the isolated operand. The repair must
            // not mint daemon descriptor state for a file whose name it is
            // about to remove — the barrier holding the daemon's mutation is
            // the wrong moment to grow protocol state — so the open succeeds
            // locally. The kernel still holds a live object either way.
            try await recordLiveObject(portable)
            return
        }
        return try await core.client.withPublicationBoundary {
            do {
                let portable = try portableItem(item)
                try await core.open(item: portable, mode: PfsFSKitMapping.openMode(from: modes))
                try await recordLiveObject(portable)
            } catch {
                throw PfsErrorMapper.fsKitError(for: error)
            }
        }
    }

    @nonobjc
    public func closeItem(_ item: FSItem, modes: FSVolume.OpenModes) async throws {
        if let portable = item as? PortableFSItem, await core.isLocalRepairItem(portable) {
            return
        }
        if let repairGate,
           let portable = item as? PortableFSItem,
           await repairGate.isArmedTruncateItem(itemIdentity: portable.identity.stableIdentity) {
            // Mirror of the local open above. Any daemon descriptors a user
            // opened before the isolation window remain owned by `VolumeCore`
            // and are retired at reclaim; a retaining close during the short
            // window is deferred, never lost. The live-object record persists
            // until reclaim regardless of close.
            return
        }
        return try await core.client.withPublicationBoundary {
            do {
                try await core.close(item: try portableItem(item), retainingModes: PfsFSKitMapping.openMode(from: modes))
            } catch {
                throw PfsErrorMapper.fsKitError(for: error)
            }
        }
    }

    @nonobjc
    public func read(from item: FSItem, at offset: off_t, length: Int, into buffer: FSMutableFileDataBuffer) async throws -> Int {
        if let portable = item as? PortableFSItem, await core.isLocalRepairItem(portable) {
            throw Self.reservedNamespaceError()
        }
        return try await core.client.withPublicationBoundary {
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
        if let portable = item as? PortableFSItem, await core.isLocalRepairItem(portable) {
            throw Self.reservedNamespaceError()
        }
        return try await core.client.withPublicationBoundary {
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
        publishAfterReply(exemptFromAdmission: admissionExemption(items: [item]), {
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
        publishAfterReply(exemptFromAdmission: admissionExemption(reservedNames: [name.data]), {
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
        publishAfterReply(exemptFromAdmission: admissionExemption(items: [item]), {
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
        publishAfterReply(exemptFromAdmission: admissionExemption(reservedNames: [name.data]), {
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
        publishAfterReply(exemptFromAdmission: admissionExemption(reservedNames: [name.data]), {
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
        publishAfterReply(exemptFromAdmission: admissionExemption(reservedNames: [name.data]), {
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
        publishAfterReply(exemptFromAdmission: admissionExemption(reservedNames: [name.data], items: [item]), {
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
        publishAfterReply(
            exemptFromAdmission: admissionExemption(
                reservedNames: [sourceName.data, destinationName.data]
            ),
            {
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
        publishAfterReply(exemptFromAdmission: admissionExemption(items: [item]), {
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
        publishAfterReply(exemptFromAdmission: admissionExemption(items: [item]), {
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
        publishAfterReply(exemptFromAdmission: admissionExemption(items: [item]), {
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
        publishAfterReply(exemptFromAdmission: admissionExemption(items: [item]), {
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
        coherence?.shutdown()
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

    // MARK: - Strict-v3 index population

    /// Attempts to bind the deferred repair actuator to the live kernel mount,
    /// once. Failure stays loud at repair time: an uninstalled actuator fails
    /// every repair closed and the barrier reports the cursor blocked.
    private func scheduleRepairRootInstall() {
        guard let coherence else { return }
        let typeName = fileSystemTypeName
        let attachRef = attachRef
        coherence.scheduleActuatorInstall {
            try PfsMacOSMountRootLocator.openMountRoot(
                fileSystemTypeName: typeName,
                attachRef: attachRef,
                // The root is authority item 1, projected through the platform
                // identifier offset like every other inode this mount reports.
                expectedRootFileID: try PfsFSKitMapping.itemIdentifier(from: 1).rawValue
            )
        }
    }

    /// The stable identity a strict mount must have for every item a repair
    /// could ever address. A strict daemon always supplies it; an item without
    /// one cannot be indexed, so publishing it would break the "absent from
    /// the index means provably uncached" claim. Fail the callback closed
    /// instead of publishing an untracked binding.
    private func strictStableIdentity(of item: PortableFSItem) throws -> PfsMacOSStableIdentity {
        do {
            return try PfsMacOSStableIdentity(item.identity.stableIdentity)
        } catch {
            throw PfsLocalClientError.daemon(
                errno: EIO,
                message: "strict-v3 item carries no stable identity"
            )
        }
    }

    /// Records one published namespace binding. Every callback that returns a
    /// (parent, name) -> item binding to the kernel must pass through here
    /// before its reply publishes, or "unknown" stops meaning "uncached".
    /// The capacity bound refuses NEW bindings rather than dropping old ones:
    /// macOS 26 has no synchronous revocation to make an eviction sound, and
    /// a silently LRU-dropped record is a kernel cache entry this mount can no
    /// longer repair.
    private func recordPublishedBinding(
        parent: FSItem,
        name: Data,
        child: PortableFSItem
    ) async throws {
        guard let coherence else { return }
        let parentIdentity = try strictStableIdentity(of: try portableItem(parent))
        let childIdentity = try strictStableIdentity(of: child)
        let vfsFileID = try PfsFSKitMapping.itemIdentifier(from: child.identity.itemID).rawValue
        if await coherence.namespaceIndex.binding(
            parentIdentity: parentIdentity,
            name: name
        ) == nil, await coherence.namespaceIndex.count() >= coherence.namespaceCapacity {
            throw PfsLocalClientError.daemon(
                errno: EIO,
                message: "strict-v3 namespace index is at capacity"
            )
        }
        await coherence.namespaceIndex.record(
            identity: childIdentity,
            entry: .init(parentIdentity: parentIdentity, name: name, vfsFileID: vfsFileID)
        )
    }

    private func forgetPublishedBinding(parent: FSItem, name: Data) async throws {
        guard let coherence else { return }
        let parentIdentity = try strictStableIdentity(of: try portableItem(parent))
        await coherence.namespaceIndex.forget(parentIdentity: parentIdentity, name: name)
    }

    /// Records one kernel object with live open state. Unlink retires the
    /// namespace coordinate but never this record; only reclaim does.
    private func recordLiveObject(_ item: PortableFSItem) async throws {
        guard let coherence else { return }
        _ = try strictStableIdentity(of: item)
        let vfsFileID = try PfsFSKitMapping.itemIdentifier(from: item.identity.itemID).rawValue
        if await coherence.liveObjects.count() >= coherence.liveObjectCapacity {
            throw PfsLocalClientError.daemon(
                errno: EIO,
                message: "strict-v3 live-object index is at capacity"
            )
        }
        do {
            try await coherence.liveObjects.record(item: item, vfsFileID: vfsFileID)
        } catch {
            throw PfsLocalClientError.daemon(
                errno: EIO,
                message: "strict-v3 live-object record failed"
            )
        }
    }

    private func forgetLiveObject(_ item: PortableFSItem) async {
        guard let coherence else { return }
        await coherence.liveObjects.forget(item: item)
    }

    /// The single decision point for every reserved name this adapter is
    /// handed. Without a gate, or with a gate that does not hold a live
    /// authorization for exactly this callback on exactly this operand, the
    /// operation is refused and never becomes a pfslocal request.
    private func consumeRepairCallback(
        _ callback: PfsMacOS26RepairCallback,
        operand: Data,
        sourceName: Data?,
        directory: FSItem,
        item: PortableFSItem? = nil
    ) async throws {
        guard let repairGate else { throw Self.reservedNamespaceError() }
        do {
            try await repairGate.consume(
                callback: callback,
                operand: operand,
                sourceName: sourceName,
                // The plan's HMAC binds a parent identity; handing the gate
                // the directory THIS callback actually names is what stops a
                // same-basename callback in a different directory from being
                // swallowed as repair.
                parentIdentity: (directory as? PortableFSItem)?.identity.stableIdentity,
                item: item
            )
        } catch {
            logger.error(
                "refused reserved-namespace callback: \(String(describing: error), privacy: .public)"
            )
            throw Self.reservedNamespaceError()
        }
    }

    static func reservedNamespaceError() -> Error {
        PfsErrorMapper.fsKitError(
            for: PfsLocalClientError.daemon(
                errno: EPERM,
                message: "the reserved repair namespace is not part of the user namespace"
            )
        )
    }

    /// The reply for a locally consumed armed truncate. The values are the
    /// repair's own authoritative coordinates — the post-state size and the
    /// inode number this mount projects for the isolated item — not daemon
    /// state, because the whole point of consuming locally is that no daemon
    /// request exists to answer with.
    private static func armedTruncateAttributes(
        for consumed: PfsMacOS26ArmedTruncateConsumption
    ) throws -> FSItem.Attributes {
        guard let identifier = FSItem.Identifier(rawValue: consumed.expectedVFSFileID) else {
            throw PfsLocalClientError.daemon(
                errno: EOVERFLOW,
                message: "armed truncate identifier cannot be represented by FSKit"
            )
        }
        let attributes = FSItem.Attributes()
        attributes.type = .file
        attributes.mode = 0o600
        attributes.linkCount = 1
        attributes.size = consumed.size
        attributes.allocSize = consumed.size
        attributes.fileID = identifier
        return attributes
    }

    /// The scratch item exists only so the create callback can return
    /// something. It is a zero-length, single-link regular file owned by the
    /// mount, and it never outlives its transaction.
    private static func localRepairAttributes(
        for item: PortableFSItem,
        requested: FSItem.Attribute?
    ) throws -> FSItem.Attributes {
        guard let identifier = FSItem.Identifier(rawValue: item.identity.itemID &+ 1) else {
            throw PfsLocalClientError.daemon(
                errno: EOVERFLOW,
                message: "local repair identifier cannot be represented by FSKit"
            )
        }
        let attributes = FSItem.Attributes()
        func includes(_ attribute: FSItem.Attribute) -> Bool {
            requested.map { $0.contains(attribute) } ?? true
        }
        if includes(.type) { attributes.type = .file }
        if includes(.mode) { attributes.mode = 0o600 }
        if includes(.linkCount) { attributes.linkCount = 1 }
        if includes(.size) { attributes.size = 0 }
        if includes(.allocSize) { attributes.allocSize = 0 }
        if includes(.fileID) { attributes.fileID = identifier }
        return attributes
    }
}
