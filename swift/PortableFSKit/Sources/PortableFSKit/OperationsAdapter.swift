import Foundation
import FSKit
import CryptoKit
import OSLog
import os
@preconcurrency import Darwin
@preconcurrency import Dispatch

private final class PfsUncheckedSendableBox<Value>: @unchecked Sendable {
    let value: Value

    init(_ value: Value) {
        self.value = value
    }
}

private extension Result {
    var pfsIsSuccess: Bool {
        if case .success = self { return true }
        return false
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

    /// A fresh walk is identified by `FSDirectoryVerifierInitial`, not by its
    /// cookie alone. FSKit can restart at cookie zero while retaining the
    /// verifier from an earlier walk. Returning a newly minted verifier in
    /// that case makes the framework reject the packed page with `EAGAIN`, and
    /// it can repeat that same zero-cookie/old-verifier request forever. The
    /// synthetic "." and ".." positions still carry the initial verifier, so
    /// they remain part of the one walk that must mint a verifier.
    @available(macOS 26.0, *)
    static func isFreshStart(cookie: UInt64, verifier: UInt64) -> Bool {
        verifier == initialVerifier
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


/// The FSKit file system: one exclusive-writer volume per attach, backed by
/// `VolumeCore`. macOS 26 and 27 use this same composition.
@available(macOS 26.0, *)
public final class PortableFSFileSystem: FSUnaryFileSystem, FSUnaryFileSystemOperations, @unchecked Sendable {
    public typealias VolumeFactory = @Sendable (
        _ socketPath: String,
        _ attachRef: String,
        _ moduleIdentity: PortableFSModuleIdentity
    ) async throws -> PortableFSVolume

    /// The product composition: resolve the attach on one pfslocal session
    /// and install the volume around it.
    public static let productVolumeFactory: VolumeFactory = { socketPath, attachRef, moduleIdentity in
        let core = try await VolumeCore.connect(
            socketPath: socketPath,
            attachRef: attachRef
        )
        return try await PortableFSVolume.make(
            core: core,
            attachRef: attachRef,
            moduleIdentity: moduleIdentity
        )
    }

    private let logger = Logger(subsystem: "dev.portablefs.fskit", category: "PortableFSFileSystem")
    private let volumeLock = NSLock()
    private var volumes: [String: PortableFSVolume] = [:]
    private let moduleIdentity: PortableFSModuleIdentity
    private let resolverFactory: @Sendable () -> PfsSocketPathResolver
    private let volumeFactory: VolumeFactory

    /// The extension entry point. Identity comes from the running extension's
    /// signed metadata; there is no OSS-identity assumption.
    public override convenience init() {
        self.init(moduleIdentity: Self.mainBundleIdentity())
    }

    /// Composition seam for an embedding product or a unit test. The volume
    /// factory defaults to the product composition.
    public init(
        moduleIdentity: PortableFSModuleIdentity,
        resolverFactory: @escaping @Sendable () -> PfsSocketPathResolver = {
            PfsSocketPathResolver(bundle: .main)
        },
        volumeFactory: @escaping VolumeFactory = PortableFSFileSystem.productVolumeFactory
    ) {
        self.moduleIdentity = moduleIdentity
        self.resolverFactory = resolverFactory
        self.volumeFactory = volumeFactory
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
            let volumeFactory = volumeFactory
            Task(priority: .userInitiated) {
                do {
                    let socketPath = try resolverFactory().resolve()
                    logger.info("loadResource resolving via socket \(socketPath, privacy: .public) for ref \(attachRef, privacy: .public)")
                    let volume = try await volumeFactory(
                        socketPath,
                        attachRef,
                        moduleIdentity
                    )
                    let published = volume.core.client.publicationGate.decide { terminal in
                        if let terminal {
                            reply.call(nil, PfsErrorMapper.fsKitError(for: terminal))
                        } else {
                            storeVolume(volume, attachRef: attachRef)
                            containerStatus = .ready
                            reply.call(volume, nil)
                        }
                    }
                    if !published { await volume.shutdown() }
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
            if let volume = registeredVolume(attachRef: attachRef) {
                Task(priority: .userInitiated) {
                    // Acknowledge local cleanup only, including after terminal
                    // failure. Keep the registration until that cleanup completes
                    // so overlapping unloads join it rather than replying early.
                    await volume.shutdown()
                    removeVolume(volume, attachRef: attachRef)
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

    private func registeredVolume(attachRef: String) -> PortableFSVolume? {
        volumeLock.lock()
        defer { volumeLock.unlock() }
        return volumes[attachRef]
    }

    private func removeVolume(_ volume: PortableFSVolume, attachRef: String) {
        volumeLock.lock()
        defer { volumeLock.unlock() }
        if volumes[attachRef] === volume { volumes.removeValue(forKey: attachRef) }
    }

    func testingRegisteredVolume(attachRef: String) -> PortableFSVolume? {
        registeredVolume(attachRef: attachRef)
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

/// One exclusive-writer FSKit volume.
///
/// Serving volume callbacks pass through `publishAfterReply`: it takes a
/// slot in the bounded callback window, runs its pfslocal requests inside one
/// publication unit, replies to FSKit through the window's serialized
/// publication decision, and only then sends the daemon its publication
/// verdict. The volume holds exactly one
/// pfslocal session, bound to its attach at Resolve and to its attach-state
/// events at construction. The client revokes publication at each terminal
/// source, before an event consumer can drain the window.
@available(macOS 26.0, *)
public class PortableFSVolume: FSVolume, FSVolume.Operations, FSVolume.ReadWriteOperations, FSVolume.XattrOperations, FSVolume.PathConfOperations, @unchecked Sendable {
    public let core: VolumeCore
    public let capabilities: PfsCapabilities
    let window: PfsCallbackWindow
    /// The session connection's request-trace label; see PfsTraceRecord.
    let traceConnection: String
    fileprivate let logger = Logger(subsystem: "dev.portablefs.fskit", category: "PortableFSVolume")
    private let fileSystemTypeName: String
    private let statLock = NSLock()
    private var cachedStatistics: FSStatFSResult
    private var eventMonitor: Task<Void, Never>?
    let kernelCache: PfsKernelCache?
    private let shutdownLock = NSLock()
    private var shutdownTask: Task<Void, Never>?
    private var beforeShutdownCleanup: (@Sendable () async -> Void)?
    private var onShutdownWait: (@Sendable (Task<Void, Never>) async -> Void)?
    private var beforePublicationFailureCleanup: (@Sendable () async -> Void)?

    /// Installs a volume around a resolved core. The connection's event
    /// binding is established before the volume can be returned to FSKit:
    /// it is the daemon's witness that this frontend observes its attach, and
    /// the volume must never serve without the terminal path it provides.
    /// Any failure here ends the session before FSKit sees the volume.
    public static func make(
        core: VolumeCore,
        attachRef: String,
        moduleIdentity: PortableFSModuleIdentity = PortableFSIdentity.moduleIdentity,
        windowCapacity: Int = PfsCallbackWindow.defaultCapacity
    ) async throws -> PortableFSVolume {
        let adapter: PortableFSVolume.Type
        if #available(macOS 27, *) { adapter = PortableFSVolumeV3.self }
        else { adapter = PortableFSVolumeV2.self }
        return try await make(core: core, attachRef: attachRef, adapter: adapter,
                              moduleIdentity: moduleIdentity, windowCapacity: windowCapacity)
    }

    // Internal construction seam exercises both lifecycle adapters on one host.
    // Production selects exactly once above; there is no runtime fallback.
    static func make(
        core: VolumeCore,
        attachRef: String,
        adapter: PortableFSVolume.Type,
        moduleIdentity: PortableFSModuleIdentity = PortableFSIdentity.moduleIdentity,
        windowCapacity: Int = PfsCallbackWindow.defaultCapacity,
        cacheClock: @escaping @Sendable () throws -> UInt64 = PfsKernelCache.continuousNanos
    ) async throws -> PortableFSVolume {
        guard let resolved = await core.resolvedVolume else {
            await core.shutdown()
            throw PfsLocalClientError.unresolved
        }
        do {
            let events = try await core.subscribeEvents()
            let client = core.client
            let window = PfsCallbackWindow(
                capacity: windowCapacity, publicationGate: client.publicationGate
            )
            let statReply: PfsStatfsReply
            do {
                statReply = try await core.statfs()
            } catch {
                await window.fail(error)
                throw error
            }
            try client.publicationGate.check()
            let cache: PfsKernelCache?
            if #available(macOS 27, *), adapter == PortableFSVolumeV3.self {
                cache = PfsKernelCache(gate: client.publicationGate, clock: cacheClock) { error in
                    await client.close(error: error)
                }
            } else {
                cache = nil
            }
            if let cache { await core.installKernelCache(cache) }
            let volume = adapter.init(
                core: core,
                attachRef: attachRef,
                resolved: resolved,
                statReply: statReply,
                moduleIdentity: moduleIdentity,
                window: window,
                traceConnection: await core.traceConnection,
                kernelCache: cache
            )
            if #available(macOS 27, *), let volume = volume as? PortableFSVolumeV3, let cache {
                cache.install { [weak volume] item, transition in
                    guard let volume else { return POSIXError(.ENXIO) }
                    let mode: FSVolume.DataCacheMode
                    switch transition.mode {
                    case .none: mode = .none
                    case .readWithCache: mode = .readWithCache
                    case .readWriteWithCache: mode = .readWriteWithCache
                    }
                    let coherency: FSVolume.KernelCacheCoherencyType
                    switch transition.coherency {
                    case .noCache: coherency = .noCache
                    case .readCache: coherency = .readCache
                    case .writeBack: coherency = .writeBack
                    }
                    let action: FSVolume.KernelCacheCoherencyAction
                    switch transition.action {
                    case .push: action = .push
                    case .pushInvalidate: action = .pushInvalidate
                    case .revoke: action = .revoke
                    }
                    return volume.setCacheState(for: item, cacheMode: mode, coherencyType: coherency, action: action)
                }
            }
            volume.eventMonitor = Task.detached(priority: .userInitiated) {
                await PfsAttachEventMonitor.run(events: events, client: client, window: window, cache: cache)
            }
            return volume
        } catch {
            await core.shutdown()
            throw error
        }
    }

    required init(
        core: VolumeCore,
        attachRef: String,
        resolved: PfsResolvedVolume,
        statReply: PfsStatfsReply,
        moduleIdentity: PortableFSModuleIdentity,
        window: PfsCallbackWindow,
        traceConnection: String,
        kernelCache: PfsKernelCache?
    ) {
        self.core = core
        self.capabilities = resolved.capabilities
        self.window = window
        self.traceConnection = traceConnection
        self.kernelCache = kernelCache
        self.fileSystemTypeName = moduleIdentity.fileSystemTypeName
        self.cachedStatistics = PfsFSKitMapping.statfs(
            from: statReply,
            capabilities: resolved.capabilities,
            fileSystemTypeName: moduleIdentity.fileSystemTypeName
        )
        // The FSKit volume identity is scoped to the ATTACH, not the backend
        // volume, exactly like the container identity above. A mount is one
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
        // xfsstore applies the same 64 KiB ceiling to one user-xattr value and
        // to a list result. FSKit has one maximum-size property, so advertise
        // the exact production substrate bound.
        64 * 1024
    }

    public var maximumFileSize: UInt64 {
        capabilities.maxFileSize == 0 ? UInt64.max : capabilities.maxFileSize
    }

    public var supportedVolumeCapabilities: FSVolume.SupportedCapabilities {
        PfsFSKitMapping.supportedCapabilities()
    }

    public var volumeStatistics: FSStatFSResult {
        statLock.lock()
        let statistics = cachedStatistics
        statLock.unlock()
        return statistics
    }

    @nonobjc
    public func activate(options: FSTaskOptions) async throws -> FSItem {
        let root: PfsUncheckedSendableBox<FSItem> = try await withCheckedThrowingContinuation { continuation in
            activate(options: options) { item, error in
                if let error { continuation.resume(throwing: error) }
                else if let item { continuation.resume(returning: PfsUncheckedSendableBox(item)) }
                else { continuation.resume(throwing: PfsLocalClientError.connectionClosed) }
            }
        }
        return root.value
    }

    public func activate(
        options: FSTaskOptions,
        replyHandler reply: @escaping (FSItem?, Error?) -> Void
    ) {
        publishAfterReply({ try await self.core.rootItem() }, reply: { result in
            switch result {
            case let .success(root): reply(root, nil)
            case let .failure(error): reply(nil, error)
            }
        })
    }

    public func deactivate(options: FSDeactivateOptions = []) async throws {
        // This native async bridge acknowledges local cleanup, even after a
        // terminal failure. It makes no serving or durability claim; neither
        // ordinary nor force deactivation initiates a kernel unmount here.
        await shutdown()
    }

    @nonobjc
    public func mount(options: FSTaskOptions) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            mount(options: options) { error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume() }
            }
        }
    }

    public func mount(options: FSTaskOptions, replyHandler reply: @escaping (Error?) -> Void) {
        publishAfterReply({}, reply: { result in
            switch result {
            case .success: reply(nil)
            case let .failure(error): reply(error)
            }
        })
    }

    public func unmount() async {
        // The native completion has no error argument. It acknowledges local
        // cleanup only, not durability, kernel absence or daemon reconciliation.
        // Keep serving durable WRITE callbacks while the healthy kernel drains.
        // Failure fences the session; this errorless completion cannot certify
        // durability or turn failed dirty writeback into successful withdrawal.
        do { try await kernelCache?.drainForUnmount() }
        catch { logger.error("unmount drain failed: \(String(describing: error), privacy: .public)") }
        await shutdown()
    }

    @nonobjc
    public func synchronize(flags: FSSyncFlags) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            synchronize(flags: flags) { error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume() }
            }
        }
    }

    public func synchronize(flags: FSSyncFlags, replyHandler reply: @escaping (Error?) -> Void) {
        publishAfterReply({
            // Explicit authority barrier over its captured applied cut.
            // Successful mutation replies are already durable. The framework
            // must drain prior work: this cannot cover undelivered kernel
            // pages or mutations outside that cut. Native fsync/F_FULLFSYNC
            // waiting and error propagation remain unproven.
            try await self.core.syncVolume()
            let stat = try await self.core.statfs()
            self.setCachedStatistics(PfsFSKitMapping.statfs(
                from: stat,
                capabilities: self.capabilities,
                fileSystemTypeName: self.fileSystemTypeName
            ))
        }, reply: { result in
            switch result {
            case .success: reply(nil)
            case let .failure(error): reply(error)
            }
        })
    }

    /// Revokes later serving success before suspending, then joins the volume's
    /// one local cleanup. Teardown acknowledgements await this same completion,
    /// including overlapping callers and callers whose tasks were cancelled.
    public func shutdown() async {
        core.client.publicationGate.revoke(PfsLocalClientError.shutdown)
        let (cleanup, onWait) = localShutdown()
        await onWait?(cleanup)
        await cleanup.value
    }

    private func localShutdown() -> (Task<Void, Never>, (@Sendable (Task<Void, Never>) async -> Void)?) {
        shutdownLock.lock()
        defer { shutdownLock.unlock() }
        if let shutdownTask { return (shutdownTask, onShutdownWait) }
        let beforeCleanup = beforeShutdownCleanup
        beforeShutdownCleanup = nil
        // Unstructured ownership cleanup does not inherit caller cancellation.
        // Capture the owned resources rather than retaining the volume in its task.
        let cleanup = Task { [window, eventMonitor, core] in
            await window.sessionEnded(PfsLocalClientError.shutdown)
            eventMonitor?.cancel()
            await beforeCleanup?()
            await core.shutdown()
        }
        shutdownTask = cleanup
        return (cleanup, onShutdownWait)
    }

    /// Continuation seams outside the publication gate for teardown ordering tests.
    /// Expose the exact task selected under shutdownLock so tests can record its
    /// identity synchronously before announcing that a caller is joining cleanup.
    func testingShutdown(
        beforeCleanup: @escaping @Sendable () async -> Void,
        onWait: @escaping @Sendable (Task<Void, Never>) async -> Void = { _ in }
    ) {
        shutdownLock.lock()
        defer { shutdownLock.unlock() }
        precondition(shutdownTask == nil)
        beforeShutdownCleanup = beforeCleanup
        onShutdownWait = onWait
    }

    /// Runs one FSKit callback. `preflight` holds refusals that depend only
    /// on the request and local item state; it runs before window admission
    /// and before any publication unit exists, so its verdict can never
    /// enter ordered publication. The operation then runs under a window slot
    /// inside one publication unit. FSKit's reply is the publication
    /// boundary, and the window decides it: the reply carries the callback's
    /// own outcome only if the session was still live at that decision,
    /// otherwise the terminal error. The publication verdict follows the
    /// reply and is published only for a successful outcome that reached
    /// FSKit; a revoked callback settles its operation and resources as
    /// unpublished.
    func publishAfterReply<Value>(
        callbackKind: StaticString = #function,
        traceFields: [PfsTraceRecord.Field] = [],
        resultTraceFields: @escaping (Value) -> [PfsTraceRecord.Field] = { _ in [] },
        preflight: @escaping @Sendable () async throws -> Void = {},
        _ operation: @escaping () async throws -> Value,
        reply: @escaping (Result<Value, Error>) -> Void,
        settled: @escaping @Sendable () -> Void = {}
    ) {
        publishAfterReply(callbackKind: callbackKind, traceFields: traceFields,
                          resultTraceFields: resultTraceFields, preflight: preflight, operation,
                          finalize: { $0 }, reply: reply, settled: settled)
    }

    /// Final cache admission is part of the gate's outcome, before either
    /// the framework reply or the semantic publication verdict is selected.
    func publishAfterReply<Value, ReplyValue>(
        callbackKind: StaticString = #function,
        traceFields: [PfsTraceRecord.Field] = [],
        resultTraceFields: @escaping (Value) -> [PfsTraceRecord.Field] = { _ in [] },
        preflight: @escaping @Sendable () async throws -> Void = {},
        _ operation: @escaping () async throws -> Value,
        finalize: @escaping (Value) throws -> ReplyValue,
        reply: @escaping (Result<ReplyValue, Error>) -> Void,
        settled: @escaping @Sendable () -> Void = {}
    ) {
        let trace = PfsCallbackTrace(
            kind: callbackKind,
            connection: traceConnection,
            trace: core.client.trace,
            fields: traceFields
        )
        let operation = PfsUncheckedSendableBox(operation)
        let resultTraceFields = PfsUncheckedSendableBox(resultTraceFields)
        let finalize = PfsUncheckedSendableBox(finalize)
        let reply = PfsUncheckedSendableBox(reply)
        Task(priority: .userInitiated) {
            defer { settled() }
            trace.emit("TaskStarted")
            do {
                try await preflight()
            } catch {
                let failure = PfsErrorMapper.fsKitError(for: error)
                reply.value(.failure(failure))
                trace.finish(outcome: "preflight-refused", errno: (failure as NSError).code)
                return
            }

            let ticket: PfsCallbackTicket
            do {
                ticket = try await self.window.admit()
            } catch {
                reply.value(.failure(PfsErrorMapper.fsKitError(for: error)))
                trace.finish(outcome: "admission-refused")
                return
            }
            trace.emit("Admitted")

            let (result, complete) = await self.core.client.withDeferredPublication(
                callbackLabel: trace.label
            ) {
                try await operation.value()
            }
            if case let .failure(error) = result {
                let nsError = error as NSError
                self.logger.error(
                    "callback operation failed before framework reply; kind=\(trace.kind, privacy: .public) domain=\(nsError.domain, privacy: .public) code=\(nsError.code)"
                )
            }
            let outcome = PfsUncheckedSendableBox(result)
            let published = await self.window.settle(ticket, decision: {
                try finalize.value(outcome.value.get())
            }, terminalCause: { error in
                guard let cause = (error as? PfsKernelCache.AdmissionFailure)?.cause else { return nil }
                Task {
                    let hook = self.shutdownLock.withLock { self.beforePublicationFailureCleanup }
                    await hook?()
                    await self.core.client.close(error: cause)
                }
                return cause
            }, reply: { result in
                reply.value(result.mapError { PfsErrorMapper.fsKitError(for: $0) as Error })
            })
            trace.emit("FrameworkReplyReturned")

            await complete(published)
            var fields: [PfsTraceRecord.Field] = []
            if published, self.core.client.trace.isActive, case let .success(value) = result {
                fields = resultTraceFields.value(value)
            }
            trace.finish(outcome: self.window.publicationGate.terminalError != nil && !published
                ? "revoked"
                : (published ? "success" : "failure"), resultFields: fields)
        }
    }

    func testingBeforePublicationFailureCleanup(_ hook: @escaping @Sendable () async -> Void) {
        shutdownLock.withLock { beforePublicationFailureCleanup = hook }
    }

    /// Deterministic seam for the window suite: the same callback path as
    /// every production entry point, with an injected operation.
    func testOnlyPublishAfterReply<Value>(
        preflight: @escaping @Sendable () async throws -> Void = {},
        operation: @escaping () async throws -> Value,
        reply: @escaping (Result<Value, Error>) -> Void,
        settled: @escaping @Sendable () -> Void = {}
    ) {
        publishAfterReply(
            callbackKind: "testOnlyCallback",
            preflight: preflight,
            operation,
            reply: reply,
            settled: settled
        )
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

    private func metadataTraceFields(
        item: FSItem? = nil,
        parent: FSItem? = nil,
        name: FSFileName? = nil,
        wanted: FSItem.Attribute? = nil
    ) -> [PfsTraceRecord.Field] {
        guard core.client.trace.isActive else { return [] }
        var fields = [PfsTraceRecord.Field(key: "pid", value: "unavailable")]
        if let item { fields += PfsMetadataTrace.identity(item as? PortableFSItem, role: "item") }
        if let parent { fields += PfsMetadataTrace.identity(parent as? PortableFSItem, role: "parent") }
        if let name { fields += PfsMetadataTrace.name(name.data) }
        if let wanted { fields.append(.init(key: "wanted", value: String(wanted.rawValue))) }
        return fields
    }

    public func getAttributes(
        _ desiredAttributes: FSItem.GetAttributesRequest,
        of item: FSItem,
        replyHandler reply: @escaping (FSItem.Attributes?, Error?) -> Void
    ) {
        publishAfterReply(traceFields: metadataTraceFields(item: item, wanted: desiredAttributes.wantedAttributes), {
            try await self.attributes(desiredAttributes, of: item)
        }, reply: { result in
            switch result {
            case let .success(attributes): reply(attributes, nil)
            case let .failure(error): reply(nil, error)
            }
        })
    }

    @nonobjc
    public func setAttributes(_ newAttributes: FSItem.SetAttributesRequest, on item: FSItem) async throws -> FSItem.Attributes {
        try await core.client.withPublicationBoundary {
            do {
                let request = PfsFSKitMapping.setAttributes(from: newAttributes)
                let attr = try await core.setattr(item: try portableItem(item), attributes: request)
                return try PfsFSKitMapping.attributes(from: attr)
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

    public func lookupItem(
        named name: FSFileName,
        inDirectory directory: FSItem,
        replyHandler reply: @escaping (FSItem?, FSFileName?, Error?) -> Void
    ) {
        publishAfterReply(traceFields: metadataTraceFields(parent: directory, name: name),
                          resultTraceFields: { PfsMetadataTrace.identity($0.0 as? PortableFSItem, role: "returned") }, {
            try await self.lookupItem(named: name, inDirectory: directory)
        }, reply: { result in
            switch result {
            case let .success((item, canonicalName)): reply(item, canonicalName, nil)
            case let .failure(error): reply(nil, nil, error)
            }
        })
    }

    @nonobjc
    public func reclaimItem(_ item: FSItem) async throws {
        try await core.client.withPublicationBoundary {
            do {
                try await core.reclaim(item: try portableItem(item), nativeKernelCheck: kernelCache != nil)
            } catch {
                throw PfsErrorMapper.fsKitError(for: error)
            }
        }
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

    /// CREATE returns the item together with its real read/write creation
    /// description, which VolumeCore installs as the item's open state; an
    /// immediately following compatible open reuses it without another OPEN.
    @nonobjc
    public func createItem(
        named name: FSFileName,
        type: FSItem.ItemType,
        inDirectory directory: FSItem,
        attributes newAttributes: FSItem.SetAttributesRequest
    ) async throws -> (FSItem, FSFileName) {
        try await core.client.withPublicationBoundary {
            do {
                let mode = newAttributes.isValid(.mode) ? newAttributes.mode : (type == .directory ? 0o755 : 0o644)
                let parent = try portableItem(directory)
                let result: PfsCreateResult
                switch type {
                case .file:
                    result = try await core.createFile(in: parent, name: name.data, mode: mode)
                case .directory:
                    result = try await core.mkdir(in: parent, name: name.data, mode: mode)
                default:
                    throw PfsLocalClientError.daemon(errno: ENOTSUP, message: "unsupported create item type")
                }
                return (result.item, PfsFSKitMapping.fileName(from: result.canonicalName))
            } catch {
                throw PfsErrorMapper.fsKitError(for: error)
            }
        }
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

    @nonobjc
    public func createSymbolicLink(
        named name: FSFileName,
        inDirectory directory: FSItem,
        attributes newAttributes: FSItem.SetAttributesRequest,
        linkContents contents: FSFileName
    ) async throws -> (FSItem, FSFileName) {
        try await core.client.withPublicationBoundary {
            do {
                let result = try await core.symlink(
                    in: try portableItem(directory),
                    name: name.data,
                    target: PfsFSKitMapping.bytes(from: contents)
                )
                return (result.item, PfsFSKitMapping.fileName(from: result.canonicalName))
            } catch {
                logger.error("symlink create failed: \(String(describing: error), privacy: .private)")
                throw PfsErrorMapper.fsKitError(for: error)
            }
        }
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

    @nonobjc
    public func createLink(to item: FSItem, named name: FSFileName, inDirectory directory: FSItem) async throws -> FSFileName {
        try await core.pushDirtyData([try portableItem(item)])
        return try await createLinkAfterPush(to: item, named: name, inDirectory: directory)
    }

    private func createLinkAfterPush(to item: FSItem, named name: FSFileName, inDirectory directory: FSItem) async throws -> FSFileName {
        try await core.client.withPublicationBoundary {
            do {
                let result = try await core.hardLinkAfterPush(
                    item: try portableItem(item),
                    in: try portableItem(directory),
                    name: name.data
                )
                return PfsFSKitMapping.fileName(from: result.canonicalName)
            } catch {
                throw PfsErrorMapper.fsKitError(for: error)
            }
        }
    }

    public func createLink(
        to item: FSItem,
        named name: FSFileName,
        inDirectory directory: FSItem,
        replyHandler reply: @escaping (FSFileName?, Error?) -> Void
    ) {
        let pushedItems = PfsUncheckedSendableBox([item])
        publishAfterReply(preflight: {
            try await self.core.pushDirtyData(try pushedItems.value.map { try self.portableItem($0) })
        }, {
            try await self.createLinkAfterPush(to: item, named: name, inDirectory: directory)
        }, reply: { result in
            switch result {
            case let .success(canonicalName): reply(canonicalName, nil)
            case let .failure(error): reply(nil, error)
            }
        })
    }

    @nonobjc
    public func removeItem(_ item: FSItem, named name: FSFileName, fromDirectory directory: FSItem) async throws {
        try await core.pushDirtyData([try portableItem(item)])
        try await removeItemAfterPush(item, named: name, fromDirectory: directory)
    }

    private func removeItemAfterPush(_ item: FSItem, named name: FSFileName, fromDirectory directory: FSItem) async throws {
        try await core.client.withPublicationBoundary {
            do {
                let portable = try portableItem(item)
                try await core.removeAfterPush(
                    item: portable,
                    named: name.data,
                    from: try portableItem(directory),
                    isDirectory: portable.kind == .directory
                )
            } catch {
                throw PfsErrorMapper.fsKitError(for: error)
            }
        }
    }

    public func removeItem(
        _ item: FSItem,
        named name: FSFileName,
        fromDirectory directory: FSItem,
        replyHandler reply: @escaping (Error?) -> Void
    ) {
        let pushedItems = PfsUncheckedSendableBox([item])
        publishAfterReply(preflight: {
            try await self.core.pushDirtyData(try pushedItems.value.map { try self.portableItem($0) })
        }, {
            try await self.removeItemAfterPush(item, named: name, fromDirectory: directory)
        }, reply: { result in
            switch result {
            case .success: reply(nil)
            case let .failure(error): reply(error)
            }
        })
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
        try await core.pushDirtyData(try [item, overItem].compactMap { $0 }.map { try portableItem($0) })
        return try await renameItemAfterPush(item, inDirectory: sourceDirectory, named: sourceName,
                                             to: destinationName, inDirectory: destinationDirectory, overItem: overItem)
    }

    private func renameItemAfterPush(_ item: FSItem, inDirectory sourceDirectory: FSItem, named sourceName: FSFileName,
                                     to destinationName: FSFileName, inDirectory destinationDirectory: FSItem,
                                     overItem: FSItem?) async throws -> FSFileName {
        try await core.client.withPublicationBoundary {
            do {
                let sourceItem = try portableItem(item)
                let sourceParent = try portableItem(sourceDirectory)
                let destinationParent = try portableItem(destinationDirectory)
                if let overItem, let replacedItem = overItem as? PortableFSItem, replacedItem !== sourceItem {
                    // Identity validation belongs before the authority mutation.
                    try await core.recordRenameReplacement(replacedItem: replacedItem)
                }
                _ = try await core.renameAfterPush(
                    item: sourceItem,
                    from: sourceParent,
                    sourceName: sourceName.data,
                    to: destinationParent,
                    destinationName: destinationName.data,
                    noReplace: false
                )
                return destinationName
            } catch {
                throw PfsErrorMapper.fsKitError(for: error)
            }
        }
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
        let pushedItems = PfsUncheckedSendableBox([item, overItem].compactMap { $0 })
        publishAfterReply(preflight: {
            try await self.core.pushDirtyData(try pushedItems.value.map { try self.portableItem($0) })
        }, {
            try await self.renameItemAfterPush(
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
            // only the initial verifier mints one. Cookie zero with a nonzero
            // verifier is a framework restart of an existing walk, not a new
            // verifier epoch.
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
                from: portableDirectory.fileID
            )
            var parentIdentifier = selfIdentifier
            if portableDirectory.fileID != 1,
               synthetics.contains(where: { $0.isParentEntry }),
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
                            from: entry.attr.fileID
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
                    if !packed { return currentVerifier }
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

    @objc(openItem:withModes:replyHandler:) public func openItem(
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

    @nonobjc
    public func closeItem(_ item: FSItem, modes: FSVolume.OpenModes) async throws {
        try await core.client.withPublicationBoundary {
            do {
                try await core.close(
                    item: try portableItem(item),
                    retainingModes: PfsFSKitMapping.openMode(from: modes)
                )
            } catch {
                throw PfsErrorMapper.fsKitError(for: error)
            }
        }
    }

    @objc(closeItem:keepingModes:replyHandler:) public func closeItem(
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

    // The native buffer callback and the trace tests share all request-issuing
    // READ work. FSKit alone constructs FSMutableFileDataBuffer; copying stays
    // in the adapter and needs no fabricated framework buffer in tests.
    func readData(from item: FSItem, at offset: off_t, length: Int) async throws -> Data {
        try await core.client.withPublicationBoundary {
            do {
                return try await core.read(item: try portableItem(item), offset: UInt64(offset), length: UInt32(clamping: length))
            } catch {
                throw PfsErrorMapper.fsKitError(for: error)
            }
        }
    }

    @nonobjc
    public func read(from item: FSItem, at offset: off_t, length: Int, into buffer: FSMutableFileDataBuffer) async throws -> Int {
        try await core.client.withPublicationBoundary {
            let data = try await readData(from: item, at: offset, length: length)
            let copied = min(data.count, buffer.length)
            data.withUnsafeBytes { source in
                buffer.withUnsafeMutableBytes { destination in
                    if let src = source.baseAddress, let dst = destination.baseAddress {
                        memcpy(dst, src, copied)
                    }
                }
            }
            return copied
        }
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

    // Permitted names take ordinary descriptor/publication admission. Only
    // a fixed refusal needs the earlier actor hop to check local ownership.
    private func refuseXattrAccessIfNeeded(named name: FSFileName, of item: FSItem) async throws {
        let target = try portableItem(item)
        let decoded = try PfsFSKitMapping.xattrName(from: name)
        if !PfsXattrPolicy.permits(decoded) {
            try await core.validateXattrAccess(item: target, name: decoded)
        }
    }

    @nonobjc
    public func xattr(named name: FSFileName, of item: FSItem) async throws -> Data {
        do {
            try await refuseXattrAccessIfNeeded(named: name, of: item)
        } catch {
            throw PfsErrorMapper.fsKitXattrError(for: error)
        }
        return try await core.client.withPublicationBoundary {
            do {
                return try await core.xattrGet(item: try portableItem(item), name: try PfsFSKitMapping.xattrName(from: name))
            } catch {
                throw PfsErrorMapper.fsKitXattrError(for: error)
            }
        }
    }

    public func getXattr(
        named name: FSFileName,
        of item: FSItem,
        replyHandler reply: @escaping (Data?, Error?) -> Void
    ) {
        let fields = metadataTraceFields(item: item, name: name)
        let target = PfsUncheckedSendableBox(item)
        let name = PfsUncheckedSendableBox(name)
        publishAfterReply(traceFields: fields, preflight: {
            do {
                try await self.refuseXattrAccessIfNeeded(named: name.value, of: target.value)
            } catch { throw PfsErrorMapper.fsKitXattrError(for: error) }
        }, {
            try await self.xattr(named: name.value, of: target.value)
        }, reply: { result in
            switch result {
            case let .success(value): reply(value, nil)
            case let .failure(error): reply(nil, error)
            }
        })
    }

    /// Delete removes a user xattr through the daemon. Every set policy is
    /// refused locally after validation; see `VolumeCore.refuseXattrSet`.
    @nonobjc
    public func setXattr(named name: FSFileName, to value: Data?, on item: FSItem, policy: FSVolume.SetXattrPolicy) async throws {
        let xattrName: String
        do {
            xattrName = try await refuseXattrSetIfRequested(named: name, on: item, policy: policy)
        } catch {
            throw PfsErrorMapper.fsKitXattrError(for: error)
        }
        try await core.client.withPublicationBoundary {
            do {
                try await core.xattrRemove(item: try portableItem(item), name: xattrName)
            } catch {
                throw PfsErrorMapper.fsKitXattrError(for: error)
            }
        }
    }

    public func setXattr(
        named name: FSFileName,
        to value: Data?,
        on item: FSItem,
        policy: FSVolume.SetXattrPolicy,
        replyHandler reply: @escaping (Error?) -> Void
    ) {
        let preflightName = PfsUncheckedSendableBox(name)
        let preflightItem = PfsUncheckedSendableBox(item)
        publishAfterReply(traceFields: metadataTraceFields(item: item, name: name), preflight: {
            do {
                _ = try await self.refuseXattrSetIfRequested(
                    named: preflightName.value,
                    on: preflightItem.value,
                    policy: policy
                )
            } catch {
                throw PfsErrorMapper.fsKitXattrError(for: error)
            }
        }, {
            try await self.setXattr(named: name, to: value, on: item, policy: policy)
        }, reply: { result in
            switch result {
            case .success: reply(nil)
            case let .failure(error): reply(error)
            }
        })
    }

    @nonobjc
    public func xattrs(of item: FSItem) async throws -> [FSFileName] {
        try await core.client.withPublicationBoundary {
            do {
                let names = try await core.xattrList(item: try portableItem(item))
                return names.map { FSFileName(string: $0) }
            } catch {
                throw PfsErrorMapper.fsKitXattrError(for: error)
            }
        }
    }

    public func listXattrs(
        of item: FSItem,
        replyHandler reply: @escaping ([FSFileName]?, Error?) -> Void
    ) {
        publishAfterReply(traceFields: metadataTraceFields(item: item), {
            try await self.xattrs(of: item)
        }, reply: { result in
            switch result {
            case let .success(names): reply(names, nil)
            case let .failure(error): reply(nil, error)
            }
        })
    }

    /// Decides the whole request's syntax (name encoding, policy, and for a
    /// set the shared `PfsXattrSetRequest` grammar) before the item is even
    /// converted, so a malformed request is EINVAL for a reclaimed and for a
    /// foreign FSItem alike. A set policy then always throws the fixed
    /// refusal; only delete returns, with the validated name.
    private func refuseXattrSetIfRequested(
        named name: FSFileName,
        on item: FSItem,
        policy: FSVolume.SetXattrPolicy
    ) async throws -> String {
        let xattrName = try PfsFSKitMapping.xattrName(from: name)
        let request: PfsXattrSetRequest
        switch policy {
        case .delete:
            if !PfsXattrPolicy.permits(xattrName) {
                try await core.validateXattrAccess(item: try portableItem(item), name: xattrName)
            }
            return xattrName
        case .mustCreate:
            request = try PfsXattrSetRequest(name: xattrName, createOnly: true, replaceOnly: false)
        case .mustReplace:
            request = try PfsXattrSetRequest(name: xattrName, createOnly: false, replaceOnly: true)
        case .alwaysSet:
            request = try PfsXattrSetRequest(name: xattrName, createOnly: false, replaceOnly: false)
        @unknown default:
            throw PfsLocalClientError.daemon(errno: EINVAL, message: "unknown xattr policy")
        }
        let target = try portableItem(item)
        try await core.refuseXattrSet(item: target, request: request)
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

/// macOS 26 retains its per-mode lifecycle. The macOS 27 volume never adopts
/// this protocol, so its deferred final close has exactly one owner.
@available(macOS 26.0, *)
final class PortableFSVolumeV2: PortableFSVolume, FSVolume.OpenCloseOperations, @unchecked Sendable {}

@available(macOS 27.0, *)
final class PortableFSVolumeV3: PortableFSVolume, FSVolume.DataCacheHandler, @unchecked Sendable {
    func open(_ item: FSItem, modes: FSVolume.OpenModes, cacheMode: FSVolume.DataCacheMode,
              context: FSContext, replyHandler reply: @escaping (FSOpenItemResult?, Error?) -> Void) {
        cacheOpen(item, modes: modes, cacheMode: cacheMode) { grant, error in
            reply(grant.map { FSOpenItemResult(grantedCoherency: $0) }, error)
        }
    }

    func upgrade(_ item: FSItem, cacheMode: FSVolume.DataCacheMode, context: FSContext,
                 replyHandler reply: @escaping (FSUpgradeItemResult?, Error?) -> Void) {
        cacheOpen(item, modes: nil, cacheMode: cacheMode) { grant, error in
            reply(grant.map { FSUpgradeItemResult(grantedCoherency: $0) }, error)
        }
    }

    /// Upgrade may acquire authorized backing read access for an already held
    /// writer. Only an application open can acquire missing write access.
    func cacheOpen(_ item: FSItem, modes: FSVolume.OpenModes?, cacheMode: FSVolume.DataCacheMode,
                   reply: @escaping (FSVolume.KernelCacheCoherencyType?, Error?) -> Void) {
        publishAfterReply({
            let requested: PfsKernelCache.Mode
            switch cacheMode {
            case .none: requested = .none
            case .readWithCache: requested = .readWithCache
            case .readWriteWithCache: requested = .readWriteWithCache
            @unknown default: throw POSIXError(.EINVAL)
            }
            guard let item = item as? PortableFSItem else { throw POSIXError(.EINVAL) }
            if let modes {
                guard !modes.isEmpty, modes.subtracting([.read, .write]).isEmpty else { throw POSIXError(.EINVAL) }
            }
            try await self.core.cacheOpen(item: item, mode: modes.map { PfsFSKitMapping.openMode(from: $0) }, requested: requested)
            return (item, requested)
        }, finalize: { value -> FSVolume.KernelCacheCoherencyType in
            let (item, requested) = value
            let grant = try self.kernelCache?.grant(item, requested: requested) ?? .noCache
            self.logger.debug("cache grant file=\(item.fileID) requested=\(String(describing: requested), privacy: .public) granted=\(String(describing: grant), privacy: .public)")
            switch grant {
            case .noCache: return .noCache
            case .readCache: return .readCache
            case .writeBack: return .writeBack
            }
        }, reply: { result in
            switch result {
            case let .success(grant): reply(grant, nil)
            case let .failure(error): reply(nil, error)
            }
        })
    }

    func close(_ item: FSItem, context: FSContext, replyHandler reply: @escaping () -> Void) {
        finalClose(item, reply: reply)
    }

    /// Cleanup still runs after terminal publication. This callback has no
    /// error channel; a cleanup failure ends the session instead of disappearing.
    func finalClose(_ item: FSItem, reply: @escaping () -> Void) {
        let reply = PfsUncheckedSendableBox(reply)
        let trace = PfsCallbackTrace(kind: "finalClose", connection: traceConnection, trace: core.client.trace)
        let item = PfsUncheckedSendableBox(item)
        Task {
            let (result, complete) = await self.core.client.withDeferredPublication(callbackLabel: trace.label) {
                guard let item = item.value as? PortableFSItem else { throw POSIXError(.EINVAL) }
                try await self.core.close(item: item)
            }
            if case let .failure(error) = result { await self.core.client.close(error: error) }
            reply.value()
            await complete(false)
            trace.finish(outcome: result.pfsIsSuccess ? "success" : "failure")
        }
    }
}
