import Foundation
import PortableFSKit
@preconcurrency import Darwin

public final class PfsLocalMockDaemon: @unchecked Sendable {
    public struct Stats: Sendable, Equatable {
        public var openRequests: Int
        public var closeRequests: Int
        public var activeHandles: Int
        public var readRequests: Int
        public var writeRequests: Int
        public var enumerateRequests: Int
        public var getAttrRequests: Int
        /// Setattr requests that arrived carrying `set_flags`. The frontend
        /// gate is invisible from the outside — a refused change and a
        /// forwarded-then-refused change both surface as ENOTSUP — so proving
        /// forwarding needs the daemon to say it saw the frame.
        public var flagChangeRequests: Int
        public var maxReadLength: UInt32
        public var maxWriteLength: Int
        public var publicationAcks: Int
    }

    public struct Configuration: Sendable {
        public var attachRef: String
        public var volumeID: String
        public var volumeName: String
        public var branch: String
        public var lookupDelaysNanoseconds: [String: UInt64]
        public var lookupNoReplyNames: Set<String>
        public var strictItemNamespace: Bool
        public var protocolMinor: UInt32?
        /// Mirrors the real daemon's per-attach AUTHORITY knowledge: it rides
        /// the resolve reply as `Capabilities.flagsSupported`, and a setattr
        /// carrying `setFlags` against an AUTHORITY-BACKED node without it is
        /// answered ENOTSUP rather than silently dropped. It says nothing
        /// about grafted nodes — see `graftBackedNames`.
        public var flagsSupported: Bool
        /// Mirrors `Capabilities.flagsUnderstood`: this daemon parses
        /// `set_flags`/`flags` at all. A real daemon sets it unconditionally;
        /// it is configurable here only so a test can model one that does not.
        /// This — not `flagsSupported` — is what the frontend gates on.
        public var flagsUnderstood: Bool
        /// Names whose backing is machine-local (a graft over the volume
        /// namespace). chflags(2) on such a node is applied to a real host
        /// inode, so it succeeds regardless of `flagsSupported`: no authority
        /// feature is involved. This is what makes a volume's flag support
        /// PER-OBJECT, and why a volume-wide frontend gate is wrong.
        public var graftBackedNames: Set<String>
        /// Models a daemon built BEFORE `set_flags`/`flags` existed. Both are
        /// appended fields at the same protocol minor, so such a daemon
        /// proto3-discards them: it never advertises `flagsSupported`, it
        /// cannot refuse what it does not parse, and it applies the rest of
        /// the setattr and reports success. That silent no-op is the failure
        /// the frontend-side gate exists to prevent.
        public var predatesFlagFields: Bool

        public init(
            attachRef: String = "mock",
            volumeID: String = "mock-volume",
            volumeName: String = "PortableFS Mock",
            branch: String = "main",
            lookupDelaysNanoseconds: [String: UInt64] = [:],
            lookupNoReplyNames: Set<String> = [],
            strictItemNamespace: Bool = false,
            protocolMinor: UInt32? = nil,
            flagsSupported: Bool = true,
            flagsUnderstood: Bool = true,
            graftBackedNames: Set<String> = [],
            predatesFlagFields: Bool = false
        ) {
            self.attachRef = attachRef
            self.volumeID = volumeID
            self.volumeName = volumeName
            self.branch = branch
            self.lookupDelaysNanoseconds = lookupDelaysNanoseconds
            self.lookupNoReplyNames = lookupNoReplyNames
            self.strictItemNamespace = strictItemNamespace
            self.protocolMinor = protocolMinor
            self.flagsSupported = flagsSupported
            self.flagsUnderstood = flagsUnderstood
            self.graftBackedNames = graftBackedNames
            self.predatesFlagFields = predatesFlagFields
        }
    }

    public let socketPath: String
    private let configuration: Configuration
    private let serverFD: Int32
    private let fileSystem: MockFileSystem
    private let sessionLock = NSLock()
    private var sessions: [Int32: MockSession] = [:]
    private let acceptQueue = DispatchQueue(label: "dev.portablefs.mock.accept", qos: .utility)
    private let clientQueue = DispatchQueue(label: "dev.portablefs.mock.client", qos: .utility, attributes: .concurrent)
    private let acceptGroup = DispatchGroup()
    private let lifecycleLock = NSLock()
    private var acceptWorkItem: DispatchWorkItem?
    private var stopped = false

    public init(configuration: Configuration = Configuration()) throws {
        self.configuration = configuration
        let suffix = UUID().uuidString.prefix(12)
        self.socketPath = "/tmp/pfs-\(suffix).sock"
        self.fileSystem = MockFileSystem(configuration: configuration)
        self.serverFD = try PfsUnixSocket.bindAndListen(path: socketPath)
        let workItem = DispatchWorkItem { [weak self] in
            self?.acceptLoop()
        }
        self.acceptWorkItem = workItem
        self.acceptGroup.enter()
        self.acceptQueue.async(execute: workItem)
    }

    deinit {
        stop()
    }

    public func stop() {
        lifecycleLock.lock()
        guard !stopped else {
            lifecycleLock.unlock()
            return
        }
        stopped = true
        lifecycleLock.unlock()

        acceptWorkItem?.cancel()
        if let wakeFD = try? PfsUnixSocket.connect(path: socketPath) {
            PfsUnixSocket.close(wakeFD)
        }
        _ = acceptGroup.wait(timeout: .now() + 2)
        Darwin.shutdown(serverFD, SHUT_RDWR)
        PfsUnixSocket.close(serverFD)
        for session in sessionSnapshot() {
            session.close()
        }
        unlink(socketPath)
    }

    public func dropConnections() {
        for session in sessionSnapshot() {
            session.close()
        }
    }

    /// Causes the next daemon close request to fail before releasing its
    /// handle. Lifecycle tests use this to verify confirmed-close ownership.
    public func failNextClose() async {
        await fileSystem.failNextClose()
    }

    /// Causes the next close to consume its handle and report a terminal errno,
    /// matching a local descriptor whose close syscall failed after retirement.
    public func retireNextCloseWithError(errno: Int32 = EIO) async {
        await fileSystem.retireNextCloseWithError(errno: errno)
    }

    /// Retires the next close handle, remembers its exact outcome for replay,
    /// then closes that client connection before sending the reply.
    public func loseNextRetiredCloseReply(errno: Int32 = 0) async {
        await fileSystem.loseNextRetiredCloseReply(errno: errno)
    }

    /// Marks the next `count` publication-bearing replies as retracted,
    /// modelling the daemon discovering that a delegation handoff crossed the
    /// operation those replies belong to.
    ///
    /// The retraction rides an ordinary reply rather than arriving as its own
    /// frame, which is the whole ordering argument: the frontend cannot see it
    /// after the values it condemns. A mock that emitted a separate message
    /// would be testing a protocol this one does not have.
    public func retractNextPublications(count: Int = 1) async {
        await fileSystem.retractNextPublications(count: count)
    }

    /// Retracts the next `count` publication-bearing requests AND refuses them
    /// without executing, which is what the real daemon does once an operation
    /// has been crossed: it fails every still-undispatched request of that
    /// operation EINTR rather than running it.
    ///
    /// This is the production shape of a retraction. The bit rides the
    /// refusal's own reply, so the frame that condemns the operation is
    /// usually an ErrorReply rather than a successful one — and a mutation
    /// that was waiting on the handoff never lands, which is what lets the
    /// frontend answer EINTR without lying about what happened.
    public func refuseNextPublicationsAsRetracted(count: Int = 1) async {
        await fileSystem.refuseNextPublicationsAsRetracted(count: count)
    }

    public func delayNextOpen(nanoseconds: UInt64) async {
        await fileSystem.delayNextOpen(nanoseconds: nanoseconds)
    }

    public func delayNextClose(nanoseconds: UInt64) async {
        await fileSystem.delayNextClose(nanoseconds: nanoseconds)
    }

    public func delayNextRead(nanoseconds: UInt64) async {
        await fileSystem.delayNextRead(nanoseconds: nanoseconds)
    }

    public func delayNextWrite(nanoseconds: UInt64) async {
        await fileSystem.delayNextWrite(nanoseconds: nanoseconds)
    }

    /// Refuses the Nth-next write request with `errno`, AFTER any earlier
    /// request in the same framework callback has already committed. That is
    /// the shape one FSKit write callback takes when it spans several daemon
    /// requests and a later one hits a fence, a lane change or an EIO: the
    /// earlier chunks are on media and the callback still has to say something
    /// truthful about them.
    public func failWrite(atIndex index: Int, errno code: Int32 = EIO) async {
        await fileSystem.failWrite(atIndex: index, errno: code)
    }

    /// Answers the Nth-next write request with a SHORT count — `written` bytes
    /// of the request's payload — which is a healthy POSIX outcome the daemon
    /// produces whenever a credit grant covers only a prefix.
    public func shortenNextWrite(to written: Int) async {
        await fileSystem.shortenNextWrite(to: written)
    }

    public func emitInvalidation(
        item: PfsItem,
        contentChanged: Bool = true,
        attrsChanged: Bool = true,
        namespaceChanged: Bool = false,
        contentVersion: UInt64 = 1
    ) {
        var invalidation = PfsInvalidation()
        invalidation.item = item
        invalidation.contentChanged = contentChanged
        invalidation.attrsChanged = attrsChanged
        invalidation.namespaceChanged = namespaceChanged
        invalidation.contentVersion = contentVersion

        var event = PfsEvent()
        event.kind = .invalidation(invalidation)

        var envelope = PfsEnvelope()
        envelope.requestID = 0
        envelope.body = .event(event)

        for session in sessionSnapshot() where session.isSubscribed {
            try? session.send(envelope)
        }
    }

    public func emitAttachState(_ state: PfsAttachState.State, detail: String = "") {
        var attachState = PfsAttachState()
        attachState.state = state
        attachState.detail = detail

        var event = PfsEvent()
        event.kind = .attachState(attachState)

        var envelope = PfsEnvelope()
        envelope.requestID = 0
        envelope.body = .event(event)

        for session in sessionSnapshot() where session.isSubscribed {
            try? session.send(envelope)
        }
    }

    public func rootIdentity() async -> PfsItemIdentity {
        await fileSystem.rootIdentity()
    }

    public func stats() async -> Stats {
        await fileSystem.stats()
    }

    public func resetStats() async {
        await fileSystem.resetStats()
    }

    private func acceptLoop() {
        defer {
            acceptGroup.leave()
        }
        while !isStopped && acceptWorkItem?.isCancelled != true {
            do {
                let clientFD = try PfsUnixSocket.accept(serverFD)
                if isStopped || acceptWorkItem?.isCancelled == true {
                    PfsUnixSocket.close(clientFD)
                    return
                }
                let session = MockSession(fd: clientFD)
                addSession(session)
                clientQueue.async { [weak self, session] in
                    self?.clientLoop(session: session)
                }
            } catch {
                if !isStopped {
                    continue
                }
                return
            }
        }
    }

    private func clientLoop(session: MockSession) {
        defer {
            removeSession(fd: session.fd)
            session.close()
        }
        var reader = PfsMockFrameReader(fd: session.fd)
        while !isStopped {
            do {
                let envelope = try reader.readFrame()
                Task.detached { [fileSystem, session] in
                    let reply = await fileSystem.handle(envelope, session: session)
                    try? session.send(reply)
                }
            } catch {
                return
            }
        }
    }

    private var isStopped: Bool {
        lifecycleLock.lock()
        let value = stopped
        lifecycleLock.unlock()
        return value
    }

    private func addSession(_ session: MockSession) {
        sessionLock.lock()
        sessions[session.fd] = session
        sessionLock.unlock()
    }

    private func removeSession(fd: Int32) {
        sessionLock.lock()
        sessions.removeValue(forKey: fd)
        sessionLock.unlock()
    }

    private func sessionSnapshot() -> [MockSession] {
        sessionLock.lock()
        let snapshot = Array(sessions.values)
        sessionLock.unlock()
        return snapshot
    }
}

private final class MockSession: @unchecked Sendable {
    let fd: Int32
    private let ioLock = NSLock()
    private let stateLock = NSLock()
    private var subscribed = false
    private var closed = false

    var isSubscribed: Bool {
        stateLock.lock()
        let value = subscribed
        stateLock.unlock()
        return value
    }

    init(fd: Int32) {
        self.fd = fd
        PfsMockFrameIO.disableSigPipe(fd: fd)
    }

    func setSubscribed() {
        stateLock.lock()
        subscribed = true
        stateLock.unlock()
    }

    func send(_ envelope: PfsEnvelope) throws {
        ioLock.lock()
        defer { ioLock.unlock() }
        guard !closed else {
            throw PfsLocalClientError.connectionClosed
        }
        try PfsMockFrameIO.writeFrame(fd: fd, envelope: envelope)
    }

    func close() {
        ioLock.lock()
        defer { ioLock.unlock() }
        let shouldClose = !closed
        closed = true
        if shouldClose {
            PfsUnixSocket.close(fd)
        }
    }
}

private struct PfsMockFrameReader {
    private let fd: Int32
    private var decoder: PfsFrameDecoder
    private var bufferedFrames: [PfsEnvelope] = []

    init(fd: Int32, maxFrameLength: Int = PfsFrameCodec.defaultMaxFrameLength) {
        self.fd = fd
        self.decoder = PfsFrameDecoder(maxFrameLength: maxFrameLength)
    }

    mutating func readFrame() throws -> PfsEnvelope {
        if !bufferedFrames.isEmpty {
            return bufferedFrames.removeFirst()
        }

        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = buffer.withUnsafeMutableBytes { rawBuffer in
                Darwin.recv(fd, rawBuffer.baseAddress, rawBuffer.count, 0)
            }
            if count > 0 {
                let frames = try decoder.append(Data(buffer.prefix(count)))
                if let frame = frames.first {
                    bufferedFrames.append(contentsOf: frames.dropFirst())
                    return frame
                }
                continue
            }
            if count == 0 {
                if decoder.bufferedByteCount == 0 {
                    throw PfsLocalClientError.connectionClosed
                }
                throw PfsLocalClientError.invalidFrame("EOF before completing frame")
            }
            let error = Darwin.errno
            if error == EINTR {
                continue
            }
            throw PfsLocalClientError.system(errno: error, operation: "recv")
        }
    }
}

private enum PfsMockFrameIO {
    static func disableSigPipe(fd: Int32) {
        var value: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &value, socklen_t(MemoryLayout<Int32>.size))
    }

    static func writeFrame(fd: Int32, envelope: PfsEnvelope, maxFrameLength: Int = PfsFrameCodec.defaultMaxFrameLength) throws {
        let data = try PfsFrameCodec(maxFrameLength: maxFrameLength).encode(envelope)
        try data.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress else {
                return
            }
            var offset = 0
            while offset < data.count {
                let sent = Darwin.send(fd, base.advanced(by: offset), data.count - offset, 0)
                if sent > 0 {
                    offset += sent
                    continue
                }
                if sent == 0 {
                    throw PfsLocalClientError.connectionClosed
                }
                let error = Darwin.errno
                if error == EINTR {
                    continue
                }
                throw PfsLocalClientError.system(errno: error, operation: "send")
            }
        }
    }
}

private actor MockFileSystem {
    // Enumeration cookie layout mirrors portablefsd exactly: [marker:1][cursor:61][tag:2],
    // where the cursor is a pure function of the entry name. Resumption is
    // "first entry whose cursor is strictly greater than the cookie", so a
    // cookie stays resolvable no matter what the directory does between pages
    // and no matter which pages the daemon already served. The mock exists to
    // hold the adapter to that contract, so it must not be more forgiving.
    private static let daemonCookieMarker: UInt64 = 1 << 63
    private static let cookieTagMask: UInt64 = 0x3
    private static let cookieTagCursor: UInt64 = 0x1
    private static let cursorMax: UInt64 = (1 << 61) - 1
    private static let cursorSpace: UInt64 = cursorMax - (1 << 20)

    private final class Node {
        let id: UInt64
        let generation: UInt64
        var kind: PfsItemKind
        var mode: UInt32
        var nlink: UInt32
        var uid: UInt32
        var gid: UInt32
        var data: Data
        var symlinkTarget: Data
        var children: [Data: UInt64]
        var xattrs: [String: Data]
        var parent: UInt64?
        var mtimeMs: Int64
        var ctimeMs: Int64
        var atimeMs: Int64
        var birthtimeMs: Int64
        var contentVersion: UInt64
        var flags: UInt32

        init(id: UInt64, kind: PfsItemKind, mode: UInt32, parent: UInt64?) {
            self.id = id
            self.generation = 1
            self.kind = kind
            self.mode = mode
            self.nlink = kind == .directory ? 2 : 1
            self.uid = UInt32(getuid())
            self.gid = UInt32(getgid())
            self.data = Data()
            self.symlinkTarget = Data()
            self.children = [:]
            self.xattrs = [:]
            self.parent = parent
            let now = Int64(Date().timeIntervalSince1970 * 1000)
            self.mtimeMs = now
            self.ctimeMs = now
            self.atimeMs = now
            self.birthtimeMs = now
            self.contentVersion = 1
            self.flags = 0
        }

        var item: PfsItem {
            var item = PfsItem()
            item.itemID = id
            item.itemGeneration = generation
            return item
        }
    }

    private struct MockPOSIXError: Error {
        var errno: Int32
        var message: String
    }

    private let configuration: PfsLocalMockDaemon.Configuration
    private var nodes: [UInt64: Node] = [:]
    private var handles: [UInt64: UInt64] = [:]
    private var nextNodeID: UInt64 = 2
    private var nextHandle: UInt64 = 1
    private var openRequests = 0
    private var closeRequests = 0
    private var readRequests = 0
    private var writeRequests = 0
    private var enumerateRequests = 0
    private var getAttrRequests = 0
    private var flagChangeRequests = 0
    private var maxReadLength: UInt32 = 0
    private var maxWriteLength = 0
    private var publicationAcks = 0
    private var pendingRetractions = 0
    private var pendingRetractionRefusals = 0
    private var pendingCloseFailures = 0
    private var pendingRetiredCloseErrnos: [Int32] = []
    private var pendingLostRetiredCloseErrnos: [Int32] = []
    private var retiredCloseReplies: [UInt64: PfsCloseReply] = [:]
    private var pendingOpenDelaysNanoseconds: [UInt64] = []
    private var pendingCloseDelaysNanoseconds: [UInt64] = []
    private var pendingReadDelaysNanoseconds: [UInt64] = []
    private var pendingWriteDelaysNanoseconds: [UInt64] = []
    /// Write-request index (0-based, counted across the whole session) → errno.
    /// Positional rather than a queue because the shape under test is "chunk k
    /// of one framework callback fails after chunks 0..<k committed", and that
    /// needs the failure placed at a known request, not merely next in line.
    private var writeErrnoByIndex: [Int: Int32] = [:]
    private var pendingWriteShortCounts: [Int] = []

    init(configuration: PfsLocalMockDaemon.Configuration) {
        self.configuration = configuration
        let root = Node(id: 1, kind: .directory, mode: 0o755, parent: nil)
        nodes[root.id] = root
    }

    func rootIdentity() -> PfsItemIdentity {
        PfsItemIdentity(itemID: 1, generation: 1)
    }

    func stats() -> PfsLocalMockDaemon.Stats {
        PfsLocalMockDaemon.Stats(
            openRequests: openRequests,
            closeRequests: closeRequests,
            activeHandles: handles.count,
            readRequests: readRequests,
            writeRequests: writeRequests,
            enumerateRequests: enumerateRequests,
            getAttrRequests: getAttrRequests,
            flagChangeRequests: flagChangeRequests,
            maxReadLength: maxReadLength,
            maxWriteLength: maxWriteLength,
            publicationAcks: publicationAcks
        )
    }

    func resetStats() {
        openRequests = 0
        closeRequests = 0
        readRequests = 0
        writeRequests = 0
        enumerateRequests = 0
        getAttrRequests = 0
        flagChangeRequests = 0
        maxReadLength = 0
        maxWriteLength = 0
        publicationAcks = 0
    }

    func retractNextPublications(count: Int) {
        pendingRetractions += count
    }

    func refuseNextPublicationsAsRetracted(count: Int) {
        pendingRetractionRefusals += count
    }

    func failNextClose() {
        pendingCloseFailures += 1
    }

    func retireNextCloseWithError(errno: Int32) {
        pendingRetiredCloseErrnos.append(errno)
    }

    func loseNextRetiredCloseReply(errno: Int32) {
        pendingLostRetiredCloseErrnos.append(errno)
    }

    func delayNextOpen(nanoseconds: UInt64) {
        pendingOpenDelaysNanoseconds.append(nanoseconds)
    }

    func delayNextClose(nanoseconds: UInt64) {
        pendingCloseDelaysNanoseconds.append(nanoseconds)
    }

    func delayNextRead(nanoseconds: UInt64) {
        pendingReadDelaysNanoseconds.append(nanoseconds)
    }

    func delayNextWrite(nanoseconds: UInt64) {
        pendingWriteDelaysNanoseconds.append(nanoseconds)
    }

    func failWrite(atIndex index: Int, errno code: Int32) {
        writeErrnoByIndex[index] = code
    }

    func shortenNextWrite(to written: Int) {
        pendingWriteShortCounts.append(written)
    }

    func handle(_ envelope: PfsEnvelope, session: MockSession) async -> PfsEnvelope {
        var reply = PfsEnvelope()
        reply.requestID = envelope.requestID
        do {
            guard let body = envelope.body else {
                throw MockPOSIXError(errno: EINVAL, message: "missing body")
            }
            switch body {
            case .lookup(_), .enumerate(_), .getAttr(_), .setAttr(_),
                 .read(_), .write(_), .create(_), .mkdir(_), .remove(_),
                 .rename(_), .symlink(_), .readlink(_), .hardLink(_),
                 .xattrGet(_), .xattrSet(_), .xattrList(_), .xattrRemove(_):
                reply.publicationAckRequired = true
            default:
                reply.publicationAckRequired = false
            }
            // Only a reply the frontend could publish can be retracted, and
            // the retraction still leaves the acknowledgement owed: the
            // daemon's handoff gate is released by the ack, not by whether
            // the frontend kept the values.
            if reply.publicationAckRequired && pendingRetractions > 0 {
                pendingRetractions -= 1
                reply.publicationRetracted = true
            }
            // The refusal arm must throw BEFORE the dispatch switch below, or
            // the mock would be modelling a daemon that retracts an operation
            // and mutates for it anyway — precisely the state the real
            // daemon's pre-dispatch check exists to make unreachable.
            if reply.publicationAckRequired && pendingRetractionRefusals > 0 {
                pendingRetractionRefusals -= 1
                reply.publicationRetracted = true
                throw MockPOSIXError(errno: EINTR, message: "operation retracted before dispatch")
            }
            switch body {
            case let .hello(request):
                var response = PfsHelloReply()
                response.protocolMajor = request.protocolMajor
                response.protocolMinor = configuration.protocolMinor ?? request.protocolMinor
                response.daemonVersion = "mock"
                reply.body = .helloReply(response)
            case let .resolve(request):
                guard request.attachRef == configuration.attachRef else {
                    throw MockPOSIXError(errno: ENOENT, message: "unknown attachRef")
                }
                var response = PfsResolveReply()
                let root = try node(for: rootIdentity().proto)
                response.root = root.item
                response.rootAttr = attr(for: root)
                response.volumeID = configuration.volumeID
                response.volumeName = configuration.volumeName
                response.branch = configuration.branch
                var capabilities = PfsCapabilities()
                capabilities.symlinks = true
                capabilities.hardLinks = true
                capabilities.xattrs = true
                capabilities.caseSensitive = true
                capabilities.maxNameBytes = 255
                capabilities.maxFileSize = UInt64.max
                capabilities.preferredIoBytes = 1_048_576
                // A daemon predating the flag fields advertises neither: it
                // cannot set fields it does not know exist, and both decode
                // false on the frontend.
                capabilities.flagsSupported = configuration.flagsSupported && !configuration.predatesFlagFields
                capabilities.flagsUnderstood = configuration.flagsUnderstood && !configuration.predatesFlagFields
                response.capabilities = capabilities
                reply.body = .resolveReply(response)
            case let .lookup(request):
                let name = displayName(request.name)
                if configuration.lookupNoReplyNames.contains(name) {
                    try await Task.sleep(nanoseconds: 3_600_000_000_000)
                }
                if let delay = configuration.lookupDelaysNanoseconds[name] {
                    try await Task.sleep(nanoseconds: delay)
                }
                let directory = try node(for: request.dir)
                guard directory.kind == .directory else {
                    throw MockPOSIXError(errno: ENOTDIR, message: "not a directory")
                }
                guard let childID = directory.children[request.name], let child = nodes[childID] else {
                    throw MockPOSIXError(errno: ENOENT, message: "not found")
                }
                var response = PfsLookupReply()
                response.attr = attr(for: child, parent: directory)
                reply.body = .lookupReply(response)
            case let .enumerate(request):
                enumerateRequests += 1
                let directory = try node(for: request.dir)
                guard directory.kind == .directory else {
                    throw MockPOSIXError(errno: ENOTDIR, message: "not a directory")
                }
                let ordered = orderedChildren(of: directory)
                let resume = try decodeCookie(request.cookie)
                let start = ordered.firstIndex { $0.cursor > resume } ?? ordered.count
                let maxEntries = max(1, Int(request.maxEntries))
                let end = min(ordered.count, start + maxEntries)
                var response = PfsEnumerateReply()
                for index in start..<end {
                    let name = ordered[index].name
                    if let childID = directory.children[name], let child = nodes[childID] {
                        var entry = PfsDirEntry()
                        entry.name = name
                        entry.attr = attr(for: child, parent: directory)
                        entry.cookie = index + 1 >= ordered.count ? 0 : encodeCookie(cursor: ordered[index].cursor)
                        response.entries.append(entry)
                    }
                }
                response.nextCookie = response.entries.last?.cookie ?? 0
                response.dirVersion = directory.contentVersion
                reply.body = .enumerateReply(response)
            case let .getAttr(request):
                getAttrRequests += 1
                var response = PfsGetAttrReply()
                response.attr = attr(for: try node(for: request.item, handle: request.handle))
                reply.body = .getAttrReply(response)
            case let .setAttr(request):
                let node = try node(for: request.item, handle: request.handle)
                // A daemon predating the appended fields never observes them:
                // proto3 discards unknown fields before any handler runs, so
                // it can neither apply nor refuse the flags change.
                let setFlags = request.setFlags && !configuration.predatesFlagFields
                if setFlags {
                    flagChangeRequests += 1
                }
                // The real daemon's decision is PER TARGET, taken where the
                // backing is known. A grafted node's backing is a real host
                // inode, so its chflags(2) lands whatever the authority can or
                // cannot store; an authority-backed node without
                // FeatureFlagPersistence is refused the WHOLE setattr before
                // anything is applied. The frontend cannot make this call — it
                // does not know what backs the object — which is exactly why
                // its own gate asks a different question (does this daemon
                // parse set_flags at all).
                if setFlags && !configuration.flagsSupported && !isGraftBacked(node) {
                    throw MockPOSIXError(errno: ENOTSUP, message: "authority does not persist BSD file flags")
                }
                if request.hasMode { node.mode = request.mode }
                if request.hasUid { node.uid = request.uid }
                if request.hasGid { node.gid = request.gid }
                if request.hasSize { resize(node: node, size: Int(request.size)) }
                if request.hasMtimeMs { node.mtimeMs = request.mtimeMs }
                if request.hasAtimeMs { node.atimeMs = request.atimeMs }
                if setFlags { node.flags = request.flags }
                node.ctimeMs = nowMs()
                var response = PfsSetAttrReply()
                response.attr = attr(for: node)
                reply.body = .setAttrReply(response)
            case let .open(request):
                _ = try namespaceNode(for: request.item)
                openRequests += 1
                let handle = nextHandle
                nextHandle += 1
                handles[handle] = request.item.itemID
                if !pendingOpenDelaysNanoseconds.isEmpty {
                    let delay = pendingOpenDelaysNanoseconds.removeFirst()
                    try await Task.sleep(nanoseconds: delay)
                }
                var response = PfsOpenReply()
                response.handle = handle
                reply.body = .openReply(response)
            case let .close(request):
                closeRequests += 1
                if !pendingCloseDelaysNanoseconds.isEmpty {
                    let delay = pendingCloseDelaysNanoseconds.removeFirst()
                    try await Task.sleep(nanoseconds: delay)
                }
                if pendingCloseFailures > 0 {
                    pendingCloseFailures -= 1
                    throw MockPOSIXError(errno: EIO, message: "injected close failure")
                }
                if let response = retiredCloseReplies[request.handle] {
                    reply.body = .closeReply(response)
                    break
                }
                guard let nodeID = handles.removeValue(forKey: request.handle) else {
                    throw MockPOSIXError(errno: EINVAL, message: "unknown handle")
                }
                reapIfUnlinked(nodeID: nodeID)
                var response = PfsCloseReply()
                response.retired = true
                let loseReply = !pendingLostRetiredCloseErrnos.isEmpty
                if loseReply {
                    response.closeErrno = pendingLostRetiredCloseErrnos.removeFirst()
                } else if !pendingRetiredCloseErrnos.isEmpty {
                    response.closeErrno = pendingRetiredCloseErrnos.removeFirst()
                }
                retiredCloseReplies[request.handle] = response
                reply.body = .closeReply(response)
                if loseReply {
                    session.close()
                }
            case let .read(request):
                readRequests += 1
                maxReadLength = max(maxReadLength, request.length)
                if !pendingReadDelaysNanoseconds.isEmpty {
                    let delay = pendingReadDelaysNanoseconds.removeFirst()
                    try await Task.sleep(nanoseconds: delay)
                }
                let node = try node(forHandle: request.handle)
                let offset = min(Int(request.offset), node.data.count)
                let end = min(node.data.count, offset + Int(request.length))
                var response = PfsReadReply()
                response.data = node.data.subdata(in: offset..<end)
                reply.body = .readReply(response)
            case let .write(request):
                let writeIndex = writeRequests
                writeRequests += 1
                maxWriteLength = max(maxWriteLength, request.data.count)
                if !pendingWriteDelaysNanoseconds.isEmpty {
                    let delay = pendingWriteDelaysNanoseconds.removeFirst()
                    try await Task.sleep(nanoseconds: delay)
                }
                if let code = writeErrnoByIndex[writeIndex] {
                    throw MockPOSIXError(errno: code, message: "injected write failure")
                }
                let node = try node(forHandle: request.handle)
                var payload = request.data
                if !pendingWriteShortCounts.isEmpty {
                    let want = pendingWriteShortCounts.removeFirst()
                    payload = payload.prefix(max(0, min(want, payload.count)))
                }
                write(node: node, offset: Int(request.offset), data: payload)
                var response = PfsWriteReply()
                response.written = UInt32(payload.count)
                response.attr = attr(for: node)
                reply.body = .writeReply(response)
            case let .create(request):
                let directory = try node(for: request.dir)
                guard directory.children[request.name] == nil else {
                    throw MockPOSIXError(errno: EEXIST, message: "exists")
                }
                let node = createNode(kind: .file, mode: request.mode, parent: directory.id)
                directory.children[request.name] = node.id
                bump(directory)
                let handle = nextHandle
                nextHandle += 1
                handles[handle] = node.id
                var response = PfsCreateReply()
                response.attr = attr(for: node)
                response.handle = handle
                reply.body = .createReply(response)
            case let .mkdir(request):
                let directory = try node(for: request.dir)
                guard directory.children[request.name] == nil else {
                    throw MockPOSIXError(errno: EEXIST, message: "exists")
                }
                let node = createNode(kind: .directory, mode: request.mode, parent: directory.id)
                directory.children[request.name] = node.id
                bump(directory)
                var response = PfsMkdirReply()
                response.attr = attr(for: node)
                reply.body = .mkdirReply(response)
            case let .remove(request):
                let directory = try node(for: request.dir)
                guard let childID = directory.children[request.name], let child = nodes[childID] else {
                    throw MockPOSIXError(errno: ENOENT, message: "not found")
                }
                if request.directory && !child.children.isEmpty {
                    throw MockPOSIXError(errno: ENOTEMPTY, message: "directory not empty")
                }
                directory.children.removeValue(forKey: request.name)
                child.nlink = child.nlink > 0 ? child.nlink - 1 : 0
                reapIfUnlinked(nodeID: childID)
                bump(directory)
                reply.body = .removeReply(PfsRemoveReply())
            case let .rename(request):
                let fromDirectory = try node(for: request.fromDir)
                let toDirectory = try node(for: request.toDir)
                guard let childID = fromDirectory.children[request.fromName] else {
                    throw MockPOSIXError(errno: ENOENT, message: "not found")
                }
                let replacedID = toDirectory.children[request.toName]
                if request.noReplace && replacedID != nil && replacedID != childID {
                    throw MockPOSIXError(errno: EEXIST, message: "exists")
                }
                if replacedID == childID {
                    // POSIX specifies a no-op when both names are hard links
                    // to the same inode: neither directory entry is removed.
                    reply.body = .renameReply(PfsRenameReply())
                    break
                }
                fromDirectory.children.removeValue(forKey: request.fromName)
                if let replacedID, replacedID != childID, let replaced = nodes[replacedID] {
                    replaced.nlink = replaced.nlink > 0 ? replaced.nlink - 1 : 0
                    reapIfUnlinked(nodeID: replacedID)
                }
                toDirectory.children[request.toName] = childID
                nodes[childID]?.parent = toDirectory.id
                bump(fromDirectory)
                bump(toDirectory)
                reply.body = .renameReply(PfsRenameReply())
            case let .symlink(request):
                let directory = try node(for: request.dir)
                guard directory.children[request.name] == nil else {
                    throw MockPOSIXError(errno: EEXIST, message: "exists")
                }
                let node = createNode(kind: .symlink, mode: 0o777, parent: directory.id)
                node.symlinkTarget = request.target
                node.data = request.target
                directory.children[request.name] = node.id
                bump(directory)
                var response = PfsSymlinkReply()
                response.attr = attr(for: node)
                reply.body = .symlinkReply(response)
            case let .readlink(request):
                let node = try node(for: request.item)
                guard node.kind == .symlink else {
                    throw MockPOSIXError(errno: EINVAL, message: "not a symlink")
                }
                var response = PfsReadlinkReply()
                response.target = node.symlinkTarget
                reply.body = .readlinkReply(response)
            case let .hardLink(request):
                let item = try node(for: request.item)
                let directory = try node(for: request.dir)
                guard item.kind != .directory else {
                    throw MockPOSIXError(errno: EPERM, message: "hard links to directories are not permitted")
                }
                guard directory.children[request.name] == nil else {
                    throw MockPOSIXError(errno: EEXIST, message: "exists")
                }
                item.nlink += 1
                directory.children[request.name] = item.id
                bump(directory)
                var response = PfsHardLinkReply()
                response.name = request.name
                response.attr = attr(for: item, parent: directory)
                reply.body = .hardLinkReply(response)
            case let .xattrGet(request):
                let node = try node(for: request.item, handle: request.handle)
                guard let value = node.xattrs[request.name] else {
                    throw MockPOSIXError(errno: ENOATTR, message: "xattr not found")
                }
                var response = PfsXattrGetReply()
                response.value = value
                reply.body = .xattrGetReply(response)
            case let .xattrSet(request):
                let node = try node(for: request.item, handle: request.handle)
                let exists = node.xattrs[request.name] != nil
                if request.createOnly && exists {
                    throw MockPOSIXError(errno: EEXIST, message: "xattr exists")
                }
                if request.replaceOnly && !exists {
                    throw MockPOSIXError(errno: ENOATTR, message: "xattr missing")
                }
                node.xattrs[request.name] = request.value
                reply.body = .xattrSetReply(PfsXattrSetReply())
            case let .xattrList(request):
                let node = try node(for: request.item, handle: request.handle)
                var response = PfsXattrListReply()
                response.names = node.xattrs.keys.sorted()
                reply.body = .xattrListReply(response)
            case let .xattrRemove(request):
                let node = try node(for: request.item, handle: request.handle)
                guard node.xattrs.removeValue(forKey: request.name) != nil else {
                    throw MockPOSIXError(errno: ENOATTR, message: "xattr missing")
                }
                reply.body = .xattrRemoveReply(PfsXattrRemoveReply())
            case .statfs:
                var response = PfsStatfsReply()
                response.blockSize = 4096
                response.totalBlocks = 1_000_000
                response.freeBlocks = 750_000
                response.totalFiles = 1_000_000
                response.freeFiles = 900_000
                reply.body = .statfsReply(response)
            case .syncVolume:
                reply.body = .syncVolumeReply(PfsSyncVolumeReply())
            case .fsync:
                reply.body = .fsyncReply(PfsFsyncReply())
            case let .reclaim(request):
                _ = try node(for: request.item)
                reply.body = .reclaimReply(PfsReclaimReply())
            case .subscribeEvents:
                session.setSubscribed()
                reply.body = .subscribeEventsReply(PfsSubscribeEventsReply())
            case .publicationAck:
                // One-way publication completion; requestID zero keeps the
                // empty mock envelope outside the request multiplexer.
                publicationAcks += 1
                break
            case .helloReply, .resolveReply, .lookupReply, .enumerateReply, .getAttrReply,
                 .setAttrReply, .openReply, .closeReply, .readReply, .writeReply,
                 .createReply, .mkdirReply, .removeReply, .renameReply, .symlinkReply,
                 .readlinkReply, .xattrGetReply, .xattrSetReply, .xattrListReply,
                 .xattrRemoveReply, .statfsReply, .fsyncReply, .reclaimReply,
                 .subscribeEventsReply, .hardLinkReply, .syncVolumeReply, .error, .event:
                throw MockPOSIXError(errno: EINVAL, message: "daemon received reply body")
            }
        } catch let error as MockPOSIXError {
            var errorReply = PfsErrorReply()
            errorReply.errno = error.errno
            errorReply.message = error.message
            reply.body = .error(errorReply)
        } catch {
            var errorReply = PfsErrorReply()
            errorReply.errno = EIO
            errorReply.message = String(describing: error)
            reply.body = .error(errorReply)
        }
        return reply
    }

    private func node(for item: PfsItem) throws -> Node {
        guard let node = nodes[item.itemID], node.generation == item.itemGeneration else {
            throw MockPOSIXError(errno: ESTALE, message: "stale item")
        }
        return node
    }

    private func node(for item: PfsItem, handle: UInt64) throws -> Node {
        guard handle != 0 else {
            return try namespaceNode(for: item)
        }
        let retained = try node(forHandle: handle)
        guard retained.id == item.itemID, retained.generation == item.itemGeneration else {
            throw MockPOSIXError(errno: EINVAL, message: "handle does not belong to item")
        }
        return retained
    }

    private func namespaceNode(for item: PfsItem) throws -> Node {
        let node = try node(for: item)
        if configuration.strictItemNamespace && node.nlink == 0 {
            throw MockPOSIXError(errno: ENOENT, message: "item is detached from the namespace")
        }
        return node
    }

    private func node(forHandle handle: UInt64) throws -> Node {
        guard let id = handles[handle], let node = nodes[id] else {
            throw MockPOSIXError(errno: EBADF, message: "bad handle")
        }
        return node
    }

    private func reapIfUnlinked(nodeID: UInt64) {
        guard let node = nodes[nodeID], node.nlink == 0 else {
            return
        }
        if handles.values.contains(nodeID) {
            return
        }
        nodes.removeValue(forKey: nodeID)
    }

    private func createNode(kind: PfsItemKind, mode: UInt32, parent: UInt64) -> Node {
        let node = Node(id: nextNodeID, kind: kind, mode: mode, parent: parent)
        nextNodeID += 1
        nodes[node.id] = node
        return node
    }

    private func liveParent(for node: Node) -> Node? {
        guard node.id != rootIdentity().itemID else {
            return nil
        }
        return nodes.values
            .filter { candidate in
                candidate.kind == .directory &&
                    candidate.children.values.contains(node.id)
            }
            .min { lhs, rhs in lhs.id < rhs.id }
    }

    private func attr(for node: Node, parent explicitParent: Node? = nil) -> PfsAttr {
        var attr = PfsAttr()
        attr.item = node.item
        if let parent = explicitParent ?? liveParent(for: node) {
            attr.parent = parent.item
        }
        attr.kind = node.kind
        attr.mode = node.mode
        attr.nlink = node.nlink
        attr.uid = node.uid
        attr.gid = node.gid
        attr.size = UInt64(node.kind == .symlink ? node.symlinkTarget.count : node.data.count)
        attr.allocSize = attr.size
        attr.mtimeMs = node.mtimeMs
        attr.ctimeMs = node.ctimeMs
        attr.atimeMs = node.atimeMs
        attr.birthtimeMs = node.birthtimeMs
        attr.contentVersion = node.contentVersion
        attr.flags = node.flags
        return attr
    }

    private func resize(node: Node, size: Int) {
        if node.data.count < size {
            node.data.append(Data(repeating: 0, count: size - node.data.count))
        } else if node.data.count > size {
            node.data.removeSubrange(size..<node.data.count)
        }
        bump(node)
    }

    private func write(node: Node, offset: Int, data: Data) {
        if node.data.count < offset {
            node.data.append(Data(repeating: 0, count: offset - node.data.count))
        }
        let end = offset + data.count
        if node.data.count < end {
            node.data.append(Data(repeating: 0, count: end - node.data.count))
        }
        node.data.replaceSubrange(offset..<end, with: data)
        bump(node)
    }

    private func bump(_ node: Node) {
        let now = nowMs()
        node.mtimeMs = now
        node.ctimeMs = now
        node.contentVersion += 1
    }

    private func nowMs() -> Int64 {
        Int64(Date().timeIntervalSince1970 * 1000)
    }

    /// A node is graft-backed when its name matches a configured graft rule.
    /// The real daemon knows this from its routing table; the mock recovers the
    /// name from the parent's directory map so no rename path has to keep a
    /// second copy of it in sync.
    private func isGraftBacked(_ node: Node) -> Bool {
        if configuration.graftBackedNames.isEmpty {
            return false
        }
        guard let parentID = node.parent, let directory = nodes[parentID] else {
            return false
        }
        for (name, id) in directory.children where id == node.id {
            if configuration.graftBackedNames.contains(displayName(name)) {
                return true
            }
        }
        return false
    }

    private func displayName(_ data: Data) -> String {
        String(data: data, encoding: .utf8) ?? data.map { String(format: "%02x", $0) }.joined()
    }

    /// The directory's total enumeration order: ascending name cursor, ties
    /// broken by name, with equal cursors perturbed upward so every entry has a
    /// unique strictly increasing resumption key.
    private func orderedChildren(of directory: Node) -> [(name: Data, cursor: UInt64)] {
        var ordered = directory.children.keys.map { (name: $0, cursor: enumerationCursor($0)) }
        ordered.sort { lhs, rhs in
            if lhs.cursor != rhs.cursor {
                return lhs.cursor < rhs.cursor
            }
            return displayName(lhs.name) < displayName(rhs.name)
        }
        for index in 1..<max(ordered.count, 1) where ordered[index].cursor <= ordered[index - 1].cursor {
            ordered[index].cursor = ordered[index - 1].cursor + 1
        }
        return ordered
    }

    private func enumerationCursor(_ name: Data) -> UInt64 {
        var hash: UInt64 = 0xcbf2_9ce4_8422_2325
        for byte in name {
            hash ^= UInt64(byte)
            hash = hash &* 0x0000_0100_0000_01b3
        }
        return 1 + hash % Self.cursorSpace
    }

    private func encodeCookie(cursor: UInt64) -> UInt64 {
        Self.daemonCookieMarker | (cursor << 2) | Self.cookieTagCursor
    }

    /// Returns the resume cursor for a cookie. Foreign cookies fail with
    /// ESTALE, the daemon's documented fail-safe; cookies this daemon issued
    /// always resolve.
    private func decodeCookie(_ cookie: UInt64) throws -> UInt64 {
        if cookie == 0 {
            return 0
        }
        guard (cookie & Self.daemonCookieMarker) != 0,
              (cookie & Self.cookieTagMask) == Self.cookieTagCursor
        else {
            throw MockPOSIXError(errno: ESTALE, message: "invalid directory cookie")
        }
        let cursor = (cookie & ~Self.daemonCookieMarker) >> 2
        guard cursor != 0 else {
            throw MockPOSIXError(errno: ESTALE, message: "invalid directory cookie")
        }
        return cursor
    }
}
