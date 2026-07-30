import Foundation
import PortableFSKit
@preconcurrency import Darwin

public final class PfsLocalMockDaemon: @unchecked Sendable {
    public struct Stats: Sendable, Equatable {
        public var openRequests: Int
        public var closeRequests: Int
        public var activeHandles: Int
        public var enumerateRequests: Int
        public var getAttrRequests: Int
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

        public init(
            attachRef: String = "mock",
            volumeID: String = "mock-volume",
            volumeName: String = "PortableFS Mock",
            branch: String = "main",
            lookupDelaysNanoseconds: [String: UInt64] = [:],
            lookupNoReplyNames: Set<String> = []
        ) {
            self.attachRef = attachRef
            self.volumeID = volumeID
            self.volumeName = volumeName
            self.branch = branch
            self.lookupDelaysNanoseconds = lookupDelaysNanoseconds
            self.lookupNoReplyNames = lookupNoReplyNames
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
        guard !stopped else {
            return
        }
        stopped = true
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
        while !stopped && acceptWorkItem?.isCancelled != true {
            do {
                let clientFD = try PfsUnixSocket.accept(serverFD)
                if stopped || acceptWorkItem?.isCancelled == true {
                    PfsUnixSocket.close(clientFD)
                    return
                }
                let session = MockSession(fd: clientFD)
                addSession(session)
                clientQueue.async { [weak self, session] in
                    self?.clientLoop(session: session)
                }
            } catch {
                if !stopped {
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
        while !stopped {
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
    private let writeLock = NSLock()
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
        writeLock.lock()
        defer { writeLock.unlock() }
        guard !closed else {
            throw PfsLocalClientError.connectionClosed
        }
        try PfsMockFrameIO.writeFrame(fd: fd, envelope: envelope)
    }

    func close() {
        stateLock.lock()
        let shouldClose = !closed
        closed = true
        stateLock.unlock()
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
    private static let daemonCookieMarker: UInt64 = 1 << 63

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
    private var enumerateRequests = 0
    private var getAttrRequests = 0
    private var maxReadLength: UInt32 = 0
    private var maxWriteLength = 0
    private var publicationAcks = 0

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
            enumerateRequests: enumerateRequests,
            getAttrRequests: getAttrRequests,
            maxReadLength: maxReadLength,
            maxWriteLength: maxWriteLength,
            publicationAcks: publicationAcks
        )
    }

    func resetStats() {
        openRequests = 0
        closeRequests = 0
        enumerateRequests = 0
        getAttrRequests = 0
        maxReadLength = 0
        maxWriteLength = 0
        publicationAcks = 0
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
            switch body {
            case let .hello(request):
                var response = PfsHelloReply()
                response.protocolMajor = request.protocolMajor
                response.protocolMinor = request.protocolMinor
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
                response.attr = attr(for: child)
                reply.body = .lookupReply(response)
            case let .enumerate(request):
                enumerateRequests += 1
                let directory = try node(for: request.dir)
                guard directory.kind == .directory else {
                    throw MockPOSIXError(errno: ENOTDIR, message: "not a directory")
                }
                let sorted = directory.children.keys.sorted { lhs, rhs in
                    displayName(lhs) < displayName(rhs)
                }
                let start = try decodeCookie(request.cookie)
                guard start <= sorted.count else {
                    throw MockPOSIXError(errno: EINVAL, message: "invalid cookie")
                }
                let maxEntries = max(1, Int(request.maxEntries))
                let end = min(sorted.count, start + maxEntries)
                var response = PfsEnumerateReply()
                for (offset, name) in sorted[start..<end].enumerated() {
                    if let childID = directory.children[name], let child = nodes[childID] {
                        let absoluteIndex = start + offset
                        var entry = PfsDirEntry()
                        entry.name = name
                        entry.attr = attr(for: child)
                        entry.cookie = absoluteIndex + 1 >= sorted.count ? 0 : encodeCookie(position: absoluteIndex + 1)
                        response.entries.append(entry)
                    }
                }
                response.nextCookie = response.entries.last?.cookie ?? 0
                response.dirVersion = directory.contentVersion
                reply.body = .enumerateReply(response)
            case let .getAttr(request):
                getAttrRequests += 1
                var response = PfsGetAttrReply()
                response.attr = attr(for: try node(for: request.item))
                reply.body = .getAttrReply(response)
            case let .setAttr(request):
                let node = try node(for: request.item)
                if request.hasMode { node.mode = request.mode }
                if request.hasUid { node.uid = request.uid }
                if request.hasGid { node.gid = request.gid }
                if request.hasSize { resize(node: node, size: Int(request.size)) }
                if request.hasMtimeMs { node.mtimeMs = request.mtimeMs }
                if request.hasAtimeMs { node.atimeMs = request.atimeMs }
                node.ctimeMs = nowMs()
                var response = PfsSetAttrReply()
                response.attr = attr(for: node)
                reply.body = .setAttrReply(response)
            case let .open(request):
                _ = try node(for: request.item)
                openRequests += 1
                let handle = nextHandle
                nextHandle += 1
                handles[handle] = request.item.itemID
                var response = PfsOpenReply()
                response.handle = handle
                reply.body = .openReply(response)
            case let .close(request):
                closeRequests += 1
                if let nodeID = handles.removeValue(forKey: request.handle) {
                    reapIfUnlinked(nodeID: nodeID)
                }
                reply.body = .closeReply(PfsCloseReply())
            case let .read(request):
                maxReadLength = max(maxReadLength, request.length)
                let node = try node(forHandle: request.handle)
                let offset = min(Int(request.offset), node.data.count)
                let end = min(node.data.count, offset + Int(request.length))
                var response = PfsReadReply()
                response.data = node.data.subdata(in: offset..<end)
                reply.body = .readReply(response)
            case let .write(request):
                maxWriteLength = max(maxWriteLength, request.data.count)
                let node = try node(forHandle: request.handle)
                write(node: node, offset: Int(request.offset), data: request.data)
                var response = PfsWriteReply()
                response.written = UInt32(request.data.count)
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
                response.attr = attr(for: item)
                reply.body = .hardLinkReply(response)
            case let .xattrGet(request):
                let node = try node(for: request.item)
                guard let value = node.xattrs[request.name] else {
                    throw MockPOSIXError(errno: ENOATTR, message: "xattr not found")
                }
                var response = PfsXattrGetReply()
                response.value = value
                reply.body = .xattrGetReply(response)
            case let .xattrSet(request):
                let node = try node(for: request.item)
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
                let node = try node(for: request.item)
                var response = PfsXattrListReply()
                response.names = node.xattrs.keys.sorted()
                reply.body = .xattrListReply(response)
            case let .xattrRemove(request):
                let node = try node(for: request.item)
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

    private func attr(for node: Node) -> PfsAttr {
        var attr = PfsAttr()
        attr.item = node.item
        attr.kind = node.kind
        attr.mode = node.mode
        attr.nlink = node.nlink
        attr.uid = node.uid
        attr.gid = node.gid
        attr.size = UInt64(node.kind == .symlink ? node.symlinkTarget.count : node.data.count)
        attr.mtimeMs = node.mtimeMs
        attr.ctimeMs = node.ctimeMs
        attr.atimeMs = node.atimeMs
        attr.birthtimeMs = node.birthtimeMs
        attr.contentVersion = node.contentVersion
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

    private func displayName(_ data: Data) -> String {
        String(data: data, encoding: .utf8) ?? data.map { String(format: "%02x", $0) }.joined()
    }

    private func encodeCookie(position: Int) -> UInt64 {
        Self.daemonCookieMarker | UInt64(position)
    }

    private func decodeCookie(_ cookie: UInt64) throws -> Int {
        if cookie == 0 {
            return 0
        }
        guard (cookie & Self.daemonCookieMarker) != 0 else {
            throw MockPOSIXError(errno: EINVAL, message: "invalid cookie")
        }
        return Int(cookie & ~Self.daemonCookieMarker)
    }
}
