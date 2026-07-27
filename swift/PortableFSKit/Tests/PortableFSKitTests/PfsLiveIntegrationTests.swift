import CryptoKit
import Foundation
import Testing
@testable import PortableFSKit
@preconcurrency import Darwin

private enum PfsLiveIntegrationError: Error, CustomStringConvertible {
    case missingEnvironment(String)
    case commandFailed(String)
    case timedOut(String)

    var description: String {
        switch self {
        case let .missingEnvironment(name):
            return "missing required live integration environment variable \(name)"
        case let .commandFailed(message):
            return message
        case let .timedOut(message):
            return message
        }
    }
}

private struct LiveControlClient {
    var socketPath: String
    var attachRef: String

    private var escapedAttachRef: String {
        var allowed = CharacterSet.urlPathAllowed
        allowed.remove(charactersIn: "/")
        return attachRef.addingPercentEncoding(withAllowedCharacters: allowed) ?? attachRef
    }

    func healthz() throws {
        _ = try request(method: "GET", path: "/healthz", body: nil)
    }

    func attachStatus() throws -> (state: String, lastError: String) {
        let data = try request(method: "GET", path: "/v1/attaches/\(escapedAttachRef)", body: nil)
        let object = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        return (
            object?["state"] as? String ?? "",
            object?["lastError"] as? String ?? ""
        )
    }

    /// True once the daemon reports the attach as removed (HTTP 404).
    func attachIsGone() -> Bool {
        do {
            _ = try attachStatus()
            return false
        } catch let error as PfsLiveIntegrationError {
            return String(describing: error).contains("HTTP 404")
        } catch {
            return false
        }
    }

    func ensureAttach(
        volumeID: String,
        branch: String,
        authorityURL: String,
        authToken: String,
        mountPath: String
    ) throws -> String {
        let data = try post(
            "/v1/attaches",
            json: [
                "volumeId": volumeID,
                "branch": branch,
                "authorityUrl": authorityURL,
                "authToken": authToken,
                "mountPath": mountPath,
                "options": [
                    "writePolicy": "writethrough",
                    "fsyncPolicy": "local",
                    "negativeCache": true,
                    "diskCacheMb": 1
                ]
            ]
        )
        let object = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        guard let attachRef = object?["attachRef"] as? String, !attachRef.isEmpty else {
            throw PfsLiveIntegrationError.commandFailed("POST /v1/attaches returned no attachRef")
        }
        return attachRef
    }

    func post(_ path: String, json body: [String: Any]) throws -> Data {
        let data = try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys])
        return try request(method: "POST", path: path, body: data)
    }

    func deleteAttach() throws {
        _ = try request(method: "DELETE", path: "/v1/attaches/\(escapedAttachRef)", body: nil)
    }

    func renewCredential() throws {
        _ = try post("/v1/attaches/\(escapedAttachRef)/credential", json: ["authToken": "live-renewed-token"])
    }

    func fsWrite(path: String, data: Data) throws {
        _ = try post(
            "/v1/attaches/\(escapedAttachRef)/fs/write",
            json: ["path": path, "dataBase64": data.base64EncodedString()]
        )
    }

    private func request(method: String, path: String, body: Data?) throws -> Data {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
        var arguments = [
            "--silent",
            "--show-error",
            "--unix-socket",
            socketPath,
            "-X",
            method,
            "--write-out",
            "\nPFS_HTTP_STATUS:%{http_code}"
        ]
        let inputPipe: Pipe?
        if body != nil {
            arguments.append(contentsOf: ["-H", "Content-Type: application/json", "--data-binary", "@-"])
            inputPipe = Pipe()
            process.standardInput = inputPipe
        } else {
            inputPipe = nil
        }
        arguments.append("http://portablefsd\(path)")
        process.arguments = arguments

        let outputPipe = Pipe()
        let errorPipe = Pipe()
        process.standardOutput = outputPipe
        process.standardError = errorPipe
        try process.run()
        if let body, let inputPipe {
            inputPipe.fileHandleForWriting.write(body)
            try? inputPipe.fileHandleForWriting.close()
        }
        process.waitUntilExit()

        let output = outputPipe.fileHandleForReading.readDataToEndOfFile()
        let stderr = String(data: errorPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        guard process.terminationStatus == 0 else {
            throw PfsLiveIntegrationError.commandFailed(
                "curl \(method) \(path) exited \(process.terminationStatus): \(stderr)"
            )
        }
        let marker = Data("\nPFS_HTTP_STATUS:".utf8)
        guard let markerRange = output.range(of: marker, options: [.backwards]) else {
            throw PfsLiveIntegrationError.commandFailed("curl \(method) \(path) returned no HTTP status: \(stderr)")
        }
        let body = output[..<markerRange.lowerBound]
        let statusBytes = output[markerRange.upperBound...]
        let statusText = String(data: Data(statusBytes), encoding: .utf8) ?? ""
        let status = Int(statusText.trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
        guard (200..<300).contains(status) else {
            let bodyText = String(data: Data(body), encoding: .utf8) ?? "<non-UTF8 body>"
            throw PfsLiveIntegrationError.commandFailed("curl \(method) \(path) HTTP \(status): \(bodyText)")
        }
        return Data(body)
    }
}

private final class LivePortableFSDProcess {
    let process: Process
    private let logHandle: FileHandle?

    init(process: Process, logHandle: FileHandle?) {
        self.process = process
        self.logHandle = logHandle
    }

    deinit {
        stop()
    }

    func stop() {
        if process.isRunning {
            process.terminate()
            Thread.sleep(forTimeInterval: 0.2)
            if process.isRunning {
                Darwin.kill(process.processIdentifier, SIGKILL)
            }
        }
        process.waitUntilExit()
        try? logHandle?.close()
    }
}

private actor LiveEventCollector {
    private var events: [PfsEvent] = []

    init(stream: AsyncStream<PfsEvent>) {
        Task {
            for await event in stream {
                await append(event)
            }
        }
    }

    func append(_ event: PfsEvent) {
        events.append(event)
    }

    func pop(matching predicate: @Sendable (PfsEvent) -> Bool) -> PfsEvent? {
        guard let index = events.firstIndex(where: predicate) else {
            return nil
        }
        return events.remove(at: index)
    }
}

private func waitForLiveEvent(
    _ collector: LiveEventCollector,
    description: String,
    timeoutNanoseconds: UInt64 = 10_000_000_000,
    matching predicate: @escaping @Sendable (PfsEvent) -> Bool
) async throws -> PfsEvent {
    let start = Date()
    let timeout = TimeInterval(Double(timeoutNanoseconds) / 1_000_000_000)
    while Date().timeIntervalSince(start) < timeout {
        if let event = await collector.pop(matching: predicate) {
            return event
        }
        try await Task.sleep(nanoseconds: 50_000_000)
    }
    throw PfsLiveIntegrationError.timedOut("timed out waiting for \(description)")
}

private func withLiveTimeout<T: Sendable>(
    _ description: String,
    seconds: TimeInterval,
    operation: @escaping @Sendable () async throws -> T
) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask {
            try await operation()
        }
        group.addTask {
            try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
            throw PfsLiveIntegrationError.timedOut("timed out waiting for \(description)")
        }
        let result = try await group.next()
        group.cancelAll()
        return try #require(result)
    }
}

private func waitForControlHealth(_ control: LiveControlClient, timeoutSeconds: TimeInterval = 10) async throws {
    let start = Date()
    while Date().timeIntervalSince(start) < timeoutSeconds {
        do {
            try control.healthz()
            return
        } catch {
            try await Task.sleep(nanoseconds: 100_000_000)
        }
    }
    throw PfsLiveIntegrationError.timedOut("timed out waiting for restarted portablefsd control socket")
}

private func killPortableFSD(pidString: String) throws {
    guard let pid = Int32(pidString) else {
        throw PfsLiveIntegrationError.missingEnvironment("valid PFS_LIVE_PORTABLEFSD_PID")
    }
    if Darwin.kill(pid, SIGKILL) != 0, errno != ESRCH {
        throw PfsLocalClientError.system(errno: errno, operation: "kill portablefsd")
    }
}

private func startPortableFSD(
    binaryPath: String,
    frontendSocket: String,
    controlSocket: String,
    stateDir: String,
    logPath: String
) throws -> LivePortableFSDProcess {
    FileManager.default.createFile(atPath: logPath, contents: nil)
    let logHandle = try FileHandle(forWritingTo: URL(fileURLWithPath: logPath))
    let process = Process()
    process.executableURL = URL(fileURLWithPath: binaryPath)
    process.arguments = [
        "-frontend-socket",
        frontendSocket,
        "-control-socket",
        controlSocket,
        "-state-dir",
        stateDir
    ]
    process.standardOutput = logHandle
    process.standardError = logHandle
    try process.run()
    return LivePortableFSDProcess(process: process, logHandle: logHandle)
}

private func liveBytes(_ string: String) -> Data {
    Data(string.utf8)
}

private func deterministicLivePayload(size: Int) -> Data {
    var payload = Data(count: size)
    payload.withUnsafeMutableBytes { rawBuffer in
        let bytes = rawBuffer.bindMemory(to: UInt8.self)
        for index in bytes.indices {
            bytes[index] = UInt8(truncatingIfNeeded: (index &* 31) &+ 17)
        }
    }
    return payload
}

private func sha256Hex(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

private func assertThrowsPOSIX(_ expectedErrno: Int32, _ operation: () async throws -> Void) async {
    do {
        try await operation()
        Issue.record("expected POSIX errno \(expectedErrno)")
    } catch {
        let mapped = PfsErrorMapper.fsKitError(for: error)
        #expect(mapped.code == Int(expectedErrno))
    }
}

private func printLivePass(_ name: String) {
    print("PFS_LIVE_MATRIX \(name) PASS")
}

private func printLiveFail(_ name: String, _ error: Error) {
    print("PFS_LIVE_MATRIX \(name) FAIL \(error)")
}

private func expectPromptPOSIX(
    _ expectedErrno: Int32,
    description: String,
    maxSeconds: TimeInterval = 5,
    operation: @escaping @Sendable () async throws -> Void
) async {
    let start = Date()
    do {
        try await withLiveTimeout(description, seconds: maxSeconds, operation: operation)
        Issue.record("expected \(description) to fail with POSIX errno \(expectedErrno)")
    } catch let error as PfsLiveIntegrationError {
        Issue.record("\(description) did not fail promptly: \(error)")
    } catch {
        let elapsed = Date().timeIntervalSince(start)
        let mapped = PfsErrorMapper.fsKitError(for: error)
        #expect(mapped.code == Int(expectedErrno))
        #expect(elapsed < maxSeconds)
    }
}

private func assertAttachRefRevival(
    environment: [String: String],
    control: LiveControlClient,
    core: VolumeCore,
    collector: LiveEventCollector,
    root: PortableFSItem,
    attachRef: String,
    frontendSocket: String,
    controlSocket: String
) async throws -> LivePortableFSDProcess {
    guard let pid = environment["PFS_LIVE_PORTABLEFSD_PID"] else {
        throw PfsLiveIntegrationError.missingEnvironment("PFS_LIVE_PORTABLEFSD_PID")
    }
    guard let binary = environment["PFS_LIVE_PORTABLEFSD_BIN"] else {
        throw PfsLiveIntegrationError.missingEnvironment("PFS_LIVE_PORTABLEFSD_BIN")
    }
    guard let stateDir = environment["PFS_LIVE_PORTABLEFSD_STATE_DIR"] else {
        throw PfsLiveIntegrationError.missingEnvironment("PFS_LIVE_PORTABLEFSD_STATE_DIR")
    }
    guard let restartLog = environment["PFS_LIVE_PORTABLEFSD_RESTART_LOG"] else {
        throw PfsLiveIntegrationError.missingEnvironment("PFS_LIVE_PORTABLEFSD_RESTART_LOG")
    }
    guard let authorityURL = environment["PFS_LIVE_AUTHORITY_URL"] else {
        throw PfsLiveIntegrationError.missingEnvironment("PFS_LIVE_AUTHORITY_URL")
    }
    guard let volumeID = environment["PFS_LIVE_VOLUME_ID"] else {
        throw PfsLiveIntegrationError.missingEnvironment("PFS_LIVE_VOLUME_ID")
    }
    guard let branch = environment["PFS_LIVE_BRANCH"] else {
        throw PfsLiveIntegrationError.missingEnvironment("PFS_LIVE_BRANCH")
    }
    guard let mountPath = environment["PFS_LIVE_MOUNT_PATH"] else {
        throw PfsLiveIntegrationError.missingEnvironment("PFS_LIVE_MOUNT_PATH")
    }

    try killPortableFSD(pidString: pid)
    try await Task.sleep(nanoseconds: 250_000_000)
    let restarted = try startPortableFSD(
        binaryPath: binary,
        frontendSocket: frontendSocket,
        controlSocket: controlSocket,
        stateDir: stateDir,
        logPath: restartLog
    )
    do {
        try await waitForControlHealth(control)

        await expectPromptPOSIX(EIO, description: "credential-pending lookup after daemon restart") {
            _ = try await core.lookup(in: root, name: liveBytes("lookup-seed.txt"))
        }
        let degraded = try await waitForLiveEvent(collector, description: "degraded state after credential-pending revive") { event in
            if case let .attachState(state)? = event.kind {
                return state.state == .degraded
            }
            return false
        }
        if case let .attachState(state)? = degraded.kind {
            #expect(state.state == .degraded)
            #expect(!state.detail.isEmpty)
        }
        let pending = try control.attachStatus()
        #expect(pending.state == "degraded")
        #expect(!pending.lastError.isEmpty)
        printLivePass("attach_ref_restart_credential_pending")

        let revivedRef = try control.ensureAttach(
            volumeID: volumeID,
            branch: branch,
            authorityURL: authorityURL,
            authToken: "",
            mountPath: mountPath
        )
        #expect(revivedRef == attachRef)
        let recovered = try await withLiveTimeout("post-revival lookup", seconds: 5) {
            try await core.lookup(in: root, name: liveBytes("lookup-seed.txt"))
        }
        #expect(recovered.attr.kind == .file)
        #expect(recovered.attr.size == 4)
        let attached = try control.attachStatus()
        #expect(attached.state == "attached")
        #expect(attached.lastError.isEmpty)
        printLivePass("attach_ref_same_ref_revival_recovery")
        return restarted
    } catch {
        restarted.stop()
        throw error
    }
}

@Test func PfsLiveIntegration_fullMatrixAgainstRealPortablefsd() async throws {
    let environment = ProcessInfo.processInfo.environment
    guard environment["PFS_LIVE"] == "1" else {
        return
    }
    guard let frontendSocket = environment["PFS_LIVE_FRONTEND_SOCKET"] else {
        throw PfsLiveIntegrationError.missingEnvironment("PFS_LIVE_FRONTEND_SOCKET")
    }
    guard let controlSocket = environment["PFS_LIVE_CONTROL_SOCKET"] else {
        throw PfsLiveIntegrationError.missingEnvironment("PFS_LIVE_CONTROL_SOCKET")
    }
    guard let attachRef = environment["PFS_LIVE_ATTACH_REF"] else {
        throw PfsLiveIntegrationError.missingEnvironment("PFS_LIVE_ATTACH_REF")
    }

    let control = LiveControlClient(socketPath: controlSocket, attachRef: attachRef)
    let core = try await VolumeCore.connect(
        socketPath: frontendSocket,
        attachRef: attachRef,
        configuration: .init(
            maxReconnectAttempts: 10,
            reconnectBaseDelayNanoseconds: 50_000_000,
            requestDeadlineNanoseconds: 30_000_000_000,
            clientName: "swift-live",
            clientVersion: "1"
        )
    )
    defer {
        Task {
            await core.shutdown()
        }
    }

    let resolved = try #require(await core.resolvedVolume)
    #expect(resolved.capabilities.symlinks)
    #expect(!resolved.capabilities.xattrs)
    #expect(resolved.capabilities.caseSensitive)
    #expect(resolved.capabilities.preferredIoBytes > 0)
    let root = resolved.root
    printLivePass("hello_resolve")

    try control.fsWrite(path: "lookup-seed.txt", data: liveBytes("seed"))
    let seed = try await core.lookup(in: root, name: liveBytes("lookup-seed.txt"))
    #expect(seed.attr.kind == .file)
    #expect(seed.attr.size == 4)
    printLivePass("lookup")

    let pagedDirectory = try await core.mkdir(in: root, name: liveBytes("paged"), mode: 0o755)
    for index in 0..<1000 {
        let name = String(format: "entry-%04d", index)
        let created = try await core.createFile(in: pagedDirectory.item, name: liveBytes(name), mode: 0o644, exclusive: true)
        try await core.close(item: created.item)
    }
    let firstPage = try await core.enumerate(
        directory: pagedDirectory.item,
        startingAt: 0,
        wantAttributes: true,
        maxEntries: PfsEnumerationCookies.daemonPageSize
    )
    #expect(firstPage.entries.count == 256)
    // Daemon cookies are opaque continuation tokens; the only stable contract
    // is the high marker bit (and that mid-page resume from one works, below).
    #expect(PfsEnumerationCookies.isDaemonCookie(firstPage.entries[127].nextCookie))
    var enumerateRPCs = 1
    var names = Set(firstPage.entries.prefix(128).compactMap { String(data: $0.name, encoding: .utf8) })
    var cookie = firstPage.entries[127].nextCookie
    while cookie != 0 {
        let page = try await core.enumerate(
            directory: pagedDirectory.item,
            startingAt: cookie,
            wantAttributes: true,
            maxEntries: PfsEnumerationCookies.daemonPageSize
        )
        enumerateRPCs += 1
        for entry in page.entries {
            if let name = String(data: entry.name, encoding: .utf8) {
                names.insert(name)
            }
        }
        cookie = page.nextCookie
    }
    #expect(names.count == 1000)
    #expect(enumerateRPCs == 5)
    print("PFS_LIVE_ENUMERATE_RPCS \(enumerateRPCs)")
    printLivePass("enumerate_1000_midpage_resume")

    let large = try await core.createFile(in: root, name: liveBytes("large.bin"), mode: 0o644, exclusive: true)
    let payload = deterministicLivePayload(size: 20 * 1024 * 1024)
    let written = try await core.write(item: large.item, offset: 0, data: payload)
    #expect(written.written == UInt32(payload.count))
    let readBack = try await core.read(item: large.item, offset: 0, length: UInt32(payload.count))
    #expect(readBack.count == payload.count)
    #expect(sha256Hex(readBack) == sha256Hex(payload))
    try await core.close(item: large.item)
    printLivePass("create_write_read_20mib_hash")

    try await core.rename(
        item: large.item,
        from: root,
        sourceName: liveBytes("large.bin"),
        to: root,
        destinationName: liveBytes("large-renamed.bin"),
        noReplace: true
    )
    let renamed = try await core.lookup(in: root, name: liveBytes("large-renamed.bin"))
    #expect(renamed.attr.size == UInt64(payload.count))
    printLivePass("rename")

    let symlink = try await core.symlink(in: root, name: liveBytes("large-link"), target: liveBytes("large-renamed.bin"))
    #expect(try await core.readlink(item: symlink.item) == liveBytes("large-renamed.bin"))
    printLivePass("symlink_readlink")

    let stat = try await core.statfs()
    #expect(stat.freeBlocks > 0)
    #expect(stat.blockSize > 0)
    printLivePass("statfs")

    await assertThrowsPOSIX(ENOTSUP) {
        _ = try await core.xattrList(item: renamed.item)
    }
    await assertThrowsPOSIX(ENOTSUP) {
        _ = try await core.xattrGet(item: renamed.item, name: "user.live")
    }
    await assertThrowsPOSIX(ENOTSUP) {
        try await core.xattrSet(item: renamed.item, name: "user.live", value: liveBytes("x"), createOnly: false, replaceOnly: false)
    }
    await assertThrowsPOSIX(ENOTSUP) {
        try await core.xattrRemove(item: renamed.item, name: "user.live")
    }
    printLivePass("xattr_enotsup")

    if resolved.capabilities.hardLinks {
        let linkedName = try await core.hardLink(item: renamed.item, in: root, name: liveBytes("large-hard"))
        #expect(linkedName == liveBytes("large-hard"))
        let linked = try await core.lookup(in: root, name: linkedName)
        #expect(linked.item.identity == renamed.item.identity)
        #expect(linked.attr.nlink == 2)
        printLivePass("hardlink")
    } else {
        // A daemon connected to a pre-hard-link authority must negotiate the
        // capability down and answer ENOTSUP without attempting the new op.
        await assertThrowsPOSIX(ENOTSUP) {
            _ = try await core.hardLink(item: renamed.item, in: root, name: liveBytes("large-hard"))
        }
        printLivePass("hardlink_enotsup_legacy_authority")
    }

    let handleCheck = try await core.createFile(in: root, name: liveBytes("handle-check.txt"), mode: 0o644, exclusive: true)
    try await core.close(item: handleCheck.item, retainingModes: .read)
    try await core.close(item: handleCheck.item)
    try await core.open(item: handleCheck.item, mode: .read)
    try await core.open(item: handleCheck.item, mode: .readWrite)
    try await core.close(item: handleCheck.item, retainingModes: .read)
    try await core.close(item: handleCheck.item)
    let handleDebug = await core.testingDebugState()
    #expect(handleDebug.openHandleCount == 0)
    printLivePass("open_close_balanced")

    try await core.reclaim(item: handleCheck.item)
    do {
        _ = try await core.getattr(item: handleCheck.item)
        Issue.record("expected reclaimed live item to become stale")
    } catch {
        #expect(PfsErrorMapper.fsKitError(for: error).code == Int(ESTALE))
    }
    printLivePass("reclaim")

    let stream = try await core.subscribeEvents()
    let collector = LiveEventCollector(stream: stream)
    try control.fsWrite(path: "external-event.txt", data: liveBytes("external"))
    do {
        let invalidation = try await waitForLiveEvent(collector, description: "invalidation from control fs/write") { event in
            if case let .invalidation(invalidation)? = event.kind {
                return invalidation.namespaceChanged || invalidation.contentChanged || invalidation.attrsChanged
            }
            return false
        }
        if case let .invalidation(details)? = invalidation.kind {
            #expect(details.namespaceChanged || details.contentChanged || details.attrsChanged)
        }
        printLivePass("subscribe_events_control_write_invalidation")
    } catch {
        Issue.record("control fs/write did not publish an invalidation event: \(error)")
        printLiveFail("subscribe_events_control_write_invalidation", error)
    }

    let restartedPortableFSD = try await assertAttachRefRevival(
        environment: environment,
        control: control,
        core: core,
        collector: collector,
        root: root,
        attachRef: attachRef,
        frontendSocket: frontendSocket,
        controlSocket: controlSocket
    )
    defer {
        restartedPortableFSD.stop()
    }

    try control.renewCredential()
    printLivePass("credential_renewal_noop")

    try control.deleteAttach()
    // The detaching AttachState event is best-effort: portablefsd's detach
    // path can close the frontend connection before the per-subscriber writer
    // drains the queued event. Accept either the event or the attach
    // disappearing from the control API as proof the detach happened.
    do {
        _ = try await withLiveTimeout("detach signal (event or control 404)", seconds: 10) {
            while true {
                if await collector.pop(matching: { event in
                    if case let .attachState(state)? = event.kind {
                        return state.state == .detaching
                    }
                    return false
                }) != nil {
                    return true
                }
                if control.attachIsGone() {
                    return true
                }
                try await Task.sleep(nanoseconds: 100_000_000)
            }
        }
        printLivePass("detach_event")
    } catch {
        Issue.record("detach produced neither a detaching event nor a control 404: \(error)")
        printLiveFail("detach_event", error)
    }

    do {
        _ = try await core.statfs()
        Issue.record("expected post-detach statfs to fail")
        printLiveFail("detach_connection_close", PfsLiveIntegrationError.commandFailed("statfs succeeded"))
    } catch {
        // ENXIO/EIO when the request hits the dying connection; ENOENT when
        // the client reconnected first and the daemon no longer knows the ref.
        let code = PfsErrorMapper.fsKitError(for: error).code
        #expect(code == Int(ENXIO) || code == Int(EIO) || code == Int(ENOENT))
        printLivePass("detach_connection_close")
    }
}
