import Darwin
import Foundation
import PortableFSKit
import Testing
@testable import PortableFSAppCore

@_silgen_name("flock")
private func serviceCoordinatorTestFlock(_ descriptor: Int32, _ operation: Int32) -> Int32

@Test func serviceCoordinatorDerivesEveryIdentityFromTheSignedHost() throws {
    let configuration = try PortableFSDServiceCoordinator.deriveConfiguration(
        bundleIdentifier: "dev.portablefs.PortableFSApp",
        teamIdentifier: "B47U2LLKHW",
        appGroupIdentifier: "B47U2LLKHW.pfsoss",
        shortVersion: "0.2.3",
        buildVersion: "42"
    )
    #expect(configuration.plistName == "dev.portablefs.PortableFSApp.portablefsd.plist")
    #expect(configuration.label == "dev.portablefs.PortableFSApp.portablefsd")
    #expect(configuration.serviceBundleIdentifier == "dev.portablefs.PortableFSApp.PortableFSDService")
    #expect(configuration.teamIdentifier == "B47U2LLKHW")
    #expect(configuration.appGroupIdentifier == "B47U2LLKHW.pfsoss")
    #expect(configuration.shortVersion == "0.2.3")
    #expect(configuration.buildVersion == "42")
}

@Test func serviceCoordinatorRejectsACrossTeamOrEmptyAppGroup() {
    #expect(throws: (any Error).self) {
        _ = try PortableFSDServiceCoordinator.deriveConfiguration(
            bundleIdentifier: "dev.portablefs.PortableFSApp",
            teamIdentifier: "B47U2LLKHW",
            appGroupIdentifier: "OTHERTEAM.pfsoss",
            shortVersion: "0.2.3",
            buildVersion: "42"
        )
    }
    #expect(throws: (any Error).self) {
        _ = try PortableFSDServiceCoordinator.deriveConfiguration(
            bundleIdentifier: "dev.portablefs.PortableFSApp",
            teamIdentifier: "B47U2LLKHW",
            appGroupIdentifier: "B47U2LLKHW.",
            shortVersion: "0.2.3",
            buildVersion: "42"
        )
    }
}

@Test func releaseIdentityContractUsesExactFrozenFieldsAndValues() throws {
    let identity = PortableFSDReleaseIdentity(
        codeDirectoryHash: String(repeating: "a", count: 40),
        executableSHA256: String(repeating: "b", count: 64),
        daemonVersion: "0.2.3",
        identitySchema: 1,
        controlProtocol: 1,
        pfslocalMajor: 1,
        pfslocalMinor: 16
    )
    try identity.validate()
    let object = try #require(
        JSONSerialization.jsonObject(with: JSONEncoder().encode(identity))
            as? [String: Any]
    )
    #expect(Set(object.keys) == [
        "codeDirectoryHash", "executableSHA256", "daemonVersion",
        "identitySchema", "controlProtocol", "pfslocalMajor", "pfslocalMinor",
    ])

    #expect(throws: (any Error).self) {
        try PortableFSDReleaseIdentity(
            codeDirectoryHash: String(repeating: "A", count: 40),
            executableSHA256: String(repeating: "b", count: 64),
            daemonVersion: "0.2.3",
            identitySchema: 1,
            controlProtocol: 1,
            pfslocalMajor: 1,
            pfslocalMinor: 16
        ).validate()
    }

    try PortableFSDReleaseIdentity(
        codeDirectoryHash: String(repeating: "a", count: 40),
        executableSHA256: String(repeating: "b", count: 64),
        daemonVersion: "0.2.3",
        identitySchema: 1,
        controlProtocol: 1,
        pfslocalMajor: 1,
        pfslocalMinor: 0
    ).validate()
}

@Test func failedRegistrationMustFenceAndSurfacesAnAmbiguousFenceFailure() {
    struct ExpectedFailure: LocalizedError {
        let name: String
        var errorDescription: String? { name }
    }

    var fenced = 0
    #expect(throws: ExpectedFailure.self) {
        try PortableFSDServiceCoordinator.completeRegisteredRelease(
            operation: { throw ExpectedFailure(name: "identity mismatch") },
            fence: { fenced += 1 }
        )
    }
    #expect(fenced == 1)

    do {
        try PortableFSDServiceCoordinator.completeRegisteredRelease(
            operation: { throw ExpectedFailure(name: "identity mismatch") },
            fence: { throw ExpectedFailure(name: "socket still present") }
        )
        Issue.record("registration unexpectedly succeeded")
    } catch {
        #expect(error.localizedDescription.contains("identity mismatch"))
        #expect(error.localizedDescription.contains("socket still present"))
        #expect(error.localizedDescription.contains("state is ambiguous"))
    }
}

@Test func serviceFenceRequiresAllThreeIndependentProofs() {
    for status in [false, true] {
        for paths in [false, true] {
            for process in [false, true] {
                #expect(
                    PortableFSDServiceCoordinator.serviceFenceReady(
                        statusNotRegistered: status,
                        runtimePathsAbsent: paths,
                        processDeparted: process
                    ) == (status && paths && process)
                )
            }
        }
    }
}

@Test func daemonOwnershipRequiresTheCanonicalNestedServicePath() throws {
    let suffix = "/Contents/Library/LaunchAgents/PortableFSDService.app/Contents/MacOS/portablefsd"
    for app in ["/Applications/PortableFS.app", "/tmp/build/PortableFSKitDev.app"] {
        #expect(try PortableFSDServiceCoordinator.daemonOwningBundle(
            executableURL: URL(fileURLWithPath: app + suffix)
        ).path == app)
    }
    for path in [
        "/tmp/portablefsd",
        "/Applications/PortableFS.app/Contents/MacOS/portablefsd",
        "/Applications/PortableFS.app/Contents/Library/LaunchAgents/Other.app/Contents/MacOS/portablefsd",
        "/Applications/PortableFS.app" + suffix + ".other",
        "/tmp/not-an-app" + suffix,
    ] {
        #expect(throws: (any Error).self) {
            try PortableFSDServiceCoordinator.daemonOwningBundle(
                executableURL: URL(fileURLWithPath: path)
            )
        }
    }
    let networkURL = try #require(URL(string: "https://example.com/PortableFS.app" + suffix))
    #expect(throws: (any Error).self) {
        try PortableFSDServiceCoordinator.daemonOwningBundle(executableURL: networkURL)
    }
}

@Test func serviceOwnershipAdmitsAReleaseUpdateWithinTheSameSignedProduct() throws {
    let incoming = try PortableFSDServiceCoordinator.deriveConfiguration(
        bundleIdentifier: "dev.portablefs.oss.KitDev",
        teamIdentifier: "B47U2LLKHW",
        appGroupIdentifier: "B47U2LLKHW.pfsoss",
        shortVersion: "0.4.1",
        buildVersion: "42"
    )
    let running = try PortableFSDServiceCoordinator.deriveConfiguration(
        bundleIdentifier: "dev.portablefs.oss.KitDev",
        teamIdentifier: "B47U2LLKHW",
        appGroupIdentifier: "B47U2LLKHW.pfsoss",
        shortVersion: "0.3.0",
        buildVersion: "1"
    )
    try PortableFSDServiceCoordinator.validateServiceOwner(running, expected: incoming)
}

@Test func serviceOwnershipRejectsOtherProductsTeamsAndAppGroups() throws {
    let expected = try PortableFSDServiceCoordinator.deriveConfiguration(
        bundleIdentifier: "dev.portablefs.oss.KitDev",
        teamIdentifier: "B47U2LLKHW",
        appGroupIdentifier: "B47U2LLKHW.pfsoss",
        shortVersion: "0.4.1",
        buildVersion: "42"
    )
    for (product, team, group) in [
        ("dev.portablefs.Other", "B47U2LLKHW", "B47U2LLKHW.pfsoss"),
        ("dev.portablefs.oss.KitDev", "OTHERTEAM", "OTHERTEAM.pfsoss"),
        ("dev.portablefs.oss.KitDev", "B47U2LLKHW", "B47U2LLKHW.other"),
    ] {
        let owner = try PortableFSDServiceCoordinator.deriveConfiguration(
            bundleIdentifier: product,
            teamIdentifier: team,
            appGroupIdentifier: group,
            shortVersion: "0.3.0",
            buildVersion: "1"
        )
        #expect(throws: (any Error).self) {
            try PortableFSDServiceCoordinator.validateServiceOwner(owner, expected: expected)
        }
    }
}

@Test func authenticatedOutgoingReleaseKeepsItsOwnLocalProtocol() throws {
    let sealed = PortableFSDReleaseIdentity(
        codeDirectoryHash: String(repeating: "a", count: 40),
        executableSHA256: String(repeating: "b", count: 64),
        daemonVersion: "0.3.0",
        identitySchema: 1,
        controlProtocol: 1,
        pfslocalMajor: 1,
        pfslocalMinor: 16
    )
    let reported = PortableFSDServiceCoordinator.LiveDaemonIdentity(
        schemaVersion: 1, controlProtocol: 1, daemonVersion: "0.3.0",
        executableSha256: sealed.executableSHA256, pfslocalMajor: 1, pfslocalMinor: 14
    )
    let running = try reported.releaseIdentity(sealed: sealed)
    #expect(running.codeDirectoryHash == sealed.codeDirectoryHash)
    #expect(running.pfslocalMinor == 14)

    for (schema, control, version, digest, major) in [
        (2, 1, "0.3.0", sealed.executableSHA256, UInt32(1)),
        (1, 2, "0.3.0", sealed.executableSHA256, UInt32(1)),
        (1, 1, "0.4.1", sealed.executableSHA256, UInt32(1)),
        (1, 1, "0.3.0", String(repeating: "c", count: 64), UInt32(1)),
        (1, 1, "0.3.0", sealed.executableSHA256, UInt32(0)),
    ] {
        let invalid = PortableFSDServiceCoordinator.LiveDaemonIdentity(
            schemaVersion: schema, controlProtocol: control, daemonVersion: version,
            executableSha256: digest, pfslocalMajor: major, pfslocalMinor: 14
        )
        #expect(throws: (any Error).self) {
            try invalid.releaseIdentity(sealed: sealed)
        }
    }
}

@Test func pfsLocalTransportErrorsSurfaceTheirOwnDescription() {
    let failure = PfsLocalClientError.system(errno: ENOENT, operation: "connect")
    #expect(failure.localizedDescription == failure.description)
    #expect(failure.localizedDescription.contains("connect"))
    #expect(!failure.localizedDescription.contains("error 6"))
}

@Test func daemonProcessWitnessRemainsBoundToTheObservedExecution() throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/sleep")
    process.arguments = ["30"]
    try process.run()
    defer {
        if process.isRunning { process.terminate() }
        process.waitUntilExit()
    }

    let witness = try PortableFSDServiceCoordinator.DaemonProcessWitness(
        pid: process.processIdentifier,
        pidVersion: 1
    )
    #expect(try !witness.hasExited())

    process.terminate()
    let deadline = Date().addingTimeInterval(5)
    while try !witness.hasExited(), Date() < deadline {
        Thread.sleep(forTimeInterval: 0.01)
    }
    #expect(try witness.hasExited())

    // A later unrelated process cannot change the terminal verdict. The
    // kqueue registration is bound to the exited execution, not a PID lookup.
    let unrelated = Process()
    unrelated.executableURL = URL(fileURLWithPath: "/usr/bin/true")
    try unrelated.run()
    unrelated.waitUntilExit()
    #expect(try witness.hasExited())
}

@Test func unpublishedDaemonFenceProvesThePinnedStateSingleton() throws {
    let fileManager = FileManager.default
    let root = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
        .appendingPathComponent("pfs-state-fence-\(UUID().uuidString)", isDirectory: true)
    #expect(try PortableFSDServiceCoordinator.stateSingletonIsUnlocked(at: root))

    try fileManager.createDirectory(
        at: root,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
    defer { try? fileManager.removeItem(at: root) }

    #expect(try PortableFSDServiceCoordinator.stateSingletonIsUnlocked(at: root))

    let lock = root.appendingPathComponent(".portablefsd-state.lock")
    #expect(fileManager.createFile(
        atPath: lock.path,
        contents: Data("owner\n".utf8),
        attributes: [.posixPermissions: 0o600]
    ))
    #expect(try PortableFSDServiceCoordinator.stateSingletonIsUnlocked(at: root))

    let descriptor = Darwin.open(lock.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    #expect(descriptor >= 0)
    guard descriptor >= 0 else { return }
    defer { Darwin.close(descriptor) }
    #expect(serviceCoordinatorTestFlock(descriptor, LOCK_EX | LOCK_NB) == 0)
    defer { _ = serviceCoordinatorTestFlock(descriptor, LOCK_UN) }
    #expect(try !PortableFSDServiceCoordinator.stateSingletonIsUnlocked(at: root))
}

@Test func unpublishedDaemonFenceRejectsUnsafeLockEntries() throws {
    let fileManager = FileManager.default

    func withRoot(_ body: (URL) throws -> Void) throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("pfs-state-fence-\(UUID().uuidString)", isDirectory: true)
        try fileManager.createDirectory(
            at: root,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        defer { try? fileManager.removeItem(at: root) }
        try body(root)
    }

    try withRoot { root in
        try fileManager.setAttributes(
            [.posixPermissions: 0o755],
            ofItemAtPath: root.path
        )
        #expect(throws: (any Error).self) {
            _ = try PortableFSDServiceCoordinator.stateSingletonIsUnlocked(at: root)
        }
    }
    try withRoot { root in
        let alias = root.appendingPathExtension("alias")
        try fileManager.createSymbolicLink(at: alias, withDestinationURL: root)
        defer { try? fileManager.removeItem(at: alias) }
        #expect(throws: (any Error).self) {
            _ = try PortableFSDServiceCoordinator.stateSingletonIsUnlocked(at: alias)
        }
    }
    try withRoot { root in
        let lock = root.appendingPathComponent(".portablefsd-state.lock")
        #expect(fileManager.createFile(
            atPath: lock.path,
            contents: Data(),
            attributes: [.posixPermissions: 0o644]
        ))
        #expect(throws: (any Error).self) {
            _ = try PortableFSDServiceCoordinator.stateSingletonIsUnlocked(at: root)
        }
    }
    try withRoot { root in
        let target = root.appendingPathComponent("target")
        #expect(fileManager.createFile(
            atPath: target.path,
            contents: Data(),
            attributes: [.posixPermissions: 0o600]
        ))
        let lock = root.appendingPathComponent(".portablefsd-state.lock")
        try fileManager.createSymbolicLink(at: lock, withDestinationURL: target)
        #expect(throws: (any Error).self) {
            _ = try PortableFSDServiceCoordinator.stateSingletonIsUnlocked(at: root)
        }
    }
    try withRoot { root in
        let lock = root.appendingPathComponent(".portablefsd-state.lock")
        let alias = root.appendingPathComponent("alias")
        #expect(fileManager.createFile(
            atPath: lock.path,
            contents: Data(),
            attributes: [.posixPermissions: 0o600]
        ))
        guard Darwin.link(lock.path, alias.path) == 0 else {
            Issue.record("create hard link: \(String(cString: strerror(errno)))")
            return
        }
        #expect(throws: (any Error).self) {
            _ = try PortableFSDServiceCoordinator.stateSingletonIsUnlocked(at: root)
        }
    }
    try withRoot { root in
        let lock = root.appendingPathComponent(".portablefsd-state.lock")
        guard Darwin.mkfifo(lock.path, 0o600) == 0 else {
            Issue.record("create FIFO: \(String(cString: strerror(errno)))")
            return
        }
        #expect(throws: (any Error).self) {
            _ = try PortableFSDServiceCoordinator.stateSingletonIsUnlocked(at: root)
        }
    }
}

@Test func unpublishedDaemonFenceRejectsLockAndDirectoryReplacementRaces() throws {
    let fileManager = FileManager.default

    let lockRoot = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
        .appendingPathComponent("pfs-lock-race-\(UUID().uuidString)", isDirectory: true)
    try fileManager.createDirectory(
        at: lockRoot,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
    defer { try? fileManager.removeItem(at: lockRoot) }
    let lock = lockRoot.appendingPathComponent(".portablefsd-state.lock")
    #expect(fileManager.createFile(
        atPath: lock.path,
        contents: Data(),
        attributes: [.posixPermissions: 0o600]
    ))
    #expect(throws: (any Error).self) {
        _ = try PortableFSDServiceCoordinator.stateSingletonIsUnlocked(
            at: lockRoot,
            beforeFinalRecheck: {
                try fileManager.removeItem(at: lock)
                guard fileManager.createFile(
                    atPath: lock.path,
                    contents: Data(),
                    attributes: [.posixPermissions: 0o600]
                ) else {
                    throw CocoaError(.fileWriteUnknown)
                }
            }
        )
    }

    let directoryRoot = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
        .appendingPathComponent("pfs-dir-race-\(UUID().uuidString)", isDirectory: true)
    let displaced = directoryRoot.appendingPathExtension("old")
    try fileManager.createDirectory(
        at: directoryRoot,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
    defer {
        try? fileManager.removeItem(at: directoryRoot)
        try? fileManager.removeItem(at: displaced)
    }
    #expect(throws: (any Error).self) {
        _ = try PortableFSDServiceCoordinator.stateSingletonIsUnlocked(
            at: directoryRoot,
            beforeFinalRecheck: {
                try fileManager.moveItem(at: directoryRoot, to: displaced)
                try fileManager.createDirectory(
                    at: directoryRoot,
                    withIntermediateDirectories: false,
                    attributes: [.posixPermissions: 0o700]
                )
            }
        )
    }
}

// MARK: - Live service owner decision flow

private typealias Coordinator = PortableFSDServiceCoordinator

private func ownerTestConfiguration() throws -> Coordinator.Configuration {
    try Coordinator.deriveConfiguration(
        bundleIdentifier: "dev.portablefs.oss.KitDev",
        teamIdentifier: "B47U2LLKHW",
        appGroupIdentifier: "B47U2LLKHW.pfsoss",
        shortVersion: "0.4.2",
        buildVersion: "42"
    )
}

private func ownerTestRelease(
    version: String,
    digit: Character,
    pfslocalMinor: UInt32 = 16
) -> PortableFSDReleaseIdentity {
    PortableFSDReleaseIdentity(
        codeDirectoryHash: String(repeating: digit, count: 40),
        executableSHA256: String(repeating: digit, count: 64),
        daemonVersion: version,
        identitySchema: 1,
        controlProtocol: 1,
        pfslocalMajor: 1,
        pfslocalMinor: pfslocalMinor
    )
}

/// Unix socket paths must fit sockaddr_un, so fixtures live under /tmp rather
/// than the much longer per-user temporary directory.
private func withOwnerFixtureDirectory(_ body: (URL) throws -> Void) throws {
    var template = Array("/tmp/pfs-owner.XXXXXX".utf8CString)
    guard let created = Darwin.mkdtemp(&template) else {
        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
    let root = URL(fileURLWithPath: String(cString: created), isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    try body(root)
}

private func makeOwnerBundle(at url: URL, identifier: String) throws -> Bundle {
    let contents = url.appendingPathComponent("Contents", isDirectory: true)
    try FileManager.default.createDirectory(at: contents, withIntermediateDirectories: true)
    let plist: [String: Any] = [
        "CFBundleIdentifier": identifier,
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": "0.4.1",
        "CFBundleVersion": "41",
        "PFSAppGroupIdentifier": "B47U2LLKHW.pfsoss",
    ]
    let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
    try data.write(to: contents.appendingPathComponent("Info.plist"))
    return try #require(Bundle(url: url))
}

private func ownerRefusal(
    _ operation: () throws -> Void
) -> Coordinator.UnauthenticatedServiceOwner? {
    do {
        try operation()
    } catch Coordinator.RegistrationError.unauthenticatedServiceOwner(let owner) {
        return owner
    } catch {
        Issue.record("expected an unauthenticated-owner refusal, got \(error.localizedDescription)")
        return nil
    }
    Issue.record("expected an unauthenticated-owner refusal")
    return nil
}

private func ownProcessExecutablePath() throws -> String {
    var buffer = [CChar](repeating: 0, count: 4 * 1_024)
    let length = proc_pidpath(getpid(), &buffer, UInt32(buffer.count))
    guard length > 0 else {
        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
    let bytes = buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
    return URL(fileURLWithPath: String(decoding: bytes, as: UTF8.self)).standardizedFileURL.path
}

/// A valid older release, or this release from another copy of the app, is
/// replaced, and every later step binds to its authenticated identity: the
/// empty-inventory guard reads that exact daemon's attaches and the fence
/// waits for that exact execution. The state singleton is never consulted.
@Test func liveOwnerDecisionReplacesAValidOlderReleaseThroughItsOwnIdentity() throws {
    try withOwnerFixtureDirectory { root in
        let incoming = ownerTestRelease(version: "0.4.2", digit: "b")
        let older = ownerTestRelease(version: "0.4.1", digit: "c", pfslocalMinor: 15)
        let incomingURL = root.appendingPathComponent("New.app", isDirectory: true)
        let oldBundle = try makeOwnerBundle(
            at: root.appendingPathComponent("Old.app", isDirectory: true),
            identifier: "dev.portablefs.oss.KitDev"
        )
        let running = Coordinator.RunningDaemon(bundle: oldBundle, releaseIdentity: older)

        guard case .replace(let outgoing?) = Coordinator.registrationStep(
            for: .authenticated(running),
            incoming: incoming,
            bundleURL: incomingURL
        ) else {
            Issue.record("a valid older release must be replaced through its identity")
            return
        }
        #expect(outgoing.releaseIdentity == older)
        #expect(Coordinator.inventoryGuardArguments(outgoing: outgoing.releaseIdentity) == [
            "lifecycle", "hold-install-exclusive", "--json",
            "--expected-daemon-version", "0.4.1",
            "--expected-daemon-sha256", String(repeating: "c", count: 64),
            "--expected-pfslocal-major", "1",
            "--expected-pfslocal-minor", "15",
        ])

        var probed: [PortableFSDReleaseIdentity] = []
        var singletonConsulted = false
        let witness = try Coordinator.replacementWitness(
            outgoing: outgoing,
            probe: { daemon in
                probed.append(daemon.releaseIdentity)
                return try Coordinator.DaemonProcessWitness(pid: getpid(), pidVersion: 1)
            },
            excludeDaemons: {
                singletonConsulted = true
                return nil
            }
        )
        guard case .process = witness else {
            Issue.record("an authenticated outgoing daemon must be fenced by its execution")
            return
        }
        #expect(probed == [older])
        #expect(!singletonConsulted)

        let sameReleaseElsewhere = Coordinator.RunningDaemon(bundle: oldBundle, releaseIdentity: incoming)
        guard case .replace(_?) = Coordinator.registrationStep(
            for: .authenticated(sameReleaseElsewhere),
            incoming: incoming,
            bundleURL: incomingURL
        ) else {
            Issue.record("this release running from another app copy must be replaced")
            return
        }
        guard case .keep = Coordinator.registrationStep(
            for: .authenticated(sameReleaseElsewhere),
            incoming: incoming,
            bundleURL: oldBundle.bundleURL
        ) else {
            Issue.record("the exact release from this bundle must be kept")
            return
        }
    }
}

/// A missing endpoint is replaced only while this app holds the state
/// singleton, so no daemon can run; the guard then adopts no daemon identity.
@Test func liveOwnerDecisionReplacesAMissingEndpointOnlyWhileHoldingTheSingleton() throws {
    try withOwnerFixtureDirectory { root in
        let owner = try Coordinator.inspectLiveServiceOwner(
            controlSocket: root.appendingPathComponent("control.sock"),
            configuration: try ownerTestConfiguration()
        )
        guard case .unpublished = owner else {
            Issue.record("a missing endpoint must classify as unpublished")
            return
        }
        guard case .replace(nil) = Coordinator.registrationStep(
            for: owner,
            incoming: ownerTestRelease(version: "0.4.2", digit: "b"),
            bundleURL: root.appendingPathComponent("New.app", isDirectory: true)
        ) else {
            Issue.record("an unpublished owner must be replaced without an outgoing identity")
            return
        }
        #expect(Coordinator.inventoryGuardArguments(outgoing: nil) == [
            "lifecycle", "hold-install-exclusive", "--json",
        ])

        let stateDirectory = root.appendingPathComponent("state", isDirectory: true)
        try FileManager.default.createDirectory(
            at: stateDirectory,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let witness = try Coordinator.replacementWitness(
            outgoing: nil,
            probe: { _ in
                Issue.record("an unpublished owner has no execution to probe")
                throw POSIXError(.EINVAL)
            },
            excludeDaemons: {
                try Coordinator.acquireStateSingletonExclusion(at: stateDirectory)
            }
        )
        guard case .excluded = witness else {
            Issue.record("a free singleton must be held across unregistration")
            return
        }
        #expect(try witness.hasDeparted())
        #expect(try !Coordinator.stateSingletonIsUnlocked(at: stateDirectory))
        witness.releaseExclusion()
        #expect(try Coordinator.stateSingletonIsUnlocked(at: stateDirectory))
    }
}

/// No endpoint, but a held state singleton: a daemon is starting or stopping
/// and nothing can authenticate it, so replacement is refused.
@Test func liveOwnerDecisionRefusesAnOccupiedStateSingleton() throws {
    try withOwnerFixtureDirectory { root in
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
        let lock = root.appendingPathComponent(".portablefsd-state.lock")
        #expect(FileManager.default.createFile(
            atPath: lock.path,
            contents: Data(),
            attributes: [.posixPermissions: 0o600]
        ))
        let descriptor = Darwin.open(lock.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        try #require(descriptor >= 0)
        defer { Darwin.close(descriptor) }
        try #require(serviceCoordinatorTestFlock(descriptor, LOCK_EX | LOCK_NB) == 0)
        defer { _ = serviceCoordinatorTestFlock(descriptor, LOCK_UN) }

        let refusal = ownerRefusal {
            _ = try Coordinator.replacementWitness(
                outgoing: nil,
                probe: { _ in
                    Issue.record("an unpublished owner has no execution to probe")
                    throw POSIXError(.EINVAL)
                },
                excludeDaemons: {
                    try Coordinator.acquireStateSingletonExclusion(at: root)
                }
            )
        }
        #expect(refusal == .occupiedStateSingleton)
    }
}

private func ownerMessage(_ owner: Coordinator.UnauthenticatedServiceOwner?) -> String {
    guard let owner else { return "" }
    return Coordinator.RegistrationError.unauthenticatedServiceOwner(owner).localizedDescription
}

/// Only an observed absence is reported as a missing owner app. A bundle
/// that exists but does not authenticate is reported as exactly that
/// failure, with the underlying error, not as a guessed replacement.
@Test func liveOwnerDecisionRefusesAMissingOrUnauthenticatableOwnerApp() throws {
    try withOwnerFixtureDirectory { root in
        let configuration = try ownerTestConfiguration()
        let socket = root.appendingPathComponent("control.sock").path

        let deleted = root.appendingPathComponent("Deleted.app", isDirectory: true)
        let missing = ownerRefusal {
            _ = try Coordinator.ownerApp(at: deleted, expected: configuration, controlSocket: socket)
        }
        #expect(missing == .ownerAppMissing(app: deleted.path))
        #expect(ownerMessage(missing).contains("no longer exists at that path"))
        #expect(ownerMessage(missing).contains("log out"))

        // Present, plausible, but unsigned: the signature check's own error
        // is the reported failure.
        let unsigned = root.appendingPathComponent("Unsigned.app", isDirectory: true)
        _ = try makeOwnerBundle(at: unsigned, identifier: "dev.portablefs.oss.KitDev")
        let unauthenticated = ownerRefusal {
            _ = try Coordinator.ownerApp(at: unsigned, expected: configuration, controlSocket: socket)
        }
        guard case let .unauthenticated(reportedSocket, step, failure)? = unauthenticated else {
            Issue.record("an unsigned owner app must be reported as a failed authentication")
            return
        }
        #expect(reportedSocket == socket)
        #expect(step == .ownerAppSignature(app: unsigned.path))
        #expect(failure.contains("signature"))
        #expect(!ownerMessage(unauthenticated).contains("was replaced while"))

        let file = root.appendingPathComponent("File.app", isDirectory: false)
        #expect(FileManager.default.createFile(atPath: file.path, contents: Data("x".utf8)))
        #expect(ownerRefusal {
            _ = try Coordinator.ownerApp(at: file, expected: configuration, controlSocket: socket)
        } == .unauthenticated(
            socket: socket,
            step: .ownerAppSignature(app: file.path),
            failure: "the path is not an app bundle"
        ))
    }
}

/// "Replaced" is reserved for an established identity mismatch: the daemon
/// reports a different release or executable than the signed app at its
/// path. Any other identity mismatch is only a failed proof.
@Test func ownerReplacementRequiresAnEstablishedIdentityMismatch() {
    let installed = ownerTestRelease(version: "0.4.2", digit: "b")
    let app = "/Applications/PortableFS.app"
    let socket = "/tmp/control.sock"
    struct Mismatch: LocalizedError { var errorDescription: String? { "identity mismatch" } }

    let olderDaemon = Coordinator.LiveDaemonIdentity(
        schemaVersion: 1, controlProtocol: 1, daemonVersion: "0.4.1",
        executableSha256: String(repeating: "c", count: 64), pfslocalMajor: 1, pfslocalMinor: 16
    )
    let replaced = Coordinator.identityRefusal(
        reported: olderDaemon, sealed: installed, app: app, socket: socket, failure: Mismatch()
    )
    #expect(replaced == .ownerAppReplaced(
        app: app,
        running: "0.4.1 (executable cccccccccccc)",
        installed: "0.4.2 (executable bbbbbbbbbbbb)"
    ))
    #expect(ownerMessage(replaced).contains("was replaced while its daemon ran"))

    let sameReleaseOtherSchema = Coordinator.LiveDaemonIdentity(
        schemaVersion: 2, controlProtocol: 1, daemonVersion: installed.daemonVersion,
        executableSha256: installed.executableSHA256, pfslocalMajor: 1, pfslocalMinor: 16
    )
    #expect(Coordinator.identityRefusal(
        reported: sameReleaseOtherSchema, sealed: installed, app: app, socket: socket, failure: Mismatch()
    ) == .unauthenticated(socket: socket, step: .daemonIdentity, failure: "identity mismatch"))
}

/// Whatever serves the endpoint without being the daemon nested in a
/// PortableFS app is a foreign owner. Here the test process itself listens
/// on the endpoint, so its real kernel-reported executable is classified.
@Test func liveOwnerDecisionRefusesAForeignSocketOwner() throws {
    try withOwnerFixtureDirectory { root in
        let configuration = try ownerTestConfiguration()
        let socket = root.appendingPathComponent("control.sock")
        let listener = try PfsUnixSocket.bindAndListen(path: socket.path)
        defer { PfsUnixSocket.close(listener) }

        let refusal = ownerRefusal {
            _ = try Coordinator.inspectLiveServiceOwner(
                controlSocket: socket,
                configuration: configuration
            )
        }
        let executable = try ownProcessExecutablePath()
        #expect(refusal == .foreignProcess(socket: socket.path, executable: executable))
        #expect(ownerMessage(refusal).contains(executable))
        #expect(ownerMessage(refusal).contains("Quit that program"))
    }
}

/// connect(2) failures are classified by their real errno. Only
/// ECONNREFUSED, a socket with no accepting daemon, gets the no-listener
/// explanation. A file that is not a socket, or a path through a file,
/// reports the OS error and invents no owner history or recovery.
@Test func liveOwnerDecisionClassifiesConnectFailuresByTheirErrno() throws {
    try withOwnerFixtureDirectory { root in
        let configuration = try ownerTestConfiguration()
        func classify(_ socket: URL) -> Coordinator.UnauthenticatedServiceOwner? {
            ownerRefusal {
                _ = try Coordinator.inspectLiveServiceOwner(
                    controlSocket: socket,
                    configuration: configuration
                )
            }
        }

        let stale = root.appendingPathComponent("stale.sock")
        PfsUnixSocket.close(try PfsUnixSocket.bindAndListen(path: stale.path))
        let refused = classify(stale)
        #expect(refused == .unreachableEndpoint(socket: stale.path, errno: ECONNREFUSED))
        #expect(ownerMessage(refused).contains("no daemon accepted a connection"))

        let regular = root.appendingPathComponent("regular.sock")
        #expect(FileManager.default.createFile(atPath: regular.path, contents: Data()))
        let notSocket = classify(regular)
        #expect(notSocket == .unreachableEndpoint(socket: regular.path, errno: ENOTSOCK))
        #expect(ownerMessage(notSocket).contains("could not connect"))
        #expect(ownerMessage(notSocket).contains(String(cString: strerror(ENOTSOCK))))
        #expect(!ownerMessage(notSocket).contains("restarting"))
        #expect(!ownerMessage(notSocket).contains("log out"))

        let throughFile = regular.appendingPathComponent("control.sock")
        let notDirectory = classify(throughFile)
        #expect(notDirectory == .unreachableEndpoint(socket: throughFile.path, errno: ENOTDIR))
        #expect(ownerMessage(notDirectory).contains(String(cString: strerror(ENOTDIR))))
    }
}

/// Every refusal says that authentication identifies whose inventory may be
/// trusted, and none of them asks the app to stop the owner it could not
/// authenticate. Recovery is prescribed only where the cause is observed.
@Test func unauthenticatedOwnerDiagnosesNameOnlyWhatWasObserved() {
    let socket = "/Users/example/.local/state/portablefs/portablefsd/control.sock"
    let app = "/Applications/PortableFS.app"
    let cases: [(Coordinator.UnauthenticatedServiceOwner, [String])] = [
        (.occupiedStateSingleton,
         ["state lock", "starting or stopping", "another copy of PortableFS", "log out"]),
        (.foreignService(app: "/Applications/PortableFSKitDev.app"),
         ["/Applications/PortableFSKitDev.app", "different signed PortableFS product", "Quit that app", "Login Items"]),
        (.ownerAppMissing(app: app),
         [app, "no longer exists", "Unmount", "log out", "installer", "quiesces"]),
        (.ownerAppReplaced(app: app, running: "0.4.1 (executable c)", installed: "0.4.2 (executable b)"),
         [app, "0.4.1 (executable c)", "0.4.2 (executable b)", "Unmount", "log out", "installer"]),
        (.unauthenticated(socket: socket, step: .peerBinding, failure: "Operation not permitted"),
         [socket, "could not bind the process serving it", "Operation not permitted.", "Quit any other copy", "installer"]),
        (.unauthenticated(socket: socket, step: .executableResolution, failure: "No such file or directory"),
         ["could not resolve the executable", "No such file or directory."]),
        (.unauthenticated(socket: socket, step: .daemonIdentity, failure: "invalid control reply"),
         ["could not read its running daemon's release identity", "invalid control reply."]),
        (.exitedDuringProof,
         ["exited", "Reopen PortableFS"]),
    ]
    for (owner, facts) in cases {
        let message = ownerMessage(owner)
        for fact in facts {
            #expect(message.contains(fact), "\(owner) diagnosis omits \"\(fact)\": \(message)")
        }
        if owner != .exitedDuringProof {
            #expect(message.contains("authentication identifies the daemon whose mount inventory"))
        }
    }
}

// MARK: - State singleton exclusion

/// What a starting portablefsd does first: open the canonical lock and try a
/// nonblocking exclusive flock (`vcs/internal/portablefsd/run.go`
/// tryAcquireLock). Returns whether this simulated daemon got the lock.
private func simulatedDaemonAcquiresStateSingleton(in directory: URL) throws -> Bool {
    let descriptor = Darwin.open(
        directory.appendingPathComponent(".portablefsd-state.lock").path,
        O_RDWR | O_NOFOLLOW | O_CLOEXEC
    )
    try #require(descriptor >= 0)
    defer { Darwin.close(descriptor) }
    if serviceCoordinatorTestFlock(descriptor, LOCK_EX | LOCK_NB) == 0 {
        _ = serviceCoordinatorTestFlock(descriptor, LOCK_UN)
        return true
    }
    #expect(errno == EWOULDBLOCK)
    return false
}

/// The fields portablefsd's readSingletonOwner requires before it will even
/// consider a takeover, and the Darwin start-identity shape it compares.
private func expectLiveOwnerRecord(in directory: URL) throws {
    let body = try Data(contentsOf: directory.appendingPathComponent(".portablefsd-state.lock"))
    let record = try #require(JSONSerialization.jsonObject(with: body) as? [String: Any])
    #expect(record["schemaVersion"] as? Int == 1)
    #expect(record["pid"] as? Int == Int(getpid()))
    let start = try #require(record["startIdentity"] as? String)
    let parts = start.split(separator: ":")
    #expect(parts.count == 2 && parts.allSatisfy { Int($0) != nil })
}

/// The absence proof is held, not sampled. Between classification and the
/// unregistration it authorizes, a daemon that KeepAlive starts cannot take
/// the state singleton, so it cannot become an unauthenticated owner that the
/// replacement then stops. Releasing the exclusion lets the incoming daemon
/// start.
@Test func stateSingletonExclusionBlocksADaemonStartUntilReleased() throws {
    try withOwnerFixtureDirectory { root in
        let stateDirectory = root.appendingPathComponent("state", isDirectory: true)
        try FileManager.default.createDirectory(
            at: stateDirectory,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        // A previous daemon's record names a process that no longer exists.
        // Left in place, it would let a starting daemon prove the holder
        // departed and take the lock over.
        let lock = stateDirectory.appendingPathComponent(".portablefsd-state.lock")
        #expect(FileManager.default.createFile(
            atPath: lock.path,
            contents: Data(#"{"schemaVersion":1,"pid":2147483646,"startIdentity":"1:1","version":"","owner":"old"}"#.utf8),
            attributes: [.posixPermissions: 0o600]
        ))

        let exclusion = try #require(
            try Coordinator.acquireStateSingletonExclusion(at: stateDirectory)
        )
        #expect(try !simulatedDaemonAcquiresStateSingleton(in: stateDirectory))
        try expectLiveOwnerRecord(in: stateDirectory)
        #expect(try !Coordinator.stateSingletonIsUnlocked(at: stateDirectory))
        // A second replacement cannot take it either.
        #expect(try Coordinator.acquireStateSingletonExclusion(at: stateDirectory) == nil)

        exclusion.release()
        #expect(try simulatedDaemonAcquiresStateSingleton(in: stateDirectory))
    }
}

/// A missing directory or lock goes through the same boundary: the
/// exclusion creates them exactly as portablefsd would (0700 directory,
/// single-link 0600 lock) and holds the lock, so a daemon starting later
/// contends on it instead of creating its own.
@Test func stateSingletonExclusionCreatesAMissingDirectoryAndLock() throws {
    try withOwnerFixtureDirectory { root in
        let stateDirectory = root
            .appendingPathComponent("state", isDirectory: true)
            .appendingPathComponent("portablefsd", isDirectory: true)
        #expect(try Coordinator.stateSingletonIsUnlocked(at: stateDirectory))
        #expect(!FileManager.default.fileExists(atPath: stateDirectory.path))

        let exclusion = try #require(
            try Coordinator.acquireStateSingletonExclusion(at: stateDirectory)
        )
        var directory = stat()
        #expect(Darwin.lstat(stateDirectory.path, &directory) == 0)
        #expect(directory.st_mode & 0o777 == 0o700)
        var lock = stat()
        #expect(Darwin.lstat(
            stateDirectory.appendingPathComponent(".portablefsd-state.lock").path,
            &lock
        ) == 0)
        #expect(lock.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG))
        #expect(lock.st_mode & 0o777 == 0o600)
        #expect(lock.st_nlink == 1)
        #expect(try !simulatedDaemonAcquiresStateSingleton(in: stateDirectory))
        try expectLiveOwnerRecord(in: stateDirectory)

        exclusion.release()
        #expect(try simulatedDaemonAcquiresStateSingleton(in: stateDirectory))
    }
}

/// A held exclusion stops proving absence if its lock is replaced by name.
@Test func stateSingletonExclusionDetectsAReplacedLock() throws {
    try withOwnerFixtureDirectory { root in
        let stateDirectory = root.appendingPathComponent("state", isDirectory: true)
        let exclusion = try #require(
            try Coordinator.acquireStateSingletonExclusion(at: stateDirectory)
        )
        defer { exclusion.release() }
        try exclusion.confirmHeld()
        let lock = stateDirectory.appendingPathComponent(".portablefsd-state.lock")
        try FileManager.default.removeItem(at: lock)
        #expect(FileManager.default.createFile(
            atPath: lock.path,
            contents: Data(),
            attributes: [.posixPermissions: 0o600]
        ))
        #expect(throws: (any Error).self) {
            try exclusion.confirmHeld()
        }
        #expect(throws: (any Error).self) {
            _ = try Coordinator.DaemonFenceWitness.excluded(exclusion).hasDeparted()
        }
    }
}
