import Darwin
import Foundation
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
        pfslocalMinor: 14
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
            pfslocalMinor: 14
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
