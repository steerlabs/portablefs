import CryptoKit
import Darwin
import Foundation
import PortableFSKit
import Security
import ServiceManagement

// Swift imports both `struct flock` and flock(2) under the same name and
// resolves the spelling as the structure initializer. Bind the documented BSD
// syscall symbol explicitly so this proof observes the daemon's actual lock.
@_silgen_name("flock")
private func portableFSFlock(_ descriptor: Int32, _ operation: Int32) -> Int32

// XNU's audit-token code-signing query, exported by libSystem but omitted
// from the SDK headers. The kernel checks the token's pid and pid version and
// answers from the process's running text vnode, never by reopening a path.
@_silgen_name("csops_audittoken")
private func portableFSCSOpsAuditToken(
    _ pid: pid_t,
    _ operation: UInt32,
    _ buffer: UnsafeMutableRawPointer?,
    _ size: Int,
    _ token: UnsafeMutablePointer<audit_token_t>
) -> Int32

/// A daemon release is exactly its authenticated CodeDirectory hash,
/// executable SHA-256 and release version. Protocol numbers are not part of
/// it: they belong to the authenticated daemon's live identity, which is
/// compared with this tuple and, for this app's own daemon, with this build's
/// exact pairing.
public struct PortableFSDReleaseIdentity: Codable, Equatable, Sendable {
    public let codeDirectoryHash: String
    public let executableSHA256: String
    public let daemonVersion: String

    /// The exact members of every encoded release tuple. Host-update frames
    /// and leases refuse any other member, including the removed protocol
    /// numbers, rather than accepting two tuple formats.
    static let jsonKeys: Set<String> = ["codeDirectoryHash", "executableSHA256", "daemonVersion"]

    public init(
        codeDirectoryHash: String,
        executableSHA256: String,
        daemonVersion: String
    ) {
        self.codeDirectoryHash = codeDirectoryHash
        self.executableSHA256 = executableSHA256
        self.daemonVersion = daemonVersion
    }

    func validate() throws {
        guard Self.isLowerHex(codeDirectoryHash, count: 40),
              Self.isLowerHex(executableSHA256, count: 64),
              !daemonVersion.isEmpty,
              daemonVersion.count <= 128,
              daemonVersion.utf8.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }) else {
            throw PortableFSDReleaseIdentityError.invalid
        }
    }

    enum CodingKeys: String, CodingKey {
        case codeDirectoryHash
        case executableSHA256
        case daemonVersion
    }

    func validated() throws -> Self {
        try validate()
        return self
    }

    private static func isLowerHex(_ value: String, count: Int) -> Bool {
        value.utf8.count == count && value.utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
        }
    }
}

enum PortableFSDReleaseIdentityError: Error {
    case invalid
}

public enum PortableFSDServiceCoordinator {
    private static let bundleProgram = "Contents/Library/LaunchAgents/PortableFSDService.app/Contents/MacOS/portablefsd"
    /// This app's exact pairing: the authenticated live identity of its own
    /// daemon must report these numbers before activation succeeds or any
    /// operation proceeds. They are never expected of another release.
    static let pairedIdentitySchema = PortableFSDLifecycle.identitySchemaVersion
    static let pairedControlProtocol = 2
    static let pairedPFSLocalMajor = PfsLocalClient.protocolMajor
    static let pairedPFSLocalMinor = PfsLocalClient.protocolMinor
    // CS_RUNTIME from Security/CSCommon.h. Swift does not import that C enum
    // case, but SecCode returns the same documented static-signature bitset.
    static let hardenedRuntimeFlag: UInt32 = 0x0001_0000

    struct Configuration: Equatable {
        let hostBundleIdentifier: String
        let plistName: String
        let label: String
        let serviceBundleIdentifier: String
        let teamIdentifier: String
        let appGroupIdentifier: String
        let shortVersion: String
        let buildVersion: String
    }

    /// One kernel-pinned execution of the sealed daemon. `pidversion` is part
    /// of the authenticated audit token and EVFILT_PROC binds the queue entry
    /// to that execution, not to a numeric PID that can later be recycled.
    final class DaemonProcessWitness {
        let pid: pid_t
        let pidVersion: Int32

        private var queue: Int32
        private var observedExit = false

        init(pid: pid_t, pidVersion: Int32) throws {
            guard pid > 0, pidVersion > 0 else {
                throw RegistrationError.invalidDaemonProcessWitness
            }
            let descriptor = Darwin.kqueue()
            guard descriptor >= 0 else {
                throw RegistrationError.inspectDaemonProcess(errno)
            }
            var change = kevent64_s(
                ident: UInt64(UInt32(bitPattern: pid)),
                filter: Int16(EVFILT_PROC),
                flags: UInt16(EV_ADD | EV_ENABLE | EV_ONESHOT),
                fflags: UInt32(NOTE_EXIT) | UInt32(bitPattern: NOTE_EXEC),
                data: 0,
                udata: 0,
                ext: (0, 0)
            )
            guard Darwin.kevent64(
                descriptor,
                &change,
                1,
                nil,
                0,
                0,
                nil
            ) == 0 else {
                let code = errno
                Darwin.close(descriptor)
                throw RegistrationError.inspectDaemonProcess(code)
            }
            self.pid = pid
            self.pidVersion = pidVersion
            self.queue = descriptor
        }

        deinit {
            close()
        }

        func close() {
            if queue >= 0 {
                Darwin.close(queue)
                queue = -1
            }
        }

        func hasExited() throws -> Bool {
            if observedExit { return true }
            guard queue >= 0 else {
                throw RegistrationError.invalidDaemonProcessWitness
            }
            var event = kevent64_s()
            var timeout = timespec(tv_sec: 0, tv_nsec: 0)
            let count = Darwin.kevent64(
                queue,
                nil,
                0,
                &event,
                1,
                0,
                &timeout
            )
            guard count >= 0 else {
                throw RegistrationError.inspectDaemonProcess(errno)
            }
            if count == 0 { return false }
            guard event.ident == UInt64(UInt32(bitPattern: pid)),
                  event.filter == Int16(EVFILT_PROC),
                  event.flags & UInt16(EV_ERROR) == 0,
                  event.fflags & UInt32(bitPattern: NOTE_EXEC) == 0,
                  event.fflags & UInt32(NOTE_EXIT) != 0 else {
                throw RegistrationError.invalidDaemonProcessWitness
            }
            observedExit = true
            return true
        }
    }

    enum DaemonFenceWitness {
        /// The authenticated execution must exit and no daemon may hold the
        /// state singleton. A daemon that stops itself after stop-if-idle
        /// can be restarted by KeepAlive before unregistration lands; the
        /// singleton is what proves no such instance survives.
        case process(DaemonProcessWitness)
        /// This app holds the state singleton, so no daemon can run.
        case excluded(StateSingletonExclusion)
        /// Departure is proven by finding the state singleton free.
        case unpublished

        func hasDeparted() throws -> Bool {
            switch self {
            case .process(let witness):
                return try witness.hasExited()
                    && PortableFSDServiceCoordinator.stateSingletonIsUnlocked()
            case .excluded(let exclusion):
                try exclusion.confirmHeld()
                return true
            case .unpublished:
                return try PortableFSDServiceCoordinator.stateSingletonIsUnlocked()
            }
        }

        func releaseExclusion() {
            if case .excluded(let exclusion) = self { exclusion.release() }
        }
    }

    /// Ownership of the canonical daemon state singleton. portablefsd takes
    /// this lock before anything else and exits without touching state when
    /// it cannot, so while it is held no daemon can run.
    final class StateSingletonExclusion {
        private var directory: Int32
        private var lock: Int32
        private let pinnedLock: stat
        private let directoryURL: URL
        private let pinnedDirectory: stat
        private let lockName: String

        init(
            directory: Int32,
            lock: Int32,
            pinnedLock: stat,
            directoryURL: URL,
            pinnedDirectory: stat,
            lockName: String = ".portablefsd-state.lock"
        ) {
            self.directory = directory
            self.lock = lock
            self.pinnedLock = pinnedLock
            self.directoryURL = directoryURL
            self.pinnedDirectory = pinnedDirectory
            self.lockName = lockName
        }

        deinit { release() }

        /// Fails unless the canonical name still denotes the locked inode.
        func confirmHeld() throws {
            var current = stat()
            guard lock >= 0,
                  Darwin.fstatat(
                    directory,
                    lockName,
                    &current,
                    AT_SYMLINK_NOFOLLOW
                  ) == 0,
                  current.st_dev == pinnedLock.st_dev,
                  current.st_ino == pinnedLock.st_ino,
                  current.st_mode == pinnedLock.st_mode,
                  current.st_uid == pinnedLock.st_uid,
                  current.st_nlink == pinnedLock.st_nlink else {
                throw RegistrationError.invalidDaemonStateSingleton
            }
        }

        /// The decisive empty-registry witness for a daemon that cannot run:
        /// while this exclusion is held, the daemon's registry entry must be
        /// absent from the pinned canonical state directory. Only ENOENT from
        /// a no-follow, descriptor-relative inspection proves that; any entry
        /// at the name, of any type, size or content, blocks replacement and
        /// is neither opened, parsed nor changed. Nothing is decoded: the
        /// registry's format is private to the release that wrote it.
        func requireDaemonRegistryAbsent() throws {
            try requireResourceAbsent(PortableFSDServiceCoordinator.daemonRegistryName)
        }
        func requireResourceAbsent(_ name: String) throws {
            try confirmHeld()
            try PortableFSDServiceCoordinator.recheckPinnedDirectory(
                directoryURL,
                expected: pinnedDirectory
            )
            var entry = stat()
            if Darwin.fstatat(
                directory,
                name,
                &entry,
                AT_SYMLINK_NOFOLLOW
            ) == 0 {
                throw RegistrationError.daemonRegistryPresent
            }
            let code = errno
            guard code == ENOENT else {
                throw RegistrationError.inspectDaemonRegistry(code)
            }
        }

        func release() {
            if lock >= 0 {
                _ = portableFSFlock(lock, LOCK_UN)
                Darwin.close(lock)
                lock = -1
            }
            if directory >= 0 {
                Darwin.close(directory)
                directory = -1
            }
        }
    }

    private struct InstallExclusiveReadiness: Decodable {
        let schemaVersion: Int
        let held: Bool
        let purpose: String
        let kernelMounts: Int
        let mountRecords: Int
        let mountIntents: Int
        let durableAttaches: Int
        let liveAttaches: Int
    }

    public enum State: Equatable {
        case enabled
        case requiresApproval
    }

    /// Registers this sealed release as the account's daemon service. An
    /// enabled service is replaced only after its live owner is either
    /// authenticated as a signed release of this product or proven absent;
    /// any other owner fails with an `UnauthenticatedServiceOwner` diagnosis
    /// and is left running.
    public static func prepareAndRegister(bundle: Bundle = .main) throws -> State {
        let configuration = try validateHostAndConfiguration(bundle: bundle)
        let socketDirectory = try PortableFSAppGroupBootstrap.prepare(bundle: bundle)
        let releaseIdentity = try validateIncomingRelease(
            bundle: bundle,
            configuration: configuration
        )

        let service = SMAppService.agent(plistName: configuration.plistName)
        switch service.status {
        case .enabled:
            let owner = try inspectLiveServiceOwner(
                controlSocket: try controlSocketURL(),
                configuration: configuration
            )
            switch registrationStep(
                for: owner,
                incoming: releaseIdentity,
                bundleURL: bundle.bundleURL
            ) {
            case .keep(let running):
                // This app's own daemon already serves; activation is
                // reported only once its live numbers equal this build's.
                try requirePaired(running.liveIdentity)
                return .enabled
            case .replace(let outgoing):
                try reregister(
                    service: service,
                    bundle: bundle,
                    socketDirectory: socketDirectory,
                    outgoing: outgoing,
                    releaseIdentity: releaseIdentity
                )
                return .enabled
            }
        case .requiresApproval:
            SMAppService.openSystemSettingsLoginItems()
            return .requiresApproval
        case .notFound, .notRegistered:
            do {
                try service.register()
            } catch {
                if service.status == .requiresApproval {
                    SMAppService.openSystemSettingsLoginItems()
                    return .requiresApproval
                }
                try completeRegisteredRelease(
                    operation: {
                        throw RegistrationError.registrationFailed(error)
                    },
                    fence: {
                        try fenceNewRegistration(
                            service: service,
                            bundle: bundle,
                            socketDirectory: socketDirectory,
                            releaseIdentity: releaseIdentity
                        )
                    }
                )
            }

            switch service.status {
            case .enabled:
                try completeRegisteredRelease(
                    operation: {
                        try requireLiveDaemon(
                            releaseIdentity,
                            bundle: bundle
                        )
                    },
                    fence: {
                        try fenceNewRegistration(
                            service: service,
                            bundle: bundle,
                            socketDirectory: socketDirectory,
                            releaseIdentity: releaseIdentity
                        )
                    }
                )
                return .enabled
            case .requiresApproval:
                SMAppService.openSystemSettingsLoginItems()
                return .requiresApproval
            case .notFound:
                try failRegisteredRelease(
                    RegistrationError.serviceNotFound,
                    service: service,
                    bundle: bundle,
                    socketDirectory: socketDirectory,
                    releaseIdentity: releaseIdentity
                )
            case .notRegistered:
                try failRegisteredRelease(
                    RegistrationError.registrationDidNotPersist,
                    service: service,
                    bundle: bundle,
                    socketDirectory: socketDirectory,
                    releaseIdentity: releaseIdentity
                )
            @unknown default:
                try failRegisteredRelease(
                    RegistrationError.unknownStatus,
                    service: service,
                    bundle: bundle,
                    socketDirectory: socketDirectory,
                    releaseIdentity: releaseIdentity
                )
            }
        @unknown default:
            throw RegistrationError.unknownStatus
        }
    }

    public static func sealedReleaseIdentity(
        bundle: Bundle = .main
    ) throws -> PortableFSDReleaseIdentity {
        let configuration = try validateHostAndConfiguration(bundle: bundle)
        return try validateIncomingRelease(
            bundle: bundle,
            configuration: configuration
        )
    }

    static func prepareForInstallerUpdate(
        bundle: Bundle = .main
    ) throws -> PortableFSDReleaseIdentity {
        let configuration = try validateHostAndConfiguration(bundle: bundle)
        let socketDirectory = try PortableFSAppGroupBootstrap.prepare(bundle: bundle)
        let releaseIdentity = try validateIncomingRelease(
            bundle: bundle,
            configuration: configuration
        )
        let service = SMAppService.agent(plistName: configuration.plistName)
        guard service.status == .enabled else {
            throw RegistrationError.registrationDidNotPersist
        }
        let updateGuard = try acquireEmptyInventoryGuard(
            bundle: bundle,
            outgoing: try ExpectedDaemon(bundle: bundle, releaseIdentity: releaseIdentity)
        )
        do {
            try quiesceWorkspaceForInstaller(bundle: bundle)
            // Capture the exact current listener only after the mount/attach
            // inventory guard is held, closing the daemon-restart gap between
            // admission proof and ServiceManagement unregistration.
            let processWitness = try probeLiveDaemon(
                releaseIdentity,
                bundle: bundle,
                pairing: .outgoing
            )
            try stopIfIdle(
                bundle: bundle,
                releaseIdentity: releaseIdentity,
                processWitness: processWitness
            )
            try unregisterAndWait(
                service: service,
                socketDirectory: socketDirectory,
                processWitness: .process(processWitness)
            )
            try requireDaemonRegistryAbsentAtFinalBoundary(
                .process(processWitness),
                excludeDaemons: { try acquireStateSingletonExclusion() }
            )
            updateGuard.release()
            return releaseIdentity
        } catch {
            if service.status == .notRegistered {
                try? service.register()
                try? requireLiveDaemon(releaseIdentity, bundle: bundle)
            }
            updateGuard.release()
            throw error
        }
    }

    /// Proves the release named by a terminal installer marker is still the
    /// exact sealed, registered, and live service before a new transaction is
    /// allowed to replace that marker.
    static func proveActiveInstallerRelease(
        expectedRelease: PortableFSDReleaseIdentity,
        bundle: Bundle = .main
    ) throws {
        let configuration = try validateHostAndConfiguration(bundle: bundle)
        let sealed = try validateIncomingRelease(
            bundle: bundle,
            configuration: configuration
        )
        guard sealed == expectedRelease,
              SMAppService.agent(plistName: configuration.plistName).status == .enabled else {
            throw RegistrationError.liveIdentityFailed(
                "the completed installer release is not this sealed registered release"
            )
        }
        try requireLiveDaemon(expectedRelease, bundle: bundle)
    }

    static func activateForInstaller(
        expectedRelease: PortableFSDReleaseIdentity,
        bundle: Bundle = .main
    ) throws {
        let configuration = try validateHostAndConfiguration(bundle: bundle)
        let sealed = try validateIncomingRelease(
            bundle: bundle,
            configuration: configuration
        )
        let socketDirectory = try PortableFSAppGroupBootstrap.prepare(bundle: bundle)
        guard sealed == expectedRelease else {
            throw RegistrationError.liveIdentityFailed(
                "the installer target is not this sealed release"
            )
        }
        let service = SMAppService.agent(plistName: configuration.plistName)
        guard service.status == .notRegistered else {
            throw RegistrationError.registrationDidNotPersist
        }
        try completeRegisteredRelease(
            operation: {
                try service.register()
                guard service.status == .enabled else {
                    throw RegistrationError.registrationDidNotPersist
                }
                try requireLiveDaemon(sealed, bundle: bundle)
            },
            fence: {
                try fenceNewRegistration(
                    service: service,
                    bundle: bundle,
                    socketDirectory: socketDirectory,
                    releaseIdentity: sealed
                )
            }
        )
    }

    static func fenceForInstaller(
        expectedRelease: PortableFSDReleaseIdentity,
        bundle: Bundle = .main
    ) throws {
        let configuration = try validateHostAndConfiguration(bundle: bundle)
        let sealed = try validateIncomingRelease(
            bundle: bundle,
            configuration: configuration
        )
        guard sealed == expectedRelease else {
            throw RegistrationError.liveIdentityFailed(
                "the installer fence target is not this sealed release"
            )
        }
        try quiesceWorkspaceForInstaller(bundle: bundle)
        let service = SMAppService.agent(plistName: configuration.plistName)
        if service.status == .notRegistered {
            let paths = try runtimePaths(bundle: bundle)
            let deadline = Date().addingTimeInterval(10)
            while Date() < deadline {
                if (try? requireRuntimePathsAbsent(paths)) != nil,
                   (try? DaemonFenceWitness.unpublished.hasDeparted()) == true {
                    return
                }
                Thread.sleep(forTimeInterval: 0.1)
            }
            try requireRuntimePathsAbsent(paths)
            guard try DaemonFenceWitness.unpublished.hasDeparted() else {
                throw RegistrationError.daemonStateSingletonHeld
            }
            return
        }
        guard service.status == .enabled else {
            throw RegistrationError.registrationDidNotPersist
        }
        let processWitness = try probeLiveDaemon(sealed, bundle: bundle, pairing: .outgoing)
        try unregisterAndWait(
            service: service,
            socketDirectory: try PortableFSAppGroupBootstrap.prepare(bundle: bundle),
            processWitness: .process(processWitness)
        )
    }

    static func restoreCancelledInstallerUpdate(
        expectedRelease: PortableFSDReleaseIdentity,
        bundle: Bundle = .main
    ) throws {
        let configuration = try validateHostAndConfiguration(bundle: bundle)
        let sealed = try validateIncomingRelease(
            bundle: bundle,
            configuration: configuration
        )
        guard sealed == expectedRelease else {
            throw RegistrationError.liveIdentityFailed(
                "the cancelled installer release is not this sealed release"
            )
        }
        let updateGuard = try acquireEmptyInventoryGuard(
            bundle: bundle,
            outgoing: try ExpectedDaemon(bundle: bundle, releaseIdentity: expectedRelease)
        )
        defer { updateGuard.release() }

        let service = SMAppService.agent(plistName: configuration.plistName)
        switch service.status {
        case .notRegistered, .notFound:
            try activateForInstaller(
                expectedRelease: expectedRelease,
                bundle: bundle
            )
        case .enabled:
            try requireLiveDaemon(expectedRelease, bundle: bundle)
        case .requiresApproval:
            throw RegistrationError.registrationDidNotPersist
        @unknown default:
            throw RegistrationError.unknownStatus
        }
    }

    private static func validateHostAndConfiguration(
        bundle: Bundle
    ) throws -> Configuration {
        guard let bundleIdentifier = bundle.bundleIdentifier,
              !bundleIdentifier.isEmpty,
              let appGroup = bundle.object(
                forInfoDictionaryKey: "PFSAppGroupIdentifier"
              ) as? String,
              !appGroup.isEmpty,
              let shortVersion = bundle.object(
                forInfoDictionaryKey: "CFBundleShortVersionString"
              ) as? String,
              !shortVersion.isEmpty,
              let buildVersion = bundle.object(
                forInfoDictionaryKey: "CFBundleVersion"
              ) as? String,
              !buildVersion.isEmpty else {
            throw RegistrationError.invalidHostBundle(bundle.bundleURL.path)
        }

        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(
            bundle.bundleURL as CFURL,
            SecCSFlags(),
            &staticCode
        ) == errSecSuccess,
              let staticCode,
              SecStaticCodeCheckValidity(
                staticCode,
                SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures),
                nil
              ) == errSecSuccess else {
            throw RegistrationError.invalidHostSignature(bundle.bundleURL.path)
        }
        var rawInformation: CFDictionary?
        guard SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &rawInformation
        ) == errSecSuccess,
              let information = rawInformation as? [CFString: Any],
              information[kSecCodeInfoIdentifier] as? String == bundleIdentifier,
              let teamIdentifier = information[kSecCodeInfoTeamIdentifier] as? String,
              !teamIdentifier.isEmpty,
              let entitlements = information[kSecCodeInfoEntitlementsDict] as? [String: Any],
              let groups = entitlements["com.apple.security.application-groups"] as? [String],
              groups == [appGroup],
              appGroup.hasPrefix(teamIdentifier + ".") else {
            throw RegistrationError.invalidHostSignature(bundle.bundleURL.path)
        }
        return try deriveConfiguration(
            bundleIdentifier: bundleIdentifier,
            teamIdentifier: teamIdentifier,
            appGroupIdentifier: appGroup,
            shortVersion: shortVersion,
            buildVersion: buildVersion
        )
    }

    static func deriveConfiguration(
        bundleIdentifier: String,
        teamIdentifier: String,
        appGroupIdentifier: String,
        shortVersion: String,
        buildVersion: String
    ) throws -> Configuration {
        guard !bundleIdentifier.isEmpty,
              !teamIdentifier.isEmpty,
              appGroupIdentifier.hasPrefix(teamIdentifier + "."),
              appGroupIdentifier.count > teamIdentifier.count + 1,
              !shortVersion.isEmpty,
              !buildVersion.isEmpty else {
            throw RegistrationError.invalidHostBundle(bundleIdentifier)
        }
        let label = bundleIdentifier + ".portablefsd"
        return Configuration(
            hostBundleIdentifier: bundleIdentifier,
            plistName: label + ".plist",
            label: label,
            serviceBundleIdentifier: bundleIdentifier + ".PortableFSDService",
            teamIdentifier: teamIdentifier,
            appGroupIdentifier: appGroupIdentifier,
            shortVersion: shortVersion,
            buildVersion: buildVersion
        )
    }

    /// The sealed release of this app's own bundle. Its exact pairing with
    /// this build's frontend is a property of the running daemon, proved
    /// from its authenticated live identity before activation succeeds.
    private static func validateIncomingRelease(
        bundle: Bundle,
        configuration: Configuration
    ) throws -> PortableFSDReleaseIdentity {
        try sealedRelease(bundle: bundle, configuration: configuration)
    }

    /// This build's exact pairing: identity schema 1, operational control 2
    /// and pfslocal 2.0. Applied only to this app's own authenticated daemon;
    /// an outgoing release keeps its own valid numbers.
    static func isPaired(_ live: PortableFSDLiveIdentity) -> Bool {
        live.schemaVersion == pairedIdentitySchema
            && live.controlProtocol == pairedControlProtocol
            && live.pfslocalMajor == pairedPFSLocalMajor
            && live.pfslocalMinor == pairedPFSLocalMinor
    }

    /// The architecture of the daemon slice the kernel runs here: arm64 on
    /// Apple silicon, including when this app itself runs translated, and
    /// x86_64 on Intel. Matches the Go CLI's selection.
    static func nativeDaemonArchitecture() throws -> String {
        #if arch(arm64)
        return "arm64"
        #elseif arch(x86_64)
        var translated: Int32 = 0
        var size = MemoryLayout<Int32>.size
        if Darwin.sysctlbyname("sysctl.proc_translated", &translated, &size, nil, 0) != 0 {
            let code = errno
            guard code == ENOENT else {
                throw RegistrationError.inspectDaemonProcess(code)
            }
            return "x86_64"
        }
        switch translated {
        case 0: return "x86_64"
        case 1: return "arm64"
        default: throw RegistrationError.inspectDaemonProcess(EINVAL)
        }
        #else
        throw RegistrationError.inspectDaemonProcess(ENOTSUP)
        #endif
    }

    /// The canonical daemon executable inside a signed app of this product:
    /// the app directory's real path followed by the fixed nested service
    /// layout. It is the only path a socket peer of that app's daemon may
    /// execute, compared byte for byte with the kernel's path for the peer's
    /// token, and the exact path the lifecycle helper is told to expect. The
    /// app directory is resolved because the kernel reports real paths, while
    /// Foundation rewrites /private/tmp and /private/var bundle URLs to their
    /// symlinks; the nested layout is not resolved, so any symlink inside the
    /// signed bundle refuses.
    static func daemonExecutablePath(bundle: Bundle) throws -> String {
        guard let resolved = Darwin.realpath(bundle.bundleURL.path, nil) else {
            throw RegistrationError.invalidHostBundle(bundle.bundleURL.path)
        }
        defer { free(resolved) }
        return String(cString: resolved) + "/" + bundleProgram
    }

    /// The release sealed into any signed app of this product, from that
    /// bundle alone: its signed daemon's CodeDirectory hash, executable hash
    /// and version.
    private static func sealedRelease(
        bundle: Bundle,
        configuration: Configuration
    ) throws -> PortableFSDReleaseIdentity {
        let appURL = bundle.bundleURL
        let serviceURL = appURL
            .appendingPathComponent("Contents/Library/LaunchAgents", isDirectory: true)
            .appendingPathComponent("PortableFSDService.app", isDirectory: true)
        guard let serviceBundle = Bundle(url: serviceURL),
              serviceBundle.bundleIdentifier == configuration.serviceBundleIdentifier,
              serviceBundle.object(forInfoDictionaryKey: "CFBundleExecutable") as? String == "portablefsd",
              serviceBundle.object(forInfoDictionaryKey: "CFBundlePackageType") as? String == "APPL",
              serviceBundle.object(forInfoDictionaryKey: "LSBackgroundOnly") as? Bool == true,
              let daemonVersion = serviceBundle.object(
                forInfoDictionaryKey: "CFBundleShortVersionString"
              ) as? String,
              daemonVersion == configuration.shortVersion,
              serviceBundle.object(
                forInfoDictionaryKey: "CFBundleVersion"
              ) as? String == configuration.buildVersion else {
            throw RegistrationError.invalidServiceBundle(serviceURL.path)
        }
        let profileURL = serviceURL
            .appendingPathComponent("Contents", isDirectory: true)
            .appendingPathComponent("embedded.provisionprofile", isDirectory: false)
        guard !FileManager.default.fileExists(atPath: profileURL.path) else {
            throw RegistrationError.unexpectedServiceProfile(profileURL.path)
        }
        let helperURL = appURL.appendingPathComponent(bundleProgram, isDirectory: false)
        guard serviceBundle.executableURL?.standardizedFileURL == helperURL.standardizedFileURL,
              FileManager.default.isExecutableFile(atPath: helperURL.path) else {
            throw RegistrationError.missingHelper(helperURL.path)
        }
        let releaseIdentity = try validateServiceSignature(
            serviceURL: serviceURL,
            executableURL: helperURL,
            daemonVersion: daemonVersion,
            configuration: configuration
        )

        let plistURL = appURL
            .appendingPathComponent("Contents/Library/LaunchAgents", isDirectory: true)
            .appendingPathComponent(configuration.plistName, isDirectory: false)
        let data: Data
        do {
            data = try Data(contentsOf: plistURL, options: .mappedIfSafe)
        } catch {
            throw RegistrationError.invalidPlist(plistURL.path)
        }
        guard let plist = try PropertyListSerialization.propertyList(
            from: data,
            options: [],
            format: nil
        ) as? [String: Any],
              plist.count == 4,
              plist["Label"] as? String == configuration.label,
              plist["BundleProgram"] as? String == bundleProgram,
              plist["RunAtLoad"] as? Bool == true,
              plist["KeepAlive"] as? Bool == true,
              plist["Program"] == nil else {
            throw RegistrationError.invalidPlist(plistURL.path)
        }
        return releaseIdentity
    }

    private static func validateServiceSignature(
        serviceURL: URL,
        executableURL: URL,
        daemonVersion: String,
        configuration: Configuration
    ) throws -> PortableFSDReleaseIdentity {
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(
            serviceURL as CFURL,
            SecCSFlags(),
            &staticCode
        ) == errSecSuccess,
              let staticCode else {
            throw RegistrationError.invalidServiceSignature(serviceURL.path)
        }

        let requirementText = "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"\(configuration.teamIdentifier)\" and identifier \"\(configuration.serviceBundleIdentifier)\""
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(
            requirementText as CFString,
            SecCSFlags(),
            &requirement
        ) == errSecSuccess,
              let requirement,
              SecStaticCodeCheckValidity(
                staticCode,
                SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures),
                requirement
              ) == errSecSuccess else {
            throw RegistrationError.invalidServiceSignature(serviceURL.path)
        }

        // The release CodeDirectory hash is the native daemon slice's: the
        // one the kernel admits on this machine and later reports for the
        // running image. It is selected explicitly, exactly as the Go CLI
        // does, never by Security's default slice choice, which can differ
        // from the kernel's for subtyped slices.
        var nativeCode: SecStaticCode?
        guard SecStaticCodeCreateWithPathAndAttributes(
            serviceURL as CFURL,
            SecCSFlags(),
            [kSecCodeAttributeArchitecture: try nativeDaemonArchitecture()] as CFDictionary,
            &nativeCode
        ) == errSecSuccess,
              let nativeCode,
              SecStaticCodeCheckValidity(
                nativeCode,
                SecCSFlags(rawValue: kSecCSStrictValidate),
                requirement
              ) == errSecSuccess else {
            throw RegistrationError.invalidServiceSignature(serviceURL.path)
        }

        var rawInformation: CFDictionary?
        guard SecCodeCopySigningInformation(
            nativeCode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &rawInformation
        ) == errSecSuccess,
              let information = rawInformation as? [CFString: Any],
              information[kSecCodeInfoIdentifier] as? String == configuration.serviceBundleIdentifier,
              information[kSecCodeInfoTeamIdentifier] as? String == configuration.teamIdentifier,
              let mainExecutable = information[kSecCodeInfoMainExecutable] as? URL,
              mainExecutable.standardizedFileURL == executableURL.standardizedFileURL,
              let flags = information[kSecCodeInfoFlags] as? NSNumber,
              flags.uint32Value & hardenedRuntimeFlag != 0,
              let unique = information[kSecCodeInfoUnique] as? Data,
              let entitlements = information[kSecCodeInfoEntitlementsDict] as? [String: Any],
              entitlements.count == 1,
              let appGroups = entitlements["com.apple.security.application-groups"] as? [String],
              appGroups == [configuration.appGroupIdentifier],
              entitlements["com.apple.security.get-task-allow"] == nil else {
            throw RegistrationError.invalidServiceSignature(serviceURL.path)
        }

        let executable: Data
        do {
            executable = try Data(contentsOf: executableURL, options: .mappedIfSafe)
        } catch {
            throw RegistrationError.hashServiceExecutable(executableURL.path, error)
        }
        return try PortableFSDReleaseIdentity(
            codeDirectoryHash: unique.map { String(format: "%02x", $0) }.joined(),
            executableSHA256: SHA256.hash(data: executable)
                .map { String(format: "%02x", $0) }
                .joined(),
            daemonVersion: daemonVersion
        ).validated()
    }

    /// A live daemon whose execution proved a signed release of this product
    /// from the app it was started from, with the identity it reported.
    struct RunningDaemon {
        let bundle: Bundle
        let releaseIdentity: PortableFSDReleaseIdentity
        let liveIdentity: PortableFSDLiveIdentity

        func expected() throws -> ExpectedDaemon {
            try ExpectedDaemon(bundle: bundle, releaseIdentity: releaseIdentity)
        }
    }

    /// The exact daemon a lifecycle helper may adopt: the authenticated
    /// release tuple and the canonical executable path inside the owning
    /// bundle it was authenticated from. Never a preference.
    struct ExpectedDaemon: Equatable {
        let executablePath: String
        let releaseIdentity: PortableFSDReleaseIdentity

        init(executablePath: String, releaseIdentity: PortableFSDReleaseIdentity) {
            self.executablePath = executablePath
            self.releaseIdentity = releaseIdentity
        }

        init(bundle: Bundle, releaseIdentity: PortableFSDReleaseIdentity) throws {
            self.init(
                executablePath: try PortableFSDServiceCoordinator.daemonExecutablePath(bundle: bundle),
                releaseIdentity: releaseIdentity
            )
        }
    }

    /// What the control endpoint proves about the service's live owner.
    enum LiveServiceOwner {
        /// No endpoint is published. Only the state singleton, inspected after
        /// mount admission closes, can prove that no daemon remains.
        case unpublished
        case authenticated(RunningDaemon)
    }

    enum ServiceRegistrationStep {
        /// This exact sealed release already runs from this bundle.
        case keep(RunningDaemon)
        /// Replace the service. A non-nil outgoing daemon is the release the
        /// empty-inventory guard and the departure fence are bound to.
        case replace(outgoing: RunningDaemon?)
    }

    /// A valid older release, or this release running from another copy of
    /// the app, is replaced through its authenticated identity. Only an
    /// exact match of release and bundle is kept.
    static func registrationStep(
        for owner: LiveServiceOwner,
        incoming: PortableFSDReleaseIdentity,
        bundleURL: URL
    ) -> ServiceRegistrationStep {
        switch owner {
        case .unpublished:
            return .replace(outgoing: nil)
        case .authenticated(let running):
            if running.releaseIdentity == incoming,
               running.bundle.bundleURL.standardizedFileURL == bundleURL.standardizedFileURL {
                return .keep(running)
            }
            return .replace(outgoing: running)
        }
    }

    private static func reregister(
        service: SMAppService,
        bundle: Bundle,
        socketDirectory: URL,
        outgoing: RunningDaemon?,
        releaseIdentity: PortableFSDReleaseIdentity
    ) throws {
        let updateGuard = try acquireEmptyInventoryGuard(
            bundle: bundle,
            outgoing: try outgoing?.expected()
        )
        defer { updateGuard.release() }

        let processWitness = try replacementWitness(
            outgoing: outgoing,
            probe: {
                try probeLiveDaemon(
                    $0.releaseIdentity,
                    bundle: $0.bundle,
                    pairing: .outgoing
                )
            },
            excludeDaemons: { try acquireStateSingletonExclusion() }
        )
        defer { processWitness.releaseExclusion() }
        if case .excluded(let exclusion) = processWitness {
            // No daemon can run while this exclusion is held, so the absent
            // registry entry is decided before anything is unregistered.
            try exclusion.requireDaemonRegistryAbsent()
        }
        if let outgoing, case .process(let witness) = processWitness {
            // Lifecycle v1 closes the outgoing release's attach admission and
            // proves its complete inventory empty in one transaction, whatever
            // that release's operational and pfslocal numbers are.
            try stopIfIdle(outgoing, processWitness: witness)
        }
        try unregisterAndWait(
            service: service,
            socketDirectory: socketDirectory,
            processWitness: processWitness
        )
        // The incoming daemon takes the state singleton before anything else.
        try requireDaemonRegistryAbsentAtFinalBoundary(
            processWitness,
            excludeDaemons: { try acquireStateSingletonExclusion() }
        )

        try completeRegisteredRelease(
            operation: {
                try service.register()
                guard service.status == .enabled else {
                    throw RegistrationError.registrationDidNotPersist
                }
                try requireLiveDaemon(releaseIdentity, bundle: bundle)
            },
            fence: {
                try fenceNewRegistration(
                    service: service,
                    bundle: bundle,
                    socketDirectory: socketDirectory,
                    releaseIdentity: releaseIdentity
                )
            }
        )
    }

    /// Captures what a replacement must see depart, once mount admission is
    /// closed. An authenticated outgoing daemon is re-proved here; its
    /// identity comes from its signed owning app and live socket peer, never
    /// a preference or the incoming release's version.
    ///
    /// Without a published endpoint the proof of absence must outlive the
    /// unregistration it authorizes: KeepAlive can start the registered
    /// service at any moment, so a free-singleton snapshot would let an
    /// unauthenticated execution start before it is stopped. The app instead
    /// holds the state singleton across unregistration. A singleton already
    /// held means a daemon is still starting or stopping; nothing can
    /// authenticate it, so it is refused.
    static func replacementWitness(
        outgoing: RunningDaemon?,
        probe: (RunningDaemon) throws -> DaemonProcessWitness,
        excludeDaemons: () throws -> StateSingletonExclusion?
    ) throws -> DaemonFenceWitness {
        if let outgoing {
            return .process(try probe(outgoing))
        }
        guard let exclusion = try excludeDaemons() else {
            throw RegistrationError.unauthenticatedServiceOwner(.occupiedStateSingleton)
        }
        return .excluded(exclusion)
    }

    /// The last step before the incoming daemon may start: under the state
    /// singleton, the departed release's registry entry must be absent. An
    /// absent owner's exclusion has been held since before unregistration; a
    /// stopped running owner's departure is followed by taking the singleton
    /// here, which a daemon restarted in the meantime would refuse. The
    /// exclusion is released only after the check, for the incoming daemon.
    static func requireDaemonRegistryAbsentAtFinalBoundary(
        _ witness: DaemonFenceWitness,
        excludeDaemons: () throws -> StateSingletonExclusion?
    ) throws {
        let exclusion: StateSingletonExclusion
        switch witness {
        case .excluded(let held):
            exclusion = held
        case .process, .unpublished:
            guard let taken = try excludeDaemons() else {
                throw RegistrationError.daemonStateSingletonHeld
            }
            exclusion = taken
        }
        defer { exclusion.release() }
        try exclusion.requireDaemonRegistryAbsent()
    }

    /// A registration is never allowed to escape without either proving the
    /// exact sealed release or proving that the attempted service is absent.
    /// Keeping this small boundary injectable gives the error path the same
    /// deterministic test coverage as the happy path without mocking
    /// ServiceManagement itself.
    static func completeRegisteredRelease(
        operation: () throws -> Void,
        fence: () throws -> Void
    ) throws {
        do {
            try operation()
        } catch {
            let registrationError = error
            do {
                try fence()
            } catch {
                throw RegistrationError.registrationFenceFailed(
                    registrationError.localizedDescription,
                    error.localizedDescription
                )
            }
            throw registrationError
        }
    }

    private static func failRegisteredRelease(
        _ failure: Error,
        service: SMAppService,
        bundle: Bundle,
        socketDirectory: URL,
        releaseIdentity: PortableFSDReleaseIdentity
    ) throws -> Never {
        try completeRegisteredRelease(
            operation: { throw failure },
            fence: {
                try fenceNewRegistration(
                    service: service,
                    bundle: bundle,
                    socketDirectory: socketDirectory,
                    releaseIdentity: releaseIdentity
                )
            }
        )
        fatalError("unreachable")
    }

    private static func fenceNewRegistration(
        service: SMAppService,
        bundle: Bundle,
        socketDirectory: URL,
        releaseIdentity: PortableFSDReleaseIdentity
    ) throws {
        switch service.status {
        case .notFound, .notRegistered:
            try waitForServiceFence(
                service: service,
                paths: try runtimePaths(socketDirectory: socketDirectory),
                processWitness: .unpublished
            )
        case .enabled, .requiresApproval:
            let witness = (try? probeLiveDaemon(releaseIdentity, bundle: bundle, pairing: .outgoing))
                .map(DaemonFenceWitness.process) ?? .unpublished
            try unregisterAndWait(
                service: service,
                socketDirectory: socketDirectory,
                processWitness: witness
            )
        @unknown default:
            let witness = (try? probeLiveDaemon(releaseIdentity, bundle: bundle, pairing: .outgoing))
                .map(DaemonFenceWitness.process) ?? .unpublished
            try unregisterAndWait(
                service: service,
                socketDirectory: socketDirectory,
                processWitness: witness
            )
        }
    }

    private static func unregisterAndWait(
        service: SMAppService,
        socketDirectory: URL,
        processWitness: DaemonFenceWitness
    ) throws {
        try service.unregister()
        try waitForServiceFence(
            service: service,
            paths: try runtimePaths(socketDirectory: socketDirectory),
            processWitness: processWitness
        )
    }

    private static func waitForServiceFence(
        service: SMAppService,
        paths: [URL],
        processWitness: DaemonFenceWitness
    ) throws {
        let unregisterDeadline = Date().addingTimeInterval(10)
        while Date() < unregisterDeadline {
            let processAbsent = try processWitness.hasDeparted()
            let socketsAbsent = try runtimePathsAbsent(paths)
            if serviceFenceReady(
                statusNotRegistered: service.status == .notRegistered,
                runtimePathsAbsent: socketsAbsent,
                processDeparted: processAbsent
            ) {
                break
            }
            Thread.sleep(forTimeInterval: 0.1)
        }
        guard service.status == .notRegistered else {
            throw RegistrationError.unregisterDidNotComplete
        }
        try requireRuntimePathsAbsent(paths)
        guard try processWitness.hasDeparted() else {
            throw RegistrationError.daemonProcessStillPresent
        }
    }

    static func serviceFenceReady(
        statusNotRegistered: Bool,
        runtimePathsAbsent: Bool,
        processDeparted: Bool
    ) -> Bool {
        statusNotRegistered && runtimePathsAbsent && processDeparted
    }

    private static func runtimePaths(bundle: Bundle) throws -> [URL] {
        try runtimePaths(
            socketDirectory: try PortableFSAppGroupBootstrap.prepare(bundle: bundle)
        )
    }

    private static func runtimePaths(socketDirectory: URL) throws -> [URL] {
        [
            try controlSocketURL(),
            socketDirectory.appendingPathComponent("pfs.sock", isDirectory: false),
        ]
    }

    private final class EmptyInventoryGuard {
        private let process: Process
        private let input: FileHandle
        private var released = false

        init(process: Process, input: FileHandle) {
            self.process = process
            self.input = input
        }

        func release() {
            guard !released else { return }
            released = true
            try? input.close()
            let cleanDeadline = Date().addingTimeInterval(2)
            while process.isRunning && Date() < cleanDeadline {
                Thread.sleep(forTimeInterval: 0.02)
            }
            if process.isRunning {
                process.terminate()
            }
            let terminateDeadline = Date().addingTimeInterval(2)
            while process.isRunning && Date() < terminateDeadline {
                Thread.sleep(forTimeInterval: 0.02)
            }
            if process.isRunning {
                _ = Darwin.kill(process.processIdentifier, SIGKILL)
            }
            let killDeadline = Date().addingTimeInterval(2)
            while process.isRunning && Date() < killDeadline {
                Thread.sleep(forTimeInterval: 0.02)
            }
            if !process.isRunning {
                process.waitUntilExit()
            }
        }

        deinit {
            release()
        }
    }

    /// The install-exclusive helper reads the lifecycle inventory of exactly
    /// the authenticated outgoing daemon: its release tuple and the canonical
    /// executable path in the bundle it was authenticated from, all four or
    /// none. Without a published endpoint there is no live identity to bind;
    /// the helper then proves the inventory empty without adopting a daemon,
    /// and this app decides registry absence under the state singleton.
    static func inventoryGuardArguments(
        outgoing: ExpectedDaemon?
    ) -> [String] {
        var arguments = ["lifecycle", "hold-install-exclusive", "--json"]
        if let outgoing {
            arguments += [
                "--expected-daemon-version", outgoing.releaseIdentity.daemonVersion,
                "--expected-daemon-sha256", outgoing.releaseIdentity.executableSHA256,
                "--expected-daemon-path", outgoing.executablePath,
                "--expected-daemon-cdhash", outgoing.releaseIdentity.codeDirectoryHash,
            ]
        }
        return arguments
    }

    private static func acquireEmptyInventoryGuard(
        bundle: Bundle,
        outgoing: ExpectedDaemon?
    ) throws -> EmptyInventoryGuard {
        let cliURL = bundle.bundleURL
            .appendingPathComponent("Contents/Helpers", isDirectory: true)
            .appendingPathComponent("portablefs", isDirectory: false)
        guard FileManager.default.isExecutableFile(atPath: cliURL.path) else {
            throw RegistrationError.missingHelper(cliURL.path)
        }

        let process = Process()
        let input = Pipe()
        let output = Pipe()
        let errors = Pipe()
        process.executableURL = cliURL
        process.arguments = inventoryGuardArguments(outgoing: outgoing)
        process.standardInput = input
        process.standardOutput = output
        process.standardError = errors
        do {
            try process.run()
        } catch {
            throw RegistrationError.inventoryPreflight(error.localizedDescription)
        }

        let guardHandle = EmptyInventoryGuard(
            process: process,
            input: input.fileHandleForWriting
        )
        let frame: Data
        do {
            frame = try readOneReadinessLine(
                from: output.fileHandleForReading.fileDescriptor,
                timeout: 5
            )
        } catch {
            guardHandle.release()
            let detail = boundedDiagnostic(
                from: errors.fileHandleForReading.fileDescriptor,
                timeout: 0.2
            )
            throw RegistrationError.inventoryPreflight(
                detail.isEmpty ? error.localizedDescription : detail
            )
        }
        guard let payload = try? JSONDecoder().decode(
            InstallExclusiveReadiness.self,
            from: frame
        ),
              payload.schemaVersion == 1,
              payload.held,
              payload.purpose == "service-update",
              payload.kernelMounts == 0,
              payload.mountRecords == 0,
              payload.mountIntents == 0,
              payload.durableAttaches == 0,
              payload.liveAttaches == 0 else {
            guardHandle.release()
            throw RegistrationError.inventoryPreflight(
                "the install-exclusive helper returned an invalid readiness frame"
            )
        }
        return guardHandle
    }

    private static func readOneReadinessLine(
        from descriptor: Int32,
        timeout: TimeInterval
    ) throws -> Data {
        let deadline = Date().addingTimeInterval(timeout)
        var frame = Data()
        while Date() < deadline && frame.count < 4096 {
            let milliseconds = max(
                1,
                Int32(deadline.timeIntervalSinceNow * 1_000)
            )
            var pollDescriptor = pollfd(
                fd: descriptor,
                events: Int16(POLLIN | POLLHUP),
                revents: 0
            )
            let ready = Darwin.poll(&pollDescriptor, 1, milliseconds)
            if ready < 0, errno == EINTR { continue }
            guard ready > 0 else {
                throw RegistrationError.inventoryPreflight(
                    "timed out waiting for install-exclusive readiness"
                )
            }
            var byte: UInt8 = 0
            let count = Darwin.read(descriptor, &byte, 1)
            if count < 0, errno == EINTR { continue }
            guard count == 1 else {
                throw RegistrationError.inventoryPreflight(
                    "install-exclusive helper closed before readiness"
                )
            }
            frame.append(byte)
            if byte == 0x0A {
                return frame
            }
        }
        throw RegistrationError.inventoryPreflight(
            "install-exclusive readiness exceeded its exact frame bound"
        )
    }

    private static func controlSocketURL() throws -> URL {
        let path: String
        do {
            path = try PortableFSAccountHome.resolve()
        } catch {
            throw RegistrationError.invalidControlSocketRoot(
                String(describing: error)
            )
        }
        return URL(fileURLWithPath: path, isDirectory: true)
            .appendingPathComponent(".local/state/portablefs/portablefsd", isDirectory: true)
            .appendingPathComponent("control.sock", isDirectory: false)
    }

    /// Proves that no daemon can still act through the canonical state
    /// singleton. portablefsd acquires this lock before every other singleton
    /// and releases it last, so a nonblocking exclusive flock after
    /// ServiceManagement reports `.notRegistered` is the exact no-publication
    /// fence for a service that never produced an authenticated control peer.
    private static func stateSingletonIsUnlocked() throws -> Bool {
        try stateSingletonIsUnlocked(at: stateDirectoryURL())
    }

    static func stateSingletonIsUnlocked(
        at stateDirectory: URL,
        beforeFinalRecheck: (() throws -> Void)? = nil
    ) throws -> Bool {
        switch try lockStateSingleton(
            at: stateDirectory,
            creating: false,
            beforeFinalRecheck: beforeFinalRecheck
        ) {
        case .absent:
            return true
        case .held:
            return false
        case .owned(let exclusion):
            exclusion.release()
            return true
        }
    }

    private static func acquireStateSingletonExclusion() throws -> StateSingletonExclusion? {
        try acquireStateSingletonExclusion(at: stateDirectoryURL())
    }

    /// Takes and keeps the state singleton, creating the private directory
    /// and lock exactly as portablefsd would when neither exists yet, so a
    /// daemon starting at any later moment contends on this lock. Nil when a
    /// daemon already holds it. The flock on the one canonical inode is the
    /// whole exclusion: the lock's contents are never written or consulted,
    /// so no stale bytes can grant anyone a takeover.
    static func acquireStateSingletonExclusion(
        at stateDirectory: URL,
        beforeFinalRecheck: (() throws -> Void)? = nil
    ) throws -> StateSingletonExclusion? {
        switch try lockStateSingleton(
            at: stateDirectory,
            creating: true,
            beforeFinalRecheck: beforeFinalRecheck
        ) {
        case .absent:
            throw RegistrationError.invalidDaemonStateSingleton
        case .held:
            return nil
        case .owned(let exclusion):
            return exclusion
        }
    }

    private static func stateDirectoryURL() throws -> URL {
        try controlSocketURL().deletingLastPathComponent()
    }

    enum StateSingletonLock {
        /// Neither the directory nor the lock exists, and none was created.
        case absent
        /// Another process holds the lock.
        case held
        case owned(StateSingletonExclusion)
    }

    private static let stateSingletonName = ".portablefsd-state.lock"
    /// The daemon's persisted attach registry. Its absence, decided under the
    /// state singleton, is the only format-independent proof that a release
    /// that cannot run left no persisted attachment behind.
    static let daemonRegistryName = "attaches.json"

    /// The one secure boundary for the state singleton: the directory must be
    /// this account's private 0700 directory and the lock this account's
    /// single-link 0600 regular file, both pinned by descriptor and rechecked
    /// by name after the lock is taken.
    static func lockStateSingleton(
        at stateDirectory: URL,
        creating: Bool,
        beforeFinalRecheck: (() throws -> Void)? = nil,
        lockName: String = ".portablefsd-state.lock"
    ) throws -> StateSingletonLock {
        guard let directory = try openStateDirectory(at: stateDirectory, creating: creating) else {
            return .absent
        }
        var directoryOwned = false
        defer { if !directoryOwned { Darwin.close(directory) } }
        var pinnedDirectory = stat()
        guard Darwin.fstat(directory, &pinnedDirectory) == 0 else {
            throw RegistrationError.inspectDaemonStateSingleton(errno)
        }

        let name = lockName
        let lock: Int32
        var namedLock = stat()
        let lockExisted = Darwin.fstatat(directory, name, &namedLock, AT_SYMLINK_NOFOLLOW) == 0
        if lockExisted {
            // Validate before opening: a FIFO or device must never be opened.
            guard namedLock.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
                  namedLock.st_uid == geteuid(),
                  namedLock.st_mode & 0o777 == 0o600,
                  namedLock.st_nlink == 1 else {
                throw RegistrationError.invalidDaemonStateSingleton
            }
            lock = Darwin.openat(directory, name, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
        } else {
            let code = errno
            guard code == ENOENT else {
                throw RegistrationError.inspectDaemonStateSingleton(code)
            }
            guard creating else {
                try beforeFinalRecheck?()
                try recheckPinnedDirectory(stateDirectory, expected: pinnedDirectory)
                return .absent
            }
            lock = Darwin.openat(
                directory,
                name,
                O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                0o600
            )
            if lock >= 0, Darwin.fchmod(lock, 0o600) != 0 {
                let failure = errno
                Darwin.close(lock)
                throw RegistrationError.inspectDaemonStateSingleton(failure)
            }
        }
        guard lock >= 0 else {
            throw RegistrationError.inspectDaemonStateSingleton(errno)
        }
        var lockOwned = false
        defer { if !lockOwned { Darwin.close(lock) } }
        var pinnedLock = stat()
        guard Darwin.fstat(lock, &pinnedLock) == 0,
              pinnedLock.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              pinnedLock.st_uid == geteuid(),
              pinnedLock.st_mode & 0o777 == 0o600,
              pinnedLock.st_nlink == 1,
              !lockExisted || (
                pinnedLock.st_dev == namedLock.st_dev
                    && pinnedLock.st_ino == namedLock.st_ino
              ) else {
            throw RegistrationError.invalidDaemonStateSingleton
        }

        if portableFSFlock(lock, LOCK_EX | LOCK_NB) != 0 {
            let code = errno
            if code == EWOULDBLOCK || code == EAGAIN { return .held }
            throw RegistrationError.inspectDaemonStateSingleton(code)
        }
        let exclusion = StateSingletonExclusion(
            directory: directory,
            lock: lock,
            pinnedLock: pinnedLock,
            directoryURL: stateDirectory,
            pinnedDirectory: pinnedDirectory,
            lockName: lockName
        )
        directoryOwned = true
        lockOwned = true
        do {
            try beforeFinalRecheck?()
            try exclusion.confirmHeld()
            try recheckPinnedDirectory(stateDirectory, expected: pinnedDirectory)
        } catch {
            exclusion.release()
            throw error
        }
        return .owned(exclusion)
    }

    /// Match Go's privatepath boundary: pin every component without following
    /// symlinks. An unsafe ancestor cannot redirect the singleton and registry
    /// checks to an empty substitute. Missing directories are created through
    /// their pinned parent, with the same private mode as the daemon uses.
    private static func openStateDirectory(at url: URL, creating: Bool) throws -> Int32? {
        let path = url.path
        let components = path.split(separator: "/", omittingEmptySubsequences: false).dropFirst()
        guard path.hasPrefix("/"), !components.isEmpty,
              components.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
            throw RegistrationError.invalidDaemonStateSingleton
        }
        var current = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard current >= 0 else { throw RegistrationError.inspectDaemonStateSingleton(errno) }
        defer { if current >= 0 { Darwin.close(current) } }
        for (index, rawComponent) in components.enumerated() {
            let component = String(rawComponent)
            var next = Darwin.openat(current, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            if next < 0, errno == ENOENT, creating {
                if Darwin.mkdirat(current, component, 0o700) != 0, errno != EEXIST {
                    throw RegistrationError.inspectDaemonStateSingleton(errno)
                }
                guard Darwin.fsync(current) == 0 else {
                    throw RegistrationError.inspectDaemonStateSingleton(errno)
                }
                next = Darwin.openat(current, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            }
            guard next >= 0 else {
                let code = errno
                if code == ENOENT, !creating { return nil }
                throw RegistrationError.inspectDaemonStateSingleton(code)
            }
            var accepted = false
            defer { if !accepted { Darwin.close(next) } }
            var opened = stat()
            var named = stat()
            guard Darwin.fstat(next, &opened) == 0,
                  Darwin.fstatat(current, component, &named, AT_SYMLINK_NOFOLLOW) == 0,
                  opened.st_dev == named.st_dev, opened.st_ino == named.st_ino,
                  opened.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR),
                  opened.st_uid == 0 || opened.st_uid == geteuid() else {
                throw RegistrationError.invalidDaemonStateSingleton
            }
            let final = index == components.count - 1
            let rootSticky = !final && opened.st_uid == 0 && opened.st_mode & mode_t(S_ISVTX) != 0
            guard opened.st_mode & 0o022 == 0 || rootSticky,
                  !final || (opened.st_uid == geteuid() && opened.st_mode & 0o777 == 0o700) else {
                throw RegistrationError.invalidDaemonStateSingleton
            }
            Darwin.close(current)
            current = next
            accepted = true
        }
        let result = current
        current = -1
        return result
    }

    fileprivate static func recheckPinnedDirectory(
        _ directory: URL,
        expected: stat
    ) throws {
        guard let descriptor = try openStateDirectory(at: directory, creating: false) else {
            throw RegistrationError.invalidDaemonStateSingleton
        }
        defer { Darwin.close(descriptor) }
        var current = stat()
        guard Darwin.fstat(descriptor, &current) == 0,
              current.st_dev == expected.st_dev,
              current.st_ino == expected.st_ino,
              current.st_mode == expected.st_mode,
              current.st_uid == expected.st_uid else {
            throw RegistrationError.invalidDaemonStateSingleton
        }
    }

    private static func runtimePathExists(_ path: String) throws -> Bool {
        var status = stat()
        if lstat(path, &status) == 0 { return true }
        let code = errno
        if code == ENOENT { return false }
        throw RegistrationError.inspectRuntimePath(path, code)
    }

    private static func runtimePathsAbsent(_ paths: [URL]) throws -> Bool {
        for path in paths where try runtimePathExists(path.path) {
            return false
        }
        return true
    }

    private static func requireRuntimePathsAbsent(_ paths: [URL]) throws {
        for path in paths where try runtimePathExists(path.path) {
            throw RegistrationError.runtimePathPresent(path.path)
        }
    }

    private static func boundedDiagnostic(
        from descriptor: Int32,
        timeout: TimeInterval
    ) -> String {
        let deadline = Date().addingTimeInterval(timeout)
        var data = Data()
        while Date() < deadline && data.count < 4096 {
            let milliseconds = max(1, Int32(deadline.timeIntervalSinceNow * 1_000))
            var pollDescriptor = pollfd(fd: descriptor, events: Int16(POLLIN | POLLHUP), revents: 0)
            let ready = Darwin.poll(&pollDescriptor, 1, milliseconds)
            if ready < 0, errno == EINTR { continue }
            if ready <= 0 { break }
            var buffer = [UInt8](repeating: 0, count: min(512, 4096 - data.count))
            let count = Darwin.read(descriptor, &buffer, buffer.count)
            if count < 0, errno == EINTR { continue }
            if count <= 0 { break }
            data.append(buffer, count: count)
        }
        return String(data: data, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    }

    /// Classifies whoever serves the account's daemon control endpoint. A
    /// missing endpoint is not proof of absence by itself; see
    /// `replacementWitness`. Every owner that cannot be authenticated as a
    /// signed release of this product is refused and never stopped, because
    /// only authentication identifies whose mount inventory the replacement
    /// may trust. A refusal names a cause only where this probe observed it;
    /// otherwise it reports the step that failed and the underlying error.
    static func inspectLiveServiceOwner(
        controlSocket: URL,
        configuration: Configuration
    ) throws -> LiveServiceOwner {
        let socket = controlSocket.path
        func refuse(_ owner: UnauthenticatedServiceOwner) -> RegistrationError {
            .unauthenticatedServiceOwner(owner)
        }
        let fd: Int32
        do {
            fd = try PfsUnixSocket.connect(path: socket)
        } catch PfsLocalClientError.system(let code, let operation)
            where operation == "connect" {
            if code == ENOENT { return .unpublished }
            throw refuse(.unreachableEndpoint(socket: socket, errno: code))
        }
        defer { PfsUnixSocket.close(fd) }

        let peer: DaemonPeer
        do {
            peer = try captureDaemonPeer(fd)
        } catch RegistrationError.unresolvableDaemonExecutable(let code) where code == ESRCH {
            throw refuse(.exitedDuringProof)
        } catch RegistrationError.inspectDaemonProcess(let code) where code == ESRCH {
            throw refuse(.exitedDuringProof)
        } catch RegistrationError.unresolvableDaemonExecutable(let code) {
            throw refuse(.unauthenticated(
                socket: socket,
                step: .executableResolution,
                failure: String(cString: strerror(code))
            ))
        } catch RegistrationError.inspectDaemonProcess(let code) {
            throw refuse(.unauthenticated(
                socket: socket,
                step: .peerBinding,
                failure: String(cString: strerror(code))
            ))
        } catch RegistrationError.invalidDaemonProcessWitness {
            throw refuse(.unauthenticated(
                socket: socket,
                step: .peerBinding,
                failure: "its peer credentials, audit token, and process ID do not identify one execution owned by this account"
            ))
        }
        let bundleURL: URL
        do {
            bundleURL = try daemonOwningBundle(executableURL: peer.executableURL)
        } catch {
            throw refuse(.foreignProcess(socket: socket, executable: peer.executableURL.path))
        }
        let app = bundleURL.path
        let owner = try ownerApp(at: bundleURL, expected: configuration, controlSocket: socket)
        let witness: DaemonProcessWitness
        do {
            witness = try authenticateDaemonPeer(
                peer,
                releaseIdentity: owner.releaseIdentity,
                bundle: owner.bundle
            )
        } catch RegistrationError.invalidDaemonProcessWitness {
            if try peer.processWitness.hasExited() { throw refuse(.exitedDuringProof) }
            throw refuse(.unauthenticated(
                socket: socket,
                step: .daemonSignature(app: app),
                failure: "its running image is not that app's daemon: its path, kernel code directory hash, or valid hardened-runtime signature does not match"
            ))
        }
        let reported: PortableFSDLiveIdentity
        do {
            reported = try readDaemonIdentity(fd)
        } catch {
            if try witness.hasExited() { throw refuse(.exitedDuringProof) }
            throw refuse(.unauthenticated(
                socket: socket,
                step: .daemonIdentity,
                failure: error.localizedDescription
            ))
        }
        // The authenticated execution reports its own protocol numbers; they
        // are accepted with its exact version and executable hash. This
        // build's numbers are never expected of that release here: only this
        // app's own daemon must be paired, which `requirePaired` decides.
        guard reported.matches(owner.releaseIdentity) else {
            throw refuse(identityRefusal(
                reported: reported,
                sealed: owner.releaseIdentity,
                app: app,
                socket: socket
            ))
        }
        guard try !witness.hasExited() else {
            throw refuse(.exitedDuringProof)
        }
        return .authenticated(RunningDaemon(
            bundle: owner.bundle,
            releaseIdentity: owner.releaseIdentity,
            liveIdentity: reported
        ))
    }

    /// The running image matched the app on disk, but the daemon's reported
    /// release did not: a different version or executable is direct evidence
    /// that the app was replaced while the old executable kept running.
    static func identityRefusal(
        reported: PortableFSDLiveIdentity,
        sealed: PortableFSDReleaseIdentity,
        app: String,
        socket: String
    ) -> UnauthenticatedServiceOwner {
        .ownerAppReplaced(
            app: app,
            running: "\(reported.daemonVersion) (executable \(reported.executableSha256.prefix(12)))",
            installed: "\(sealed.daemonVersion) (executable \(sealed.executableSHA256.prefix(12)))"
        )
    }

    struct OwnerApp {
        let bundle: Bundle
        let configuration: Configuration
        let releaseIdentity: PortableFSDReleaseIdentity
    }

    /// Authenticates the app a live daemon was started from, as it exists on
    /// disk now. Only an absent path is reported as a missing app, and only a
    /// valid bundle of another signed product as a foreign owner; any other
    /// failure is reported as exactly that failure.
    static func ownerApp(
        at bundleURL: URL,
        expected: Configuration,
        controlSocket: String
    ) throws -> OwnerApp {
        let app = bundleURL.path
        func refuse(_ owner: UnauthenticatedServiceOwner) -> RegistrationError {
            .unauthenticatedServiceOwner(owner)
        }
        func refuse(_ step: AuthenticationStep, _ failure: String) -> RegistrationError {
            refuse(.unauthenticated(socket: controlSocket, step: step, failure: failure))
        }
        var entry = stat()
        guard Darwin.lstat(app, &entry) == 0 else {
            let code = errno
            if code == ENOENT || code == ENOTDIR {
                throw refuse(.ownerAppMissing(app: app))
            }
            throw refuse(.ownerAppInspection(app: app), String(cString: strerror(code)))
        }
        guard entry.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR),
              let bundle = Bundle(url: bundleURL) else {
            throw refuse(.ownerAppSignature(app: app), "the path is not an app bundle")
        }
        let configuration: Configuration
        do {
            configuration = try validateHostAndConfiguration(bundle: bundle)
        } catch {
            throw refuse(.ownerAppSignature(app: app), error.localizedDescription)
        }
        do {
            try validateServiceOwner(configuration, expected: expected)
        } catch {
            throw refuse(.foreignService(app: app))
        }
        let releaseIdentity: PortableFSDReleaseIdentity
        do {
            releaseIdentity = try sealedRelease(
                bundle: bundle,
                configuration: configuration
            )
        } catch {
            throw refuse(.ownerAppSignature(app: app), error.localizedDescription)
        }
        return OwnerApp(
            bundle: bundle,
            configuration: configuration,
            releaseIdentity: releaseIdentity
        )
    }

    /// The kernel supplies the executing path; only the canonical nested
    /// service layout can identify an owning app. No app-directory search or
    /// preference can nominate a different release for that socket.
    static func daemonOwningBundle(executableURL: URL) throws -> URL {
        guard executableURL.isFileURL else {
            throw RegistrationError.invalidDaemonProcessWitness
        }
        var owner = executableURL
        for component in bundleProgram.split(separator: "/").reversed() {
            guard owner.lastPathComponent == component else {
                throw RegistrationError.invalidDaemonProcessWitness
            }
            owner.deleteLastPathComponent()
        }
        guard owner.pathExtension == "app" else {
            throw RegistrationError.invalidHostBundle(owner.path)
        }
        return owner
    }

    static func validateServiceOwner(_ owner: Configuration, expected: Configuration) throws {
        guard owner.hostBundleIdentifier == expected.hostBundleIdentifier,
              owner.plistName == expected.plistName,
              owner.label == expected.label,
              owner.serviceBundleIdentifier == expected.serviceBundleIdentifier,
              owner.teamIdentifier == expected.teamIdentifier,
              owner.appGroupIdentifier == expected.appGroupIdentifier else {
            throw RegistrationError.liveIdentityFailed(
                "the control socket belongs to a different signed service"
            )
        }
    }

    /// Activation and every ordinary use of this app's own daemon: the
    /// authenticated execution must report this release and this build's
    /// exact pairing before success is reported.
    private static func requireLiveDaemon(
        _ releaseIdentity: PortableFSDReleaseIdentity,
        bundle: Bundle
    ) throws {
        let deadline = Date().addingTimeInterval(10)
        var lastError: Error?
        repeat {
            do {
                let witness = try probeLiveDaemon(releaseIdentity, bundle: bundle, pairing: .incoming)
                witness.close()
                return
            } catch {
                lastError = error
                Thread.sleep(forTimeInterval: 0.1)
            }
        } while Date() < deadline
        throw RegistrationError.liveIdentityFailed(
            lastError?.localizedDescription ?? "timed out"
        )
    }

    /// Which live-identity rule a probe applies after authentication.
    enum LivePairing {
        /// This app's own daemon being activated or used: its live numbers
        /// must equal this build's exact pairing.
        case incoming
        /// A release being quiesced, verified for removal or fenced: its own
        /// valid numbers are accepted with its exact version and hash.
        case outgoing
    }

    /// A mismatch prevents activation success and every operational request.
    static func requirePaired(_ live: PortableFSDLiveIdentity) throws {
        guard isPaired(live) else {
            throw RegistrationError.unpairedLiveDaemon(
                "schema \(live.schemaVersion), control \(live.controlProtocol), pfslocal \(live.pfslocalMajor).\(live.pfslocalMinor)"
            )
        }
    }

    /// Connects to the account's control socket and authenticates the peer
    /// as `releaseIdentity` running from `bundle`, before any request.
    private static func probeLiveDaemon(
        _ releaseIdentity: PortableFSDReleaseIdentity,
        bundle: Bundle,
        pairing: LivePairing
    ) throws -> DaemonProcessWitness {
        let fd = try PfsUnixSocket.connect(path: try controlSocketURL().path)
        defer { PfsUnixSocket.close(fd) }
        let processWitness = try authenticateDaemonPeer(
            captureDaemonPeer(fd),
            releaseIdentity: releaseIdentity,
            bundle: bundle
        )
        try requireDaemonIdentity(
            fd,
            releaseIdentity: releaseIdentity,
            pairing: pairing,
            processWitness: processWitness
        )
        return processWitness
    }

    private static func requireDaemonIdentity(
        _ fd: Int32,
        releaseIdentity: PortableFSDReleaseIdentity,
        pairing: LivePairing,
        processWitness: DaemonProcessWitness
    ) throws {
        let identity = try readDaemonIdentity(fd)
        guard identity.matches(releaseIdentity) else {
            throw RegistrationError.liveIdentityFailed(
                "running daemon does not match the sealed executable"
            )
        }
        if pairing == .incoming {
            try requirePaired(identity)
        }
        guard try !processWitness.hasExited() else {
            throw RegistrationError.liveIdentityFailed(
                "authenticated daemon exited during identity proof"
            )
        }
    }

    private static func setLifecycleTimeouts(_ fd: Int32) throws {
        var timeout = timeval(tv_sec: 2, tv_usec: 0)
        guard setsockopt(
            fd,
            SOL_SOCKET,
            SO_RCVTIMEO,
            &timeout,
            socklen_t(MemoryLayout<timeval>.size)
        ) == 0,
              setsockopt(
                fd,
                SOL_SOCKET,
                SO_SNDTIMEO,
                &timeout,
                socklen_t(MemoryLayout<timeval>.size)
              ) == 0 else {
            throw RegistrationError.liveIdentityFailed("set socket timeout")
        }
    }

    /// Reads the lifecycle v1 identity on an already authenticated control
    /// connection.
    private static func readDaemonIdentity(_ fd: Int32) throws -> PortableFSDLiveIdentity {
        try setLifecycleTimeouts(fd)
        do {
            return try PortableFSDLifecycle.identity(from: PortableFSDLifecycle.exchange(
                fd,
                method: "GET",
                path: PortableFSDLifecycle.identityPath
            ))
        } catch PortableFSDLifecycleError.refused(let status) {
            throw RegistrationError.liveIdentityFailed("lifecycle identity answered HTTP \(status)")
        } catch {
            throw RegistrationError.liveIdentityFailed("invalid lifecycle identity reply")
        }
    }

    /// Asks an authenticated running daemon to close its attach admission and
    /// stop if, atomically, its complete registered inventory is empty. The
    /// request goes only to the exact execution `processWitness` pinned: a new
    /// connection must authenticate as the same signed daemon from the same
    /// app, with the same pid and pid version. A busy refusal leaves the
    /// daemon serving exactly as it was.
    private static func stopIfIdle(
        _ running: RunningDaemon,
        processWitness: DaemonProcessWitness
    ) throws {
        try stopIfIdle(
            bundle: running.bundle,
            releaseIdentity: running.releaseIdentity,
            processWitness: processWitness
        )
    }

    private static func stopIfIdle(
        bundle: Bundle,
        releaseIdentity: PortableFSDReleaseIdentity,
        processWitness: DaemonProcessWitness
    ) throws {
        let fd = try PfsUnixSocket.connect(path: try controlSocketURL().path)
        defer { PfsUnixSocket.close(fd) }
        let peer = try captureDaemonPeer(fd)
        defer { peer.processWitness.close() }
        _ = try authenticateDaemonPeer(
            peer,
            releaseIdentity: releaseIdentity,
            bundle: bundle
        )
        guard peer.processWitness.pid == processWitness.pid,
              peer.processWitness.pidVersion == processWitness.pidVersion else {
            throw RegistrationError.invalidDaemonProcessWitness
        }
        try setLifecycleTimeouts(fd)
        do {
            try PortableFSDLifecycle.stopIfIdleOutcome(PortableFSDLifecycle.exchange(
                fd,
                method: "POST",
                path: PortableFSDLifecycle.stopIfIdlePath
            ))
        } catch PortableFSDLifecycleError.busy {
            throw RegistrationError.outgoingReleaseBusy
        } catch PortableFSDLifecycleError.refused(let status) {
            throw RegistrationError.lifecycleStopRefused("HTTP \(status)")
        } catch {
            throw RegistrationError.lifecycleStopRefused("invalid reply")
        }
    }

    struct DaemonPeer {
        let auditToken: audit_token_t
        let executableURL: URL
        let processWitness: DaemonProcessWitness
    }

    static func captureDaemonPeer(_ descriptor: Int32) throws -> DaemonPeer {
        var peerUID: uid_t = 0
        var peerGID: gid_t = 0
        guard Darwin.getpeereid(descriptor, &peerUID, &peerGID) == 0,
              peerUID == geteuid() else {
            throw RegistrationError.invalidDaemonProcessWitness
        }

        var token = audit_token_t()
        var tokenSize = socklen_t(MemoryLayout<audit_token_t>.size)
        guard Darwin.getsockopt(
            descriptor,
            SOL_LOCAL,
            LOCAL_PEERTOKEN,
            &token,
            &tokenSize
        ) == 0,
              tokenSize == MemoryLayout<audit_token_t>.size,
              audit_token_to_euid(token) == geteuid() else {
            throw RegistrationError.invalidDaemonProcessWitness
        }
        let pid = audit_token_to_pid(token)
        let pidVersion = audit_token_to_pidversion(token)
        var socketPID: pid_t = 0
        var socketPIDSize = socklen_t(MemoryLayout<pid_t>.size)
        guard Darwin.getsockopt(
            descriptor,
            SOL_LOCAL,
            LOCAL_PEERPID,
            &socketPID,
            &socketPIDSize
        ) == 0,
              socketPIDSize == MemoryLayout<pid_t>.size,
              pid > 0,
              socketPID == pid,
              pidVersion > 0 else {
            throw RegistrationError.invalidDaemonProcessWitness
        }

        guard let path = tokenExecutablePath(&token) else {
            throw RegistrationError.unresolvableDaemonExecutable(errno)
        }
        let executableURL = URL(fileURLWithPath: path, isDirectory: false)

        // Register the process event before inspecting code. If this execution
        // exits at any point after its audit token was captured, the queued
        // NOTE_EXIT makes the witness terminal even if the numeric PID is
        // immediately recycled.
        let processWitness = try DaemonProcessWitness(
            pid: pid,
            pidVersion: pidVersion
        )
        return DaemonPeer(
            auditToken: token,
            executableURL: executableURL,
            processWitness: processWitness
        )
    }

    /// The executable path the kernel binds to this exact token, or nil with
    /// errno set when the execution cannot be resolved.
    private static func tokenExecutablePath(_ token: inout audit_token_t) -> String? {
        var path = [CChar](repeating: 0, count: 4 * 1_024)
        guard proc_pidpath_audittoken(&token, &path, UInt32(path.count)) > 0 else {
            return nil
        }
        let bytes = path.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        let resolved = String(decoding: bytes, as: UTF8.self)
        return resolved.hasPrefix("/") ? resolved : nil
    }

    /// Authenticates a socket peer as the daemon of `releaseIdentity` running
    /// from `bundle`. The bundle itself was already authenticated statically
    /// (signature, identifier, team, hardened runtime and entitlements) when
    /// `releaseIdentity` was derived from it; this proves the peer's running
    /// image is exactly that signed code at its canonical path.
    private static func authenticateDaemonPeer(
        _ peer: DaemonPeer,
        releaseIdentity: PortableFSDReleaseIdentity,
        bundle: Bundle
    ) throws -> DaemonProcessWitness {
        try requireRunningImage(
            peer,
            expectedPath: try daemonExecutablePath(bundle: bundle),
            expectedCDHash: releaseIdentity.codeDirectoryHash
        )
        return peer.processWitness
    }

    // CS_OPS_STATUS, CS_OPS_CDHASH and CS_VALID from XNU's sys/codesign.h;
    // CS_RUNTIME is `hardenedRuntimeFlag`.
    private static let csOpsStatus: UInt32 = 0
    private static let csOpsCDHash: UInt32 = 5
    private static let csValid: UInt32 = 0x0000_0001

    /// The running-image rule, identical to the Go CLI's: the token-bound
    /// executable path equals the canonical daemon path of the authenticated
    /// owner bundle; the kernel reports valid, hardened-runtime code for that
    /// token; and the kernel's CodeDirectory hash of the running text equals
    /// the authenticated release's, all 20 bytes. Every query uses the one
    /// captured token, validity is rechecked after the hash is read, and the
    /// path is reproved last. Any syscall failure, departed or replaced
    /// execution, or mismatch refuses the connection; nothing is retried
    /// against a bare PID and no pathname is reopened or hashed.
    static func requireRunningImage(
        _ peer: DaemonPeer,
        expectedPath: String,
        expectedCDHash: String
    ) throws {
        var token = peer.auditToken
        let pid = peer.processWitness.pid
        guard peer.executableURL.path == expectedPath,
              audit_token_to_euid(token) == geteuid(),
              audit_token_to_pid(token) == pid,
              audit_token_to_pidversion(token) == peer.processWitness.pidVersion else {
            throw RegistrationError.invalidDaemonProcessWitness
        }
        let required = csValid | hardenedRuntimeFlag
        func validHardenedCode() -> Bool {
            var flags: UInt32 = 0
            return portableFSCSOpsAuditToken(
                pid,
                csOpsStatus,
                &flags,
                MemoryLayout<UInt32>.size,
                &token
            ) == 0 && flags & required == required
        }
        guard validHardenedCode() else {
            throw RegistrationError.invalidDaemonProcessWitness
        }
        var cdhash = [UInt8](repeating: 0, count: 20)
        guard portableFSCSOpsAuditToken(pid, csOpsCDHash, &cdhash, cdhash.count, &token) == 0,
              validHardenedCode(),
              cdhash.map({ String(format: "%02x", $0) }).joined() == expectedCDHash,
              tokenExecutablePath(&token) == expectedPath,
              try !peer.processWitness.hasExited() else {
            throw RegistrationError.invalidDaemonProcessWitness
        }
    }

    /// The step of live-owner authentication that failed when no more
    /// specific cause was observed.
    enum AuthenticationStep: Equatable {
        case peerBinding
        case executableResolution
        case ownerAppInspection(app: String)
        case ownerAppSignature(app: String)
        case daemonSignature(app: String)
        case daemonIdentity

        var action: String {
            switch self {
            case .peerBinding:
                return "bind the process serving it to one execution in this account"
            case .executableResolution:
                return "resolve the executable of the process serving it"
            case .ownerAppInspection(let app):
                return "inspect \(app), the app that started its daemon"
            case .ownerAppSignature(let app):
                return "authenticate \(app), the app that started its daemon"
            case .daemonSignature(let app):
                return "authenticate its running daemon against \(app)"
            case .daemonIdentity:
                return "read its running daemon's release identity"
            }
        }
    }

    /// A live service owner, or the state singleton behind a missing
    /// endpoint, that this app cannot authenticate. Each case states only
    /// what the probe observed; the replacement is refused in every case.
    enum UnauthenticatedServiceOwner: Equatable {
        /// connect(2) to the endpoint failed with this errno.
        case unreachableEndpoint(socket: String, errno: Int32)
        /// No endpoint is published, but another process holds the state
        /// singleton.
        case occupiedStateSingleton
        /// The endpoint is served by an executable outside the daemon service
        /// nested in an app bundle.
        case foreignProcess(socket: String, executable: String)
        /// A validly signed app of another product, team, or app group owns
        /// the endpoint.
        case foreignService(app: String)
        /// The kernel names the daemon's executable inside an app that no
        /// longer exists at that path.
        case ownerAppMissing(app: String)
        /// The daemon reports a different release or executable than the
        /// signed app at its path.
        case ownerAppReplaced(app: String, running: String, installed: String)
        /// An authentication step failed; nothing more is established.
        case unauthenticated(socket: String, step: AuthenticationStep, failure: String)
        /// The daemon exited while it was being authenticated.
        case exitedDuringProof

        var diagnosis: String {
            let refusal = "PortableFS stops or replaces only a daemon it can authenticate, because authentication identifies the daemon whose mount inventory the replacement then proves empty."
            let installer = "Update PortableFS only with its installer, which quiesces the running daemon before it replaces the app."
            let orphanRecovery = "Unmount any PortableFS volumes, log out of macOS and back in to end that daemon, then reopen PortableFS. \(installer)"
            let daemonLog = "~/.local/state/portablefs/portablefsd.log"
            switch self {
            case let .unreachableEndpoint(socket, code) where code == ECONNREFUSED:
                return "A socket exists at \(socket), but no daemon accepted a connection on it (\(String(cString: strerror(code)))). \(refusal) Reopen PortableFS in a moment: a starting daemon replaces a socket left by one that stopped. If this persists, \(daemonLog) records why no daemon is listening."
            case let .unreachableEndpoint(socket, code):
                return "PortableFS could not connect to its daemon control socket at \(socket): \(String(cString: strerror(code))). \(refusal) PortableFS leaves that path unchanged; \(daemonLog) records the daemon's own view of it."
            case .occupiedStateSingleton:
                return "No PortableFS daemon has published its control socket, but another process holds the PortableFS state lock: a daemon that is starting or stopping, or another copy of PortableFS replacing the service. \(refusal) Reopen PortableFS once it settles. If this persists, quit every other copy of PortableFS; if it still persists, log out of macOS and back in."
            case let .foreignProcess(socket, executable):
                return "The PortableFS daemon control socket at \(socket) is served by \(executable), which is not the daemon service nested in a PortableFS app. \(refusal) Quit that program, then reopen PortableFS."
            case let .foreignService(app):
                return "The running PortableFS daemon belongs to \(app), a different signed PortableFS product; only one product can own this account's daemon. \(refusal) Quit that app and turn off its background item in System Settings > General > Login Items, then reopen this app."
            case let .ownerAppMissing(app):
                return "The running PortableFS daemon was started from \(app), which no longer exists at that path. \(refusal) \(orphanRecovery)"
            case let .ownerAppReplaced(app, running, installed):
                return "The running PortableFS daemon is release \(running), but \(app) now contains release \(installed): the app was replaced while its daemon ran. \(refusal) \(orphanRecovery)"
            case let .unauthenticated(socket, step, failure):
                let reason = failure.hasSuffix(".") ? failure : failure + "."
                return "PortableFS could not \(step.action) for the daemon control socket at \(socket): \(reason) \(refusal) Quit any other copy of PortableFS and reopen this one. If the app that started the daemon was deleted or replaced while it ran, unmount any PortableFS volumes and log out of macOS and back in to end that daemon. \(installer)"
            case .exitedDuringProof:
                return "The PortableFS daemon exited while PortableFS was authenticating it. Reopen PortableFS."
            }
        }
    }

    enum RegistrationError: LocalizedError {
        case invalidHostBundle(String)
        case invalidHostSignature(String)
        case missingHelper(String)
        case invalidServiceBundle(String)
        case unexpectedServiceProfile(String)
        case invalidServiceSignature(String)
        case hashServiceExecutable(String, any Error)
        case invalidPlist(String)
        case unpairedLiveDaemon(String)
        case daemonRegistryPresent
        case inspectDaemonRegistry(Int32)
        case inventoryPreflight(String)
        case outgoingReleaseBusy
        case lifecycleStopRefused(String)
        case invalidControlSocketRoot(String)
        case runtimePathPresent(String)
        case inspectRuntimePath(String, Int32)
        case inspectDaemonProcess(Int32)
        case unresolvableDaemonExecutable(Int32)
        case invalidDaemonProcessWitness
        case unauthenticatedServiceOwner(UnauthenticatedServiceOwner)
        case inspectDaemonStateSingleton(Int32)
        case invalidDaemonStateSingleton
        case daemonStateSingletonHeld
        case daemonProcessStillPresent
        case unregisterDidNotComplete
        case liveIdentityFailed(String)
        case serviceNotFound
        case registrationDidNotPersist
        case registrationFailed(any Error)
        case registrationFenceFailed(String, String)
        case unknownStatus

        var errorDescription: String? {
            switch self {
            case .invalidHostBundle(let path):
                return "The PortableFS host bundle has an incomplete signed identity at \(path)."
            case .invalidHostSignature(let path):
                return "The PortableFS host signature, team, or app-group identity is invalid at \(path)."
            case .missingHelper(let path):
                return "The sealed app has no executable PortableFS daemon at \(path)."
            case .invalidServiceBundle(let path):
                return "The sealed app has an invalid PortableFS daemon service bundle at \(path)."
            case .unexpectedServiceProfile(let path):
                return "The PortableFS daemon service unexpectedly embeds a provisioning profile at \(path)."
            case .invalidServiceSignature(let path):
                return "The PortableFS daemon service has an invalid Developer ID signature or entitlement set at \(path)."
            case .hashServiceExecutable(let path, let error):
                return "Could not hash the sealed PortableFS daemon at \(path): \(error.localizedDescription)"
            case .invalidPlist(let path):
                return "The sealed app has an invalid PortableFS LaunchAgent property list at \(path)."
            case .unpairedLiveDaemon(let reported):
                return "This app's PortableFS daemon reports protocol numbers (\(reported)) that are not paired with this app's frontend, so it was not activated."
            case .daemonRegistryPresent:
                return "The stopped PortableFS daemon left a persisted attach registry, so nothing was replaced. Reopen the PortableFS release that owns those volumes and unmount them, then try again."
            case .inspectDaemonRegistry(let code):
                return "PortableFS could not prove the stopped daemon's attach registry absent: \(String(cString: strerror(code)))"
            case .outgoingReleaseBusy:
                return "The running PortableFS daemon still has registered volumes, so it was left running. Unmount every PortableFS volume, then try again."
            case .lifecycleStopRefused(let detail):
                return "The running PortableFS daemon did not confirm an idle stop (\(detail)); it was left in place and nothing was replaced."
            case .inventoryPreflight(let detail):
                return "PortableFS could not prove an empty mount and daemon-attach inventory before service replacement (\(detail)). Unmount every PortableFS volume and quit any other copy of PortableFS, then try again."
            case .invalidControlSocketRoot(let path):
                return "PortableFS could not resolve its canonical account control root from \(path)."
            case .runtimePathPresent(let path):
                return "PortableFS service replacement found a live runtime path at \(path)."
            case .inspectRuntimePath(let path, let code):
                return "PortableFS could not prove runtime path absence at \(path): \(String(cString: strerror(code)))"
            case .inspectDaemonProcess(let code):
                return "PortableFS could not inspect the authenticated daemon process: \(String(cString: strerror(code)))"
            case .unresolvableDaemonExecutable(let code):
                return "PortableFS could not resolve the executable of the live daemon process: \(String(cString: strerror(code)))"
            case .invalidDaemonProcessWitness:
                return "PortableFS could not bind the live daemon to its exact signed process execution."
            case .unauthenticatedServiceOwner(let owner):
                return owner.diagnosis
            case .inspectDaemonStateSingleton(let code):
                return "PortableFS could not inspect the canonical daemon state singleton: \(String(cString: strerror(code)))"
            case .invalidDaemonStateSingleton:
                return "PortableFS found an unsafe or replaced canonical daemon state singleton."
            case .daemonStateSingletonHeld:
                return "PortableFS found the canonical daemon state singleton still held after service removal."
            case .daemonProcessStillPresent:
                return "PortableFS found the authenticated daemon process still running after service removal."
            case .unregisterDidNotComplete:
                return "Service Management did not finish unregistering the previous PortableFS daemon."
            case .liveIdentityFailed(let detail):
                return "The live PortableFS daemon did not prove the sealed release identity: \(detail)"
            case .serviceNotFound:
                return "Service Management could not find the bundled PortableFS LaunchAgent."
            case .registrationDidNotPersist:
                return "Service Management did not persist the PortableFS LaunchAgent registration."
            case .registrationFailed(let error):
                return "Service Management refused the PortableFS LaunchAgent: \(error.localizedDescription)"
            case .registrationFenceFailed(let registration, let fence):
                return "PortableFS registration failed (\(registration)) and the app could not prove the attempted daemon absent (\(fence)); service state is ambiguous and remains fail-closed."
            case .unknownStatus:
                return "Service Management returned an unknown PortableFS LaunchAgent status."
            }
        }
    }
}

extension PortableFSDServiceCoordinator {
    /// Binds the caller's live text to the statically verified enclosing release
    /// before it trusts that release's nested service pins. This uses the same
    /// audit-token rule as socket peers, including after an app is replaced.
    public static func requireCurrentRunningImage(expectedPath: String, expectedCDHash: String) throws {
        var token = audit_token_t()
        var count = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<integer_t>.size)
        let status = withUnsafeMutablePointer(to:&token) { pointer in
            pointer.withMemoryRebound(to:integer_t.self,capacity:Int(count)) {
                task_info(mach_task_self_,task_flavor_t(TASK_AUDIT_TOKEN),$0,&count)
            }
        }
        guard status == KERN_SUCCESS else { throw PortableFSSignedServiceError.invalidIdentity }
        let witness = try DaemonProcessWitness(pid:getpid(),pidVersion:audit_token_to_pidversion(token))
        defer { witness.close() }
        let peer = DaemonPeer(auditToken:token,executableURL:URL(fileURLWithPath:expectedPath),processWitness:witness)
        try requireRunningImage(peer,expectedPath:expectedPath,expectedCDHash:expectedCDHash)
    }
}

// The installer already holds the shared product's exclusive lifecycle guard.
// The workspace's durable marker is independent of any private registry format.
extension PortableFSDServiceCoordinator {
    static func quiesceWorkspaceForInstaller(bundle: Bundle) throws {
        guard let identifier = bundle.bundleIdentifier else { throw PortableFSSignedServiceError.invalidBundle }
        // The manual-registration development host has no workspace component.
        guard FileManager.default.fileExists(atPath: bundle.bundleURL.appendingPathComponent("Contents/Library/LaunchAgents/PortableFSWorkspaceService.app").path) else { return }
        let directory = URL(fileURLWithPath: try PortableFSAccountHome.resolve(), isDirectory: true).appendingPathComponent(".local/state/portablefs/workspace", isDirectory: true)
        try requireWorkspaceResourceWitnessAbsent(directory)
        let service = SMAppService.agent(plistName: identifier + ".workspace.plist")
        switch service.status {
        case .enabled, .requiresApproval: try service.unregister()
        case .notRegistered, .notFound: break
        @unknown default: throw PortableFSSignedServiceError.invalidIdentity
        }
        let deadline = Date().addingTimeInterval(10)
        repeat {
            if service.status == .notRegistered || service.status == .notFound {
                switch try lockStateSingleton(at: directory, creating: false, lockName: "service.lock") {
                case .absent:
                    try requireWorkspaceResourceWitnessAbsent(directory)
                    return
                case .owned(let exclusion):
                    defer { exclusion.release() }
                    try exclusion.requireResourceAbsent("resources.present")
                    var socket = stat()
                    let path = directory.appendingPathComponent("control.sock").path
                    guard lstat(path, &socket) != 0, errno == ENOENT else { throw PortableFSSignedServiceError.invalidIdentity }
                    return
                case .held: break
                }
            }
            Thread.sleep(forTimeInterval: 0.05)
        } while Date() < deadline
        throw PortableFSSignedServiceError.codeValidation("workspace singleton release unconfirmed")
    }
}

extension PortableFSDServiceCoordinator {
    private static func requireWorkspaceResourceWitnessAbsent(_ url: URL) throws {
        guard let directory = try openStateDirectory(at: url, creating: false) else { return }
        defer { Darwin.close(directory) }
        var pinned = stat(), entry = stat()
        guard fstat(directory, &pinned) == 0 else { throw PortableFSSignedServiceError.invalidIdentity }
        guard fstatat(directory, "resources.present", &entry, AT_SYMLINK_NOFOLLOW) != 0, errno == ENOENT else {
            throw PortableFSSignedServiceError.codeValidation("workspace resources remain; cleanly stop Linux Workspace before updating")
        }
        guard fsync(directory) == 0 else { throw PortableFSSignedServiceError.invalidIdentity }
        try recheckPinnedDirectory(url, expected: pinned)
    }
}
