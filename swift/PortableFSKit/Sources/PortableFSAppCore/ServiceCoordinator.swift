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

public struct PortableFSDReleaseIdentity: Codable, Equatable, Sendable {
    public let codeDirectoryHash: String
    public let executableSHA256: String
    public let daemonVersion: String
    public let identitySchema: Int
    public let controlProtocol: Int
    public let pfslocalMajor: UInt32
    public let pfslocalMinor: UInt32

    public init(
        codeDirectoryHash: String,
        executableSHA256: String,
        daemonVersion: String,
        identitySchema: Int,
        controlProtocol: Int,
        pfslocalMajor: UInt32,
        pfslocalMinor: UInt32
    ) {
        self.codeDirectoryHash = codeDirectoryHash
        self.executableSHA256 = executableSHA256
        self.daemonVersion = daemonVersion
        self.identitySchema = identitySchema
        self.controlProtocol = controlProtocol
        self.pfslocalMajor = pfslocalMajor
        self.pfslocalMinor = pfslocalMinor
    }

    func validate() throws {
        guard Self.isLowerHex(codeDirectoryHash, count: 40),
              Self.isLowerHex(executableSHA256, count: 64),
              !daemonVersion.isEmpty,
              daemonVersion.count <= 128,
              daemonVersion.utf8.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }),
              identitySchema > 0,
              controlProtocol > 0,
              pfslocalMajor > 0 else {
            throw PortableFSDReleaseIdentityError.invalid
        }
    }

    enum CodingKeys: String, CodingKey {
        case codeDirectoryHash
        case executableSHA256
        case daemonVersion
        case identitySchema
        case controlProtocol
        case pfslocalMajor
        case pfslocalMinor
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
    private static let identitySchemaVersion = 1
    private static let controlProtocolVersion = 1
    private static let pfsLocalMajor: UInt32 = 1
    private static let pfsLocalMinor: UInt32 = 16
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

    struct LiveDaemonIdentity: Decodable {
        let schemaVersion: Int
        let controlProtocol: Int
        let daemonVersion: String
        let executableSha256: String
        let pfslocalMajor: UInt32
        let pfslocalMinor: UInt32

        func releaseIdentity(sealed: PortableFSDReleaseIdentity) throws -> PortableFSDReleaseIdentity {
            guard schemaVersion == identitySchemaVersion,
                  controlProtocol == controlProtocolVersion,
                  daemonVersion == sealed.daemonVersion,
                  executableSha256 == sealed.executableSHA256 else {
                throw RegistrationError.liveIdentityFailed(
                    "running daemon does not match its signed owning app"
                )
            }
            // The authenticated outgoing binary declares its local protocol;
            // the incoming app's compiled protocol cannot describe an older release.
            return try PortableFSDReleaseIdentity(
                codeDirectoryHash: sealed.codeDirectoryHash,
                executableSHA256: sealed.executableSHA256,
                daemonVersion: sealed.daemonVersion,
                identitySchema: schemaVersion,
                controlProtocol: controlProtocol,
                pfslocalMajor: pfslocalMajor,
                pfslocalMinor: pfslocalMinor
            ).validated()
        }
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
        case process(DaemonProcessWitness)
        /// This app holds the state singleton, so no daemon can run.
        case excluded(StateSingletonExclusion)
        /// Departure is proven by finding the state singleton free.
        case unpublished

        func hasDeparted() throws -> Bool {
            switch self {
            case .process(let witness):
                return try witness.hasExited()
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

        init(directory: Int32, lock: Int32, pinnedLock: stat) {
            self.directory = directory
            self.lock = lock
            self.pinnedLock = pinnedLock
        }

        deinit { release() }

        /// Fails unless the canonical name still denotes the locked inode.
        func confirmHeld() throws {
            var current = stat()
            guard lock >= 0,
                  Darwin.fstatat(
                    directory,
                    PortableFSDServiceCoordinator.stateSingletonName,
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

        /// Writes this process's owner record in portablefsd's schema 1:
        /// pid plus the kernel start time that distinguishes it from a
        /// recycled pid, formatted as the daemon formats it on Darwin.
        func publishOwnerRecord(owner: String) throws {
            struct Record: Encodable {
                let schemaVersion: Int
                let pid: Int32
                let startIdentity: String
                let version: String
                let owner: String
            }
            let pid = getpid()
            var info = kinfo_proc()
            var size = MemoryLayout<kinfo_proc>.stride
            var name: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
            guard Darwin.sysctl(&name, 4, &info, &size, nil, 0) == 0,
                  info.kp_proc.p_pid == pid else {
                throw RegistrationError.inspectDaemonStateSingleton(errno)
            }
            let start = info.kp_proc.p_un.__p_starttime
            var body = try JSONEncoder().encode(Record(
                schemaVersion: 1,
                pid: pid,
                startIdentity: "\(start.tv_sec):\(start.tv_usec)",
                version: "",
                owner: owner
            ))
            body.append(0x0A)
            guard Darwin.ftruncate(lock, 0) == 0 else {
                throw RegistrationError.inspectDaemonStateSingleton(errno)
            }
            let written = body.withUnsafeBytes { bytes in
                Darwin.pwrite(lock, bytes.baseAddress, bytes.count, 0)
            }
            guard written == body.count, Darwin.fsync(lock) == 0 else {
                throw RegistrationError.inspectDaemonStateSingleton(written < 0 ? errno : EIO)
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
        let releaseIdentity = try validateSealedBundle(
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
            case .keep:
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
        return try validateSealedBundle(
            bundle: bundle,
            configuration: configuration
        )
    }

    static func prepareForInstallerUpdate(
        bundle: Bundle = .main
    ) throws -> PortableFSDReleaseIdentity {
        let configuration = try validateHostAndConfiguration(bundle: bundle)
        let socketDirectory = try PortableFSAppGroupBootstrap.prepare(bundle: bundle)
        let releaseIdentity = try validateSealedBundle(
            bundle: bundle,
            configuration: configuration
        )
        let service = SMAppService.agent(plistName: configuration.plistName)
        guard service.status == .enabled else {
            throw RegistrationError.registrationDidNotPersist
        }
        let updateGuard = try acquireEmptyInventoryGuard(
            bundle: bundle,
            runningIdentity: releaseIdentity
        )
        do {
            // Capture the exact current listener only after the mount/attach
            // inventory guard is held, closing the daemon-restart gap between
            // admission proof and ServiceManagement unregistration.
            let processWitness = try probeLiveDaemon(
                releaseIdentity,
                bundle: bundle
            )
            try unregisterAndWait(
                service: service,
                socketDirectory: socketDirectory,
                processWitness: .process(processWitness)
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
        let sealed = try validateSealedBundle(
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
        let sealed = try validateSealedBundle(
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
        let sealed = try validateSealedBundle(
            bundle: bundle,
            configuration: configuration
        )
        guard sealed == expectedRelease else {
            throw RegistrationError.liveIdentityFailed(
                "the installer fence target is not this sealed release"
            )
        }
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
        let processWitness = try probeLiveDaemon(sealed, bundle: bundle)
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
        let sealed = try validateSealedBundle(
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
            runningIdentity: expectedRelease
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

    private static func validateSealedBundle(
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

        var rawInformation: CFDictionary?
        guard SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &rawInformation
        ) == errSecSuccess,
              let information = rawInformation as? [CFString: Any],
              information[kSecCodeInfoIdentifier] as? String == configuration.serviceBundleIdentifier,
              information[kSecCodeInfoTeamIdentifier] as? String == configuration.teamIdentifier,
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
            daemonVersion: daemonVersion,
            identitySchema: identitySchemaVersion,
            controlProtocol: controlProtocolVersion,
            pfslocalMajor: pfsLocalMajor,
            pfslocalMinor: pfsLocalMinor
        ).validated()
    }

    /// A live daemon whose execution proved a signed release of this product
    /// from the app it was started from.
    struct RunningDaemon {
        let bundle: Bundle
        let releaseIdentity: PortableFSDReleaseIdentity
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
        case keep
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
                return .keep
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
            runningIdentity: outgoing?.releaseIdentity
        )
        defer { updateGuard.release() }

        let processWitness = try replacementWitness(
            outgoing: outgoing,
            probe: { try probeLiveDaemon($0.releaseIdentity, bundle: $0.bundle) },
            excludeDaemons: { try acquireStateSingletonExclusion() }
        )
        defer { processWitness.releaseExclusion() }
        try unregisterAndWait(
            service: service,
            socketDirectory: socketDirectory,
            processWitness: processWitness
        )
        // The incoming daemon takes the state singleton before anything else.
        processWitness.releaseExclusion()

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
            let witness = (try? probeLiveDaemon(releaseIdentity, bundle: bundle))
                .map(DaemonFenceWitness.process) ?? .unpublished
            try unregisterAndWait(
                service: service,
                socketDirectory: socketDirectory,
                processWitness: witness
            )
        @unknown default:
            let witness = (try? probeLiveDaemon(releaseIdentity, bundle: bundle))
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
            socketDirectory.appendingPathComponent("pfs-root.sock", isDirectory: false),
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

    /// The install-exclusive helper reads the attach inventory of exactly the
    /// authenticated outgoing release. Without a published endpoint there is
    /// no live identity to bind, and the helper proves the inventory empty
    /// without adopting a daemon.
    static func inventoryGuardArguments(
        outgoing: PortableFSDReleaseIdentity?
    ) -> [String] {
        var arguments = ["lifecycle", "hold-install-exclusive", "--json"]
        if let outgoing {
            arguments += [
                "--expected-daemon-version", outgoing.daemonVersion,
                "--expected-daemon-sha256", outgoing.executableSHA256,
                "--expected-pfslocal-major", String(outgoing.pfslocalMajor),
                "--expected-pfslocal-minor", String(outgoing.pfslocalMinor),
            ]
        }
        return arguments
    }

    private static func acquireEmptyInventoryGuard(
        bundle: Bundle,
        runningIdentity: PortableFSDReleaseIdentity?
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
        process.arguments = inventoryGuardArguments(outgoing: runningIdentity)
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
    /// daemon already holds it. The holder publishes its own owner record in
    /// the daemon's format: a starting daemon that finds the lock held reads
    /// that record, and must classify a live holder rather than prove the
    /// previous daemon's stale record departed and take the lock over.
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
            do {
                try exclusion.publishOwnerRecord(owner: stateDirectory.path)
            } catch {
                exclusion.release()
                throw error
            }
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

    /// The one secure boundary for the state singleton: the directory must be
    /// this account's private 0700 directory and the lock this account's
    /// single-link 0600 regular file, both pinned by descriptor and rechecked
    /// by name after the lock is taken.
    static func lockStateSingleton(
        at stateDirectory: URL,
        creating: Bool,
        beforeFinalRecheck: (() throws -> Void)? = nil
    ) throws -> StateSingletonLock {
        var namedDirectory = stat()
        if Darwin.lstat(stateDirectory.path, &namedDirectory) != 0 {
            let code = errno
            guard code == ENOENT else {
                throw RegistrationError.inspectDaemonStateSingleton(code)
            }
            guard creating else { return .absent }
            do {
                try FileManager.default.createDirectory(
                    at: stateDirectory,
                    withIntermediateDirectories: true,
                    attributes: [.posixPermissions: 0o700]
                )
            } catch {
                var code = EIO
                if let underlying = (error as NSError).userInfo[NSUnderlyingErrorKey] as? NSError,
                   underlying.domain == NSPOSIXErrorDomain {
                    code = Int32(underlying.code)
                }
                throw RegistrationError.inspectDaemonStateSingleton(code)
            }
            guard Darwin.lstat(stateDirectory.path, &namedDirectory) == 0 else {
                throw RegistrationError.inspectDaemonStateSingleton(errno)
            }
        }
        guard namedDirectory.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR),
              namedDirectory.st_uid == geteuid(),
              namedDirectory.st_mode & 0o777 == 0o700 else {
            throw RegistrationError.invalidDaemonStateSingleton
        }
        let directory = Darwin.open(
            stateDirectory.path,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        guard directory >= 0 else {
            throw RegistrationError.inspectDaemonStateSingleton(errno)
        }
        var directoryOwned = false
        defer { if !directoryOwned { Darwin.close(directory) } }

        var pinnedDirectory = stat()
        guard Darwin.fstat(directory, &pinnedDirectory) == 0,
              pinnedDirectory.st_dev == namedDirectory.st_dev,
              pinnedDirectory.st_ino == namedDirectory.st_ino,
              pinnedDirectory.st_mode == namedDirectory.st_mode,
              pinnedDirectory.st_uid == namedDirectory.st_uid else {
            throw RegistrationError.invalidDaemonStateSingleton
        }

        let name = stateSingletonName
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
            pinnedLock: pinnedLock
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

    private static func recheckPinnedDirectory(
        _ directory: URL,
        expected: stat
    ) throws {
        var current = stat()
        guard Darwin.lstat(directory.path, &current) == 0,
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
                configuration: owner.configuration,
                bundle: owner.bundle
            )
        } catch RegistrationError.invalidDaemonProcessWitness {
            if try peer.processWitness.hasExited() { throw refuse(.exitedDuringProof) }
            throw refuse(.unauthenticated(
                socket: socket,
                step: .daemonSignature(app: app),
                failure: "its running code does not satisfy that app's signing requirement, code directory hash, or entitlements"
            ))
        }
        let reported: LiveDaemonIdentity
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
        let runningIdentity: PortableFSDReleaseIdentity
        do {
            runningIdentity = try reported.releaseIdentity(sealed: owner.releaseIdentity)
        } catch {
            throw refuse(identityRefusal(
                reported: reported,
                sealed: owner.releaseIdentity,
                app: app,
                socket: socket,
                failure: error
            ))
        }
        guard try !witness.hasExited() else {
            throw refuse(.exitedDuringProof)
        }
        return .authenticated(
            RunningDaemon(bundle: owner.bundle, releaseIdentity: runningIdentity)
        )
    }

    /// The code signature matched the app on disk, but the daemon's reported
    /// identity did not. A different release or executable is direct
    /// evidence that the app was replaced while the old executable kept
    /// running; any other mismatch is only a failed identity proof.
    static func identityRefusal(
        reported: LiveDaemonIdentity,
        sealed: PortableFSDReleaseIdentity,
        app: String,
        socket: String,
        failure: Error
    ) -> UnauthenticatedServiceOwner {
        guard reported.daemonVersion != sealed.daemonVersion
            || reported.executableSha256 != sealed.executableSHA256 else {
            return .unauthenticated(
                socket: socket,
                step: .daemonIdentity,
                failure: failure.localizedDescription
            )
        }
        return .ownerAppReplaced(
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
            releaseIdentity = try validateSealedBundle(
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
        var owner = executableURL.standardizedFileURL
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

    private static func requireLiveDaemon(
        _ releaseIdentity: PortableFSDReleaseIdentity,
        bundle: Bundle
    ) throws {
        let deadline = Date().addingTimeInterval(10)
        var lastError: Error?
        repeat {
            do {
                let witness = try probeLiveDaemon(releaseIdentity, bundle: bundle)
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

    private static func probeLiveDaemon(
        _ releaseIdentity: PortableFSDReleaseIdentity,
        bundle: Bundle
    ) throws -> DaemonProcessWitness {
        let configuration = try validateHostAndConfiguration(bundle: bundle)
        let fd = try PfsUnixSocket.connect(path: try controlSocketURL().path)
        defer { PfsUnixSocket.close(fd) }
        let processWitness = try authenticateDaemonPeer(
            captureDaemonPeer(fd),
            releaseIdentity: releaseIdentity,
            configuration: configuration,
            bundle: bundle
        )
        try requireDaemonIdentity(fd, releaseIdentity: releaseIdentity, processWitness: processWitness)
        return processWitness
    }

    private static func requireDaemonIdentity(
        _ fd: Int32,
        releaseIdentity: PortableFSDReleaseIdentity,
        processWitness: DaemonProcessWitness
    ) throws {
        let identity = try readDaemonIdentity(fd)
        guard identity.schemaVersion == releaseIdentity.identitySchema,
              identity.controlProtocol == releaseIdentity.controlProtocol,
              identity.daemonVersion == releaseIdentity.daemonVersion,
              identity.executableSha256 == releaseIdentity.executableSHA256,
              identity.pfslocalMajor == releaseIdentity.pfslocalMajor,
              identity.pfslocalMinor == releaseIdentity.pfslocalMinor else {
            throw RegistrationError.liveIdentityFailed(
                "running daemon does not match the sealed executable"
            )
        }
        guard try !processWitness.hasExited() else {
            throw RegistrationError.liveIdentityFailed(
                "authenticated daemon exited during identity proof"
            )
        }
    }

    private static func readDaemonIdentity(_ fd: Int32) throws -> LiveDaemonIdentity {
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

        let request = Data(
            "GET /v1/identity HTTP/1.1\r\nHost: portablefsd\r\nConnection: close\r\n\r\n".utf8
        )
        var sent = 0
        while sent < request.count {
            let count = request.withUnsafeBytes { bytes in
                guard let baseAddress = bytes.baseAddress else { return -1 }
                return Darwin.write(fd, baseAddress.advanced(by: sent), request.count - sent)
            }
            if count < 0, errno == EINTR { continue }
            guard count > 0 else {
                throw RegistrationError.liveIdentityFailed("write control request")
            }
            sent += count
        }

        var response = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while response.count <= 1 << 20 {
            let count = Darwin.read(fd, &buffer, buffer.count)
            if count < 0, errno == EINTR { continue }
            if count == 0 { break }
            guard count > 0 else {
                throw RegistrationError.liveIdentityFailed("read control reply")
            }
            response.append(buffer, count: count)
        }
        guard response.count <= 1 << 20,
              let boundary = response.range(of: Data("\r\n\r\n".utf8)),
              let header = String(
                data: response[..<boundary.lowerBound],
                encoding: .utf8
              ),
              header.hasPrefix("HTTP/1.1 200 ") else {
            throw RegistrationError.liveIdentityFailed("invalid control reply")
        }
        let body = response[boundary.upperBound...]
        try PortableFSDStrictJSON.validate(Data(body))
        return try JSONDecoder().decode(LiveDaemonIdentity.self, from: body)
    }

    private struct DaemonPeer {
        let auditToken: Data
        let executableURL: URL
        let processWitness: DaemonProcessWitness
    }

    private static func captureDaemonPeer(_ descriptor: Int32) throws -> DaemonPeer {
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

        var path = [CChar](repeating: 0, count: 4 * 1_024)
        let pathLength = proc_pidpath_audittoken(
            &token,
            &path,
            UInt32(path.count)
        )
        guard pathLength > 0 else {
            throw RegistrationError.unresolvableDaemonExecutable(errno)
        }
        let pathBytes = path.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        let executableURL = URL(
            fileURLWithPath: String(decoding: pathBytes, as: UTF8.self),
            isDirectory: false
        ).standardizedFileURL

        // Register the process event before inspecting code. If this execution
        // exits at any point after its audit token was captured, the queued
        // NOTE_EXIT makes the witness terminal even if the numeric PID is
        // immediately recycled.
        let processWitness = try DaemonProcessWitness(
            pid: pid,
            pidVersion: pidVersion
        )
        return DaemonPeer(
            auditToken: withUnsafeBytes(of: &token) { Data($0) },
            executableURL: executableURL,
            processWitness: processWitness
        )
    }

    private static func authenticateDaemonPeer(
        _ peer: DaemonPeer,
        releaseIdentity: PortableFSDReleaseIdentity,
        configuration: Configuration,
        bundle: Bundle
    ) throws -> DaemonProcessWitness {
        let expectedExecutable = bundle.bundleURL
            .appendingPathComponent(bundleProgram, isDirectory: false)
            .standardizedFileURL
        guard peer.executableURL == expectedExecutable else {
            throw RegistrationError.invalidDaemonProcessWitness
        }
        let attributes = [kSecGuestAttributeAudit: peer.auditToken] as CFDictionary
        var dynamicCode: SecCode?
        guard SecCodeCopyGuestWithAttributes(
            nil,
            attributes,
            SecCSFlags(),
            &dynamicCode
        ) == errSecSuccess,
              let dynamicCode else {
            throw RegistrationError.invalidDaemonProcessWitness
        }

        let requirementText = "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"\(configuration.teamIdentifier)\" and identifier \"\(configuration.serviceBundleIdentifier)\""
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(
            requirementText as CFString,
            SecCSFlags(),
            &requirement
        ) == errSecSuccess,
              let requirement,
              SecCodeCheckValidity(
                dynamicCode,
                SecCSFlags(rawValue: kSecCSStrictValidate),
                requirement
              ) == errSecSuccess else {
            throw RegistrationError.invalidDaemonProcessWitness
        }

        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(
            dynamicCode,
            SecCSFlags(),
            &staticCode
        ) == errSecSuccess,
              let staticCode,
              SecStaticCodeCheckValidity(
                staticCode,
                SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures),
                requirement
              ) == errSecSuccess else {
            throw RegistrationError.invalidDaemonProcessWitness
        }
        var rawInformation: CFDictionary?
        guard SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &rawInformation
        ) == errSecSuccess,
              let information = rawInformation as? [CFString: Any],
              information[kSecCodeInfoIdentifier] as? String == configuration.serviceBundleIdentifier,
              information[kSecCodeInfoTeamIdentifier] as? String == configuration.teamIdentifier,
              let mainExecutable = information[kSecCodeInfoMainExecutable] as? URL,
              mainExecutable.standardizedFileURL == expectedExecutable,
              let flags = information[kSecCodeInfoFlags] as? NSNumber,
              flags.uint32Value & hardenedRuntimeFlag != 0,
              let unique = information[kSecCodeInfoUnique] as? Data,
              unique.map({ String(format: "%02x", $0) }).joined() == releaseIdentity.codeDirectoryHash,
              let entitlements = information[kSecCodeInfoEntitlementsDict] as? [String: Any],
              entitlements.count == 1,
              entitlements["com.apple.security.application-groups"] as? [String] == [configuration.appGroupIdentifier],
              entitlements["com.apple.security.get-task-allow"] == nil,
              try !peer.processWitness.hasExited() else {
            throw RegistrationError.invalidDaemonProcessWitness
        }
        return peer.processWitness
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
        case inventoryPreflight(String)
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
