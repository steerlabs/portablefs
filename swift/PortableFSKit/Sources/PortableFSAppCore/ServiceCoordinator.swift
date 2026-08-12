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
    private static let registeredIdentityDefaultsKey = "PFSRegisteredLaunchAgentIdentity"
    private static let identitySchemaVersion = 1
    private static let controlProtocolVersion = 1
    private static let pfsLocalMajor: UInt32 = 1
    private static let pfsLocalMinor: UInt32 = 14
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

    private struct LiveDaemonIdentity: Decodable {
        let schemaVersion: Int
        let controlProtocol: Int
        let daemonVersion: String
        let executableSha256: String
        let pfslocalMajor: UInt32
        let pfslocalMinor: UInt32
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

    private enum DaemonFenceWitness {
        case process(DaemonProcessWitness)
        case unpublished

        func hasDeparted() throws -> Bool {
            switch self {
            case .process(let witness):
                return try witness.hasExited()
            case .unpublished:
                return try PortableFSDServiceCoordinator.stateSingletonIsUnlocked()
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
            let registeredIdentity = loadRegisteredIdentity()
            if registeredIdentity == nil,
               liveDaemonMatches(releaseIdentity, bundle: bundle) {
                try persistRegisteredIdentity(releaseIdentity)
                return .enabled
            }
            if registeredIdentity != releaseIdentity ||
                !liveDaemonMatches(releaseIdentity, bundle: bundle) {
                try reregister(
                    service: service,
                    bundle: bundle,
                    socketDirectory: socketDirectory,
                    registeredIdentity: registeredIdentity,
                    releaseIdentity: releaseIdentity
                )
            }
            return .enabled
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
                        try persistRegisteredIdentity(releaseIdentity)
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
        guard loadRegisteredIdentity() == releaseIdentity else {
            throw RegistrationError.liveIdentityFailed(
                "the persisted registered release is not this sealed release"
            )
        }
        let service = SMAppService.agent(plistName: configuration.plistName)
        guard service.status == .enabled else {
            throw RegistrationError.registrationDidNotPersist
        }
        let updateGuard = try acquireEmptyInventoryGuard(
            bundle: bundle,
            registeredIdentity: releaseIdentity
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
              loadRegisteredIdentity() == expectedRelease,
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
                try persistRegisteredIdentity(sealed)
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
            registeredIdentity: expectedRelease
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
            try persistRegisteredIdentity(expectedRelease)
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

    private static func loadRegisteredIdentity() -> PortableFSDReleaseIdentity? {
        guard let data = UserDefaults.standard.data(
            forKey: registeredIdentityDefaultsKey
        ) else {
            return nil
        }
        return try? JSONDecoder().decode(PortableFSDReleaseIdentity.self, from: data)
    }

    private static func persistRegisteredIdentity(_ identity: PortableFSDReleaseIdentity) throws {
        let data = try JSONEncoder().encode(identity)
        UserDefaults.standard.set(data, forKey: registeredIdentityDefaultsKey)
        guard UserDefaults.standard.data(
            forKey: registeredIdentityDefaultsKey
        ) == data else {
            throw RegistrationError.persistIdentity
        }
    }

    private static func reregister(
        service: SMAppService,
        bundle: Bundle,
        socketDirectory: URL,
        registeredIdentity: PortableFSDReleaseIdentity?,
        releaseIdentity: PortableFSDReleaseIdentity
    ) throws {
        guard let registeredIdentity else {
            throw RegistrationError.liveIdentityFailed(
                "an enabled daemon has no persisted registered identity"
            )
        }
        let updateGuard = try acquireEmptyInventoryGuard(
            bundle: bundle,
            registeredIdentity: registeredIdentity
        )
        defer { updateGuard.release() }

        // The process witness is captured from the authenticated live control
        // peer after admission is quiesced and before registration mutation.
        // An enabled service with no verifiable peer is never updated in place.
        let processWitness = try probeLiveDaemon(
            registeredIdentity,
            bundle: bundle
        )
        try unregisterAndWait(
            service: service,
            socketDirectory: socketDirectory,
            processWitness: .process(processWitness)
        )

        try completeRegisteredRelease(
            operation: {
                try service.register()
                guard service.status == .enabled else {
                    throw RegistrationError.registrationDidNotPersist
                }
                try requireLiveDaemon(releaseIdentity, bundle: bundle)
                try persistRegisteredIdentity(releaseIdentity)
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

    private static func acquireEmptyInventoryGuard(
        bundle: Bundle,
        registeredIdentity: PortableFSDReleaseIdentity?
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
        var arguments = [
            "lifecycle", "hold-install-exclusive", "--json"
        ]
        if let registeredIdentity {
            arguments += [
                "--expected-daemon-version", registeredIdentity.daemonVersion,
                "--expected-daemon-sha256", registeredIdentity.executableSHA256,
                "--expected-pfslocal-major", String(registeredIdentity.pfslocalMajor),
                "--expected-pfslocal-minor", String(registeredIdentity.pfslocalMinor),
            ]
        }
        process.arguments = arguments
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
        try stateSingletonIsUnlocked(
            at: controlSocketURL().deletingLastPathComponent()
        )
    }

    static func stateSingletonIsUnlocked(
        at stateDirectory: URL,
        beforeFinalRecheck: (() throws -> Void)? = nil
    ) throws -> Bool {
        var namedDirectory = stat()
        guard Darwin.lstat(stateDirectory.path, &namedDirectory) == 0 else {
            let code = errno
            if code == ENOENT { return true }
            throw RegistrationError.inspectDaemonStateSingleton(code)
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
        defer { Darwin.close(directory) }

        var pinnedDirectory = stat()
        guard Darwin.fstat(directory, &pinnedDirectory) == 0,
              pinnedDirectory.st_dev == namedDirectory.st_dev,
              pinnedDirectory.st_ino == namedDirectory.st_ino,
              pinnedDirectory.st_mode == namedDirectory.st_mode,
              pinnedDirectory.st_uid == namedDirectory.st_uid else {
            throw RegistrationError.invalidDaemonStateSingleton
        }

        let name = ".portablefsd-state.lock"
        var namedLock = stat()
        if Darwin.fstatat(
            directory,
            name,
            &namedLock,
            AT_SYMLINK_NOFOLLOW
        ) != 0 {
            let code = errno
            if code == ENOENT {
                try beforeFinalRecheck?()
                try recheckPinnedDirectory(
                    stateDirectory,
                    expected: pinnedDirectory
                )
                return true
            }
            throw RegistrationError.inspectDaemonStateSingleton(code)
        }
        guard namedLock.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              namedLock.st_uid == geteuid(),
              namedLock.st_mode & 0o777 == 0o600,
              namedLock.st_nlink == 1 else {
            throw RegistrationError.invalidDaemonStateSingleton
        }
        let lock = Darwin.openat(
            directory,
            name,
            O_RDONLY | O_NOFOLLOW | O_CLOEXEC
        )
        guard lock >= 0 else {
            throw RegistrationError.inspectDaemonStateSingleton(errno)
        }
        defer { Darwin.close(lock) }
        var pinnedLock = stat()
        guard Darwin.fstat(lock, &pinnedLock) == 0,
              pinnedLock.st_dev == namedLock.st_dev,
              pinnedLock.st_ino == namedLock.st_ino,
              pinnedLock.st_mode == namedLock.st_mode,
              pinnedLock.st_uid == namedLock.st_uid,
              pinnedLock.st_nlink == namedLock.st_nlink else {
            throw RegistrationError.invalidDaemonStateSingleton
        }

        if portableFSFlock(lock, LOCK_EX | LOCK_NB) != 0 {
            let code = errno
            if code == EWOULDBLOCK || code == EAGAIN { return false }
            throw RegistrationError.inspectDaemonStateSingleton(code)
        }
        defer { _ = portableFSFlock(lock, LOCK_UN) }

        try beforeFinalRecheck?()
        var currentLock = stat()
        guard Darwin.fstatat(
            directory,
            name,
            &currentLock,
            AT_SYMLINK_NOFOLLOW
        ) == 0,
              currentLock.st_dev == pinnedLock.st_dev,
              currentLock.st_ino == pinnedLock.st_ino,
              currentLock.st_mode == pinnedLock.st_mode,
              currentLock.st_uid == pinnedLock.st_uid,
              currentLock.st_nlink == pinnedLock.st_nlink else {
            throw RegistrationError.invalidDaemonStateSingleton
        }
        try recheckPinnedDirectory(stateDirectory, expected: pinnedDirectory)
        return true
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

    private static func liveDaemonMatches(
        _ releaseIdentity: PortableFSDReleaseIdentity,
        bundle: Bundle
    ) -> Bool {
        do {
            let witness = try probeLiveDaemon(releaseIdentity, bundle: bundle)
            witness.close()
            return true
        } catch {
            return false
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
            fd,
            releaseIdentity: releaseIdentity,
            configuration: configuration,
            bundle: bundle
        )
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
                Darwin.write(fd, bytes.baseAddress!.advanced(by: sent), request.count - sent)
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
        let identity = try JSONDecoder().decode(LiveDaemonIdentity.self, from: body)
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
        return processWitness
    }

    private static func authenticateDaemonPeer(
        _ descriptor: Int32,
        releaseIdentity: PortableFSDReleaseIdentity,
        configuration: Configuration,
        bundle: Bundle
    ) throws -> DaemonProcessWitness {
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

        let expectedExecutable = bundle.bundleURL
            .appendingPathComponent(bundleProgram, isDirectory: false)
            .standardizedFileURL
        var path = [CChar](repeating: 0, count: 4 * 1_024)
        let pathLength = proc_pidpath_audittoken(
            &token,
            &path,
            UInt32(path.count)
        )
        guard pathLength > 0 else {
            throw RegistrationError.inspectDaemonProcess(errno)
        }
        let pathBytes = path.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        guard URL(
            fileURLWithPath: String(decoding: pathBytes, as: UTF8.self),
            isDirectory: false
        ).standardizedFileURL == expectedExecutable else {
            throw RegistrationError.invalidDaemonProcessWitness
        }

        // Register the process event before inspecting code. If this execution
        // exits at any point after its audit token was captured, the queued
        // NOTE_EXIT makes the witness terminal even if the numeric PID is
        // immediately recycled.
        let processWitness = try DaemonProcessWitness(
            pid: pid,
            pidVersion: pidVersion
        )
        let tokenData = withUnsafeBytes(of: &token) { Data($0) }
        let attributes = [kSecGuestAttributeAudit: tokenData] as CFDictionary
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
              try !processWitness.hasExited() else {
            throw RegistrationError.invalidDaemonProcessWitness
        }
        return processWitness
    }

    private enum RegistrationError: LocalizedError {
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
        case invalidDaemonProcessWitness
        case inspectDaemonStateSingleton(Int32)
        case invalidDaemonStateSingleton
        case daemonStateSingletonHeld
        case daemonProcessStillPresent
        case unregisterDidNotComplete
        case liveIdentityFailed(String)
        case persistIdentity
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
                return "PortableFS could not prove an empty mount and daemon-attach inventory before service replacement: \(detail)"
            case .invalidControlSocketRoot(let path):
                return "PortableFS could not resolve its canonical account control root from \(path)."
            case .runtimePathPresent(let path):
                return "PortableFS service replacement found a live runtime path at \(path)."
            case .inspectRuntimePath(let path, let code):
                return "PortableFS could not prove runtime path absence at \(path): \(String(cString: strerror(code)))"
            case .inspectDaemonProcess(let code):
                return "PortableFS could not inspect the authenticated daemon process: \(String(cString: strerror(code)))"
            case .invalidDaemonProcessWitness:
                return "PortableFS could not bind the live daemon to its exact signed process execution."
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
            case .persistIdentity:
                return "PortableFS could not persist the registered daemon release identity."
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
