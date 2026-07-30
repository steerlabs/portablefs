import AppKit
import Foundation
import Observation
import PortableFSAppCore

struct AppAlert: Identifiable, Equatable {
    let id = UUID()
    var title: String
    var detail: String
    var occurredAt = Date()

    var pasteboardText: String {
        "PortableFS error at \(occurredAt.formatted(date: .abbreviated, time: .standard))\n\(title)\n\n\(detail)"
    }
}

enum DeviceFlowPhase: Equatable {
    case idle
    case starting
    case waitingForApproval(userCode: String, verificationURL: String)
    case succeeded(profile: String)
    case failed(message: String)
}

/// Menu-bar presentation state. The Go CLI is the sole owner of mount,
/// daemon, access-lease, readiness, and lifecycle-lock state. The Swift app
/// invokes that exact bundled CLI and presents its structured output.
@MainActor
@Observable
final class AppModel {
    // MARK: Config / identity

    private(set) var config = PortableFSConfig()
    let configPath: String
    private let accountHome: String
    private let startupPathError: String?
    private(set) var configError: String?

    var settings: ResolvedControlPlaneSettings {
        .resolve(config: config)
    }

    var isSignedIn: Bool {
        configError == nil && settings.hasAPICredentials
    }

    var signedInDescription: String {
        guard isSignedIn else {
            return "Not signed in"
        }
        let host = URL(string: settings.apiURL)?.host ?? settings.apiURL
        return "\(config.currentProfile) @ \(host)"
    }

    var accountEnvironmentOverrideNames: [String] {
        ["PORTABLEFS_API_URL", "PORTABLEFS_API_TOKEN"].filter {
            !(ProcessInfo.processInfo.environment[$0] ?? "").isEmpty
        }
    }

    var hasAccountEnvironmentOverrides: Bool {
        !accountEnvironmentOverrideNames.isEmpty
    }

    // MARK: Volumes and mounts

    private(set) var volumes: [ListedVolume] = []
    private(set) var volumesError: String?
    private(set) var isRefreshingVolumes = false
    private(set) var mountStates: [String: MountStateMachine] = [:]
    private(set) var localMounts: [PortableFSCLIMountRow] = []
    private(set) var isLocalMountInventoryKnown = false

    // MARK: Errors / sign-in

    private(set) var alerts: [AppAlert] = []
    private(set) var isQuitting = false
    private(set) var deviceFlow: DeviceFlowPhase = .idle
    private(set) var isAccountMutationInProgress = false

    // MARK: Settings

    var mountBaseDirectory: String {
        didSet {
            if mountBaseDirectoryValidationError == nil {
                UserDefaults.standard.set(mountBaseDirectory, forKey: Self.mountBaseDirectoryKey)
            }
        }
    }

    var mountBaseDirectoryValidationError: String? {
        Self.validateMountBaseDirectory(mountBaseDirectory)
    }

    private static let mountBaseDirectoryKey = "mountBaseDirectory"

    private let cli = PortableFSCLI()
    private var lifecycleHold: PortableFSCLILease?
    private var deviceFlowTask: Task<Void, Never>?
    private var localPollTask: Task<Void, Never>?
    private var volumePollTask: Task<Void, Never>?
    private var interactiveSessionActivated = false
    private var isRefreshingLocalState = false
    private var localStateError: String?
    private var interactiveSessionRequested = false

    private(set) var isLifecycleReady = false

    var menuBarSymbolName: String {
        if localMounts.contains(where: { $0.health == "live" }) ||
            mountStates.values.contains(where: { $0.state.isMounted }) {
            return "externaldrive.fill.badge.checkmark"
        }
        return "externaldrive"
    }

    var unlistedLocalMounts: [PortableFSCLIMountRow] {
        let listed = volumes.reduce(into: [String: ListedVolume]()) {
            $0[$1.volumeId] = $1
        }
        return localMounts.filter { row in
            if row.health == "stale" {
                return true
            }
            guard let volume = listed[row.volumeId] else {
                return true
            }
            let expectedPath = PortableFSAppPaths.mountPoint(
                baseDirectory: mountBaseDirectory,
                volumeID: volume.volumeId
            )
            return row.mountPath != expectedPath || row.branch != volume.defaultBranch
        }
    }

    init() {
        let defaults = UserDefaults.standard
        do {
            let accountHome = try PortableFSAccountHome.resolve()
            self.accountHome = accountHome
            configPath = PortableFSConfigFile.defaultPath(homeDirectory: accountHome)
            startupPathError = nil
            mountBaseDirectory = defaults.string(forKey: Self.mountBaseDirectoryKey)
                ?? PortableFSAppPaths.defaultMountBaseDirectory(homeDirectory: accountHome)
        } catch {
            accountHome = ""
            configPath = ""
            startupPathError = String(describing: error)
            mountBaseDirectory = ""
        }
        if startupPathError == nil {
            reloadConfig()
        } else {
            configError = startupPathError
        }
        Task {
            await acquireAppLifecycle()
        }
    }

    /// Polling begins only after the user opens the menu. Launch executes only
    /// the required lifecycle-holder command; it does not start a daemon,
    /// inspect mounts, or contact a server.
    func activateInteractiveSession() {
        interactiveSessionRequested = true
        guard isLifecycleReady else {
            return
        }
        startInteractivePolling()
    }

    private func startInteractivePolling() {
        guard !interactiveSessionActivated else {
            return
        }
        interactiveSessionActivated = true
        Task {
            await refreshVolumes()
            await refreshLocalState()
        }
        localPollTask = Task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(5))
                await refreshLocalState()
            }
        }
        volumePollTask = Task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(60))
                if isSignedIn {
                    await refreshVolumes()
                }
            }
        }
    }

    private func acquireAppLifecycle() async {
        if let startupPathError {
            let alert = NSAlert()
            alert.alertStyle = .critical
            alert.messageText = "PortableFS Could Not Resolve This Account"
            alert.informativeText = startupPathError
            alert.runModal()
            NSApplication.shared.terminate(nil)
            return
        }
        do {
            let hold = try await cli.holdLifecycle()
            lifecycleHold = hold
            isLifecycleReady = true
            Task {
                if let failure = await hold.waitForUnexpectedExit() {
                    handleUnexpectedLifecycleExit(failure)
                }
            }
            if interactiveSessionRequested {
                startInteractivePolling()
            }
            if FirstRunAssistant.shared.shouldPresentAtLaunch {
                FirstRunAssistant.shared.present()
            }
        } catch {
            let alert = NSAlert()
            alert.alertStyle = .critical
            alert.messageText = "PortableFS Could Not Start"
            alert.informativeText = "PortableFS is being installed or updated, or its lifecycle lock could not be acquired.\n\n\(error.localizedDescription)"
            alert.runModal()
            NSApplication.shared.terminate(nil)
        }
    }

    private func handleUnexpectedLifecycleExit(_ error: PortableFSCLIError) {
        guard !isQuitting else {
            return
        }
        isLifecycleReady = false
        let alert = NSAlert()
        alert.alertStyle = .critical
        alert.messageText = "PortableFS Lifecycle Guard Stopped"
        alert.informativeText = "The process protecting this app from concurrent replacement exited unexpectedly. PortableFS will close rather than continue without that guarantee.\n\n\(error.localizedDescription)"
        alert.runModal()
        NSApplication.shared.terminate(nil)
    }

    // MARK: Config

    func reloadConfig() {
        do {
            config = try PortableFSConfigFile.load(
                path: configPath,
                canonicalHomeDirectory: accountHome
            )
            configError = nil
        } catch {
            let message = String(describing: error)
            config = PortableFSConfig()
            volumes = []
            volumesError = nil
            mountStates = [:]
            if configError != message {
                configError = message
                reportError(title: "Could not read config", detail: message)
            }
        }
    }

    func switchProfile(_ name: String) {
        guard isLifecycleReady else {
            return
        }
        guard !hasAccountEnvironmentOverrides else {
            reportEnvironmentAccountOverride(action: "Profile switch")
            return
        }
        Task {
            await performSwitchProfile(name)
        }
    }

    private func performSwitchProfile(_ name: String) async {
        guard await updateConfigUnderAccountGuard(
            action: "Profile switch",
            mutate: {
                guard $0.profiles[name] != nil || name == $0.currentProfile else {
                    throw PortableFSAccountMutationError.profileNotFound(name)
                }
                $0.currentProfile = name
            }
        ) == nil else {
            return
        }
        volumes = []
        await refreshVolumes()
        await refreshLocalState()
    }

    func signOut() {
        guard isLifecycleReady else {
            return
        }
        guard !hasAccountEnvironmentOverrides else {
            reportEnvironmentAccountOverride(action: "Sign out")
            return
        }
        Task {
            await performSignOut()
        }
    }

    private func performSignOut() async {
        guard await updateConfigUnderAccountGuard(
            action: "Sign out",
            mutate: {
                $0.profiles.removeValue(forKey: $0.currentProfile)
            }
        ) == nil else {
            return
        }
        volumes = []
        volumesError = nil
    }

    /// Account mutations acquire the same exclusive session guard that every
    /// Go mount holds shared for its entire lifetime. The holder also performs
    /// the authoritative mount-record and daemon-attach checks before its
    /// readiness frame, closing the check/use race that polling cannot close.
    private func updateConfigUnderAccountGuard(
        action: String,
        mutate: (inout PortableFSConfig) throws -> Void
    ) async -> Error? {
        guard !isAccountMutationInProgress else {
            return PortableFSAccountMutationError.alreadyInProgress
        }
        isAccountMutationInProgress = true
        defer {
            isAccountMutationInProgress = false
        }

        let accountHold: PortableFSCLILease
        do {
            accountHold = try await cli.holdAccountExclusive()
            localMounts = []
            isLocalMountInventoryKnown = true
        } catch {
            isLocalMountInventoryKnown = false
            reportError(
                title: "\(action) refused",
                detail: "PortableFS could not acquire an exclusive account session with an empty mount and attach inventory, so it did not change account state.\n\n\(error)"
            )
            return error
        }
        defer {
            accountHold.release()
        }

        do {
            // Reload only after the exclusive holder is ready so an external
            // CLI mutation that completed while we waited cannot be lost.
            var next = try PortableFSConfigFile.load(
                path: configPath,
                canonicalHomeDirectory: accountHome
            )
            try mutate(&next)
            try PortableFSConfigFile.save(
                next,
                path: configPath,
                canonicalHomeDirectory: accountHome
            )
            config = try PortableFSConfigFile.load(
                path: configPath,
                canonicalHomeDirectory: accountHome
            )
            configError = nil
            return nil
        } catch {
            let detail = String(describing: error)
            config = PortableFSConfig()
            volumes = []
            volumesError = nil
            mountStates = [:]
            configError = detail
            reportError(title: "Could not save config", detail: detail)
            return error
        }
    }

    // MARK: Sign-in

    func signIn(
        serverURL: String,
        token: String,
        managerURL: String,
        managerToken: String,
        profile: String
    ) async -> String? {
        guard isLifecycleReady else {
            return "PortableFS has not acquired its application lifecycle guard."
        }
        guard !hasAccountEnvironmentOverrides else {
            return environmentAccountOverrideMessage(
                action: "Sign in"
            )
        }
        let normalized = ControlPlaneClient.normalizeServerURL(serverURL)
        guard !normalized.isEmpty else {
            return "Server URL is required."
        }
        guard !token.isEmpty else {
            return "API token is required (or use device sign-in)."
        }
        let profileName = profile.isEmpty ? "default" : profile
        let client = ControlPlaneClient(baseURL: normalized, token: token)
        let verification = await client.verifyCredential()
        switch verification {
        case .accepted:
            let resolvedManagerURL = ControlPlaneClient.normalizeServerURL(managerURL)
            if let error = await saveProfile(
                name: profileName,
                profile: PortableFSProfile(
                    apiUrl: normalized,
                    apiToken: token,
                    managerUrl: resolvedManagerURL,
                    managerToken: managerToken
                )
            ) {
                return "Credentials were accepted but could not be saved: \(error)"
            }
            await refreshVolumes()
            return nil
        case let .rejected(status):
            return "The server rejected the token (HTTP \(status)); nothing was saved."
        case let .unreachable(message):
            return "The server could not be reached (\(message)); nothing was saved."
        }
    }

    func startDeviceSignIn(serverURL: String, managerURL: String, managerToken: String, profile: String) {
        guard isLifecycleReady else {
            return
        }
        guard !hasAccountEnvironmentOverrides else {
            deviceFlow = .failed(
                message: environmentAccountOverrideMessage(action: "Sign in")
            )
            return
        }
        let normalized = ControlPlaneClient.normalizeServerURL(serverURL)
        guard !normalized.isEmpty else {
            deviceFlow = .failed(message: "Server URL is required.")
            return
        }
        cancelDeviceSignIn()
        deviceFlow = .starting
        let profileName = profile.isEmpty ? "default" : profile
        deviceFlowTask = Task {
            await runDeviceSignIn(
                serverURL: normalized,
                managerURL: ControlPlaneClient.normalizeServerURL(managerURL),
                managerToken: managerToken,
                profile: profileName
            )
        }
    }

    func cancelDeviceSignIn() {
        deviceFlowTask?.cancel()
        deviceFlowTask = nil
        switch deviceFlow {
        case .starting, .waitingForApproval:
            deviceFlow = .idle
        default:
            break
        }
    }

    func resetDeviceSignIn() {
        cancelDeviceSignIn()
        deviceFlow = .idle
    }

    private func runDeviceSignIn(
        serverURL: String,
        managerURL: String,
        managerToken: String,
        profile: String
    ) async {
        let client = ControlPlaneClient(baseURL: serverURL, token: "")
        let code: DeviceCodeResponse
        do {
            code = try await client.startDeviceFlow()
        } catch {
            deviceFlow = .failed(message: String(describing: error))
            return
        }
        deviceFlow = .waitingForApproval(
            userCode: code.userCode,
            verificationURL: code.verificationUri
        )
        if let url = URL(string: code.verificationUri) {
            NSWorkspace.shared.open(url)
        }

        let deadline = Date().addingTimeInterval(code.expiry)
        while !Task.isCancelled {
            if Date() > deadline {
                deviceFlow = .failed(
                    message: "Device sign-in expired before the code was entered. Start over."
                )
                return
            }
            do {
                switch try await client.pollDeviceToken(deviceCode: code.deviceCode) {
                case let .ready(apiKey, serverManagerURL):
                    var resolvedManagerURL = managerURL
                    if resolvedManagerURL.isEmpty && !serverManagerURL.isEmpty {
                        resolvedManagerURL = ControlPlaneClient.normalizeServerURL(serverManagerURL)
                    }
                    if let error = await saveProfile(
                        name: profile,
                        profile: PortableFSProfile(
                            apiUrl: serverURL,
                            apiToken: apiKey,
                            managerUrl: resolvedManagerURL,
                            managerToken: managerToken
                        )
                    ) {
                        deviceFlow = .failed(
                            message: "Sign-in succeeded but the profile could not be saved: \(error)"
                        )
                        return
                    }
                    deviceFlow = .succeeded(profile: profile)
                    await refreshVolumes()
                    return
                case .pending:
                    break
                case let .denied(message):
                    deviceFlow = .failed(
                        message: "Device sign-in was denied or expired: \(message)"
                    )
                    return
                }
            } catch {
                deviceFlow = .failed(message: String(describing: error))
                return
            }
            try? await Task.sleep(for: .seconds(code.pollInterval))
        }
    }

    private func saveProfile(name: String, profile: PortableFSProfile) async -> Error? {
        await updateConfigUnderAccountGuard(action: "Sign in") {
            $0.profiles[name] = profile
            $0.currentProfile = name
        }
    }

    private func environmentAccountOverrideMessage(action: String) -> String {
        "\(action) is unavailable because \(accountEnvironmentOverrideNames.joined(separator: ", ")) overrides the saved account. Relaunch PortableFS without those environment variables before changing profiles or credentials."
    }

    private func reportEnvironmentAccountOverride(action: String) {
        reportError(
            title: "\(action) refused",
            detail: environmentAccountOverrideMessage(action: action)
        )
    }

    // MARK: Volumes and local mount state

    func refreshAll() async {
        guard isLifecycleReady else {
            return
        }
        await refreshVolumes()
        await refreshLocalState()
    }

    func refreshVolumes() async {
        guard isLifecycleReady else {
            return
        }
        reloadConfig()
        guard isSignedIn else {
            volumes = []
            volumesError = nil
            return
        }
        guard !isRefreshingVolumes else {
            return
        }
        isRefreshingVolumes = true
        defer {
            isRefreshingVolumes = false
        }
        let client = ControlPlaneClient(baseURL: settings.apiURL, token: settings.apiToken)
        do {
            let fetched = try await client.listVolumes()
            guard fetched.allSatisfy({ Self.isValidVolumeID($0.volumeId) }) else {
                let invalid = fetched.first(where: { !Self.isValidVolumeID($0.volumeId) })?.volumeId
                    ?? "<unknown>"
                throw PortableFSVolumeIdentityError.invalid(invalid)
            }
            guard Set(fetched.map(\.volumeId)).count == fetched.count else {
                throw PortableFSVolumeIdentityError.duplicateVolume
            }
            for volume in fetched {
                guard volume.branches.allSatisfy({ Self.isValidBranchName($0.name) }) else {
                    throw PortableFSVolumeIdentityError.invalidBranch(volume.volumeId)
                }
                guard Set(volume.branches.map(\.name)).count == volume.branches.count else {
                    throw PortableFSVolumeIdentityError.duplicateBranch(volume.volumeId)
                }
                let defaultBranch = volume.defaultBranch
                guard Self.isValidBranchName(defaultBranch),
                      volume.branches.filter({ $0.name == defaultBranch }).count == 1 else {
                    throw PortableFSVolumeIdentityError.missingDefaultBranch(volume.volumeId)
                }
            }
            volumes = fetched
            volumesError = nil
        } catch {
            volumesError = String(describing: error)
        }
    }

    func mountState(for volume: ListedVolume) -> VolumeMountState {
        mountStates[volume.volumeId]?.state ?? .unmounted
    }

    func canMount(_ volume: ListedVolume) -> Bool {
        !isAccountMutationInProgress &&
            mountBaseDirectoryValidationError == nil &&
            isLocalMountInventoryKnown &&
            !localMounts.contains(where: { $0.volumeId == volume.volumeId }) &&
            mountStates[volume.volumeId]?.state.isBusy != true
    }

    func refreshLocalState() async {
        guard isLifecycleReady else {
            return
        }
        guard !isRefreshingLocalState else {
            return
        }
        isRefreshingLocalState = true
        defer {
            isRefreshingLocalState = false
        }
        do {
            let rows = try await cli.mounts()
            localMounts = rows
            isLocalMountInventoryKnown = true
            let rowsByVolume = Dictionary(grouping: rows, by: \.volumeId)
            for volume in volumes {
                if mountStates[volume.volumeId]?.state.isBusy == true {
                    continue
                }
                let expectedPath = PortableFSAppPaths.mountPoint(
                    baseDirectory: mountBaseDirectory,
                    volumeID: volume.volumeId
                )
                guard let row = rowsByVolume[volume.volumeId]?.first(where: {
                    $0.mountPath == expectedPath && $0.branch == volume.defaultBranch
                }) else {
                    mountStates[volume.volumeId] = MountStateMachine(state: .unmounted)
                    continue
                }
                if row.requiresCleanup {
                    mountStates[volume.volumeId] = MountStateMachine(
                        state: .cleanupRequired(
                            mountPath: row.mountPath,
                            operationPhase: row.operationPhase
                        )
                    )
                } else if row.health == "stale" {
                    mountStates[volume.volumeId] = MountStateMachine(
                        state: .failed(
                            message: "Stale mount record at \(row.mountPath); run portablefs umount \(row.mountPath)."
                        )
                    )
                } else {
                    mountStates[volume.volumeId] = MountStateMachine(
                        state: .mounted(
                            attachRef: row.attachRef ?? "cli-owned",
                            mountPath: row.mountPath
                        )
                    )
                }
            }
            localStateError = nil
        } catch {
            isLocalMountInventoryKnown = false
            let detail = String(describing: error)
            if localStateError != detail {
                localStateError = detail
                reportError(title: "Could not read local mounts", detail: detail)
            }
        }
    }

    // MARK: Mount / unmount

    func mount(_ volume: ListedVolume) {
        guard isLifecycleReady else {
            return
        }
        Task {
            await performMount(volume)
        }
    }

    func unmount(_ volume: ListedVolume) {
        guard isLifecycleReady else {
            return
        }
        Task {
            await performUnmount(volume)
        }
    }

    func unmountLocalMount(_ row: PortableFSCLIMountRow) {
        guard isLifecycleReady else {
            return
        }
        Task {
            do {
                try await cli.unmount(mountPath: row.mountPath)
            } catch {
                reportError(
                    title: "Unmount \(row.volumeId) failed",
                    detail: String(describing: error)
                )
            }
            await refreshLocalState()
        }
    }

    private func performMount(_ volume: ListedVolume) async {
        let volumeID = volume.volumeId
        if let mountBaseDirectoryValidationError {
            reportError(
                title: "Mount refused",
                detail: mountBaseDirectoryValidationError
            )
            return
        }
        guard !isAccountMutationInProgress else {
            reportError(
                title: "Mount refused",
                detail: "Finish the active account change before mounting."
            )
            return
        }
        guard mountStates[volumeID]?.state.isBusy != true else {
            return
        }
        guard isSignedIn else {
            reportError(title: "Not signed in", detail: "Sign in before mounting volumes.")
            return
        }
        guard isLocalMountInventoryKnown else {
            reportError(
                title: "Mount refused",
                detail: "PortableFS could not verify the complete local mount inventory. Refresh and resolve that error before mounting."
            )
            return
        }
        guard !localMounts.contains(where: { $0.volumeId == volumeID }) else {
            reportError(
                title: "Mount refused",
                detail: "\(volumeID) already has a local mount record. Unmount it before mounting the volume at another location."
            )
            return
        }
        guard Self.isValidVolumeID(volumeID) else {
            reportError(
                title: "Mount refused",
                detail: "The server returned an invalid volume identifier. Expected 1–220 ASCII letters, digits, underscores, or hyphens."
            )
            return
        }

        mountStates[volumeID] = MountStateMachine(state: .mintingSession)
        let mountPath = PortableFSAppPaths.mountPoint(
            baseDirectory: mountBaseDirectory,
            volumeID: volumeID
        )
        do {
            let mounted = try await cli.mount(
                volumeID: volumeID,
                branch: volume.defaultBranch,
                mountPath: mountPath
            )
            mountStates[volumeID] = MountStateMachine(
                state: .mounted(
                    attachRef: mounted.attachRef ?? "cli-owned",
                    mountPath: mounted.mountPath
                )
            )
        } catch {
            let detail = String(describing: error)
            mountStates[volumeID] = MountStateMachine(
                state: .failed(message: shortMessage(detail))
            )
            reportError(title: "Mount \(volumeID) failed", detail: describeMountFailure(detail))
        }
        await refreshLocalState()
    }

    private func performUnmount(_ volume: ListedVolume) async {
        let volumeID = volume.volumeId
        let state = mountState(for: volume)
        let attachRef: String
        let mountPath: String
        switch state {
        case let .mounted(ref, path):
            attachRef = ref
            mountPath = path
        case let .cleanupRequired(path, _):
            attachRef = "cleanup-required"
            mountPath = path
        default:
            return
        }
        mountStates[volumeID] = MountStateMachine(
            state: .unmounting(attachRef: attachRef, mountPath: mountPath)
        )
        do {
            try await cli.unmount(mountPath: mountPath)
            mountStates[volumeID] = MountStateMachine(state: .unmounted)
        } catch {
            let detail = String(describing: error)
            mountStates[volumeID] = MountStateMachine(
                state: .failed(message: shortMessage(detail))
            )
            reportError(title: "Unmount \(volumeID) failed", detail: detail)
        }
        await refreshLocalState()
    }

    func openInFinder(_ volume: ListedVolume) {
        guard let path = mountState(for: volume).mountPath else {
            return
        }
        NSWorkspace.shared.open(URL(fileURLWithPath: path, isDirectory: true))
    }

    private func describeMountFailure(_ detail: String) -> String {
        detail + "\n\nIf this is the first mount, open File System Extension Setup from " +
            "the PortableFS menu and confirm the extension is enabled. Only a successful " +
            "mount verifies enablement."
    }

    private func shortMessage(_ detail: String) -> String {
        let firstLine = detail.split(separator: "\n").first.map(String.init) ?? detail
        return firstLine.count > 120 ? String(firstLine.prefix(117)) + "…" : firstLine
    }

    private static func isValidVolumeID(_ value: String) -> Bool {
        let bytes = value.utf8
        guard !bytes.isEmpty, bytes.count <= 220 else {
            return false
        }
        return bytes.allSatisfy { byte in
            (byte >= 48 && byte <= 57) ||
                (byte >= 65 && byte <= 90) ||
                (byte >= 97 && byte <= 122) ||
                byte == 95 ||
                byte == 45
        }
    }

    private static func isValidBranchName(_ value: String) -> Bool {
        !value.isEmpty && value.count <= 128 && !value.unicodeScalars.contains {
            $0.value == 0 || CharacterSet.controlCharacters.contains($0)
        }
    }

    private static func validateMountBaseDirectory(_ value: String) -> String? {
        guard !value.isEmpty else {
            return "Choose a mount base directory."
        }
        guard value.hasPrefix("/") else {
            return "The mount base directory must be an absolute path."
        }
        guard !value.unicodeScalars.contains(where: {
            $0.value == 0 || CharacterSet.controlCharacters.contains($0)
        }) else {
            return "The mount base directory contains control characters."
        }
        let clean = URL(fileURLWithPath: value, isDirectory: true).standardizedFileURL.path
        guard clean == value else {
            return "Use a clean absolute mount path without ~, '.', '..', or a trailing slash."
        }
        guard value != "/" else {
            return "The filesystem root cannot be used as the mount base directory."
        }
        return nil
    }

    // MARK: Errors / quit

    func reportError(title: String, detail: String) {
        alerts.insert(AppAlert(title: title, detail: detail), at: 0)
        if alerts.count > 8 {
            alerts.removeLast(alerts.count - 8)
        }
    }

    func copyAlert(_ alert: AppAlert) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(alert.pasteboardText, forType: .string)
    }

    func clearAlerts() {
        alerts = []
    }

    /// The CLI owns persistent mounts, so quitting the presentation process
    /// does not mutate or reconstruct their lifecycle.
    func quitApp() {
        guard !isQuitting else {
            return
        }
        isQuitting = true
        localPollTask?.cancel()
        volumePollTask?.cancel()
        deviceFlowTask?.cancel()
        lifecycleHold?.release()
        lifecycleHold = nil
        NSApplication.shared.terminate(nil)
    }
}

private enum PortableFSVolumeIdentityError: LocalizedError {
    case invalid(String)
    case duplicateVolume
    case invalidBranch(String)
    case duplicateBranch(String)
    case missingDefaultBranch(String)

    var errorDescription: String? {
        switch self {
        case let .invalid(value):
            return "The server returned invalid volume identifier \(value). Expected [A-Za-z0-9_-]{1,220}; no volumes were displayed."
        case .duplicateVolume:
            return "The server returned duplicate volume identifiers; no volumes were displayed."
        case let .invalidBranch(volumeID):
            return "The server returned an invalid branch identity for \(volumeID); no volumes were displayed."
        case let .duplicateBranch(volumeID):
            return "The server returned duplicate branch identities for \(volumeID); no volumes were displayed."
        case let .missingDefaultBranch(volumeID):
            return "The server returned no unique valid default branch for \(volumeID); no volumes were displayed."
        }
    }
}

private enum PortableFSAccountMutationError: LocalizedError {
    case profileNotFound(String)
    case alreadyInProgress

    var errorDescription: String? {
        switch self {
        case let .profileNotFound(name):
            return "Saved profile \(name) no longer exists; account state was not changed."
        case .alreadyInProgress:
            return "Another account change is already in progress."
        }
    }
}
