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

/// In-memory ownership of one mounted access lease. Credentials are
/// deliberately not persisted; a clean quit releases every lease, while an
/// app crash is a visible terminal supervision failure rather than an
/// invitation to reconstruct hidden state.
@MainActor
private final class MountedAccessLease {
    let client: ControlPlaneClient
    let attachRef: String
    var session: AccessSessionInfo
    var pendingRenewalOperationID: String?
    var pendingReleaseOperationID: String?
    var renewalDelayWasReported = false
    var task: Task<Void, Never>?

    init(client: ControlPlaneClient, attachRef: String, session: AccessSessionInfo) {
        self.client = client
        self.attachRef = attachRef
        self.session = session
    }
}

/// Central app state: config/profile identity, the volume list, per-volume
/// mount state machines, the supervised daemon, and surfaced errors.
@MainActor
@Observable
final class AppModel {
    // MARK: Config / identity

    private(set) var config = PortableFSConfig()
    let configPath = PortableFSConfigFile.defaultPath()
    private(set) var configError: String?

    var settings: ResolvedControlPlaneSettings {
        .resolve(config: config)
    }

    var isSignedIn: Bool {
        settings.hasAPICredentials
    }

    var signedInDescription: String {
        guard isSignedIn else {
            return "Not signed in"
        }
        let host = URL(string: settings.apiURL)?.host ?? settings.apiURL
        return "\(config.currentProfile) @ \(host)"
    }

    // MARK: Volumes and mounts

    private(set) var volumes: [ListedVolume] = []
    private(set) var volumesError: String?
    private(set) var isRefreshingVolumes = false
    private(set) var mountStates: [String: MountStateMachine] = [:]

    // MARK: Daemon

    let daemon = DaemonSupervisor()

    // MARK: Errors

    private(set) var alerts: [AppAlert] = []
    private(set) var isQuitting = false

    // MARK: Sign-in

    private(set) var deviceFlow: DeviceFlowPhase = .idle
    private var deviceFlowTask: Task<Void, Never>?

    // MARK: Settings-backed knobs

    var mountBaseDirectory: String {
        didSet { UserDefaults.standard.set(mountBaseDirectory, forKey: Self.mountBaseDirectoryKey) }
    }

    var daemonBinaryOverride: String {
        didSet {
            UserDefaults.standard.set(daemonBinaryOverride, forKey: Self.daemonBinaryOverrideKey)
            daemon.binaryOverride = daemonBinaryOverride
        }
    }

    private static let mountBaseDirectoryKey = "mountBaseDirectory"
    private static let daemonBinaryOverrideKey = "daemonBinaryPath"

    private var localPollTask: Task<Void, Never>?
    private var volumePollTask: Task<Void, Never>?
    private var mountedLeases: [String: MountedAccessLease] = [:]
    private var pendingLeaseCreateOperations: [String: String] = [:]
    private var localStateError: String?

    var menuBarSymbolName: String {
        if mountStates.values.contains(where: { $0.state.isMounted }) {
            return "externaldrive.fill.badge.checkmark"
        }
        return "externaldrive"
    }

    init() {
        let defaults = UserDefaults.standard
        mountBaseDirectory = defaults.string(forKey: Self.mountBaseDirectoryKey)
            ?? PortableFSAppPaths.defaultMountBaseDirectory()
        daemonBinaryOverride = defaults.string(forKey: Self.daemonBinaryOverrideKey) ?? ""
        daemon.binaryOverride = daemonBinaryOverride
        start()
    }

    private func start() {
        reloadConfig()
        Task {
            await daemon.start()
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

    // MARK: Config

    func reloadConfig() {
        do {
            config = try PortableFSConfigFile.load(path: configPath)
            configError = nil
        } catch {
            let message = String(describing: error)
            // Periodic refreshes reload the shared config; report a broken
            // file once, not on every poll tick.
            if configError != message {
                configError = message
                reportError(title: "Could not read config", detail: message)
            }
        }
    }

    func switchProfile(_ name: String) {
        guard config.profiles[name] != nil || name == config.currentProfile else {
            return
        }
        guard mountedLeases.isEmpty, MountTable.portableFSMounts().isEmpty else {
            reportError(
                title: "Profile switch refused",
                detail: "Cleanly unmount every PortableFS volume before switching profiles."
            )
            return
        }
        guard updateConfig({ $0.currentProfile = name }) == nil else {
            return
        }
        volumes = []
        Task {
            await refreshVolumes()
        }
    }

    func signOut() {
        guard mountedLeases.isEmpty, MountTable.portableFSMounts().isEmpty else {
            reportError(
                title: "Sign out refused",
                detail: "Cleanly unmount every PortableFS volume before signing out."
            )
            return
        }
        let currentProfile = config.currentProfile
        guard updateConfig({ $0.profiles.removeValue(forKey: currentProfile) }) == nil else {
            return
        }
        volumes = []
        volumesError = nil
    }

    /// Commits one config mutation atomically. The in-memory identity changes
    /// only after the shared CLI/app config file was durably replaced.
    private func updateConfig(_ mutate: (inout PortableFSConfig) -> Void) -> Error? {
        var next = config
        mutate(&next)
        do {
            try PortableFSConfigFile.save(next, path: configPath)
            config = next
            configError = nil
            return nil
        } catch {
            configError = String(describing: error)
            reportError(title: "Could not save config", detail: String(describing: error))
            return error
        }
    }

    // MARK: Sign-in

    /// Manual token sign-in, mirroring `portablefs login <url> --token <t>`.
    /// Returns nil on success, otherwise a user-facing failure message.
    func signIn(
        serverURL: String,
        token: String,
        managerURL: String,
        managerToken: String,
        profile: String
    ) async -> String? {
        let normalized = ControlPlaneClient.normalizeServerURL(serverURL)
        guard !normalized.isEmpty else {
            return "Server URL is required."
        }
        guard !token.isEmpty else {
            return "API token is required (or use device sign-in)."
        }
        let profileName = profile.isEmpty ? "default" : profile
        let verification = await ControlPlaneClient(baseURL: normalized, token: token).verifyCredential()
        switch verification {
        case .accepted:
            if let error = saveProfile(
                name: profileName,
                profile: PortableFSProfile(
                    apiUrl: normalized,
                    apiToken: token,
                    managerUrl: ControlPlaneClient.normalizeServerURL(managerURL),
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

    /// OAuth-style device flow, mirroring `portablefs login <url>`.
    func startDeviceSignIn(serverURL: String, managerURL: String, managerToken: String, profile: String) {
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
        if case .waitingForApproval = deviceFlow {
            deviceFlow = .idle
        } else if deviceFlow == .starting {
            deviceFlow = .idle
        }
    }

    func resetDeviceSignIn() {
        cancelDeviceSignIn()
        deviceFlow = .idle
    }

    private func runDeviceSignIn(serverURL: String, managerURL: String, managerToken: String, profile: String) async {
        let client = ControlPlaneClient(baseURL: serverURL, token: "")
        let code: DeviceCodeResponse
        do {
            code = try await client.startDeviceFlow()
        } catch {
            deviceFlow = .failed(message: String(describing: error))
            return
        }
        deviceFlow = .waitingForApproval(userCode: code.userCode, verificationURL: code.verificationUri)
        if let url = URL(string: code.verificationUri) {
            NSWorkspace.shared.open(url)
        }

        let deadline = Date().addingTimeInterval(code.expiry)
        while !Task.isCancelled {
            if Date() > deadline {
                deviceFlow = .failed(message: "Device sign-in expired before the code was entered. Start over.")
                return
            }
            do {
                switch try await client.pollDeviceToken(deviceCode: code.deviceCode) {
                case let .ready(apiKey, serverManagerURL):
                    var resolvedManagerURL = managerURL
                    if resolvedManagerURL.isEmpty && !serverManagerURL.isEmpty {
                        resolvedManagerURL = ControlPlaneClient.normalizeServerURL(serverManagerURL)
                    }
                    if let error = saveProfile(
                        name: profile,
                        profile: PortableFSProfile(
                            apiUrl: serverURL,
                            apiToken: apiKey,
                            managerUrl: resolvedManagerURL,
                            managerToken: managerToken
                        )
                    ) {
                        deviceFlow = .failed(message: "Sign-in succeeded but the profile could not be saved: \(error)")
                        return
                    }
                    deviceFlow = .succeeded(profile: profile)
                    await refreshVolumes()
                    return
                case .pending:
                    break
                case let .denied(message):
                    deviceFlow = .failed(message: "Device sign-in was denied or expired: \(message)")
                    return
                }
            } catch {
                deviceFlow = .failed(message: String(describing: error))
                return
            }
            try? await Task.sleep(for: .seconds(code.pollInterval))
        }
    }

    private func saveProfile(name: String, profile: PortableFSProfile) -> Error? {
        updateConfig {
            $0.profiles[name] = profile
            $0.currentProfile = name
        }
    }

    // MARK: Volumes

    func refreshAll() async {
        await refreshVolumes()
        await refreshLocalState()
    }

    func refreshVolumes() async {
        // The config file is shared with the CLI; pick up `portablefs login`
        // runs that happened while the app was open.
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
        defer { isRefreshingVolumes = false }
        let client = ControlPlaneClient(baseURL: settings.apiURL, token: settings.apiToken)
        do {
            volumes = try await client.listVolumes()
            volumesError = nil
        } catch {
            volumesError = String(describing: error)
        }
    }

    func mountState(for volume: ListedVolume) -> VolumeMountState {
        mountStates[volume.volumeId]?.state ?? .unmounted
    }

    /// Reconciles per-volume state with reality: the kernel mount table plus
    /// the daemon's attach list.
    func refreshLocalState() async {
        await daemon.checkHealth()
        let kernelMounts = MountTable.portableFSMounts()
        var attaches: [DaemonAttachStatus] = []
        if daemon.healthy {
            do {
                attaches = try await daemon.control.listAttaches()
                localStateError = nil
            } catch {
                let detail = String(describing: error)
                if localStateError != detail {
                    localStateError = detail
                    reportError(
                        title: "Could not reconcile local mounts",
                        detail: "PortableFS preserved the current mount state because the daemon attach list could not be read: \(detail)"
                    )
                }
                return
            }
        }
        var mountsByRef: [String: MountedFilesystem] = [:]
        for mount in kernelMounts {
            if let ref = mount.attachRef {
                mountsByRef[ref] = mount
            }
        }
        for volume in volumes {
            var machine = mountStates[volume.volumeId] ?? MountStateMachine()
            if machine.state.isBusy {
                continue
            }
            let volumeAttaches = attaches.filter { $0.volumeId == volume.volumeId }
            if let live = volumeAttaches.compactMap({ attach in mountsByRef[attach.attachRef].map { (attach, $0) } }).first {
                machine.apply(.observedMounted(attachRef: live.0.attachRef, mountPath: live.1.mountPoint))
            } else if daemon.healthy {
                machine.apply(.observedUnmounted)
            }
            mountStates[volume.volumeId] = machine
        }
    }

    // MARK: Mount / unmount

    func mount(_ volume: ListedVolume) {
        Task {
            await performMount(volume)
        }
    }

    func unmount(_ volume: ListedVolume) {
        Task {
            await performUnmount(volume)
        }
    }

    private func applyMountEvent(_ volumeID: String, _ event: VolumeMountEvent) {
        var machine = mountStates[volumeID] ?? MountStateMachine()
        machine.apply(event)
        mountStates[volumeID] = machine
    }

    private func performMount(_ volume: ListedVolume) async {
        let volumeID = volume.volumeId
        guard !(mountStates[volumeID]?.state.isBusy ?? false) else {
            return
        }
        guard mountedLeases[volumeID] == nil else {
            reportError(
                title: "Mount \(volumeID) refused",
                detail: "This volume still owns an access lease from an incomplete detach or release. Quit PortableFS to retry that exact cleanup operation before mounting again."
            )
            return
        }
        guard isSignedIn else {
            reportError(title: "Not signed in", detail: "Sign in before mounting volumes.")
            return
        }
        guard daemon.healthy else {
            reportError(
                title: "Daemon is not running",
                detail: "portablefsd is not answering on \(daemon.controlSocketPath). \(daemon.statusDetail)"
            )
            return
        }
        applyMountEvent(volumeID, .mountRequested)
        let branch = volume.defaultBranch
        let createKey = volumeID + "\u{0}" + branch
        let mountPath = PortableFSAppPaths.mountPoint(baseDirectory: mountBaseDirectory, volumeID: volumeID)
        var ensuredAttachRef: String?
        var managerClient: ControlPlaneClient?
        var accessSession: AccessSessionInfo?
        do {
            // 1. Create an access lease against the authority manager.
            let manager = settings.managerEndpoint()
            let client = ControlPlaneClient(baseURL: manager.url, token: manager.token)
            managerClient = client
            let operationID = pendingLeaseCreateOperations[createKey]
                ?? UUID().uuidString.lowercased()
            pendingLeaseCreateOperations[createKey] = operationID
            let session = try await client.accessSession(
                volumeID: volumeID,
                branch: branch,
                operationID: operationID
            )
            pendingLeaseCreateOperations.removeValue(forKey: createKey)
            accessSession = session
            applyMountEvent(volumeID, .sessionMinted)

            // 2. Attach through the portablefsd control socket.
            let attach = try await daemon.control.ensureAttach(DaemonEnsureAttachRequest(
                volumeId: volumeID,
                branch: branch,
                authorityUrl: session.authorityUrl,
                authToken: session.token,
                mountPath: mountPath
            ))
            ensuredAttachRef = attach.attachRef
            applyMountEvent(volumeID, .attachEnsured(attachRef: attach.attachRef))
            startLeaseMaintenance(
                volumeID: volumeID,
                client: client,
                attachRef: attach.attachRef,
                session: session
            )

            // 3. FSKit mount of the pfslocal-backed filesystem.
            try FileManager.default.createDirectory(atPath: mountPath, withIntermediateDirectories: true)
            try await MountCommand.mount(attachRef: attach.attachRef, mountPath: mountPath)
            try await MountCommand.waitUntilReady(
                attachRef: attach.attachRef,
                mountPath: mountPath
            )
            applyMountEvent(volumeID, .mountCompleted(mountPath: mountPath))
        } catch {
            if ControlPlaneClient.accessLeaseFailureDisposition(error) == .terminal {
                pendingLeaseCreateOperations.removeValue(forKey: createKey)
            }
            // Cleanup is ordered and fail-closed. Never delete the daemon
            // attach while its kernel mount still exists: that would strand
            // a mounted FSKit volume with no backend.
            var cleanupDetails: [String] = []
            var mayDetach = true
            if let ensuredAttachRef,
               MountCommand.hasLiveMount(attachRef: ensuredAttachRef, mountPath: mountPath) {
                do {
                    try await MountCommand.unmount(mountPath: mountPath)
                } catch {
                    if MountCommand.hasLiveMount(attachRef: ensuredAttachRef, mountPath: mountPath) {
                        mayDetach = false
                        cleanupDetails.append(
                            "Cleanup unmount failed; the kernel mount and daemon attach were deliberately left live: \(error)"
                        )
                    } else {
                        cleanupDetails.append("Cleanup unmount reported an error after the mount disappeared: \(error)")
                    }
                }
            }
            if mayDetach, let ensuredAttachRef {
                do {
                    try await daemon.control.deleteAttach(ref: ensuredAttachRef)
                } catch {
                    mayDetach = false
                    cleanupDetails.append("Cleanup detach failed; the attach remains registered: \(error)")
                }
            }
            if mayDetach {
                if mountedLeases[volumeID] != nil {
                    if let releaseError = await stopLeaseMaintenance(volumeID: volumeID, release: true) {
                        cleanupDetails.append("Cleanup lease release failed: \(releaseError)")
                    }
                } else if let managerClient, let accessSession {
                    let operationID = UUID().uuidString.lowercased()
                    if let releaseError = await releaseAccessSessionExactly(
                        client: managerClient,
                        session: accessSession,
                        operationID: operationID
                    ) {
                        cleanupDetails.append("Cleanup lease release failed: \(releaseError)")
                    }
                }
            }
            var detail = describeMountFailure(error)
            if !cleanupDetails.isEmpty {
                detail += "\n\n" + cleanupDetails.joined(separator: "\n")
            }
            applyMountEvent(volumeID, .failed(message: shortMessage(detail)))
            reportError(title: "Mount \(volumeID) failed", detail: detail)
        }
        await refreshLocalState()
    }

    private func performUnmount(_ volume: ListedVolume) async {
        let volumeID = volume.volumeId
        guard case let .mounted(attachRef, mountPath) = mountState(for: volume) else {
            return
        }
        applyMountEvent(volumeID, .unmountRequested)
        do {
            // Normal unmount is a durability operation: drain and prove the
            // authority barrier while the kernel mount is still usable.
            try await daemon.control.sync(ref: attachRef)
            try await MountCommand.unmount(mountPath: mountPath)
            applyMountEvent(volumeID, .unmountCompleted)
        } catch {
            let detail = String(describing: error)
            applyMountEvent(volumeID, .failed(message: shortMessage(detail)))
            reportError(title: "Unmount \(volumeID) failed", detail: detail)
            await refreshLocalState()
            return
        }
        do {
            try await daemon.control.deleteAttach(ref: attachRef)
            applyMountEvent(volumeID, .detachCompleted)
        } catch {
            let detail = String(describing: error)
            applyMountEvent(volumeID, .failed(message: shortMessage(detail)))
            reportError(title: "Detach \(volumeID) failed", detail: "The volume was unmounted but the daemon attach could not be removed: \(detail)")
            await refreshLocalState()
            return
        }
        if let releaseError = await stopLeaseMaintenance(volumeID: volumeID, release: true) {
            reportError(
                title: "Lease release \(volumeID) failed",
                detail: "The volume is safely unmounted and detached, but its access lease could not be explicitly released: \(releaseError)"
            )
        }
        await refreshLocalState()
    }

    // MARK: Access lease lifecycle

    private func startLeaseMaintenance(
        volumeID: String,
        client: ControlPlaneClient,
        attachRef: String,
        session: AccessSessionInfo
    ) {
        mountedLeases[volumeID]?.task?.cancel()
        let runtime = MountedAccessLease(client: client, attachRef: attachRef, session: session)
        mountedLeases[volumeID] = runtime
        runtime.task = Task { [weak self, weak runtime] in
            guard let self, let runtime else {
                return
            }
            await self.runLeaseMaintenance(volumeID: volumeID, runtime: runtime)
        }
    }

    /// Advances only the lease that was minted for this mount. Ambiguous
    /// responses retry the same operation ID; every definitive refusal is a
    /// surfaced terminal failure. There is intentionally no create/reacquire
    /// path here.
    private func runLeaseMaintenance(volumeID: String, runtime: MountedAccessLease) async {
        while !Task.isCancelled, mountedLeases[volumeID] === runtime {
            let nowMs = Int64(Date().timeIntervalSince1970 * 1_000)
            let remainingMs = runtime.session.expiresAtMs - nowMs
            guard remainingMs > 0 else {
                reportLeaseTerminalFailure(
                    volumeID: volumeID,
                    detail: "The access lease expired before its renewal completed. PortableFS did not create a replacement lease."
                )
                return
            }

            let waitMs: Int64
            if runtime.pendingRenewalOperationID == nil {
                waitMs = max(5_000, remainingMs / 2)
            } else {
                waitMs = min(5_000, max(1_000, remainingMs / 4))
            }
            do {
                try await Task.sleep(for: .milliseconds(waitMs))
            } catch {
                return
            }
            guard !Task.isCancelled, mountedLeases[volumeID] === runtime else {
                return
            }

            let operationID = runtime.pendingRenewalOperationID
                ?? UUID().uuidString.lowercased()
            runtime.pendingRenewalOperationID = operationID
            do {
                let renewed = try await runtime.client.renewAccessSession(
                    runtime.session,
                    operationID: operationID
                )
                if renewed.token != runtime.session.token {
                    // The app does not request rotation, but installing an
                    // explicitly returned token keeps this strict if the
                    // server ever rotates by policy.
                    try await daemon.control.setCredential(
                        ref: runtime.attachRef,
                        authToken: renewed.token
                    )
                }
                runtime.session = renewed
                runtime.pendingRenewalOperationID = nil
                runtime.renewalDelayWasReported = false
            } catch {
                switch ControlPlaneClient.accessLeaseFailureDisposition(error) {
                case .retrySameOperation:
                    if !runtime.renewalDelayWasReported {
                        runtime.renewalDelayWasReported = true
                        reportError(
                            title: "Lease renewal delayed for \(volumeID)",
                            detail: "PortableFS will retry the exact same renewal operation; it will not create a replacement lease.\n\n\(error)"
                        )
                    }
                case .terminal:
                    reportLeaseTerminalFailure(
                        volumeID: volumeID,
                        detail: "The manager definitively refused the existing access lease. PortableFS did not create a replacement lease.\n\n\(error)"
                    )
                    return
                }
            }
        }
    }

    private func reportLeaseTerminalFailure(volumeID: String, detail: String) {
        reportError(title: "Access lease failed for \(volumeID)", detail: detail)
    }

    /// Retries only the same release operation after an ambiguous response.
    /// The bounded retry improves clean-unmount behavior without creating a
    /// new operation, lease, or route. A terminal response or exhausted
    /// deadline is returned to the caller unchanged and surfaced.
    private func releaseAccessSessionExactly(
        client: ControlPlaneClient,
        session: AccessSessionInfo,
        operationID: String
    ) async -> Error? {
        let deadline = Date().addingTimeInterval(10)
        var delayMs: Int64 = 100
        while true {
            do {
                try await client.releaseAccessSession(
                    session,
                    operationID: operationID
                )
                return nil
            } catch {
                guard ControlPlaneClient.accessLeaseFailureDisposition(error) == .retrySameOperation,
                      Date() < deadline else {
                    return error
                }
                let remainingMs = max(
                    1,
                    Int64(deadline.timeIntervalSinceNow * 1_000)
                )
                do {
                    try await Task.sleep(
                        for: .milliseconds(min(delayMs, remainingMs))
                    )
                } catch {
                    return error
                }
                delayMs = min(delayMs * 2, 1_000)
            }
        }
    }

    /// Stops renewal and optionally releases the latest confirmed lease.
    /// Returns the exact release failure so callers cannot silently hide it.
    private func stopLeaseMaintenance(volumeID: String, release: Bool) async -> Error? {
        guard let runtime = mountedLeases[volumeID] else {
            return nil
        }
        runtime.task?.cancel()
        runtime.task = nil
        guard release else {
            mountedLeases.removeValue(forKey: volumeID)
            return nil
        }
        let operationID = runtime.pendingReleaseOperationID
            ?? UUID().uuidString.lowercased()
        runtime.pendingReleaseOperationID = operationID
        if let error = await releaseAccessSessionExactly(
            client: runtime.client,
            session: runtime.session,
            operationID: operationID
        ) {
            return error
        } else {
            mountedLeases.removeValue(forKey: volumeID)
            return nil
        }
    }

    private func stopLeaseMaintenance(attachRef: String, release: Bool) async -> Error? {
        guard let volumeID = mountedLeases.first(where: { $0.value.attachRef == attachRef })?.key else {
            return nil
        }
        return await stopLeaseMaintenance(volumeID: volumeID, release: release)
    }

    func openInFinder(_ volume: ListedVolume) {
        guard let path = mountState(for: volume).mountPath else {
            return
        }
        NSWorkspace.shared.open(URL(fileURLWithPath: path, isDirectory: true))
    }

    private func describeMountFailure(_ error: Error) -> String {
        let text = String(describing: error)
        if error is MountCommandError {
            return text + "\n\nIf this is the first run, enable the PortableFS file system extension: " +
                "System Settings -> General -> Login Items & Extensions -> File System Extensions, " +
                "then retry the mount. Also confirm portablefsd is healthy (menu: Daemon status)."
        }
        return text
    }

    private func shortMessage(_ detail: String) -> String {
        let firstLine = detail.split(separator: "\n").first.map(String.init) ?? detail
        return firstLine.count > 120 ? String(firstLine.prefix(117)) + "…" : firstLine
    }

    // MARK: Errors

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

    // MARK: Quit

    /// Cleanly drains and unmounts every PortableFS mount, then exits. The
    /// daemon intentionally outlives the app and may be stopped explicitly
    /// with the matching CLI once it is idle.
    func quitApp() {
        guard !isQuitting else {
            return
        }
        isQuitting = true
        Task {
            for mount in MountTable.portableFSMounts() {
                guard let attachRef = mount.attachRef else {
                    reportError(
                        title: "Quit refused",
                        detail: "Could not identify the PortableFS attach mounted at \(mount.mountPoint)."
                    )
                    isQuitting = false
                    return
                }
                do {
                    try await daemon.control.sync(ref: attachRef)
                    try await MountCommand.unmount(mountPath: mount.mountPoint)
                    try await daemon.control.deleteAttach(ref: attachRef)
                    if let releaseError = await stopLeaseMaintenance(attachRef: attachRef, release: true) {
                        throw releaseError
                    }
                } catch {
                    reportError(
                        title: "Quit refused",
                        detail: "Could not cleanly unmount \(mount.mountPoint): \(error)"
                    )
                    await refreshLocalState()
                    isQuitting = false
                    return
                }
            }
            // A failed detach may leave an unmounted daemon attach plus its
            // lease. Clean those explicitly; release retries preserve the
            // original operation ID held by stopLeaseMaintenance.
            for (volumeID, runtime) in Array(mountedLeases) {
                do {
                    try await daemon.control.deleteAttach(ref: runtime.attachRef)
                } catch {
                    reportError(
                        title: "Quit refused",
                        detail: "Could not detach the remaining \(volumeID) attach \(runtime.attachRef): \(error)"
                    )
                    isQuitting = false
                    return
                }
                if let releaseError = await stopLeaseMaintenance(volumeID: volumeID, release: true) {
                    reportError(
                        title: "Quit refused",
                        detail: "Could not release the remaining \(volumeID) access lease: \(releaseError)"
                    )
                    isQuitting = false
                    return
                }
            }
            localPollTask?.cancel()
            volumePollTask?.cancel()
            deviceFlowTask?.cancel()
            NSApplication.shared.terminate(nil)
        }
    }
}
