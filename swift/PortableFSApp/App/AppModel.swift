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
        config.currentProfile = name
        persistConfig()
        volumes = []
        Task {
            await refreshVolumes()
        }
    }

    func signOut() {
        config.profiles.removeValue(forKey: config.currentProfile)
        persistConfig()
        volumes = []
        volumesError = nil
    }

    private func persistConfig() {
        do {
            try PortableFSConfigFile.save(config, path: configPath)
            configError = nil
        } catch {
            configError = String(describing: error)
            reportError(title: "Could not save config", detail: String(describing: error))
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
        saveProfile(
            name: profileName,
            profile: PortableFSProfile(
                apiUrl: normalized,
                apiToken: token,
                managerUrl: ControlPlaneClient.normalizeServerURL(managerURL),
                managerToken: managerToken
            )
        )
        let verification = await ControlPlaneClient(baseURL: normalized, token: token).verifyCredential()
        switch verification {
        case .accepted:
            await refreshVolumes()
            return nil
        case let .rejected(status):
            return "Credentials were saved to \(configPath) but the server rejected the token (HTTP \(status))."
        case let .unreachable(message):
            return "Credentials were saved to \(configPath) but the server could not be reached: \(message)"
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
                    saveProfile(
                        name: profile,
                        profile: PortableFSProfile(
                            apiUrl: serverURL,
                            apiToken: apiKey,
                            managerUrl: resolvedManagerURL,
                            managerToken: managerToken
                        )
                    )
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

    private func saveProfile(name: String, profile: PortableFSProfile) {
        config.profiles[name] = profile
        config.currentProfile = name
        persistConfig()
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
            attaches = (try? await daemon.control.listAttaches()) ?? []
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
        let mountPath = PortableFSAppPaths.mountPoint(baseDirectory: mountBaseDirectory, volumeID: volumeID)
        do {
            // 1. Mint a mount session against the authority manager.
            let manager = settings.managerEndpoint()
            let managerClient = ControlPlaneClient(baseURL: manager.url, token: manager.token)
            let session = try await managerClient.mountSession(volumeID: volumeID, branch: branch)
            applyMountEvent(volumeID, .sessionMinted)

            // 2. Attach through the portablefsd control socket.
            let attach = try await daemon.control.ensureAttach(DaemonEnsureAttachRequest(
                volumeId: volumeID,
                branch: branch,
                authorityUrl: session.authorityUrl,
                authToken: session.token,
                mountPath: mountPath
            ))
            applyMountEvent(volumeID, .attachEnsured(attachRef: attach.attachRef))

            // 3. FSKit mount of the pfslocal-backed filesystem.
            try FileManager.default.createDirectory(atPath: mountPath, withIntermediateDirectories: true)
            try await MountCommand.mount(attachRef: attach.attachRef, mountPath: mountPath)
            applyMountEvent(volumeID, .mountCompleted(mountPath: mountPath))
        } catch {
            let detail = describeMountFailure(error)
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
        }
        await refreshLocalState()
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

    /// Unmounts every live PortableFS kernel mount, detaches the attaches
    /// that were actually released, stops the daemon, and exits.
    func quitApp() {
        localPollTask?.cancel()
        volumePollTask?.cancel()
        deviceFlowTask?.cancel()
        Task {
            for mount in MountTable.portableFSMounts() {
                try? await MountCommand.unmount(mountPath: mount.mountPoint)
            }
            if daemon.healthy, let attaches = try? await daemon.control.listAttaches() {
                let stillMounted = Set(MountTable.portableFSMounts().compactMap(\.attachRef))
                for attach in attaches where !stillMounted.contains(attach.attachRef) {
                    try? await daemon.control.deleteAttach(ref: attach.attachRef)
                }
            }
            await daemon.stop()
            NSApplication.shared.terminate(nil)
        }
    }
}
