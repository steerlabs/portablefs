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

/// Menu-bar presentation state.
///
/// A v3 mount is admitted by direct credentials — authority address, single-use
/// volume capability, mutual-TLS client identity — which arrive through
/// `portablefs mount`. The app mints none of them and therefore does not mount.
/// What it owns is the LIFECYCLE of mounts that already exist: the inventory
/// the bundled CLI reports, unmount and crash reconciliation, and one-time
/// file system extension enablement. ServiceManagement owns the per-user
/// daemon lifecycle; the exact bundled CLI owns mount and lifecycle-lock state.
@MainActor
@Observable
final class AppModel {
    // MARK: Account identity

    private var startupPathError: String?

    // MARK: Mount inventory

    private(set) var mounts: [PortableFSCLIMountRow] = []
    private(set) var isMountInventoryKnown = false
    private(set) var unmountingPaths: Set<String> = []

    // MARK: Daemon

    private(set) var cliVersion: String?

    // MARK: Errors / quit

    private(set) var alerts: [AppAlert] = []
    private(set) var isQuitting = false

    private let cli = PortableFSCLI()
    private var serviceUpdateServer: PortableFSDServiceUpdateServer?
    private var lifecycleHold: PortableFSCLILease?
    private var lifecycleAcquireTask: Task<Void, Never>?
    private var mountPollTask: Task<Void, Never>?
    private var interactiveSessionActivated = false
    private var isRefreshingMounts = false
    private var mountInventoryError: String?
    private var interactiveSessionRequested = false

    private(set) var isLifecycleReady = false

    var menuBarSymbolName: String {
        mounts.contains { $0.health == "live" }
            ? "externaldrive.fill.badge.checkmark"
            : "externaldrive"
    }

    init() {
        startupPathError = nil
        var startupFailure: String?
        do {
            _ = try PortableFSAccountHome.resolve()
        } catch {
            startupFailure = String(describing: error)
        }

        var shouldAcquireLifecycle = false
        if startupFailure == nil {
            do {
                let server = try PortableFSDServiceUpdateServer.start(
                    callbacks: .init(
                        quiesceNormalLifecycle: { [weak self] in
                            guard let self else {
                                throw PortableFSCLIError(
                                    command: "PortableFS update",
                                    status: nil,
                                    detail: "host lifecycle owner disappeared"
                                )
                            }
                            var outcome: Result<Void, any Error>?
                            DispatchQueue.main.sync {
                                outcome = Result {
                                    try self.quiesceForInstallerUpdate()
                                }
                            }
                            try outcome!.get()
                        },
                        resumeNormalLifecycle: { [weak self] in
                            DispatchQueue.main.async {
                                self?.scheduleLifecycleAcquisition()
                            }
                        },
                        requestHostExit: {
                            DispatchQueue.main.async {
                                NSApplication.shared.terminate(nil)
                            }
                        }
                    )
                )
                serviceUpdateServer = server
                switch server.startupDisposition {
                case .normal:
                    if try PortableFSDServiceCoordinator.prepareAndRegister() == .requiresApproval {
                        startupFailure = "Allow PortableFS in System Settings > General > Login Items, then reopen the app."
                    } else {
                        shouldAcquireLifecycle = true
                    }
                case .installerControlled:
                    // The tokenized update session owns activation. Normal
                    // registration before it completes would violate fencing.
                    break
                }
            } catch {
                startupFailure = "PortableFS could not start its signed service/update boundary: \(error.localizedDescription)"
            }
        }
        startupPathError = startupFailure
        if shouldAcquireLifecycle || startupFailure != nil {
            scheduleLifecycleAcquisition()
        }
    }

    /// Polling begins only after the user opens the menu. Launch executes only
    /// the required lifecycle-holder command; it does not start a daemon or
    /// inspect mounts.
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
            await refreshMounts()
            await refreshVersion()
        }
        mountPollTask = Task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(5))
                await refreshMounts()
            }
        }
    }

    private func scheduleLifecycleAcquisition() {
        guard lifecycleAcquireTask == nil,
              lifecycleHold == nil,
              !isQuitting else { return }
        lifecycleAcquireTask = Task {
            await acquireAppLifecycle()
            lifecycleAcquireTask = nil
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
        let deadline = Date().addingTimeInterval(10)
        var lastError: Error?
        while !Task.isCancelled && Date() < deadline {
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
                return
            } catch {
                lastError = error
                try? await Task.sleep(for: .milliseconds(100))
            }
        }
        guard !Task.isCancelled else { return }
        let alert = NSAlert()
        alert.alertStyle = .critical
        alert.messageText = "PortableFS Could Not Start"
        alert.informativeText = "PortableFS is being installed or updated, or its lifecycle lock could not be acquired.\n\n\(lastError?.localizedDescription ?? "timed out")"
        alert.runModal()
        NSApplication.shared.terminate(nil)
    }

    private func quiesceForInstallerUpdate() throws {
        guard isLifecycleReady, let hold = lifecycleHold else {
            throw PortableFSCLIError(
                command: "PortableFS update",
                status: nil,
                detail: "normal app lifecycle is not held"
            )
        }
        isLifecycleReady = false
        mountPollTask?.cancel()
        mountPollTask = nil
        interactiveSessionActivated = false
        lifecycleHold = nil
        try hold.releaseAndWait()
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

    // MARK: Mount inventory

    func refreshAll() async {
        guard isLifecycleReady else {
            return
        }
        await refreshMounts()
        await refreshVersion()
    }

    func refreshMounts() async {
        guard isLifecycleReady else {
            return
        }
        guard !isRefreshingMounts else {
            return
        }
        isRefreshingMounts = true
        defer {
            isRefreshingMounts = false
        }
        do {
            mounts = try await cli.mounts()
            isMountInventoryKnown = true
            mountInventoryError = nil
        } catch {
            isMountInventoryKnown = false
            let detail = String(describing: error)
            if mountInventoryError != detail {
                mountInventoryError = detail
                reportError(title: "Could not read local mounts", detail: detail)
            }
        }
    }

    private func refreshVersion() async {
        guard isLifecycleReady, cliVersion == nil else {
            return
        }
        cliVersion = try? await cli.version()
    }

    // MARK: Unmount

    func isUnmounting(_ row: PortableFSCLIMountRow) -> Bool {
        unmountingPaths.contains(row.mountPath)
    }

    func unmount(_ row: PortableFSCLIMountRow) {
        guard isLifecycleReady, !unmountingPaths.contains(row.mountPath) else {
            return
        }
        Task {
            await performUnmount(row)
        }
    }

    private func performUnmount(_ row: PortableFSCLIMountRow) async {
        unmountingPaths.insert(row.mountPath)
        defer {
            unmountingPaths.remove(row.mountPath)
        }
        do {
            try await cli.unmount(mountPath: row.mountPath)
        } catch {
            reportError(
                title: "Unmount \(row.volumeId) failed",
                detail: String(describing: error)
            )
        }
        await refreshMounts()
    }

    func revealInFinder(_ row: PortableFSCLIMountRow) {
        NSWorkspace.shared.open(URL(fileURLWithPath: row.mountPath, isDirectory: true))
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
        lifecycleAcquireTask?.cancel()
        mountPollTask?.cancel()
        lifecycleHold?.release()
        lifecycleHold = nil
        serviceUpdateServer?.stop()
        NSApplication.shared.terminate(nil)
    }
}
