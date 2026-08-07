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
/// the bundled CLI reports, unmount and crash reconciliation, the per-user
/// daemon, and the one-time file system extension enablement. Every one of
/// those runs through the exact signed CLI inside this bundle, which is the
/// sole owner of mount, daemon, and lifecycle-lock state.
@MainActor
@Observable
final class AppModel {
    // MARK: Account identity

    private let startupPathError: String?

    // MARK: Mount inventory

    private(set) var mounts: [PortableFSCLIMountRow] = []
    private(set) var isMountInventoryKnown = false
    private(set) var unmountingPaths: Set<String> = []

    // MARK: Daemon

    private(set) var isStoppingDaemon = false
    private(set) var cliVersion: String?

    // MARK: Errors / quit

    private(set) var alerts: [AppAlert] = []
    private(set) var isQuitting = false

    private let cli = PortableFSCLI()
    private var lifecycleHold: PortableFSCLILease?
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
        do {
            _ = try PortableFSAccountHome.resolve()
            startupPathError = nil
        } catch {
            startupPathError = String(describing: error)
        }
        Task {
            await acquireAppLifecycle()
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

    // MARK: Daemon

    /// The daemon serves every mount on this account, so stopping it is
    /// offered only when this app sees no mounts at all. The CLI still proves
    /// idleness atomically; this is the presentation half of that refusal.
    var canStopDaemon: Bool {
        isLifecycleReady && isMountInventoryKnown && mounts.isEmpty && !isStoppingDaemon
    }

    func stopDaemon() {
        guard canStopDaemon else {
            return
        }
        Task {
            isStoppingDaemon = true
            defer {
                isStoppingDaemon = false
            }
            do {
                try await cli.stopDaemon()
            } catch {
                reportError(
                    title: "Stop background daemon failed",
                    detail: String(describing: error)
                )
            }
            await refreshMounts()
        }
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
        mountPollTask?.cancel()
        lifecycleHold?.release()
        lifecycleHold = nil
        NSApplication.shared.terminate(nil)
    }
}
