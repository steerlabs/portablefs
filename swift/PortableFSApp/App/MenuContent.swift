import AppKit
import PortableFSAppCore
import SwiftUI

struct MenuContent: View {
    let model: AppModel
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        Group {
            if !model.isLifecycleReady {
                Text("Starting PortableFS…")
                Divider()
                Button("Quit PortableFS") {
                    model.quitApp()
                }
            } else {
                mountsSection
                Divider()

                alertsSection

                Button("Refresh") {
                    Task {
                        await model.refreshAll()
                    }
                }
                Button("Settings…") {
                    NSApplication.shared.activate()
                    openSettings()
                }
                Button("File System Extension Setup…") {
                    FirstRunAssistant.shared.present()
                }
                Button(model.isStoppingDaemon ? "Stopping Background Daemon…" : "Stop Background Daemon") {
                    model.stopDaemon()
                }
                .disabled(!model.canStopDaemon)
                Divider()
                Button("Quit PortableFS") {
                    model.quitApp()
                }
                .disabled(model.isQuitting)
            }
        }
        .onAppear {
            model.activateInteractiveSession()
        }
    }

    @ViewBuilder
    private var mountsSection: some View {
        if !model.isMountInventoryKnown {
            Text("Mount inventory unavailable")
        } else if model.mounts.isEmpty {
            // Mounting needs direct v3 credentials this app never holds, so
            // the honest empty state points at the command that does.
            Text("No mounted volumes")
            Text("Mount with: portablefs mount <volume> <directory>")
        } else {
            ForEach(model.mounts) { mount in
                MountMenu(model: model, mount: mount)
            }
        }
    }

    @ViewBuilder
    private var alertsSection: some View {
        if !model.alerts.isEmpty {
            ForEach(model.alerts.prefix(4)) { alert in
                Menu {
                    Button("Copy Details") {
                        model.copyAlert(alert)
                    }
                    Divider()
                    Text(alert.detail.count > 300 ? String(alert.detail.prefix(297)) + "…" : alert.detail)
                } label: {
                    Label(alert.title, systemImage: "exclamationmark.triangle")
                }
            }
            Button("Clear Alerts") {
                model.clearAlerts()
            }
            Divider()
        }
    }
}

private struct MountMenu: View {
    let model: AppModel
    let mount: PortableFSCLIMountRow

    var body: some View {
        Menu {
            Text(mount.mountPath)
            Text(statusLabel)
            if !mount.attachError.isEmpty {
                Text(
                    mount.attachError.count > 300
                        ? String(mount.attachError.prefix(297)) + "…"
                        : mount.attachError
                )
            }
            Divider()
            if !mount.requiresCleanup {
                Button("Reveal in Finder") {
                    model.revealInFinder(mount)
                }
            }
            Button(mount.requiresCleanup ? "Unmount / Reconcile" : "Unmount") {
                model.unmount(mount)
            }
            .disabled(model.isUnmounting(mount))
            if !mount.attachError.isEmpty {
                Button("Copy Attach Error") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(mount.attachError, forType: .string)
                }
            }
        } label: {
            Label(mount.volumeId, systemImage: symbolName)
        }
    }

    private var statusLabel: String {
        if model.isUnmounting(mount) {
            return "Unmounting…"
        }
        if mount.requiresCleanup {
            return mount.operationPhase.isEmpty
                ? "Cleanup required"
                : "Cleanup required (\(mount.operationPhase))"
        }
        if mount.attachState.isEmpty {
            return "Health: \(mount.health)"
        }
        return "Health: \(mount.health), attach: \(mount.attachState)"
    }

    private var symbolName: String {
        if mount.requiresCleanup || mount.health != "live" || mount.attachState == "degraded" {
            return "exclamationmark.triangle"
        }
        return "circle.fill"
    }
}
