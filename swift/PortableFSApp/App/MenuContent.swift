import AppKit
import PortableFSAppCore
import SwiftUI

struct MenuContent: View {
    let model: AppModel
    @Environment(\.openWindow) private var openWindow
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        Text(model.signedInDescription)
        Text("Daemon: \(model.daemon.statusLabel)")
        Divider()

        volumesSection
        Divider()

        alertsSection

        Button("Refresh") {
            Task {
                await model.refreshAll()
            }
        }
        if model.isSignedIn {
            Button("Sign In / Switch Account…") {
                openSignInWindow()
            }
        } else {
            Button("Sign In…") {
                openSignInWindow()
            }
        }
        Button("Settings…") {
            NSApplication.shared.activate()
            openSettings()
        }
        Divider()
        Button("Quit PortableFS") {
            model.quitApp()
        }
        .disabled(model.isQuitting)
    }

    private func openSignInWindow() {
        NSApplication.shared.activate()
        openWindow(id: SignInView.windowID)
    }

    @ViewBuilder
    private var volumesSection: some View {
        if !model.isSignedIn {
            Text("Sign in to list volumes")
        } else if let error = model.volumesError {
            Menu("Volume list unavailable") {
                Button("Copy Error Details") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(error, forType: .string)
                }
            }
        } else if model.volumes.isEmpty {
            Text(model.isRefreshingVolumes ? "Loading volumes…" : "No volumes")
        } else {
            ForEach(model.volumes) { volume in
                VolumeMenu(model: model, volume: volume)
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

private struct VolumeMenu: View {
    let model: AppModel
    let volume: ListedVolume

    var body: some View {
        let state = model.mountState(for: volume)
        Menu {
            Text(state.menuStatusLabel)
            if let path = state.mountPath {
                Text(path)
            }
            Divider()
            switch state {
            case .mounted:
                Button("Open in Finder") {
                    model.openInFinder(volume)
                }
                Button("Unmount") {
                    model.unmount(volume)
                }
            case .unmounted, .failed:
                Button("Mount \(volume.volumeId)@\(volume.defaultBranch)") {
                    model.mount(volume)
                }
                if case let .failed(message) = state {
                    Button("Copy Error") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(message, forType: .string)
                    }
                }
            default:
                EmptyView()
            }
        } label: {
            Label(volume.volumeId, systemImage: symbolName(for: state))
        }
    }

    private func symbolName(for state: VolumeMountState) -> String {
        switch state {
        case .mounted:
            return "circle.fill"
        case .failed:
            return "exclamationmark.triangle"
        case .unmounted:
            return "circle"
        default:
            return "circle.dotted"
        }
    }
}
