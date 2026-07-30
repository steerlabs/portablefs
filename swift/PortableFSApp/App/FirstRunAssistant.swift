import AppKit
import SwiftUI

@MainActor
final class FirstRunAssistant {
    static let shared = FirstRunAssistant()

    private static let completedVersionKey = "firstRunAssistantCompletedVersion"
    private static let currentVersion = 1

    private var windowController: NSWindowController?

    var shouldPresentAtLaunch: Bool {
        UserDefaults.standard.integer(forKey: Self.completedVersionKey) < Self.currentVersion
    }

    func present() {
        if let window = windowController?.window {
            NSApplication.shared.activate()
            window.makeKeyAndOrderFront(nil)
            return
        }

        let view = FirstRunAssistantView(
            openSystemSettings: Self.openSystemSettings,
            complete: { [weak self] in
                UserDefaults.standard.set(Self.currentVersion, forKey: Self.completedVersionKey)
                self?.windowController?.close()
                self?.windowController = nil
            }
        )
        let content = NSHostingController(rootView: view)
        let window = NSWindow(contentViewController: content)
        window.title = "Set Up PortableFS"
        window.styleMask = [.titled, .closable]
        window.isReleasedWhenClosed = false
        window.center()

        let controller = NSWindowController(window: window)
        windowController = controller
        NSApplication.shared.activate()
        controller.showWindow(nil)
    }

    private static func openSystemSettings() {
        let url = URL(fileURLWithPath: "/System/Applications/System Settings.app", isDirectory: true)
        let configuration = NSWorkspace.OpenConfiguration()
        NSWorkspace.shared.openApplication(at: url, configuration: configuration) { _, error in
            guard let error else {
                return
            }
            Task { @MainActor in
                let alert = NSAlert(error: error)
                alert.messageText = "Could Not Open System Settings"
                alert.runModal()
            }
        }
    }
}

private struct FirstRunAssistantView: View {
    private enum Step {
        case enableExtension
        case firstMount
    }

    let openSystemSettings: () -> Void
    let complete: () -> Void

    @State private var step = Step.enableExtension

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Label("PortableFS File System Extension", systemImage: "externaldrive")
                .font(.title2.weight(.semibold))

            switch step {
            case .enableExtension:
                enableExtension
            case .firstMount:
                firstMount
            }
        }
        .padding(28)
        .frame(width: 560)
    }

    private var enableExtension: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("macOS requires you to enable the extension once before PortableFS can mount a volume.")

            VStack(alignment: .leading, spacing: 8) {
                Text("1. Open System Settings.")
                Text("2. Choose General → Login Items & Extensions.")
                Text("3. Open File System Extensions and enable PortableFS.")
            }
            .padding(.leading, 8)

            Text("PortableFS cannot verify this toggle without attempting a real mount. Continuing records only that you followed these instructions.")
                .font(.callout)
                .foregroundStyle(.secondary)

            HStack {
                Button("Open System Settings") {
                    openSystemSettings()
                }
                Spacer()
                Button("I Enabled It — Continue") {
                    step = .firstMount
                }
                .keyboardShortcut(.defaultAction)
            }
        }
    }

    private var firstMount: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Try a real mount")
                .font(.headline)

            Text("Sign in from the PortableFS menu bar, then choose a volume and Mount. That mount attempt—not this assistant—is the authoritative extension check.")

            Text("You can also mount from Terminal:")
                .foregroundStyle(.secondary)

            HStack {
                Text("portablefs mount <volume> <mount-directory>")
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                Spacer()
                Button("Copy") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(
                        "portablefs mount <volume> <mount-directory>",
                        forType: .string
                    )
                }
            }
            .padding(12)
            .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))

            Label(
                "Extension enablement is still unverified until a mount succeeds.",
                systemImage: "info.circle"
            )
            .font(.callout)
            .foregroundStyle(.secondary)

            HStack {
                Button("Back") {
                    step = .enableExtension
                }
                Spacer()
                Button("Done") {
                    complete()
                }
                .keyboardShortcut(.defaultAction)
            }
        }
    }
}
