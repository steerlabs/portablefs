import Cocoa
import PortableFSAppCore

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var window: NSWindow?
    private var statusLabel: NSTextField?
    private var updateServer: PortableFSDServiceUpdateServer?

    private static let enabledDetail = "PortableFSKit macOS 27 Dev Host (launchd service enabled)"

    private func publishPresentation(state: String, detail: String) {
        // These defaults and the label are presentation-only diagnostics. No
        // service, installer, or mount decision reads them as authority.
        UserDefaults.standard.set(state, forKey: "PFSLaunchAgentState")
        UserDefaults.standard.set(detail, forKey: "PFSLaunchAgentDetail")
        statusLabel?.stringValue = detail
        NSLog("%@", detail)
    }

    private func publishEnabledPresentation() {
        publishPresentation(state: "enabled", detail: Self.enabledDetail)
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        let status: String
        let diagnosticState: String
        do {
            let server = try PortableFSDServiceUpdateServer.start(
                callbacks: .init(
                    quiesceNormalLifecycle: {},
                    resumeNormalLifecycle: { [weak self] in
                        Task { @MainActor [weak self] in
                            self?.publishEnabledPresentation()
                        }
                    },
                    requestHostExit: {
                        DispatchQueue.main.async {
                            NSApplication.shared.terminate(nil)
                        }
                    }
                )
            )
            updateServer = server
            switch server.startupDisposition {
            case .normal:
                switch try PortableFSDServiceCoordinator.prepareAndRegister() {
                case .enabled:
                    status = Self.enabledDetail
                    diagnosticState = "enabled"
                case .requiresApproval:
                    status = "Allow PortableFS in System Settings > General > Login Items, then reopen this app."
                    diagnosticState = "requiresApproval"
                }
            case .installerControlled:
                status = "PortableFSKit macOS 27 Dev Host (waiting for authenticated installer activation)"
                diagnosticState = "installerControlled"
            }
        } catch {
            status = "PortableFS could not register its launchd service: \(error.localizedDescription)"
            diagnosticState = "error"
        }
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 620, height: 220),
            styleMask: [.titled, .closable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        window.title = "PortableFSKit macOS 27 Dev"
        window.center()
        let statusLabel = NSTextField(labelWithString: status)
        window.contentView = statusLabel
        window.makeKeyAndOrderFront(nil)
        self.statusLabel = statusLabel
        self.window = window
        publishPresentation(state: diagnosticState, detail: status)
    }
}

@main
@MainActor
enum PortableFSKitMacOS27DevMain {
    private static let delegate = AppDelegate()

    static func main() {
        let application = NSApplication.shared
        application.delegate = delegate
        application.setActivationPolicy(.regular)
        application.run()
    }
}
