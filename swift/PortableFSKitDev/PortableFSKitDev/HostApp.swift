import Cocoa
import PortableFSAppCore

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var window: NSWindow?
    private var statusLabel: NSTextField?
    private var updateServer: PortableFSDServiceUpdateServer?

    private static let enabledDetail = "PortableFSKit Dev Host (launchd service enabled)"

    private func publishEnabledPresentation() {
        statusLabel?.stringValue = Self.enabledDetail
        NSLog("%@", Self.enabledDetail)
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        let status: String
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
                case .requiresApproval:
                    status = "Allow PortableFS in System Settings > General > Login Items, then reopen this app."
                }
            case .installerControlled:
                status = "PortableFSKit Dev Host (waiting for authenticated installer activation)"
            }
        } catch {
            status = "PortableFS could not register its launchd service: \(error.localizedDescription)"
            NSLog("%@", status)
        }
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 520, height: 220),
            styleMask: [.titled, .closable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        window.title = "PortableFSKit Dev"
        window.center()
        let statusLabel = NSTextField(labelWithString: status)
        window.contentView = statusLabel
        window.makeKeyAndOrderFront(nil)
        self.statusLabel = statusLabel
        self.window = window
    }
}

@main
@MainActor
enum PortableFSKitDevMain {
    private static let delegate = AppDelegate()

    static func main() {
        let application = NSApplication.shared
        application.delegate = delegate
        application.setActivationPolicy(.regular)
        application.run()
    }
}
