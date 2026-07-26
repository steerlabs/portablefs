import Cocoa

@main
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var window: NSWindow?

    func applicationDidFinishLaunching(_ notification: Notification) {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 520, height: 220),
            styleMask: [.titled, .closable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        window.title = "PortableFSKit Dev"
        window.center()
        window.contentView = NSTextField(labelWithString: "PortableFSKit Dev Host")
        window.makeKeyAndOrderFront(nil)
        self.window = window
    }
}
