import AppKit
import Foundation
import Observation
import ServiceManagement

@MainActor @Observable public final class PortableFSWorkspaceModel {
    public private(set) var status = PortableFSWorkspaceStatus()
    public private(set) var consentMissing = false
    public private(set) var working = false
    public private(set) var detail: String?
    private var wantsStart = false
    private var pendingDocument: Data?
    private let interactive: Bool
    private var refreshing = false
    private var home: URL { get throws { URL(fileURLWithPath: try PortableFSAccountHome.resolve(), isDirectory: true) } }
    private var client: PortableFSWorkspaceClient { get throws { PortableFSWorkspaceClient(home: try home) } }
    public init() { interactive = true }
    /// A presentation-only fixture cannot register a service, open a real
    /// editor profile or execute SSH while a test captures menu states.
    public init(snapshot: PortableFSWorkspaceStatus, consentMissing: Bool = false) {
        status = snapshot; self.consentMissing = consentMissing; interactive = false
    }
    public var statusText: String { consentMissing ? "Allow PortableFS in Background Items" : detail ?? status.message }

    public func refresh() async {
        guard interactive, !refreshing, !working else { return }
        refreshing = true; defer { refreshing = false }
        do {
            if wantsStart {
                guard try PortableFSWorkspaceServiceRegistration.register() else { consentMissing = true; return }
                consentMissing = false; wantsStart = false
                if let pendingDocument {
                    status = try await client.perform(.mount, document: pendingDocument)
                    self.pendingDocument = nil
                } else { status = try await client.perform(.start) }
            } else { status = try await client.perform(.status) }
            detail = nil
        } catch { detail = error.localizedDescription }
    }
    public func start() {
        guard interactive, !working else { return }
        wantsStart = true
        status.message = "Starting Linux Workspace…"
        Task { await refresh() }
    }
    public func stop(force: Bool = false) {
        guard interactive else { return }
        if force && !confirm(title: "Force Stop…", detail: "Open operations will fail and unflushed changes can be lost. Linux data will be kept.", action: "Force Stop") { return }
        perform(.stop, force: force)
    }
    public func remove(_ volume: PortableFSWorkspaceVolume, force: Bool = false) {
        guard interactive else { return }
        if force && !confirm(title: "Force Remove…", detail: "Open operations will fail and unflushed changes can be lost. Remote files will be kept.", action: "Force Remove") { return }
        perform(.umount, volume: volume.volumeId, force: force)
    }
    public func openDocument(authorization: Bool = false) {
        guard interactive else { return }
        let panel = NSOpenPanel()
        panel.title = authorization ? "Open Authorization…" : "Add Volume…"
        panel.canChooseDirectories = false; panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [.init(filenameExtension: "pfsworkspace") ?? .json]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let values = try url.resourceValues(forKeys: [.fileSizeKey])
            guard let size = values.fileSize, size <= 512 << 10 else { throw PortableFSWorkspaceError("Workspace document is too large") }
            let data = try Data(contentsOf: url)
            guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  object["kind"] as? String == (authorization ? "authorization" : "connection") else { throw PortableFSWorkspaceError(authorization ? "Open an authorization response." : "Open a workspace connection document.") }
            guard try PortableFSWorkspaceServiceRegistration.register() else {
                pendingDocument = data; wantsStart = true; consentMissing = true; return
            }
            perform(.mount, document: data)
        } catch { detail = error.localizedDescription }
    }
    public func saveRequest(_ volume: PortableFSWorkspaceVolume) {
        guard interactive else { return }
        do {
            guard let path = volume.authorizationRequest,
                  path == (try home).appendingPathComponent(".local/state/portablefs/workspace/authorization-" + volume.volumeId + ".pfsworkspace").path else { throw PortableFSWorkspaceError("Authorization request is not ready") }
            let data = try Data(contentsOf: URL(fileURLWithPath: path))
            guard data.count <= 512 << 10 else { throw PortableFSWorkspaceError("Authorization request is too large") }
            let panel = NSSavePanel(); panel.title = "Save Authorization Request…"; panel.nameFieldStringValue = volume.volumeId + "-request.pfsworkspace"
            guard panel.runModal() == .OK, let destination = panel.url else { return }
            try data.write(to: destination, options: .atomic)
        } catch { detail = error.localizedDescription }
    }
    private func perform(_ operation: PortableFSWorkspaceClient.Operation, document: Data? = nil, volume: String? = nil, force: Bool = false) {
        guard !working else { return }; working = true
        Task {
            defer { working = false }
            do { status = try await client.perform(operation, document: document, volume: volume, force: force); detail = nil }
            catch { detail = error.localizedDescription }
        }
    }
    public func openSettings() { if interactive { SMAppService.openSystemSettingsLoginItems() } }
    public func copy(_ text: String) { NSPasteboard.general.clearContents(); NSPasteboard.general.setString(text, forType: .string) }
    public func copyDetails(volume: PortableFSWorkspaceVolume? = nil) {
        // Only public presentation/evidence fields; never export a saved grant.
        var text = status.message + "\n" + status.notices.joined(separator: "\n")
        if let detail { text += "\n" + detail }
        for row in volume.map({ [$0] }) ?? status.volumes {
            text += "\n\(row.volumeId)\n\(row.path)\n\(row.state)\n\(row.message)"
        }
        copy(text)
    }
    public func terminal() {
        guard interactive, status.canConnect else { return }
        do {
            guard let terminal = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.apple.Terminal") else { throw PortableFSWorkspaceError("Terminal is not available.") }
            let document = try PortableFSWorkspaceTerminal.commandFile(in: FileManager.default.temporaryDirectory)
            NSWorkspace.shared.open([document], withApplicationAt: terminal, configuration: .init()) { _, error in
                if let error {
                    try? FileManager.default.removeItem(at: document)
                    Task { @MainActor in self.detail = "Terminal could not open SSH: \(error.localizedDescription)" }
                }
            }
        } catch { detail = error.localizedDescription }
    }
    public func editor(_ editor: PortableFSWorkspaceEditor, volume: PortableFSWorkspaceVolume) {
        guard interactive, status.canConnect, volume.canOpen else { return }
        Task {
            do { try await editor.open(volume: volume.volumeId) }
            catch { showError(error.localizedDescription) }
        }
    }
    public func removeWorkspace() {
        guard interactive else { return }
        let alert = NSAlert(); alert.messageText = "Remove Linux Workspace…"
        alert.informativeText = "Stop Linux Workspace and remove its background service and SSH setup. Remote volumes will be kept."
        alert.addButton(withTitle: "Keep Linux data")
        alert.addButton(withTitle: "Cancel")
        alert.addButton(withTitle: "Delete Linux data…")
        let choice = alert.runModal()
        guard choice != .alertSecondButtonReturn else { return }
        let disposition: WorkspaceRemoval.DataDisposition = choice == .alertThirdButtonReturn ? .delete : .keep
        if disposition == .delete && !confirm(title: "Delete Linux data…", detail: "Permanently delete the Linux home, editor installations, SSH identity and local workspace data. This cannot be undone. Remote volumes will be kept.", action: "Delete Linux data") { return }
        guard !working else { return }; working = true
        Task {
            defer { working = false }
            do {
                _ = try await WorkspaceRemoval.remove(data: disposition)
                status = PortableFSWorkspaceStatus(); detail = nil; wantsStart = false; consentMissing = false
            } catch { showError(error.localizedDescription); detail = error.localizedDescription }
        }
    }
    private func confirm(title: String, detail: String, action: String) -> Bool {
        let alert = NSAlert(); alert.alertStyle = .warning; alert.messageText = title; alert.informativeText = detail
        alert.addButton(withTitle: "Cancel"); alert.addButton(withTitle: action)
        return alert.runModal() == .alertSecondButtonReturn
    }
    private func showError(_ text: String) {
        let alert = NSAlert(); alert.messageText = text; alert.addButton(withTitle: "OK"); alert.runModal()
    }
}
