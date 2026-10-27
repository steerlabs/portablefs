import SwiftUI

public struct PortableFSWorkspaceMenu: View {
    private let model: PortableFSWorkspaceModel
    public init(model: PortableFSWorkspaceModel) { self.model = model }
    public var body: some View {
        Menu("Linux Workspace") {
            Text(model.statusText)
            ForEach(model.status.outcomes) { outcome in
                Menu(outcome.message) {
                    if let volume = outcome.volumeId { Text(volume) }
                    Button("Copy Details") { model.copyDetails(outcome: outcome) }
                    Button("Dismiss") { model.dismiss(outcome) }.disabled(model.working)
                }
            }
            if model.status.outcomes.isEmpty { ForEach(model.status.notices, id: \.self) { Text($0) } }
            if model.consentMissing { Button("Open System Settings") { model.openSettings() } }
            Divider()
            if model.status.showsStop {
                Button("Stop Linux Workspace") { model.stop() }.disabled(model.working)
                if model.detail != nil || model.status.state == "cleanup-required" || model.status.volumes.contains(where: { $0.state == "busy" }) {
                    Button("Force Stop…") { model.stop(force: true) }.disabled(model.working)
                }
            } else { Button("Start Linux Workspace") { model.start() }.disabled(model.working) }
            Menu("Connect…") {
                Button("Open Terminal") { model.terminal() }
                ForEach(PortableFSWorkspaceEditor.allCases, id: \.self) { editor in
                    if model.status.volumes.count == 1, let volume = model.status.volumes.first {
                        Button("Open in \(editor.name)") { model.editor(editor, volume: volume) }.disabled(!volume.canOpen)
                    } else {
                        Menu("Open in \(editor.name)") {
                            ForEach(model.status.volumes) { volume in
                                Button(volume.volumeId) { model.editor(editor, volume: volume) }.disabled(!volume.canOpen)
                            }
                        }.disabled(model.status.volumes.isEmpty)
                    }
                }
                Button("Copy SSH Command") { model.copy(PortableFSWorkspaceSSH.command) }
            }.disabled(!model.status.canConnect)
            Button("Add Volume…") { model.openDocument() }.disabled(model.working)
            ForEach(model.status.volumes) { volume in
                Menu(volume.volumeId) {
                    Text(volume.path)
                    Text(volume.message.isEmpty ? volume.state.capitalized : volume.message)
                    Divider()
                    Button("Copy Linux Path") { model.copy(volume.path) }
                    if volume.requiresAuthorization {
                        if volume.authorizationRequest != nil { Button("Save Authorization Request…") { model.saveRequest(volume) } }
                        Button("Open Authorization…") { model.openDocument(authorization: true) }
                    }
                    if volume.requiresReopen && volume.canOpen {
                        ForEach(PortableFSWorkspaceEditor.allCases, id: \.self) { editor in
                            Button("Open in \(editor.name)") { model.editor(editor, volume: volume) }
                        }
                    }
                    Button("Remove from Linux") { model.remove(volume) }.disabled(model.working)
                    if volume.state == "busy" || volume.state == "terminal" {
                        Button("Force Remove…") { model.remove(volume, force: true) }.disabled(model.working)
                    }
                    Button("Copy Details") { model.copyDetails(volume: volume) }
                }
            }
            if model.detail != nil || !model.status.notices.isEmpty || model.status.state == "cleanup-required" || model.status.state == "refused" {
                Divider()
                Button("Copy Details") { model.copyDetails() }
            }
        }
    }
}
