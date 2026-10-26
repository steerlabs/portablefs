import AppKit
import SwiftUI
import PortableFSAppCore

@main
struct PortableFSAppMain: App {
    @State private var model: AppModel

    init() {
        if Array(CommandLine.arguments.dropFirst()) == ["--workspace-service-register"] {
            do {
                let enabled = try PortableFSWorkspaceServiceRegistration.register()
                if !enabled { fputs("Allow PortableFS in Background Items\n", stderr) }
                exit(enabled ? 0 : 3)
            } catch { fputs("workspace service registration failed: \(error)\n", stderr); exit(1) }
        }
        _model = State(initialValue: AppModel())
    }

    var body: some Scene {
        MenuBarExtra {
            MenuContent(model: model)
        } label: {
            Image(systemName: model.menuBarSymbolName)
                .accessibilityLabel("PortableFS")
        }

        Settings {
            SettingsView(model: model)
        }
    }
}
