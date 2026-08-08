import AppKit
import SwiftUI

@main
struct PortableFSAppMain: App {
    @State private var model = AppModel()

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
