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

        Window("Sign In to PortableFS", id: SignInView.windowID) {
            SignInView(model: model)
        }
        .windowResizability(.contentSize)
        .defaultPosition(.center)

        Settings {
            SettingsView(model: model)
        }
    }
}
