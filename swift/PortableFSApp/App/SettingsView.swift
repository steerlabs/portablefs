import AppKit
import SwiftUI

struct SettingsView: View {
    @Bindable var model: AppModel

    var body: some View {
        Form {
            Section("Account") {
                if model.config.profiles.isEmpty {
                    Text("No profiles yet — use Sign In from the menu.")
                        .foregroundStyle(.secondary)
                } else {
                    Picker("Profile", selection: profileBinding) {
                        ForEach(model.config.profiles.keys.sorted(), id: \.self) { name in
                            Text(name).tag(name)
                        }
                    }
                    LabeledContent("Server", value: model.settings.apiURL.isEmpty ? "—" : model.settings.apiURL)
                    Button("Sign Out of \"\(model.config.currentProfile)\"", role: .destructive) {
                        model.signOut()
                    }
                }
                LabeledContent("Config file", value: model.configPath)
                    .font(.caption)
            }

            Section("Mounts") {
                TextField("Mount base directory", text: $model.mountBaseDirectory)
                    .autocorrectionDisabled()
                Text("Volumes mount at <base>/<volume-id>.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("Daemon") {
                LabeledContent("Status", value: model.daemon.statusLabel)
                if !model.daemon.statusDetail.isEmpty {
                    Text(model.daemon.statusDetail)
                        .font(.caption)
                        .foregroundStyle(.red)
                        .textSelection(.enabled)
                }
                if let binary = model.daemon.binaryPath {
                    LabeledContent("Binary", value: binary)
                        .font(.caption)
                }
                TextField("portablefsd path override", text: $model.daemonBinaryOverride, prompt: Text("auto-detect"))
                    .autocorrectionDisabled()
                LabeledContent("Frontend socket", value: model.daemon.frontendSocketPath)
                    .font(.caption)
                LabeledContent("Control socket", value: model.daemon.controlSocketPath)
                    .font(.caption)
                LabeledContent("Log", value: model.daemon.logPath)
                    .font(.caption)
                Button("Reveal Log in Finder") {
                    NSWorkspace.shared.activateFileViewerSelecting(
                        [URL(fileURLWithPath: model.daemon.logPath)]
                    )
                }
            }
        }
        .formStyle(.grouped)
        .frame(width: 520)
        .fixedSize(horizontal: false, vertical: true)
    }

    private var profileBinding: Binding<String> {
        Binding(
            get: { model.config.currentProfile },
            set: { model.switchProfile($0) }
        )
    }
}
