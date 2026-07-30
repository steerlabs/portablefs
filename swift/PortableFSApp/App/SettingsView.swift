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
                    .disabled(
                        model.isAccountMutationInProgress ||
                            model.hasAccountEnvironmentOverrides
                    )
                    LabeledContent("Server", value: model.settings.apiURL.isEmpty ? "—" : model.settings.apiURL)
                    Button("Sign Out of \"\(model.config.currentProfile)\"", role: .destructive) {
                        model.signOut()
                    }
                    .disabled(
                        model.isAccountMutationInProgress ||
                            model.hasAccountEnvironmentOverrides
                    )
                }
                if model.hasAccountEnvironmentOverrides {
                    Text(
                        "\(model.accountEnvironmentOverrideNames.joined(separator: ", ")) controls the active account. Relaunch without it before changing saved profiles."
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
                LabeledContent("Config file", value: model.configPath)
                    .font(.caption)
            }

            Section("Mounts") {
                HStack {
                    TextField("Mount base directory", text: $model.mountBaseDirectory)
                        .autocorrectionDisabled()
                    Button("Choose Folder…") {
                        chooseMountBaseDirectory()
                    }
                }
                .disabled(!model.isLocalMountInventoryKnown || !model.localMounts.isEmpty)
                Text("Volumes mount at <base>/<volume-id>.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if let error = model.mountBaseDirectoryValidationError {
                    Text(error)
                        .font(.caption)
                        .foregroundStyle(.red)
                } else if !model.isLocalMountInventoryKnown {
                    Text("The mount location remains locked until PortableFS obtains a complete local mount inventory.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else if !model.localMounts.isEmpty {
                    Text("Unmount every PortableFS volume before changing the mount location.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Section("Mount Runtime") {
                Text("The signed portablefs CLI inside this app owns mounts, daemon state, access leases, and lifecycle coordination.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
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

    private func chooseMountBaseDirectory() {
        let panel = NSOpenPanel()
        panel.title = "Choose PortableFS Mount Directory"
        panel.prompt = "Choose"
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.canCreateDirectories = true
        if model.mountBaseDirectoryValidationError == nil {
            panel.directoryURL = URL(
                fileURLWithPath: model.mountBaseDirectory,
                isDirectory: true
            )
        }
        guard panel.runModal() == .OK, let url = panel.url else {
            return
        }
        model.mountBaseDirectory = url.standardizedFileURL.path
    }
}
