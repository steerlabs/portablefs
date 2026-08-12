import AppKit
import SwiftUI

struct SettingsView: View {
    let model: AppModel

    var body: some View {
        Form {
            Section("Mount Runtime") {
                Text("launchd supervises the signed per-user PortableFS daemon. The bundled portablefs CLI owns mount lifecycle state; this app presents that state and drives unmount and reconciliation.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                LabeledContent("PortableFS", value: model.cliVersion ?? "—")
            }

            Section("Mounting") {
                // Naming the exact credential shape is the honest answer to
                // "why is there no Mount button": a v3 session is admitted by
                // direct credentials, and this app holds none of them.
                Text("A volume mounts with direct authority credentials — an authority address, a single-use volume capability, and a mutual-TLS client identity. PortableFS.app never mints or stores those, so mounting happens from Terminal.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                HStack {
                    Text("portablefs mount <volume> <directory>")
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                    Spacer()
                    Button("Copy") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(
                            "portablefs mount <volume> <directory>",
                            forType: .string
                        )
                    }
                }
                Text("Run `portablefs help mount` for the full credential flags.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("File System Extension") {
                Text("macOS requires the PortableFS file system extension to be enabled once before any mount can succeed.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                Button("Open Setup Assistant…") {
                    FirstRunAssistant.shared.present()
                }
            }
        }
        .formStyle(.grouped)
        .frame(width: 520)
        .fixedSize(horizontal: false, vertical: true)
    }
}
