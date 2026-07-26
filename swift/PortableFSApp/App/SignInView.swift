import AppKit
import SwiftUI

/// Sign-in mirrors `portablefs login`: device flow against the server's
/// `/v1/auth/device/*` endpoints, or a pasted pre-issued token. Both paths
/// write the shared CLI config file.
struct SignInView: View {
    static let windowID = "sign-in"

    let model: AppModel
    @Environment(\.dismiss) private var dismiss

    @State private var serverURL = ""
    @State private var apiToken = ""
    @State private var managerURL = ""
    @State private var managerToken = ""
    @State private var profile = "default"
    @State private var isSaving = false
    @State private var manualResult: String?
    @State private var manualSucceeded = false

    var body: some View {
        Form {
            Section("Server") {
                TextField("Server URL", text: $serverURL, prompt: Text("https://api.portablefs.example"))
                    .textContentType(.URL)
                    .autocorrectionDisabled()
                TextField("Profile", text: $profile, prompt: Text("default"))
            }

            Section("Device Sign-In") {
                deviceFlowContent
            }

            Section("Or Paste a Token") {
                SecureField("API token", text: $apiToken)
                DisclosureGroup("Advanced (authority manager)") {
                    TextField("Manager URL (optional)", text: $managerURL, prompt: Text("defaults to server URL"))
                        .autocorrectionDisabled()
                    SecureField("Manager token (optional)", text: $managerToken)
                }
                HStack {
                    Button("Save & Verify") {
                        saveManualToken()
                    }
                    .disabled(isSaving || serverURL.isEmpty || apiToken.isEmpty)
                    if isSaving {
                        ProgressView()
                            .controlSize(.small)
                    }
                }
                if let manualResult {
                    Text(manualResult)
                        .font(.callout)
                        .foregroundStyle(manualSucceeded ? Color.green : Color.red)
                        .textSelection(.enabled)
                }
            }

            Section {
                LabeledContent("Config file", value: model.configPath)
                    .font(.caption)
            }
        }
        .formStyle(.grouped)
        .frame(width: 460)
        .fixedSize(horizontal: false, vertical: true)
        .onAppear {
            if serverURL.isEmpty {
                serverURL = model.settings.apiURL
            }
            profile = model.config.currentProfile
        }
        .onDisappear {
            model.cancelDeviceSignIn()
        }
    }

    @ViewBuilder
    private var deviceFlowContent: some View {
        switch model.deviceFlow {
        case .idle:
            Button("Start Device Sign-In") {
                model.startDeviceSignIn(
                    serverURL: serverURL,
                    managerURL: managerURL,
                    managerToken: managerToken,
                    profile: profile
                )
            }
            .disabled(serverURL.isEmpty)
        case .starting:
            HStack {
                ProgressView()
                    .controlSize(.small)
                Text("Requesting device code…")
            }
        case let .waitingForApproval(userCode, verificationURL):
            VStack(alignment: .leading, spacing: 6) {
                Text("Enter this code in your browser:")
                Text(userCode)
                    .font(.system(.title2, design: .monospaced).bold())
                    .textSelection(.enabled)
                HStack {
                    Button("Open \(verificationURL)") {
                        if let url = URL(string: verificationURL) {
                            NSWorkspace.shared.open(url)
                        }
                    }
                    Button("Cancel") {
                        model.cancelDeviceSignIn()
                    }
                }
                HStack(spacing: 6) {
                    ProgressView()
                        .controlSize(.small)
                    Text("Waiting for approval…")
                        .foregroundStyle(.secondary)
                }
            }
        case let .succeeded(profileName):
            HStack {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(.green)
                Text("Signed in (profile \"\(profileName)\").")
                Button("Done") {
                    model.resetDeviceSignIn()
                    dismiss()
                }
            }
        case let .failed(message):
            VStack(alignment: .leading, spacing: 6) {
                Text(message)
                    .foregroundStyle(.red)
                    .textSelection(.enabled)
                Button("Start Over") {
                    model.resetDeviceSignIn()
                }
            }
        }
    }

    private func saveManualToken() {
        isSaving = true
        manualResult = nil
        Task {
            let failure = await model.signIn(
                serverURL: serverURL,
                token: apiToken,
                managerURL: managerURL,
                managerToken: managerToken,
                profile: profile
            )
            isSaving = false
            if let failure {
                manualSucceeded = false
                manualResult = failure
            } else {
                manualSucceeded = true
                manualResult = "Signed in and verified."
            }
        }
    }
}
