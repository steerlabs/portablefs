import Darwin
import Foundation
import PortableFSAppCore
import ServiceManagement

/// Native tests never register a shipping or developer-app identity. This
/// executable is fixture-only and is not embedded in the product.
@main struct WorkspaceServiceTestHost {
    static func main() async {
        guard let id = Bundle.main.bundleIdentifier, id.hasPrefix("dev.portablefs.workspace-tests.") else { exit(64) }
        do {
            switch Array(CommandLine.arguments.dropFirst()) {
            case ["--workspace-service-register"]:
                let enabled = try PortableFSWorkspaceServiceRegistration.register()
                if !enabled { fputs("Allow PortableFS in Background Items\n", stderr) }; exit(enabled ? 0 : 3)
            case ["--unregister-workspace-test"]:
                try await SMAppService.agent(plistName:id + ".workspace.plist").unregister(); exit(0)
            default: exit(64)
            }
        } catch { fputs("workspace test service: \(error)\n",stderr); exit(1) }
    }
}
