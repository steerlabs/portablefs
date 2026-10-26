import Darwin
import Foundation
import PortableFSAppCore
import PortableFSKit
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
            case ["--abandon-workspace-test-request"]:
                guard let home=Bundle.main.object(forInfoDictionaryKey:"PFSWorkspaceTestHome") as? String else { exit(64) }
                let fd=try PfsUnixSocket.connect(path:home+"/.local/state/portablefs/workspace/control.sock")
                defer { PfsUnixSocket.close(fd) }
                let request=Data("{\"version\":1,\"operation\":\"status\"}\n".utf8)
                _=request.withUnsafeBytes { Darwin.write(fd,$0.baseAddress,$0.count) }
                _=Darwin.shutdown(fd,SHUT_RD)
                try await Task.sleep(for:.milliseconds(200))
                exit(0)
            case ["--unregister-workspace-test"]:
                try await SMAppService.agent(plistName:id + ".workspace.plist").unregister(); exit(0)
            default: exit(64)
            }
        } catch { fputs("workspace test service: \(error)\n",stderr); exit(1) }
    }
}
