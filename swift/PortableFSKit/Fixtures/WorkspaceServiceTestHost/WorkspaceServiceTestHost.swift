import Darwin
import Foundation
import PortableFSWorkspaceCore
@testable import PortableFSAppCore
import PortableFSKit
import ServiceManagement
import AppKit
import SwiftUI

/// Native tests never register a shipping or developer-app identity. This
/// executable is fixture-only and is not embedded in the product.
@main struct WorkspaceServiceTestHost {
    @MainActor static func main() {
        let args = Array(CommandLine.arguments.dropFirst())
        if args.count == 3, args[0] == "--workspace-menu-fixture" {
            do {
                guard Bundle.main.bundleIdentifier?.hasPrefix("dev.portablefs.workspace-tests.") == true else { exit(64) }
                showMenu(status: try PortableFSWorkspaceStatus.decode(Data(contentsOf: URL(fileURLWithPath: args[1]))), consent: args[2] == "denied")
            } catch { fputs("workspace menu fixture: \(error)\n", stderr); exit(1) }
            return
        }
        Task { @MainActor in await handle() }
        RunLoop.main.run()
    }
    @MainActor private static func handle() async {
        guard let id = Bundle.main.bundleIdentifier, id.hasPrefix("dev.portablefs.workspace-tests.") else { exit(64) }
        do {
            switch Array(CommandLine.arguments.dropFirst()) {
            case ["--workspace-update-quiesce"]:
                try await Task.detached { try PortableFSDServiceCoordinator.quiesceWorkspaceForInstaller(bundle: .main) }.value
                exit(0)
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
            case ["--workspace-seed-main-job-overflow"]:
                guard Bundle.main.bundleIdentifier?.hasPrefix("dev.portablefs.workspace-tests.") == true else { exit(64) }
                let directory = try testHome().appendingPathComponent(".local/state/portablefs/workspace")
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
                guard !FileManager.default.fileExists(atPath: directory.appendingPathComponent("desired.json").path) else { exit(64) }
                var status = WorkspaceStatusReply(); status.state = "running"
                status.bootID = Data(repeating: 1, count: 16); status.hostServiceID = Data(repeating: 2, count: 16); status.guestServiceID = Data(repeating: 3, count: 16)
                var pages: [String] = []
                for index in 1...128 {
                    var mount = WorkspaceMountID(); mount.authorityID = Data(repeating: 4, count: 32); mount.volumeID = "old-clean"
                    mount.incarnation = Data(repeating: UInt8((index + 1) / 2), count: 16)
                    var job = WorkspaceMountJob(); job.mount = mount; job.requestID = UInt64(index)
                    job.operation = index % 2 == 0 ? "mount" : "provision"; job.phase = "complete"
                    var retired = WorkspaceRetiredOutcome(); retired.retirementSequence = UInt64(index); retired.job = job
                    status.retired = [retired]
                    var frame = WorkspaceEnvelope(); frame.version = 8; frame.requestID = 1; frame.statusReply = status
                    pages.append(try WorkspaceControl.encode(frame).base64EncodedString())
                }
                let raw = try JSONSerialization.data(withJSONObject: ["version": 2, "running": false, "volumes": [], "retained": pages, "current": pages[127]])
                for (name, data) in [("resources.present", Data("8\n".utf8)), ("desired.json", raw)] {
                    let file = directory.appendingPathComponent(name); try data.write(to: file, options: .atomic)
                    guard chmod(file.path, 0o600) == 0 else { exit(1) }
                }
                print("128 retired job pages across 64 mount incarnations, plus current snapshot"); exit(0)
            case ["--unregister-workspace-test"]:
                let service = SMAppService.agent(plistName: id + ".workspace.plist")
                if service.status != .notRegistered && service.status != .notFound { try await service.unregister() }
                guard service.status == .notRegistered || service.status == .notFound else { exit(1) }
                exit(0)
            case let args where args.count == 2 && args[0] == "--workspace-api":
                let client = try client()
                guard let action = PortableFSWorkspaceClient.Operation(rawValue: args[1]) else { exit(64) }
                let status = try await client.perform(action)
                print(String(decoding: try JSONEncoder().encode(status), as: UTF8.self)); exit(0)
            case let args where args.count == 3 && args[0] == "--workspace-api" && args[1] == "mount":
                let status = try await client().perform(.mount, document: Data(contentsOf: URL(fileURLWithPath: args[2])))
                print(String(decoding: try JSONEncoder().encode(status), as: UTF8.self)); exit(0)
            case let args where args.count == 3 && args[0] == "--workspace-api" && args[1] == "dismiss":
                let status = try await client().perform(.dismiss, outcomeID: args[2])
                print(String(decoding: try JSONEncoder().encode(status), as: UTF8.self)); exit(0)
            case let args where args.count == 3 && args[0] == "--workspace-api" && args[1] == "umount":
                let status = try await client().perform(.umount, volume: args[2])
                print(String(decoding: try JSONEncoder().encode(status), as: UTF8.self)); exit(0)
            case let args where args.count == 2 && args[0] == "--workspace-remove":
                guard let disposition = WorkspaceRemoval.DataDisposition(rawValue: args[1]) else { exit(64) }
                _ = try await WorkspaceRemoval.remove(data: disposition, home: testHome()); exit(0)
            case let args where args.count == 6 && args[0] == "--workspace-editor":
                guard let editor = PortableFSWorkspaceEditor(rawValue: args[1]) else { exit(64) }
                try await editor.open(volume: args[2], application: URL(fileURLWithPath: args[3]), userData: URL(fileURLWithPath: args[4]), extensions: URL(fileURLWithPath: args[5])); exit(0)
            default: exit(64)
            }
        } catch { fputs("workspace test service: \(error)\n",stderr); exit(1) }
    }
    private static func testHome() throws -> URL {
        guard let home = Bundle.main.object(forInfoDictionaryKey: "PFSWorkspaceTestHome") as? String else { throw PortableFSWorkspaceError("Test home missing") }
        return URL(fileURLWithPath: home, isDirectory: true)
    }
    private static func client() throws -> PortableFSWorkspaceClient { PortableFSWorkspaceClient(home: try testHome()) }
    @MainActor private static func showMenu(status: PortableFSWorkspaceStatus, consent: Bool) {
        let app = NSApplication.shared
        app.setActivationPolicy(.regular)
        app.finishLaunching()
        let model = PortableFSWorkspaceModel(snapshot: status, consentMissing: consent)
        let window = NSWindow(contentRect: NSRect(x: 200, y: 400, width: 330, height: 110), styleMask: [.titled, .closable], backing: .buffered, defer: false)
        window.title = "PortableFS Workspace Menu Test"
        window.contentView = NSHostingView(rootView: VStack(alignment: .leading, spacing: 16) {
            Text("PortableFS").font(.headline)
            PortableFSWorkspaceMenu(model: model)
        }.padding(20).frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading))
        window.center(); window.makeKeyAndOrderFront(nil); app.activate()
        app.run()
        withExtendedLifetime((model, window)) {}
    }
}
