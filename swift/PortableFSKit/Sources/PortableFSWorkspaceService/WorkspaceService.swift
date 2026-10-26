import Darwin
import Foundation
import PortableFSAppCore
import PortableFSWorkspaceCore
import PortableFSWorkspaceVM

@main struct WorkspaceService {
    @MainActor static func main() {
        do {
            let own = Bundle.main.bundleURL.standardizedFileURL
            guard own.lastPathComponent == "PortableFSWorkspaceService.app" else { throw WorkspaceVMError("workspace service must run inside its signed bundle") }
            let root = own.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            guard let bundle = Bundle(url: root), let id = bundle.bundleIdentifier,
                  Bundle.main.bundleIdentifier == id + ".WorkspaceService" else { throw WorkspaceVMError("workspace service release identity mismatch") }
            let release = try PortableFSSignedRelease(bundle: bundle)
            _ = try PortableFSSignedRelease.codeHash(own)
            var home = URL(fileURLWithPath: try PortableFSAccountHome.resolve(), isDirectory: true)
            #if WORKSPACE_SERVICE_TESTING
            guard id.hasPrefix("dev.portablefs.workspace-tests."), let testHome = bundle.object(forInfoDictionaryKey: "PFSWorkspaceTestHome") as? String else { throw WorkspaceVMError("test-only service requires a throwaway identity") }
            home = URL(fileURLWithPath: testHome, isDirectory: true)
            #endif
            let account = home.appendingPathComponent(".local/state/portablefs", isDirectory: true)
            let directory = account.appendingPathComponent("workspace", isDirectory: true)
            var image = root.appendingPathComponent("Contents/Resources/LinuxWorkspace", isDirectory: true)
            #if WORKSPACE_SERVICE_TESTING
            guard let testImage = bundle.object(forInfoDictionaryKey: "PFSWorkspaceTestImage") as? String else { throw WorkspaceVMError("test image missing") }
            image = URL(fileURLWithPath: testImage, isDirectory: true)
            #endif
            try PortableFSProductUpdate.requireNormalAdmission(accountDirectory: account)
            let store = try WorkspaceHostState(directory: directory)
            let owner = WorkspaceProductOwner(store: store, reservationDirectory: account, hostBoot: try WorkspaceHostState.hostBootIdentity()) {
                let artifact: WorkspaceArtifact
                do {
                    guard let pin = Bundle.main.object(forInfoDictionaryKey: "PFSWorkspaceImageManifestSHA256") as? String else { throw WorkspaceVMError("missing image pin") }
                    artifact = try WorkspaceArtifact(directory: image, manifestSHA256: pin)
                } catch { throw WorkspaceVMError("Workspace image failed verification") }
                guard artifact.release.appVersion == bundle.object(forInfoDictionaryKey:"CFBundleShortVersionString") as? String else { throw WorkspaceVMError("Workspace image failed verification") }
                return try WorkspaceVMRuntime(artifact: artifact, directory: directory)
            }
            let listener = try PortableFSSignedLocalListener(directory: directory, socketName: "control.sock", release: release, frameLimit: WorkspaceHostControl.maxFrame)
            let queue = DispatchQueue(label: "dev.portablefs.workspace.host-api")
            // One bounded reader owns socket I/O away from the VZ queue. API
            // handlers only commit desired work; VM/guest operations are async.
            let slots = DispatchSemaphore(value: 8)
            let workers = DispatchQueue(label: "dev.portablefs.workspace.host-api.io", attributes: .concurrent)
            queue.async {
                while true {
                    do {
                        let connection = try listener.accept()
                        guard slots.wait(timeout:.now()) == .success else { connection.close(); continue }
                        workers.async {
                            defer { connection.close(); slots.signal() }
                            do {
                                let data=try connection.readFrame()
                                try PortableFSDStrictJSON.validate(data)
                                let object=try JSONSerialization.jsonObject(with:data) as? [String:Any]
                                let semaphore = DispatchSemaphore(value: 0)
                                let response = ResponseBox()
                                if object?["lifecycleVersion"] != nil {
                                    let request=try WorkspaceHostLifecycleRequest.decode(data)
                                    Task { @MainActor in response.value=try? WorkspaceHostControl.encode(owner.lifecycle(request));semaphore.signal() }
                                } else {
                                    let request=try WorkspaceHostControl.decodeRequest(data)
                                    Task { @MainActor in response.value = try? WorkspaceHostControl.encode(owner.handle(request)); semaphore.signal() }
                                }
                                guard semaphore.wait(timeout: .now() + 20) == .success, let value = response.value else { return }
                                try connection.writeFrame(value)
                            } catch { /* A disconnected waiter does not cancel accepted work. */ }
                        }
                    } catch PortableFSSignedServiceError.invalidIdentity { continue }
                    catch { fputs("portablefs-workspace-service: host listener failed\n", stderr); exit(1) }
                }
            }
            var signals: [DispatchSourceSignal] = []
            for number in [SIGTERM, SIGINT] {
                signal(number, SIG_IGN)
                let source = DispatchSource.makeSignalSource(signal: number, queue: .main)
                source.setEventHandler {
                    // Service termination is not a user Force Stop. Leave the
                    // execution witness unless the real owner confirms stop.
                    listener.close(); exit(0)
                }
                source.resume(); signals.append(source)
            }
            owner.launch()
            RunLoop.main.run()
            withExtendedLifetime((owner, listener, signals)) {}
        } catch { fputs("portablefs-workspace-service: \(error)\n", stderr); exit(1) }
    }
}
private final class ResponseBox: @unchecked Sendable {
    // Published across the semaphore's release/acquire edge only.
    var value: Data?
}
