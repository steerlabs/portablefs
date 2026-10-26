import Darwin
import Foundation
import Testing
@testable import PortableFSAppCore

private func uxHome() throws -> URL {
    let home = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent("pfs-ux-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    return home
}
private let uxStanza = Data("""
Host portablefs-workspace
  HostName portablefs-workspace
  User workspace
  ProxyCommand /usr/bin/nc -U /tmp/portablefs-test-only.sock
  IdentitiesOnly yes
  IdentityAgent none
  ForwardAgent no
  ClearAllForwardings yes
Host *

""".utf8)
private func uxSSH(_ config: URL, host: String) throws -> String {
    let process = Process(), output = Pipe(), error = Pipe()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh"); process.arguments = ["-G", "-F", config.path, host]
    process.standardInput = FileHandle.nullDevice; process.standardOutput = output; process.standardError = error
    try process.run()
    let data = output.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
    guard process.terminationStatus == 0 else { throw PortableFSWorkspaceError(String(decoding: error.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)) }
    return String(decoding: data, as: UTF8.self)
}
private func uxConfig(_ original: Data?, home: URL) throws -> URL {
    let ssh = home.appendingPathComponent(".ssh")
    try FileManager.default.createDirectory(at: ssh, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    let config = ssh.appendingPathComponent("config")
    if let original { try original.write(to: config); chmod(config.path, 0o600) }
    return config
}

@Suite struct WorkspaceSSHConfigurationTests {
    @Test func preservesOriginalBytesEffectiveOptionsAndScope() throws {
        for original in ["", "Host *\n  User other\n  ForwardAgent yes\n", "Host peer\r\n  Port 2222\r\nHost *\r\n  ServerAliveInterval 17\r\n", "Host peer\n  User peer", "Match host peer\n  User matched\nHost *\n  User default\n", "Include extras.conf\nHost *\n User fallback\n"] {
            let home = try uxHome(); defer { try? FileManager.default.removeItem(at: home) }
            let config = try uxConfig(Data(original.utf8), home: home)
            let extra = home.appendingPathComponent(".ssh/extras.conf")
            try Data("Host peer\n  HostName peer.example\n  User included\nHost *\n".utf8).write(to: extra)
            // OpenSSH expands ~ from passwd, independently of HOME. Test copies
            // replace only that path, never reading/writing the real ~/.ssh.
            let expandedBefore = original.replacingOccurrences(of: "extras.conf", with: extra.path)
            let probe = home.appendingPathComponent("probe")
            try Data(expandedBefore.utf8).write(to: probe)
            let before = try uxSSH(probe, host: "peer")
            try PortableFSWorkspaceSSH.install(home: home, stanza: uxStanza)
            let first = try Data(contentsOf: config)
            #expect(first.suffix(original.utf8.count) == Data(original.utf8))
            try PortableFSWorkspaceSSH.install(home: home, stanza: uxStanza)
            #expect(try Data(contentsOf: config) == first)
            let generated = String(decoding: first, as: UTF8.self)
                .replacingOccurrences(of: "~/.ssh/portablefs-workspace.conf", with: home.appendingPathComponent(".ssh/portablefs-workspace.conf").path)
                .replacingOccurrences(of: "extras.conf", with: extra.path)
            try Data(generated.utf8).write(to: probe)
            #expect(try uxSSH(probe, host: "peer") == before)
            let workspace = try uxSSH(probe, host: "portablefs-workspace")
            #expect(workspace.contains("user workspace\n")); #expect(workspace.contains("forwardagent no\n"))
            #expect(workspace.contains("identityagent none\n")); #expect(workspace.contains("clearallforwardings yes\n"))
            try PortableFSWorkspaceSSH.remove(home: home)
            #expect(try Data(contentsOf: config) == Data(original.utf8))
            #expect(try Data(contentsOf: extra) == Data("Host peer\n  HostName peer.example\n  User included\nHost *\n".utf8))
            try PortableFSWorkspaceSSH.remove(home: home)
        }
    }
    @Test func freshHomeCreatesAndRemovesOnlyOwnedFiles() throws {
        let home = try uxHome(); defer { try? FileManager.default.removeItem(at: home) }
        try PortableFSWorkspaceSSH.install(home: home, stanza: uxStanza)
        let ssh = home.appendingPathComponent(".ssh")
        #expect((try FileManager.default.attributesOfItem(atPath: ssh.appendingPathComponent("config").path)[.posixPermissions] as? NSNumber)?.intValue == 0o600)
        try Data("keep".utf8).write(to: ssh.appendingPathComponent("unrelated.conf"))
        try PortableFSWorkspaceSSH.remove(home: home)
        #expect(!FileManager.default.fileExists(atPath: ssh.appendingPathComponent("config").path))
        #expect(try String(contentsOf: ssh.appendingPathComponent("unrelated.conf"), encoding: .utf8) == "keep")
    }
    @Test func conflictingAliasesRefuseWithoutMutation() throws {
        for original in ["Host portablefs-workspace\n User someone\n", "Host=\"PORTABLEFS-WORKSPACE\"\n", "Match host portablefs-workspace\n User other\n", "Include conflicting.conf\n", "Host portablefs-*\n User other\n"] {
            let home = try uxHome(); defer { try? FileManager.default.removeItem(at: home) }
            let config = try uxConfig(Data(original.utf8), home: home)
            try Data("Host portablefs-workspace\n".utf8).write(to: home.appendingPathComponent(".ssh/conflicting.conf"))
            #expect(throws: PortableFSWorkspaceError("SSH name already in use")) { try PortableFSWorkspaceSSH.install(home: home, stanza: uxStanza) }
            #expect(try Data(contentsOf: config) == Data(original.utf8))
            #expect(!FileManager.default.fileExists(atPath: home.appendingPathComponent(".ssh/portablefs-workspace.conf").path))
        }
    }
    @Test func symlinkTargetIsAtomicallyEditedAndRestoredWithoutReplacingLink() throws {
        let home = try uxHome(); defer { try? FileManager.default.removeItem(at: home) }
        let config = try uxConfig(nil, home: home), target = home.appendingPathComponent("shared-config")
        let original = Data("Host peer\r\n User example".utf8)
        try original.write(to: target); chmod(target.path, 0o600)
        try FileManager.default.createSymbolicLink(at: config, withDestinationURL: target)
        try PortableFSWorkspaceSSH.install(home: home, stanza: uxStanza)
        #expect(try FileManager.default.destinationOfSymbolicLink(atPath: config.path) == target.path)
        try PortableFSWorkspaceSSH.remove(home: home)
        #expect(try Data(contentsOf: target) == original)
        #expect(try FileManager.default.destinationOfSymbolicLink(atPath: config.path) == target.path)
    }
    @Test func readonlyConfigAndUnownedIncludeRefuse() throws {
        let home = try uxHome(); defer { try? FileManager.default.removeItem(at: home) }
        let original = Data("Host peer\n".utf8), config = try uxConfig(original, home: home)
        chmod(config.path, 0o400)
        #expect(throws: (any Error).self) { try PortableFSWorkspaceSSH.install(home: home, stanza: uxStanza) }
        #expect(try Data(contentsOf: config) == original)
        chmod(config.path, 0o600)
        try uxStanza.write(to: home.appendingPathComponent(".ssh/portablefs-workspace.conf"))
        #expect(throws: (any Error).self) { try PortableFSWorkspaceSSH.install(home: home, stanza: uxStanza) }
    }
    @Test func uninstallPreservesUserEditsAndRefusesModifiedManagedInclude() throws {
        let home = try uxHome(); defer { try? FileManager.default.removeItem(at: home) }
        let config = try uxConfig(Data("Host peer\n".utf8), home: home)
        try PortableFSWorkspaceSSH.install(home: home, stanza: uxStanza)
        var current = try Data(contentsOf: config); current.append(Data(" User edited\n".utf8)); try current.write(to: config)
        let include = home.appendingPathComponent(".ssh/portablefs-workspace.conf")
        try Data("user edited".utf8).write(to: include)
        #expect(throws: (any Error).self) { try PortableFSWorkspaceSSH.remove(home: home) }
        #expect(try Data(contentsOf: config) == current)
        try uxStanza.write(to: include)
        try PortableFSWorkspaceSSH.remove(home: home)
        #expect(try String(contentsOf: config, encoding: .utf8) == "Host peer\n User edited\n")
    }
    @Test func interruptedSetupFinishesOrRemovesOnlyItsOwnEdits() throws {
        for cut in [0, 1, 2] {
            let home = try uxHome(); defer { try? FileManager.default.removeItem(at: home) }
            let original = Data("Host peer\r\n User peer".utf8), config = try uxConfig(original, home: home)
            try PortableFSWorkspaceSSH.install(home: home, stanza: uxStanza)
            let receipt = home.appendingPathComponent(".ssh/.portablefs-workspace.json")
            var saved = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: receipt)) as? [String: Any])
            saved["installing"] = true; try JSONSerialization.data(withJSONObject: saved).write(to: receipt)
            if cut < 2 { try original.write(to: config) }
            if cut == 0 { try FileManager.default.removeItem(at: home.appendingPathComponent(".ssh/portablefs-workspace.conf")) }
            try PortableFSWorkspaceSSH.install(home: home, stanza: uxStanza)
            try PortableFSWorkspaceSSH.remove(home: home)
            #expect(try Data(contentsOf: config) == original)
        }
    }
    @Test func interruptedSSHRemovalCompletesAfterConfigEdit() throws {
        for includeRemoved in [false, true] {
            let home = try uxHome(); defer { try? FileManager.default.removeItem(at: home) }
            let original = Data("Host peer\n User peer".utf8), config = try uxConfig(original, home: home)
            try PortableFSWorkspaceSSH.install(home: home, stanza: uxStanza)
            let receipt = home.appendingPathComponent(".ssh/.portablefs-workspace.json")
            var saved = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: receipt)) as? [String: Any])
            saved["removing"] = true; try JSONSerialization.data(withJSONObject: saved).write(to: receipt)
            try original.write(to: config)
            if includeRemoved { try FileManager.default.removeItem(at: home.appendingPathComponent(".ssh/portablefs-workspace.conf")) }
            try PortableFSWorkspaceSSH.remove(home: home)
            #expect(try Data(contentsOf: config) == original)
            try PortableFSWorkspaceSSH.remove(home: home)
        }
    }
}

@Suite struct WorkspacePresentationTests {
    @Test func terminalDocumentExecutesOnlyTheManagedAliasAndRemovesItself() throws {
        let home = try uxHome(); defer { try? FileManager.default.removeItem(at: home) }
        let document = try PortableFSWorkspaceTerminal.commandFile(in: home)
        #expect(try String(contentsOf: document, encoding: .utf8) == "#!/bin/sh\n/bin/rm -- \"$0\"\nexec /usr/bin/ssh portablefs-workspace\n")
        #expect((try FileManager.default.attributesOfItem(atPath: document.path)[.posixPermissions] as? NSNumber)?.intValue == 0o700)
    }
    @Test func statusDoesNotStartServiceOrHideRetainedStateWhenSocketIsMissing() async throws {
        let home = try uxHome(); defer { try? FileManager.default.removeItem(at: home) }
        let client = PortableFSWorkspaceClient(home: home)
        #expect(try await client.perform(.status).state == "stopped")
        #expect(!FileManager.default.fileExists(atPath: home.appendingPathComponent(".local").path))
        let directory = home.appendingPathComponent(".local/state/portablefs/workspace")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try Data("retained state".utf8).write(to: directory.appendingPathComponent("desired.json"))
        await #expect(throws: PortableFSWorkspaceError("Cleanup required: Linux Workspace service is unavailable")) { try await client.perform(.status) }
    }
    @Test func editorURLsAndMissingExtensionAreExplicit() throws {
        for editor in PortableFSWorkspaceEditor.allCases {
            let expected = editor == .vscode ? "vscode-remote://ssh-remote+portablefs-workspace/workspaces/vol-1" : "cursor://vscode-remote/ssh-remote+portablefs-workspace/workspaces/vol-1"
            #expect(try editor.folderURL(volume: "vol-1").absoluteString == expected)
            #expect(throws: (any Error).self) { try editor.folderURL(volume: "../escape") }
            #expect(throws: (any Error).self) { try editor.requireRemoteSSH(extensions: "other.extension\n") }
            try editor.requireRemoteSSH(extensions: "ms-vscode-remote.remote-ssh\n")
        }
        try PortableFSWorkspaceEditor.cursor.requireRemoteSSH(extensions: "anysphere.remote-ssh\n")
        #expect(throws: (any Error).self) { try PortableFSWorkspaceEditor.vscode.requireRemoteSSH(extensions: "anysphere.remote-ssh") }
        #expect(PortableFSWorkspaceSSH.command == "ssh portablefs-workspace")
    }
    @Test func lossAndReopenSurviveReadyAndStoppedStates() throws {
        var value = PortableFSWorkspaceStatus(); value.someChangesWereNotSaved = true; value.previousWriteOutcomeUnknown = true
        value.volumes = [.init(volume: "vol-1", state: "ready", message: "Reconnect your editor and reopen this folder.")]
        value.state = "running"
        let decoded = try PortableFSWorkspaceStatus.decode(JSONEncoder().encode(value))
        #expect(decoded.canConnect); #expect(decoded.notices == ["Some changes were not saved", "Previous write outcome unknown"])
        #expect(decoded.volumes[0].requiresReopen); #expect(decoded.volumes[0].canOpen)
        value.state = "stopped"; #expect(!value.canConnect); #expect(value.notices == decoded.notices)
        value.volumes[0].path = "/tmp/unmounted"
        #expect(throws: (any Error).self) { try PortableFSWorkspaceStatus.decode(JSONEncoder().encode(value)) }
    }
}

@Suite @MainActor struct WorkspaceRemovalTests {
    @Test func removalIsIdempotentAndPreservesRemoteFiles() async throws {
        for data in [WorkspaceRemoval.DataDisposition.keep, .delete] {
            let home = try uxHome(); defer { try? FileManager.default.removeItem(at: home) }
            let directory = home.appendingPathComponent(".local/state/portablefs/workspace")
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            try Data("owned".utf8).write(to: directory.appendingPathComponent("data.ext4"))
            try Data().write(to: directory.appendingPathComponent("service.lock"))
            let remote = home.appendingPathComponent("remote-volume"); try Data("remote".utf8).write(to: remote)
            try PortableFSWorkspaceSSH.install(home: home, stanza: uxStanza)
            var calls: [String] = []
            var running = PortableFSWorkspaceStatus(); running.state = "running"; running.desiredRunning = true
            let actions = WorkspaceRemoval.Actions(stop: { calls.append("stop"); return .init() }, status: { running }, quiesce: { calls.append("quiesce") }, unregister: { calls.append("unregister") }, removeSSH: { calls.append("ssh"); try PortableFSWorkspaceSSH.remove(home: home) })
            _ = try await WorkspaceRemoval.run(data: data, home: home, actions: actions)
            #expect(calls == ["stop", "quiesce", "unregister", "ssh"])
            _ = try await WorkspaceRemoval.run(data: data, home: home, actions: actions)
            #expect(calls.count == 4)
            #expect(FileManager.default.fileExists(atPath: directory.path) == (data == .keep))
            #expect(try String(contentsOf: remote, encoding: .utf8) == "remote")
            #expect(try !WorkspaceRemoval.removalPending(home: home))
            try WorkspaceRemoval.prepareToStart(home: home)
        }
    }
    @Test func removalRefusesUnsafeOutcomesBeforeUnregister() async throws {
        for reason in ["busy", "cleanup-required", "lost", "unknown"] {
            let home = try uxHome(); defer { try? FileManager.default.removeItem(at: home) }
            var status = PortableFSWorkspaceStatus(); status.state = reason == "busy" ? "running" : "stopped"
            if reason == "busy" { status.volumes = [.init(volume: "vol-1", state: "busy", message: "Volume is in use. Close its terminals and editor windows, then try again.")] }
            if reason == "cleanup-required" { status.state = reason; status.message = "Cleanup required" }
            status.someChangesWereNotSaved = reason == "lost"; status.previousWriteOutcomeUnknown = reason == "unknown"
            var touched = false
            let actions = WorkspaceRemoval.Actions(stop: { status }, status: { status }, quiesce: { touched = true }, unregister: { touched = true }, removeSSH: { touched = true })
            await #expect(throws: (any Error).self) { try await WorkspaceRemoval.run(data: .delete, home: home, actions: actions) }
            #expect(!touched)
        }
    }
    @Test func interruptionAfterUnregisterResumesWithoutNeedingService() async throws {
        let home = try uxHome(); defer { try? FileManager.default.removeItem(at: home) }
        var stops = 0, unregistrations = 0
        var running = PortableFSWorkspaceStatus(); running.state = "running"; running.desiredRunning = true
        var actions = WorkspaceRemoval.Actions(stop: { stops += 1; return .init() }, status: { running }, quiesce: {}, unregister: { unregistrations += 1 }, removeSSH: { throw PortableFSWorkspaceError("injected interruption") })
        await #expect(throws: (any Error).self) { try await WorkspaceRemoval.run(data: .keep, home: home, actions: actions) }
        #expect(try WorkspaceRemoval.removalPending(home: home))
        #expect(throws: (any Error).self) { try WorkspaceRemoval.prepareToStart(home: home) }
        actions.removeSSH = {}
        _ = try await WorkspaceRemoval.run(data: .keep, home: home, actions: actions)
        #expect(stops == 1); #expect(unregistrations == 1)
    }
    @Test func interruptedQuiescenceCanRetryAlreadyStoppedServiceWithoutAnotherStop() async throws {
        let home = try uxHome(); defer { try? FileManager.default.removeItem(at: home) }
        var actions = WorkspaceRemoval.Actions(stop: { throw PortableFSWorkspaceError("quiesced service refuses new Stop") }, status: { .init() }, quiesce: { throw PortableFSWorkspaceError("interrupted before checkpoint") }, unregister: {}, removeSSH: {})
        await #expect(throws: (any Error).self) { try await WorkspaceRemoval.run(data: .keep, home: home, actions: actions) }
        actions.quiesce = {}
        _ = try await WorkspaceRemoval.run(data: .keep, home: home, actions: actions)
    }
    @Test func interruptedDeletionResumesWhenTheOldLockFileWasAlreadyDeleted() async throws {
        let home = try uxHome(); defer { try? FileManager.default.removeItem(at: home) }
        let directory = home.appendingPathComponent(".local/state/portablefs/workspace")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try Data().write(to: directory.appendingPathComponent("service.lock"))
        try Data("remaining local data".utf8).write(to: directory.appendingPathComponent("data.ext4"))
        let actions = WorkspaceRemoval.Actions(stop: { .init() }, status: { .init() }, quiesce: {}, unregister: {}, removeSSH: {})
        _ = try await WorkspaceRemoval.run(data: .keep, home: home, actions: actions)
        // Simulate interruption during deletion, after the earlier invocation
        // durably proved idle, unregistered and removed its SSH configuration.
        let journal = home.appendingPathComponent(".local/state/portablefs/workspace-removal.json")
        try Data("{\"version\":1,\"data\":\"delete\",\"phase\":\"ssh-removed\"}".utf8).write(to: journal)
        try FileManager.default.removeItem(at: directory.appendingPathComponent("service.lock"))
        _ = try await WorkspaceRemoval.run(data: .delete, home: home, actions: actions)
        #expect(!FileManager.default.fileExists(atPath: directory.path))
    }
}
