import Foundation
import Testing
@testable import PortableFSKit
import PortableFSKitMockDaemon
import FSKit

private func enumerationBytes(_ string: String) -> Data {
    Data(string.utf8)
}

@Test func syntheticDotEntriesArePlannedWhenAttributesAreNotRequested() throws {
    let entries = try PfsEnumerationCookies.syntheticEntries(
        for: FSDirectoryCookie.initial.rawValue,
        attributesRequested: false
    )
    #expect(entries.map { String(data: $0.name, encoding: .utf8) } == [".", ".."])
    #expect(entries[0].nextCookie == PfsEnumerationCookies.dotDotCookie)
    #expect(entries[1].nextCookie == PfsEnumerationCookies.entriesStartCookie)
    #expect(try PfsEnumerationCookies.daemonCookie(for: PfsEnumerationCookies.entriesStartCookie, attributesRequested: false) == 0)
    let daemonCookie = PfsEnumerationCookies.daemonCookieMarker | 60
    #expect(try PfsEnumerationCookies.daemonCookie(for: daemonCookie, attributesRequested: false) == daemonCookie)
    #expect(try PfsEnumerationCookies.fskitCookie(for: daemonCookie, attributesRequested: false) == daemonCookie)
    #expect(try PfsEnumerationCookies.fskitCookie(for: 0, attributesRequested: false) == PfsEnumerationCookies.terminalCookie)
    #expect(PfsEnumerationCookies.isTerminal(PfsEnumerationCookies.terminalCookie))
    #expect(PfsEnumerationCookies.isDaemonCookie(daemonCookie))
    #expect(try PfsEnumerationCookies.syntheticEntries(for: 123, attributesRequested: true).isEmpty)
}

@Test func initialDirectoryVerifierIsAlwaysAcceptedByAdapterPolicy() throws {
    #expect(FSDirectoryVerifier.initial.rawValue == 0)
    #expect(try PfsEnumerationCookies.daemonCookie(for: FSDirectoryCookie.initial.rawValue, attributesRequested: true) == 0)
    #expect(try PfsEnumerationCookies.daemonCookie(for: FSDirectoryCookie.initial.rawValue, attributesRequested: false) == 0)
    let daemonCookie = PfsEnumerationCookies.daemonCookieMarker | 60
    #expect(try PfsEnumerationCookies.fskitCookie(for: daemonCookie, attributesRequested: true) == daemonCookie)
}

@Test func coreEnumerationUsesPerEntryCookiesAndBatchesMidPageResume() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()

    for index in 0..<1000 {
        let name = String(format: "file-%04d", index)
        let created = try await core.createFile(in: root, name: enumerationBytes(name), mode: 0o644)
        try await core.close(item: created.item, retainingModes: .unspecified)
    }

    await daemon.resetStats()
    let firstPage = try await core.enumerate(
        directory: root,
        startingAt: 0,
        wantAttributes: true,
        maxEntries: PfsEnumerationCookies.daemonPageSize
    )
    #expect(firstPage.entries.count == 256)
    // Per-entry cookies are opaque daemon resumption points, not positions: all
    // that is contractual is that they live in the daemon's high-bit namespace,
    // advance strictly with the enumeration, and that the page's next cookie is
    // the last entry's.
    #expect(firstPage.entries.allSatisfy { PfsEnumerationCookies.isDaemonCookie($0.nextCookie) })
    #expect(zip(firstPage.entries, firstPage.entries.dropFirst()).allSatisfy { $0.nextCookie < $1.nextCookie })
    #expect(firstPage.nextCookie == firstPage.entries[255].nextCookie)

    var names = Set(firstPage.entries.prefix(128).compactMap { String(data: $0.name, encoding: .utf8) })
    var cookie = firstPage.entries[127].nextCookie
    while cookie != 0 {
        let page = try await core.enumerate(
            directory: root,
            startingAt: cookie,
            wantAttributes: true,
            maxEntries: PfsEnumerationCookies.daemonPageSize
        )
        for entry in page.entries {
            if let name = String(data: entry.name, encoding: .utf8) {
                names.insert(name)
            }
        }
        cookie = page.nextCookie
    }

    let stats = await daemon.stats()
    let allowedRPCs = ((1000 + Int(PfsEnumerationCookies.daemonPageSize) - 1) / Int(PfsEnumerationCookies.daemonPageSize)) + 1
    #expect(names.count == 1000)
    #expect(stats.enumerateRequests <= allowedRPCs)
    #expect(stats.enumerateRequests == 5)
}
