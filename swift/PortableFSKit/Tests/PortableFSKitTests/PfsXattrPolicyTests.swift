import Foundation
import Testing
@testable import PortableFSKit

@Test func xattrPolicyMatchesAuthorityGoldens() throws {
    struct Case: Decodable { let name: String; let allowed: Bool }
    var root = URL(fileURLWithPath: #filePath)
    for _ in 0..<5 { root.deleteLastPathComponent() }
    let file = root.appendingPathComponent("vcs/internal/xfsstore/testdata/xattr-policy.json")
    let cases = try JSONDecoder().decode([Case].self, from: Data(contentsOf: file))
    for test in cases {
        // Byte diagnostics distinguish invisible marks and canonically equal names.
        #expect(PfsXattrPolicy.permits(test.name) == test.allowed, "UTF-8: \(Array(test.name.utf8))")
    }
}
