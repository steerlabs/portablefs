These `.hex` fixtures are copied from the Go daemon tree at the repository
root:

`pfslocal/testdata/*.hex`

Keep the `.hex` files byte-identical to the Go fixtures. The Swift tests decode
them with SwiftProtobuf and re-encode the same logical envelopes to catch
cross-language pfslocal wire drift.

`v7_resolve_contract.hex` is also compared against the real Go coherence
bridge's emitted Resolve contract. Swift decodes it and runs the shipping
contract parser, so independent fixtures cannot hide a nested-major mismatch.
