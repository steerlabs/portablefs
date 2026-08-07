These `.hex` fixtures are copied from the Go daemon tree at the repository
root:

`pfslocal/testdata/*.hex`

Keep the `.hex` files byte-identical to the Go fixtures. The Swift tests decode
them with SwiftProtobuf and re-encode the same logical envelopes to catch
cross-language pfslocal wire drift.

`source_phase_queueable.hex` pins protocol-minor-11 Envelope field 5 on an
ordered Write request, including its required nonzero operation identity.
