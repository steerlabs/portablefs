These current pfslocal 2.0 fixtures are shared with `pfslocal/testdata`.
Regenerate both copies from the Go codec together:

```
UPDATE_GOLDENS=1 go -C vcs test ./internal/pfslocal
```

`hello_request.hex` and `hello_reply.hex` carry a live 2.0 pairing and a positive
request deadline. `resolve_contract.hex` carries the mandatory incarnation,
`fskit-exclusive-writer-v1` policy, and 5,000 ms liveness interval. Owning Items
carry nonzero stable identities; enumeration snapshots transfer no ownership.
