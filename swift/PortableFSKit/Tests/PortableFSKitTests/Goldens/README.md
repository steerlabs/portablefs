These current pfslocal 2.0 fixtures are shared with `pfslocal/testdata`.
Regenerate both copies from the Go codec together:

```
UPDATE_GOLDENS=1 go -C vcs test ./internal/pfslocal
```

`hello_request.hex` and `hello_reply.hex` carry a live 2.0 pairing and a positive
request deadline. `resolve_contract.hex` carries the root, root attributes, volume identity/name
and numeric limits. Resolve binds the connection to one exact attach incarnation. Owning Items
carry nonzero stable identities; enumeration snapshots transfer no ownership.

`cache_proof.hex` carries the shared continuous-clock horizon and installed
authorization deadline in a request-ID-zero CacheProof event.
