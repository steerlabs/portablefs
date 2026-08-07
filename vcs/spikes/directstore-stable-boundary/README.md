# Direct-store stable-boundary spike

This spike tests one local replica invariant:

```text
append response or client success reply
    => Raft record -> StateCommit -> object bytes is complete and hash-valid
```

It is not a consensus implementation, storage format proposal, filesystem, or
benchmark. The JSON records exist only to make the durability dependency
inspectable.

`TestCrashAtEveryOrderingPoint` starts a helper process for every semantic
before/after cut, waits for an explicit pipe handshake, sends `SIGKILL`, and
opens the directory again. There are no sleeps or timing constants. Each stable
file operation writes a temporary file, syncs it, renames it, and syncs its
directory. Recovery ignores temporary files and accepts an installed root only
when every digest link validates.

`TestUnsafeResponseBeforeObjectSyncIsDetected` is the negative control. It
stabilizes a `StateCommit` and Raft record and emits the append response before
creating the referenced object. A kill leaves the exact shape that would lose
acknowledged data; recovery rejects it as corruption.

Run:

```bash
go -C vcs test ./spikes/directstore-stable-boundary -v
```

A process kill is weaker than a machine power cut because dirty kernel cache
may survive the child. This spike proves program order, real sync calls, and
fail-closed recovery validation. The Phase 1 fault harness must additionally
model only-declared-stable bytes and inject torn writes, directory loss,
`ENOSPC`, corruption, and sync errors on the target storage stack.

The cut list is derived from the design's `O -> S -> L -> A -> I -> P`
implication chain. File modes are owner-only to isolate test artifacts. The
SHA-256 links mirror existing PFT2/histstore content addressing rather than
selecting a new digest. The spike introduces no timeout, retry, batching, size,
or throughput parameter.
