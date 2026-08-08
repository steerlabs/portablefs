// Package directstoreharness is the failure-first test substrate for the
// replicated readable-store exploration.
//
// RunRandom derives its entire workload and fault schedule from a stable
// SplitMix64 seed. RunExhaustive expands the caller-supplied Phase 0 catalog
// across both sides of every persistence and message cut, short writes,
// ENOSPC, checksum failure, and all 63 directed three-replica partition
// matrices. The target sees volatile and declared-synced byte images through
// Environment; Crash always discards the former.
//
// A Recorder streams a versioned binary persistence trace while hashing those
// exact bytes. Passing nil as the trace output is the constant-I/O soak mode;
// rerunning the same seed with a writer emits the byte-identical full trace.
// The checker compares successful exact mutations and linearizable reads with
// a sequential reference register and audits quorum certificates, committed
// roots, and per-replica apply order continuously.
//
// The included Fixture exercises the harness before real replica processes
// exist. It is not a consensus implementation or a production storage engine.
package directstoreharness
