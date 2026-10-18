// Package lantrace defines the bounded, correlated diagnostic trace that
// attributes PortableFS LAN workload time (protocol 8 design §9.3 and its
// round-2 amendment), and the collector, report and reconciliation built on
// it. It depends only on the standard library so every producer can import it.
//
// # Status
//
// The trace is an explicit opt-in diagnostic for authorized qualification
// runs, collected alongside the products' low-cardinality counters. It is not
// a production correctness log and no filesystem decision may depend on it.
// Producer owners decide how a diagnostic run enables it; this package defines
// no switch, flag or environment variable.
//
// # Content rule
//
// The content rule is a producer obligation: a trace never contains tokens,
// credentials, raw authentication material, capabilities, file contents,
// pointers, secret-bearing URLs or arbitrary user paths. Mount, session,
// connection-namespace and superblock identities are run-local labels that
// producers derive with OpaqueLabel from a non-secret identity. name_hex
// carries one raw directory-entry name per event, and a producer emits it only
// for the authorized synthetic corpus. Item and parent fields carry stable
// local incarnation numbers, never authority tokens.
//
// The grammar bounds what can be written, not where it came from. It admits
// only allowlisted keys, enumerated categories, labels of at most 64
// characters from [A-Za-z0-9._:-] that start with a letter, bounded integers,
// and name_hex of 1 to 255 decoded bytes. That rules out free-text fields and
// long or multi-component strings in labels, but it cannot tell a synthetic
// name from a real one (name_hex accepts any bytes, including a slash) or
// recognize a secret encoded as a label or an integer. Each producer's
// integration must enforce the content rule at its emission sites.
//
// # Stream grammar
//
// Schema "pfs-lan-trace-1". A producer stream is JSON Lines, one object per
// line, each at most MaxLineBytes including the newline:
//
//	{"record":"header","schema":"pfs-lan-trace-1","run":R,"layer":L,"process":P,"clock":C}
//	{"record":"event","seq":N,"t_ns":T,"kind":K, ...Event fields...}
//	{"record":"trailer","emitted":E,"lost":X}
//
// Keys are exact and case-sensitive, drawn from a fixed allowlist, and never
// repeated. Values are strings, non-negative integers or booleans; null,
// arrays and nested objects are rejected. An Event field other than kind is
// present only when non-zero: an explicit zero or empty value is rejected, so
// absence and zero mean the same thing. Each kind fixes its allowed layers,
// phases and required and optional fields (see the rules in schema.go).
//
// Sequence rule, for every producer: each event the producer accepts for
// recording between its header and trailer consumes the next sequence
// number, starting at 1, whether it is then written or lost (rejected by the
// grammar, over the byte budget, dropped from a full queue, or lost to a sink
// failure). The trailer's emitted plus lost therefore equals the last number
// allocated, the written numbers strictly increase within [1, emitted+lost],
// exactly emitted of them are written, and every gap is a counted loss. The
// collector records a complete stream that breaks this as inconsistent, and
// the report rejects a collection whose events break it without that flag.
// t_ns is nanoseconds on the producer's own monotonic clock since stream
// start, and the header's clock label names that domain. Timestamps
// from different streams are never subtracted: cross-host intervals are not
// observable, and durations (dur_ns, proof_age_ns) are measured inside one
// process. The trailer reports how many events the producer wrote and how
// many it lost (queue overflow, byte budget, invalid event, sink failure). A
// stream without a trailer is incomplete.
//
// # Correlation
//
// Callback and operation identities are qualified by conn, the daemon's
// frontend connection incarnation; pfslocal request and operation IDs are
// unique only within it, and conn itself is unique only within one daemon
// process. conn_ns is the run-unique namespace of conn: a label both the
// frontend and the daemon must hold identically for that connection. The
// report joins a frontend local/send to a daemon local/enqueue by
// (conn_ns, conn, request), and a client (daemon or Linux) authority/send to
// an authority authority/receive by (session, authority request). Matched
// anchors must agree on their operation (and on mount when both name one);
// disagreement is a conflict, never a match. An anchor without conn_ns makes
// the frontend/daemon join unavailable rather than exact. pfslocal 2.0 does not
// carry conn to the frontend, so until a producer can prove the shared
// namespace that join is reported unavailable.
//
// # Producers
//
// Go producers (P2 authority, P3 Linux client, P4 daemon) use Recorder: Emit
// validates, never blocks on the sink, and counts every event it cannot keep.
// The Swift frontend (P5) emits the same grammar itself under the same bounds:
// non-blocking enqueue into a fixed ring, a byte budget, a lost counter, strictly
// increasing seq, and the trailer at close.
//
// # Collection and analysis
//
// Collect validates the producer streams of one run and merges them into one
// bounded collection document; Report and Reconcile read only that document.
// Any lost, dropped, rejected, incomplete, evicted or unmatched record makes
// exact attribution invalid for the run. It never says anything about
// filesystem correctness.
package lantrace
