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
// A trace never contains tokens, credentials, raw authentication material,
// capabilities, file contents, pointers or secret-bearing URLs. Every string is
// an enumerated category or a short opaque Label. Mount, session and
// superblock identities are run-local labels; producers that must agree on a
// label derive it with OpaqueLabel from a non-secret identity. The only raw
// filesystem bytes are one name per event, as lowercase hex in name_hex, and a
// producer emits it only for the authorized synthetic corpus. Item and parent
// fields carry stable local incarnation numbers, never authority tokens.
//
// The grammar makes free text and paths unrepresentable. It cannot recognize a
// secret deliberately encoded as a label or an integer; that remains a
// producer obligation.
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
// seq starts at 1 and strictly increases; an event dropped by the producer may
// leave a gap. t_ns is nanoseconds on the producer's own monotonic clock since
// stream start, and the header's clock label names that domain. Timestamps
// from different streams are never subtracted: cross-host intervals are not
// observable, and durations (dur_ns, proof_age_ns) are measured inside one
// process. The trailer reports how many events the producer wrote and how
// many it lost (queue overflow, byte budget, invalid event, sink failure). A
// stream without a trailer is incomplete.
//
// # Correlation
//
// Callback and operation identities are qualified by conn, the daemon's
// never-reused frontend connection incarnation; pfslocal request and operation
// IDs are unique only within it. The report joins a frontend local/send to a
// daemon local/enqueue by (conn, request), and a client (daemon or Linux)
// authority/send to an authority authority/receive by (session, authority
// request). Both layers of a join must emit identical identities.
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
