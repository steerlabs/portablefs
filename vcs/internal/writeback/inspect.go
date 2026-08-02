package writeback

// Read-only inspection of an abandoned stream, for callers that must decide
// whether its bytes are garbage.
//
// ── WHY THE RECOVERY REGISTRY IS NOT THE ANSWER ──────────────────────────────
//
// job.json's counters are maintained by DIFFERENT writers at different points
// of a stream's life, and only some of them account for the whole tail:
//
//   - AdmittedThrough is a SNAPSHOT of the WAL tail taken when a stream enters
//     a recovery or park lifecycle (recovery start, force-park). The live
//     engine never advances it, so an ACTIVE stream's AdmittedThrough sits at
//     the zero it was created with while AppliedThrough climbs. appliedThrough
//     legitimately exceeds admittedThrough, and their difference is not a
//     quantity of anything.
//   - PendingRecords/PendingBytes are refreshed by Engine.noteApplied, which
//     runs when the authority APPLIES something. Appending does not touch
//     them. So an active stream that appended records and then died reports
//     the pending count from its last APPLY — which can be zero over a tail
//     that is not empty.
//
// A garbage collector that believed either shape would delete a user's
// unshipped writes. What cannot lie is a COUNT of the mutation frames the
// stream still retains past its applied watermark — things that exist, in one
// file set, tallied the same way forceParkStream tallies them.
//
// The applied watermark itself is max(the stream's own highest APPLIED
// certificate, the registry's appliedThrough), exactly as analyzeAbandonedStream
// derives it. Both inputs are MONOTONE — a certificate is written only after
// the authority applied through it, and appliedThrough only advances on apply —
// so a stale copy of either can only understate the watermark and overstate the
// tail. That is the safe direction: a garbage collector may keep bytes it did
// not have to, and may never delete bytes it should have kept. The certificate
// alone is not enough because it is written only when a checkpoint actually
// reclaims a segment (streamWAL.CheckpointAndReclaim), so a small stream that
// drained completely carries none at all.

import (
	"fmt"
	"os"
	"path/filepath"
)

// StreamTail is what one stream directory PROVABLY still holds, measured from
// the stream's own segments rather than from its recovery registry.
type StreamTail struct {
	// Segments/SegmentBytes describe the retained segment files. Segment bytes
	// are NOT a measure of unshipped data: an applied prefix that has not been
	// reclaimed yet still occupies them.
	Segments     int
	SegmentBytes uint64
	// Records/Bytes are the mutation frames retained past the stream's applied
	// watermark, and their payload bytes. Zero means the stream is drained:
	// every record it still holds has been applied at the authority.
	Records uint64
	Bytes   uint64
	// AppliedThrough is the watermark Records/Bytes were measured against.
	AppliedThrough uint64
	// CleanlyClosed reports a terminal CLOSE frame — the stream was shut down
	// with nothing outstanding.
	CleanlyClosed bool
}

// InspectStreamTail measures one stream directory without changing a byte of
// it: no torn-tail repair, no registry write, no lock. An error means the
// stream could not be proven drained (damaged framing, an applied certificate
// that does not reconcile, a registry claiming an applied watermark past the
// local WAL tail) and the caller must preserve it — "unreadable" is never
// "empty".
func InspectStreamTail(dir string) (StreamTail, error) {
	var out StreamTail
	names, err := filepath.Glob(filepath.Join(dir, "wb-*.pfw"))
	if err != nil {
		return out, err
	}
	out.Segments = len(names)
	for _, name := range names {
		info, err := os.Stat(name)
		if err != nil {
			return out, err
		}
		if size := info.Size(); size > 0 {
			out.SegmentBytes += uint64(size)
		}
	}
	if out.Segments == 0 {
		// Nothing is retained, so nothing is unshipped. This is the shape a
		// stream reaches when every segment has been applied and reclaimed.
		out.CleanlyClosed = true
		return out, nil
	}
	scan, err := scanStreamReadOnly(dir)
	if err != nil {
		return out, err
	}
	_, mutations, marks, closed, err := decodeStreamFrames(scan.frames)
	if err != nil {
		return out, err
	}
	out.CleanlyClosed = closed
	cert, err := highestAppliedCertificate(marks, scan.lastSeq)
	if err != nil {
		return out, err
	}
	applied := cert.global
	if job, ok := loadJob(dir); ok {
		if job.AppliedThrough > scan.lastSeq {
			// The same refusal validateJobIdentity makes: a registry that
			// claims more applied than the WAL ever held is not a watermark
			// this may be measured against.
			return out, fmt.Errorf("%w: recovery registry applied watermark %d exceeds the local WAL tail %d",
				ErrCorrupt, job.AppliedThrough, scan.lastSeq)
		}
		applied = max(applied, job.AppliedThrough)
	}
	out.AppliedThrough = applied
	for _, fr := range mutations {
		if fr.seq > applied {
			out.Records++
			out.Bytes += uint64(len(fr.payload))
		}
	}
	return out, nil
}
