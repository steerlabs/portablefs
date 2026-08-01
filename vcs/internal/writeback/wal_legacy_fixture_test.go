package writeback

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// legacyStream hand-builds a PFW5 stream directory with the PRE-81e235b
// (eaa0c58-era) writer shape. Only two things differed then, and both are
// reproduced exactly here:
//
//   - control payloads were `json.Marshal(v)` with NO field caps, so a
//     DELEGATION frame could carry an authority epoch of any length the frozen
//     frame decoder accepts (payloadLen <= maxMutationPayload);
//   - there was no control reserve, so the mutation lane was free to take the
//     stream all the way to BudgetBytes with nothing held back for close-out.
//
// Everything else — encodeSegmentHeader, encodeFrame, frameLen, digestNext and
// the segment/frame size constants — is byte-identical between eaa0c58 and
// HEAD (verified with `git diff eaa0c58 HEAD -- vcs/internal/writeback/wal.go`),
// so these fixtures are exactly what the old encoder would have produced.
type legacyStream struct {
	t   *testing.T
	dir string

	mountID  [16]byte
	volumeID string
	branch   string
	walEpoch uint64

	// segmentTarget is the builder's own rotation threshold, kept independent
	// of the package variable so a fixture never depends on live-writer tuning.
	segmentTarget int64

	f       *os.File
	path    string
	ordinal uint64
	size    int64
	sealed  int64 // bytes in already-rotated segments
	frameNo uint64
	seq     uint64
	digest  [32]byte

	live map[string]string
}

func newLegacyStream(t *testing.T, stateDir string, mountID [16]byte, volumeID, branch string, walEpoch uint64) *legacyStream {
	t.Helper()
	dir := filepath.Join(stateDir, streamDirName(walEpoch))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("legacy fixture mkdir: %v", err)
	}
	s := &legacyStream{
		t: t, dir: dir, mountID: mountID, volumeID: volumeID, branch: branch,
		walEpoch: walEpoch, segmentTarget: 64 << 10,
		digest: digestZero(), live: map[string]string{},
	}
	s.openSegment(1, 1, 1)
	t.Cleanup(func() {
		if s.f != nil {
			_ = s.f.Close()
		}
	})
	return s
}

func (s *legacyStream) openSegment(ordinal, firstFrame, firstSeq uint64) {
	s.t.Helper()
	if s.f != nil {
		if err := s.f.Sync(); err != nil {
			s.t.Fatalf("legacy fixture sync segment %d: %v", s.ordinal, err)
		}
		if err := s.f.Close(); err != nil {
			s.t.Fatalf("legacy fixture close segment %d: %v", s.ordinal, err)
		}
		s.sealed += s.size
	}
	buf, err := encodeSegmentHeader(segmentHeader{
		MountID: s.mountID, VolumeID: s.volumeID, Branch: s.branch,
		WALEpoch: s.walEpoch, Ordinal: ordinal,
		FirstFrame: firstFrame, FirstSeq: firstSeq,
	})
	if err != nil {
		s.t.Fatalf("legacy fixture segment header: %v", err)
	}
	path := segmentPath(s.dir, ordinal)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		s.t.Fatalf("legacy fixture create segment %d: %v", ordinal, err)
	}
	if _, err := f.Write(buf); err != nil {
		s.t.Fatalf("legacy fixture write segment header %d: %v", ordinal, err)
	}
	s.f, s.path, s.ordinal, s.size = f, path, ordinal, segmentHeaderSize
	s.frameNo = firstFrame - 1
}

// rotate reproduces the old rotation: a fresh segment whose live delegation
// set is re-emitted before the segment may carry anything else.
func (s *legacyStream) rotate() {
	s.t.Helper()
	s.openSegment(s.ordinal+1, s.frameNo+1, s.seq+1)
	scopes := make([]string, 0, len(s.live))
	for scope := range s.live {
		scopes = append(scopes, scope)
	}
	sort.Strings(scopes)
	for _, scope := range scopes {
		s.writeFrame(frameDelegation, 0, s.legacyPayload(delegationFrame{Scope: scope, Epoch: s.live[scope]}))
	}
}

// legacyPayload is the eaa0c58 control encoder verbatim: encoding/json with no
// field caps in front of it.
func (s *legacyStream) legacyPayload(v any) []byte {
	s.t.Helper()
	payload, err := json.Marshal(v)
	if err != nil {
		s.t.Fatalf("legacy fixture marshal control payload: %v", err)
	}
	if len(payload) > maxMutationPayload {
		s.t.Fatalf("legacy fixture control payload of %d bytes is not decodable under the frozen PFW5 bound %d",
			len(payload), maxMutationPayload)
	}
	return payload
}

func (s *legacyStream) writeFrame(typ frameType, seq uint64, payload []byte) {
	s.t.Helper()
	body := encodeFrame(nil, typ, s.frameNo+1, seq, payload)
	if _, err := s.f.WriteAt(body, s.size); err != nil {
		s.t.Fatalf("legacy fixture write frame: %v", err)
	}
	s.frameNo++
	s.size += int64(len(body))
}

// delegation installs a grant. epoch may be any length the frozen decoder
// accepts — that is the whole point of the fixture.
func (s *legacyStream) delegation(scope, epoch string) {
	s.t.Helper()
	s.writeFrame(frameDelegation, 0, s.legacyPayload(delegationFrame{Scope: scope, Epoch: epoch}))
	s.live[scope] = epoch
}

// footprint is the fixture's current on-disk WAL footprint.
func (s *legacyStream) footprint() int64 { return s.sealed + s.size }

func (s *legacyStream) mutation(rec wal.Record) {
	s.t.Helper()
	payload, err := wal.EncodePFR1(&rec)
	if err != nil {
		s.t.Fatalf("legacy fixture encode record: %v", err)
	}
	if s.size >= s.segmentTarget {
		s.rotate()
	}
	s.seq++
	s.digest = digestNext(s.digest, s.seq, payload)
	s.writeFrame(frameMutation, s.seq, payload)
}

// mutationCost is the exact footprint the next mutation of payloadLen bytes
// adds, the pending re-emitting rotation included.
func (s *legacyStream) mutationCost(payloadLen int) int64 {
	cost := frameLen(payloadLen)
	if s.size >= s.segmentTarget {
		cost += segmentHeaderSize
		for scope, epoch := range s.live {
			cost += frameLen(len(s.legacyPayload(delegationFrame{Scope: scope, Epoch: epoch})))
		}
	}
	return cost
}

// fillToCap drives the fixture to the last byte its cap will give it: coarse
// records first, then the smallest record shape, which is how a pre-upgrade
// mutation lane could leave a stream with NO headroom for close-out.
func (s *legacyStream) fillToCap(budget int64, coarse int) {
	s.t.Helper()
	written := 0
	for size := coarse; size >= 1; {
		rec := wal.Record{
			Op:   wal.OpWrite,
			Path: fmt.Sprintf("s%d/f%06d", written%4, written),
			Data: make([]byte, size),
		}
		payload, err := wal.EncodePFR1(&rec)
		if err != nil {
			s.t.Fatalf("legacy fixture encode fill record: %v", err)
		}
		if s.footprint()+s.mutationCost(len(payload)) > budget {
			size /= 2
			continue
		}
		s.mutation(rec)
		written++
	}
}

// applied appends the durable APPLIED checkpoint that authorizes reclaiming
// every segment below `through` (barrier A of the recovery close-out).
func (s *legacyStream) applied(through uint64, digest [32]byte) {
	s.t.Helper()
	s.writeFrame(frameApplied, 0, s.legacyPayload(appliedFrame{
		Through: through, Digest: fmt.Sprintf("%x", digest),
	}))
}

// reclaimSegmentPrefix deletes every segment but the last, ascending: the exact
// on-disk state barrier B of the recovery close-out leaves behind, and the state
// a crash between the reclaim and the RELEASE frames must still recover from.
func reclaimSegmentPrefix(t *testing.T, dir string) {
	t.Helper()
	names := streamSegmentNames(t, dir)
	removed := map[string]bool{}
	for _, name := range names[:len(names)-1] {
		removed[filepath.Base(name)] = true
	}
	reclaimSegmentSubset(t, dir, removed)
}

// streamSegmentNames lists a stream's segment files in ordinal order. Ordinals
// are zero-padded in the filename, so lexical order is ordinal order.
func streamSegmentNames(t *testing.T, dir string) []string {
	t.Helper()
	names, err := filepath.Glob(filepath.Join(dir, "wb-*.pfw"))
	if err != nil {
		t.Fatalf("glob segments: %v", err)
	}
	sort.Strings(names)
	return names
}

// reclaimSegmentSubset materializes an ARBITRARY persisted-unlink subset: the
// on-disk state a crash leaves when the reclaim ISSUED a set of unlinks but the
// filesystem persisted only `removed` of them. Persistence order is not syscall
// order, so the reachable subsets are decided by where the reclaim put its
// directory barriers, not by the order it called Remove in. reclaimSegmentPrefix
// is the special case where every unlink but the last segment's persisted.
func reclaimSegmentSubset(t *testing.T, dir string, removed map[string]bool) {
	t.Helper()
	for _, name := range streamSegmentNames(t, dir) {
		if !removed[filepath.Base(name)] {
			continue
		}
		if err := os.Remove(name); err != nil {
			t.Fatalf("reclaim %s: %v", filepath.Base(name), err)
		}
	}
	if err := fsyncDir(dir); err != nil {
		t.Fatalf("sync stream dir after reclaim: %v", err)
	}
}

// finish syncs the fixture and asserts it is valid under the frozen PFW5
// decoder — the precondition of the legacy-stream recovery contract.
func (s *legacyStream) finish() *streamScan {
	s.t.Helper()
	if err := s.f.Sync(); err != nil {
		s.t.Fatalf("legacy fixture sync: %v", err)
	}
	if err := s.f.Close(); err != nil {
		s.t.Fatalf("legacy fixture close: %v", err)
	}
	s.f = nil
	if err := fsyncDir(s.dir); err != nil {
		s.t.Fatalf("legacy fixture sync dir: %v", err)
	}
	scan, err := scanStreamReadOnly(s.dir)
	if err != nil {
		s.t.Fatalf("legacy fixture is not valid under the frozen PFW5 decoder: %v", err)
	}
	return scan
}

// streamFootprint is the stream's on-disk WAL footprint, the quantity
// BudgetBytes bounds.
func streamFootprint(t *testing.T, dir string) int64 {
	t.Helper()
	names, err := filepath.Glob(filepath.Join(dir, "wb-*.pfw"))
	if err != nil {
		t.Fatalf("glob segments: %v", err)
	}
	var total int64
	for _, name := range names {
		info, err := os.Stat(name)
		if err != nil {
			t.Fatalf("stat segment: %v", err)
		}
		total += info.Size()
	}
	return total
}

func streamSegmentCount(t *testing.T, dir string) int {
	t.Helper()
	names, err := filepath.Glob(filepath.Join(dir, "wb-*.pfw"))
	if err != nil {
		t.Fatalf("glob segments: %v", err)
	}
	return len(names)
}
