package seglog

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// admitPoll is how often a throttled writer re-checks the space budget, and
// maxAdmitWait bounds the wait so that a cleaner which cannot make progress
// degrades throughput instead of hanging the store.
const (
	admitPoll               = 200 * time.Microsecond
	maxStallWithoutProgress = 10 * time.Second
)

// Loc addresses one record inside the segmented log.
type Loc struct {
	Off int64
	Seq uint64
	Seg uint32
	Len int32
}

// Options configures a Store.
type Options struct {
	Dir string

	// SegmentBytes seals a segment once it reaches this size.
	SegmentBytes int64

	// GroupInterval and GroupBytes are the group-commit policy: a group is
	// committed once it is this old or this large, whichever comes first.
	// An explicit Barrier commits immediately.
	GroupInterval time.Duration
	GroupBytes    int

	// PersistIndex builds a Pebble index over log offsets asynchronously.
	PersistIndex bool

	// IndexOpener builds the persistent index. It is injected so that the
	// seglog package does not depend on Pebble directly.
	IndexOpener func(dir string) (Index, error)

	// CleanUtilization is the live/total ratio the cleaner maintains. Zero
	// disables cleaning.
	CleanUtilization float64

	// CleanInterval is how long the cleaner idles when there is nothing to do.
	CleanInterval time.Duration

	// SpaceHeadroom is how far past the cleaner's space budget a writer may
	// run before it is made to wait. Without admission control the log grows
	// without bound whenever the cleaner cannot keep up, and a measurement of
	// amplification during that growth is meaningless.
	SpaceHeadroom float64

	// FastRecovery loads the persistent index and scans only the log tail it
	// has not absorbed. Without it, Open rebuilds the index by scanning every
	// segment, which is the fallback that must always work.
	FastRecovery bool
}

func (o *Options) withDefaults() {
	if o.SegmentBytes <= 0 {
		o.SegmentBytes = 64 << 20
	}
	if o.GroupInterval <= 0 {
		o.GroupInterval = time.Millisecond
	}
	if o.GroupBytes <= 0 {
		o.GroupBytes = 1 << 20
	}
	if o.CleanInterval <= 0 {
		o.CleanInterval = 2 * time.Millisecond
	}
	if o.SpaceHeadroom <= 0 {
		o.SpaceHeadroom = 1.10
	}
}

// Index is the persistent, rebuildable index over log offsets.
type Index interface {
	Apply(entries []IndexEntry, head Loc) error
	Load(fn func(key []byte, loc Loc)) (head Loc, err error)
	Flush() error
	// Settle leaves no deferred flush or compaction work outstanding.
	Settle() error
	DiskBytes() (int64, error)
	Close() error
}

// IndexEntry is one persistent index mutation. Deleted marks a tombstone.
type IndexEntry struct {
	Key     string
	Loc     Loc
	Deleted bool
}

// EncodeLoc and DecodeLoc give index implementations a fixed 24-byte value.
func EncodeLoc(loc Loc) []byte {
	out := make([]byte, 24)
	binary.LittleEndian.PutUint64(out[0:], uint64(loc.Off))
	binary.LittleEndian.PutUint64(out[8:], loc.Seq)
	binary.LittleEndian.PutUint32(out[16:], loc.Seg)
	binary.LittleEndian.PutUint32(out[20:], uint32(loc.Len))
	return out
}

// DecodeLoc reverses EncodeLoc.
func DecodeLoc(buf []byte) (Loc, error) {
	if len(buf) != 24 {
		return Loc{}, fmt.Errorf("seglog: index value is %d bytes", len(buf))
	}
	return Loc{
		Off: int64(binary.LittleEndian.Uint64(buf[0:])),
		Seq: binary.LittleEndian.Uint64(buf[8:]),
		Seg: binary.LittleEndian.Uint32(buf[16:]),
		Len: int32(binary.LittleEndian.Uint32(buf[20:])),
	}, nil
}

type segment struct {
	id       uint32
	path     string
	write    *os.File
	read     *os.File
	size     int64
	live     int64
	sealed   bool
	cleaning bool
}

// Stats are cumulative counters. All byte counters are format bytes, never a
// substitute for the kernel disk-write counter.
type Stats struct {
	Groups             uint64
	Syncs              uint64
	Records            uint64
	LogicalBytes       uint64
	AppendedBytes      uint64
	TrailerBytes       uint64
	CleanCopiedBytes   uint64
	CleanRecords       uint64
	CleanPasses        uint64
	SegmentsReclaimed  uint64
	ReclaimedBytes     uint64
	LiveBytes          int64
	TotalBytes         int64
	Segments           int
	IndexKeys          int
	MaxGroupRecords    int
	AdmitWaitNanos     uint64
	AdmitOverruns      uint64
	CleanRetries       uint64
	LiveCorrections    uint64
	LiveCorrectedBytes uint64
}

// Store is the segmented append-only log with an in-memory index over log
// offsets and an optional asynchronous persistent index.
type Store struct {
	opts Options

	mu       sync.Mutex
	index    map[string]Loc
	segments map[uint32]*segment
	order    []uint32
	head     *segment
	nextSeg  uint32
	seq      uint64
	durable  uint64
	stats    Stats
	recovery RecoveryReport

	pending      [][]byte
	pendingIdx   []IndexEntry
	pendingVals  map[string][]byte
	pendingKeys  map[string]struct{}
	inflightVals map[string][]byte
	inflightKeys map[string]struct{}
	pendingBytes int
	groupStart   time.Time

	flushMu sync.Mutex

	idx       Index
	idxQueue  chan indexOp
	idxDone   chan struct{}
	idxErr    error
	syncTimes []time.Duration

	stopOnce sync.Once
	stop     chan struct{}
	wg       sync.WaitGroup
	closed   bool
}

// Open creates or reopens a store. Recovery always establishes the in-memory
// index; see Recover for a measured, explicit rebuild.
func Open(opts Options) (*Store, error) {
	opts.withDefaults()
	if err := os.MkdirAll(opts.Dir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{
		opts:        opts,
		index:       make(map[string]Loc),
		segments:    make(map[uint32]*segment),
		pendingVals: make(map[string][]byte),
		pendingKeys: make(map[string]struct{}),
		stop:        make(chan struct{}),
	}
	if err := s.loadSegments(); err != nil {
		return nil, err
	}
	var idx Index
	if opts.PersistIndex {
		if opts.IndexOpener == nil {
			return nil, errors.New("seglog: PersistIndex requires IndexOpener")
		}
		opened, err := opts.IndexOpener(filepath.Join(opts.Dir, "index"))
		if err != nil {
			return nil, err
		}
		idx = opened
	}
	started := time.Now()
	if opts.FastRecovery && idx != nil {
		s.recovery.Mode = "index+tail"
		usable, err := s.recoverFast(idx)
		if err != nil {
			return nil, err
		}
		if !usable {
			// The index references a segment the cleaner already reclaimed, so
			// it is a snapshot older than the log's own free decisions. The log
			// is always authoritative; fall back to the scan.
			s.index = make(map[string]Loc)
			s.recovery.Mode = "index-rejected-full-scan"
			scanned, err := s.rebuildFromLog()
			if err != nil {
				return nil, err
			}
			s.recovery.BytesScanned = scanned
		}
	} else {
		s.recovery.Mode = "full-scan"
		scanned, err := s.rebuildFromLog()
		if err != nil {
			return nil, err
		}
		s.recovery.BytesScanned = scanned
	}
	for _, loc := range s.index {
		if seg := s.segments[loc.Seg]; seg != nil {
			seg.live += int64(loc.Len)
		}
	}
	s.recomputeTotals()
	s.recovery.Duration = time.Since(started)
	s.recovery.Keys = len(s.index)
	s.recovery.Segments = len(s.segments)
	if err := s.openHead(); err != nil {
		return nil, err
	}
	if idx != nil {
		s.idx = idx
		s.idxQueue = make(chan indexOp, 256)
		s.idxDone = make(chan struct{})
		s.wg.Add(1)
		go s.indexLoop()
	}
	s.wg.Add(1)
	go s.timerLoop()
	if opts.CleanUtilization > 0 {
		s.wg.Add(1)
		go s.cleanLoop()
	}
	return s, nil
}

func segmentName(id uint32) string { return fmt.Sprintf("seg-%010d.log", id) }

func (s *Store) loadSegments() error {
	entries, err := os.ReadDir(s.opts.Dir)
	if err != nil {
		return err
	}
	var ids []uint32
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "seg-") || !strings.HasSuffix(name, ".log") {
			continue
		}
		id, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(name, "seg-"), ".log"), 10, 32)
		if err != nil {
			return fmt.Errorf("seglog: unexpected segment name %q", name)
		}
		ids = append(ids, uint32(id))
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		path := filepath.Join(s.opts.Dir, segmentName(id))
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		read, err := os.Open(path)
		if err != nil {
			return err
		}
		seg := &segment{id: id, path: path, read: read, size: info.Size(), sealed: true}
		s.segments[id] = seg
		s.order = append(s.order, id)
		if id >= s.nextSeg {
			s.nextSeg = id + 1
		}
	}
	return nil
}

// rebuildFromLog scans every segment forward, truncates each to its last
// complete group, and rebuilds the in-memory index. Returns bytes scanned.
func (s *Store) rebuildFromLog() (int64, error) {
	var scanned int64
	for _, id := range s.order {
		seg := s.segments[id]
		good, err := s.scanSegmentFrom(seg, 0)
		if err != nil {
			return scanned, err
		}
		scanned += seg.size
		if good < seg.size {
			if err := truncateSegment(seg, good); err != nil {
				return scanned, err
			}
		}
	}
	return scanned, nil
}

func truncateSegment(seg *segment, good int64) error {
	if err := os.Truncate(seg.path, good); err != nil {
		return err
	}
	seg.size = good
	return nil
}

// scanSegment applies every record in the segment's complete groups and
// returns the offset just past the last complete group.
func (s *Store) scanSegmentFrom(seg *segment, from int64) (int64, error) {
	data, err := os.ReadFile(seg.path)
	if err != nil {
		return 0, err
	}
	offset := from
	lastGood := from
	var staged []stagedRecord
	for offset < int64(len(data)) {
		h, key, value, err := DecodeRecord(data[offset:])
		if err != nil {
			break
		}
		total := h.Total()
		if h.Kind == KindTrailer {
			for _, rec := range staged {
				s.applyScanned(seg, rec)
			}
			staged = staged[:0]
			offset += total
			lastGood = offset
			if h.Seq > s.seq {
				s.seq = h.Seq
			}
			continue
		}
		staged = append(staged, stagedRecord{
			seq:  h.Seq,
			kind: h.Kind,
			key:  string(key),
			loc:  Loc{Off: offset, Seq: h.Seq, Seg: seg.id, Len: int32(total)},
		})
		_ = value
		offset += total
	}
	return lastGood, nil
}

type stagedRecord struct {
	seq  uint64
	kind uint8
	key  string
	loc  Loc
}

func (s *Store) applyScanned(seg *segment, rec stagedRecord) {
	if rec.seq > s.seq {
		s.seq = rec.seq
	}
	existing, ok := s.index[rec.key]
	if ok && (existing.Seq > rec.seq || (existing.Seq == rec.seq && existing.Seg > rec.loc.Seg)) {
		return
	}
	if rec.kind == KindDelete {
		delete(s.index, rec.key)
		return
	}
	s.index[rec.key] = rec.loc
}

func (s *Store) openHead() error {
	if len(s.order) > 0 {
		last := s.segments[s.order[len(s.order)-1]]
		if last.size < s.opts.SegmentBytes {
			write, err := os.OpenFile(last.path, os.O_WRONLY, 0o600)
			if err != nil {
				return err
			}
			if _, err := write.Seek(last.size, 0); err != nil {
				return err
			}
			last.write = write
			last.sealed = false
			s.head = last
			return nil
		}
	}
	return s.rollSegment()
}

func (s *Store) rollSegment() error {
	if s.head != nil {
		if err := s.head.write.Close(); err != nil {
			return err
		}
		s.head.write = nil
		s.head.sealed = true
	}
	id := s.nextSeg
	s.nextSeg++
	path := filepath.Join(s.opts.Dir, segmentName(id))
	write, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	read, err := os.Open(path)
	if err != nil {
		write.Close()
		return err
	}
	seg := &segment{id: id, path: path, write: write, read: read}
	s.segments[id] = seg
	s.order = append(s.order, id)
	s.head = seg
	return nil
}

func (s *Store) recomputeTotals() {
	var live, total int64
	for _, seg := range s.segments {
		live += seg.live
		total += seg.size
	}
	s.stats.LiveBytes = live
	s.stats.TotalBytes = total
	s.stats.Segments = len(s.segments)
	s.stats.IndexKeys = len(s.index)
}

// Put stages a mutation. It becomes durable and visible at the next group
// commit.
func (s *Store) Put(key string, value []byte) error {
	return s.stage(KindPut, key, value, 0, nil)
}

// Delete stages a tombstone.
func (s *Store) Delete(key string) error {
	return s.stage(KindDelete, key, nil, 0, nil)
}

// admit blocks a foreground writer while the log is above the cleaner's space
// budget. Cleaner relocations are never blocked: they are what restores the
// budget.
func (s *Store) admit() {
	if s.opts.CleanUtilization <= 0 {
		return
	}
	budget := s.opts.SpaceHeadroom / s.opts.CleanUtilization
	floor := 4 * s.opts.SegmentBytes
	var (
		waited       time.Duration
		lastReclaim  uint64
		lastProgress time.Time
		blocked      bool
	)
	for {
		s.mu.Lock()
		live, total, reclaimed := s.stats.LiveBytes, s.stats.TotalBytes, s.stats.ReclaimedBytes
		s.mu.Unlock()
		// Below the floor there are too few sealed segments for the cleaner to
		// have any choice, so throttling would only deadlock the writer.
		if live == 0 || total <= floor || float64(total) <= budget*float64(live) {
			break
		}
		now := time.Now()
		if !blocked {
			blocked = true
			lastReclaim = reclaimed
			lastProgress = now
		} else if reclaimed != lastReclaim {
			lastReclaim = reclaimed
			lastProgress = now
		} else if now.Sub(lastProgress) > maxStallWithoutProgress {
			// The cleaner is not reclaiming. Blocking further would hang the
			// store rather than bound it; record the overrun and let the write
			// through so the measurement shows unbounded space instead.
			s.mu.Lock()
			s.stats.AdmitOverruns++
			s.mu.Unlock()
			break
		}
		select {
		case <-s.stop:
			return
		case <-time.After(admitPoll):
		}
		waited += time.Since(now)
	}
	if waited > 0 {
		s.mu.Lock()
		s.stats.AdmitWaitNanos += uint64(waited)
		s.mu.Unlock()
	}
}

// SpacePressure reports the cleaner's current view for diagnostics.
func (s *Store) SpacePressure() (live, total int64, segments int, reclaimed uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recomputeTotals()
	return s.stats.LiveBytes, s.stats.TotalBytes, len(s.segments), s.stats.ReclaimedBytes
}

// stage appends one record to the current group. forceSeq reuses an existing
// sequence number, which the cleaner needs so that a relocated record does not
// overtake a newer mutation. expect, when non-nil, makes the append
// conditional on the index still pointing at that exact location; this is the
// cleaner's liveness check, performed under the same lock as the append.
func (s *Store) stage(kind uint8, key string, value []byte, forceSeq uint64, expect *Loc) error {
	if forceSeq == 0 {
		s.admit()
	}
	for {
		s.mu.Lock()
		if expect != nil {
			current, ok := s.index[key]
			if !ok || current != *expect {
				s.mu.Unlock()
				return nil
			}
			_, staged := s.pendingKeys[key]
			if _, inflight := s.inflightKeys[key]; staged || inflight {
				// A newer mutation for this key is already staged or in
				// flight. Relocating the old record would race it.
				s.mu.Unlock()
				return nil
			}
		}
		seq := forceSeq
		if seq == 0 {
			seq = s.seq + 1
		}
		rec, err := EncodeRecord(seq, kind, []byte(key), value)
		if err != nil {
			s.mu.Unlock()
			return err
		}
		if s.head.size+int64(s.pendingBytes)+int64(len(rec))+HeaderBytes > s.opts.SegmentBytes {
			s.mu.Unlock()
			// Sealing the head must exclude every other writer, so the flush
			// and the roll happen under one flushMu hold.
			s.flushMu.Lock()
			err := s.flushLocked()
			if err == nil {
				s.mu.Lock()
				// Another writer may have rolled while this one waited for
				// flushMu. Rolling again would seal an empty segment.
				if s.head.size+int64(len(rec))+HeaderBytes > s.opts.SegmentBytes {
					err = s.rollSegment()
				}
				s.mu.Unlock()
			}
			s.flushMu.Unlock()
			if err != nil {
				return err
			}
			continue
		}
		if forceSeq == 0 {
			s.seq = seq
			s.stats.LogicalBytes += uint64(len(key) + len(value))
		} else {
			s.stats.CleanCopiedBytes += uint64(len(rec))
			s.stats.CleanRecords++
		}
		loc := Loc{Off: s.head.size + int64(s.pendingBytes), Seq: seq, Seg: s.head.id, Len: int32(len(rec))}
		s.pending = append(s.pending, rec)
		s.pendingBytes += len(rec)
		s.pendingIdx = append(s.pendingIdx, IndexEntry{Key: key, Loc: loc, Deleted: kind == KindDelete})
		if kind == KindPut {
			s.pendingVals[key] = value
		} else {
			delete(s.pendingVals, key)
		}
		s.pendingKeys[key] = struct{}{}
		if s.groupStart.IsZero() {
			s.groupStart = time.Now()
		}
		full := s.pendingBytes >= s.opts.GroupBytes
		s.mu.Unlock()
		if full {
			return s.flush()
		}
		return nil
	}
}

// Barrier commits the current group immediately and waits for durability.
func (s *Store) Barrier() error { return s.flush() }

func (s *Store) flush() error {
	s.flushMu.Lock()
	defer s.flushMu.Unlock()
	return s.flushLocked()
}

// flushLocked commits the open group. The caller holds flushMu, which
// serializes every write to the head segment.
func (s *Store) flushLocked() error {
	s.mu.Lock()
	if len(s.pending) == 0 {
		s.mu.Unlock()
		return nil
	}
	batch := s.pending
	entries := s.pendingIdx
	head := s.head
	lastSeq := entries[len(entries)-1].Loc.Seq
	trailer, err := EncodeRecord(lastSeq, KindTrailer, nil, nil)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	batch = append(batch, trailer)
	total := s.pendingBytes + len(trailer)
	// Reserve the file range before releasing the lock. A concurrent writer
	// computes its record offsets from head.size, and the write below takes
	// milliseconds; without the reservation a staged record would be assigned
	// an offset that this group is about to occupy.
	head.size += int64(total)
	s.pending = nil
	s.pendingIdx = nil
	s.pendingBytes = 0
	s.groupStart = time.Time{}
	s.inflightVals, s.pendingVals = s.pendingVals, make(map[string][]byte)
	s.inflightKeys, s.pendingKeys = s.pendingKeys, make(map[string]struct{})
	if len(entries) > s.stats.MaxGroupRecords {
		s.stats.MaxGroupRecords = len(entries)
	}
	s.mu.Unlock()

	if err := writevAll(head.write, batch); err != nil {
		return err
	}
	started := time.Now()
	if err := head.write.Sync(); err != nil {
		return err
	}
	elapsed := time.Since(started)

	s.mu.Lock()
	s.syncTimes = append(s.syncTimes, elapsed)
	s.stats.Groups++
	s.stats.Syncs++
	s.stats.Records += uint64(len(entries))
	s.stats.AppendedBytes += uint64(total)
	s.stats.TrailerBytes += uint64(len(trailer))
	for _, entry := range entries {
		s.applyIndexEntry(entry)
	}
	if lastSeq > s.durable {
		s.durable = lastSeq
	}
	s.inflightVals = nil
	s.inflightKeys = nil
	s.recomputeTotals()
	idx := s.idx
	idxHead := Loc{Seg: head.id, Off: head.size}
	s.mu.Unlock()

	if idx != nil {
		queued := make([]IndexEntry, len(entries))
		copy(queued, entries)
		select {
		case s.idxQueue <- indexOp{entries: queued, head: idxHead}:
		case <-s.stop:
		}
	}
	return nil
}

// applyIndexEntry maintains the in-memory index and per-segment live bytes.
// The caller holds s.mu.
func (s *Store) applyIndexEntry(entry IndexEntry) {
	if old, ok := s.index[entry.Key]; ok {
		if seg := s.segments[old.Seg]; seg != nil {
			seg.live -= int64(old.Len)
		}
	}
	if entry.Deleted {
		delete(s.index, entry.Key)
		return
	}
	s.index[entry.Key] = entry.Loc
	if seg := s.segments[entry.Loc.Seg]; seg != nil {
		seg.live += int64(entry.Loc.Len)
	}
}

// Get resolves a key through the index and reads the value out of the log.
func (s *Store) Get(key string) ([]byte, bool, error) {
	s.mu.Lock()
	if value, ok := s.pendingVals[key]; ok {
		out := make([]byte, len(value))
		copy(out, value)
		s.mu.Unlock()
		return out, true, nil
	}
	if value, ok := s.inflightVals[key]; ok {
		out := make([]byte, len(value))
		copy(out, value)
		s.mu.Unlock()
		return out, true, nil
	}
	loc, ok := s.index[key]
	if !ok {
		s.mu.Unlock()
		return nil, false, nil
	}
	seg := s.segments[loc.Seg]
	if seg == nil {
		s.mu.Unlock()
		return nil, false, fmt.Errorf("seglog: segment %d is absent for key %q", loc.Seg, key)
	}
	read := seg.read
	s.mu.Unlock()

	buf := make([]byte, loc.Len)
	if _, err := read.ReadAt(buf, loc.Off); err != nil {
		return nil, false, err
	}
	h, gotKey, value, err := DecodeRecord(buf)
	if err != nil {
		return nil, false, err
	}
	if string(gotKey) != key || h.Kind != KindPut {
		return nil, false, fmt.Errorf("seglog: record at %d/%d does not hold %q", loc.Seg, loc.Off, key)
	}
	out := make([]byte, len(value))
	copy(out, value)
	return out, true, nil
}

func writevAll(file *os.File, buffers [][]byte) error {
	fd := int(file.Fd())
	for len(buffers) > 0 {
		chunk := buffers
		if len(chunk) > 1000 {
			chunk = chunk[:1000]
		}
		written, err := unix.Writev(fd, chunk)
		if err != nil {
			return err
		}
		remaining := written
		for len(buffers) > 0 {
			if remaining >= len(buffers[0]) {
				remaining -= len(buffers[0])
				buffers = buffers[1:]
				continue
			}
			buffers[0] = buffers[0][remaining:]
			remaining = 0
			break
		}
		if remaining > 0 {
			return errors.New("seglog: writev reported more bytes than supplied")
		}
	}
	return nil
}

func (s *Store) timerLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.opts.GroupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			s.mu.Lock()
			due := !s.groupStart.IsZero() && time.Since(s.groupStart) >= s.opts.GroupInterval
			s.mu.Unlock()
			if due {
				_ = s.flush()
			}
		}
	}
}

// indexOp is one unit of asynchronous index work. A nil entries slice with a
// non-nil done channel is a flush barrier.
type indexOp struct {
	entries []IndexEntry
	head    Loc
	flush   bool
	settle  bool
	done    chan error
}

func (s *Store) indexLoop() {
	defer s.wg.Done()
	defer close(s.idxDone)
	for {
		select {
		case <-s.stop:
			s.drainIndex()
			return
		case op := <-s.idxQueue:
			if err := s.runIndexOp(op); err != nil {
				return
			}
		}
	}
}

func (s *Store) runIndexOp(op indexOp) error {
	if len(op.entries) > 0 {
		if err := s.idx.Apply(op.entries, op.head); err != nil {
			s.recordIndexError(err)
			s.reply(op, err)
			return err
		}
	}
	if op.flush {
		if err := s.idx.Flush(); err != nil {
			s.recordIndexError(err)
			s.reply(op, err)
			return err
		}
	}
	if op.settle {
		if err := s.idx.Settle(); err != nil {
			s.recordIndexError(err)
			s.reply(op, err)
			return err
		}
	}
	s.reply(op, nil)
	return nil
}

func (s *Store) reply(op indexOp, err error) {
	if op.done != nil {
		op.done <- err
	}
}

func (s *Store) recordIndexError(err error) {
	s.mu.Lock()
	if s.idxErr == nil {
		s.idxErr = err
	}
	s.mu.Unlock()
}

func (s *Store) drainIndex() {
	for {
		select {
		case op := <-s.idxQueue:
			if err := s.runIndexOp(op); err != nil {
				return
			}
		default:
			return
		}
	}
}

// FlushIndex drains the asynchronous index queue and makes the persistent
// index durable. It is a no-op when the persistent index is disabled.
func (s *Store) FlushIndex() error { return s.indexBarrier(indexOp{flush: true}) }

// SettleIndex additionally leaves the persistent index with no outstanding
// compaction debt. Fixture construction uses it so that a later measurement is
// not charged for work the fixture created.
func (s *Store) SettleIndex() error { return s.indexBarrier(indexOp{flush: true, settle: true}) }

func (s *Store) indexBarrier(op indexOp) error {
	if s.idx == nil {
		return nil
	}
	op.done = make(chan error, 1)
	select {
	case s.idxQueue <- op:
	case <-s.stop:
		return nil
	}
	return <-op.done
}

// Stats returns a snapshot of the cumulative counters.
func (s *Store) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recomputeTotals()
	out := s.stats
	return out
}

// SyncLatencies returns and clears the recorded fsync durations.
func (s *Store) SyncLatencies() []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.syncTimes
	s.syncTimes = nil
	return out
}

// ResetStats zeroes the cumulative counters without touching stored data.
func (s *Store) ResetStats() {
	s.mu.Lock()
	defer s.mu.Unlock()
	live, total, segs, keys := s.stats.LiveBytes, s.stats.TotalBytes, s.stats.Segments, s.stats.IndexKeys
	s.stats = Stats{LiveBytes: live, TotalBytes: total, Segments: segs, IndexKeys: keys}
	s.syncTimes = nil
}

// IndexKeys reports the number of live in-memory index entries.
func (s *Store) IndexKeys() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.index)
}

// Close commits any pending group, stops background work, and closes files.
func (s *Store) Close() error {
	if err := s.Barrier(); err != nil {
		return err
	}
	var err error
	s.stopOnce.Do(func() {
		close(s.stop)
		s.wg.Wait()
		if s.idx != nil {
			if flushErr := s.idx.Flush(); flushErr != nil {
				err = flushErr
			}
			if closeErr := s.idx.Close(); err == nil {
				err = closeErr
			}
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		s.closed = true
		for _, seg := range s.segments {
			if seg.write != nil {
				if closeErr := seg.write.Close(); err == nil {
					err = closeErr
				}
			}
			if closeErr := seg.read.Close(); err == nil {
				err = closeErr
			}
		}
	})
	return err
}
