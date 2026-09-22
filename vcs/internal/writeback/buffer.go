package writeback

import (
	"context"
	"fmt"
	"math"
	"sync"
	"syscall"
	"time"
)

type record struct {
	inOverlay                  bool
	next                       *record
	seq, generation, applied   uint64
	acceptedAt                 int64
	kind                       Kind
	off                        int64
	data                       []byte
	attrs                      Attributes
	writeOptions               WriteOptions
	state                      State
	file                       *file
	extents                    *extent
	prevTruncate, nextTruncate *record
	heapIndex                  int
}
type file struct {
	batchStorage    batch
	entryStorage    [4]Entry
	flushOffset     int
	id              Identity
	generation      uint64
	retiring        bool
	head, tail      *record
	extents         extentMap
	size            int64
	exact           bool
	lastLoss        uint64
	lastErrno       syscall.Errno
	lastGenericLoss uint64
	lost            bool
	flushUsers      int // includes callers waiting for the active flusher
	flushing        bool
	pending         *batch
	lastTruncate    *record
	accepted        *record
	lastApplied     uint64
	scheduled       bool
	reschedule      bool
}
type barrierState struct {
	cut     Cut
	lost    bool
	generic bool
	errno   syscall.Errno
}
type Buffer struct {
	batcher                                 BatchFlusher
	batchWidth, batchPayload                int
	maxFlushIdentities                      int
	waitingAdmissions                       int
	mu                                      sync.Mutex
	files                                   map[Identity]*file
	active                                  map[Identity]*file
	appliedHeap, visibleHeap                recordHeap
	records                                 []record
	free                                    *record
	pool                                    extentPool
	bytes                                   int64
	count                                   int
	maxBytes                                int64
	maxEntries                              int
	sequence, loss, token, visible, durable uint64
	lastErrno                               syscall.Errno
	lastGenericLoss                         uint64
	barriers                                map[*barrierState]struct{}
	changed                                 chan struct{}
	retiringAll, stopped                    bool
	flusher                                 Flusher
	kick                                    chan struct{}
	ctx                                     context.Context
	cancel                                  context.CancelFunc
	done                                    chan struct{}
	interval                                time.Duration
}

func New(flusher Flusher, opts Options) (*Buffer, error) {
	if flusher == nil || opts.MaxBytes < 0 || opts.MaxEntries < 0 || opts.MaxFlushIdentities < 0 {
		return nil, ErrInvalid
	}
	if opts.MaxBytes == 0 {
		opts.MaxBytes = DefaultMaxBytes
	}
	if opts.MaxEntries == 0 {
		opts.MaxEntries = DefaultMaxEntries
	}
	if opts.FlushInterval == 0 {
		opts.FlushInterval = time.Second
	}
	if opts.MaxFlushIdentities == 0 {
		opts.MaxFlushIdentities = 16
	}
	b := &Buffer{maxFlushIdentities: opts.MaxFlushIdentities,
		loss:  opts.InitialLossSequence,
		files: make(map[Identity]*file), active: make(map[Identity]*file), barriers: make(map[*barrierState]struct{}),
		appliedHeap: make(recordHeap, 0, opts.MaxEntries),
		visibleHeap: make(recordHeap, 0, opts.MaxEntries),
		records:     make([]record, opts.MaxEntries),
		pool:        newExtentPool(2*opts.MaxEntries + 2),
		maxBytes:    opts.MaxBytes, maxEntries: opts.MaxEntries,
		flusher: flusher, interval: opts.FlushInterval,
		kick: make(chan struct{}, 1), done: make(chan struct{}),
	}
	if batcher, ok := flusher.(BatchFlusher); ok {
		width, payload := batcher.FlushBatchSize()
		if width < 0 || width > 4 || width > 0 && (payload <= 0 || payload > MaxPayload) {
			return nil, ErrInvalid
		}
		if width > 0 {
			b.batcher, b.batchWidth, b.batchPayload = batcher, width, payload
		}
	}
	for i := range b.records {
		b.records[i].next = b.free
		b.free = &b.records[i]
	}
	b.ctx, b.cancel = context.WithCancel(context.Background())
	go b.schedule()
	return b, nil
}
func (b *Buffer) file(id Identity) *file {
	f := b.files[id]
	if f == nil {
		f = &file{id: id, generation: 1, extents: extentMap{pool: &b.pool}}
		b.files[id] = f
	}
	return f
}
func (b *Buffer) signal() {
	if b.changed != nil {
		close(b.changed)
		b.changed = nil
	}
}
func (b *Buffer) change() <-chan struct{} {
	if b.changed == nil {
		b.changed = make(chan struct{})
	}
	return b.changed
}
func wait(ctx context.Context, ch <-chan struct{}) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-ch:
		return nil
	}
}
func (b *Buffer) trigger() {
	select {
	case b.kick <- struct{}{}:
	default:
	}
}

func (b *Buffer) Write(ctx context.Context, id Identity, off int64, data []byte) (Cut, error) {
	return b.WriteWithOptions(ctx, id, off, data, WriteOptions{})
}
func (b *Buffer) WriteWithOptions(ctx context.Context, id Identity, off int64, data []byte, opts WriteOptions) (Cut, error) {
	return b.writeInGeneration(ctx, id, 0, off, data, opts)
}

// Generation-bound admission lets an owner release its own admission lock
// while waiting for capacity. A concurrent drop or ownership transition must
// fail the old waiter instead of accepting it into the replacement generation.
func (b *Buffer) WriteInGeneration(ctx context.Context, id Identity, generation uint64, off int64, data []byte, opts WriteOptions) (Cut, error) {
	if generation == 0 {
		return Cut{}, ErrInvalid
	}
	return b.writeInGeneration(ctx, id, generation, off, data, opts)
}
func (b *Buffer) writeInGeneration(ctx context.Context, id Identity, generation uint64, off int64, data []byte, opts WriteOptions) (Cut, error) {
	if off < 0 || len(data) == 0 || int64(len(data)) > math.MaxInt64-off || int64(len(data)) > b.maxBytes {
		return Cut{}, ErrInvalid
	}
	return b.admit(ctx, id, generation, Write, off, data, Attributes{}, opts)
}
func (b *Buffer) Truncate(ctx context.Context, id Identity, size int64) (Cut, error) {
	return b.truncateInGeneration(ctx, id, 0, size)
}
func (b *Buffer) TruncateInGeneration(ctx context.Context, id Identity, generation uint64, size int64) (Cut, error) {
	if generation == 0 {
		return Cut{}, ErrInvalid
	}
	return b.truncateInGeneration(ctx, id, generation, size)
}
func (b *Buffer) truncateInGeneration(ctx context.Context, id Identity, generation uint64, size int64) (Cut, error) {
	if size < 0 {
		return Cut{}, ErrInvalid
	}
	return b.admit(ctx, id, generation, Truncate, 0, nil, Attributes{Size: size, HasSize: true}, WriteOptions{})
}
func (b *Buffer) SetAttr(ctx context.Context, id Identity, a Attributes) (Cut, error) {
	return b.setAttrInGeneration(ctx, id, 0, a)
}
func (b *Buffer) SetAttrInGeneration(ctx context.Context, id Identity, generation uint64, a Attributes) (Cut, error) {
	if generation == 0 {
		return Cut{}, ErrInvalid
	}
	return b.setAttrInGeneration(ctx, id, generation, a)
}
func (b *Buffer) setAttrInGeneration(ctx context.Context, id Identity, generation uint64, a Attributes) (Cut, error) {
	if a.HasCTime || a.HasSize && a.Size < 0 || a.ATimeNow && a.HasATime || a.MTimeNow && a.HasMTime {
		return Cut{}, ErrInvalid
	}
	return b.admit(ctx, id, generation, SetAttr, 0, nil, a, WriteOptions{})
}
func (b *Buffer) admit(ctx context.Context, id Identity, generation uint64, kind Kind, off int64, data []byte, a Attributes, opts WriteOptions) (Cut, error) {
	// The caller's payload becomes immutable before admission, but the copy is
	// deliberately outside the global buffer mutex so a large write does not
	// stall disjoint reads, acknowledgements, or capacity release.
	copied := append([]byte(nil), data...)
	b.mu.Lock()
	defer b.mu.Unlock()
	for {
		if err := ctx.Err(); err != nil {
			return Cut{}, err
		}
		if b.stopped {
			return Cut{}, ErrClosed
		}
		f := b.file(id)
		if generation != 0 && f.generation != generation {
			return Cut{}, ErrLost
		}
		if !b.retiringAll && !f.retiring && b.count < b.maxEntries && b.bytes < b.maxBytes && int64(len(data)) <= b.maxBytes-b.bytes {
			now := time.Now().UnixNano()
			if a.ATimeNow || a.MTimeNow {
				if a.ATimeNow {
					a.ATimeNS = now
					a.HasATime = true
					a.ATimeNow = false
				}
				if a.MTimeNow {
					a.MTimeNS = now
					a.HasMTime = true
					a.MTimeNow = false
				}
			}
			r := b.free
			b.free = r.next
			b.sequence++
			*r = record{file: f, seq: b.sequence, generation: f.generation, kind: kind, off: off, data: copied, attrs: a, state: Accepted, acceptedAt: now, writeOptions: opts}
			if f.tail == nil {
				f.head = r
			} else {
				f.tail.next = r
			}
			f.tail = r
			if f.accepted == nil {
				f.accepted = r
			}
			b.active[id] = f
			b.count++
			b.bytes += int64(len(data))
			b.overlay(f, r)
			if b.count == b.maxEntries || b.bytes == b.maxBytes {
				b.trigger()
			}
			return Cut{b.sequence, b.loss}, nil
		}
		if b.count == b.maxEntries || b.bytes == b.maxBytes || int64(len(data)) > b.maxBytes-b.bytes {
			b.trigger()
		}
		ch := b.change()
		b.waitingAdmissions++
		b.mu.Unlock()
		err := wait(ctx, ch)
		b.mu.Lock()
		b.waitingAdmissions--
		if err != nil {
			return Cut{}, err
		}
	}
}
func (b *Buffer) overlay(f *file, r *record) {
	r.inOverlay = true
	if r.kind == Write {
		f.extents.set(r.off, r.off+int64(len(r.data)), r.data, r)
	}
	if r.attrs.HasSize {
		r.prevTruncate = f.lastTruncate
		if f.lastTruncate != nil {
			f.lastTruncate.nextTruncate = r
		}
		f.lastTruncate = r
		if r.attrs.Size < math.MaxInt64 {
			f.extents.set(r.attrs.Size, math.MaxInt64, nil, r)
		}
	}
	b.sizeLocked(f)
}
func (b *Buffer) sizeLocked(f *file) {
	f.size = extentEnd(f.extents.root)
	f.exact = f.lastTruncate != nil
	if f.exact {
		f.size = max(f.size, f.lastTruncate.attrs.Size)
	}
}
func (b *Buffer) Snapshot() Cut { b.mu.Lock(); defer b.mu.Unlock(); return Cut{b.sequence, b.loss} }

// BeginBarrier captures a root completion cut. Callers hold their admission
// fence only around this method, then pass the returned cut through flushing,
// the remote barrier, and WaitBarrier. The registered state makes a later drop
// fail this barrier only when the drop contains an operation in its prefix.
func (b *Buffer) BeginBarrier(observedLoss uint64) BarrierCut {
	b.mu.Lock()
	defer b.mu.Unlock()
	cut := Cut{Sequence: b.sequence, LossSequence: b.loss}
	state := &barrierState{cut: cut, lost: b.loss > observedLoss}
	if state.lost {
		if b.lastGenericLoss > observedLoss {
			state.generic = true
		} else {
			state.errno = b.lastErrno
		}
	}
	b.barriers[state] = struct{}{}
	return BarrierCut{Cut: cut, state: state}
}

// EndBarrier releases a cut whose operation aborted before WaitBarrier.
func (b *Buffer) EndBarrier(cut BarrierCut) {
	if cut.state == nil {
		return
	}
	b.mu.Lock()
	delete(b.barriers, cut.state)
	b.mu.Unlock()
}
func (b *Buffer) Size(id Identity, base int64) int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	f := b.files[id]
	if f == nil {
		return base
	}
	if f.exact {
		return f.size
	}
	return max(base, f.size)
}
func (b *Buffer) Stats() Stats {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := Stats{Bytes: b.bytes, Entries: b.count, LossSequence: b.loss, WaitingAdmissions: b.waitingAdmissions, Identities: len(b.files)}
	for _, f := range b.files {
		if f.flushing {
			s.Flushing++
		}
		if f.scheduled {
			s.Scheduled++
		}
		for r := f.head; r != nil; r = r.next {
			switch r.state {
			case Accepted:
				s.Accepted++
				s.AcceptedBytes += int64(len(r.data))
			case Applied:
				s.Applied++
			case Visible:
				s.Visible++
			}
		}
	}
	return s
}
func (b *Buffer) LossSequence() uint64 { b.mu.Lock(); defer b.mu.Unlock(); return b.loss }
func (b *Buffer) Lost(id Identity) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	f := b.files[id]
	return f != nil && f.lost
}
func (b *Buffer) ClearLost(id Identity) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	f := b.files[id]
	if f == nil {
		return false
	}
	v := f.lost
	f.lost = false
	return v
}

// IdentityLoss lets each handle maintain its own observation; clearing Lost
// must not erase an error that another open handle has yet to observe.
func (b *Buffer) IdentityLoss(id Identity) uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	f := b.files[id]
	if f == nil {
		return 0
	}
	return f.lastLoss
}

func (b *Buffer) HasRetained(id Identity) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	f := b.files[id]
	return f != nil && f.head != nil
}

// RetainedGeneration is the oldest generation still needed by retained records,
// or the current admission generation if no records remain. It never creates
// identity metadata. Admission and generations are monotonically ordered.
func (b *Buffer) RetainedGeneration(id Identity) (uint64, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if f := b.files[id]; f != nil {
		if f.head != nil {
			return f.head.generation, true
		}
		return f.generation, false
	}
	return 0, false
}

// Quiescent reports whether no record or internal flush reference remains.
// The owner must separately exclude new admissions before retiring metadata.
func (b *Buffer) Quiescent(id Identity) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	f := b.files[id]
	return f == nil || f.head == nil && f.flushUsers == 0 && !f.flushing && !f.scheduled && f.pending == nil
}

func (b *Buffer) notifyIdle(id Identity) {
	if observer, ok := b.flusher.(IdleObserver); ok {
		observer.BufferIdle(id)
	}
}

// IdentityFailure returns the loss ticket and its errno as one observation.
func (b *Buffer) IdentityFailure(id Identity, observed uint64) (uint64, syscall.Errno) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if f := b.files[id]; f != nil {
		if f.lastGenericLoss > observed || f.lastLoss <= observed {
			return f.lastLoss, 0
		}
		return f.lastLoss, f.lastErrno
	}
	return 0, 0
}
func (b *Buffer) ErrnoSince(observed uint64) syscall.Errno {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.loss > observed && b.lastGenericLoss <= observed {
		return b.lastErrno
	}
	return 0
}
func (b *Buffer) Drop(id Identity, reason string) DropReport {
	return b.DropWithErrno(id, reason, 0)
}

// DropWithErrno preserves a definite storage refusal for every open observer.
func (b *Buffer) DropWithErrno(id Identity, reason string, errno syscall.Errno) DropReport {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.dropLocked(id, reason, errno)
}

// DropAll reports exactly the identities that still retain non-durable records.
func (b *Buffer) DropAll(reason string) []DropReport {
	b.mu.Lock()
	defer b.mu.Unlock()
	reports := make([]DropReport, 0, len(b.active))
	for id, f := range b.active {
		if f.head != nil {
			reports = append(reports, b.dropLocked(id, reason, 0))
		}
	}
	return reports
}

func (b *Buffer) dropLocked(id Identity, reason string, errno syscall.Errno) DropReport {
	f := b.file(id)
	for barrier := range b.barriers {
		affected := false
		for r := f.head; r != nil && r.seq <= barrier.cut.Sequence; r = r.next {
			affected = true
			break
		}
		if !affected {
			continue
		}
		barrier.lost = true
		if errno == 0 {
			barrier.generic = true
			barrier.errno = 0
		} else if !barrier.generic {
			barrier.errno = errno
		}
	}
	b.loss++
	f.lastLoss = b.loss
	f.lastErrno, b.lastErrno = errno, errno
	if errno == 0 {
		f.lastGenericLoss, b.lastGenericLoss = b.loss, b.loss
	}
	f.lost = true
	report := DropReport{Identity: id, Reason: reason, LossSequence: b.loss, Errno: errno}
	f.extents.clear()
	f.size = 0
	f.exact = false
	for r := f.head; r != nil; {
		next := r.next
		report.Bytes += int64(len(r.data))
		report.Entries++
		b.release(r)
		r = next
	}
	f.head = nil
	f.tail = nil
	f.pending = nil
	f.flushOffset = 0
	f.reschedule = false
	f.batchStorage = batch{}
	clear(f.entryStorage[:])
	f.accepted = nil
	f.lastTruncate = nil
	delete(b.active, id)
	f.generation++
	b.signal()
	return report
}
func (b *Buffer) release(r *record) {
	if r.state == Applied {
		b.appliedHeap.remove(r.heapIndex)
	} else if r.state == Visible {
		b.visibleHeap.remove(r.heapIndex)
	}
	f := r.file
	f.extents.retire(r)
	if r.inOverlay && r.attrs.HasSize {
		if r.prevTruncate != nil {
			r.prevTruncate.nextTruncate = r.nextTruncate
		}
		if r.nextTruncate != nil {
			r.nextTruncate.prevTruncate = r.prevTruncate
		} else {
			f.lastTruncate = r.prevTruncate
		}
	}
	b.count--
	b.bytes -= int64(len(r.data))
	*r = record{next: b.free}
	b.free = r
}

// FenceAdmissions wakes capacity waiters without joining a flush that may
// itself need frontend admission locks. Retained records remain for Drop.
func (b *Buffer) FenceAdmissions() {
	b.mu.Lock()
	b.stopped = true
	b.signal()
	b.mu.Unlock()
}

// Stop cancels background I/O and rejects further admission. It does not drop
// retained entries. Drain via Barrier before Stop for a clean unmount.
func (b *Buffer) Stop() {
	b.FenceAdmissions()
	b.cancel()
	<-b.done
}

type backgroundFlush struct {
	file *file
	cut  Cut
}

// Background application uses a bounded pool so an unavailable identity does
// not hold unrelated accepted data behind it. Explicit fsync, recall and close
// flushes bypass the pool and can overtake locally queued jobs.
func (b *Buffer) schedule() {
	jobs := make(chan backgroundFlush, b.maxFlushIdentities)
	var workers sync.WaitGroup
	for range b.maxFlushIdentities {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for job := range jobs {
				_, err := b.FlushIdentity(b.ctx, job.file.id, job.cut)
				if err == nil {
					if observer, ok := b.flusher.(FlushCycleObserver); ok {
						observer.FlushCycleCompleted(b.ctx, job.file.id)
					}
				}
				b.mu.Lock()
				job.file.scheduled = false
				if err == nil && job.file.reschedule && job.file.accepted != nil {
					job.file.reschedule = false
					b.trigger()
				}
				b.mu.Unlock()
				b.notifyIdle(job.file.id)
			}
		}()
	}
	defer func() {
		close(jobs)
		workers.Wait()
		close(b.done)
	}()
	var tick <-chan time.Time
	if b.interval > 0 {
		timer := time.NewTicker(b.interval)
		tick = timer.C
		defer timer.Stop()
	}
	for {
		select {
		case <-b.ctx.Done():
			return
		case <-tick:
		case <-b.kick:
		}
		b.mu.Lock()
		cut := Cut{b.sequence, b.loss}
		var pending []backgroundFlush
		for _, f := range b.active {
			if f.scheduled || f.flushing {
				f.reschedule = true
				continue
			}
			f.reschedule = false
			if f.accepted == nil {
				continue
			}
			f.scheduled = true
			pending = append(pending, backgroundFlush{file: f, cut: cut})
		}
		b.mu.Unlock()
		for _, job := range pending {
			select {
			case jobs <- job:
			case <-b.ctx.Done():
				return
			}
		}
	}
}

// Generation returns the local admission generation. The frontend binds this
// value to its Authority delegation id and generation before admitting writes.
func (b *Buffer) Generation(id Identity) uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.file(id).generation
}

// Forget releases idle identity metadata after the frontend has closed every
// handle and released its delegation. No old cut or generation may be reused.
func (b *Buffer) Forget(id Identity) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	f := b.files[id]
	if f == nil {
		return true
	}
	if f.head != nil || f.retiring || f.flushUsers != 0 || f.flushing || f.scheduled || f.lost || b.retiringAll {
		return false
	}
	delete(b.files, id)
	return true
}

// Retirement blocks new admissions until Resume. The cut includes every
// admission that finished copying before the fence. A nil identity fences the
// whole mount, including identities first seen during retirement.
type Retirement struct {
	b        *Buffer
	files    []*file
	all      bool
	cut      Cut
	resumed  bool
	detached bool
}

func (b *Buffer) BeginRetire(ctx context.Context, id *Identity) (*Retirement, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if b.stopped {
			return nil, ErrClosed
		}
		busy := b.retiringAll
		if id != nil {
			busy = busy || b.file(*id).retiring
		} else {
			for _, f := range b.files {
				busy = busy || f.retiring
			}
		}
		if !busy {
			break
		}
		ch := b.change()
		b.mu.Unlock()
		err := wait(ctx, ch)
		b.mu.Lock()
		if err != nil {
			return nil, err
		}
	}
	r := &Retirement{b: b, all: id == nil, cut: Cut{b.sequence, b.loss}}
	if id == nil {
		b.retiringAll = true
		for _, f := range b.files {
			f.retiring = true
			r.files = append(r.files, f)
		}
	} else {
		f := b.file(*id)
		f.retiring = true
		r.files = append(r.files, f)
	}
	return r, nil
}
func (r *Retirement) Cut() Cut { return r.cut }
func (r *Retirement) Resume() error {
	b := r.b
	b.mu.Lock()
	defer b.mu.Unlock()
	if r.resumed {
		return nil
	}
	for _, f := range r.files {
		if f.accepted != nil && f.accepted.seq <= r.cut.Sequence {
			return fmt.Errorf("resume generation: %w", ErrPending)
		}
	}
	for _, f := range r.files {
		f.retiring = false
		f.generation++
	}
	if r.all {
		b.retiringAll = false
	}
	r.resumed = true
	b.signal()
	return nil
}

func recordedLossError(errno syscall.Errno) error {
	if errno != 0 {
		return errno
	}
	return ErrLost
}

// DetachOverlay ends serving the retired ownership interval without discarding
// its durability or loss obligation. A later owner starts with an Authority
// base; the old records remain charged until their durable prefix arrives.
func (r *Retirement) DetachOverlay() error {
	b := r.b
	b.mu.Lock()
	defer b.mu.Unlock()
	if r.resumed {
		return ErrInvalid
	}
	for _, f := range r.files {
		if !f.retiring {
			return ErrInvalid
		}
		if f.accepted != nil && f.accepted.seq <= r.cut.Sequence {
			return ErrPending
		}
	}
	for _, f := range r.files {
		f.extents.clear()
		for entry := f.head; entry != nil; entry = entry.next {
			entry.inOverlay = false
			entry.prevTruncate, entry.nextTruncate = nil, nil
		}
		f.lastTruncate = nil
		f.size, f.exact = 0, false
	}
	r.detached = true
	return nil
}

// Cancel reopens admission in the same ownership generation after an abandoned
// retirement. Its caller must still own that generation at the Authority.
func (r *Retirement) Cancel() {
	b := r.b
	b.mu.Lock()
	defer b.mu.Unlock()
	if r.resumed || r.detached {
		return
	}
	for _, f := range r.files {
		f.retiring = false
	}
	if r.all {
		b.retiringAll = false
	}
	r.resumed = true
	b.signal()
}
