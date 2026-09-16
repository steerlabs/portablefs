package writeback

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"
)

type record struct {
	next                       *record
	seq, generation, applied   uint64
	kind                       Kind
	off                        int64
	data                       []byte
	attrs                      Attributes
	state                      State
	file                       *file
	extents                    *extent
	prevTruncate, nextTruncate *record
	heapIndex                  int
}
type file struct {
	batchStorage batch
	entryStorage [1]Entry
	id           Identity
	generation   uint64
	retiring     bool
	head, tail   *record
	extents      extentMap
	size         int64
	exact        bool
	lastLoss     uint64
	lost         bool
	flushing     bool
	pending      *batch
	lastTruncate *record
	accepted     *record
	lastApplied  uint64
	scheduled    bool
}
type Buffer struct {
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
	if flusher == nil || opts.MaxBytes < 0 || opts.MaxEntries < 0 {
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
	b := &Buffer{
		loss:  opts.InitialLossSequence,
		files: make(map[Identity]*file), active: make(map[Identity]*file),
		appliedHeap: make(recordHeap, 0, opts.MaxEntries),
		visibleHeap: make(recordHeap, 0, opts.MaxEntries),
		records:     make([]record, opts.MaxEntries),
		pool:        newExtentPool(2*opts.MaxEntries + 2),
		maxBytes:    opts.MaxBytes, maxEntries: opts.MaxEntries,
		flusher: flusher, interval: opts.FlushInterval,
		kick: make(chan struct{}, 1), done: make(chan struct{}),
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
	if off < 0 || len(data) == 0 || int64(len(data)) > math.MaxInt64-off || int64(len(data)) > b.maxBytes {
		return Cut{}, ErrInvalid
	}
	return b.admit(ctx, id, Write, off, data, Attributes{})
}
func (b *Buffer) Truncate(ctx context.Context, id Identity, size int64) (Cut, error) {
	if size < 0 {
		return Cut{}, ErrInvalid
	}
	return b.admit(ctx, id, Truncate, 0, nil, Attributes{Size: size, HasSize: true})
}
func (b *Buffer) SetAttr(ctx context.Context, id Identity, a Attributes) (Cut, error) {
	if a.HasSize && a.Size < 0 || a.ATimeNow && a.HasATime || a.MTimeNow && a.HasMTime {
		return Cut{}, ErrInvalid
	}
	return b.admit(ctx, id, SetAttr, 0, nil, a)
}
func (b *Buffer) admit(ctx context.Context, id Identity, kind Kind, off int64, data []byte, a Attributes) (Cut, error) {
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
		if !b.retiringAll && !f.retiring && b.count < b.maxEntries && b.bytes < b.maxBytes && int64(len(data)) <= b.maxBytes-b.bytes {
			// Copy is inside the admission fence: BeginRetire cannot miss a reserved
			// operation, and cancellation never leaves an unreported accepted entry.
			copied := append([]byte(nil), data...)
			if a.ATimeNow || a.MTimeNow {
				now := time.Now().UnixNano()
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
			*r = record{file: f, seq: b.sequence, generation: f.generation, kind: kind, off: off, data: copied, attrs: a, state: Accepted}
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
		b.mu.Unlock()
		err := wait(ctx, ch)
		b.mu.Lock()
		if err != nil {
			return Cut{}, err
		}
	}
}
func (b *Buffer) overlay(f *file, r *record) {
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
	s := Stats{Bytes: b.bytes, Entries: b.count, LossSequence: b.loss}
	for _, f := range b.files {
		for r := f.head; r != nil; r = r.next {
			switch r.state {
			case Accepted:
				s.Accepted++
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
func (b *Buffer) Drop(id Identity, reason string) DropReport {
	b.mu.Lock()
	defer b.mu.Unlock()
	f := b.file(id)
	b.loss++
	f.lastLoss = b.loss
	f.lost = true
	report := DropReport{Identity: id, Reason: reason, LossSequence: b.loss}
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
	f.batchStorage = batch{}
	f.entryStorage[0] = Entry{}
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
	if r.attrs.HasSize {
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

// Stop cancels background I/O and rejects further admission. It does not drop
// retained entries. Drain via Barrier before Stop for a clean unmount.
func (b *Buffer) Stop() {
	b.mu.Lock()
	b.stopped = true
	b.signal()
	b.mu.Unlock()
	b.cancel()
	<-b.done
}
func (b *Buffer) schedule() {
	defer close(b.done)
	var wg sync.WaitGroup
	defer wg.Wait()
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
		for _, f := range b.active {
			if f.scheduled || f.flushing {
				continue
			}
			f.scheduled = true
			wg.Add(1)
			go func(f *file) {
				defer wg.Done()
				_, err := b.FlushIdentity(b.ctx, f.id, cut)
				b.mu.Lock()
				f.scheduled = false
				if err == nil && f.accepted != nil {
					b.trigger()
				}
				b.mu.Unlock()
			}(f)
		}
		b.mu.Unlock()
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
	if f.head != nil || f.retiring || f.flushing || f.scheduled || f.lost || b.retiringAll {
		return false
	}
	delete(b.files, id)
	return true
}

// Retirement blocks new admissions until Resume. The cut includes every
// admission that finished copying before the fence. A nil identity fences the
// whole mount, including identities first seen during retirement.
type Retirement struct {
	b       *Buffer
	files   []*file
	all     bool
	cut     Cut
	resumed bool
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
