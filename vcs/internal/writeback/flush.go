package writeback

import (
	"context"
	"fmt"
	"sync"
)

type batch struct {
	wave                 bool
	completedLast        *record
	endOffset            int
	entries              []Entry
	next                 int
	first, last, applied uint64
}

// batchLocked coalesces only consecutive writes in one generation and cut.
// Metadata and truncation are ordering barriers. Original acceptance records
// remain retained: coalescing cannot erase a durability or loss obligation.
func (b *Buffer) batchLocked(f *file, cut Cut) *batch {
	if f.pending != nil {
		if f.pending.first > cut.Sequence {
			return nil
		}
		return f.pending
	}
	if b.batcher != nil {
		return b.waveLocked(f, cut)
	}
	r := f.accepted
	if r == nil || r.seq > cut.Sequence {
		return nil
	}
	last := r
	lo := r.off
	hi := lo + int64(len(r.data))
	if r.kind == Write && len(r.data) <= MaxPayload {
		for n := r.next; n != nil && n.seq <= cut.Sequence && n.state == Accepted && n.kind == Write && n.generation == r.generation && n.writeOptions == r.writeOptions; n = n.next {
			end := n.off + int64(len(n.data))
			a, z := min(lo, n.off), max(hi, end)
			if n.off > hi || end < lo || z-a > MaxPayload {
				break
			}
			lo, hi, last = a, z, n
		}
	}
	p := &f.batchStorage
	*p = batch{first: r.seq, last: last.seq, entries: f.entryStorage[:0]}
	data := r.data
	if last != r {
		data = make([]byte, hi-lo)
		for n := r; ; n = n.next {
			copy(data[n.off-lo:], n.data)
			if n == last {
				break
			}
		}
	}
	if r.kind == Write {
		for off := 0; off < len(data); off += MaxPayload {
			end := min(len(data), off+MaxPayload)
			b.token++
			p.entries = append(p.entries, Entry{
				Token: b.token, First: r.seq, Last: last.seq, Generation: r.generation,
				Kind: Write, Offset: lo + int64(off), Data: data[off:end], WriteOptions: r.writeOptions,
			})
		}
	} else {
		b.token++
		p.entries = append(p.entries, Entry{Token: b.token, First: r.seq, Last: r.seq, Generation: r.generation, Kind: r.kind, Attributes: r.attrs})
	}
	f.pending = p
	return p
}

// FlushIdentity waits for application (not durability) through cut and returns
// the largest Authority sequence it observed. It may finish an already-started
// batch extending past cut; it never pulls a new entry past cut into a batch.
func (b *Buffer) FlushIdentity(ctx context.Context, id Identity, cut Cut) (uint64, error) {
	b.mu.Lock()
	f := b.file(id)
	for f.flushing {
		ch := b.change()
		b.mu.Unlock()
		err := wait(ctx, ch)
		b.mu.Lock()
		if err != nil {
			b.mu.Unlock()
			return 0, err
		}
	}
	f.flushing = true
	b.mu.Unlock()
	completed := false
	defer func() {
		b.mu.Lock()
		f.flushing = false
		b.signal()
		if completed && f.reschedule && f.accepted != nil {
			f.reschedule = false
			b.trigger()
		}
		b.mu.Unlock()
	}()
	var applied uint64
	for {
		if err := ctx.Err(); err != nil {
			return applied, err
		}
		b.mu.Lock()
		if f.lastLoss > cut.LossSequence {
			errno := f.lastErrno
			if f.lastGenericLoss > cut.LossSequence {
				errno = 0
			}
			err := recordedLossError(errno)
			b.mu.Unlock()
			return applied, err
		}
		applied = max(applied, f.lastApplied)
		p := b.batchLocked(f, cut)
		if p == nil {
			completed = true
			b.mu.Unlock()
			return applied, nil
		}
		entry := p.entries[p.next]
		wave := p.wave
		floor := max(p.applied, f.lastApplied)
		var retained [4]Entry
		entries := retained[:0]
		if wave {
			entries = retained[:len(p.entries)]
			copy(entries, p.entries)
		}
		b.mu.Unlock()
		seq := floor
		var err error
		if wave {
			var sequences []uint64
			sequences, err = b.batcher.FlushBatch(ctx, id, entries)
			if err == nil {
				if len(sequences) != len(entries) {
					err = ErrInvalid
				}
				for _, next := range sequences {
					if next == 0 || next < seq {
						err = ErrInvalid
						break
					}
					seq = next
				}
			}
		} else {
			seq, err = b.flusher.Flush(ctx, id, entry)
		}
		b.mu.Lock()
		if err != nil {
			b.mu.Unlock()
			return applied, fmt.Errorf("flush %x token %d: %w", id, entry.Token, err)
		}
		if f.pending != p {
			b.mu.Unlock()
			return applied, ErrLost
		}
		if seq == 0 || seq < p.applied || seq < f.lastApplied {
			b.mu.Unlock()
			return applied, fmt.Errorf("flush %x: non-monotonic applied sequence: %w", id, ErrInvalid)
		}
		f.lastApplied = seq
		p.applied = max(p.applied, seq)
		applied = max(applied, seq)
		p.next++
		if p.wave {
			p.next = len(p.entries)
		}
		if p.next == len(p.entries) {
			last := p.last
			if p.wave {
				last = 0
				if p.completedLast != nil {
					last = p.completedLast.seq
				}
				f.flushOffset = p.endOffset
			}
			for r := f.accepted; r != nil && r.seq <= last; r = r.next {
				if r.seq >= p.first {
					r.applied = p.applied
					r.state = Applied
					b.appliedHeap.push(r)
					f.accepted = r.next
				}
			}
			f.pending = nil
			*p = batch{}
			clear(f.entryStorage[:])
			b.advanceLocked()
			b.signal()
		}
		b.mu.Unlock()
	}
}

func (b *Buffer) targets(cut Cut) []Identity {
	b.mu.Lock()
	defer b.mu.Unlock()
	ids := make([]Identity, 0, len(b.active))
	for id, f := range b.active {
		if f.head != nil && f.head.seq <= cut.Sequence {
			ids = append(ids, id)
		}
	}
	return ids
}

// FlushAll flushes the cut concurrently across identities, retaining per-file
// order, using a bounded worker pool. It visits every target even if one fails.
func (b *Buffer) FlushAll(ctx context.Context, cut Cut) (uint64, error) {
	ids := b.targets(cut)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var seq uint64
	var first error
	next := 0
	for worker := 0; worker < min(b.maxFlushIdentities, len(ids)); worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				mu.Lock()
				if next == len(ids) {
					mu.Unlock()
					return
				}
				id := ids[next]
				next++
				mu.Unlock()
				s, e := b.FlushIdentity(ctx, id, cut)
				mu.Lock()
				seq = max(seq, s)
				if first == nil {
					first = e
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	b.mu.Lock()
	lost := b.loss > cut.LossSequence
	b.mu.Unlock()
	if first == nil && lost {
		first = ErrLost
	}
	return seq, first
}

func (b *Buffer) VisibleSequence(seq uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.visible = max(b.visible, seq)
	b.advanceLocked()
	b.signal()
}

// DurableSequence is a cumulative Authority watermark. The integration must
// deliver it only after visibility through seq is established. It therefore
// proves both Visible and Durable, even if it races ahead of a Flush reply.
func (b *Buffer) DurableSequence(seq uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.durable = max(b.durable, seq)
	b.visible = max(b.visible, seq)
	b.advanceLocked()
	b.signal()
}

// DurableIdentity records a successful file FSYNC for the already-applied cut.
// It cannot advance the volume prefix: another identity may still be dirty.
func (b *Buffer) DurableIdentity(id Identity, cut Cut) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	f := b.files[id]
	if f == nil {
		return nil
	}
	if f.lastLoss > cut.LossSequence {
		if f.lastGenericLoss > cut.LossSequence {
			return ErrLost
		}
		return recordedLossError(f.lastErrno)
	}
	for r := f.head; r != nil && r.seq <= cut.Sequence; r = r.next {
		if r.state == Accepted {
			return ErrInvalid
		}
	}
	for f.head != nil && f.head.seq <= cut.Sequence {
		r := f.head
		f.head = r.next
		b.release(r)
	}
	if f.head == nil {
		f.tail = nil
		delete(b.active, id)
	}
	b.sizeLocked(f)
	b.signal()
	return nil
}

func (b *Buffer) advanceLocked() {
	for len(b.appliedHeap) > 0 && b.appliedHeap[0].applied <= b.visible {
		r := b.appliedHeap.remove(0)
		r.state = Visible
		b.visibleHeap.push(r)
	}
	for len(b.visibleHeap) > 0 && b.visibleHeap[0].applied <= b.durable {
		r := b.visibleHeap.remove(0)
		r.state = Durable
		f := r.file
		for f.head != nil && f.head.state == Durable {
			r = f.head
			f.head = r.next
			b.release(r)
		}
		if f.head == nil {
			f.tail = nil
			delete(b.active, f.id)
		}
		b.sizeLocked(f)
	}
}
func (b *Buffer) waitDurable(ctx context.Context, id *Identity, cut Cut) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for {
		pending := false
		if id != nil {
			f := b.files[*id]
			if f != nil {
				if f.lastLoss > cut.LossSequence {
					if f.lastGenericLoss > cut.LossSequence {
						return ErrLost
					}
					return recordedLossError(f.lastErrno)
				}
				pending = f.head != nil && f.head.seq <= cut.Sequence
			}
		} else {
			if b.loss > cut.LossSequence {
				if b.lastGenericLoss > cut.LossSequence {
					return ErrLost
				}
				return recordedLossError(b.lastErrno)
			}
			for _, f := range b.active {
				pending = pending || (f.head != nil && f.head.seq <= cut.Sequence)
			}
		}
		if !pending {
			return nil
		}
		ch := b.change()
		b.mu.Unlock()
		err := wait(ctx, ch)
		b.mu.Lock()
		if err != nil {
			return err
		}
	}
}
func (b *Buffer) WriteSync(ctx context.Context, id Identity, off int64, data []byte) (Cut, error) {
	return b.WriteSyncWithOptions(ctx, id, off, data, WriteOptions{})
}
func (b *Buffer) WriteSyncWithOptions(ctx context.Context, id Identity, off int64, data []byte, opts WriteOptions) (Cut, error) {
	cut, err := b.WriteWithOptions(ctx, id, off, data, opts)
	if err != nil {
		return cut, err
	}
	_, err = b.FlushIdentity(ctx, id, cut)
	if err == nil {
		err = b.waitDurable(ctx, &id, cut)
	}
	return cut, err
}
func (b *Buffer) Fsync(ctx context.Context, id Identity) error {
	cut := b.Snapshot()
	if _, err := b.FlushIdentity(ctx, id, cut); err != nil {
		return err
	}
	return b.waitDurable(ctx, &id, cut)
}
func (b *Buffer) Barrier(ctx context.Context, observedLoss uint64) (bool, error) {
	cut := b.Snapshot()
	_, err := b.FlushAll(ctx, cut)
	if err == nil {
		err = b.waitDurable(ctx, nil, cut)
	}
	return b.LossSequence() > observedLoss, err
}
