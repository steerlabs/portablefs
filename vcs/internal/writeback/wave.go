package writeback

// waveLocked follows acceptance order, splitting directly at the negotiated
// payload size. Adjacent records share scatter spans; overlaps stay separate
// ordered operations so last-writer-wins never requires a temporary payload.
func (b *Buffer) waveLocked(f *file, cut Cut) *batch {
	r := f.accepted
	if r == nil || r.seq > cut.Sequence {
		return nil
	}
	p := &f.batchStorage
	*p = batch{wave: true, first: r.seq, entries: f.entryStorage[:0]}
	if r.kind != Write {
		b.token++
		p.entries = append(p.entries, Entry{Token: b.token, First: r.seq, Last: r.seq, AppliedThrough: r.seq, Generation: r.generation, Kind: r.kind, Attributes: r.attrs})
		p.last, p.completedLast = r.seq, r
		f.pending = p
		return p
	}
	generation, options := r.generation, r.writeOptions
	off := f.flushOffset
	eligible := func() bool {
		return r != nil && r.seq <= cut.Sequence && r.kind == Write && r.generation == generation && r.writeOptions == options
	}
	for len(p.entries) < b.batchWidth && eligible() {
		b.token++
		entry := Entry{Token: b.token, First: r.seq, Generation: generation, Kind: Write, Offset: r.off + int64(off), WriteOptions: options}
		used, spans := 0, 0
		for eligible() && used < b.batchPayload && r.off+int64(off) == entry.Offset+int64(used) && spans < 64 {
			end := min(len(r.data), off+b.batchPayload-used)
			piece := r.data[off:end]
			if spans == 0 {
				entry.Data = piece
			} else {
				if entry.Segments == nil {
					entry.Segments = make([][]byte, 1, 4)
					entry.Segments[0] = entry.Data
					entry.Data = nil
				}
				entry.Segments = append(entry.Segments, piece)
			}
			spans++
			used += len(piece)
			off = end
			entry.Last = r.seq
			if off == len(r.data) {
				entry.AppliedThrough = r.seq
				p.completedLast = r
				r = r.next
				off = 0
			}
		}
		p.last = entry.Last
		p.entries = append(p.entries, entry)
	}
	p.endOffset = off
	f.pending = p
	return p
}
