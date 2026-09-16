package writeback

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
)

// Read snapshots the overlay before fetching without holding the buffer lock.
// Snapshotted slices remain immutable even if a concurrent notification retires
// their records. EOF from fetch is normal; holes introduced locally read zero.
func (b *Buffer) Read(ctx context.Context, id Identity, off int64, length int, fetch Fetch) ([]byte, error) {
	if off < 0 || length < 0 || int64(length) > math.MaxInt64-off || fetch == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if length == 0 {
		return []byte{}, nil
	}
	b.mu.Lock()
	f := b.files[id]
	var local [32]span
	dirty := local[:0]
	var size int64
	exact := false
	if f != nil {
		size, exact = f.size, f.exact
		spans(f.extents.root, off, off+int64(length), &dirty)
	}
	b.mu.Unlock()
	if exact {
		if off >= size {
			return []byte{}, nil
		}
		length = int(min(int64(length), size-off))
	}
	base, err := fetch(ctx, off, length)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("fetch %x: %w", id, err)
	}
	if len(base) > length {
		return nil, fmt.Errorf("fetch %x returned excess bytes: %w", id, ErrInvalid)
	}
	n := len(base)
	if exact {
		n = length
	} else if size > off {
		n = max(n, int(min(int64(length), size-off)))
	}
	out := make([]byte, n)
	copy(out, base)
	for _, s := range dirty {
		lo, hi := max(off, s.lo), min(off+int64(n), s.hi)
		if hi <= lo {
			continue
		}
		if s.data == nil {
			clear(out[lo-off : hi-off])
		} else {
			copy(out[lo-off:hi-off], s.data[lo-s.lo:hi-s.lo])
		}
	}
	return out, nil
}

// OverlayAttributes applies retained metadata in program order. Base must
// reflect Authority state from the same delegation. Size uses the indexed size
// summary; implicit write timestamps and privilege-bit changes remain the
// frontend's responsibility and can be admitted as explicit SetAttr entries.
func (b *Buffer) OverlayAttributes(id Identity, base Attributes) Attributes {
	b.mu.Lock()
	defer b.mu.Unlock()
	f := b.files[id]
	if f == nil {
		return base
	}
	for r := f.head; r != nil; r = r.next {
		a := r.attrs
		if a.HasMode {
			base.Mode = a.Mode
			base.HasMode = true
		}
		if a.HasUID {
			base.UID = a.UID
			base.HasUID = true
		}
		if a.HasGID {
			base.GID = a.GID
			base.HasGID = true
		}
		if a.HasATime {
			base.ATimeNS = a.ATimeNS
			base.HasATime = true
			base.ATimeNow = false
		}
		if a.HasMTime {
			base.MTimeNS = a.MTimeNS
			base.HasMTime = true
			base.MTimeNow = false
		}
	}
	if f.exact {
		base.Size = f.size
		base.HasSize = true
	} else if f.size > base.Size {
		base.Size = f.size
		base.HasSize = true
	}
	return base
}
