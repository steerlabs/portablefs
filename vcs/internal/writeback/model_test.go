package writeback

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"
)

// Compare the retained overlay and transport coalescing against a separate
// byte-array filesystem while only prefixes become durable. This exercises
// arena reuse and ownership lists, not just a tree that never retires nodes.
func TestPartialDurabilityAgainstNaiveFilesystem(t *testing.T) {
	for seed := int64(0); seed < 16; seed++ {
		t.Run(fmt.Sprintf("seed_%d", seed), func(t *testing.T) {
			rng := rand.New(rand.NewSource(seed))
			ctx := context.Background()
			var remote, model [2][]byte
			var seq uint64
			flusher := flusherFunc(func(_ context.Context, id Identity, e Entry) (uint64, error) {
				i := int(id[0])
				remote[i] = applyModelEntry(remote[i], e)
				seq++
				return seq, nil
			})
			b := newTestBuffer(t, flusher, Options{MaxBytes: 1 << 20, MaxEntries: 2048, FlushInterval: -1})
			for step := 0; step < 1000; step++ {
				i := rng.Intn(2)
				id := Identity{byte(i)}
				switch rng.Intn(6) {
				case 0, 1, 2:
					off := int64(rng.Intn(128))
					data := make([]byte, 1+rng.Intn(32))
					_, _ = rng.Read(data)
					if _, err := b.Write(ctx, id, off, data); err != nil {
						t.Fatal(err)
					}
					model[i] = applyModelEntry(model[i], Entry{Kind: Write, Offset: off, Data: data})
				case 3:
					size := int64(rng.Intn(160))
					if _, err := b.Truncate(ctx, id, size); err != nil {
						t.Fatal(err)
					}
					model[i] = applyModelEntry(model[i], Entry{Kind: Truncate, Attributes: Attributes{HasSize: true, Size: size}})
				case 4:
					if _, err := b.FlushIdentity(ctx, id, b.Snapshot()); err != nil {
						t.Fatal(err)
					}
				case 5:
					if seq > 0 {
						b.DurableSequence(uint64(rng.Int63n(int64(seq) + 1)))
					}
				}
				for j := range model {
					identity := Identity{byte(j)}
					got, err := b.Read(ctx, identity, 0, 200, bytesFetch(remote[j]))
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(got, model[j]) {
						t.Fatalf("step %d identity %d read %x, want %x", step, j, got, model[j])
					}
					if size := b.Size(identity, int64(len(remote[j]))); size != int64(len(model[j])) {
						t.Fatalf("step %d size %d, want %d", step, size, len(model[j]))
					}
				}
			}
			for i := range model {
				if _, err := b.FlushIdentity(ctx, Identity{byte(i)}, b.Snapshot()); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(remote[i], model[i]) {
					t.Fatalf("final authority bytes %x, want %x", remote[i], model[i])
				}
			}
			b.DurableSequence(seq)
			if stats := b.Stats(); stats.Entries != 0 || stats.Bytes != 0 {
				t.Fatalf("retained after final durability: %+v", stats)
			}
			assertPoolAccounting(t, &b.pool, 0)
		})
	}
}

func applyModelEntry(file []byte, e Entry) []byte {
	if e.Kind == Write {
		end := int(e.Offset) + len(e.Data)
		if end > len(file) {
			file = append(file, make([]byte, end-len(file))...)
		}
		copy(file[int(e.Offset):], e.Data)
	}
	if e.Attributes.HasSize {
		n := int(e.Attributes.Size)
		if n > len(file) {
			file = append(file, make([]byte, n-len(file))...)
		} else {
			file = file[:n:n]
		}
	}
	return file
}

func TestExplicitCutDoesNotScheduleLaterAdmissions(t *testing.T) {
	calls := make(chan Entry, 4)
	b := newTestBuffer(t, flusherFunc(func(_ context.Context, _ Identity, e Entry) (uint64, error) { calls <- e; return e.Last, nil }))
	id := Identity{33}
	cut := mustWrite(t, b, id, 0, "first")
	mustWrite(t, b, id, 5, "later")
	if _, err := b.FlushIdentity(context.Background(), id, cut); err != nil {
		t.Fatal(err)
	}
	<-calls
	select {
	case e := <-calls:
		t.Fatalf("explicit cut scheduled later entry %d", e.First)
	case <-time.After(20 * time.Millisecond):
	}
}
