//go:build linux

package fusev3

import (
	"context"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

func ownCacheRecord(t *testing.T, f *strictFixture) (*inodeRecord, uint64) {
	t.Helper()
	entry := f.lookup(t, 1, "file")
	record := f.raw.acquire(entry.NodeId)
	t.Cleanup(func() { f.raw.release(record) })
	return record, entry.NodeId
}

func TestOwnWriteSkipsNeverCachedInode(t *testing.T) {
	f := newStrictFixture(t)
	record, inode := ownCacheRecord(t, f)
	writer := openV7Writer(t, f, inode)
	f.notify.mu.Lock()
	f.notify.calls = nil
	f.notify.mu.Unlock()
	for i := 0; i < 100; i++ {
		writeV7(t, f, inode, writer.Fh, uint64(i*4), []byte("data"))
	}
	if calls := f.notify.snapshot(); len(calls) != 0 {
		t.Fatalf("writer-only notifications: %+v", calls)
	}
	if allocs := testing.AllocsPerRun(1000, func() {
		if err := record.acceptOwnWrite(context.Background(), 0, 4); err != nil {
			panic(err)
		}
	}); allocs != 0 {
		t.Fatalf("writer-only invalidation allocations=%g", allocs)
	}
}

func TestOwnWriteCoalescesClosedReaderRanges(t *testing.T) {
	for _, boundary := range []string{"flush-cycle", "cached-open"} {
		t.Run(boundary, func(t *testing.T) {
			f := newStrictFixture(t)
			record, inode := ownCacheRecord(t, f)
			// Model a previously published KEEP_CACHE description whose RELEASE has
			// finished. Its folios remain even after the local grant is released.
			record.readCache.addReader()
			record.readCache.removeReader()
			writer := openV7Writer(t, f, inode)
			f.notify.mu.Lock()
			f.notify.calls = nil
			f.notify.mu.Unlock()
			writeV7(t, f, inode, writer.Fh, 100, []byte("one"))
			writeV7(t, f, inode, writer.Fh, 20, []byte("two"))
			writeV7(t, f, inode, writer.Fh, 80, []byte("three"))
			if calls := f.notify.snapshot(); len(calls) != 0 {
				t.Fatalf("closed-reader immediate notifications: %+v", calls)
			}
			if boundary == "flush-cycle" {
				var id writeback.Identity
				copy(id[:], record.identity[:])
				f.mount.delegations.FlushCycleCompleted(context.Background(), id)
			} else {
				// The fake Authority explicitly permits the read OPEN, including after a
				// local release which deliberately delivers no CONTROL event.
				out := &fuse.OpenOut{}
				if status := f.rawCall(func(unique uint64) fuse.Status {
					return f.raw.Open(nil, &fuse.OpenIn{InHeader: fuse.InHeader{Unique: unique, NodeId: inode}}, out)
				}); status != fuse.OK {
					t.Fatal(status)
				}
			}
			calls := f.notify.snapshot()
			if len(calls) != 1 || calls[0].kind != "inode" || calls[0].off != 20 || calls[0].length != 83 {
				t.Fatalf("coalesced notify: %+v", calls)
			}
			if err := record.drainOwnWrites(context.Background()); err != nil {
				t.Fatal(err)
			}
			if len(f.notify.snapshot()) != 1 {
				t.Fatal("empty tick repeated notify")
			}
		})
	}
}

func TestOwnWriteWaitsForNotificationAndIncludesConcurrentRange(t *testing.T) {
	f := newStrictFixture(t)
	record, _ := ownCacheRecord(t, f)
	record.readCache.addReader()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	f.notify.onInode = func(_ uint64, _, _ int64) { once.Do(func() { close(entered); <-release }) }
	first, second := make(chan error, 1), make(chan error, 1)
	go func() { first <- record.acceptOwnWrite(context.Background(), 10, 4) }()
	<-entered
	go func() { second <- record.acceptOwnWrite(context.Background(), 40, 8) }()
	deadline := time.Now().Add(time.Second)
	for {
		record.readCache.mu.Lock()
		pending := record.readCache.pending
		record.readCache.mu.Unlock()
		if pending {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("second write did not join pending range")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case err := <-first:
		t.Fatalf("write outran notify: %v", err)
	default:
	}
	select {
	case err := <-second:
		t.Fatalf("concurrent write outran notify: %v", err)
	default:
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := <-second; err != nil {
		t.Fatal(err)
	}
	calls := f.notify.snapshot()
	if len(calls) != 2 || calls[1].off != 40 || calls[1].length != 8 {
		t.Fatalf("notifications %+v", calls)
	}
}

func TestOwnReadHandleCountIncludesClosingInFlightRead(t *testing.T) {
	f := newStrictFixture(t)
	record, _ := ownCacheRecord(t, f)
	id, ok := f.raw.addHandle(record, &handleRecord{file: &fileHandle{node: record.node, buffered: true}})
	if !ok {
		t.Fatal("add handle")
	}
	held, _ := f.raw.acquireFileHandle(id)
	done := make(chan struct{})
	go func() { f.raw.takeHandle(id, handleAuthorityFile); close(done) }()
	deadline := time.Now().Add(time.Second)
	for {
		f.raw.mu.Lock()
		closing := held.closing
		f.raw.mu.Unlock()
		if closing {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("release did not start")
		}
		time.Sleep(time.Millisecond)
	}
	record.readCache.mu.Lock()
	readers := record.readCache.readers
	record.readCache.mu.Unlock()
	if readers != 1 {
		t.Fatalf("in-flight reader count=%d", readers)
	}
	f.raw.releaseHandleOperation(held)
	<-done
	f.raw.unpin(record)
	record.readCache.mu.Lock()
	defer record.readCache.mu.Unlock()
	if record.readCache.readers != 0 || !record.readCache.retained.Load() {
		t.Fatal("release discarded retained-folio obligation")
	}
}

func preparePendingOwnCacheWrite(t *testing.T, record *inodeRecord) {
	t.Helper()
	record.readCache.addReader()
	record.readCache.removeReader()
	if err := record.acceptOwnWrite(context.Background(), 0, 4); err != nil {
		t.Fatal(err)
	}
}

func TestOwnCachePublicationFailureIsInodeLocal(t *testing.T) {
	for _, operation := range []string{"open", "create"} {
		for _, persistent := range []bool{false, true} {
			name := "transient"
			if persistent {
				name = "persistent"
			}
			t.Run(operation+"/"+name, func(t *testing.T) {
				f := newStrictFixture(t)
				f.rpc.mu.Lock()
				f.rpc.byName = map[string]*authoritypb.Item{
					"file":  cloneItem(f.rpc.item),
					"other": testItem(92, authoritypb.Attr_REGULAR, 92),
				}
				f.rpc.mu.Unlock()
				record, inode := ownCacheRecord(t, f)
				preparePendingOwnCacheWrite(t, record)
				f.raw.mu.Lock()
				pins, handles := record.pins, len(f.raw.handles)
				f.raw.mu.Unlock()
				loss := f.mount.delegations.LossSequence()
				f.mount.subscription.config.repairLead = 30 * time.Millisecond
				f.mount.subscription.config.retryDelay = 2 * time.Millisecond

				attempts := 0
				f.notify.mu.Lock()
				f.notify.onInode = func(_ uint64, _, _ int64) {
					f.notify.mu.Lock()
					defer f.notify.mu.Unlock()
					attempts++
					f.notify.inodeST = fuse.OK
					if persistent || attempts == 1 {
						f.notify.inodeST = fuse.EIO
					}
				}
				f.notify.mu.Unlock()

				status := f.rawCall(func(unique uint64) fuse.Status {
					switch operation {
					case "open":
						return f.raw.Open(nil, &fuse.OpenIn{InHeader: fuse.InHeader{Unique: unique, NodeId: inode}}, &fuse.OpenOut{})
					case "create":
						return f.raw.Create(nil, &fuse.CreateIn{InHeader: fuse.InHeader{Unique: unique, NodeId: fuse.FUSE_ROOT_ID}, Flags: uint32(syscall.O_CREAT | syscall.O_RDONLY), Mode: 0o600}, "file", &fuse.CreateOut{})
					default:
						panic("unknown operation")
					}
				})
				if persistent {
					if status != fuse.EIO || attempts < 2 || !record.stale.Load() {
						t.Fatalf("persistent %s = %v attempts=%d stale=%t", operation, status, attempts, record.stale.Load())
					}
					f.raw.mu.Lock()
					if record.pins != pins || len(f.raw.handles) != handles {
						t.Fatalf("unpublished handle leaked: pins %d/%d handles %d/%d", record.pins, pins, len(f.raw.handles), handles)
					}
					f.raw.mu.Unlock()
				} else if status != fuse.OK || attempts != 2 || record.stale.Load() {
					t.Fatalf("transient %s = %v attempts=%d stale=%t", operation, status, attempts, record.stale.Load())
				}
				if f.mount.isRevoked() {
					t.Fatalf("%s notification failure revoked mount: %v", operation, f.mount.fatalError())
				}
				if got := f.mount.delegations.LossSequence(); got != loss {
					t.Fatalf("%s discarded no buffered entry but advanced loss %d -> %d", operation, loss, got)
				}

				other := f.lookup(t, fuse.FUSE_ROOT_ID, "other")
				if out := f.openForData(t, other.NodeId); out.Fh == 0 {
					t.Fatal("unrelated file did not remain usable")
				}
			})
		}
	}
}

func TestOwnCacheWriteFailureReportsDiscardedBuffer(t *testing.T) {
	f := newStrictFixture(t)
	record, inode := ownCacheRecord(t, f)
	record.readCache.addReader()
	writer := openV7Writer(t, f, inode)
	f.mount.subscription.config.repairLead = 30 * time.Millisecond
	f.mount.subscription.config.retryDelay = 2 * time.Millisecond
	f.notify.mu.Lock()
	f.notify.inodeST = fuse.EIO
	f.notify.mu.Unlock()
	var reports []writeback.DropReport
	f.mount.delegations.SetDropReporter(func(report writeback.DropReport) {
		reports = append(reports, report)
	})
	loss := f.mount.delegations.LossSequence()
	status := f.rawCall(func(unique uint64) fuse.Status {
		_, status := f.raw.Write(nil, &fuse.WriteIn{
			InHeader: fuse.InHeader{Unique: unique, NodeId: inode},
			Fh:       writer.Fh,
			Size:     4,
			Flags:    uint32(syscall.O_RDWR),
		}, []byte("lost"))
		return status
	})
	if status != fuse.EIO || f.mount.isRevoked() || !record.stale.Load() {
		t.Fatalf("failed write = %v revoked=%t stale=%t", status, f.mount.isRevoked(), record.stale.Load())
	}
	if got := f.mount.delegations.LossSequence(); got <= loss {
		t.Fatalf("discarded buffer did not advance loss: %d -> %d", loss, got)
	}
	if len(reports) != 1 || reports[0].Entries == 0 || reports[0].LossSequence <= loss {
		t.Fatalf("discarded buffer reports = %+v", reports)
	}
}
