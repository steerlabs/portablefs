package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/cockroachdb/pebble/v2"
	"github.com/cockroachdb/pebble/v2/vfs"
	"github.com/steerlabs/portablefs/vcs/internal/pft2"
	"github.com/steerlabs/portablefs/vcs/spikes/direct-store-seglog/seglog"
)

// kv is the mutation surface the logical filesystem model needs.
type kv interface {
	Get(key string) ([]byte, bool, error)
	Put(key string, value []byte) error
	Delete(key string) error
}

// engine adds durability and lifecycle to a kv.
type engine interface {
	kv
	// Barrier makes every staged mutation durable.
	Barrier() error
	// DiskBytes reports the engine's on-disk footprint.
	DiskBytes() (int64, error)
	// Settle drains deferred background work so that a later measurement is
	// charged only for the mutations it performs.
	Settle() error
	Close() error
}

// applyMutation performs one logical filesystem operation and returns the
// application data bytes it carried.
func applyMutation(store kv, state *mutationState, kind string, op int) (uint64, error) {
	switch kind {
	case "random-4k":
		ino := uint64(3 + state.rng.IntN(state.fileCount-1))
		offset := uint64(state.rng.IntN(int(sparseFileBytes/pft2.CellBytes))) * pft2.CellBytes
		if err := store.Put(cellKey(ino, offset), dataCell(op, ino^offset)); err != nil {
			return 0, err
		}
		return pft2.CellBytes, touchInode(store, ino, op, nil)
	case "sequential-append":
		if err := store.Put(cellKey(2, state.appendAt), dataCell(op, state.appendAt)); err != nil {
			return 0, err
		}
		state.appendAt += pft2.CellBytes
		size := state.appendAt
		return pft2.CellBytes, touchInode(store, 2, op, func(value *inodeValue) { value.Size = size })
	case "small-creates":
		ino := state.allocateIno()
		name := fmt.Sprintf("new-%09d", state.created)
		state.created++
		meta := inodeValue{Kind: 1, Mode: 0o644, Size: createBytes, Mtime: int64(op + 1), Ctime: int64(op + 1)}
		if err := store.Put(inodeKey(ino), encodeInodeValue(meta)); err != nil {
			return 0, err
		}
		if err := store.Put(dirKey(1, name), encodeDirValue(ino, 1)); err != nil {
			return 0, err
		}
		if err := store.Put(cellKey(ino, 0), createCell(op, ino)); err != nil {
			return 0, err
		}
		return createBytes, touchInode(store, 1, op, nil)
	case "rename":
		value, found, err := store.Get(dirKey(1, state.rename))
		if err != nil {
			return 0, err
		}
		if !found {
			return 0, fmt.Errorf("rename source %q is absent", state.rename)
		}
		if err := store.Delete(dirKey(1, state.rename)); err != nil {
			return 0, err
		}
		if err := store.Put(dirKey(1, state.renameAlt), value); err != nil {
			return 0, err
		}
		state.rename, state.renameAlt = state.renameAlt, state.rename
		if err := touchInode(store, state.renameIno, op, nil); err != nil {
			return 0, err
		}
		return 0, touchInode(store, 1, op, nil)
	case "chmod":
		ino := uint64(3 + state.rng.IntN(state.fileCount-1))
		mode := uint32(0o600)
		if op%2 == 1 {
			mode = 0o644
		}
		return 0, touchInode(store, ino, op, func(value *inodeValue) { value.Mode = mode })
	case "mkdir":
		ino := state.allocateIno()
		name := fmt.Sprintf("dir-%09d", state.mkdirs)
		state.mkdirs++
		meta := inodeValue{Kind: 2, Mode: 0o755, Mtime: int64(op + 1), Ctime: int64(op + 1)}
		if err := store.Put(inodeKey(ino), encodeInodeValue(meta)); err != nil {
			return 0, err
		}
		if err := store.Put(dirKey(1, name), encodeDirValue(ino, 2)); err != nil {
			return 0, err
		}
		return 0, touchInode(store, 1, op, nil)
	default:
		return 0, fmt.Errorf("unknown operation %q", kind)
	}
}

func touchInode(store kv, ino uint64, op int, mutate func(*inodeValue)) error {
	raw, found, err := store.Get(inodeKey(ino))
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("inode %d is absent", ino)
	}
	value, err := decodeInodeValue(raw)
	if err != nil {
		return err
	}
	value.Mtime = int64(op + 1)
	value.Ctime = int64(op + 1)
	if mutate != nil {
		mutate(&value)
	}
	return store.Put(inodeKey(ino), encodeInodeValue(value))
}

// seglogEngine is the proposed format: a segmented append-only value log with
// a rebuildable index over log offsets.
type seglogEngine struct {
	store *seglog.Store
	dir   string
}

func (e *seglogEngine) Get(key string) ([]byte, bool, error) { return e.store.Get(key) }
func (e *seglogEngine) Put(key string, value []byte) error   { return e.store.Put(key, value) }
func (e *seglogEngine) Delete(key string) error              { return e.store.Delete(key) }
func (e *seglogEngine) Barrier() error                       { return e.store.Barrier() }
func (e *seglogEngine) DiskBytes() (int64, error)            { return directoryBytes(e.dir) }

func (e *seglogEngine) Settle() error {
	if err := e.store.Barrier(); err != nil {
		return err
	}
	return e.store.SettleIndex()
}
func (e *seglogEngine) Close() error { return e.store.Close() }

// pebbleEngine is the control: an ordinary LSM with values inline, a write
// ahead log, and durable commits. It exists to test the claim that value
// separation is what makes the append-once property hold.
type pebbleEngine struct {
	db  *pebble.DB
	dir string
}

func openPebbleEngine(dir string) (*pebbleEngine, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	opts := &pebble.Options{
		FS:                          vfs.Default,
		MemTableSize:                64 << 20,
		MemTableStopWritesThreshold: 4,
		L0CompactionThreshold:       4,
		CompactionConcurrencyRange:  func() (int, int) { return 1, 2 },
		Cache:                       pebble.NewCache(64 << 20),
		Logger:                      quietLogger{},
	}
	defer opts.Cache.Unref()
	db, err := pebble.Open(dir, opts)
	if err != nil {
		return nil, err
	}
	return &pebbleEngine{db: db, dir: dir}, nil
}

func (e *pebbleEngine) Get(key string) ([]byte, bool, error) {
	value, closer, err := e.db.Get([]byte(key))
	if errors.Is(err, pebble.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	out := make([]byte, len(value))
	copy(out, value)
	return out, true, closer.Close()
}

func (e *pebbleEngine) Put(key string, value []byte) error {
	return e.db.Set([]byte(key), value, pebble.NoSync)
}

func (e *pebbleEngine) Delete(key string) error {
	return e.db.Delete([]byte(key), pebble.NoSync)
}

func (e *pebbleEngine) Barrier() error { return e.db.LogData(nil, pebble.Sync) }

func (e *pebbleEngine) DiskBytes() (int64, error) { return directoryBytes(e.dir) }

func (e *pebbleEngine) Settle() error {
	if err := e.db.Flush(); err != nil {
		return err
	}
	return compactAll(e.db)
}

// compactAll rewrites the whole key space into the bottom level, leaving no
// compaction debt behind.
func compactAll(db *pebble.DB) error {
	start := []byte{0x00}
	end := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	if err := db.Compact(context.Background(), start, end, true); err != nil {
		return err
	}
	return nil
}

func (e *pebbleEngine) Close() error { return e.db.Close() }

// quietLogger keeps Pebble's recovery chatter out of the measurement output.
type quietLogger struct{}

func (quietLogger) Infof(string, ...any)  {}
func (quietLogger) Errorf(string, ...any) {}
func (quietLogger) Fatalf(format string, args ...any) {
	panic(fmt.Sprintf(format, args...))
}

func directoryBytes(dir string) (int64, error) {
	var total int64
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			// A background compaction can delete a table between the
			// directory listing and the stat. Skipping it undercounts by one
			// obsolete file, which is the correct answer anyway.
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		total += info.Size()
		return nil
	})
	if os.IsNotExist(err) {
		return total, nil
	}
	return total, err
}
