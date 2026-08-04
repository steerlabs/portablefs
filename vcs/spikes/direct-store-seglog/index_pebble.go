package main

import (
	"os"

	"github.com/cockroachdb/pebble/v2"
	"github.com/cockroachdb/pebble/v2/vfs"
	"github.com/steerlabs/portablefs/vcs/spikes/direct-store-seglog/seglog"
)

// pebbleIndex is the rebuildable persistent index over log offsets. Its
// contents are recoverable by scanning the log, so it runs with the WAL
// disabled: index durability is never on the foreground acknowledgement path.
type pebbleIndex struct {
	db  *pebble.DB
	dir string
}

var (
	indexKeyPrefix = []byte{'k'}
	indexHeadKey   = []byte{'h'}
)

func openPebbleIndex(dir string) (seglog.Index, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	opts := &pebble.Options{
		FS:                          vfs.Default,
		DisableWAL:                  true,
		MemTableSize:                32 << 20,
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
	return &pebbleIndex{db: db, dir: dir}, nil
}

func userKey(key string) []byte {
	out := make([]byte, 1+len(key))
	out[0] = indexKeyPrefix[0]
	copy(out[1:], key)
	return out
}

func (p *pebbleIndex) Apply(entries []seglog.IndexEntry, head seglog.Loc) error {
	batch := p.db.NewBatch()
	defer batch.Close()
	for _, entry := range entries {
		if entry.Deleted {
			if err := batch.Delete(userKey(entry.Key), nil); err != nil {
				return err
			}
			continue
		}
		if err := batch.Set(userKey(entry.Key), seglog.EncodeLoc(entry.Loc), nil); err != nil {
			return err
		}
	}
	if err := batch.Set(indexHeadKey, seglog.EncodeLoc(head), nil); err != nil {
		return err
	}
	return batch.Commit(pebble.NoSync)
}

func (p *pebbleIndex) Load(fn func(key []byte, loc seglog.Loc)) (seglog.Loc, error) {
	var head seglog.Loc
	value, closer, err := p.db.Get(indexHeadKey)
	if err == nil {
		head, err = seglog.DecodeLoc(value)
		closer.Close()
		if err != nil {
			return seglog.Loc{}, err
		}
	} else if err != pebble.ErrNotFound {
		return seglog.Loc{}, err
	}
	iter, err := p.db.NewIter(&pebble.IterOptions{
		LowerBound: []byte{'k'},
		UpperBound: []byte{'l'},
	})
	if err != nil {
		return seglog.Loc{}, err
	}
	defer iter.Close()
	for iter.First(); iter.Valid(); iter.Next() {
		loc, err := seglog.DecodeLoc(iter.Value())
		if err != nil {
			return seglog.Loc{}, err
		}
		fn(iter.Key()[1:], loc)
	}
	return head, iter.Error()
}

func (p *pebbleIndex) Flush() error { return p.db.Flush() }

// Settle leaves the index with no outstanding flush or compaction debt, so a
// later measurement is not charged for work that fixture construction caused.
func (p *pebbleIndex) Settle() error {
	if err := p.db.Flush(); err != nil {
		return err
	}
	return compactAll(p.db)
}

func (p *pebbleIndex) DiskBytes() (int64, error) { return directoryBytes(p.dir) }

func (p *pebbleIndex) Metrics() *pebble.Metrics { return p.db.Metrics() }

func (p *pebbleIndex) Close() error { return p.db.Close() }
