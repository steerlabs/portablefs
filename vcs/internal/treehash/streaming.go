package treehash

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"sort"
	"strconv"
)

// Streaming computes the canonical tree hash over an entry stream that
// arrives in ascending byte (C / code-point) order — the order the legacy
// conversion pipeline assigns ordinals in — WITHOUT buffering the stream.
//
// Per shard it keeps one running SHA-256 plus the last path; memory is
// O(shards + longest path), independent of entry count. The only divergence
// between byte order and the canonical UTF-16 code-unit order involves paths
// containing runes >= U+E000 (BMP private-use/high area vs surrogate pairs);
// such paths — and every later entry of their shard — are held in a bounded
// per-shard overflow that is UTF-16-sorted at Root(). Trees without such
// paths (all real workloads and the million-entry differential) stream with
// zero overflow.
type Streaming struct {
	shards map[uint32]*shardStream
}

type pathKey struct {
	path string
	key  string
}

type shardStream struct {
	h        hash.Hash
	count    int
	lastPath string
	overflow []pathKey
}

// NewStreaming creates an empty streaming computer.
func NewStreaming() *Streaming {
	return &Streaming{shards: map[uint32]*shardStream{}}
}

// pathNeedsBuffer reports whether byte order and UTF-16 code-unit order can
// disagree about this path's position (it contains a rune >= U+E000).
func pathNeedsBuffer(p string) bool {
	for _, r := range p {
		if r >= 0xE000 {
			return true
		}
	}
	return false
}

// Add folds one entry. Entries must arrive in strictly ascending byte order
// of Path (unique paths); a violation is an error.
func (s *Streaming) Add(e Entry) error {
	id := shardID(e.Path)
	sh, ok := s.shards[id]
	if !ok {
		sh = &shardStream{}
		s.shards[id] = sh
	}
	key := comparableKey(e)
	if len(sh.overflow) > 0 || pathNeedsBuffer(e.Path) {
		// Once a shard holds any order-ambiguous path, every later entry of
		// that shard waits with it (it may interleave in UTF-16 order).
		sh.overflow = append(sh.overflow, pathKey{path: e.Path, key: key})
		return nil
	}
	if sh.count > 0 && !lessUTF16(sh.lastPath, e.Path) {
		return fmt.Errorf("treehash: entry %q arrived out of order after %q", e.Path, sh.lastPath)
	}
	if sh.h == nil {
		sh.h = sha256.New()
		sh.h.Write([]byte(shardVersion))
		sh.h.Write([]byte("\n"))
	}
	if sh.count > 0 {
		sh.h.Write([]byte("\n"))
	}
	sh.h.Write([]byte(e.Path))
	sh.h.Write([]byte{0})
	sh.h.Write([]byte(key))
	sh.count++
	sh.lastPath = e.Path
	return nil
}

// Root finalizes every shard (flushing UTF-16-sorted overflow tails) and
// returns the canonical root hash.
func (s *Streaming) Root() string {
	shardHashes := make(map[uint32]string, len(s.shards))
	for id, sh := range s.shards {
		if len(sh.overflow) > 0 {
			sort.Slice(sh.overflow, func(i, j int) bool {
				return lessUTF16(sh.overflow[i].path, sh.overflow[j].path)
			})
			for _, pk := range sh.overflow {
				if sh.h == nil {
					sh.h = sha256.New()
					sh.h.Write([]byte(shardVersion))
					sh.h.Write([]byte("\n"))
				}
				if sh.count > 0 {
					sh.h.Write([]byte("\n"))
				}
				sh.h.Write([]byte(pk.path))
				sh.h.Write([]byte{0})
				sh.h.Write([]byte(pk.key))
				sh.count++
			}
			sh.overflow = nil
		}
		if sh.h == nil {
			continue
		}
		var sum [32]byte
		copy(sum[:], sh.h.Sum(nil))
		shardHashes[id] = digest(sum)
	}

	ids := make([]uint32, 0, len(shardHashes))
	for id := range shardHashes {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	h := sha256.New()
	h.Write([]byte(rootVersion))
	h.Write([]byte("\n"))
	h.Write([]byte(strconv.Itoa(shardCount)))
	for _, id := range ids {
		h.Write([]byte("\n"))
		h.Write([]byte(strconv.FormatUint(uint64(id), 10)))
		h.Write([]byte{0})
		h.Write([]byte(shardHashes[id]))
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return digest(sum)
}
