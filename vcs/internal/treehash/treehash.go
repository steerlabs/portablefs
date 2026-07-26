// Package treehash is a faithful Go port of the canonical PortableFS volume tree
// hash (packages/core/src/tree.ts). The VCS must compute byte-identical hashes
// to the TS server, which validates manifest.treeHash on commit.
//
// The hash is a sharded Merkle structure:
//   - Each entry maps to a comparable key (stableJson of its content-identifying
//     fields, keys sorted, undefined omitted).
//   - Paths shard by FNV-1a over UTF-16 code units, mod 1024.
//   - A shard hash covers its paths (sorted by UTF-16 code unit) and keys.
//   - The root hash covers the shard hashes (shards sorted by id).
package treehash

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

const (
	shardCount   = 1024
	rootVersion  = "portablefs-tree-root-v2"
	shardVersion = "portablefs-tree-shard-v2"
)

// Blob is the content-identifying blob ref of a file.
type Blob struct {
	Digest      string
	Size        int64
	Compression string
	Packed      bool
}

// Chunk is one block of a large file.
type Chunk struct {
	Digest string
	Size   int64
	Offset int64
}

// Entry is the content-identifying view of a manifest entry.
type Entry struct {
	Path       string
	Kind       string
	Mode       uint32
	Size       int64
	Executable bool
	Blob       *Blob
	Chunks     []Chunk
	LinkTarget string
	UID        uint32 // owner; omitted from the hash when 0 (root) for back-compat
	GID        uint32 // group; omitted from the hash when 0 (root) for back-compat
}

// jsString mirrors JSON.stringify string escaping exactly (escape ", \, and the
// named control escapes; \u00xx for other control chars; everything else UTF-8).
func jsString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r < 0x20 {
				b.WriteString(fmt.Sprintf(`\u%04x`, r))
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func boolean(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func integer(v int64) string { return strconv.FormatInt(v, 10) }

// comparableKey reproduces stableJson(comparableEntry(e)): keys alphabetical,
// undefined fields omitted.
func comparableKey(e Entry) string {
	var parts []string
	kv := func(k, v string) { parts = append(parts, jsString(k)+":"+v) }

	if e.Blob != nil {
		blob := "{" +
			jsString("compression") + ":" + jsString(e.Blob.Compression) + "," +
			jsString("digest") + ":" + jsString(e.Blob.Digest) + "," +
			jsString("packed") + ":" + boolean(e.Blob.Packed) + "," +
			jsString("size") + ":" + integer(e.Blob.Size) +
			"}"
		kv("blob", blob)
	}
	if len(e.Chunks) > 0 {
		var elems []string
		for _, c := range e.Chunks {
			elems = append(elems, "{"+
				jsString("digest")+":"+jsString(c.Digest)+","+
				jsString("offset")+":"+integer(c.Offset)+","+
				jsString("size")+":"+integer(c.Size)+
				"}")
		}
		kv("chunks", "["+strings.Join(elems, ",")+"]")
	}
	kv("executable", boolean(e.Executable))
	if e.GID != 0 {
		kv("gid", integer(int64(e.GID)))
	}
	kv("kind", jsString(e.Kind))
	if e.LinkTarget != "" {
		kv("linkTarget", jsString(e.LinkTarget))
	}
	kv("mode", integer(int64(e.Mode)))
	kv("path", jsString(e.Path))
	kv("size", integer(e.Size))
	if e.UID != 0 {
		kv("uid", integer(int64(e.UID)))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// shardID is FNV-1a over the path's UTF-16 code units, mod shardCount.
func shardID(p string) uint32 {
	var h uint32 = 2166136261
	for _, u := range utf16.Encode([]rune(p)) {
		h ^= uint32(u)
		h *= 16777619
	}
	return h % shardCount
}

// lessUTF16 compares by UTF-16 code unit, matching JS string `<`.
func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

func digest(h [32]byte) string { return "sha256:" + hex.EncodeToString(h[:]) }

func shardHash(keysByPath map[string]string) string {
	paths := make([]string, 0, len(keysByPath))
	for p := range keysByPath {
		paths = append(paths, p)
	}
	sort.Slice(paths, func(i, j int) bool { return lessUTF16(paths[i], paths[j]) })

	h := sha256.New()
	h.Write([]byte(shardVersion))
	h.Write([]byte("\n"))
	for i, p := range paths {
		if i > 0 {
			h.Write([]byte("\n"))
		}
		h.Write([]byte(p))
		h.Write([]byte{0})
		h.Write([]byte(keysByPath[p]))
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return digest(sum)
}

// ComparableKey exposes the per-entry comparable key (for cross-check/debug).
func ComparableKey(e Entry) string { return comparableKey(e) }

// ShardID exposes the FNV shard id of a path (for cross-check/debug).
func ShardID(p string) uint32 { return shardID(p) }

// Compute returns the canonical tree hash ("sha256:...") for the entries.
func Compute(entries []Entry) string {
	shards := map[uint32]map[string]string{}
	for _, e := range entries {
		id := shardID(e.Path)
		m, ok := shards[id]
		if !ok {
			m = map[string]string{}
			shards[id] = m
		}
		m[e.Path] = comparableKey(e)
	}

	shardHashes := make(map[uint32]string, len(shards))
	for id, m := range shards {
		shardHashes[id] = shardHash(m)
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
