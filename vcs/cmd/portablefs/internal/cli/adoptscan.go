package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"
)

// adoptEntry is one filesystem node captured by the adopt scan. The field
// semantics mirror packages/core/src/tree.ts scanWorkspace so the Go-computed
// tree hash is byte-identical to what the TS server computes: mode is the
// lstat permission bits (mode & 0o777), executable is mode&0o111 for files and
// directories (never symlinks), symlink size is the byte length of the raw
// readlink target, directory size is 0. Files at or above
// adoptChunkThresholdBytes carry chunk refs exactly like the TS scanner —
// chunks participate in the tree hash, so representing a large file as one
// whole blob would make the server's next rescan rewrite the entry.
type adoptEntry struct {
	relPath    string // relative posix path, no leading slash
	absPath    string
	kind       string // "file" | "directory" | "symlink"
	mode       uint32
	size       int64
	mtimeMs    int64
	executable bool
	linkTarget string
	digest     string       // "sha256:<hex>", filled by the hash phase for files
	chunks     []adoptChunk // set when size >= adoptChunkThresholdBytes
}

// adoptChunk mirrors the TS ChunkRef (packages/protocol chunkRefSchema).
type adoptChunk struct {
	digest string
	size   int64
	offset int64
}

const (
	// adoptChunkThresholdBytes and adoptChunkBytes MUST equal the TS scanner's
	// defaultLargeFileThresholdBytes / defaultLargeFileChunkBytes
	// (packages/core/src/tree.ts): the server rescans workspaces with those
	// defaults, and a different representation for the same bytes changes the
	// tree hash.
	adoptChunkThresholdBytes = 8 << 20
	adoptChunkBytes          = 4 << 20
)

// adoptSkip records a node the scan intentionally left out (never an error).
type adoptSkip struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

type adoptScanResult struct {
	entries    []*adoptEntry
	files      int
	dirs       int
	symlinks   int
	totalBytes int64 // sum of file sizes
	skipped    []adoptSkip
	excluded   int              // nodes dropped by --exclude/.portablefsignore
	topBytes   map[string]int64 // file bytes under each top-level directory
}

// ignorePattern is one parsed gitignore-style pattern. A pattern containing a
// slash matches the full path relative to the adopt root; a pattern without a
// slash matches any basename at any depth. Trailing "/" restricts to
// directories, leading "!" re-includes (last match wins), "**" matches any
// number of path segments. Like git, re-including a file whose parent
// directory is excluded has no effect (the walk prunes the directory).
type ignorePattern struct {
	negate    bool
	dirOnly   bool
	matchBase bool
	segments  []string
}

type ignoreMatcher struct {
	patterns []ignorePattern
}

func parseIgnorePattern(raw string) (ignorePattern, bool) {
	p := strings.TrimSpace(raw)
	if p == "" || strings.HasPrefix(p, "#") {
		return ignorePattern{}, false
	}
	var pat ignorePattern
	if strings.HasPrefix(p, "!") {
		pat.negate = true
		p = p[1:]
	}
	if strings.HasSuffix(p, "/") {
		pat.dirOnly = true
		p = strings.TrimSuffix(p, "/")
	}
	// Like gitignore, any slash (including a leading one) anchors the pattern
	// to the adopt root; only slash-free patterns match basenames at any depth.
	anchored := strings.Contains(p, "/")
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return ignorePattern{}, false
	}
	pat.matchBase = !anchored
	pat.segments = strings.Split(p, "/")
	return pat, true
}

func newIgnoreMatcher(patterns []string) *ignoreMatcher {
	m := &ignoreMatcher{}
	for _, raw := range patterns {
		if pat, ok := parseIgnorePattern(raw); ok {
			m.patterns = append(m.patterns, pat)
		}
	}
	return m
}

// loadIgnoreFile reads .portablefsignore at the adopt root; a missing file is
// simply no patterns.
func loadIgnoreFile(root string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(root, ".portablefsignore"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read .portablefsignore: %w", err)
	}
	return strings.Split(string(data), "\n"), nil
}

// segMatch matches pattern segments against path segments. "**" matches zero
// or more segments mid-pattern; a trailing "**" matches everything inside (at
// least one segment), like gitignore's "dir/**".
func segMatch(pat, segs []string) bool {
	if len(pat) == 0 {
		return len(segs) == 0
	}
	if pat[0] == "**" {
		if len(pat) == 1 {
			return len(segs) >= 1
		}
		for i := 0; i <= len(segs); i++ {
			if segMatch(pat[1:], segs[i:]) {
				return true
			}
		}
		return false
	}
	if len(segs) == 0 {
		return false
	}
	if ok, _ := path.Match(pat[0], segs[0]); !ok {
		return false
	}
	return segMatch(pat[1:], segs[1:])
}

func (m *ignoreMatcher) ignored(rel string, isDir bool) bool {
	if len(m.patterns) == 0 {
		return false
	}
	segs := strings.Split(rel, "/")
	base := segs[len(segs)-1]
	ignored := false
	for _, p := range m.patterns {
		if p.dirOnly && !isDir {
			continue
		}
		var match bool
		if p.matchBase {
			match, _ = path.Match(p.segments[0], base)
		} else {
			match = segMatch(p.segments, segs)
		}
		if match {
			ignored = !p.negate
		}
	}
	return ignored
}

func describeNodeType(mode fs.FileMode) string {
	switch {
	case mode&fs.ModeSocket != 0:
		return "socket"
	case mode&fs.ModeNamedPipe != 0:
		return "named pipe"
	case mode&fs.ModeDevice != 0, mode&fs.ModeCharDevice != 0:
		return "device node"
	default:
		return "unsupported node type"
	}
}

// adoptScanDir walks root with lstat semantics: symlinks are captured verbatim
// (raw readlink target, never followed, so no cycles), empty directories are
// preserved as entries, and everything is included by default — only
// sockets/FIFOs/devices and matcher-excluded paths are left out.
func adoptScanDir(root string, matcher *ignoreMatcher) (*adoptScanResult, error) {
	res := &adoptScanResult{topBytes: map[string]int64{}}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("scan %s: %w", p, walkErr)
		}
		if p == root {
			return nil
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		isDir := d.IsDir()
		// The server rejects paths that are not well-formed strings; invalid
		// UTF-8 in a filename cannot round-trip through JSON without silently
		// changing the path (and the tree hash), so skip it loudly instead.
		if !utf8.ValidString(rel) {
			res.skipped = append(res.skipped, adoptSkip{Path: safePathLabel(rel), Reason: "path is not valid UTF-8"})
			if isDir {
				return fs.SkipDir
			}
			return nil
		}
		if matcher.ignored(rel, isDir) {
			res.excluded++
			if isDir {
				return fs.SkipDir
			}
			return nil
		}
		info, infoErr := d.Info() // lstat: WalkDir never follows symlinks
		if infoErr != nil {
			return fmt.Errorf("stat %s: %w", p, infoErr)
		}
		mode := uint32(info.Mode() & fs.ModePerm)
		mtimeMs := info.ModTime().UnixMilli()
		if mtimeMs < 0 {
			mtimeMs = 0 // the manifest schema requires nonnegative mtimes
		}
		switch {
		case isDir:
			res.dirs++
			res.entries = append(res.entries, &adoptEntry{
				relPath: rel, absPath: p, kind: "directory",
				mode: mode, size: 0, mtimeMs: mtimeMs,
				executable: mode&0o111 != 0,
			})
		case d.Type()&fs.ModeSymlink != 0:
			target, linkErr := os.Readlink(p)
			if linkErr != nil {
				return fmt.Errorf("readlink %s: %w", p, linkErr)
			}
			if !utf8.ValidString(target) {
				res.skipped = append(res.skipped, adoptSkip{Path: rel, Reason: "symlink target is not valid UTF-8"})
				return nil
			}
			res.symlinks++
			res.entries = append(res.entries, &adoptEntry{
				relPath: rel, absPath: p, kind: "symlink",
				mode: mode, size: int64(len(target)), mtimeMs: mtimeMs,
				executable: false, linkTarget: target,
			})
		case d.Type().IsRegular():
			res.files++
			res.totalBytes += info.Size()
			if i := strings.IndexByte(rel, '/'); i > 0 {
				res.topBytes[rel[:i]] += info.Size()
			}
			res.entries = append(res.entries, &adoptEntry{
				relPath: rel, absPath: p, kind: "file",
				mode: mode, size: info.Size(), mtimeMs: mtimeMs,
				executable: mode&0o111 != 0,
			})
		default:
			res.skipped = append(res.skipped, adoptSkip{Path: rel, Reason: describeNodeType(d.Type())})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(res.entries, func(i, j int) bool { return res.entries[i].relPath < res.entries[j].relPath })
	return res, nil
}

// safePathLabel renders a possibly-invalid-UTF-8 path safely for warnings.
func safePathLabel(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	return fmt.Sprintf("%q", s)
}

// hashFile streams one file through sha256, returning the blob digest and the
// byte count actually hashed.
func hashFile(absPath string) (string, int64, error) {
	f, err := os.Open(absPath)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), n, nil
}

// hashChunkedFile reads one large file sequentially, producing the whole-file
// digest plus per-chunk refs with the SAME chunk size the TS scanner uses.
func hashChunkedFile(absPath string) (string, int64, []adoptChunk, error) {
	f, err := os.Open(absPath)
	if err != nil {
		return "", 0, nil, err
	}
	defer f.Close()
	full := sha256.New()
	var chunks []adoptChunk
	var offset int64
	buf := make([]byte, adoptChunkBytes)
	for {
		n, err := io.ReadFull(f, buf)
		if n > 0 {
			full.Write(buf[:n])
			sum := sha256.Sum256(buf[:n])
			chunks = append(chunks, adoptChunk{
				digest: "sha256:" + hex.EncodeToString(sum[:]),
				size:   int64(n),
				offset: offset,
			})
			offset += int64(n)
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return "", 0, nil, err
		}
	}
	return "sha256:" + hex.EncodeToString(full.Sum(nil)), offset, chunks, nil
}

// adoptHashFiles computes the sha256 blob digest of every file entry with
// bounded concurrency. The byte count actually hashed becomes the entry's
// authoritative size, so the manifest always describes the bytes that will be
// uploaded even if a file changed between lstat and read.
func adoptHashFiles(entries []*adoptEntry, concurrency int) (int64, error) {
	if concurrency < 1 {
		concurrency = 1
	}
	var files []*adoptEntry
	for _, en := range entries {
		if en.kind == "file" {
			files = append(files, en)
		}
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	setErr := func(err error) {
		mu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		mu.Unlock()
	}
	for _, en := range files {
		wg.Add(1)
		sem <- struct{}{}
		go func(en *adoptEntry) {
			defer wg.Done()
			defer func() { <-sem }()
			// The threshold gates on the scanned size (like the TS scanner's
			// pre-read lstat); the hash re-measures the authoritative size.
			if en.size >= adoptChunkThresholdBytes && en.size > 0 {
				digest, n, chunks, err := hashChunkedFile(en.absPath)
				if err != nil {
					setErr(fmt.Errorf("read %s: %w", en.relPath, err))
					return
				}
				en.digest = digest
				en.size = n
				en.chunks = chunks
				return
			}
			digest, n, err := hashFile(en.absPath)
			if err != nil {
				setErr(fmt.Errorf("read %s: %w", en.relPath, err))
				return
			}
			en.digest = digest
			en.size = n
		}(en)
	}
	wg.Wait()
	if firstErr != nil {
		return 0, firstErr
	}
	var total int64
	for _, en := range files {
		total += en.size
	}
	return total, nil
}
