package main

import (
	"bytes"
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/archive"
	"github.com/steerlabs/portablefs/vcs/internal/archivestore"
	"github.com/steerlabs/portablefs/vcs/readonlyfs"
)

// Archived mode serves list, preview, and download for an ARCHIVED volume
// directly out of the sealed archive: the manifest answers the namespace, and
// ranged GETs over the pack objects answer content (restore-mode.md
// "Files-gateway archived mode"). It holds no authority session and never wakes
// a volume, so its only shared state is a bounded manifest cache.
const (
	// defaultArchivedManifests is the decoded-manifest cache size; the cache is
	// additionally held to a total decoded budget so that one enormous manifest
	// cannot consume the allowance of eight ordinary ones.
	defaultArchivedManifests = 8
	archivedManifestBudget   = 512 << 20

	// maximumArchiveFetch bounds the pack bytes one preview or download may
	// need. A request past it is refused rather than served slowly: the gateway
	// is a browsing surface, not a bulk restore path.
	maximumArchiveFetch = 4 << 30

	// maximumArchiveContent bounds concurrent content reconstructions. Each one
	// holds at most one coalesced range, one decompressed frame, and one logical
	// chunk, so this is what turns the format's per-request memory into a
	// process-wide bound.
	maximumArchiveContent = 8

	// archiveRangeGap is how many unwanted pack bytes are worth swallowing to
	// avoid a second GET; archiveRangeMaximum caps one coalesced request so that
	// a request's transient buffer stays small. Neither splits a frame.
	archiveRangeGap     = 1 << 20
	archiveRangeMaximum = 8 << 20

	// maximumArchiveRangeBytes refuses a single planned range whose length would
	// drive an outsized allocation. A manifest that produces one is either
	// corrupt or built with parameters this gateway will not serve.
	maximumArchiveRangeBytes = 256 << 20

	// archivedCursorBytes is the stateless directory cursor: a child offset plus
	// a binding digest over the archive identity and the parent it was issued
	// for. The manifest is immutable, so a cursor needs no registry entry and no
	// single-use semantics — only the same binding the live cursor registry
	// enforces by construction.
	archivedCursorBytes = 16
)

var (
	// errArchiveCapacity is a refusal to hold a manifest, not a store failure.
	errArchiveCapacity = errors.New("sealed manifest exceeds the decoded-manifest budget")
	// errArchiveBudget is a refusal to fetch, not a store failure.
	errArchiveBudget = errors.New("request needs more pack bytes than the per-request budget")
)

type archiveGateway struct {
	store     *archivestore.Client
	manifests *manifestCache
	content   chan struct{}
}

func newArchiveGateway(configPath string, maximumManifests int) (*archiveGateway, error) {
	config, err := archivestore.LoadConfigFile(configPath)
	if err != nil {
		return nil, err
	}
	store, err := archivestore.New(config)
	if err != nil {
		return nil, err
	}
	return newArchiveGatewayFor(store, maximumManifests), nil
}

func newArchiveGatewayFor(store *archivestore.Client, maximumManifests int) *archiveGateway {
	return &archiveGateway{
		store:     store,
		manifests: newManifestCache(maximumManifests, archivedManifestBudget),
		content:   make(chan struct{}, maximumArchiveContent),
	}
}

// archivedManifest is one decoded manifest plus the child index that turns the
// depth-first entry table into directory pages. Both are immutable once built,
// so every reader shares one copy.
type archivedManifest struct {
	manifest   *archive.Manifest
	childStart []uint32
	childOrder []uint32
	footprint  int64
}

func (a *archivedManifest) children(parent uint32) []uint32 {
	return a.childOrder[a.childStart[parent]:a.childStart[parent+1]]
}

// resolve walks one opaque path key — the same key scheme live mode uses —
// against the entry table. It returns the entry index, or a Linux errno the
// caller maps exactly as the live path does.
func (a *archivedManifest) resolve(pathKey string) (uint32, error) {
	components, err := readonlyfs.DecodePath(pathKey)
	if err != nil {
		return 0, syscall.EINVAL
	}
	index := uint32(0)
	for _, component := range components {
		if a.manifest.Entries[index].Type != archive.TypeDirectory {
			return 0, syscall.ENOTDIR
		}
		found := false
		for _, child := range a.children(index) {
			if bytes.Equal(a.manifest.Entries[child].Name, component) {
				index, found = child, true
				break
			}
		}
		if !found {
			return 0, syscall.ENOENT
		}
	}
	return index, nil
}

// indexChildren groups every entry under its parent in entry-table order. The
// table is depth-first, so a directory's children are not contiguous in it; one
// counting pass makes them contiguous here and makes a directory page a slice.
func indexChildren(manifest *archive.Manifest) (start, order []uint32) {
	start = make([]uint32, len(manifest.Entries)+1)
	for index := 1; index < len(manifest.Entries); index++ {
		start[manifest.Entries[index].ParentIndex+1]++
	}
	for index := 1; index < len(start); index++ {
		start[index] += start[index-1]
	}
	order = make([]uint32, len(manifest.Entries)-1)
	cursor := append([]uint32(nil), start[:len(start)-1]...)
	for index := 1; index < len(manifest.Entries); index++ {
		parent := manifest.Entries[index].ParentIndex
		order[cursor[parent]] = uint32(index)
		cursor[parent]++
	}
	return start, order
}

// manifestFootprint is a deliberate over-estimate of one decoded manifest's
// heap cost. It sizes a budget, so erring high costs a cache slot and erring
// low would let the cache outgrow the allowance it exists to enforce.
func manifestFootprint(manifest *archive.Manifest) int64 {
	const (
		entryBytes  = 192
		chunkBytes  = 96
		extentBytes = 16
		xattrBytes  = 48
		frameBytes  = 48
		indexBytes  = 8
	)
	total := int64(len(manifest.Frames)) * frameBytes
	total += int64(len(manifest.Entries)) * (entryBytes + indexBytes)
	for index := range manifest.Entries {
		entry := &manifest.Entries[index]
		total += int64(len(entry.Name)) + int64(len(entry.LinkName))
		for _, xattr := range entry.Xattrs {
			total += xattrBytes + int64(len(xattr.Name)) + int64(len(xattr.Value))
		}
		total += int64(len(entry.Chunks)) * chunkBytes
		for _, chunk := range entry.Chunks {
			total += int64(len(chunk.Extents)) * extentBytes
		}
	}
	return total
}

// manifestCache is a bounded LRU over decoded manifests, keyed by the archive
// identity triple. One fetch per key is in flight at a time: a second request
// for the same archive waits for the first rather than downloading it again.
type manifestCache struct {
	mu      sync.Mutex
	maximum int
	budget  int64
	used    int64
	order   *list.List
	byKey   map[string]*list.Element
}

type manifestCacheEntry struct {
	key      string
	ready    chan struct{}
	manifest *archivedManifest
	err      error
}

func newManifestCache(maximum int, budget int64) *manifestCache {
	return &manifestCache{maximum: maximum, budget: budget, order: list.New(), byKey: make(map[string]*list.Element)}
}

func (c *manifestCache) load(ctx context.Context, key string, fetch func(context.Context) (*archivedManifest, error)) (*archivedManifest, error) {
	c.mu.Lock()
	if element, cached := c.byKey[key]; cached {
		entry := element.Value.(*manifestCacheEntry)
		c.order.MoveToFront(element)
		c.mu.Unlock()
		select {
		case <-entry.ready:
			return entry.manifest, entry.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	entry := &manifestCacheEntry{key: key, ready: make(chan struct{})}
	c.byKey[key] = c.order.PushFront(entry)
	c.mu.Unlock()

	manifest, err := fetch(ctx)
	c.mu.Lock()
	if err == nil && manifest.footprint > c.budget {
		manifest, err = nil, fmt.Errorf("%w: %d bytes against a budget of %d", errArchiveCapacity, manifest.footprint, c.budget)
	}
	entry.manifest, entry.err = manifest, err
	if err != nil {
		if element, cached := c.byKey[key]; cached && element.Value.(*manifestCacheEntry) == entry {
			c.order.Remove(element)
			delete(c.byKey, key)
		}
	} else {
		c.used += manifest.footprint
		c.evictLocked(entry)
	}
	c.mu.Unlock()
	close(entry.ready)
	return manifest, err
}

// evictLocked drops least-recently-used manifests until the cache is inside
// both bounds. An entry still loading holds no accounted bytes and is never
// evicted; neither is the entry that was just admitted.
func (c *manifestCache) evictLocked(keep *manifestCacheEntry) {
	for c.order.Len() > c.maximum || c.used > c.budget {
		element := c.order.Back()
		for element != nil {
			candidate := element.Value.(*manifestCacheEntry)
			if candidate != keep && candidate.manifest != nil {
				break
			}
			element = element.Prev()
		}
		if element == nil {
			return
		}
		candidate := element.Value.(*manifestCacheEntry)
		c.order.Remove(element)
		delete(c.byKey, candidate.key)
		c.used -= candidate.manifest.footprint
	}
}

func (g *archiveGateway) manifest(ctx context.Context, volumeID string, epoch uint64, attempt string) (*archivedManifest, error) {
	key := volumeID + "\x00" + strconv.FormatUint(epoch, 10) + "\x00" + attempt
	return g.manifests.load(ctx, key, func(ctx context.Context) (*archivedManifest, error) {
		return g.fetchManifest(ctx, volumeID, epoch, attempt)
	})
}

func (g *archiveGateway) fetchManifest(ctx context.Context, volumeID string, epoch uint64, attempt string) (*archivedManifest, error) {
	key, err := g.store.KeyFor(volumeID, epoch, attempt, manifestObjectName)
	if err != nil {
		return nil, err
	}
	raw, err := g.store.GetObject(ctx, key, archive.MaxManifestBytes)
	if err != nil {
		return nil, err
	}
	// Decode verifies the footer digest before it parses anything and runs the
	// full structural validation afterwards, so nothing below re-derives either.
	manifest, err := archive.Decode(raw)
	if err != nil {
		return nil, err
	}
	// The key says which archive was asked for; the header says which archive
	// arrived. A disagreement is a store returning the wrong object under a
	// derived key, which is a data-integrity event, not a miss.
	volume, volumeOK := uuidBytes(volumeID)
	sealedAttempt, attemptOK := uuidBytes(attempt)
	if !volumeOK || !attemptOK {
		return nil, fmt.Errorf("%w: archive identity is not a canonical UUID", archivestore.ErrInvalid)
	}
	if manifest.Header.VolumeID != volume || manifest.Header.Attempt != sealedAttempt || manifest.Header.SealedEpoch != epoch {
		return nil, fmt.Errorf("%w: manifest at %q describes a different archive attempt", archive.ErrInvalid, key)
	}
	start, order := indexChildren(manifest)
	return &archivedManifest{manifest: manifest, childStart: start, childOrder: order, footprint: manifestFootprint(manifest)}, nil
}

// manifestObjectName and packObjectName mirror the archiver's pinned key
// components (internal/archiver/sealed.go); the archive is never listed, so
// these derivations are the only way into an attempt's objects.
const manifestObjectName = "manifest"

func packObjectName(index uint32) string { return fmt.Sprintf("pack-%06d", index) }

// uuidBytes parses the lowercase canonical UUID form the key grammar accepts
// into the raw 16 bytes the manifest header carries.
func uuidBytes(value string) ([16]byte, bool) {
	var out [16]byte
	if len(value) != 36 {
		return out, false
	}
	position := 0
	for index := 0; index < len(value); index++ {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if value[index] != '-' {
				return out, false
			}
			continue
		}
		digit, ok := hexDigit(value[index])
		if !ok {
			return out, false
		}
		if position%2 == 0 {
			out[position/2] = digit << 4
		} else {
			out[position/2] |= digit
		}
		position++
	}
	return out, position == 32
}

func hexDigit(character byte) (byte, bool) {
	switch {
	case character >= '0' && character <= '9':
		return character - '0', true
	case character >= 'a' && character <= 'f':
		return character - 'a' + 10, true
	default:
		return 0, false
	}
}

func (s *server) serveArchivedEntries(writer http.ResponseWriter, request *http.Request, claims tokenClaims, parentKey, cursorToken, knownRevision, retainedCursor string, limit int) {
	gateway := s.archive
	if gateway == nil {
		writeArchiveUnconfigured(writer)
		return
	}
	if !acquireOperation(request.Context(), s.operations) {
		writeError(writer, http.StatusServiceUnavailable, "busy", "Files service is busy")
		return
	}
	defer releaseOperation(s.operations)
	sealed, err := gateway.manifest(request.Context(), claims.VolumeID, claims.SealedEpoch, claims.Attempt)
	if err != nil {
		writeArchiveError(writer, claims.VolumeID, err)
		return
	}
	parentIndex, err := sealed.resolve(parentKey)
	if err != nil {
		writeArchivedPathError(writer, err)
		return
	}
	if sealed.manifest.Entries[parentIndex].Type != archive.TypeDirectory {
		writeError(writer, http.StatusBadRequest, "invalid_path", "directory key is invalid")
		return
	}
	children := sealed.children(parentIndex)
	offset := 0
	if cursorToken != "" {
		decoded, ok := decodeArchivedCursor(cursorToken, claims, parentKey, parentIndex)
		if !ok || decoded > len(children) {
			writeError(writer, http.StatusConflict, "cursor_expired", "directory cursor expired; list the directory again")
			return
		}
		offset = decoded
	}
	end := min(offset+limit, len(children))
	page := children[offset:end]
	revision := archivedPageRevision(sealed, parentKey, parentIndex, page)
	next := ""
	if end < len(children) {
		next = encodeArchivedCursor(claims, parentKey, parentIndex, end)
	}
	// A sealed archive cannot change, so revalidation is exact: an unchanged
	// page is one whose revision matches and whose continuation is the very
	// cursor the caller retained. The stateless cursor makes retention free —
	// there is nothing to renew and nothing to drop.
	unchanged := knownRevision == revision && (retainedCursor != "" && retainedCursor == next || retainedCursor == "" && next == "")
	entries := make([]map[string]any, 0, len(page))
	if !unchanged {
		for _, index := range page {
			entry := &sealed.manifest.Entries[index]
			key, keyErr := readonlyfs.AppendPath(parentKey, entry.Name)
			if keyErr != nil {
				writeError(writer, http.StatusBadRequest, "invalid_path", "directory contains an entry whose path key exceeds its bound")
				return
			}
			entries = append(entries, map[string]any{
				"executable": entry.Mode&0o111 != 0, "hidden": len(entry.Name) > 0 && entry.Name[0] == '.',
				"key": key, "kind": archivedKind(entry.Type), "mode": entry.Mode & 0o7777,
				"modifiedAt": time.Unix(0, entry.MTimeNanos).UTC().Format(time.RFC3339Nano), "name": displayName(entry.Name),
				"nameBytes": base64.RawURLEncoding.EncodeToString(entry.Name), "sizeBytes": entry.Size,
			})
		}
	}
	payload := map[string]any{"cursor": nil, "entries": entries, "parentKey": parentKey, "revision": revision}
	if next != "" {
		payload["cursor"] = next
	}
	writeJSON(writer, http.StatusOK, payload)
}

func (s *server) serveArchivedContent(writer http.ResponseWriter, request *http.Request, claims tokenClaims, fileKey, mode string, offset, length uint64) {
	gateway := s.archive
	if gateway == nil {
		writeArchiveUnconfigured(writer)
		return
	}
	pool := s.operations
	if mode == "download" {
		pool = s.downloads
	}
	if !acquireOperation(request.Context(), pool) {
		writeError(writer, http.StatusServiceUnavailable, "busy", "Files service is busy")
		return
	}
	defer releaseOperation(pool)
	if !acquireOperation(request.Context(), gateway.content) {
		writeError(writer, http.StatusServiceUnavailable, "busy", "Files service is busy")
		return
	}
	defer releaseOperation(gateway.content)
	sealed, err := gateway.manifest(request.Context(), claims.VolumeID, claims.SealedEpoch, claims.Attempt)
	if err != nil {
		writeArchiveError(writer, claims.VolumeID, err)
		return
	}
	entryIndex, err := sealed.resolve(fileKey)
	if err != nil {
		writeArchivedPathError(writer, err)
		return
	}
	entry := &sealed.manifest.Entries[entryIndex]
	if entry.Type != archive.TypeRegular {
		// Symlinks and directories are listed but never opened, as in live mode,
		// where the authority answers a non-file open with EISDIR.
		writeArchivedPathError(writer, syscall.EISDIR)
		return
	}
	if offset > entry.Size {
		writeError(writer, http.StatusRequestedRangeNotSatisfiable, "invalid_range", "content offset exceeds file size")
		return
	}
	remaining := entry.Size - offset
	if length != 0 && length < remaining {
		remaining = length
	}
	content, err := gateway.openContent(request.Context(), sealed, claims, entryIndex, offset, remaining)
	if err != nil {
		writeArchiveError(writer, claims.VolumeID, err)
		return
	}
	first := make([]byte, min(remaining, 32<<10))
	read, err := content.readAt(first, offset)
	if err != nil {
		writeArchiveError(writer, claims.VolumeID, err)
		return
	}
	first = first[:read]
	writer.Header().Set("Content-Type", http.DetectContentType(first))
	// The archive is immutable, so the entry's content digest is a complete and
	// permanently stable validator.
	writer.Header().Set("ETag", `"`+base64.RawURLEncoding.EncodeToString(entry.ContentDigest[:])+`"`)
	writer.Header().Set("X-Opensteer-File-Size", strconv.FormatUint(entry.Size, 10))
	writer.Header().Set("X-Opensteer-File-Truncated", strconv.FormatBool(offset+remaining < entry.Size))
	writer.Header().Set("Last-Modified", time.Unix(0, entry.MTimeNanos).UTC().Format(http.TimeFormat))
	writer.WriteHeader(http.StatusOK)
	if _, err := writer.Write(first); err != nil {
		return
	}
	position := offset + uint64(len(first))
	buffer := make([]byte, 64<<10)
	for position < offset+remaining {
		want := min(uint64(len(buffer)), offset+remaining-position)
		read, err = content.readAt(buffer[:want], position)
		if read > 0 {
			if _, writeErr := writer.Write(buffer[:read]); writeErr != nil {
				return
			}
			position += uint64(read)
		}
		if err != nil {
			// The response is already committed; a truncated body is all this
			// can be, so the failure is logged rather than re-reported.
			log.Printf("portablefs-files: archived download for volume %s ended early: %v", claims.VolumeID, err)
			return
		}
		if read == 0 {
			return
		}
	}
}

// archivedContent reconstructs one file's logical bytes out of the sealed
// packs. Every byte it returns has been verified: the frame against its
// recorded length and checksum, and each chunk slice against its SHA-256.
type archivedContent struct {
	reader      *archive.PackReader
	chunks      int
	chunkSize   uint64
	entryIndex  uint32
	loadedChunk int
	chunk       []byte
}

func (g *archiveGateway) openContent(ctx context.Context, sealed *archivedManifest, claims tokenClaims, entryIndex uint32, offset, length uint64) (*archivedContent, error) {
	entry := &sealed.manifest.Entries[entryIndex]
	chunkSize := uint64(sealed.manifest.Header.ChunkSizeBytes)
	frames := make([]uint32, 0, 8)
	if length > 0 {
		first := int(offset / chunkSize)
		last := int((offset + length - 1) / chunkSize)
		for index := first; index <= last && index < len(entry.Chunks); index++ {
			if chunk := entry.Chunks[index]; chunk.Stored() {
				frames = append(frames, chunk.FrameIndex)
			}
		}
	}
	ranges, err := sealed.manifest.CoalesceFrames(frames, archive.RangePolicy{MaxGapBytes: archiveRangeGap, MaxRangeBytes: archiveRangeMaximum})
	if err != nil {
		return nil, err
	}
	planned := uint64(0)
	for _, byteRange := range ranges {
		if byteRange.Length > maximumArchiveRangeBytes {
			return nil, fmt.Errorf("%w: a single pack range of %d bytes is past the gateway bound", archive.ErrInvalid, byteRange.Length)
		}
		planned += byteRange.Length
	}
	if planned > maximumArchiveFetch {
		return nil, fmt.Errorf("%w: %d bytes against a budget of %d", errArchiveBudget, planned, uint64(maximumArchiveFetch))
	}
	source := &rangedPackSource{
		ctx: ctx, store: g.store, volumeID: claims.VolumeID, epoch: claims.SealedEpoch, attempt: claims.Attempt,
		ranges: ranges, budget: maximumArchiveFetch, loaded: -1,
	}
	reader, err := archive.NewPackReader(sealed.manifest, source)
	if err != nil {
		return nil, err
	}
	return &archivedContent{reader: reader, chunks: len(entry.Chunks), chunkSize: chunkSize, entryIndex: entryIndex, loadedChunk: -1}, nil
}

// readAt fills destination from the file's logical bytes at offset, holes read
// as zeros. It holds one chunk at a time, which is what keeps a download of an
// arbitrarily large file inside a bounded working set.
func (c *archivedContent) readAt(destination []byte, offset uint64) (int, error) {
	written := 0
	for written < len(destination) {
		position := offset + uint64(written)
		chunkIndex := int(position / c.chunkSize)
		if chunkIndex >= c.chunks {
			return written, nil
		}
		if c.loadedChunk != chunkIndex {
			span, err := c.reader.ReadChunkLogical(c.entryIndex, chunkIndex)
			if err != nil {
				return written, err
			}
			c.chunk, c.loadedChunk = span, chunkIndex
		}
		inner := position - uint64(chunkIndex)*c.chunkSize
		if inner >= uint64(len(c.chunk)) {
			return written, nil
		}
		written += copy(destination[written:], c.chunk[inner:])
	}
	return written, nil
}

// rangedPackSource serves the format's pack reads from the archive store. It is
// request-scoped — it carries the request context because PackSource takes none
// — and holds exactly one coalesced range at a time.
type rangedPackSource struct {
	ctx      context.Context
	store    *archivestore.Client
	volumeID string
	epoch    uint64
	attempt  string
	ranges   []archive.ByteRange
	budget   int64
	fetched  int64
	loaded   int
	bytes    []byte
}

func (p *rangedPackSource) ReadPackRange(index uint32, offset, length uint64) ([]byte, error) {
	position := -1
	for candidate := range p.ranges {
		planned := p.ranges[candidate]
		if planned.PackIndex == index && offset >= planned.Offset && offset+length <= planned.End() {
			position = candidate
			break
		}
	}
	if position < 0 {
		return nil, fmt.Errorf("%w: pack %d range [%d,%d) was not planned for this request", archive.ErrInvalid, index, offset, offset+length)
	}
	if position != p.loaded {
		planned := p.ranges[position]
		if p.fetched+int64(planned.Length) > p.budget {
			return nil, fmt.Errorf("%w: refetching pack ranges passed the budget of %d", errArchiveBudget, p.budget)
		}
		key, err := p.store.KeyFor(p.volumeID, p.epoch, p.attempt, packObjectName(planned.PackIndex))
		if err != nil {
			return nil, err
		}
		stream, err := p.store.GetObjectRange(p.ctx, key, int64(planned.Offset), int64(planned.Length))
		if err != nil {
			return nil, err
		}
		buffer := make([]byte, planned.Length)
		_, err = io.ReadFull(stream, buffer)
		_ = stream.Close()
		if err != nil {
			return nil, err
		}
		p.bytes, p.loaded = buffer, position
		p.fetched += int64(planned.Length)
	}
	start := offset - p.ranges[position].Offset
	return p.bytes[start : start+length], nil
}

func archivedKind(entryType archive.EntryType) readonlyfs.Kind {
	switch entryType {
	case archive.TypeDirectory:
		return readonlyfs.KindDirectory
	case archive.TypeSymlink:
		return readonlyfs.KindSymlink
	case archive.TypeRegular:
		return readonlyfs.KindFile
	default:
		return readonlyfs.KindOpaque
	}
}

// archivedPageRevision digests exactly what the page reports, as live mode's
// pageRevision does, so a caller's revalidation logic is identical in both
// modes. The entry index stands in for the inode: it is the immutable identity
// of a node inside one sealed attempt.
func archivedPageRevision(sealed *archivedManifest, parentKey string, parentIndex uint32, page []uint32) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte(parentKey))
	writeArchivedEntryDigest(digest, sealed, parentIndex)
	for _, index := range page {
		_, _ = digest.Write(sealed.manifest.Entries[index].Name)
		writeArchivedEntryDigest(digest, sealed, index)
	}
	return base64.RawURLEncoding.EncodeToString(digest.Sum(nil))
}

func writeArchivedEntryDigest(writer io.Writer, sealed *archivedManifest, index uint32) {
	entry := &sealed.manifest.Entries[index]
	var values [28]byte
	binary.BigEndian.PutUint32(values[0:4], index)
	binary.BigEndian.PutUint64(values[4:12], entry.Size)
	binary.BigEndian.PutUint64(values[12:20], uint64(entry.MTimeNanos))
	binary.BigEndian.PutUint32(values[20:24], entry.Mode)
	binary.BigEndian.PutUint32(values[24:28], uint32(entry.Type))
	_, _ = writer.Write(values[:])
	_, _ = writer.Write(entry.ContentDigest[:])
}

// encodeArchivedCursor and decodeArchivedCursor implement the stateless
// directory cursor: the next child offset, plus a digest binding it to the
// archive identity and the parent directory it was issued for. It is the same
// binding the live cursor registry checks (volume, parent, session) with the
// session replaced by the immutable archive attempt.
func encodeArchivedCursor(claims tokenClaims, parentKey string, parentIndex uint32, offset int) string {
	var raw [archivedCursorBytes]byte
	binary.BigEndian.PutUint32(raw[0:4], uint32(offset))
	binary.BigEndian.PutUint32(raw[4:8], parentIndex)
	binding := archivedCursorBinding(claims, parentKey, parentIndex)
	copy(raw[8:], binding[:8])
	return base64.RawURLEncoding.EncodeToString(raw[:])
}

func decodeArchivedCursor(token string, claims tokenClaims, parentKey string, parentIndex uint32) (int, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != archivedCursorBytes {
		return 0, false
	}
	if binary.BigEndian.Uint32(raw[4:8]) != parentIndex {
		return 0, false
	}
	binding := archivedCursorBinding(claims, parentKey, parentIndex)
	if !bytes.Equal(raw[8:], binding[:8]) {
		return 0, false
	}
	return int(binary.BigEndian.Uint32(raw[0:4])), true
}

func archivedCursorBinding(claims tokenClaims, parentKey string, parentIndex uint32) [32]byte {
	digest := sha256.New()
	_, _ = digest.Write([]byte("portablefs-files archived cursor\x00"))
	_, _ = digest.Write([]byte(claims.VolumeID))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(strconv.FormatUint(claims.SealedEpoch, 10)))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(claims.Attempt))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(parentKey))
	_, _ = digest.Write([]byte{0})
	var index [4]byte
	binary.BigEndian.PutUint32(index[:], parentIndex)
	_, _ = digest.Write(index[:])
	var out [32]byte
	copy(out[:], digest.Sum(nil))
	return out
}

func writeArchiveUnconfigured(writer http.ResponseWriter) {
	writeError(writer, http.StatusServiceUnavailable, "archive_unconfigured",
		"Files service has no archive-store configuration; archived Workspaces cannot be served")
}

func writeArchivedPathError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, syscall.ENOENT):
		writeError(writer, http.StatusNotFound, "not_found", "PortableFS could not complete the file request")
	default:
		writeError(writer, http.StatusBadRequest, "invalid_path", "PortableFS could not complete the file request")
	}
}

// writeArchiveError maps every archived-mode failure onto the two shapes the
// product driver understands: a retryable unavailability, and a loud
// data-integrity event. Neither leaks store detail into the response.
func writeArchiveError(writer http.ResponseWriter, volumeID string, err error) {
	var storeError *archivestore.Error
	switch {
	case errors.Is(err, archivestore.ErrInvalid):
		// A local addressing fault: the token's epoch or attempt is not one this
		// key grammar can derive a key from.
		writeError(writer, http.StatusBadRequest, "invalid_request", "archive addressing claims are invalid")
	case errors.Is(err, errArchiveBudget):
		writeError(writer, http.StatusRequestEntityTooLarge, "archive_range_too_large",
			"this file needs more archived bytes than one Files request may fetch")
	case errors.Is(err, errArchiveCapacity):
		log.Printf("portablefs-files: archive manifest for volume %s exceeds the decoded budget: %v", volumeID, err)
		writeError(writer, http.StatusServiceUnavailable, "archive_capacity", "Files service cannot hold this Workspace's sealed manifest")
	case errors.Is(err, archive.ErrFrameCorrupt) || errors.Is(err, archive.ErrInvalid):
		log.Printf("portablefs-files: ARCHIVE CORRUPT for volume %s: %v", volumeID, err)
		writeError(writer, http.StatusBadGateway, "archive_corrupt", "sealed archive content failed verification")
	case errors.As(err, &storeError):
		log.Printf("portablefs-files: archive store failure for volume %s: %v", volumeID, err)
		writeError(writer, http.StatusBadGateway, "archive_unavailable", "sealed archive is temporarily unreachable")
	case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
		writeError(writer, http.StatusGatewayTimeout, "timeout", "PortableFS could not complete the file request")
	default:
		log.Printf("portablefs-files: archive failure for volume %s: %v", volumeID, err)
		writeError(writer, http.StatusBadGateway, "archive_unavailable", "sealed archive is temporarily unreachable")
	}
}
