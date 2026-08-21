package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/steerlabs/portablefs/vcs/archive"
	"github.com/steerlabs/portablefs/vcs/internal/archivestore"
	"github.com/steerlabs/portablefs/vcs/readonlyfs"
)

const (
	testAttempt     = "7b1d9e40-1c2f-4a63-8f0e-2d5c6b7a9e01"
	testSealedEpoch = 12
	testBucket      = "portablefs-archive-test"
	testKeyPrefix   = "cell-a"
	testChunkSize   = 4096
)

// fakeS3 is a byte-map object store. archivestore signs every request; this
// server simply ignores the Authorization header, which is all a gateway test
// needs — the signing itself is proved by archivestore's own suite.
type fakeS3 struct {
	mu      sync.Mutex
	objects map[string][]byte
	gets    map[string]int
}

func newFakeS3() *fakeS3 {
	return &fakeS3{objects: make(map[string][]byte), gets: make(map[string]int)}
}

func (f *fakeS3) put(key string, payload []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[key] = append([]byte(nil), payload...)
}

func (f *fakeS3) object(key string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	payload, ok := f.objects[key]
	return payload, ok
}

func (f *fakeS3) getCount(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gets[key]
}

func (f *fakeS3) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	key := strings.TrimPrefix(request.URL.Path, "/"+testBucket+"/")
	object, ok := f.object(key)
	if !ok {
		writer.WriteHeader(http.StatusNotFound)
		_, _ = writer.Write([]byte(`<?xml version="1.0"?><Error><Code>NoSuchKey</Code><Message>no such key</Message></Error>`))
		return
	}
	f.mu.Lock()
	f.gets[key]++
	f.mu.Unlock()
	if request.Method == http.MethodHead {
		writer.Header().Set("Content-Length", strconv.Itoa(len(object)))
		writer.WriteHeader(http.StatusOK)
		return
	}
	if header := request.Header.Get("Range"); header != "" {
		var first, last int
		if _, err := fmt.Sscanf(header, "bytes=%d-%d", &first, &last); err != nil || first < 0 || last < first || last >= len(object) {
			writer.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}
		slice := object[first : last+1]
		writer.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", first, last, len(object)))
		writer.Header().Set("Content-Length", strconv.Itoa(len(slice)))
		writer.WriteHeader(http.StatusPartialContent)
		_, _ = writer.Write(slice)
		return
	}
	writer.Header().Set("Content-Length", strconv.Itoa(len(object)))
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(object)
}

type memorySink struct{ packs [][]byte }

type memoryPack struct {
	owner  *memorySink
	index  uint32
	buffer bytes.Buffer
}

func (p *memoryPack) Write(payload []byte) (int, error) { return p.buffer.Write(payload) }

func (p *memoryPack) Close() error {
	p.owner.packs[p.index] = append([]byte(nil), p.buffer.Bytes()...)
	return nil
}

func (m *memorySink) OpenPack(index uint32) (io.WriteCloser, error) {
	if int(index) != len(m.packs) {
		return nil, fmt.Errorf("packs opened out of order: got %d, have %d", index, len(m.packs))
	}
	m.packs = append(m.packs, nil)
	return &memoryPack{owner: m, index: index}, nil
}

// sealedTree is the tree the archived tests browse, plus the logical bytes each
// file must read back as.
type sealedTree struct {
	notes  []byte
	data   []byte
	sparse []byte
}

func newSealedTree() sealedTree {
	data := make([]byte, 10000)
	for index := range data {
		data[index] = byte(index*31 + index/7)
	}
	sparse := make([]byte, 8192)
	copy(sparse[4096:], []byte("only these bytes are allocated!!"))
	return sealedTree{notes: []byte("hello from the sealed archive\n"), data: data, sparse: sparse}
}

func buildSealedArchive(t *testing.T, tree sealedTree) (*archive.Manifest, [][]byte) {
	t.Helper()
	volume, ok := uuidBytes(testVolume)
	if !ok {
		t.Fatal("test volume is not a canonical UUID")
	}
	attempt, ok := uuidBytes(testAttempt)
	if !ok {
		t.Fatal("test attempt is not a canonical UUID")
	}
	notes := &archive.MemoryFile{Logical: tree.notes, Data: []archive.Extent{{Offset: 0, Length: uint64(len(tree.notes))}}}
	data := &archive.MemoryFile{Logical: tree.data, Data: []archive.Extent{{Offset: 0, Length: uint64(len(tree.data))}}}
	// One chunk lies wholly inside a hole and stores nothing; the next stores a
	// single extent. Both must read back as the logical image, holes as zeros.
	sparse := &archive.MemoryFile{Logical: tree.sparse, Data: []archive.Extent{{Offset: 4096, Length: 32}}}
	entries := []archive.SourceEntry{
		{ParentIndex: 0, Type: archive.TypeDirectory, Mode: 0o755, MTimeNanos: 1_700_000_000_000_000_000, Nlink: 2},
		{ParentIndex: 0, Name: []byte("notes.txt"), Type: archive.TypeRegular, Size: uint64(len(tree.notes)),
			Mode: 0o644, MTimeNanos: 1_700_000_001_000_000_000, Nlink: 1,
			Open: func() (archive.SourceFile, error) { return notes, nil }},
		{ParentIndex: 0, Name: []byte("readme.link"), Type: archive.TypeSymlink, Size: uint64(len("notes.txt")),
			Mode: 0o777, MTimeNanos: 1_700_000_002_000_000_000, LinkName: []byte("notes.txt"), Nlink: 1},
		{ParentIndex: 0, Name: []byte("sub"), Type: archive.TypeDirectory, Mode: 0o755, MTimeNanos: 1_700_000_003_000_000_000, Nlink: 2},
		{ParentIndex: 3, Name: []byte("data.bin"), Type: archive.TypeRegular, Size: uint64(len(tree.data)),
			Mode: 0o755, MTimeNanos: 1_700_000_004_000_000_000, Nlink: 1,
			Open: func() (archive.SourceFile, error) { return data, nil }},
		{ParentIndex: 3, Name: []byte("sparse.bin"), Type: archive.TypeRegular, Size: uint64(len(tree.sparse)),
			Mode: 0o644, MTimeNanos: 1_700_000_005_000_000_000, Nlink: 1,
			Open: func() (archive.SourceFile, error) { return sparse, nil }},
	}
	config := archive.DefaultBuilderConfig()
	config.ChunkSizeBytes = testChunkSize
	config.PackTargetBytes = 1 << 20
	config.VolumeID = volume
	config.SealedEpoch = testSealedEpoch
	config.Attempt = attempt
	sink := &memorySink{}
	manifest, err := archive.Build(config, archive.NewSliceSource(entries), sink)
	if err != nil {
		t.Fatal(err)
	}
	return manifest, sink.packs
}

// newArchivedService stands up the gateway over a fake archive store holding
// one sealed archive of the tree above.
func newArchivedService(t *testing.T) (*server, ed25519.PrivateKey, *fakeS3, sealedTree) {
	t.Helper()
	tree := newSealedTree()
	manifest, packs := buildSealedArchive(t, tree)
	encoded, err := archive.Encode(manifest)
	if err != nil {
		t.Fatal(err)
	}
	store := newFakeS3()
	store.put(testObjectKey(t, "manifest"), encoded)
	for index, pack := range packs {
		store.put(testObjectKey(t, packObjectName(uint32(index))), pack)
	}
	origin := httptest.NewServer(store)
	t.Cleanup(origin.Close)
	client, err := archivestore.New(archivestore.Config{
		Endpoint: origin.URL, Region: "us-east-1", Bucket: testBucket, KeyPrefix: testKeyPrefix,
		AccessKeyID: "AKIAEXAMPLEKEYID", SecretAccessKey: "example-secret", ChecksumCapability: archivestore.ChecksumNone,
		PathStyle: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	public, private := testKeys(t)
	service := newTestServer(t, public, (&fakeDialer{}).dial)
	service.archive = newArchiveGatewayFor(client, defaultArchivedManifests)
	return service, private, store, tree
}

func testObjectKey(t *testing.T, object string) string {
	t.Helper()
	key, err := archivestore.KeyFor(testKeyPrefix, testVolume, testSealedEpoch, testAttempt, object)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func archivedClaims(claims tokenClaims) tokenClaims {
	claims.VolumeID = testVolume
	claims.Archived = true
	claims.SealedEpoch = testSealedEpoch
	claims.Attempt = testAttempt
	return claims
}

func pathKey(t *testing.T, components ...string) string {
	t.Helper()
	raw := make([][]byte, 0, len(components))
	for _, component := range components {
		raw = append(raw, []byte(component))
	}
	key, err := readonlyfs.EncodePath(raw)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func archivedList(t *testing.T, service *server, private ed25519.PrivateKey, parentKey, cursor, revision, retain string, limit int) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	query := "parent=" + parentKey + "&limit=" + strconv.Itoa(limit)
	if cursor != "" {
		query += "&cursor=" + cursor
	}
	if revision != "" {
		query += "&revision=" + revision
	}
	if retain != "" {
		query += "&retain=" + retain
	}
	request := signedRequest(t, private, http.MethodGet, "/v1/volumes/"+testVolume+"/entries?"+query, archivedClaims(tokenClaims{
		Operation: "list", PathKey: parentKey, Cursor: cursor, KnownRevision: revision, RetainedCursor: retain, Limit: uint64(limit),
	}), nil)
	recorder := httptest.NewRecorder()
	service.routes().ServeHTTP(recorder, request)
	payload := map[string]any{}
	if recorder.Code == http.StatusOK {
		if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
			t.Fatal(err)
		}
	}
	return recorder, payload
}

func archivedContentRequest(t *testing.T, service *server, private ed25519.PrivateKey, fileKey, mode string, offset, length uint64) *httptest.ResponseRecorder {
	t.Helper()
	target := fmt.Sprintf("/v1/volumes/%s/content?file=%s&length=%d&mode=%s&offset=%d", testVolume, fileKey, length, mode, offset)
	request := signedRequest(t, private, http.MethodGet, target, archivedClaims(tokenClaims{
		Operation: mode, PathKey: fileKey, Offset: offset, Length: length,
	}), nil)
	recorder := httptest.NewRecorder()
	service.routes().ServeHTTP(recorder, request)
	return recorder
}

func entryNames(t *testing.T, payload map[string]any) []string {
	t.Helper()
	raw, ok := payload["entries"].([]any)
	if !ok {
		t.Fatalf("payload has no entries: %v", payload)
	}
	names := make([]string, 0, len(raw))
	for _, value := range raw {
		entry, ok := value.(map[string]any)
		if !ok {
			t.Fatalf("entry is not an object: %v", value)
		}
		names = append(names, entry["name"].(string))
	}
	return names
}

func TestArchivedListingServesDirectoryPagesFromTheManifest(t *testing.T) {
	service, private, store, _ := newArchivedService(t)
	recorder, payload := archivedList(t, service, private, "", "", "", "", 200)
	if recorder.Code != http.StatusOK {
		t.Fatalf("archived list = %d (%s)", recorder.Code, recorder.Body.String())
	}
	if names := entryNames(t, payload); strings.Join(names, ",") != "notes.txt,readme.link,sub" {
		t.Fatalf("root listing = %v", names)
	}
	if payload["cursor"] != nil || payload["parentKey"] != "" || payload["revision"] == "" {
		t.Fatalf("root page shape = %v", payload)
	}
	entries := payload["entries"].([]any)
	notes := entries[0].(map[string]any)
	if notes["kind"] != string(readonlyfs.KindFile) || notes["sizeBytes"].(float64) != 30 || notes["executable"] != false || notes["hidden"] != false {
		t.Fatalf("notes.txt entry = %v", notes)
	}
	if notes["key"] != pathKey(t, "notes.txt") || notes["nameBytes"] != base64.RawURLEncoding.EncodeToString([]byte("notes.txt")) {
		t.Fatalf("notes.txt keys = %v", notes)
	}
	if notes["mode"].(float64) != 0o644 || notes["modifiedAt"] == nil {
		t.Fatalf("notes.txt attributes = %v", notes)
	}
	if entries[1].(map[string]any)["kind"] != string(readonlyfs.KindSymlink) || entries[2].(map[string]any)["kind"] != string(readonlyfs.KindDirectory) {
		t.Fatalf("kinds = %v", entries)
	}

	// A second listing reuses the cached manifest rather than downloading it.
	if _, _ = archivedList(t, service, private, pathKey(t, "sub"), "", "", "", 200); store.getCount(testObjectKey(t, "manifest")) != 1 {
		t.Fatalf("manifest was fetched %d times, want one bounded fetch", store.getCount(testObjectKey(t, "manifest")))
	}
	_, subPayload := archivedList(t, service, private, pathKey(t, "sub"), "", "", "", 200)
	if names := entryNames(t, subPayload); strings.Join(names, ",") != "data.bin,sparse.bin" {
		t.Fatalf("sub listing = %v", names)
	}
}

func TestArchivedListingPaginatesAndRevalidatesLikeLiveMode(t *testing.T) {
	service, private, _, _ := newArchivedService(t)
	_, first := archivedList(t, service, private, "", "", "", "", 1)
	if names := entryNames(t, first); strings.Join(names, ",") != "notes.txt" {
		t.Fatalf("first page = %v", names)
	}
	cursor, ok := first["cursor"].(string)
	if !ok || cursor == "" {
		t.Fatalf("first page carried no cursor: %v", first)
	}
	_, second := archivedList(t, service, private, "", cursor, "", "", 1)
	if names := entryNames(t, second); strings.Join(names, ",") != "readme.link" {
		t.Fatalf("second page = %v", names)
	}
	_, third := archivedList(t, service, private, "", second["cursor"].(string), "", "", 1)
	if names := entryNames(t, third); strings.Join(names, ",") != "sub" {
		t.Fatalf("third page = %v", names)
	}
	if third["cursor"] != nil {
		t.Fatalf("last page carried a cursor: %v", third)
	}

	// Revalidation of an unchanged page returns no entries and the same
	// continuation, exactly as the live path does for an unchanged directory.
	_, unchanged := archivedList(t, service, private, "", "", first["revision"].(string), cursor, 1)
	if len(unchanged["entries"].([]any)) != 0 || unchanged["cursor"] != cursor || unchanged["revision"] != first["revision"] {
		t.Fatalf("revalidated page = %v", unchanged)
	}

	// A cursor issued for one directory is not a cursor for another.
	recorder, _ := archivedList(t, service, private, pathKey(t, "sub"), cursor, "", "", 1)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("cross-directory cursor = %d, want 409", recorder.Code)
	}
}

func TestArchivedPreviewAndDownloadReconstructSealedContent(t *testing.T) {
	service, private, _, tree := newArchivedService(t)
	preview := archivedContentRequest(t, service, private, pathKey(t, "notes.txt"), "preview", 0, previewMaximum)
	if preview.Code != http.StatusOK {
		t.Fatalf("archived preview = %d (%s)", preview.Code, preview.Body.String())
	}
	if !bytes.Equal(preview.Body.Bytes(), tree.notes) {
		t.Fatalf("preview body = %q", preview.Body.String())
	}
	digest := sha256.Sum256(tree.notes)
	if preview.Header().Get("ETag") != `"`+base64.RawURLEncoding.EncodeToString(digest[:])+`"` {
		t.Fatalf("preview ETag = %s", preview.Header().Get("ETag"))
	}
	if preview.Header().Get("X-Opensteer-File-Size") != strconv.Itoa(len(tree.notes)) || preview.Header().Get("X-Opensteer-File-Truncated") != "false" {
		t.Fatalf("preview headers = %v", preview.Header())
	}
	if preview.Header().Get("Last-Modified") == "" || preview.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("preview headers = %v", preview.Header())
	}

	// A whole-file download crosses chunk and frame boundaries.
	download := archivedContentRequest(t, service, private, pathKey(t, "sub", "data.bin"), "download", 0, 0)
	if download.Code != http.StatusOK {
		t.Fatalf("archived download = %d (%s)", download.Code, download.Body.String())
	}
	if !bytes.Equal(download.Body.Bytes(), tree.data) {
		t.Fatalf("download returned %d bytes, want %d", download.Body.Len(), len(tree.data))
	}

	// Holes read back as zeros, including a chunk that stores nothing at all.
	sparse := archivedContentRequest(t, service, private, pathKey(t, "sub", "sparse.bin"), "download", 0, 0)
	if sparse.Code != http.StatusOK || !bytes.Equal(sparse.Body.Bytes(), tree.sparse) {
		t.Fatalf("sparse download = %d, %d bytes", sparse.Code, sparse.Body.Len())
	}

	// A bounded window inside the file honours offset and length.
	window := archivedContentRequest(t, service, private, pathKey(t, "sub", "data.bin"), "preview", 4096, 64)
	if window.Code != http.StatusOK || !bytes.Equal(window.Body.Bytes(), tree.data[4096:4160]) {
		t.Fatalf("windowed preview = %d, %q", window.Code, window.Body.String())
	}
	if window.Header().Get("X-Opensteer-File-Truncated") != "true" {
		t.Fatalf("windowed preview truncation = %s", window.Header().Get("X-Opensteer-File-Truncated"))
	}

	// An offset past the end is a range error, as in live mode.
	past := archivedContentRequest(t, service, private, pathKey(t, "notes.txt"), "preview", uint64(len(tree.notes))+1, 16)
	if past.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("out-of-range preview = %d, want 416", past.Code)
	}
}

func TestArchivedSymlinksAndDirectoriesAreListedButNotOpened(t *testing.T) {
	service, private, _, _ := newArchivedService(t)
	for _, key := range []string{pathKey(t, "readme.link"), pathKey(t, "sub")} {
		recorder := archivedContentRequest(t, service, private, key, "preview", 0, 64)
		if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "invalid_path") {
			t.Fatalf("opening %q = %d (%s)", key, recorder.Code, recorder.Body.String())
		}
	}
	missing := archivedContentRequest(t, service, private, pathKey(t, "absent.txt"), "preview", 0, 64)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing file = %d, want 404", missing.Code)
	}
}

func TestArchivedContentFailsLoudlyWhenAPackIsCorrupt(t *testing.T) {
	service, private, store, _ := newArchivedService(t)
	pack, ok := store.object(testObjectKey(t, packObjectName(0)))
	if !ok {
		t.Fatal("the sealed archive has no pack 0")
	}
	store.put(testObjectKey(t, packObjectName(0)), bytes.Repeat([]byte{0xFF}, len(pack)))
	recorder := archivedContentRequest(t, service, private, pathKey(t, "notes.txt"), "preview", 0, previewMaximum)
	if recorder.Code != http.StatusBadGateway || !strings.Contains(recorder.Body.String(), "archive_corrupt") {
		t.Fatalf("corrupt pack = %d (%s), want 502 archive_corrupt", recorder.Code, recorder.Body.String())
	}
}

func TestArchivedManifestMismatchIsAnIntegrityEvent(t *testing.T) {
	service, private, store, tree := newArchivedService(t)
	// A manifest that decodes cleanly but describes another attempt is the
	// store answering a derived key with the wrong object.
	other := newSealedTree()
	other.notes = tree.notes
	manifest, _ := buildSealedArchive(t, other)
	manifest.Header.SealedEpoch = testSealedEpoch + 1
	encoded, err := archive.Encode(manifest)
	if err != nil {
		t.Fatal(err)
	}
	store.put(testObjectKey(t, "manifest"), encoded)
	recorder, _ := archivedList(t, service, private, "", "", "", "", 200)
	if recorder.Code != http.StatusBadGateway || !strings.Contains(recorder.Body.String(), "archive_corrupt") {
		t.Fatalf("mismatched manifest = %d (%s)", recorder.Code, recorder.Body.String())
	}
}

func TestArchivedStoreFailureIsRetryableUnavailability(t *testing.T) {
	service, private, store, _ := newArchivedService(t)
	store.mu.Lock()
	delete(store.objects, testObjectKey(t, "manifest"))
	store.mu.Unlock()
	recorder, _ := archivedList(t, service, private, "", "", "", "", 200)
	if recorder.Code != http.StatusBadGateway || !strings.Contains(recorder.Body.String(), "archive_unavailable") {
		t.Fatalf("missing manifest = %d (%s), want 502 archive_unavailable", recorder.Code, recorder.Body.String())
	}
}

func TestArchivedRequestsAreRefusedWithoutArchiveConfiguration(t *testing.T) {
	public, private := testKeys(t)
	service := newTestServer(t, public, (&fakeDialer{}).dial)
	recorder, _ := archivedList(t, service, private, "", "", "", "", 200)
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "archive_unconfigured") {
		t.Fatalf("unconfigured archived list = %d (%s)", recorder.Code, recorder.Body.String())
	}
	content := archivedContentRequest(t, service, private, pathKey(t, "notes.txt"), "preview", 0, 64)
	if content.Code != http.StatusServiceUnavailable || !strings.Contains(content.Body.String(), "archive_unconfigured") {
		t.Fatalf("unconfigured archived preview = %d (%s)", content.Code, content.Body.String())
	}
}

func TestArchivedClaimsMustCarryTheAddressingTriple(t *testing.T) {
	service, private, _, _ := newArchivedService(t)
	incomplete := []tokenClaims{
		{Operation: "list", VolumeID: testVolume, Archived: true, Limit: 200, Attempt: testAttempt},
		{Operation: "list", VolumeID: testVolume, Archived: true, Limit: 200, SealedEpoch: testSealedEpoch},
		{Operation: "list", VolumeID: testVolume, Archived: true, Limit: 200},
	}
	for _, claims := range incomplete {
		request := signedRequest(t, private, http.MethodGet, "/v1/volumes/"+testVolume+"/entries?parent=&limit=200", claims, nil)
		recorder := httptest.NewRecorder()
		service.routes().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("archived list without addressing claims = %d, want 401", recorder.Code)
		}
	}

	// Addressing claims are equally refused where archived mode is not offered,
	// and archived mode itself is refused on a live-only route.
	request := signedRequest(t, private, http.MethodGet, "/v1/volumes/"+testVolume+"/session", tokenClaims{
		Operation: "session.status", VolumeID: testVolume, SealedEpoch: testSealedEpoch, Attempt: testAttempt,
	}, nil)
	recorder := httptest.NewRecorder()
	service.routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("session status with addressing claims = %d, want 401", recorder.Code)
	}
	request = signedRequest(t, private, http.MethodGet, "/v1/volumes/"+testVolume+"/session", archivedClaims(tokenClaims{
		Operation: "session.status",
	}), nil)
	recorder = httptest.NewRecorder()
	service.routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("archived session status = %d, want 401", recorder.Code)
	}
}

func TestArchivedListingNeedsNoAuthoritySession(t *testing.T) {
	service, private, _, _ := newArchivedService(t)
	recorder, _ := archivedList(t, service, private, "", "", "", "", 200)
	if recorder.Code != http.StatusOK {
		t.Fatalf("archived list = %d", recorder.Code)
	}
	service.mu.Lock()
	live := len(service.sessions)
	service.mu.Unlock()
	if live != 0 {
		t.Fatalf("archived browsing installed %d authority sessions", live)
	}
}
