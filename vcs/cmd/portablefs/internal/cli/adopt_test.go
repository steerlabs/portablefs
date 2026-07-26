package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trendup-ai/portablefs/vcs/internal/treehash"
)

// ---- fake volume-api for adopt ----

// adoptWireEntry mirrors the manifest entry JSON the CLI sends.
type adoptWireEntry struct {
	Path       string `json:"path"`
	Kind       string `json:"kind"`
	Mode       uint32 `json:"mode"`
	Size       int64  `json:"size"`
	MtimeMs    int64  `json:"mtimeMs"`
	Executable bool   `json:"executable"`
	Blob       *struct {
		Digest      string `json:"digest"`
		Size        int64  `json:"size"`
		Compression string `json:"compression"`
		Packed      bool   `json:"packed"`
	} `json:"blob"`
	Chunks []struct {
		Digest string `json:"digest"`
		Size   int64  `json:"size"`
		Offset int64  `json:"offset"`
	} `json:"chunks"`
	LinkTarget string `json:"linkTarget"`
}

type adoptWireCommit struct {
	LeaseID              string `json:"leaseId"`
	FencingToken         int64  `json:"fencingToken"`
	ExpectedHeadCommitID string `json:"expectedHeadCommitId"`
	Manifest             struct {
		Version  string           `json:"version"`
		TreeHash string           `json:"treeHash"`
		Entries  []adoptWireEntry `json:"entries"`
	} `json:"manifest"`
	MutationCount int64 `json:"mutationCount"`
	ByteCount     int64 `json:"byteCount"`
}

// adoptFakeServer is a volume-api double for adopt: it parses the OSVB batch
// framing with the same strictness as the real server, verifies every blob's
// digest, and recomputes the manifest tree hash on commit.
type adoptFakeServer struct {
	t   *testing.T
	srv *httptest.Server

	mu            sync.Mutex
	requests      []string          // "METHOD /path"
	blobs         map[string][]byte // digest -> verified bytes
	batchCount    int
	batchEntries  int
	putCount      int
	attachCalls   int
	commitCalls   int
	detachCalls   int
	activateCalls int
	commit        *adoptWireCommit // last commit body

	// behavior knobs
	createStatus int             // 0 => 201
	noProbeRoute bool            // 404 on /v1/blobs/probe
	probePresent map[string]bool // digests reported as NOT missing
	onProbe      func()          // side effect when probe is called (mutation tests)
	branch       string          // expected branch (default main)
	// history served by GET /v1/volumes/:id/commits; empty = one genesis
	// commit (the stranded-adopt shape).
	historyJSON string
	// historyStatus overrides the commits route's status (0 => 200); the
	// body then comes from historyJSON verbatim (typed error envelopes).
	historyStatus int
	// activateJSON overrides the activate-journal response body (default:
	// immediately active).
	activateJSON string
}

func newAdoptServer(t *testing.T) *adoptFakeServer {
	t.Helper()
	s := &adoptFakeServer{
		t:            t,
		blobs:        map[string][]byte{},
		probePresent: map[string]bool{},
		branch:       "main",
	}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *adoptFakeServer) args(extra ...string) []string {
	return append(extra, "--api-url", s.srv.URL, "--api-token", "tok")
}

func (s *adoptFakeServer) requestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

func sendJSONBody(w http.ResponseWriter, status int, body string) {
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func (s *adoptFakeServer) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	s.requests = append(s.requests, r.Method+" "+r.URL.Path)
	s.mu.Unlock()
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")

	switch {
	case r.Method == "POST" && r.URL.Path == "/v1/volumes":
		if s.createStatus == 409 {
			sendJSONBody(w, 409, `{"error":{"code":"VOLUME_ALREADY_EXISTS","message":"Volume already exists."}}`)
			return
		}
		var req struct {
			VolumeID   string `json:"volumeId"`
			BranchName string `json:"branchName"`
		}
		if err := json.Unmarshal(body, &req); err != nil || req.VolumeID == "" || req.BranchName != s.branch {
			s.t.Errorf("create volume body wrong: %s", body)
			sendJSONBody(w, 400, `{"error":{"code":"BAD","message":"create body"}}`)
			return
		}
		sendJSONBody(w, 201, fmt.Sprintf(
			`{"volume":{"id":%q,"tenantId":"t1","createdAt":1},"branch":{"id":"b1","volumeId":%q,"name":%q,"headCommitId":"cmt_0"},"head":{"id":"cmt_0","treeHash":"sha256:aa"}}`,
			req.VolumeID, req.VolumeID, req.BranchName))

	case r.Method == "GET" && len(parts) == 4 && parts[1] == "volumes" && parts[3] == "commits":
		if s.historyStatus != 0 {
			sendJSONBody(w, s.historyStatus, s.historyJSON)
			return
		}
		history := s.historyJSON
		if history == "" {
			history = `{"commits":[{"id":"cmt_0","treeHash":"sha256:aa","createdAtMs":1,"mutationCount":0,"byteCount":0,"parentCommitId":""}]}`
		}
		sendJSONBody(w, 200, history)

	case r.Method == "POST" && len(parts) == 4 && parts[1] == "volumes" && parts[3] == "attach":
		var req struct {
			Branch     string  `json:"branch"`
			Mode       string  `json:"mode"`
			HolderID   string  `json:"holderId"`
			LeaseTtlMs float64 `json:"leaseTtlMs"`
		}
		if err := json.Unmarshal(body, &req); err != nil || req.Branch != s.branch || req.Mode != "write" ||
			!strings.HasPrefix(req.HolderID, "adopt-") || req.LeaseTtlMs != 600000 {
			s.t.Errorf("attach body wrong: %s", body)
			sendJSONBody(w, 400, `{"error":{"code":"BAD","message":"attach body"}}`)
			return
		}
		s.mu.Lock()
		s.attachCalls++
		s.mu.Unlock()
		sendJSONBody(w, 200, `{"session":{"id":"as_1","baseCommitId":"cmt_0","lease":{"id":"lease_1","fencingToken":7,"expiresAt":99999999999}}}`)

	case r.Method == "POST" && r.URL.Path == "/v1/blobs/probe":
		if s.noProbeRoute {
			sendJSONBody(w, 404, `{"error":{"code":"VOLUME_NOT_FOUND","message":"Route not found."}}`)
			return
		}
		if s.onProbe != nil {
			s.onProbe()
		}
		var req struct {
			Digests []string `json:"digests"`
		}
		if err := json.Unmarshal(body, &req); err != nil || len(req.Digests) == 0 || len(req.Digests) > 4096 {
			s.t.Errorf("probe body wrong: %s", body)
			sendJSONBody(w, 400, `{"error":{"code":"BAD","message":"probe body"}}`)
			return
		}
		var missing []string
		for _, d := range req.Digests {
			if !s.probePresent[d] {
				missing = append(missing, d)
			}
		}
		out, _ := json.Marshal(map[string]any{"missing": missing})
		sendJSONBody(w, 200, string(out))

	case r.Method == "POST" && r.URL.Path == "/v1/blobs/batch-binary":
		entries, ok := s.parseOSVB(body)
		if !ok {
			sendJSONBody(w, 400, `{"error":{"code":"VOLUME_BLOB_BATCH_INVALID","message":"bad framing"}}`)
			return
		}
		var total int64
		s.mu.Lock()
		s.batchCount++
		s.batchEntries += len(entries)
		for d, b := range entries {
			s.blobs[d] = b
			total += int64(len(b))
		}
		s.mu.Unlock()
		if r.URL.Query().Get("response") != "ack" {
			s.t.Errorf("batch-binary must be called with ?response=ack, got %q", r.URL.RawQuery)
		}
		sendJSONBody(w, 201, fmt.Sprintf(`{"count":%d,"bytes":%d}`, len(entries), total))

	case r.Method == "PUT" && len(parts) == 3 && parts[1] == "blobs":
		digest := parts[2]
		sum := sha256.Sum256(body)
		if got := "sha256:" + hex.EncodeToString(sum[:]); got != digest {
			sendJSONBody(w, 400, fmt.Sprintf(`{"error":{"code":"VOLUME_BLOB_DIGEST_MISMATCH","message":"Expected %s, received %s."}}`, digest, got))
			return
		}
		s.mu.Lock()
		s.putCount++
		s.blobs[digest] = append([]byte(nil), body...)
		s.mu.Unlock()
		sendJSONBody(w, 201, fmt.Sprintf(`{"blob":{"digest":%q,"size":%d}}`, digest, len(body)))

	case r.Method == "POST" && len(parts) == 4 && parts[1] == "attach-sessions" && parts[3] == "commit-summary":
		var req adoptWireCommit
		if err := json.Unmarshal(body, &req); err != nil {
			s.t.Errorf("commit body undecodable: %v", err)
			sendJSONBody(w, 400, `{"error":{"code":"BAD","message":"commit body"}}`)
			return
		}
		if msg := s.validateCommit(&req); msg != "" {
			s.t.Errorf("commit invalid: %s", msg)
			sendJSONBody(w, 400, fmt.Sprintf(`{"error":{"code":"BAD","message":%q}}`, msg))
			return
		}
		s.mu.Lock()
		s.commitCalls++
		s.commit = &req
		s.mu.Unlock()
		sendJSONBody(w, 200, fmt.Sprintf(
			`{"commit":{"id":"cmt_adopt","treeHash":%q,"parentCommitId":"cmt_0","mutationCount":%d,"byteCount":%d,"createdAt":2},"branch":{"id":"b1","name":%q,"headCommitId":"cmt_adopt"}}`,
			req.Manifest.TreeHash, req.MutationCount, req.ByteCount, s.branch))

	case r.Method == "POST" && len(parts) == 4 && parts[1] == "attach-sessions" && parts[3] == "detach":
		var req struct {
			ReleaseLease bool `json:"releaseLease"`
		}
		if err := json.Unmarshal(body, &req); err != nil || !req.ReleaseLease {
			s.t.Errorf("detach must send releaseLease:true, got %s", body)
		}
		s.mu.Lock()
		s.detachCalls++
		s.mu.Unlock()
		sendJSONBody(w, 200, `{"session":{"id":"as_1","detachedAt":3}}`)

	case r.Method == "POST" && len(parts) == 4 && parts[1] == "leases" && parts[3] == "renew":
		sendJSONBody(w, 200, `{"lease":{"id":"lease_1","fencingToken":7,"expiresAt":99999999999}}`)

	case r.Method == "POST" && len(parts) == 4 && parts[1] == "volumes" && parts[3] == "activate-journal":
		// Journal activation converges immediately in the fake: adopt calls
		// this after its final commit AND after releasing the authoring
		// session (the managed authority needs the writer lease free).
		s.mu.Lock()
		s.activateCalls++
		detached := s.detachCalls
		s.mu.Unlock()
		if detached == 0 {
			s.t.Errorf("activate-journal called before the authoring session was detached")
		}
		s.mu.Lock()
		activateJSON := s.activateJSON
		s.mu.Unlock()
		if activateJSON != "" {
			sendJSONBody(w, 200, activateJSON)
			return
		}
		sendJSONBody(w, 200, `{"state":"active","branchMode":"managed_journal"}`)

	default:
		sendJSONBody(w, 404, `{"error":{"code":"VOLUME_NOT_FOUND","message":"Route not found."}}`)
	}
}

// parseOSVB reimplements the server's parseBlobBatchBinary strictly, so the
// client framing is validated independently of encodeBlobBatchBinary.
func (s *adoptFakeServer) parseOSVB(body []byte) (map[string][]byte, bool) {
	if len(body) < 8 || string(body[:4]) != "OSVB" {
		s.t.Errorf("blob batch header invalid: % x", body[:min(8, len(body))])
		return nil, false
	}
	version := binary.BigEndian.Uint16(body[4:6])
	count := int(binary.BigEndian.Uint16(body[6:8]))
	if version != 1 {
		s.t.Errorf("blob batch version = %d, want 1", version)
		return nil, false
	}
	if count < 1 || count > 1024 {
		s.t.Errorf("blob batch count = %d, want 1..1024", count)
		return nil, false
	}
	entries := map[string][]byte{}
	offset := 8
	for i := 0; i < count; i++ {
		if offset+6 > len(body) {
			s.t.Errorf("blob batch entry %d truncated", i)
			return nil, false
		}
		digestLen := int(binary.BigEndian.Uint16(body[offset:]))
		size := int(binary.BigEndian.Uint32(body[offset+2:]))
		offset += 6
		if digestLen < 1 || offset+digestLen+size > len(body) {
			s.t.Errorf("blob batch entry %d lengths invalid", i)
			return nil, false
		}
		digest := string(body[offset : offset+digestLen])
		offset += digestLen
		blob := append([]byte(nil), body[offset:offset+size]...)
		offset += size
		sum := sha256.Sum256(blob)
		if got := "sha256:" + hex.EncodeToString(sum[:]); got != digest {
			s.t.Errorf("blob batch entry %d digest mismatch: claimed %s, actual %s", i, digest, got)
			return nil, false
		}
		entries[digest] = blob
	}
	if offset != len(body) {
		s.t.Errorf("blob batch has %d trailing bytes", len(body)-offset)
		return nil, false
	}
	return entries, true
}

// validateCommit checks the lease fields, the protocol version, recomputes the
// tree hash over the received entries, and requires proof of possession for
// every referenced blob — like the real server does.
func (s *adoptFakeServer) validateCommit(req *adoptWireCommit) string {
	if req.LeaseID != "lease_1" || req.FencingToken != 7 {
		return fmt.Sprintf("lease fields wrong: %s/%d", req.LeaseID, req.FencingToken)
	}
	if req.ExpectedHeadCommitID != "cmt_0" {
		return "expectedHeadCommitId must be the attach baseCommitId"
	}
	if req.Manifest.Version != "portablefs-v1" {
		return fmt.Sprintf("manifest version = %q", req.Manifest.Version)
	}
	if req.MutationCount != int64(len(req.Manifest.Entries)) {
		return fmt.Sprintf("mutationCount = %d, entries = %d", req.MutationCount, len(req.Manifest.Entries))
	}
	var hashEntries []treehash.Entry
	var fileBytes int64
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, en := range req.Manifest.Entries {
		if i > 0 && !(req.Manifest.Entries[i-1].Path < en.Path) {
			return fmt.Sprintf("entries not sorted by path at %q", en.Path)
		}
		he := treehash.Entry{
			Path: en.Path, Kind: en.Kind, Mode: en.Mode, Size: en.Size,
			Executable: en.Executable, LinkTarget: en.LinkTarget,
		}
		if en.Kind == "file" {
			if en.Blob == nil {
				return fmt.Sprintf("file entry %q has no blob", en.Path)
			}
			if en.Blob.Compression != "none" || en.Blob.Packed || en.Blob.Size != en.Size {
				return fmt.Sprintf("file entry %q blob ref wrong: %+v", en.Path, *en.Blob)
			}
			if len(en.Chunks) > 0 {
				// Chunked entries reference chunk blobs (like the real server's
				// assertManifestBlobsExist); the whole-file digest is metadata.
				var chunkTotal int64
				for _, ch := range en.Chunks {
					if _, stored := s.blobs[ch.Digest]; !stored && !s.probePresent[ch.Digest] {
						return fmt.Sprintf("file entry %q references unstored chunk %s", en.Path, ch.Digest)
					}
					if ch.Offset != chunkTotal {
						return fmt.Sprintf("file entry %q chunk offset = %d, want %d", en.Path, ch.Offset, chunkTotal)
					}
					chunkTotal += ch.Size
					he.Chunks = append(he.Chunks, treehash.Chunk{Digest: ch.Digest, Size: ch.Size, Offset: ch.Offset})
				}
				if chunkTotal != en.Size {
					return fmt.Sprintf("file entry %q chunks cover %d bytes, size is %d", en.Path, chunkTotal, en.Size)
				}
			} else if _, stored := s.blobs[en.Blob.Digest]; !stored && !s.probePresent[en.Blob.Digest] {
				return fmt.Sprintf("file entry %q references unstored blob %s", en.Path, en.Blob.Digest)
			}
			he.Blob = &treehash.Blob{Digest: en.Blob.Digest, Size: en.Blob.Size, Compression: "none", Packed: false}
			fileBytes += en.Size
		}
		hashEntries = append(hashEntries, he)
	}
	if got := treehash.Compute(hashEntries); got != req.Manifest.TreeHash {
		return fmt.Sprintf("treeHash mismatch: manifest %s, recomputed %s", req.Manifest.TreeHash, got)
	}
	if req.ByteCount != fileBytes {
		return fmt.Sprintf("byteCount = %d, sum of file sizes = %d", req.ByteCount, fileBytes)
	}
	return ""
}

// ---- fixture ----

func sha256Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func writeFixtureFile(t *testing.T, path string, contents []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil { // chmod ignores the umask
		t.Fatal(err)
	}
}

// adoptFixture builds the happy-path tree: nested dirs, an empty dir, a
// zero-byte file, a unicode filename, an executable, an internal symlink, and
// a symlink pointing outside the tree.
func adoptFixture(t *testing.T) (root string, contents map[string][]byte) {
	t.Helper()
	root = t.TempDir()
	contents = map[string][]byte{
		"README.md":           []byte("hello adopt\n"),
		"zero.txt":            {},
		"src/main.go":         []byte("package main\n"),
		"src/nested/data.bin": {0, 1, 2, 253, 254, 255},
		"tools/run.sh":        []byte("#!/bin/sh\necho hi\n"),
		"文档-测试.txt":           []byte("unicode filename\n"),
	}
	for rel, data := range contents {
		mode := os.FileMode(0o644)
		if rel == "tools/run.sh" {
			mode = 0o755
		}
		writeFixtureFile(t, filepath.Join(root, rel), data, mode)
	}
	if err := os.Mkdir(filepath.Join(root, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("src/main.go", filepath.Join(root, "link-inside")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../outside-target", filepath.Join(root, "link-outside")); err != nil {
		t.Fatal(err)
	}
	return root, contents
}

// expectedTreehashEntries independently re-derives the manifest semantics
// (lstat perm bits, executable, symlink target size, dir size 0, blob refs)
// from the fixture, guarding the scanner<->treehash contract.
func expectedTreehashEntries(t *testing.T, root string, contents map[string][]byte) []treehash.Entry {
	t.Helper()
	var entries []treehash.Entry
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == root {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		mode := uint32(info.Mode() & fs.ModePerm)
		switch {
		case d.IsDir():
			entries = append(entries, treehash.Entry{
				Path: rel, Kind: "directory", Mode: mode, Size: 0, Executable: mode&0o111 != 0,
			})
		case d.Type()&fs.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			entries = append(entries, treehash.Entry{
				Path: rel, Kind: "symlink", Mode: mode, Size: int64(len(target)), LinkTarget: target,
			})
		default:
			data, ok := contents[rel]
			if !ok {
				return fmt.Errorf("fixture walk found unexpected file %s", rel)
			}
			entries = append(entries, treehash.Entry{
				Path: rel, Kind: "file", Mode: mode, Size: int64(len(data)), Executable: mode&0o111 != 0,
				Blob: &treehash.Blob{Digest: sha256Digest(data), Size: int64(len(data)), Compression: "none", Packed: false},
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

func manifestPaths(c *adoptWireCommit) []string {
	var paths []string
	for _, en := range c.Manifest.Entries {
		paths = append(paths, en.Path)
	}
	sort.Strings(paths)
	return paths
}

func manifestEntry(t *testing.T, c *adoptWireCommit, path string) adoptWireEntry {
	t.Helper()
	for _, en := range c.Manifest.Entries {
		if en.Path == path {
			return en
		}
	}
	t.Fatalf("manifest has no entry for %q (paths: %v)", path, manifestPaths(c))
	return adoptWireEntry{}
}

// ---- tests ----

func TestSanitizeVolumeName(t *testing.T) {
	cases := map[string]string{
		"my-project_9":           "my-project_9",
		"My Project!":            "My-Project-",
		"héllo wörld":            "h-llo-w-rld",
		"文档":                     "--",
		"a.b/c":                  "a-b-c",
		strings.Repeat("x", 300): strings.Repeat("x", 220),
	}
	for in, want := range cases {
		if got := sanitizeVolumeName(in); got != want {
			t.Errorf("sanitizeVolumeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAdoptIgnoreMatcher(t *testing.T) {
	cases := []struct {
		patterns []string
		rel      string
		isDir    bool
		want     bool
	}{
		{[]string{"node_modules"}, "node_modules", true, true},
		{[]string{"node_modules"}, "a/b/node_modules", true, true},
		{[]string{"/dist"}, "dist", true, true},
		{[]string{"/dist"}, "sub/dist", true, false}, // anchored: root only
		{[]string{"*.log"}, "a/b/x.log", false, true},
		{[]string{"*.log"}, "x.logs", false, false},
		{[]string{"build/"}, "build", true, true},
		{[]string{"build/"}, "build", false, false}, // dirOnly
		{[]string{"a/**/b"}, "a/b", false, true},
		{[]string{"a/**/b"}, "a/x/y/b", false, true},
		{[]string{"a/**/b"}, "b", false, false},
		{[]string{"docs/**"}, "docs", true, false}, // only what is inside
		{[]string{"docs/**"}, "docs/x", false, true},
		{[]string{"*.log", "!keep.log"}, "keep.log", false, false}, // last match wins
		{[]string{"*.log", "!keep.log"}, "other.log", false, true},
		{[]string{"# comment", "", "  "}, "anything", false, false},
	}
	for _, c := range cases {
		m := newIgnoreMatcher(c.patterns)
		if got := m.ignored(c.rel, c.isDir); got != c.want {
			t.Errorf("patterns %v: ignored(%q, dir=%v) = %v, want %v", c.patterns, c.rel, c.isDir, got, c.want)
		}
	}
}

func TestAdoptHappyPathCommitsManifest(t *testing.T) {
	root, contents := adoptFixture(t)
	s := newAdoptServer(t)
	// The server already holds README's blob: the probe dedups it away.
	readmeDigest := sha256Digest(contents["README.md"])
	s.probePresent[readmeDigest] = true

	e, stdout, stderr := testEnv(t)
	if rc := e.run(s.args("adopt", root, "--name", "happy-vol")); rc != 0 {
		t.Fatalf("rc = %d, stderr: %s", rc, stderr.String())
	}
	if s.commitCalls != 1 || s.detachCalls != 1 || s.attachCalls != 1 {
		t.Fatalf("attach/commit/detach = %d/%d/%d, want 1/1/1", s.attachCalls, s.commitCalls, s.detachCalls)
	}

	// The committed tree hash must equal treehash.Compute over independently
	// re-derived entries (scanner <-> hash contract).
	expected := expectedTreehashEntries(t, root, contents)
	if want := treehash.Compute(expected); s.commit.Manifest.TreeHash != want {
		t.Fatalf("manifest treeHash = %s, want %s (from independent scan)", s.commit.Manifest.TreeHash, want)
	}
	wantPaths := []string{
		"README.md", "empty", "link-inside", "link-outside", "src", "src/main.go",
		"src/nested", "src/nested/data.bin", "tools", "tools/run.sh", "zero.txt", "文档-测试.txt",
	}
	if got := manifestPaths(s.commit); strings.Join(got, ",") != strings.Join(wantPaths, ",") {
		t.Fatalf("manifest paths = %v, want %v", got, wantPaths)
	}

	// Spot-check entry semantics.
	run := manifestEntry(t, s.commit, "tools/run.sh")
	if !run.Executable || run.Mode&0o111 == 0 {
		t.Fatalf("run.sh must keep the executable bit: %+v", run)
	}
	outside := manifestEntry(t, s.commit, "link-outside")
	if outside.Kind != "symlink" || outside.LinkTarget != "../../outside-target" || outside.Size != int64(len("../../outside-target")) {
		t.Fatalf("outside symlink must be captured verbatim: %+v", outside)
	}
	empty := manifestEntry(t, s.commit, "empty")
	if empty.Kind != "directory" || empty.Size != 0 {
		t.Fatalf("empty dir entry wrong: %+v", empty)
	}
	zero := manifestEntry(t, s.commit, "zero.txt")
	if zero.Blob == nil || zero.Blob.Digest != sha256Digest(nil) || zero.Size != 0 {
		t.Fatalf("zero-byte file entry wrong: %+v", zero)
	}

	// Deduped blob was never uploaded; everything else was.
	if _, uploaded := s.blobs[readmeDigest]; uploaded {
		t.Fatal("README blob was probe-present and must not be uploaded")
	}
	for rel, data := range contents {
		if rel == "README.md" {
			continue
		}
		if got, ok := s.blobs[sha256Digest(data)]; !ok || !bytes.Equal(got, data) {
			t.Fatalf("blob for %s missing or corrupted on the server", rel)
		}
	}

	out := stdout.String()
	for _, want := range []string{"happy-vol", "cmt_adopt", "next steps", "portablefs mount happy-vol", "including .git", "--exclude"} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout missing %q:\n%s", want, out)
		}
	}
}

func TestAdoptJSONOutputShape(t *testing.T) {
	root := t.TempDir()
	writeFixtureFile(t, filepath.Join(root, "a.txt"), []byte("same"), 0o644)
	writeFixtureFile(t, filepath.Join(root, "b.txt"), []byte("same"), 0o644)
	writeFixtureFile(t, filepath.Join(root, "c.txt"), []byte("unique"), 0o644)
	s := newAdoptServer(t)
	s.probePresent[sha256Digest([]byte("unique"))] = true

	e, stdout, stderr := testEnv(t)
	if rc := e.run(s.args("adopt", root, "--name", "json-vol", "--json", "--quiet")); rc != 0 {
		t.Fatalf("rc = %d, stderr: %s", rc, stderr.String())
	}
	var got map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("--json must emit one JSON document: %v (%q)", err, stdout.String())
	}
	want := map[string]any{
		"volumeId": "json-vol", "branch": "main", "commitId": "cmt_adopt",
		"files": float64(3), "dirs": float64(0), "symlinks": float64(0),
		"bytes": float64(4 + 4 + 6), "skipped": float64(0),
		"uploadedBlobs": float64(1), "dedupedBlobs": float64(1),
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("json[%q] = %v, want %v", k, got[k], v)
		}
	}
	if _, ok := got["treeHash"].(string); !ok {
		t.Errorf("json must include treeHash, got %v", got["treeHash"])
	}
	if len(got) != 11 {
		t.Errorf("json must have exactly the 11 spec keys, got %d: %v", len(got), got)
	}
}

func TestAdoptProbe404UploadsEverything(t *testing.T) {
	root, contents := adoptFixture(t)
	s := newAdoptServer(t)
	s.noProbeRoute = true

	e, _, stderr := testEnv(t)
	if rc := e.run(s.args("adopt", root, "--name", "noprobe-vol")); rc != 0 {
		t.Fatalf("rc = %d, stderr: %s", rc, stderr.String())
	}
	for rel, data := range contents {
		if _, ok := s.blobs[sha256Digest(data)]; !ok {
			t.Fatalf("without a probe route every blob must be uploaded; missing %s", rel)
		}
	}
	if s.commitCalls != 1 {
		t.Fatalf("commitCalls = %d", s.commitCalls)
	}
}

func TestAdoptDedupIdenticalFiles(t *testing.T) {
	root := t.TempDir()
	same := []byte("identical contents\n")
	writeFixtureFile(t, filepath.Join(root, "first.txt"), same, 0o644)
	writeFixtureFile(t, filepath.Join(root, "sub/second.txt"), same, 0o644)
	s := newAdoptServer(t)

	e, _, stderr := testEnv(t)
	if rc := e.run(s.args("adopt", root, "--name", "dedup-vol")); rc != 0 {
		t.Fatalf("rc = %d, stderr: %s", rc, stderr.String())
	}
	if s.batchEntries != 1 {
		t.Fatalf("identical files must upload a single blob entry, got %d", s.batchEntries)
	}
	d := sha256Digest(same)
	if manifestEntry(t, s.commit, "first.txt").Blob.Digest != d || manifestEntry(t, s.commit, "sub/second.txt").Blob.Digest != d {
		t.Fatal("both manifest entries must reference the shared digest")
	}
}

func TestAdoptExcludesAndIgnoreFile(t *testing.T) {
	root := t.TempDir()
	writeFixtureFile(t, filepath.Join(root, ".portablefsignore"), []byte("# comment line\n*.log\nnode_modules/\n!keep.log\n"), 0o644)
	writeFixtureFile(t, filepath.Join(root, "app.log"), []byte("drop me"), 0o644)
	writeFixtureFile(t, filepath.Join(root, "keep.log"), []byte("re-included"), 0o644)
	writeFixtureFile(t, filepath.Join(root, "node_modules/pkg/x.js"), []byte("dep"), 0o644)
	writeFixtureFile(t, filepath.Join(root, "dist/bundle.js"), []byte("built"), 0o644)
	writeFixtureFile(t, filepath.Join(root, "sub/dist/inner.js"), []byte("built2"), 0o644)
	writeFixtureFile(t, filepath.Join(root, "rootonly"), []byte("root"), 0o644)
	writeFixtureFile(t, filepath.Join(root, "sub/rootonly"), []byte("nested"), 0o644)
	writeFixtureFile(t, filepath.Join(root, "src/ok.txt"), []byte("kept"), 0o644)
	s := newAdoptServer(t)

	e, _, stderr := testEnv(t)
	rc := e.run(s.args("adopt", root, "--name", "excl-vol", "--exclude", "dist", "--exclude", "/rootonly"))
	if rc != 0 {
		t.Fatalf("rc = %d, stderr: %s", rc, stderr.String())
	}
	want := []string{".portablefsignore", "keep.log", "src", "src/ok.txt", "sub", "sub/rootonly"}
	if got := manifestPaths(s.commit); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("manifest paths = %v, want %v", got, want)
	}
}

func TestAdoptDryRunMakesZeroRequests(t *testing.T) {
	root, _ := adoptFixture(t)
	var requests int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		w.WriteHeader(500)
	}))
	defer srv.Close()

	e, stdout, _ := testEnv(t)
	if rc := e.run([]string{"adopt", root, "--dry-run", "--api-url", srv.URL, "--api-token", "tok"}); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if requests != 0 {
		t.Fatalf("--dry-run must make zero HTTP requests, made %d", requests)
	}
	if !strings.Contains(stdout.String(), "dry run") || !strings.Contains(stdout.String(), "6 files") {
		t.Fatalf("dry-run summary wrong: %q", stdout.String())
	}

	stdout.Reset()
	if rc := e.run([]string{"adopt", root, "--dry-run", "--json", "--api-url", srv.URL, "--api-token", "tok"}); rc != 0 {
		t.Fatal("dry-run --json failed")
	}
	var parsed struct {
		DryRun   bool  `json:"dryRun"`
		Files    int   `json:"files"`
		Dirs     int   `json:"dirs"`
		Symlinks int   `json:"symlinks"`
		Bytes    int64 `json:"bytes"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("dry-run --json invalid: %v", err)
	}
	if !parsed.DryRun || parsed.Files != 6 || parsed.Dirs != 4 || parsed.Symlinks != 2 {
		t.Fatalf("dry-run json = %+v", parsed)
	}
	if requests != 0 {
		t.Fatalf("--dry-run --json must make zero HTTP requests, made %d", requests)
	}
}

func TestAdoptUnreadableFileFailsCleanlyAndDetaches(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits are not enforced")
	}
	root := t.TempDir()
	writeFixtureFile(t, filepath.Join(root, "ok.txt"), []byte("fine"), 0o644)
	writeFixtureFile(t, filepath.Join(root, "locked/secret.txt"), []byte("no read"), 0o644)
	if err := os.Chmod(filepath.Join(root, "locked/secret.txt"), 0o000); err != nil {
		t.Fatal(err)
	}
	s := newAdoptServer(t)

	e, _, stderr := testEnv(t)
	if rc := e.run(s.args("adopt", root, "--name", "locked-vol")); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	if !strings.Contains(stderr.String(), "locked/secret.txt") {
		t.Fatalf("error must name the unreadable file: %q", stderr.String())
	}
	if s.detachCalls != 1 {
		t.Fatalf("the write session must be detached on failure, detachCalls = %d", s.detachCalls)
	}
	if s.commitCalls != 0 {
		t.Fatalf("no commit must happen after a failed read, commitCalls = %d", s.commitCalls)
	}
}

// TestAdopt409ResumesIntoEmptyVolume covers the interrupted-adopt retry: the
// name exists but holds only its genesis commit (hosted control planes have
// no volume deletion), so adopt resumes into it instead of stranding the name.
func TestAdopt409ResumesIntoEmptyVolume(t *testing.T) {
	root := t.TempDir()
	writeFixtureFile(t, filepath.Join(root, "a.txt"), []byte("x"), 0o644)
	s := newAdoptServer(t)
	s.createStatus = 409 // historyJSON default = one genesis commit -> empty

	e, stdout, stderr := testEnv(t)
	if rc := e.run(s.args("adopt", root, "--name", "taken")); rc != 0 {
		t.Fatalf("rc = %d, stderr: %s", rc, stderr.String())
	}
	if s.commitCalls != 1 || s.attachCalls != 1 {
		t.Fatalf("resume must attach and commit exactly once, got attach=%d commit=%d", s.attachCalls, s.commitCalls)
	}
	// The fixture root may be reported through a resolved symlink (macOS
	// /var -> /private/var), so assert on the volume rather than the path.
	if !strings.Contains(stdout.String(), "into volume taken") {
		t.Fatalf("resume must complete the adopt: %q", stdout.String())
	}
}

// TestAdopt409RefusesNonEmptyVolume keeps the safety property: a name that
// already carries committed content is never silently overwritten.
func TestAdopt409RefusesNonEmptyVolume(t *testing.T) {
	root := t.TempDir()
	writeFixtureFile(t, filepath.Join(root, "a.txt"), []byte("x"), 0o644)
	s := newAdoptServer(t)
	s.createStatus = 409
	s.historyJSON = `{"commits":[{"id":"cmt_1","treeHash":"sha256:bb","createdAtMs":2,"mutationCount":3,"byteCount":9,"parentCommitId":"cmt_0"},{"id":"cmt_0","treeHash":"sha256:aa","createdAtMs":1,"mutationCount":0,"byteCount":0,"parentCommitId":""}]}`

	e, _, stderr := testEnv(t)
	if rc := e.run(s.args("adopt", root, "--name", "taken")); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	msg := stderr.String()
	if !strings.Contains(msg, "already exists with content") || !strings.Contains(msg, "--name") {
		t.Fatalf("non-empty 409 must refuse with a friendly message pointing at --name: %q", msg)
	}
	if s.commitCalls != 0 || s.attachCalls != 0 {
		t.Fatalf("refusal must not attach or commit, got attach=%d commit=%d", s.attachCalls, s.commitCalls)
	}
}

// TestAdopt409ProvisioningExplainsItself: the name-taken state check hitting
// VOLUME_PROVISIONING means a previous adopt is mid-flight (or died partway);
// say that, not "state could not be checked: <upstream text>".
func TestAdopt409ProvisioningExplainsItself(t *testing.T) {
	root := t.TempDir()
	writeFixtureFile(t, filepath.Join(root, "a.txt"), []byte("x"), 0o644)
	s := newAdoptServer(t)
	s.createStatus = 409
	s.historyStatus = 409
	s.historyJSON = `{"error":{"code":"VOLUME_PROVISIONING","message":"Volume is provisioning."}}`

	e, _, stderr := testEnv(t)
	if rc := e.run(s.args("adopt", root, "--name", "taken")); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	msg := stderr.String()
	if !strings.Contains(msg, "still provisioning") || !strings.Contains(msg, "--name") {
		t.Fatalf("provisioning refusal must explain the state and the way out: %q", msg)
	}
	if strings.Contains(msg, "could not be checked") || strings.Contains(msg, "VOLUME_PROVISIONING") {
		t.Fatalf("no raw envelope text on the provisioning path: %q", msg)
	}
}

// TestAdopt409CrossTenantSaysUnavailable: create says the name exists but the
// state check answers VOLUME_NOT_FOUND — another tenant owns the name. The
// contradictory upstream texts must never be pasted together.
func TestAdopt409CrossTenantSaysUnavailable(t *testing.T) {
	root := t.TempDir()
	writeFixtureFile(t, filepath.Join(root, "a.txt"), []byte("x"), 0o644)
	s := newAdoptServer(t)
	s.createStatus = 409
	s.historyStatus = 404
	s.historyJSON = `{"error":{"code":"VOLUME_NOT_FOUND","message":"Volume not found."}}`

	e, _, stderr := testEnv(t)
	if rc := e.run(s.args("adopt", root, "--name", "taken")); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	msg := stderr.String()
	if !strings.Contains(msg, "unavailable") || !strings.Contains(msg, "--name") {
		t.Fatalf("cross-tenant refusal must say the name is unavailable: %q", msg)
	}
	for _, contradiction := range []string{"not found", "could not be checked", "VOLUME_NOT_FOUND"} {
		if strings.Contains(msg, contradiction) {
			t.Fatalf("contradictory upstream text must not leak: %q", msg)
		}
	}
}

func TestAdoptMutatedFileUsesNewDigest(t *testing.T) {
	root := t.TempDir()
	oldContents := []byte("original contents\n")
	newContents := []byte("MUTATED! the file changed between scan and upload\n")
	mutPath := filepath.Join(root, "mut.txt")
	writeFixtureFile(t, mutPath, oldContents, 0o644)
	writeFixtureFile(t, filepath.Join(root, "steady.txt"), []byte("steady"), 0o644)

	s := newAdoptServer(t)
	// The probe runs after hashing and before the upload: mutate there.
	s.onProbe = func() {
		if err := os.WriteFile(mutPath, newContents, 0o644); err != nil {
			t.Errorf("mutate: %v", err)
		}
	}

	e, _, stderr := testEnv(t)
	if rc := e.run(s.args("adopt", root, "--name", "mut-vol")); rc != 0 {
		t.Fatalf("rc = %d, stderr: %s", rc, stderr.String())
	}
	newDigest := sha256Digest(newContents)
	en := manifestEntry(t, s.commit, "mut.txt")
	if en.Blob.Digest != newDigest || en.Size != int64(len(newContents)) {
		t.Fatalf("mutated file must commit with the new digest/size: %+v", en)
	}
	if got, ok := s.blobs[newDigest]; !ok || !bytes.Equal(got, newContents) {
		t.Fatal("the new bytes must be what was uploaded")
	}
	if _, ok := s.blobs[sha256Digest(oldContents)]; ok {
		t.Fatal("the stale pre-mutation blob must not be uploaded")
	}
	if !strings.Contains(stderr.String(), "changed while adopting") {
		t.Fatalf("a mutation warning must be printed: %q", stderr.String())
	}
}

func TestAdoptLargeFileStreamsViaPut(t *testing.T) {
	root := t.TempDir()
	large := bytes.Repeat([]byte("0123456789abcdef"), (7<<20)/16) // 7 MiB > 6 MiB cutoff
	writeFixtureFile(t, filepath.Join(root, "big.bin"), large, 0o644)
	writeFixtureFile(t, filepath.Join(root, "small.txt"), []byte("small"), 0o644)
	s := newAdoptServer(t)

	e, _, stderr := testEnv(t)
	if rc := e.run(s.args("adopt", root, "--name", "large-vol")); rc != 0 {
		t.Fatalf("rc = %d, stderr: %s", rc, stderr.String())
	}
	if s.putCount != 1 {
		t.Fatalf("files over 6MiB must stream via PUT, putCount = %d", s.putCount)
	}
	if s.batchEntries != 1 {
		t.Fatalf("only the small file belongs in a batch, batchEntries = %d", s.batchEntries)
	}
	if got, ok := s.blobs[sha256Digest(large)]; !ok || !bytes.Equal(got, large) {
		t.Fatal("streamed blob missing or corrupted")
	}
}

func TestAdoptChunksFilesAtTsThreshold(t *testing.T) {
	// Files >= 8 MiB must carry chunk refs identical to the TS scanner's
	// (4 MiB chunks), upload each chunk as its own blob, and hash with the
	// chunks in the tree hash — otherwise the server's next rescan of the
	// same bytes would produce a different manifest entry and rewrite it.
	root := t.TempDir()
	chunked := bytes.Repeat([]byte("chunky-0123456789"), (9<<20)/17+1) // > 8 MiB, not chunk-aligned
	writeFixtureFile(t, filepath.Join(root, "model.bin"), chunked, 0o644)
	s := newAdoptServer(t)

	e, _, stderr := testEnv(t)
	if rc := e.run(s.args("adopt", root, "--name", "chunk-vol", "--quiet")); rc != 0 {
		t.Fatalf("rc = %d, stderr: %s", rc, stderr.String())
	}
	if s.putCount != 0 {
		t.Fatalf("chunked files upload via batches, not whole-file PUT; putCount = %d", s.putCount)
	}
	entry := manifestEntry(t, s.commit, "model.bin")
	wantChunks := (len(chunked) + (4 << 20) - 1) / (4 << 20)
	if len(entry.Chunks) != wantChunks {
		t.Fatalf("chunks = %d, want %d", len(entry.Chunks), wantChunks)
	}
	if entry.Blob == nil || entry.Blob.Digest != sha256Digest(chunked) {
		t.Fatalf("whole-file digest must cover the concatenation")
	}
	var offset int64
	for i, ch := range entry.Chunks {
		end := offset + ch.Size
		if got := sha256Digest(chunked[offset:end]); ch.Digest != got {
			t.Fatalf("chunk %d digest mismatch", i)
		}
		stored, ok := s.blobs[ch.Digest]
		if !ok || !bytes.Equal(stored, chunked[offset:end]) {
			t.Fatalf("chunk %d not uploaded verbatim", i)
		}
		offset = end
	}
	if offset != int64(len(chunked)) {
		t.Fatalf("chunks cover %d bytes, want %d", offset, len(chunked))
	}
}

func TestAdoptBatchSplitsAtEntryCap(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 1025; i++ {
		writeFixtureFile(t, filepath.Join(root, fmt.Sprintf("f/%04d.txt", i)), []byte(fmt.Sprintf("file-%d", i)), 0o644)
	}
	s := newAdoptServer(t)

	e, _, stderr := testEnv(t)
	if rc := e.run(s.args("adopt", root, "--name", "batch-vol", "--quiet")); rc != 0 {
		t.Fatalf("rc = %d, stderr: %s", rc, stderr.String())
	}
	if s.batchCount != 2 || s.batchEntries != 1025 {
		t.Fatalf("1025 unique blobs must split into 2 batches (1024 cap): batches=%d entries=%d", s.batchCount, s.batchEntries)
	}
}

func TestAdoptBulkyDirHintOnDryRun(t *testing.T) {
	root := t.TempDir()
	writeFixtureFile(t, filepath.Join(root, "small.txt"), []byte("tiny"), 0o644)
	bigPath := filepath.Join(root, "bigdir", "huge.bin")
	writeFixtureFile(t, bigPath, nil, 0o644)
	if err := os.Truncate(bigPath, 600<<20); err != nil { // sparse: no real disk use
		t.Fatal(err)
	}

	e, _, stderr := testEnv(t)
	if rc := e.run([]string{"adopt", root, "--dry-run"}); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if !strings.Contains(stderr.String(), "--exclude 'bigdir/'") {
		t.Fatalf("a >500MiB top-level dir must earn an --exclude hint: %q", stderr.String())
	}
}

func TestAdoptRenewLeaseWhenHalfTTLElapsed(t *testing.T) {
	f := newFakeServer(t)
	renews := 0
	f.on("POST", "/v1/leases/lease_1/renew", func(body map[string]any) (int, string) {
		renews++
		if body["fencingToken"] != float64(7) || body["leaseTtlMs"] != float64(600000) {
			return 400, `{"error":{"code":"BAD","message":"renew body wrong"}}`
		}
		return 200, `{"lease":{"id":"lease_1","fencingToken":7,"expiresAt":9}}`
	})
	e, _, _ := testEnv(t)
	base := time.Now()
	current := base
	r := &adoptRun{
		e:            e,
		opts:         &adoptOpts{},
		api:          newAPIClient(f.srv.URL, "tok"),
		now:          func() time.Time { return current },
		sleep:        func(time.Duration) {},
		leaseID:      "lease_1",
		fencingToken: 7,
		lastRenew:    base,
	}
	ctx := t.Context()
	current = base.Add(time.Minute)
	if err := r.renewLeaseIfNeeded(ctx); err != nil || renews != 0 {
		t.Fatalf("no renew before TTL/2: err=%v renews=%d", err, renews)
	}
	current = base.Add(6 * time.Minute)
	if err := r.renewLeaseIfNeeded(ctx); err != nil || renews != 1 {
		t.Fatalf("renew after TTL/2: err=%v renews=%d", err, renews)
	}
	if err := r.renewLeaseIfNeeded(ctx); err != nil || renews != 1 {
		t.Fatalf("renew must reset the clock: err=%v renews=%d", err, renews)
	}
}

func TestAdoptCommandRegistered(t *testing.T) {
	if _, ok := findCommand("adopt"); !ok {
		t.Fatal("adopt must be registered in the command table")
	}
	text, ok := commandHelp("adopt")
	if !ok {
		t.Fatal("adopt must have detailed help")
	}
	for _, want := range []string{"--exclude", "--dry-run", "--mount", ".portablefsignore", "gitignore-style"} {
		if !strings.Contains(text, want) {
			t.Fatalf("adopt help missing %q", want)
		}
	}
	if !strings.Contains(rootHelp(), "adopt <dir>") {
		t.Fatal("root help must list adopt")
	}
}

// TestUploadRequestTimeoutScalesWithSize pins the per-attempt upload
// deadline: the shared 60s request floor, scaled at 128 KiB/s above it so
// big blobs on slow links get the time they physically need.
func TestUploadRequestTimeoutScalesWithSize(t *testing.T) {
	cases := []struct {
		bytes int64
		want  time.Duration
	}{
		{0, 60 * time.Second},
		{6 << 20, 60 * time.Second},          // small blobs stay on the floor
		{60 * (128 << 10), 60 * time.Second}, // exact floor boundary
		{8 << 20, 64 * time.Second},          // one full batch just clears the floor
		{100 << 20, 800 * time.Second},       // 100 MiB at 128 KiB/s
		{1 << 30, 8192 * time.Second},        // 1 GiB at 128 KiB/s
	}
	for _, tc := range cases {
		if got := uploadRequestTimeout(tc.bytes); got != tc.want {
			t.Fatalf("uploadRequestTimeout(%d) = %s, want %s", tc.bytes, got, tc.want)
		}
	}
}

// TestAdoptActivationTerminalFailureStopsFast: when the server reports the
// activation cut terminally failed, adopt must stop polling immediately (one
// call, no 15-minute wait), surface the server's error, and keep the resume
// hint (the content is committed).
func TestAdoptActivationTerminalFailureStopsFast(t *testing.T) {
	root := t.TempDir()
	writeFixtureFile(t, filepath.Join(root, "a.txt"), []byte("x"), 0o644)
	s := newAdoptServer(t)
	s.activateJSON = `{"state":"converting","cutState":"failed","lastError":"cut worker crashed: disk full"}`

	e, _, stderr := testEnv(t)
	if rc := e.run(s.args("adopt", root, "--name", "vol1")); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	msg := stderr.String()
	if !strings.Contains(msg, "activation failed: cut worker crashed: disk full") {
		t.Fatalf("must surface the server's error: %q", msg)
	}
	if !strings.Contains(msg, "resume with: portablefs activate vol1") {
		t.Fatalf("must keep the resume hint: %q", msg)
	}
	if s.activateCalls != 1 {
		t.Fatalf("terminal cut failure must stop polling immediately, got %d activate calls", s.activateCalls)
	}
}

// TestAdoptActivationRendersServerTelemetry: the additive
// cutState/attemptCount/lastError fields render in the progress line while
// polling continues, and disappear cleanly when the server omits them.
func TestAdoptActivationRendersServerTelemetry(t *testing.T) {
	root := t.TempDir()
	writeFixtureFile(t, filepath.Join(root, "a.txt"), []byte("x"), 0o644)
	s := newAdoptServer(t)
	s.activateJSON = `{"state":"converting","conversion":{"state":"final_cut"},"cutState":"materializing","attemptCount":3}`

	// The stubbed sleeper flips the server to active before the second poll.
	e, _, stderr := testEnv(t)
	flipped := false
	e.sleepFn = func(time.Duration) {
		if !flipped {
			flipped = true
			s.mu.Lock()
			s.activateJSON = `{"state":"active","branchMode":"managed_journal"}`
			s.mu.Unlock()
		}
	}
	if rc := e.run(s.args("adopt", root, "--name", "vol2")); rc != 0 {
		t.Fatalf("rc = %d, stderr: %s", rc, stderr.String())
	}
	if !strings.Contains(stderr.String(), "activating journal (final_cut, cut materializing, attempt 3) ...") {
		t.Fatalf("progress must render the server's telemetry: %q", stderr.String())
	}
}
