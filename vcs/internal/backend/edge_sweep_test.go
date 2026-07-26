package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// ---------------------------------------------------------------------------
// Manifest / Entry / Chunk value handling at edge sizes (0, 1, max) and shapes.
// ---------------------------------------------------------------------------

// TestManifestEmptyEntries: a head manifest with an empty entry list yields a
// zero-length (non-nil-safe) slice and no error — the empty-volume boundary.
func TestManifestEmptyEntries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"head":{"manifest":{"entries":[]}}}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "")
	entries, err := c.Manifest(context.Background(), "vol", "main")
	if err != nil {
		t.Fatalf("Manifest empty: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("len=%d, want 0", len(entries))
	}
}

// TestManifestMissingHeadIsEmpty: a status body with no head/manifest at all
// decodes to zero entries (the just-created, never-committed volume), not an error.
func TestManifestMissingHeadIsEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "")
	entries, err := c.Manifest(context.Background(), "vol", "main")
	if err != nil {
		t.Fatalf("Manifest no-head: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("len=%d, want 0", len(entries))
	}
}

// TestManifestEdgeSizesAndFields exercises the numeric/boolean field mapping at
// boundaries: size 0, size 1, size math.MaxInt64, mode/uid/gid round-trip, a
// fractional mtimeMs truncating to int64, executable=true, and a multi-chunk file
// whose chunk offsets/sizes are preserved verbatim.
func TestManifestEdgeSizesAndFields(t *testing.T) {
	body := fmt.Sprintf(`{"head":{"manifest":{"entries":[
	  {"path":"zero","kind":"file","mode":420,"size":0,"mtimeMs":0,"blob":{"digest":"sha256:z","size":0,"compression":"none","packed":false}},
	  {"path":"one","kind":"file","mode":511,"size":1,"mtimeMs":1.9,"executable":true,"uid":1000,"gid":2000,"blob":{"digest":"sha256:o","size":1,"compression":"gzip","packed":true}},
	  {"path":"max","kind":"file","mode":420,"size":%d,"chunks":[
	    {"digest":"sha256:c0","size":%d,"offset":0},
	    {"digest":"sha256:c1","size":1,"offset":%d}
	  ]}
	]}}}`, int64(math.MaxInt64), int64(math.MaxInt64)-1, int64(math.MaxInt64)-1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "")
	entries, err := c.Manifest(context.Background(), "vol", "main")
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("len=%d, want 3", len(entries))
	}

	zero := entries[0]
	if zero.Size != 0 || zero.BlobDigest != "sha256:z" || zero.BlobCompression != "none" || zero.BlobPacked {
		t.Errorf("zero entry wrong: %+v", zero)
	}

	one := entries[1]
	if one.Size != 1 || one.Mode != 511 || !one.Executable || one.UID != 1000 || one.GID != 2000 {
		t.Errorf("one entry wrong: %+v", one)
	}
	if one.MtimeMs != 1 { // fractional ms (1.9) truncates toward zero on int64() conversion
		t.Errorf("mtimeMs = %d, want 1 (truncated from 1.9)", one.MtimeMs)
	}
	if one.BlobCompression != "gzip" || !one.BlobPacked || one.BlobSize != 1 {
		t.Errorf("one blob fields wrong: %+v", one)
	}

	mx := entries[2]
	if mx.Size != math.MaxInt64 {
		t.Errorf("max size = %d, want MaxInt64", mx.Size)
	}
	if len(mx.Chunks) != 2 || mx.Chunks[0].Size != math.MaxInt64-1 || mx.Chunks[1].Offset != math.MaxInt64-1 || mx.Chunks[1].Size != 1 {
		t.Errorf("max chunks wrong: %+v", mx.Chunks)
	}
	// BlobDigest must be empty for a chunked file (the doc contract on Entry).
	if mx.BlobDigest != "" {
		t.Errorf("chunked file has BlobDigest %q, want empty", mx.BlobDigest)
	}
}

// TestManifestDefaultsBranchWhenEmpty: an empty branch string must default to
// "main" on the query string (mirrors the documented behavior).
func TestManifestDefaultsBranchWhenEmpty(t *testing.T) {
	var gotBranch atomic.Value
	gotBranch.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBranch.Store(r.URL.Query().Get("branch"))
		_, _ = w.Write([]byte(`{"head":{"manifest":{"entries":[]}}}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "")
	if _, err := c.Manifest(context.Background(), "vol", ""); err != nil {
		t.Fatal(err)
	}
	if got := gotBranch.Load().(string); got != "main" {
		t.Fatalf("branch on wire = %q, want main", got)
	}
}

// TestManifestEscapesVolumeAndBranch: a volume id and branch with characters that
// require escaping (slash, space, percent, unicode) must be encoded so the server
// receives them intact.
func TestManifestEscapesVolumeAndBranch(t *testing.T) {
	const volID = "vol/with space%and"
	const branch = "feature/é+x"
	var (
		gotPath   atomic.Value
		gotBranch atomic.Value
	)
	gotPath.Store("")
	gotBranch.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// r.URL.Path is already percent-decoded by net/http; PathEscape round-trips it.
		gotPath.Store(r.URL.Path)
		gotBranch.Store(r.URL.Query().Get("branch"))
		_, _ = w.Write([]byte(`{"head":{"manifest":{"entries":[]}}}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "")
	if _, err := c.Manifest(context.Background(), volID, branch); err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if got := gotPath.Load().(string); got != "/v1/volumes/"+volID+"/status" {
		t.Fatalf("decoded path = %q, want volume id preserved", got)
	}
	if got := gotBranch.Load().(string); got != branch {
		t.Fatalf("decoded branch = %q, want %q", got, branch)
	}
}

// TestManifestErrorBodyIncludesStatusAndBody: a non-200 surfaces the status code
// and a (truncated) body so the caller can classify it.
func TestManifestErrorBodyIncludesStatusAndBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		// > 2 KiB body to exercise the LimitReader truncation path.
		_, _ = w.Write([]byte(strings.Repeat("E", 5000)))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "")
	_, err := c.Manifest(context.Background(), "vol", "main")
	if err == nil {
		t.Fatal("want error on 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("error %q lacks status code", err)
	}
}

// TestManifestBadJSONErrors: a 200 with undecodable JSON is a decode error, not a
// silent empty manifest.
func TestManifestBadJSONErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"head": not-json`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "")
	if _, err := c.Manifest(context.Background(), "vol", "main"); err == nil {
		t.Fatal("want decode error on malformed body")
	}
}

// ---------------------------------------------------------------------------
// Blob read path: Content-Length present (pre-sized buffer), absent (-1), zero,
// empty, and a 1 MiB body; plus digest-colon escaping and error status.
// ---------------------------------------------------------------------------

// TestBlobContentLengthVariants reads the same byte payload three ways: with a
// correct Content-Length (pre-sized buffer path), with Content-Length stripped
// (chunked transfer => ContentLength -1 => io.ReadAll path), and an empty body.
func TestBlobContentLengthVariants(t *testing.T) {
	const big = 1 << 20 // 1 MiB exercises the pre-sized buffer allocation
	payload := make([]byte, big)
	for i := range payload {
		payload[i] = byte(i)
	}

	cases := []struct {
		name  string
		body  []byte
		flush bool // flush before writing -> forces chunked transfer (no Content-Length)
	}{
		{"empty", []byte{}, false},
		{"one", []byte{0x42}, false},
		{"sized-1MiB", payload, false},
		{"chunked-no-content-length", payload, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.flush {
					w.WriteHeader(http.StatusOK)
					w.(http.Flusher).Flush() // commit headers with no Content-Length => chunked
				}
				_, _ = w.Write(tc.body)
			}))
			defer srv.Close()
			c := NewClient(srv.URL, "")
			got, err := c.Blob(context.Background(), "sha256:deadbeef")
			if err != nil {
				t.Fatalf("Blob: %v", err)
			}
			if len(got) != len(tc.body) {
				t.Fatalf("len=%d, want %d", len(got), len(tc.body))
			}
			for i := range got {
				if got[i] != tc.body[i] {
					t.Fatalf("byte %d = %d, want %d", i, got[i], tc.body[i])
				}
			}
		})
	}
}

// TestBlobEscapesColon: a "sha256:<hex>" digest's colon is the only special char;
// it must be percent-encoded so the path segment is well-formed and the server
// recovers the original digest.
func TestBlobEscapesColon(t *testing.T) {
	const digest = "sha256:abc123"
	var gotPath atomic.Value
	gotPath.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath.Store(r.URL.Path) // net/http decodes %3A back to ':'
		_, _ = w.Write([]byte("x"))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "")
	if _, err := c.Blob(context.Background(), digest); err != nil {
		t.Fatal(err)
	}
	if got := gotPath.Load().(string); got != "/v1/blobs/"+digest {
		t.Fatalf("decoded blob path = %q, want %q", got, "/v1/blobs/"+digest)
	}
}

// TestBlobNon200Errors: a 404 (or any non-200) for a blob is an error.
func TestBlobNon200Errors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "")
	if _, err := c.Blob(context.Background(), "sha256:missing"); err == nil {
		t.Fatal("want error on 404 blob")
	}
}

// ---------------------------------------------------------------------------
// PutBlob / CreateVolume / Attach / Commit wire shapes and edge payloads.
// ---------------------------------------------------------------------------

// TestPutBlobEmptyAndSized round-trips a zero-byte and a 1-byte body, asserts the
// PUT verb + escaped digest path + the exact bytes the server receives.
func TestPutBlobEmptyAndSized(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"one", []byte{0x7f}},
		{"small", []byte("hello")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []byte
			var method, path atomic.Value
			method.Store("")
			path.Store("")
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				method.Store(r.Method)
				path.Store(r.URL.Path)
				got, _ = io.ReadAll(r.Body)
				w.WriteHeader(http.StatusCreated)
			}))
			defer srv.Close()
			c := NewClient(srv.URL, "")
			if err := c.PutBlob(context.Background(), "sha256:zz", tc.data); err != nil {
				t.Fatalf("PutBlob: %v", err)
			}
			if method.Load().(string) != http.MethodPut {
				t.Fatalf("method = %s, want PUT", method.Load())
			}
			if path.Load().(string) != "/v1/blobs/sha256:zz" {
				t.Fatalf("path = %s", path.Load())
			}
			if len(got) != len(tc.data) || string(got) != string(tc.data) {
				t.Fatalf("body = %q, want %q", got, tc.data)
			}
		})
	}
}

// TestPutBlobErrorIncludesBody: a non-2xx PUT surfaces status + (truncated) body.
func TestPutBlobErrorIncludesBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "digest mismatch", http.StatusBadRequest)
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "")
	err := c.PutBlob(context.Background(), "sha256:zz", []byte("x"))
	if err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("err = %v, want a 400 error", err)
	}
}

// TestCommitWireShapeAndManifestSerialization is the load-bearing serialization
// test: it asserts the Commit POST carries leaseId, fencingToken (incl. a large
// value), expectedHeadCommitId, mutation/byte counts, and a manifest whose
// ManifestEntry omitempty fields behave correctly — UID/GID 0 omitted (tree-hash
// back-compat), non-zero present; blob/chunks/linkTarget omitted when empty.
func TestCommitWireShapeAndManifestSerialization(t *testing.T) {
	var captured map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode(&captured); err != nil {
			t.Errorf("decode commit body: %v", err)
		}
		_, _ = w.Write([]byte(`{"commit":{"id":"commit_99"}}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "")

	in := CommitInput{
		ExpectedHeadCommitID: "head_1",
		LeaseID:              "lease_1",
		FencingToken:         math.MaxInt64,
		MutationCount:        3,
		ByteCount:            123456789012,
		Manifest: Manifest{
			Version:  "v1",
			TreeHash: "sha256:tree",
			Entries: []ManifestEntry{
				{Path: "root-owned", Kind: "file", Mode: 0o644, Size: 1, UID: 0, GID: 0, Blob: &BlobRef{Digest: "sha256:b", Size: 1}},
				{Path: "user-owned", Kind: "file", Mode: 0o644, Size: 2, UID: 1000, GID: 1000},
				{Path: "ln", Kind: "symlink", Mode: 0o777, LinkTarget: "root-owned"},
			},
		},
	}
	id, err := c.Commit(context.Background(), "sess_1", in)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if id != "commit_99" {
		t.Fatalf("commit id = %q, want commit_99", id)
	}

	// Top-level fields.
	if captured["leaseId"] != "lease_1" || captured["expectedHeadCommitId"] != "head_1" {
		t.Errorf("commit envelope wrong: %+v", captured)
	}
	// Numbers decode as float64; MaxInt64 is not exactly representable, so compare
	// via the documented JSON the server would re-marshal instead. Assert it is huge.
	if ft, _ := captured["fencingToken"].(float64); ft < 9.0e18 {
		t.Errorf("fencingToken = %v, want ~MaxInt64", captured["fencingToken"])
	}

	man := captured["manifest"].(map[string]any)
	if man["version"] != "v1" || man["treeHash"] != "sha256:tree" {
		t.Errorf("manifest header wrong: %+v", man)
	}
	ents := man["entries"].([]any)
	if len(ents) != 3 {
		t.Fatalf("entries len=%d, want 3", len(ents))
	}

	rootOwned := ents[0].(map[string]any)
	if _, hasUID := rootOwned["uid"]; hasUID {
		t.Errorf("root-owned entry serialized uid (omitempty broken): %+v", rootOwned)
	}
	if _, hasGID := rootOwned["gid"]; hasGID {
		t.Errorf("root-owned entry serialized gid (omitempty broken): %+v", rootOwned)
	}
	if _, hasBlob := rootOwned["blob"]; !hasBlob {
		t.Errorf("root-owned entry missing blob: %+v", rootOwned)
	}

	userOwned := ents[1].(map[string]any)
	if userOwned["uid"].(float64) != 1000 || userOwned["gid"].(float64) != 1000 {
		t.Errorf("user-owned uid/gid not serialized: %+v", userOwned)
	}
	if _, hasBlob := userOwned["blob"]; hasBlob {
		t.Errorf("user-owned (no blob) serialized a blob: %+v", userOwned)
	}
	if _, hasChunks := userOwned["chunks"]; hasChunks {
		t.Errorf("user-owned serialized empty chunks: %+v", userOwned)
	}

	ln := ents[2].(map[string]any)
	if ln["linkTarget"] != "root-owned" {
		t.Errorf("symlink linkTarget wrong: %+v", ln)
	}
}

// TestAttachParsesSessionAndLease: the Attach response mapping (session id, lease
// id + fencing token, head commit, manifest version) and the request body shape.
func TestAttachParsesSessionAndLease(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = w.Write([]byte(`{
		  "session":{"id":"sess_1","lease":{"id":"lease_1","fencingToken":42}},
		  "branch":{"headCommitId":"head_1"},
		  "manifest":{"version":"v9"}
		}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "")
	res, err := c.Attach(context.Background(), "vol", "", "holder-x", 1234)
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if res.SessionID != "sess_1" || res.LeaseID != "lease_1" || res.FencingToken != 42 ||
		res.HeadCommitID != "head_1" || res.ManifestVersion != "v9" {
		t.Fatalf("attach result wrong: %+v", res)
	}
	// Empty branch defaults to main; mode/holder/ttl carried through.
	if body["branch"] != "main" || body["mode"] != "write" || body["holderId"] != "holder-x" {
		t.Errorf("attach body wrong: %+v", body)
	}
	if body["shared"] != false {
		t.Errorf("attach must request exclusive (shared=false): %+v", body)
	}
}

// TestCreateVolumeReturnsID + defaulting of the branch name.
func TestCreateVolumeReturnsID(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = w.Write([]byte(`{"volume":{"id":"vol_new"}}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "")
	id, err := c.CreateVolume(context.Background(), "tenant_1", "")
	if err != nil {
		t.Fatalf("CreateVolume: %v", err)
	}
	if id != "vol_new" {
		t.Fatalf("id = %q, want vol_new", id)
	}
	if body["tenantId"] != "tenant_1" || body["branchName"] != "main" {
		t.Errorf("create body wrong: %+v", body)
	}
}

// ---------------------------------------------------------------------------
// Error classification: IsLeaseBusy / IsLeaseLost across statuses, body codes,
// nil, wrapped, and non-HTTPError.
// ---------------------------------------------------------------------------

func TestIsLeaseBusyClassification(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"plain", errors.New("boom"), false},
		{"423-locked", &HTTPError{Status: http.StatusLocked}, true},
		{"body-code-409", &HTTPError{Status: http.StatusConflict, Body: "VOLUME_WRITE_LEASE_BUSY"}, true},
		{"wrapped-423", fmt.Errorf("attach: %w", &HTTPError{Status: http.StatusLocked}), true},
		{"unrelated-500", &HTTPError{Status: http.StatusInternalServerError, Body: "oops"}, false},
		{"lease-lost-not-busy", &HTTPError{Status: http.StatusConflict, Body: "VOLUME_LEASE_STALE"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsLeaseBusy(tc.err); got != tc.want {
				t.Fatalf("IsLeaseBusy(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestIsLeaseLostClassification(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"plain", errors.New("boom"), false},
		{"stale-body", &HTTPError{Status: http.StatusOK, Body: "VOLUME_LEASE_STALE"}, true},
		{"not-found-body", &HTTPError{Status: http.StatusOK, Body: "VOLUME_LEASE_NOT_FOUND"}, true},
		{"expired-body", &HTTPError{Status: http.StatusOK, Body: "VOLUME_LEASE_EXPIRED"}, true},
		{"409", &HTTPError{Status: http.StatusConflict}, true},
		{"410-gone", &HTTPError{Status: http.StatusGone}, true},
		{"412-precondition", &HTTPError{Status: http.StatusPreconditionFailed}, true},
		{"wrapped-409", fmt.Errorf("renew: %w", &HTTPError{Status: http.StatusConflict}), true},
		{"423-busy-not-lost", &HTTPError{Status: http.StatusLocked}, false},
		{"500-not-lost", &HTTPError{Status: http.StatusInternalServerError}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsLeaseLost(tc.err); got != tc.want {
				t.Fatalf("IsLeaseLost(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestHTTPErrorError formats Method/Path/Status/Body.
func TestHTTPErrorError(t *testing.T) {
	e := &HTTPError{Method: "POST", Path: "/x", Status: 423, Body: "busy"}
	s := e.Error()
	for _, want := range []string{"POST", "/x", "423", "busy"} {
		if !strings.Contains(s, want) {
			t.Errorf("Error()=%q missing %q", s, want)
		}
	}
}

// TestNewClientTrimsTrailingSlash: a baseURL with a trailing slash must not yield
// a double slash in request paths.
func TestNewClientTrimsTrailingSlash(t *testing.T) {
	var gotPath atomic.Value
	gotPath.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath.Store(r.URL.Path)
		_, _ = w.Write([]byte(`{"head":{"manifest":{"entries":[]}}}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL+"/", "") // trailing slash
	if _, err := c.Manifest(context.Background(), "vol", "main"); err != nil {
		t.Fatal(err)
	}
	if got := gotPath.Load().(string); strings.Contains(got, "//") {
		t.Fatalf("path has double slash: %q", got)
	}
}

// TestAuthHeaderOnlyWhenTokenSet: with a token, every request carries the Bearer
// header; with an empty token, none is sent.
func TestAuthHeaderOnlyWhenTokenSet(t *testing.T) {
	for _, tc := range []struct {
		name      string
		token     string
		wantBear  string
		wantNoHdr bool
	}{
		{"with-token", "secret", "Bearer secret", false},
		{"no-token", "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var hdr atomic.Value
			hdr.Store("")
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hdr.Store(r.Header.Get("Authorization"))
				_, _ = w.Write([]byte(`{"head":{"manifest":{"entries":[]}}}`))
			}))
			defer srv.Close()
			c := NewClient(srv.URL, tc.token)
			if _, err := c.Manifest(context.Background(), "vol", "main"); err != nil {
				t.Fatal(err)
			}
			got := hdr.Load().(string)
			if tc.wantNoHdr && got != "" {
				t.Fatalf("auth header sent with empty token: %q", got)
			}
			if !tc.wantNoHdr && got != tc.wantBear {
				t.Fatalf("auth header = %q, want %q", got, tc.wantBear)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Concurrency: a single Client is shared by many goroutines hitting all the
// read/write methods at once. Run under -race to catch shared-state data races.
// ---------------------------------------------------------------------------

func TestClientConcurrentMixedCalls(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/status"):
			_, _ = w.Write([]byte(`{"head":{"manifest":{"entries":[{"path":"a","kind":"file","size":1,"blob":{"digest":"sha256:a"}}]}}}`))
		case strings.HasPrefix(r.URL.Path, "/v1/blobs/") && r.Method == http.MethodGet:
			_, _ = w.Write([]byte("x"))
		case strings.HasPrefix(r.URL.Path, "/v1/blobs/") && r.Method == http.MethodPut:
			w.WriteHeader(http.StatusCreated)
		case strings.HasSuffix(r.URL.Path, "/attach"):
			_, _ = w.Write([]byte(`{"session":{"id":"s","lease":{"id":"l","fencingToken":1}},"branch":{"headCommitId":"h"},"manifest":{"version":"v"}}`))
		case strings.HasSuffix(r.URL.Path, "/commit"):
			_, _ = w.Write([]byte(`{"commit":{"id":"c"}}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "tok")

	const workers = 24
	var wg sync.WaitGroup
	var fail atomic.Int64
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx := context.Background()
			switch i % 4 {
			case 0:
				if _, err := c.Manifest(ctx, "vol", "main"); err != nil {
					fail.Add(1)
				}
			case 1:
				if _, err := c.Blob(ctx, "sha256:a"); err != nil {
					fail.Add(1)
				}
			case 2:
				if err := c.PutBlob(ctx, "sha256:a", []byte("x")); err != nil {
					fail.Add(1)
				}
			case 3:
				if _, err := c.Attach(ctx, "vol", "main", "h", 1000); err != nil {
					fail.Add(1)
				}
			}
		}(i)
	}
	wg.Wait()
	if fail.Load() != 0 {
		t.Fatalf("%d concurrent calls failed", fail.Load())
	}
}
