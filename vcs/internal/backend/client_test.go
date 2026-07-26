package backend

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestManifestParsesFilesChunksAndSymlinks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("missing/wrong auth header: %q", got)
		}
		switch r.URL.Path {
		case "/v1/volumes/vol_1/status":
			if b := r.URL.Query().Get("branch"); b != "main" {
				t.Errorf("branch query = %q, want main", b)
			}
			_, _ = w.Write([]byte(`{"head":{"manifest":{"entries":[
			  {"path":"a.txt","kind":"file","mode":420,"size":3,"mtimeMs":7,"executable":false,"blob":{"digest":"sha256:deadbeef"}},
			  {"path":"big.bin","kind":"file","mode":420,"size":6,"chunks":[{"digest":"sha256:c1","size":3,"offset":0},{"digest":"sha256:c2","size":3,"offset":3}]},
			  {"path":"dir","kind":"directory","mode":493,"size":0},
			  {"path":"link","kind":"symlink","mode":511,"linkTarget":"a.txt"}
			]}}}`))
		case "/v1/blobs/sha256:deadbeef":
			_, _ = w.Write([]byte("abc"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "tok")
	entries, err := c.Manifest(context.Background(), "vol_1", "main")
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("got %d entries, want 4", len(entries))
	}
	if entries[0].Path != "a.txt" || entries[0].BlobDigest != "sha256:deadbeef" || entries[0].Size != 3 || entries[0].MtimeMs != 7 {
		t.Errorf("file entry wrong: %+v", entries[0])
	}
	if entries[1].Path != "big.bin" || len(entries[1].Chunks) != 2 ||
		entries[1].Chunks[0].Digest != "sha256:c1" || entries[1].Chunks[1].Offset != 3 {
		t.Errorf("chunked entry wrong: %+v", entries[1])
	}
	if entries[2].Kind != "directory" {
		t.Errorf("dir entry wrong: %+v", entries[2])
	}
	if entries[3].Kind != "symlink" || entries[3].LinkTarget != "a.txt" {
		t.Errorf("symlink entry wrong: %+v", entries[3])
	}

	b, err := c.Blob(context.Background(), "sha256:deadbeef")
	if err != nil || string(b) != "abc" {
		t.Fatalf("Blob = %q, %v; want abc", b, err)
	}
}

func TestManifestHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":{"code":"VOLUME_NOT_FOUND"}}`, http.StatusNotFound)
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "")
	if _, err := c.Manifest(context.Background(), "missing", "main"); err == nil {
		t.Fatal("expected error for 404 status, got nil")
	}
}

// The rotating credential file is the live bearer token: its contents are
// re-read when the file changes (the manager rotates by replacing the file),
// and the static token remains the fallback while the file is missing or
// empty. This is how managed children keep a valid volume-api identity
// across credential rotations without restarting.
func TestTokenFileIsReadAndReReadOnRotation(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"head":{"manifest":{"entries":[]}}}`))
	}))
	defer srv.Close()

	file := filepath.Join(t.TempDir(), "volume-api-credential")
	c := NewClientWithTokenFile(srv.URL, "static-fallback", file)

	// Missing file: the static token is the fallback.
	if _, err := c.Manifest(context.Background(), "vol_1", "main"); err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	// First credential.
	if err := os.WriteFile(file, []byte("pfrc_first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Manifest(context.Background(), "vol_1", "main"); err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	// Rotation: atomic replace with different contents and a different mtime.
	tmp := file + ".tmp"
	if err := os.WriteFile(tmp, []byte("pfrc_second\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(tmp, future, future); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, file); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Manifest(context.Background(), "vol_1", "main"); err != nil {
		t.Fatalf("Manifest: %v", err)
	}

	want := []string{"Bearer static-fallback", "Bearer pfrc_first", "Bearer pfrc_second"}
	if len(seen) != len(want) {
		t.Fatalf("saw %d requests, want %d (%v)", len(seen), len(want), seen)
	}
	for i, header := range want {
		if seen[i] != header {
			t.Errorf("request %d auth = %q, want %q", i, seen[i], header)
		}
	}
}
