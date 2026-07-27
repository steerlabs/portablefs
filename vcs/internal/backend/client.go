// Package backend talks to the existing PortableFS volume-api over HTTP so the
// VCS can resolve a committed volume's manifest and pull blob/chunk bytes.
// Slice 1 is read-only: we only need the head manifest and blob reads.
package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Chunk is one block of a large (chunked) file: its content-addressed digest,
// byte length, and offset within the file.
type Chunk struct {
	Digest string
	Size   int64
	Offset int64
}

// Entry is a flattened manifest entry (file, directory, or symlink).
type Entry struct {
	Path            string
	Kind            string // "file" | "directory" | "symlink"
	Mode            uint32
	Size            int64
	MtimeMs         int64
	CtimeMs         int64
	AtimeMs         int64
	Executable      bool
	UID             uint32  // POSIX owner (0 = root)
	GID             uint32  // POSIX group (0 = root)
	Ino             uint64  // stable authority-assigned inode identity (0 = entry from a pre-identity manifest)
	BlobDigest      string  // whole-file blob (empty for chunked files / dirs / symlinks)
	BlobSize        int64   // storage size of the blob (== Size when uncompressed)
	BlobCompression string  // "none" | "gzip"
	BlobPacked      bool    // whether the blob is packed
	Chunks          []Chunk // present for large chunked files; read by fetching each chunk
	LinkTarget      string  // present for symlinks
}

// Client is a read-only HTTP client for volume-api.
type Client struct {
	baseURL string
	token   string
	hc      *http.Client

	// Optional rotating-credential file (manager-minted short-lived runtime
	// read credentials): when set, the CURRENT file contents are the bearer
	// token, re-read when the file changes, so the manager can rotate the
	// credential without restarting this process. The static token is the
	// fallback while the file is empty or unreadable.
	tokenFile string
	fileMu    sync.Mutex
	fileTok   string
	fileMod   time.Time
	fileSize  int64
}

// NewClient builds a Client. token may be empty (no auth header).
func NewClient(baseURL, token string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		hc:      &http.Client{Timeout: 60 * time.Second},
	}
}

// NewClientWithTokenFile builds a Client whose bearer token is read (and
// re-read on change) from tokenFile, falling back to the static token.
func NewClientWithTokenFile(baseURL, token, tokenFile string) *Client {
	c := NewClient(baseURL, token)
	c.tokenFile = tokenFile
	return c
}

// currentToken returns the live bearer token: the rotating file's contents
// when configured and readable, otherwise the static token.
func (c *Client) currentToken() string {
	if c.tokenFile == "" {
		return c.token
	}
	c.fileMu.Lock()
	defer c.fileMu.Unlock()
	info, err := os.Stat(c.tokenFile)
	if err != nil {
		return c.token
	}
	if info.ModTime().Equal(c.fileMod) && info.Size() == c.fileSize && c.fileTok != "" {
		return c.fileTok
	}
	raw, err := os.ReadFile(c.tokenFile)
	if err != nil {
		return c.token
	}
	tok := strings.TrimSpace(string(raw))
	if tok == "" {
		return c.token
	}
	c.fileTok, c.fileMod, c.fileSize = tok, info.ModTime(), info.Size()
	return tok
}

func (c *Client) get(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if token := c.currentToken(); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return c.hc.Do(req)
}

type blobJSON struct {
	Digest      string `json:"digest"`
	Size        int64  `json:"size"`
	Compression string `json:"compression"`
	Packed      bool   `json:"packed"`
}
type chunkJSON struct {
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
	Offset int64  `json:"offset"`
}
type entryJSON struct {
	Path       string      `json:"path"`
	Kind       string      `json:"kind"`
	Mode       uint32      `json:"mode"`
	Size       int64       `json:"size"`
	MtimeMs    float64     `json:"mtimeMs"` // manifests store fractional milliseconds
	CtimeMs    float64     `json:"ctimeMs"`
	AtimeMs    float64     `json:"atimeMs"`
	Executable bool        `json:"executable"`
	UID        uint32      `json:"uid"`
	GID        uint32      `json:"gid"`
	Ino        uint64      `json:"ino"`
	Blob       *blobJSON   `json:"blob"`
	Chunks     []chunkJSON `json:"chunks"`
	LinkTarget string      `json:"linkTarget"`
}
type statusJSON struct {
	Head struct {
		Manifest struct {
			Entries []entryJSON `json:"entries"`
		} `json:"manifest"`
	} `json:"head"`
}

// Manifest fetches the head commit's full manifest for a volume+branch via the
// status endpoint (one call: status returns the head commit WITH its manifest).
func (c *Client) Manifest(ctx context.Context, volumeID, branch string) ([]Entry, error) {
	if branch == "" {
		branch = "main"
	}
	p := fmt.Sprintf("/v1/volumes/%s/status?branch=%s", url.PathEscape(volumeID), url.QueryEscape(branch))
	resp, err := c.get(ctx, p)
	if err != nil {
		return nil, fmt.Errorf("status request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("status %s: http %d: %s", volumeID, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var s statusJSON
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return nil, fmt.Errorf("decode status: %w", err)
	}
	return entriesFromJSON(s.Head.Manifest.Entries), nil
}

// ManifestAt fetches the manifest of one EXACT commit. Managed cold recovery
// uses it to load the journal-selected baseCommitId — never the branch's
// possibly newer head — before replaying the retained journal suffix.
func (c *Client) ManifestAt(ctx context.Context, commitID string) ([]Entry, error) {
	resp, err := c.get(ctx, "/v1/commits/"+url.PathEscape(commitID)+"/manifest")
	if err != nil {
		return nil, fmt.Errorf("commit manifest request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("commit manifest %s: http %d: %s", commitID, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var m struct {
		Manifest struct {
			Entries []entryJSON `json:"entries"`
		} `json:"manifest"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, fmt.Errorf("decode commit manifest: %w", err)
	}
	return entriesFromJSON(m.Manifest.Entries), nil
}

func entriesFromJSON(entries []entryJSON) []Entry {
	out := make([]Entry, 0, len(entries))
	for _, e := range entries {
		mtimeMs := int64(e.MtimeMs)
		ctimeMs := int64(e.CtimeMs)
		if ctimeMs == 0 {
			ctimeMs = mtimeMs
		}
		atimeMs := int64(e.AtimeMs)
		if atimeMs == 0 {
			atimeMs = mtimeMs
		}
		ent := Entry{
			Path: e.Path, Kind: e.Kind, Mode: e.Mode, Size: e.Size,
			MtimeMs: mtimeMs, CtimeMs: ctimeMs, AtimeMs: atimeMs,
			Executable: e.Executable, LinkTarget: e.LinkTarget,
			UID: e.UID, GID: e.GID, Ino: e.Ino,
		}
		if e.Blob != nil {
			ent.BlobDigest = e.Blob.Digest
			ent.BlobSize = e.Blob.Size
			ent.BlobCompression = e.Blob.Compression
			ent.BlobPacked = e.Blob.Packed
		}
		for _, ch := range e.Chunks {
			ent.Chunks = append(ent.Chunks, Chunk{Digest: ch.Digest, Size: ch.Size, Offset: ch.Offset})
		}
		out = append(out, ent)
	}
	return out
}

// Blob fetches the raw bytes of a content-addressed blob (or chunk).
func (c *Client) Blob(ctx context.Context, digest string) ([]byte, error) {
	// Match the TS client's encodeURIComponent: the only special char in a
	// "sha256:<hex>" digest is the colon.
	seg := strings.ReplaceAll(digest, ":", "%3A")
	resp, err := c.get(ctx, "/v1/blobs/"+seg)
	if err != nil {
		return nil, fmt.Errorf("blob request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("blob %s: http %d", digest, resp.StatusCode)
	}
	// Pre-size the buffer from Content-Length so a multi-MiB blob is read in one
	// allocation instead of io.ReadAll's repeated grow-and-copy doubling.
	if resp.ContentLength > 0 {
		buf := bytes.NewBuffer(make([]byte, 0, resp.ContentLength))
		if _, err := buf.ReadFrom(resp.Body); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}
	return io.ReadAll(resp.Body)
}
