package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// BlobRef / ChunkRef / ManifestEntry / Manifest mirror the wire shapes the
// volume-api expects on commit.
type BlobRef struct {
	Digest      string `json:"digest"`
	Size        int64  `json:"size"`
	Compression string `json:"compression"`
	Packed      bool   `json:"packed"`
}
type ChunkRef struct {
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
	Offset int64  `json:"offset"`
}
type ManifestEntry struct {
	Path       string     `json:"path"`
	Kind       string     `json:"kind"`
	Mode       uint32     `json:"mode"`
	Size       int64      `json:"size"`
	MtimeMs    int64      `json:"mtimeMs"`
	CtimeMs    int64      `json:"ctimeMs,omitempty"`
	AtimeMs    int64      `json:"atimeMs,omitempty"`
	Executable bool       `json:"executable"`
	UID        uint32     `json:"uid,omitempty"` // omitted (== root) keeps the tree hash back-compatible
	GID        uint32     `json:"gid,omitempty"`
	Ino        uint64     `json:"ino,omitempty"` // stable inode identity; persisted but EXCLUDED from the tree hash
	Blob       *BlobRef   `json:"blob,omitempty"`
	Chunks     []ChunkRef `json:"chunks,omitempty"`
	LinkTarget string     `json:"linkTarget,omitempty"`
}
type Manifest struct {
	Version  string          `json:"version"`
	TreeHash string          `json:"treeHash"`
	Entries  []ManifestEntry `json:"entries"`
}

// AttachResult holds the session + lease needed to commit.
type AttachResult struct {
	SessionID       string
	LeaseID         string
	FencingToken    int64
	HeadCommitID    string
	ManifestVersion string
}

// CommitInput is a full-manifest commit.
type CommitInput struct {
	ExpectedHeadCommitID string
	LeaseID              string
	FencingToken         int64
	Manifest             Manifest
	MutationCount        int64
	ByteCount            int64
}

func (c *Client) postJSON(ctx context.Context, path string, body any, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token := c.currentToken(); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return &HTTPError{Method: http.MethodPost, Path: path, Status: resp.StatusCode, Body: strings.TrimSpace(string(data))}
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

// CreateVolume creates a new volume and returns its id.
func (c *Client) CreateVolume(ctx context.Context, tenantID, branch string) (string, error) {
	if branch == "" {
		branch = "main"
	}
	var out struct {
		Volume struct {
			ID string `json:"id"`
		} `json:"volume"`
	}
	if err := c.postJSON(ctx, "/v1/volumes", map[string]any{"tenantId": tenantID, "branchName": branch}, &out); err != nil {
		return "", err
	}
	return out.Volume.ID, nil
}

// PutBlob uploads a content-addressed blob. The server verifies the digest.
func (c *Client) PutBlob(ctx context.Context, digest string, data []byte) error {
	seg := strings.ReplaceAll(digest, ":", "%3A")
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+"/v1/blobs/"+seg, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if token := c.currentToken(); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("PUT blob %s: http %d: %s", digest, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// Attach opens a write session + lease on a branch. This is the explicit
// legacy-manifest authoring path (adopt/base authoring on legacy_manifest
// branches). Managed authorities must use AttachReceipted: it is the only
// attach the volume API admits on a journal-owned branch, and its
// retry-stable operation id means a lost response cannot orphan an exclusive
// lease and manufacture another session on retry.
func (c *Client) Attach(ctx context.Context, volumeID, branch, holderID string, leaseTtlMs int64) (*AttachResult, error) {
	return c.attachAt(ctx, "/v1/volumes/"+url.PathEscape(volumeID)+"/attach", branch, holderID, leaseTtlMs, "")
}

// AttachReceipted opens a managed write session using a retry-stable
// operation id. Repeating the exact request returns the original outcome; an
// old server cannot silently accept it because the route is distinct.
func (c *Client) AttachReceipted(ctx context.Context, volumeID, branch, holderID string, leaseTtlMs int64, operationID string) (*AttachResult, error) {
	if operationID == "" || len(operationID) > 256 {
		return nil, fmt.Errorf("attach operation id must be 1..256 bytes")
	}
	return c.attachAt(ctx, "/v1/volumes/"+url.PathEscape(volumeID)+"/attach-receipted", branch, holderID, leaseTtlMs, operationID)
}

func (c *Client) attachAt(ctx context.Context, path, branch, holderID string, leaseTtlMs int64, operationID string) (*AttachResult, error) {
	if branch == "" {
		branch = "main"
	}
	body := map[string]any{
		"branch": branch, "mode": "write", "shared": false,
		"holderId": holderID, "leaseTtlMs": leaseTtlMs,
	}
	if operationID != "" {
		body["operationId"] = operationID
	}
	var out struct {
		Session struct {
			ID    string `json:"id"`
			Lease struct {
				ID           string `json:"id"`
				FencingToken int64  `json:"fencingToken"`
			} `json:"lease"`
		} `json:"session"`
		Branch struct {
			HeadCommitID string `json:"headCommitId"`
		} `json:"branch"`
		Manifest struct {
			Version string `json:"version"`
		} `json:"manifest"`
		Receipt struct {
			OperationID string `json:"operationId"`
			Replayed    bool   `json:"replayed"`
		} `json:"receipt"`
	}
	if err := c.postJSON(ctx, path, body, &out); err != nil {
		return nil, err
	}
	if operationID != "" && out.Receipt.OperationID != operationID {
		return nil, fmt.Errorf("receipted attach response operation id = %q, want %q", out.Receipt.OperationID, operationID)
	}
	return &AttachResult{
		SessionID:       out.Session.ID,
		LeaseID:         out.Session.Lease.ID,
		FencingToken:    out.Session.Lease.FencingToken,
		HeadCommitID:    out.Branch.HeadCommitID,
		ManifestVersion: out.Manifest.Version,
	}, nil
}

// Commit advances the branch head with a full manifest. Returns the new commit id.
func (c *Client) Commit(ctx context.Context, sessionID string, in CommitInput) (string, error) {
	body := map[string]any{
		"leaseId":              in.LeaseID,
		"fencingToken":         in.FencingToken,
		"expectedHeadCommitId": in.ExpectedHeadCommitID,
		"manifest":             in.Manifest,
		"mutationCount":        in.MutationCount,
		"byteCount":            in.ByteCount,
	}
	var out struct {
		Commit struct {
			ID string `json:"id"`
		} `json:"commit"`
	}
	if err := c.postJSON(ctx, "/v1/attach-sessions/"+url.PathEscape(sessionID)+"/commit", body, &out); err != nil {
		return "", err
	}
	return out.Commit.ID, nil
}

// Detach closes the session and releases its lease.
func (c *Client) Detach(ctx context.Context, sessionID string) error {
	return c.postJSON(ctx, "/v1/attach-sessions/"+url.PathEscape(sessionID)+"/detach",
		map[string]any{"releaseLease": true}, nil)
}

// RenewLease extends a held lease's expiry (fenced by fencingToken).
func (c *Client) RenewLease(ctx context.Context, leaseID string, fencingToken, leaseTtlMs int64) error {
	return c.postJSON(ctx, "/v1/leases/"+url.PathEscape(leaseID)+"/renew",
		map[string]any{"fencingToken": fencingToken, "leaseTtlMs": leaseTtlMs}, nil)
}
