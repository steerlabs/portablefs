package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"time"
)

// volumeNamePattern mirrors the server-side volume id constraints; validating
// client-side turns a 400 round-trip into an immediate, specific error.
var volumeNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,220}$`)

func validVolumeName(name string) bool { return volumeNamePattern.MatchString(name) }

// apiClient speaks the volume-api HTTP surface (docs/api.md).
type apiClient struct {
	*jsonClient
}

func newAPIClient(baseURL, token string) *apiClient {
	return &apiClient{jsonClient: newJSONClient(baseURL, token)}
}

// apiClient is the env-bound constructor command code uses (arms the version
// handshake); newAPIClient stays for handshake-free direct construction.
func (e *cmdEnv) apiClient(baseURL, token string) *apiClient {
	return &apiClient{jsonClient: e.jsonClient(baseURL, token)}
}

type volumeInfo struct {
	ID        string `json:"id"`
	TenantID  string `json:"tenantId"`
	CreatedAt int64  `json:"createdAt"`
}

type branchInfo struct {
	ID           string `json:"id"`
	VolumeID     string `json:"volumeId"`
	Name         string `json:"name"`
	HeadCommitID string `json:"headCommitId"`
	CreatedAt    int64  `json:"createdAt"`
	UpdatedAt    int64  `json:"updatedAt"`
	// BranchMode is the branch's serving mode (legacy_manifest,
	// managed_journal, migrating, retiring, retired). Additive: servers
	// that predate branch modes leave it empty.
	BranchMode string `json:"branchMode"`
}

// isJournalServed reports whether the branch is served by a live journal
// authority — the modes whose manifest head is not live truth.
func (b branchInfo) isJournalServed() bool {
	return b.BranchMode == "managed_journal" || b.BranchMode == "migrating"
}

// commitInfo is a commit summary; the full-manifest fields the server may echo
// are deliberately not decoded.
type commitInfo struct {
	ID             string `json:"id"`
	TreeHash       string `json:"treeHash"`
	ParentCommitID string `json:"parentCommitId"`
	MutationCount  int64  `json:"mutationCount"`
	ByteCount      int64  `json:"byteCount"`
	CreatedAt      int64  `json:"createdAt"`
}

type volumeMutationResponse struct {
	Volume volumeInfo `json:"volume"`
	Branch branchInfo `json:"branch"`
	Head   commitInfo `json:"head"`
}

// createVolume creates a JOURNAL-BORN volume with branch "main": the branch
// is born managed_journal so the managed authority can serve it immediately
// (mount works with no conversion step). name and tenantID are optional; the
// server generates a volume id when name is empty and derives the tenant from
// the credential when tenantID is empty. Adopt deliberately does NOT use
// this: it authors the base through manifest commits, which requires the
// legacy authoring birth.
func (c *apiClient) createVolume(ctx context.Context, name, tenantID string) (*volumeMutationResponse, error) {
	body := map[string]any{"branchName": "main", "managed": true}
	if name != "" {
		body["volumeId"] = name
	}
	if tenantID != "" {
		body["tenantId"] = tenantID
	}
	var out volumeMutationResponse
	idempotencyKey, err := mintIdempotencyKey()
	if err != nil {
		return nil, err
	}
	if err := c.doIdempotent(ctx, "POST", "/v1/volumes", body, &out, 0, idempotencyKey); err != nil {
		if httpCode(err) == "VOLUME_VALIDATION_FAILED" && tenantID == "" {
			return nil, fmt.Errorf("create volume: %w (this volume-api build requires a tenantId in the request; pass --tenant <id>)", err)
		}
		return nil, err
	}
	return &out, nil
}

type listedBranch struct {
	Name         string `json:"name"`
	HeadCommitID string `json:"headCommitId"`
}

type listedVolume struct {
	VolumeID    string         `json:"volumeId"`
	TenantID    string         `json:"tenantId"`
	CreatedAtMs int64          `json:"createdAtMs"`
	Branches    []listedBranch `json:"branches"`
}

// journalActivationResponse mirrors POST /v1/volumes/:id/activate-journal:
// the poll-driven journal activation status (the legacy->managed conversion
// adopt drives after authoring its base).
type journalActivationResponse struct {
	State      string `json:"state"` // active | converting | failed
	BranchMode string `json:"branchMode"`
	// CutState/AttemptCount/LastError are additive top-level activation
	// telemetry (absent on older servers): the underlying history cut's
	// state, its attempt counter, and the last failure text. A CutState of
	// "failed" is terminal — polling further can never succeed.
	CutState     string `json:"cutState"`
	AttemptCount int    `json:"attemptCount"`
	LastError    string `json:"lastError"`
	Conversion   *struct {
		ConversionID string          `json:"conversionId"`
		State        string          `json:"state"`
		Attempt      int             `json:"attempt"`
		LastError    json.RawMessage `json:"lastError"`
	} `json:"conversion"`
	Cut *struct {
		CutID        string          `json:"cutId"`
		State        string          `json:"state"`
		AttemptCount int             `json:"attemptCount"`
		LastError    json.RawMessage `json:"lastError"`
	} `json:"cut"`
}

// activateJournal advances one journal-activation step server-side and
// answers the current status. Idempotent; callers poll until "active".
func (c *apiClient) activateJournal(ctx context.Context, volumeID, branch string) (*journalActivationResponse, error) {
	path := fmt.Sprintf("/v1/volumes/%s/activate-journal", url.PathEscape(volumeID))
	body := map[string]string{}
	if branch != "" {
		body["branch"] = branch
	}
	var out journalActivationResponse
	if err := c.do(ctx, "POST", path, body, &out, 0); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *apiClient) listVolumes(ctx context.Context, limit int) ([]listedVolume, error) {
	path := "/v1/volumes"
	if limit > 0 {
		path += fmt.Sprintf("?limit=%d", limit)
	}
	var out struct {
		Volumes []listedVolume `json:"volumes"`
	}
	if err := c.do(ctx, "GET", path, nil, &out, 0); err != nil {
		return nil, err
	}
	return out.Volumes, nil
}

// retireVolumeReceipt mirrors DELETE /v1/volumes/:volumeId — the receipted
// retirement contract: the retired volume id plus the ISO8601 instant it left
// service.
type retireVolumeReceipt struct {
	VolumeID  string `json:"volumeId"`
	RetiredAt string `json:"retiredAt"`
}

// retireVolume issues the receipted retirement. Unknown, foreign, and
// already-retired volumes all answer the same non-enumerating 404; hosted
// control planes replay retries exact-once through the Idempotency-Key.
func (c *apiClient) retireVolume(ctx context.Context, volumeID string) (*retireVolumeReceipt, error) {
	var out retireVolumeReceipt
	path := fmt.Sprintf("/v1/volumes/%s", url.PathEscape(volumeID))
	idempotencyKey, err := mintIdempotencyKey()
	if err != nil {
		return nil, err
	}
	if err := c.doIdempotent(ctx, "DELETE", path, nil, &out, 0, idempotencyKey); err != nil {
		return nil, err
	}
	return &out, nil
}

// resolveVolumeTenant answers the volume's tenant id through mode-agnostic
// metadata: the volume LISTING first (metadata-only, answers for every branch
// mode), then the manifest head as a backstop for credentials that cannot
// list (the admin token cannot list without an explicit tenant, but head is
// per-volume and answers for base-authoring branches). Best-effort: an
// unresolvable tenant returns "" and callers omit the field — servers that
// require it produce their own typed error.
func (c *apiClient) resolveVolumeTenant(ctx context.Context, volumeID, branch string) string {
	if listed, err := c.listVolumes(ctx, 1000); err == nil {
		for _, volume := range listed {
			if volume.VolumeID == volumeID {
				return volume.TenantID
			}
		}
	}
	if head, err := c.head(ctx, volumeID, branch); err == nil && head != nil {
		return head.Volume.TenantID
	}
	return ""
}

type headResponse struct {
	Volume            volumeInfo `json:"volume"`
	Branch            branchInfo `json:"branch"`
	Head              commitInfo `json:"head"`
	ActiveLeases      int64      `json:"activeLeases"`
	ActiveDelegations int64      `json:"activeDelegations"`
}

// head fetches the manifest-free branch head summary plus lease/delegation counts.
func (c *apiClient) head(ctx context.Context, volumeID, branch string) (*headResponse, error) {
	var out headResponse
	path := fmt.Sprintf("/v1/volumes/%s/head?branch=%s", url.PathEscape(volumeID), url.QueryEscape(branch))
	if err := c.do(ctx, "GET", path, nil, &out, 0); err != nil {
		return nil, err
	}
	return &out, nil
}

type historyCommit struct {
	ID             string `json:"id"`
	TreeHash       string `json:"treeHash"`
	CreatedAtMs    int64  `json:"createdAtMs"`
	MutationCount  int64  `json:"mutationCount"`
	ByteCount      int64  `json:"byteCount"`
	ParentCommitID string `json:"parentCommitId"`
	// CommitKind is the additive commit-family discriminator: "pft2" for
	// journal-era cut commits, empty for manifest commits.
	CommitKind string `json:"commitKind"`
}

func (c *apiClient) history(ctx context.Context, volumeID, branch string, limit int) ([]historyCommit, error) {
	var out struct {
		Commits []historyCommit `json:"commits"`
	}
	path := fmt.Sprintf("/v1/volumes/%s/commits?branch=%s&limit=%d",
		url.PathEscape(volumeID), url.QueryEscape(branch), limit)
	if err := c.do(ctx, "GET", path, nil, &out, 0); err != nil {
		return nil, err
	}
	return out.Commits, nil
}

type snapshotInfo struct {
	ID        string `json:"id"`
	VolumeID  string `json:"volumeId"`
	BranchID  string `json:"branchId"`
	CommitID  string `json:"commitId"`
	Name      string `json:"name"`
	CreatedAt int64  `json:"createdAt"`
	// Journal-era lifecycle fields (additive; empty on older servers and on
	// commit-pinned records, which are born ready). A snapshot of a
	// journal-served branch is an asynchronous history cut: State walks
	// pending -> materializing -> ready (or failed/canceled), CutID names
	// the cut, and ResultCommitID is the published commit once ready.
	State          string `json:"state"`
	CutID          string `json:"cutId"`
	ResultCommitID string `json:"resultCommitId"`
}

// isReady reports whether the snapshot can be branched or forked right now.
// Older servers emit no state field; their records are always born ready.
func (s snapshotInfo) isReady() bool { return s.State == "" || s.State == "ready" }

// isMaterializing reports whether the snapshot is a cut still being written.
func (s snapshotInfo) isMaterializing() bool {
	return s.State == "pending" || s.State == "materializing"
}

// isDead reports a definitively failed cut (can never become ready).
func (s snapshotInfo) isDead() bool { return s.State == "failed" || s.State == "canceled" }

func (c *apiClient) snapshot(ctx context.Context, volumeID, branch, name string) (*snapshotInfo, error) {
	body := map[string]string{"branch": branch}
	if name != "" {
		body["name"] = name
	}
	var out struct {
		Snapshot snapshotInfo `json:"snapshot"`
	}
	path := fmt.Sprintf("/v1/volumes/%s/snapshots", url.PathEscape(volumeID))
	idempotencyKey, err := mintIdempotencyKey()
	if err != nil {
		return nil, err
	}
	if err := c.doIdempotent(ctx, "POST", path, body, &out, 0, idempotencyKey); err != nil {
		return nil, err
	}
	return &out.Snapshot, nil
}

func (c *apiClient) snapshots(ctx context.Context, volumeID, branch string) ([]snapshotInfo, error) {
	path := fmt.Sprintf("/v1/volumes/%s/snapshots", url.PathEscape(volumeID))
	if branch != "" {
		path += "?branch=" + url.QueryEscape(branch)
	}
	var out struct {
		Snapshots []snapshotInfo `json:"snapshots"`
	}
	if err := c.do(ctx, "GET", path, nil, &out, 0); err != nil {
		return nil, err
	}
	return out.Snapshots, nil
}

type createBranchResponse struct {
	Branch branchInfo `json:"branch"`
	Head   commitInfo `json:"head"`
	// CommitKind is set ("pft2") when the branch was born from a ready
	// history cut; such heads are manifest-free commit summaries.
	CommitKind string `json:"commitKind"`
}

// createBranch creates a same-volume branch. Exactly one source wins:
// fromSnapshotID (any snapshot record id, including ready history cuts) beats
// fromSnapshotName (commit-pinned snapshots by name) beats the fromBranch
// head. fromSnapshotId has been in the request schema since the first
// release, so sending it is safe against every server of this lineage.
func (c *apiClient) createBranch(ctx context.Context, volumeID, branchName, fromBranch, fromSnapshotName, fromSnapshotID string) (*createBranchResponse, error) {
	body := map[string]string{"branchName": branchName, "fromBranch": fromBranch}
	if fromSnapshotID != "" {
		body["fromSnapshotId"] = fromSnapshotID
	} else if fromSnapshotName != "" {
		body["fromSnapshotName"] = fromSnapshotName
	}
	var out createBranchResponse
	path := fmt.Sprintf("/v1/volumes/%s/branches", url.PathEscape(volumeID))
	idempotencyKey, err := mintIdempotencyKey()
	if err != nil {
		return nil, err
	}
	if err := c.doIdempotent(ctx, "POST", path, body, &out, 0, idempotencyKey); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *apiClient) branches(ctx context.Context, volumeID string) ([]branchInfo, error) {
	var out struct {
		Branches []branchInfo `json:"branches"`
	}
	path := fmt.Sprintf("/v1/volumes/%s/branches", url.PathEscape(volumeID))
	if err := c.do(ctx, "GET", path, nil, &out, 0); err != nil {
		return nil, err
	}
	return out.Branches, nil
}

// forkSnapshot creates a new volume at snapshotID's commit. tenantID is the
// source volume's tenant (the server also derives it from the credential;
// sending it keeps older builds with a required-tenantId schema working).
func (c *apiClient) forkSnapshot(ctx context.Context, snapshotID, tenantID, newVolumeID string) (*volumeMutationResponse, error) {
	body := map[string]string{"branchName": "main"}
	if tenantID != "" {
		body["tenantId"] = tenantID
	}
	if newVolumeID != "" {
		body["volumeId"] = newVolumeID
	}
	var out volumeMutationResponse
	path := fmt.Sprintf("/v1/snapshots/%s/fork", url.PathEscape(snapshotID))
	idempotencyKey, err := mintIdempotencyKey()
	if err != nil {
		return nil, err
	}
	if err := c.doIdempotent(ctx, "POST", path, body, &out, 0, idempotencyKey); err != nil {
		return nil, err
	}
	return &out, nil
}

type grepMatch struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Text string `json:"text"`
}

type grepResult struct {
	Matches       []grepMatch `json:"matches"`
	StoppedReason string      `json:"stoppedReason"`
	DurationMs    float64     `json:"durationMs"`
	HeadCommitID  string      `json:"headCommitId"`
}

func (c *apiClient) grep(ctx context.Context, volumeID, branch, dir, pattern string, maxResults int) (*grepResult, error) {
	body := map[string]any{
		"branch":     branch,
		"directory":  dir,
		"pattern":    pattern,
		"recursive":  true,
		"maxResults": maxResults,
	}
	var out grepResult
	path := fmt.Sprintf("/v1/volumes/%s/grep", url.PathEscape(volumeID))
	if err := c.do(ctx, "POST", path, body, &out, 2*time.Minute); err != nil {
		return nil, err
	}
	return &out, nil
}
