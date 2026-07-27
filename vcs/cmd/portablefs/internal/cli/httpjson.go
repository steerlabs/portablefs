package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

const defaultRequestTimeout = 60 * time.Second

// minCLIVersionHeader is the version-handshake header the control plane sets
// on /v1 responses when it wants a minimum CLI version. The name is a fixed
// protocol constant shared with the server.
const minCLIVersionHeader = "x-portablefs-min-cli-version"

// semver is a release version triple; pre-release/build suffixes are parsed
// past but do not participate in ordering (release binaries are stamped as
// plain v-major.minor.patch).
type semver struct{ major, minor, patch int }

var semverPattern = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)([-+].*)?$`)

func parseSemver(s string) (semver, bool) {
	m := semverPattern.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return semver{}, false
	}
	var v semver
	if _, err := fmt.Sscanf(m[1]+" "+m[2]+" "+m[3], "%d %d %d", &v.major, &v.minor, &v.patch); err != nil {
		return semver{}, false
	}
	return v, true
}

func (a semver) less(b semver) bool {
	if a.major != b.major {
		return a.major < b.major
	}
	if a.minor != b.minor {
		return a.minor < b.minor
	}
	return a.patch < b.patch
}

// upgradeCommand is the copy-paste fix for a too-old binary: the canonical
// installer script. It is origin-independent on purpose — self-hosted servers
// do not serve an /install route, so pointing at the deployment origin would
// 404 exactly when a version-skewed client is stuck and needs the upgrade.
func upgradeCommand() string {
	return "curl -fsSL https://raw.githubusercontent.com/steerlabs/portablefs/main/scripts/install.sh | sh"
}

// versionSkewError is the version handshake's terminal refusal: the server
// declared a minimum CLI version above this binary. It is permanent for the
// life of the process, so retry loops must never retry it.
type versionSkewError struct {
	cliVersion string
	minVersion string
	origin     string
}

func (e *versionSkewError) Error() string {
	return fmt.Sprintf("this CLI is %s but the server at %s requires at least %s; upgrade with: %s",
		e.cliVersion, e.origin, e.minVersion, upgradeCommand())
}

// httpError is a non-2xx response, carrying the server's error code/message
// when it sent one so callers can branch on status and print actionable text.
type httpError struct {
	Status  int
	Code    string
	Message string
}

func (e *httpError) Error() string {
	if friendly := friendlyErrorText(e.Code); friendly != "" {
		return friendly
	}
	msg := e.Message
	if msg == "" {
		msg = http.StatusText(e.Status)
	}
	suffix := ""
	if e.Status == 401 {
		// Every 401 is a credential problem, and the actionable next step is
		// the same everywhere: your login may be for a different server, or
		// your key was revoked.
		suffix = "; your login may be for a different server, or your key was revoked — run `portablefs login`"
	}
	if e.Code != "" {
		return fmt.Sprintf("%s (%s, HTTP %d)%s", msg, e.Code, e.Status, suffix)
	}
	return fmt.Sprintf("%s (HTTP %d)%s", msg, e.Status, suffix)
}

// friendlyErrorText translates the typed error codes users actually hit into
// plain language with a next step. The raw envelope text for these codes is
// internal jargon ("live journal authority", "manifest access", "schema
// lineage") and must never reach a user's terminal; unknown codes keep the
// upstream message so real information is never dropped.
func friendlyErrorText(code string) string {
	switch code {
	case "LIVE_AUTHORITY_ROUTE_REQUIRED":
		return "this branch is served by its live authority, which takes writes only through a mount (portablefs mount). Grep, status, snapshot, fork, and branch handle live branches directly"
	case "HISTORY_CUT_REQUIRED":
		return "this branch is retiring from live service; its committed history stays readable through snapshots (portablefs snapshots <volumeId>)"
	case "HISTORY_CUT_NOT_READY":
		return "the exact snapshot of the live state this operation runs against is still being written (it takes a few seconds); retry shortly, or watch `portablefs snapshots <volumeId>` until it shows ready"
	case "HISTORY_CUT_FAILED":
		return "this snapshot failed while being written and can never be used; create a fresh one (portablefs snapshot <volumeId>)"
	case "HISTORY_FORK_UNSUPPORTED":
		return "this server cannot fork a live branch's snapshot into a new volume; open it as a branch in the same volume instead: portablefs branch <volumeId> <branchName> --from-snapshot <snapshotId>"
	case "ACCESS_LEASE_UNAUTHORIZED":
		return "the server rejected this mount's access credentials (revoked or rotated); run `portablefs login` and remount"
	case "ACCESS_LEASE_INTERNAL":
		return "the server hit an internal error while preparing this mount (commonly the volume's authority failing to start); try again, and if it persists check the server logs (self-hosted quickstart stacks: `docker compose logs authority-manager`)"
	case "VOLUME_COMMIT_PFT2_NO_MANIFEST":
		return "this operation asked for a commit's legacy manifest, but the volume's history is content-addressed and carries none; read it through the live routes (mount/status/snapshots) — hitting this from a current CLI means the server needs an upgrade"
	}
	return ""
}

func httpStatus(err error) int {
	if he, ok := err.(*httpError); ok {
		return he.Status
	}
	return 0
}

func httpCode(err error) string {
	if he, ok := err.(*httpError); ok {
		return he.Code
	}
	return ""
}

// parseErrorBody accepts both server error envelopes: the volume-api's
// {"error":{"code","message"}} and the authority manager's {"error":"..."}.
func parseErrorBody(status int, body []byte) *httpError {
	he := &httpError{Status: status}
	var nested struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &nested); err == nil && (nested.Error.Code != "" || nested.Error.Message != "") {
		he.Code, he.Message = nested.Error.Code, nested.Error.Message
		return he
	}
	var flat struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &flat); err == nil && flat.Error != "" {
		he.Message = flat.Error
		return he
	}
	if trimmed := strings.TrimSpace(string(body)); trimmed != "" && len(trimmed) < 300 {
		he.Message = trimmed
	}
	return he
}

// jsonClient issues bearer-authenticated JSON requests against one base URL.
type jsonClient struct {
	baseURL string
	token   string
	http    *http.Client

	// cliVersion/warnW arm the per-response version handshake (see
	// checkMinCLIVersion). Command code constructs clients through the
	// cmdEnv helpers (cmdEnv.apiClient/managerClient/jsonClient), which bind
	// them; a bare newJSONClient carries no handshake.
	cliVersion  string
	warnW       io.Writer
	devWarnOnce sync.Once
}

func newJSONClient(baseURL, token string) *jsonClient {
	return &jsonClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http:    &http.Client{},
	}
}

// jsonClient is the env-bound constructor every command path uses: it arms
// the version handshake with this process's version and warning sink.
func (e *cmdEnv) jsonClient(baseURL, token string) *jsonClient {
	c := newJSONClient(baseURL, token)
	c.cliVersion = e.version
	c.warnW = e.stderr
	return c
}

// checkMinCLIVersion enforces the server's version handshake on ONE response
// (nothing is cached; every response is evaluated on its own). A response
// without the header, or with one that does not parse, passes. A binary
// version that is valid semver below the minimum is a terminal refusal; a
// non-semver build ("dev", locally built) warns once per client and
// proceeds, because it cannot be ordered against a release version.
func (c *jsonClient) checkMinCLIVersion(h http.Header) error {
	minRaw := strings.TrimSpace(h.Get(minCLIVersionHeader))
	if minRaw == "" {
		return nil
	}
	minRequired, ok := parseSemver(minRaw)
	if !ok {
		return nil
	}
	cli, ok := parseSemver(c.cliVersion)
	if !ok {
		c.devWarnOnce.Do(func() {
			if c.warnW != nil {
				fmt.Fprintf(c.warnW,
					"portablefs: warning: the server at %s requires CLI %s or newer; this %q build skips the check — if commands misbehave, upgrade with: %s\n",
					c.baseURL, minRaw, c.cliVersion, upgradeCommand())
			}
		})
		return nil
	}
	if cli.less(minRequired) {
		return &versionSkewError{cliVersion: c.cliVersion, minVersion: minRaw, origin: c.baseURL}
	}
	return nil
}

// do sends method+path with an optional JSON body and decodes a 2xx JSON
// response into out (out nil = discard). body non-nil is JSON-encoded; use an
// empty map for an explicit empty JSON object body. timeout <= 0 uses the
// default.
func (c *jsonClient) do(ctx context.Context, method, path string, body, out any, timeout time.Duration) error {
	return c.doIdempotent(ctx, method, path, body, out, timeout, "")
}

// doIdempotent is do with a caller-retained Idempotency-Key. Hosted control
// planes require the header on resource mutations (their exact-operation
// ledger replays the recorded outcome for the same key instead of repeating
// the effect); the self-host volume-api ignores it. Callers mint one key per
// LOGICAL operation and reuse it across retries of that operation.
func (c *jsonClient) doIdempotent(ctx context.Context, method, path string, body, out any, timeout time.Duration, idempotencyKey string) error {
	if timeout <= 0 {
		timeout = defaultRequestTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var rd io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("content-type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("authorization", "Bearer "+c.token)
	}
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, c.baseURL+path, err)
	}
	defer resp.Body.Close()
	if verr := c.checkMinCLIVersion(resp.Header); verr != nil {
		return verr
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return fmt.Errorf("%s %s: read response: %w", method, c.baseURL+path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return parseErrorBody(resp.StatusCode, data)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s %s: parse response: %w", method, c.baseURL+path, err)
	}
	return nil
}

// mintIdempotencyKey mints the caller-retained key for one logical resource
// mutation (volume create, snapshot, branch, fork). Reuses the CLI's v4-UUID
// minting; hosted ledgers key replay on it, self-host ignores it.
func mintIdempotencyKey() string {
	return "cli-" + newOperationID()
}

// doRaw is do without status interpretation: it returns the HTTP status and
// body so flows that branch on specific codes (device login polling) can.
func (c *jsonClient) doRaw(ctx context.Context, method, path string, body any) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, defaultRequestTimeout)
	defer cancel()
	var rd io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rd = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rd)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("content-type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%s %s: %w", method, c.baseURL+path, err)
	}
	defer resp.Body.Close()
	if verr := c.checkMinCLIVersion(resp.Header); verr != nil {
		return 0, nil, verr
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, nil, fmt.Errorf("%s %s: read response: %w", method, c.baseURL+path, err)
	}
	return resp.StatusCode, data, nil
}
