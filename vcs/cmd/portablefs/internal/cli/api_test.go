package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

// recordedRequest captures one request the fake server saw.
type recordedRequest struct {
	Method         string
	Path           string
	Body           map[string]any
	IdempotencyKey string
}

// fakeServer is a scriptable volume-api/manager double that records requests.
type fakeServer struct {
	mu       sync.Mutex
	requests []recordedRequest
	routes   map[string]func(body map[string]any) (int, string)
	srv      *httptest.Server
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	f := &fakeServer{routes: map[string]func(map[string]any) (int, string){}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&body)
		}
		key := r.Method + " " + r.URL.Path
		f.mu.Lock()
		f.requests = append(f.requests, recordedRequest{
			Method:         r.Method,
			Path:           r.URL.Path + querySuffix(r),
			Body:           body,
			IdempotencyKey: r.Header.Get("Idempotency-Key"),
		})
		handler := f.routes[key]
		f.mu.Unlock()
		if handler == nil {
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"error":{"code":"VOLUME_NOT_FOUND","message":"Route not found."}}`))
			return
		}
		status, resp := handler(body)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(resp))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func querySuffix(r *http.Request) string {
	if r.URL.RawQuery == "" {
		return ""
	}
	return "?" + r.URL.RawQuery
}

func (f *fakeServer) on(method, path string, handler func(map[string]any) (int, string)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[method+" "+path] = handler
}

func (f *fakeServer) recorded() []recordedRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedRequest(nil), f.requests...)
}

func (f *fakeServer) commonArgs(extra ...string) []string {
	return append(extra, "--api-url", f.srv.URL, "--api-token", "tok")
}

func TestCreateVolumeBodyAndOutput(t *testing.T) {
	f := newFakeServer(t)
	f.on("POST", "/v1/volumes", func(body map[string]any) (int, string) {
		if body["volumeId"] != "agent-ws" || body["branchName"] != "main" {
			return 400, `{"error":{"code":"BAD","message":"unexpected body"}}`
		}
		if _, hasTenant := body["tenantId"]; hasTenant {
			return 400, `{"error":{"code":"BAD","message":"tenantId must be omitted unless --tenant"}}`
		}
		return 201, `{"volume":{"id":"agent-ws","tenantId":"t1"},"branch":{"name":"main","headCommitId":"cmt_1"},"head":{"id":"cmt_1","treeHash":"sha256:aa"}}`
	})
	e, stdout, _ := testEnv(t)
	if rc := e.run(f.commonArgs("create", "agent-ws")); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	out := stdout.String()
	if !strings.Contains(out, "agent-ws") || !strings.Contains(out, "main") || !strings.Contains(out, "cmt_1") {
		t.Fatalf("create output must show volume, branch, head: %q", out)
	}
}

// TestResourceMutationsCarryIdempotencyKeys pins the hosted-control-plane
// contract: every resource mutation (create, snapshot, branch, fork) sends a
// caller-retained Idempotency-Key; reads never do. Hosted ledgers reject
// keyless mutations before any effect (IDEMPOTENCY_KEY_REQUIRED).
func TestResourceMutationsCarryIdempotencyKeys(t *testing.T) {
	f := newFakeServer(t)
	f.on("POST", "/v1/volumes", func(map[string]any) (int, string) {
		return 201, `{"volume":{"id":"v1","tenantId":"t"},"branch":{"name":"main","headCommitId":"c"},"head":{"id":"c","treeHash":"sha256:aa"}}`
	})
	f.on("POST", "/v1/volumes/v1/snapshots", func(map[string]any) (int, string) {
		return 201, `{"snapshot":{"id":"snp_1","volumeId":"v1","branchId":"b","commitId":"c","name":"s1","createdAt":1}}`
	})
	f.on("POST", "/v1/volumes/v1/branches", func(map[string]any) (int, string) {
		return 201, `{"branch":{"name":"dev","headCommitId":"c"},"head":{"id":"c","treeHash":"sha256:aa"}}`
	})
	f.on("POST", "/v1/snapshots/snp_1/fork", func(map[string]any) (int, string) {
		return 201, `{"volume":{"id":"v2","tenantId":"t"},"branch":{"name":"main","headCommitId":"c"},"head":{"id":"c","treeHash":"sha256:aa"}}`
	})
	f.on("GET", "/v1/volumes/v1/snapshots", func(map[string]any) (int, string) {
		return 200, `{"snapshots":[]}`
	})
	f.on("GET", "/v1/volumes/v1/head", func(map[string]any) (int, string) {
		return 200, `{"volume":{"id":"v1","tenantId":"t"},"branch":{"name":"main","headCommitId":"c"},"head":{"id":"c","treeHash":"sha256:aa"},"activeLeases":0,"activeDelegations":0}`
	})

	e, _, _ := testEnv(t)
	for _, args := range [][]string{
		f.commonArgs("create", "v1"),
		f.commonArgs("snapshot", "v1", "--name", "s1"),
		f.commonArgs("branch", "v1", "dev", "--from-branch", "main"),
		// fork without --snapshot snapshots the branch head first: two keyed
		// mutations (snapshot, then fork) for one command.
		f.commonArgs("fork", "v1", "--name", "v2"),
	} {
		if rc := e.run(args); rc != 0 {
			t.Fatalf("%v rc = %d", args, rc)
		}
	}

	keys := map[string]bool{}
	for _, req := range f.recorded() {
		if req.Method == "POST" {
			if req.IdempotencyKey == "" || len(req.IdempotencyKey) > 128 {
				t.Fatalf("POST %s must carry a bounded Idempotency-Key, got %q", req.Path, req.IdempotencyKey)
			}
			if keys[req.IdempotencyKey] {
				t.Fatalf("each logical operation must mint its own key; %q reused", req.IdempotencyKey)
			}
			keys[req.IdempotencyKey] = true
		} else if req.IdempotencyKey != "" {
			t.Fatalf("read %s %s must not carry an Idempotency-Key", req.Method, req.Path)
		}
	}
	if len(keys) != 5 {
		t.Fatalf("expected 5 keyed mutations (create, snapshot, branch, fork-snapshot, fork), saw %d", len(keys))
	}
}

func TestCreateVolumeTenantFlagIncluded(t *testing.T) {
	f := newFakeServer(t)
	f.on("POST", "/v1/volumes", func(body map[string]any) (int, string) {
		if body["tenantId"] != "team_9" {
			return 400, `{"error":{"code":"BAD","message":"missing tenantId"}}`
		}
		return 201, `{"volume":{"id":"v","tenantId":"team_9"},"branch":{"name":"main","headCommitId":"c"},"head":{"id":"c","treeHash":"sha256:aa"}}`
	})
	e, _, _ := testEnv(t)
	if rc := e.run(f.commonArgs("create", "v", "--tenant", "team_9")); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
}

func TestCreateVolumeNameValidatedClientSide(t *testing.T) {
	e, _, stderr := testEnv(t)
	if rc := e.run([]string{"create", "bad name!", "--api-url", "http://127.0.0.1:1", "--api-token", "t"}); rc != 2 {
		t.Fatalf("rc = %d, want 2 (no request should be sent)", rc)
	}
	if !strings.Contains(stderr.String(), "A-Za-z0-9_-") {
		t.Fatalf("stderr must show the allowed pattern: %q", stderr.String())
	}
	if rc := e.run([]string{"create", strings.Repeat("x", 221), "--api-url", "http://127.0.0.1:1", "--api-token", "t"}); rc != 2 {
		t.Fatal("names over 220 chars must be rejected client-side")
	}
}

func TestLsListsVolumes(t *testing.T) {
	f := newFakeServer(t)
	f.on("GET", "/v1/volumes", func(map[string]any) (int, string) {
		return 200, `{"volumes":[{"volumeId":"vol_1","tenantId":"t1","createdAtMs":1700000000000,"branches":[{"name":"main","headCommitId":"cmt_9"}]}]}`
	})
	e, stdout, _ := testEnv(t)
	if rc := e.run(f.commonArgs("ls")); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if !strings.Contains(stdout.String(), "vol_1") || !strings.Contains(stdout.String(), "cmt_9") {
		t.Fatalf("ls output: %q", stdout.String())
	}
}

func TestLs404ExplainsUpgrade(t *testing.T) {
	f := newFakeServer(t) // no route: default 404
	e, _, stderr := testEnv(t)
	if rc := e.run(f.commonArgs("ls")); rc != 1 {
		t.Fatalf("rc = %d", rc)
	}
	if !strings.Contains(stderr.String(), "server does not support volume listing (upgrade volume-api)") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestStatusShowsHeadAndCounts(t *testing.T) {
	f := newFakeServer(t)
	f.on("GET", "/v1/volumes/vol_1/branches", func(map[string]any) (int, string) {
		return 200, `{"branches":[{"name":"dev","headCommitId":"cmt_5","branchMode":"legacy_manifest"}]}`
	})
	f.on("GET", "/v1/volumes/vol_1/head", func(map[string]any) (int, string) {
		return 200, `{"volume":{"id":"vol_1","tenantId":"t1"},"branch":{"name":"dev","headCommitId":"cmt_5"},"head":{"id":"cmt_5","treeHash":"sha256:beef"},"activeLeases":2,"activeDelegations":3}`
	})
	e, stdout, _ := testEnv(t)
	if rc := e.run(f.commonArgs("status", "vol_1", "--branch", "dev")); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	var headReq string
	for _, r := range f.recorded() {
		if strings.Contains(r.Path, "/head") {
			headReq = r.Path
		}
	}
	if !strings.Contains(headReq, "branch=dev") {
		t.Fatalf("head request must carry the branch: %+v", f.recorded())
	}
	out := stdout.String()
	for _, want := range []string{"cmt_5", "sha256:beef", "2 active", "3 active"} {
		if !strings.Contains(out, want) {
			t.Fatalf("status output missing %q: %q", want, out)
		}
	}
}

// TestStatusJournalLiveBranch pins the launch-blocker fix: a journal-served
// (managed_journal) branch must never die on the manifest head route. Status
// rebuilds from mode-agnostic reads — branch listing, latest commit, snapshot
// cuts — and reports the live state in plain language.
func TestStatusJournalLiveBranch(t *testing.T) {
	f := newFakeServer(t)
	f.on("GET", "/v1/volumes/vol_live/branches", func(map[string]any) (int, string) {
		return 200, `{"branches":[{"name":"main","headCommitId":"cmt_base","branchMode":"managed_journal"}]}`
	})
	f.on("GET", "/v1/volumes/vol_live/commits", func(map[string]any) (int, string) {
		return 200, `{"commits":[{"id":"cpft2_9","treeHash":"pft2:abc","createdAtMs":1700000002000,"mutationCount":4,"byteCount":99,"commitKind":"pft2"}]}`
	})
	f.on("GET", "/v1/volumes/vol_live/snapshots", func(map[string]any) (int, string) {
		return 200, `{"snapshots":[
			{"id":"hcut_1","volumeId":"vol_live","branchId":"b1","commitId":"cmt_base","createdAt":5,"state":"ready","cutId":"hcut_1","resultCommitId":"cpft2_9"},
			{"id":"hcut_2","volumeId":"vol_live","branchId":"b1","commitId":"cmt_base","createdAt":9,"state":"pending","cutId":"hcut_2"}]}`
	})
	e, stdout, stderr := testEnv(t)
	if rc := e.run(f.commonArgs("status", "vol_live")); rc != 0 {
		t.Fatalf("rc = %d, stderr: %q", rc, stderr.String())
	}
	for _, r := range f.recorded() {
		if strings.Contains(r.Path, "/head") {
			t.Fatalf("status must not touch the manifest head route for a live branch: %+v", f.recorded())
		}
	}
	out := stdout.String()
	for _, want := range []string{"vol_live", "live", "cpft2_9", "hcut_1", "1 still being written"} {
		if !strings.Contains(out, want) {
			t.Fatalf("live status missing %q: %q", want, out)
		}
	}
	for _, jargon := range []string{"LIVE_AUTHORITY", "manifest access", "409"} {
		if strings.Contains(out, jargon) || strings.Contains(stderr.String(), jargon) {
			t.Fatalf("live status must not leak internal jargon %q: %q %q", jargon, out, stderr.String())
		}
	}
}

// TestStatusFallsBackWhenHeadRefusesLive covers older branch listings that
// carry no branchMode: the typed live-authority refusal on the head route
// switches status to the live rendering instead of failing.
func TestStatusFallsBackWhenHeadRefusesLive(t *testing.T) {
	f := newFakeServer(t)
	f.on("GET", "/v1/volumes/vol_1/branches", func(map[string]any) (int, string) {
		return 200, `{"branches":[{"name":"main","headCommitId":"cmt_base"}]}`
	})
	f.on("GET", "/v1/volumes/vol_1/head", func(map[string]any) (int, string) {
		return 409, `{"error":{"code":"LIVE_AUTHORITY_ROUTE_REQUIRED","message":"This branch is served by a live journal authority; use the live filesystem routes instead of manifest access."}}`
	})
	f.on("GET", "/v1/volumes/vol_1/commits", func(map[string]any) (int, string) {
		return 200, `{"commits":[{"id":"cpft2_1","treeHash":"pft2:aa","createdAtMs":1,"commitKind":"pft2"}]}`
	})
	f.on("GET", "/v1/volumes/vol_1/snapshots", func(map[string]any) (int, string) {
		return 200, `{"snapshots":[]}`
	})
	e, stdout, stderr := testEnv(t)
	if rc := e.run(f.commonArgs("status", "vol_1")); rc != 0 {
		t.Fatalf("rc = %d, stderr: %q", rc, stderr.String())
	}
	if !strings.Contains(stdout.String(), "live") || strings.Contains(stdout.String(), "LIVE_AUTHORITY") {
		t.Fatalf("fallback must render the live view without jargon: %q", stdout.String())
	}
}

// TestStatusShowsCredentialExpiredMount pins the status <-> mounts tie-in: a
// recorded local mount of the branch appears with its credential health.
func TestStatusShowsCredentialExpiredMount(t *testing.T) {
	e, stdout, _ := testEnv(t)
	stateHome := t.TempDir()
	e.getenv = func(k string) string {
		if k == "XDG_STATE_HOME" {
			return stateHome
		}
		return ""
	}
	dir, err := e.mountStateDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeMountState(dir, mountState{
		MountPath: "/tmp/w1", VolumeID: "vol_live", Branch: "main", PID: os.Getpid(),
		Strategy: "fuse", Status: mountStatusCredentialExpired, StatusChangedAtMs: 1700000000000,
	}); err != nil {
		t.Fatal(err)
	}
	f := newFakeServer(t)
	f.on("GET", "/v1/volumes/vol_live/branches", func(map[string]any) (int, string) {
		return 200, `{"branches":[{"name":"main","headCommitId":"cmt_base","branchMode":"managed_journal"}]}`
	})
	f.on("GET", "/v1/volumes/vol_live/commits", func(map[string]any) (int, string) {
		return 200, `{"commits":[]}`
	})
	f.on("GET", "/v1/volumes/vol_live/snapshots", func(map[string]any) (int, string) {
		return 200, `{"snapshots":[]}`
	})
	if rc := e.run(f.commonArgs("status", "vol_live")); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if !strings.Contains(stdout.String(), "/tmp/w1") || !strings.Contains(stdout.String(), "credential-expired") {
		t.Fatalf("status must surface the degraded local mount: %q", stdout.String())
	}
}

func TestHistoryListsCommits(t *testing.T) {
	f := newFakeServer(t)
	f.on("GET", "/v1/volumes/vol_1/commits", func(map[string]any) (int, string) {
		return 200, `{"commits":[{"id":"cmt_2","treeHash":"sha256:bb","createdAtMs":1700000001000,"mutationCount":4,"byteCount":128,"parentCommitId":"cmt_1"},{"id":"cmt_1","treeHash":"sha256:aa","createdAtMs":1700000000000}]}`
	})
	e, stdout, _ := testEnv(t)
	if rc := e.run(f.commonArgs("history", "vol_1", "--limit", "10")); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	reqs := f.recorded()
	if !strings.Contains(reqs[0].Path, "limit=10") || !strings.Contains(reqs[0].Path, "branch=main") {
		t.Fatalf("history query wrong: %s", reqs[0].Path)
	}
	if !strings.Contains(stdout.String(), "cmt_2") || !strings.Contains(stdout.String(), "cmt_1") {
		t.Fatalf("history output: %q", stdout.String())
	}
}

func TestHistory404FallsBackToStatusAndSnapshots(t *testing.T) {
	f := newFakeServer(t) // /commits missing => 404
	f.on("GET", "/v1/volumes/vol_1/head", func(map[string]any) (int, string) {
		return 200, `{"volume":{"id":"vol_1","tenantId":"t1"},"branch":{"name":"main","headCommitId":"cmt_7"},"head":{"id":"cmt_7","treeHash":"sha256:cc"}}`
	})
	f.on("GET", "/v1/volumes/vol_1/snapshots", func(map[string]any) (int, string) {
		return 200, `{"snapshots":[{"id":"snp_1","volumeId":"vol_1","branchId":"b1","commitId":"cmt_3","name":"before-x","createdAt":1700000000000}]}`
	})
	e, stdout, stderr := testEnv(t)
	if rc := e.run(f.commonArgs("history", "vol_1")); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if !strings.Contains(stderr.String(), "does not support commit history") {
		t.Fatalf("fallback note missing: %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "cmt_7") || !strings.Contains(stdout.String(), "before-x") {
		t.Fatalf("fallback output: %q", stdout.String())
	}
}

func TestSnapshotCreateAndList(t *testing.T) {
	f := newFakeServer(t)
	f.on("POST", "/v1/volumes/vol_1/snapshots", func(body map[string]any) (int, string) {
		if body["branch"] != "main" || body["name"] != "before-x" {
			return 400, `{"error":{"code":"BAD","message":"wrong body"}}`
		}
		return 201, `{"snapshot":{"id":"snp_1","volumeId":"vol_1","branchId":"b1","commitId":"cmt_1","name":"before-x","createdAt":1}}`
	})
	f.on("GET", "/v1/volumes/vol_1/snapshots", func(map[string]any) (int, string) {
		return 200, `{"snapshots":[{"id":"snp_1","volumeId":"vol_1","branchId":"b1","commitId":"cmt_1","name":"before-x","createdAt":1}]}`
	})
	e, stdout, _ := testEnv(t)
	if rc := e.run(f.commonArgs("snapshot", "vol_1", "--name", "before-x")); rc != 0 {
		t.Fatalf("snapshot rc = %d", rc)
	}
	if !strings.Contains(stdout.String(), "snp_1") {
		t.Fatalf("snapshot output: %q", stdout.String())
	}
	stdout.Reset()
	if rc := e.run(f.commonArgs("snapshots", "vol_1", "--branch", "main")); rc != 0 {
		t.Fatal("snapshots failed")
	}
	if !strings.Contains(stdout.String(), "before-x") {
		t.Fatalf("snapshots output: %q", stdout.String())
	}
	last := f.recorded()[len(f.recorded())-1]
	if !strings.Contains(last.Path, "branch=main") {
		t.Fatalf("snapshots list must filter by branch: %s", last.Path)
	}
}

func TestBranchCreateAndList(t *testing.T) {
	f := newFakeServer(t)
	f.on("GET", "/v1/volumes/vol_1/snapshots", func(map[string]any) (int, string) {
		return 200, `{"snapshots":[{"id":"snp_1","volumeId":"vol_1","branchId":"b1","commitId":"cmt_1","name":"before-x","createdAt":1}]}`
	})
	f.on("POST", "/v1/volumes/vol_1/branches", func(body map[string]any) (int, string) {
		// --from-snapshot resolves client-side and rides as the exact id.
		if body["branchName"] != "experiment" || body["fromBranch"] != "main" || body["fromSnapshotId"] != "snp_1" {
			return 400, `{"error":{"code":"BAD","message":"wrong body"}}`
		}
		return 201, `{"branch":{"name":"experiment","headCommitId":"cmt_1"},"head":{"id":"cmt_1","treeHash":"sha256:aa"}}`
	})
	f.on("GET", "/v1/volumes/vol_1/branches", func(map[string]any) (int, string) {
		return 200, `{"branches":[{"name":"main","headCommitId":"cmt_2"},{"name":"experiment","headCommitId":"cmt_1"}]}`
	})
	e, stdout, _ := testEnv(t)
	if rc := e.run(f.commonArgs("branch", "vol_1", "experiment", "--from-snapshot", "before-x")); rc != 0 {
		t.Fatalf("branch rc = %d", rc)
	}
	if !strings.Contains(stdout.String(), "experiment") {
		t.Fatalf("branch output: %q", stdout.String())
	}
	// The snapshot lookup stays scoped to the SOURCE branch, mirroring the
	// server's own fromSnapshotName resolution.
	for _, r := range f.recorded() {
		if r.Method == "GET" && strings.Contains(r.Path, "/snapshots") && !strings.Contains(r.Path, "branch=main") {
			t.Fatalf("snapshot resolution must scope to the source branch: %s", r.Path)
		}
	}
	stdout.Reset()
	if rc := e.run(f.commonArgs("branches", "vol_1")); rc != 0 {
		t.Fatal("branches failed")
	}
	if !strings.Contains(stdout.String(), "main @ cmt_2") {
		t.Fatalf("branches output: %q", stdout.String())
	}
}

// TestBranchLiveHeadFallsBackToCut pins the journal-live branch flow: the
// server's typed live-authority refusal of a live-head branch birth makes the
// CLI record a snapshot cut, wait for it, and open the branch from the cut.
func TestBranchLiveHeadFallsBackToCut(t *testing.T) {
	f := newFakeServer(t)
	branchCalls := 0
	f.on("POST", "/v1/volumes/vol_live/branches", func(body map[string]any) (int, string) {
		branchCalls++
		if branchCalls == 1 {
			if body["fromSnapshotId"] != nil || body["fromSnapshotName"] != nil {
				return 400, `{"error":{"code":"BAD","message":"first attempt must target the branch head"}}`
			}
			return 409, `{"error":{"code":"LIVE_AUTHORITY_ROUTE_REQUIRED","message":"This branch is served by a live journal authority; use the live filesystem routes instead of manifest access."}}`
		}
		if body["fromSnapshotId"] != "hcut_7" {
			return 400, `{"error":{"code":"BAD","message":"retry must branch from the ready cut"}}`
		}
		return 201, `{"branch":{"name":"exp","headCommitId":"cpft2_7"},"head":{"id":"cpft2_7","treeHash":"pft2:aa"},"commitKind":"pft2"}`
	})
	f.on("POST", "/v1/volumes/vol_live/snapshots", func(body map[string]any) (int, string) {
		if body["branch"] != "main" {
			return 400, `{"error":{"code":"BAD","message":"cut must capture the source branch"}}`
		}
		return 201, `{"snapshot":{"id":"hcut_7","volumeId":"vol_live","branchId":"b1","commitId":"cmt_base","createdAt":5,"state":"pending","cutId":"hcut_7"}}`
	})
	polls := 0
	f.on("GET", "/v1/volumes/vol_live/snapshots", func(map[string]any) (int, string) {
		polls++
		state := "materializing"
		if polls >= 2 {
			state = "ready"
		}
		return 200, fmt.Sprintf(`{"snapshots":[{"id":"hcut_7","volumeId":"vol_live","branchId":"b1","commitId":"cmt_base","createdAt":5,"state":%q,"cutId":"hcut_7"}]}`, state)
	})
	e, stdout, stderr := testEnv(t)
	if rc := e.run(f.commonArgs("branch", "vol_live", "exp")); rc != 0 {
		t.Fatalf("branch rc = %d, stderr: %q", rc, stderr.String())
	}
	if !strings.Contains(stdout.String(), "created branch exp @ cpft2_7") {
		t.Fatalf("branch output: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "live") {
		t.Fatalf("the cut fallback must explain itself: %q", stderr.String())
	}
	if strings.Contains(stderr.String(), "LIVE_AUTHORITY") {
		t.Fatalf("no internal jargon on the fallback path: %q", stderr.String())
	}
	if branchCalls != 2 {
		t.Fatalf("branch calls = %d, want 2 (live refusal, then branch-from-cut)", branchCalls)
	}
}

// TestBranchFromCutIdWaitsForReady: --from-snapshot may name a cut still
// being written; the CLI waits and then branches from the exact cut id.
func TestBranchFromCutIdWaitsForReady(t *testing.T) {
	f := newFakeServer(t)
	polls := 0
	f.on("GET", "/v1/volumes/vol_live/snapshots", func(map[string]any) (int, string) {
		polls++
		state := "pending"
		if polls >= 2 {
			state = "ready"
		}
		return 200, fmt.Sprintf(`{"snapshots":[{"id":"hcut_3","volumeId":"vol_live","branchId":"b1","commitId":"cmt_base","createdAt":5,"state":%q,"cutId":"hcut_3"}]}`, state)
	})
	f.on("POST", "/v1/volumes/vol_live/branches", func(body map[string]any) (int, string) {
		if body["fromSnapshotId"] != "hcut_3" {
			return 400, `{"error":{"code":"BAD","message":"must branch from the cut id"}}`
		}
		return 201, `{"branch":{"name":"exp","headCommitId":"cpft2_3"},"head":{"id":"cpft2_3","treeHash":"pft2:bb"},"commitKind":"pft2"}`
	})
	e, stdout, stderr := testEnv(t)
	if rc := e.run(f.commonArgs("branch", "vol_live", "exp", "--from-snapshot", "hcut_3")); rc != 0 {
		t.Fatalf("branch rc = %d, stderr: %q", rc, stderr.String())
	}
	if !strings.Contains(stdout.String(), "cpft2_3") {
		t.Fatalf("branch output: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "hcut_3") {
		t.Fatalf("the wait must narrate progress: %q", stderr.String())
	}
}

// TestForkAutoSnapshotPath pins the fork flow with no --snapshot: tenant
// resolution through the mode-agnostic volume list (NEVER the manifest head
// route, which refuses journal-served branches), snapshot named fork-<unixms>
// from the branch, then fork of that snapshot carrying the source tenant.
func TestForkAutoSnapshotPath(t *testing.T) {
	f := newFakeServer(t)
	f.on("GET", "/v1/volumes", func(map[string]any) (int, string) {
		return 200, `{"volumes":[{"volumeId":"vol_1","tenantId":"t42","createdAtMs":1,"branches":[{"name":"main","headCommitId":"cmt_1"}]}]}`
	})
	f.on("POST", "/v1/volumes/vol_1/snapshots", func(body map[string]any) (int, string) {
		name, _ := body["name"].(string)
		if !strings.HasPrefix(name, "fork-") || body["branch"] != "main" {
			return 400, `{"error":{"code":"BAD","message":"auto-snapshot name must be fork-<unixms>"}}`
		}
		return 201, fmt.Sprintf(`{"snapshot":{"id":"snp_9","volumeId":"vol_1","branchId":"b1","commitId":"cmt_1","name":%q,"createdAt":5}}`, name)
	})
	f.on("POST", "/v1/snapshots/snp_9/fork", func(body map[string]any) (int, string) {
		if body["tenantId"] != "t42" || body["volumeId"] != "agent-2" || body["branchName"] != "main" {
			return 400, `{"error":{"code":"BAD","message":"fork body wrong"}}`
		}
		return 201, `{"volume":{"id":"agent-2","tenantId":"t42"},"branch":{"name":"main","headCommitId":"cmt_1"},"head":{"id":"cmt_1","treeHash":"sha256:aa"}}`
	})
	e, stdout, _ := testEnv(t)
	if rc := e.run(f.commonArgs("fork", "vol_1", "--name", "agent-2")); rc != 0 {
		t.Fatalf("fork rc = %d", rc)
	}
	if !strings.Contains(stdout.String(), "agent-2") {
		t.Fatalf("fork must print the new volume id: %q", stdout.String())
	}
	var methods []string
	for _, r := range f.recorded() {
		methods = append(methods, r.Method+" "+strings.SplitN(r.Path, "?", 2)[0])
	}
	want := []string{"GET /v1/volumes", "POST /v1/volumes/vol_1/snapshots", "POST /v1/snapshots/snp_9/fork"}
	if strings.Join(methods, ",") != strings.Join(want, ",") {
		t.Fatalf("fork call sequence = %v, want %v", methods, want)
	}
}

// TestForkJournalLiveCutFlow is the launch-blocker end-to-end: forking a
// journal-live volume snapshots the live state (an asynchronous cut), waits
// for the cut with progress, and forks the ready record — no manifest head
// preflight anywhere.
func TestForkJournalLiveCutFlow(t *testing.T) {
	f := newFakeServer(t)
	f.on("GET", "/v1/volumes", func(map[string]any) (int, string) {
		return 200, `{"volumes":[{"volumeId":"vol_live","tenantId":"t1","createdAtMs":1,"branches":[{"name":"main","headCommitId":"cmt_base"}]}]}`
	})
	f.on("POST", "/v1/volumes/vol_live/snapshots", func(map[string]any) (int, string) {
		return 201, `{"snapshot":{"id":"hcut_5","volumeId":"vol_live","branchId":"b1","commitId":"cmt_base","createdAt":5,"state":"pending","cutId":"hcut_5"}}`
	})
	polls := 0
	f.on("GET", "/v1/volumes/vol_live/snapshots", func(map[string]any) (int, string) {
		polls++
		state := "materializing"
		if polls >= 3 {
			state = "ready"
		}
		return 200, fmt.Sprintf(`{"snapshots":[{"id":"hcut_5","volumeId":"vol_live","branchId":"b1","commitId":"cmt_base","createdAt":5,"state":%q,"cutId":"hcut_5","resultCommitId":"cpft2_5"}]}`, state)
	})
	f.on("POST", "/v1/snapshots/hcut_5/fork", func(body map[string]any) (int, string) {
		if body["tenantId"] != "t1" || body["volumeId"] != "agent-9" {
			return 400, `{"error":{"code":"BAD","message":"fork body wrong"}}`
		}
		return 201, `{"volume":{"id":"agent-9","tenantId":"t1"},"branch":{"name":"main","headCommitId":"cpft2_5"},"head":{"id":"cpft2_5","treeHash":"pft2:aa"}}`
	})
	e, stdout, stderr := testEnv(t)
	if rc := e.run(f.commonArgs("fork", "vol_live", "--name", "agent-9")); rc != 0 {
		t.Fatalf("fork rc = %d, stderr: %q", rc, stderr.String())
	}
	for _, r := range f.recorded() {
		if strings.Contains(r.Path, "/head") {
			t.Fatalf("fork must not preflight the manifest head route: %+v", f.recorded())
		}
	}
	if !strings.Contains(stdout.String(), "agent-9") {
		t.Fatalf("fork output: %q", stdout.String())
	}
	progress := stderr.String()
	if !strings.Contains(progress, "hcut_5") || !strings.Contains(progress, "ready") {
		t.Fatalf("the cut wait must narrate progress: %q", progress)
	}
}

// TestForkTranslatesUnsupportedCutFork: when the server's schema lineage
// cannot fork a cut across volumes, the CLI answers in plain language with
// the exact branch command that works — never the raw typed envelope.
func TestForkTranslatesUnsupportedCutFork(t *testing.T) {
	f := newFakeServer(t)
	f.on("GET", "/v1/volumes", func(map[string]any) (int, string) {
		return 200, `{"volumes":[{"volumeId":"vol_live","tenantId":"t1","createdAtMs":1,"branches":[{"name":"main","headCommitId":"cmt_base"}]}]}`
	})
	f.on("GET", "/v1/volumes/vol_live/snapshots", func(map[string]any) (int, string) {
		return 200, `{"snapshots":[{"id":"hcut_5","volumeId":"vol_live","branchId":"b1","commitId":"cmt_base","createdAt":5,"state":"ready","cutId":"hcut_5"}]}`
	})
	f.on("POST", "/v1/snapshots/hcut_5/fork", func(map[string]any) (int, string) {
		return 409, `{"error":{"code":"HISTORY_FORK_UNSUPPORTED","message":"Cross-volume fork of a journal-era cut is not supported by this schema lineage; branch from the cut within its volume instead."}}`
	})
	e, _, stderr := testEnv(t)
	if rc := e.run(f.commonArgs("fork", "vol_live", "--snapshot", "hcut_5", "--name", "agent-9")); rc != 1 {
		t.Fatalf("rc = %d", rc)
	}
	msg := stderr.String()
	if !strings.Contains(msg, "portablefs branch vol_live") || !strings.Contains(msg, "--from-snapshot hcut_5") {
		t.Fatalf("the refusal must hand over the working branch command: %q", msg)
	}
	for _, jargon := range []string{"schema lineage", "HISTORY_FORK_UNSUPPORTED", "journal-era"} {
		if strings.Contains(msg, jargon) {
			t.Fatalf("raw envelope text must not leak: %q", msg)
		}
	}
}

// TestForkNeverServedLiveVolumeIsActionable: snapshotting a journal-born
// volume that has never been mounted answers a typed mode conflict whose raw
// text ("Manifest commits cannot mutate...") means nothing to a user; fork
// and snapshot must translate it to the mount-once remediation.
func TestForkNeverServedLiveVolumeIsActionable(t *testing.T) {
	f := newFakeServer(t)
	f.on("GET", "/v1/volumes", func(map[string]any) (int, string) {
		return 200, `{"volumes":[{"volumeId":"vol_new","tenantId":"t1","createdAtMs":1,"branches":[{"name":"main","headCommitId":"cmt_0"}]}]}`
	})
	f.on("POST", "/v1/volumes/vol_new/snapshots", func(map[string]any) (int, string) {
		return 409, `{"error":{"code":"VOLUME_BRANCH_MODE_CONFLICT","message":"Manifest commits cannot mutate a managed_journal branch head."}}`
	})
	e, _, stderr := testEnv(t)
	if rc := e.run(f.commonArgs("fork", "vol_new", "--name", "agent-1")); rc != 1 {
		t.Fatalf("rc = %d", rc)
	}
	msg := stderr.String()
	if !strings.Contains(msg, "portablefs mount vol_new") || !strings.Contains(msg, "never been served") {
		t.Fatalf("never-served refusal must point at mounting once: %q", msg)
	}
	if strings.Contains(msg, "Manifest commits") || strings.Contains(msg, "VOLUME_BRANCH_MODE_CONFLICT") {
		t.Fatalf("raw envelope text must not leak: %q", msg)
	}
}

// TestForkFailedCutIsActionable: a failed cut can never be forked; say so
// plainly instead of forwarding a typed conflict.
func TestForkFailedCutIsActionable(t *testing.T) {
	f := newFakeServer(t)
	f.on("GET", "/v1/volumes", func(map[string]any) (int, string) {
		return 200, `{"volumes":[{"volumeId":"vol_live","tenantId":"t1","createdAtMs":1,"branches":[{"name":"main","headCommitId":"cmt_base"}]}]}`
	})
	f.on("GET", "/v1/volumes/vol_live/snapshots", func(map[string]any) (int, string) {
		return 200, `{"snapshots":[{"id":"hcut_bad","volumeId":"vol_live","branchId":"b1","commitId":"cmt_base","createdAt":5,"state":"failed","cutId":"hcut_bad"}]}`
	})
	e, _, stderr := testEnv(t)
	if rc := e.run(f.commonArgs("fork", "vol_live", "--snapshot", "hcut_bad")); rc != 1 {
		t.Fatalf("rc = %d", rc)
	}
	if !strings.Contains(stderr.String(), "failed") || !strings.Contains(stderr.String(), "portablefs snapshot vol_live") {
		t.Fatalf("failed-cut refusal must be actionable: %q", stderr.String())
	}
}

func TestForkNamedSnapshotPicksNewestMatch(t *testing.T) {
	f := newFakeServer(t)
	f.on("GET", "/v1/volumes/vol_1/head", func(map[string]any) (int, string) {
		return 200, `{"volume":{"id":"vol_1","tenantId":"t1"},"branch":{"name":"main","headCommitId":"cmt_1"},"head":{"id":"cmt_1","treeHash":"sha256:aa"}}`
	})
	f.on("GET", "/v1/volumes/vol_1/snapshots", func(map[string]any) (int, string) {
		return 200, `{"snapshots":[
			{"id":"snp_old","volumeId":"vol_1","branchId":"b1","commitId":"cmt_1","name":"rc","createdAt":1},
			{"id":"snp_new","volumeId":"vol_1","branchId":"b1","commitId":"cmt_2","name":"rc","createdAt":9}]}`
	})
	f.on("POST", "/v1/snapshots/snp_new/fork", func(map[string]any) (int, string) {
		return 201, `{"volume":{"id":"vol_fork","tenantId":"t1"},"branch":{"name":"main","headCommitId":"cmt_2"},"head":{"id":"cmt_2","treeHash":"sha256:bb"}}`
	})
	e, stdout, _ := testEnv(t)
	if rc := e.run(f.commonArgs("fork", "vol_1", "--snapshot", "rc")); rc != 0 {
		t.Fatalf("fork rc = %d", rc)
	}
	if !strings.Contains(stdout.String(), "vol_fork") {
		t.Fatalf("fork output: %q", stdout.String())
	}
}

func TestForkUnknownSnapshotIsActionable(t *testing.T) {
	f := newFakeServer(t)
	f.on("GET", "/v1/volumes/vol_1/head", func(map[string]any) (int, string) {
		return 200, `{"volume":{"id":"vol_1","tenantId":"t1"},"branch":{"name":"main","headCommitId":"cmt_1"},"head":{"id":"cmt_1","treeHash":"sha256:aa"}}`
	})
	f.on("GET", "/v1/volumes/vol_1/snapshots", func(map[string]any) (int, string) {
		return 200, `{"snapshots":[]}`
	})
	e, _, stderr := testEnv(t)
	if rc := e.run(f.commonArgs("fork", "vol_1", "--snapshot", "nope")); rc != 1 {
		t.Fatalf("rc = %d", rc)
	}
	if !strings.Contains(stderr.String(), "portablefs snapshots vol_1") {
		t.Fatalf("error must point at the snapshots command: %q", stderr.String())
	}
}

// Test401AppendsLoginGuidance pins the credential-failure copy: every 401
// tells the user the two realistic causes and the fix.
func Test401AppendsLoginGuidance(t *testing.T) {
	f := newFakeServer(t)
	f.on("GET", "/v1/volumes", func(map[string]any) (int, string) {
		return 401, `{"error":{"code":"VOLUME_UNAUTHORIZED","message":"Unauthorized."}}`
	})
	e, _, stderr := testEnv(t)
	if rc := e.run(f.commonArgs("ls")); rc != 1 {
		t.Fatalf("rc = %d", rc)
	}
	msg := stderr.String()
	if !strings.Contains(msg, "different server") || !strings.Contains(msg, "revoked") || !strings.Contains(msg, "portablefs login") {
		t.Fatalf("401 must carry actionable guidance: %q", msg)
	}
}

func TestGrepPrintsMatchesAndExitCodes(t *testing.T) {
	f := newFakeServer(t)
	f.on("POST", "/v1/volumes/vol_1/grep", func(body map[string]any) (int, string) {
		if body["pattern"] != "qualified" || body["directory"] != "prospects" || body["recursive"] != true {
			return 400, `{"error":{"code":"BAD","message":"wrong grep body"}}`
		}
		if max, ok := body["maxResults"].(float64); !ok || max != 5 {
			return 400, `{"error":{"code":"BAD","message":"wrong maxResults"}}`
		}
		return 200, `{"matches":[{"file":"prospects/ada.md","line":3,"text":"status: qualified"}],"stoppedReason":"completed","durationMs":4,"headCommitId":"cmt_1"}`
	})
	e, stdout, _ := testEnv(t)
	if rc := e.run(f.commonArgs("grep", "vol_1", "qualified", "--dir", "prospects", "--max", "5")); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if got := stdout.String(); got != "prospects/ada.md:3:status: qualified\n" {
		t.Fatalf("grep output = %q", got)
	}

	f.on("POST", "/v1/volumes/vol_1/grep", func(map[string]any) (int, string) {
		return 200, `{"matches":[],"stoppedReason":"completed","durationMs":1,"headCommitId":"cmt_1"}`
	})
	if rc := e.run(f.commonArgs("grep", "vol_1", "qualified", "--dir", "prospects", "--max", "5")); rc != 1 {
		t.Fatalf("no matches must exit 1 (grep semantics), got %d", rc)
	}
}

func TestJSONOutputIsMachineReadable(t *testing.T) {
	f := newFakeServer(t)
	f.on("GET", "/v1/volumes/vol_1/branches", func(map[string]any) (int, string) {
		return 200, `{"branches":[{"name":"main","headCommitId":"cmt_5","branchMode":"legacy_manifest"}]}`
	})
	f.on("GET", "/v1/volumes/vol_1/head", func(map[string]any) (int, string) {
		return 200, `{"volume":{"id":"vol_1","tenantId":"t1"},"branch":{"name":"main","headCommitId":"cmt_5"},"head":{"id":"cmt_5","treeHash":"sha256:beef"},"activeLeases":1,"activeDelegations":0}`
	})
	e, stdout, _ := testEnv(t)
	if rc := e.run(f.commonArgs("status", "vol_1", "--json")); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	var parsed struct {
		VolumeID     string `json:"volumeId"`
		HeadCommitID string `json:"headCommitId"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("status --json must emit valid JSON: %v (%q)", err, stdout.String())
	}
	if parsed.VolumeID != "vol_1" || parsed.HeadCommitID != "cmt_5" {
		t.Fatalf("parsed = %+v", parsed)
	}
}
