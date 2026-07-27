package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/treehash"
)

const (
	// adoptProtocolVersion mirrors protocolVersion in packages/protocol.
	adoptProtocolVersion = "portablefs-v1"
	// adoptLeaseTTL matches the attach default; the lease is renewed between
	// requests once half of it has elapsed so long imports never lapse.
	adoptLeaseTTL = 10 * time.Minute
	// adoptBatchMaxEntries and adoptBatchMaxBytes bound one batch-binary
	// request (the server rejects batches over 1024 entries).
	adoptBatchMaxEntries = 1024
	adoptBatchMaxBytes   = 8 << 20
	// adoptLargeBlobBytes is the cutoff above which a blob is streamed with
	// PUT /v1/blobs/:digest instead of being buffered into a batch.
	adoptLargeBlobBytes = 6 << 20
	// adoptProbeChunk bounds one POST /v1/blobs/probe request (schema max 4096).
	adoptProbeChunk = 4096
	// adoptRetryAttempts covers transient 5xx/network failures on uploads.
	adoptRetryAttempts = 3
	// adoptBulkyDirBytes is the size above which a top-level directory earns a
	// "consider --exclude" hint.
	adoptBulkyDirBytes = 500 << 20
)

type adoptOpts struct {
	common      commonOpts
	name        string
	branch      string
	excludes    repeatableFlag
	dryRun      bool
	mountPath   string
	concurrency int
	quiet       bool
}

// repeatableFlag collects every occurrence of a repeatable string flag.
type repeatableFlag []string

func (r *repeatableFlag) String() string { return strings.Join(*r, ",") }

func (r *repeatableFlag) Set(v string) error {
	*r = append(*r, v)
	return nil
}

// sanitizeVolumeName derives a valid volume name from a directory basename:
// every rune outside [A-Za-z0-9_-] becomes '-', truncated to 220.
func sanitizeVolumeName(base string) string {
	var b strings.Builder
	for _, r := range base {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	s := b.String()
	if len(s) > 220 {
		s = s[:220]
	}
	return s
}

func cmdAdopt(e *cmdEnv, args []string) int {
	fs := newFlagSet("adopt")
	var o adoptOpts
	addCommonFlags(fs, &o.common)
	fs.StringVar(&o.name, "name", "", "volume name (default: sanitized directory basename)")
	fs.StringVar(&o.branch, "branch", "main", "branch name for the initial commit")
	fs.Var(&o.excludes, "exclude", "gitignore-style pattern to leave out (repeatable; .portablefsignore at the root is also read)")
	fs.BoolVar(&o.dryRun, "dry-run", false, "scan and report only; no network calls")
	fs.StringVar(&o.mountPath, "mount", "", "after adopting, mount the volume at this path")
	fs.IntVar(&o.concurrency, "concurrency", 0, "file hashing concurrency (default: min(8, number of CPUs))")
	fs.BoolVar(&o.quiet, "quiet", false, "suppress progress and per-file warnings")
	positionals, err := parseArgs(fs, args)
	if err != nil {
		return e.handleParseError("adopt", err)
	}
	if len(positionals) != 1 {
		return e.usageError("adopt", fmt.Errorf("expected exactly one directory"))
	}
	if o.concurrency < 0 {
		return e.usageError("adopt", fmt.Errorf("--concurrency must be positive"))
	}
	if o.concurrency == 0 {
		o.concurrency = min(8, runtime.NumCPU())
	}
	if o.branch == "" {
		return e.usageError("adopt", fmt.Errorf("--branch must not be empty"))
	}

	dir, err := filepath.Abs(positionals[0])
	if err != nil {
		return e.fail("adopt", err)
	}
	if resolved, rerr := filepath.EvalSymlinks(dir); rerr == nil {
		dir = resolved
	}
	info, err := os.Stat(dir)
	if err != nil {
		return e.fail("adopt", fmt.Errorf("directory %s: %w", positionals[0], err))
	}
	if !info.IsDir() {
		return e.fail("adopt", fmt.Errorf("%s is not a directory", positionals[0]))
	}

	name := o.name
	if name == "" {
		name = sanitizeVolumeName(filepath.Base(dir))
	}
	if !validVolumeName(name) {
		return e.usageError("adopt", fmt.Errorf("invalid volume name %q: must match [A-Za-z0-9_-]{1,220} (pass --name)", name))
	}

	run := &adoptRun{e: e, opts: &o, now: time.Now, sleep: e.sleepFn}
	if run.sleep == nil {
		run.sleep = time.Sleep
	}
	return run.execute(dir, name)
}

// adoptRun carries the state of one adopt invocation.
type adoptRun struct {
	e     *cmdEnv
	opts  *adoptOpts
	api   *apiClient
	now   func() time.Time
	sleep func(time.Duration)

	// lease state (valid between attach and detach)
	leaseID      string
	fencingToken int64
	lastRenew    time.Time
}

func (r *adoptRun) progressf(format string, args ...any) {
	if r.opts.quiet {
		return
	}
	fmt.Fprintf(r.e.stderr, format+"\n", args...)
}

// scanTree loads the ignore rules, walks the directory, and reports skip
// warnings plus the bulky top-level directory hints.
func (r *adoptRun) scanTree(dir string) (*adoptScanResult, error) {
	ignoreLines, err := loadIgnoreFile(dir)
	if err != nil {
		return nil, err
	}
	matcher := newIgnoreMatcher(append(ignoreLines, r.opts.excludes...))
	r.progressf("scanning %s ...", dir)
	scan, err := adoptScanDir(dir, matcher)
	if err != nil {
		return nil, err
	}
	for _, sk := range scan.skipped {
		if !r.opts.quiet {
			fmt.Fprintf(r.e.stderr, "portablefs adopt: warning: skipping %s (%s)\n", sk.Path, sk.Reason)
		}
	}
	r.progressf("scanned %d files, %d dirs, %d symlinks (%s), %d excluded, %d skipped",
		scan.files, scan.dirs, scan.symlinks, humanBytes(scan.totalBytes), scan.excluded, len(scan.skipped))
	names := make([]string, 0, len(scan.topBytes))
	for name, size := range scan.topBytes {
		if size > adoptBulkyDirBytes {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		r.progressf("note: %s/ holds %s; add --exclude '%s/' to leave it out", name, humanBytes(scan.topBytes[name]), name)
	}
	return scan, nil
}

func (r *adoptRun) execute(dir, name string) int {
	e, o := r.e, r.opts

	if o.dryRun {
		scan, err := r.scanTree(dir)
		if err != nil {
			return e.fail("adopt", err)
		}
		if o.common.jsonOut {
			return e.printJSON(map[string]any{
				"dryRun":   true,
				"volumeId": name,
				"branch":   o.branch,
				"files":    scan.files,
				"dirs":     scan.dirs,
				"symlinks": scan.symlinks,
				"bytes":    scan.totalBytes,
				"excluded": scan.excluded,
				"skipped":  len(scan.skipped),
			})
		}
		fmt.Fprintf(e.stdout, "dry run: would adopt %s into volume %s (branch %s)\n", dir, name, o.branch)
		fmt.Fprintf(e.stdout, "  entries  %d files, %d dirs, %d symlinks\n", scan.files, scan.dirs, scan.symlinks)
		fmt.Fprintf(e.stdout, "  bytes    %s\n", humanBytes(scan.totalBytes))
		if scan.excluded > 0 {
			fmt.Fprintf(e.stdout, "  excluded %d\n", scan.excluded)
		}
		if len(scan.skipped) > 0 {
			fmt.Fprintf(e.stdout, "  skipped  %d (unsupported node types)\n", len(scan.skipped))
		}
		return 0
	}

	s, err := e.resolveSettings(&o.common)
	if err != nil {
		return e.fail("adopt", err)
	}
	if err := s.requireAPI(); err != nil {
		return e.fail("adopt", err)
	}
	r.api = e.apiClient(s.apiURL, s.apiToken)
	ctx := context.Background()

	// Create the volume first: name conflicts must fail before any scanning
	// or hashing work is spent.
	created, err := r.api.adoptCreateVolume(ctx, name, o.branch)
	if err != nil {
		if httpCode(err) == "VOLUME_ALREADY_EXISTS" || httpStatus(err) == 409 {
			// An interrupted adopt leaves a created-but-empty volume behind
			// (hosted control planes have no volume deletion). Adopting into
			// an EMPTY existing volume is semantically identical to a fresh
			// create, so the retry resumes instead of stranding the name.
			empty, checkErr := r.api.volumeBranchIsEmpty(ctx, name, o.branch)
			if checkErr != nil {
				// The check's typed refusals each mean something specific;
				// pasting the raw upstream text after "already exists" reads
				// as a contradiction ("already exists ... not found").
				switch httpCode(checkErr) {
				case "VOLUME_PROVISIONING":
					return e.fail("adopt", fmt.Errorf("a previous adopt of %q is still provisioning (or failed partway); wait for it to finish, or choose another name with --name", name))
				case "VOLUME_NOT_FOUND":
					// The name is taken by a volume this credential cannot
					// see (another tenant). Say only what the user can act on.
					return e.fail("adopt", fmt.Errorf("volume name %q is unavailable; choose another name with --name", name))
				}
				return e.fail("adopt", fmt.Errorf("volume %q already exists and its state could not be checked: %w", name, checkErr))
			}
			if !empty {
				return e.fail("adopt", fmt.Errorf("volume %q already exists with content: pick a different name with --name, or work with the existing volume (portablefs mount %s <path>; if a previous adopt was interrupted before activation, resume with: portablefs activate %s)", name, name, name))
			}
			r.progressf("volume %q already exists and is empty (an interrupted adopt?); resuming into it", name)
			created = &volumeMutationResponse{Volume: volumeInfo{ID: name}}
		} else {
			return e.fail("adopt", err)
		}
	}

	// Attach the write session before the local work so the deferred detach
	// releases the lease on every failure path (scan, hash, upload, commit).
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}
	if len(hostname) > 200 {
		hostname = hostname[:200]
	}
	holderID := fmt.Sprintf("adopt-%s-%d", hostname, os.Getpid())
	session, err := r.api.adoptAttachWrite(ctx, name, o.branch, holderID, adoptLeaseTTL.Milliseconds())
	if err != nil {
		return e.fail("adopt", err)
	}
	r.leaseID = session.leaseID
	r.fencingToken = session.fencingToken
	r.lastRenew = r.now()
	sessionReleased := false
	releaseSession := func() {
		if sessionReleased {
			return
		}
		sessionReleased = true
		detachCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		// The exclusive write lease must not outlive adopt: retry transient
		// failures, and if release still fails, say exactly what that means
		// (the lease self-expires, but mounts could block until then).
		derr := r.withRetry(func() error {
			return r.api.adoptDetach(detachCtx, session.sessionID)
		})
		if derr != nil {
			fmt.Fprintf(e.stderr,
				"portablefs adopt: warning: could not release the write lease on %q: %v\n"+
					"  the import itself is committed; the lease expires on its own within %s,\n"+
					"  and until then another write mount on this branch may be rejected\n",
				name, derr, adoptLeaseTTL)
		}
	}
	defer releaseSession()

	scan, err := r.scanTree(dir)
	if err != nil {
		return e.fail("adopt", err)
	}

	fileEntries := make([]*adoptEntry, 0, scan.files)
	for _, en := range scan.entries {
		if en.kind == "file" {
			fileEntries = append(fileEntries, en)
		}
	}

	r.progressf("hashing %d files (concurrency %d) ...", len(fileEntries), o.concurrency)
	if _, err := adoptHashFiles(scan.entries, o.concurrency); err != nil {
		return e.fail("adopt", err)
	}

	// Probe which blobs the server already has; servers without the probe
	// route (404) mean "upload everything". Identical file contents share one
	// digest, so each unique digest is probed (and later uploaded) once. A
	// commit references chunk digests for chunked entries (never the
	// whole-file digest), so those are what get probed and uploaded.
	uniqueSize := map[string]int64{}
	for _, en := range fileEntries {
		if len(en.chunks) > 0 {
			for _, ch := range en.chunks {
				if _, seen := uniqueSize[ch.digest]; !seen {
					uniqueSize[ch.digest] = ch.size
				}
			}
			continue
		}
		if _, seen := uniqueSize[en.digest]; !seen {
			uniqueSize[en.digest] = en.size
		}
	}
	digests := make([]string, 0, len(uniqueSize))
	for d := range uniqueSize {
		digests = append(digests, d)
	}
	sort.Strings(digests)
	r.progressf("probing server for %d blobs ...", len(digests))
	missing, probeSupported, err := r.probeBlobs(ctx, digests)
	if err != nil {
		return e.fail("adopt", err)
	}
	if !probeSupported {
		r.progressf("server has no blob probe route; uploading all blobs")
	}
	present := map[string]bool{}
	var plannedCount int
	var plannedBytes int64
	for _, d := range digests {
		if probeSupported && !missing[d] {
			present[d] = true
			continue
		}
		plannedCount++
		plannedBytes += uniqueSize[d]
	}

	r.progressf("uploading %d blobs (%s) ...", plannedCount, humanBytes(plannedBytes))
	uploadedSet := map[string]bool{}
	uploaded := 0
	var batch []adoptBatchBlob
	var batchBytes int64
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := r.renewLeaseIfNeeded(ctx); err != nil {
			return err
		}
		if err := r.uploadBatch(ctx, batch); err != nil {
			return err
		}
		uploaded += len(batch)
		r.progressf("uploaded %d/%d blobs", uploaded, plannedCount)
		batch, batchBytes = nil, 0
		return nil
	}
	appendBlob := func(digest string, data []byte) error {
		if len(batch) >= adoptBatchMaxEntries || batchBytes+int64(len(data)) > adoptBatchMaxBytes {
			if err := flush(); err != nil {
				return err
			}
		}
		batch = append(batch, adoptBatchBlob{digest: digest, bytes: data})
		batchBytes += int64(len(data))
		uploadedSet[digest] = true
		return nil
	}
	for _, en := range fileEntries {
		if len(en.chunks) > 0 {
			// Chunked large file: the commit references the chunk digests, so
			// each missing chunk uploads as its own blob (chunks are 4 MiB and
			// always fit a batch). A chunk whose bytes changed since the scan
			// re-hashes the whole file once and restarts that file's chunks.
			if err := r.uploadChunkedFile(en, present, uploadedSet, appendBlob, func(n int) {
				uploaded += n
				r.progressf("uploaded %d/%d blobs", uploaded, plannedCount)
			}); err != nil {
				return e.fail("adopt", err)
			}
			continue
		}
		if present[en.digest] || uploadedSet[en.digest] {
			continue
		}
		if en.size > adoptLargeBlobBytes {
			if err := flush(); err != nil {
				return e.fail("adopt", err)
			}
			if err := r.renewLeaseIfNeeded(ctx); err != nil {
				return e.fail("adopt", err)
			}
			r.progressf("uploading large file %s (%s) ...", en.relPath, humanBytes(en.size))
			if err := r.uploadLargeBlob(ctx, en, present, uploadedSet); err != nil {
				return e.fail("adopt", err)
			}
			if uploadedSet[en.digest] {
				uploaded++
				r.progressf("uploaded %d/%d blobs", uploaded, plannedCount)
			}
			continue
		}
		data, err := os.ReadFile(en.absPath)
		if err != nil {
			return e.fail("adopt", fmt.Errorf("read %s: %w", en.relPath, err))
		}
		sum := sha256.Sum256(data)
		if got := "sha256:" + hex.EncodeToString(sum[:]); got != en.digest {
			// The file changed between scan and upload. The in-memory bytes
			// and their hash are consistent, so import the current contents:
			// upload these bytes under the new digest and update the entry.
			r.progressf("portablefs adopt: warning: %s changed while adopting; importing the current contents", en.relPath)
			en.digest = got
			en.size = int64(len(data))
			if present[en.digest] || uploadedSet[en.digest] {
				continue
			}
		}
		if len(batch) >= adoptBatchMaxEntries || batchBytes+int64(len(data)) > adoptBatchMaxBytes {
			if err := flush(); err != nil {
				return e.fail("adopt", err)
			}
		}
		batch = append(batch, adoptBatchBlob{digest: en.digest, bytes: data})
		batchBytes += int64(len(data))
		uploadedSet[en.digest] = true
	}
	if err := flush(); err != nil {
		return e.fail("adopt", err)
	}

	var totalBytes int64
	finalUnique := map[string]bool{}
	for _, en := range fileEntries {
		totalBytes += en.size
		if len(en.chunks) > 0 {
			for _, ch := range en.chunks {
				finalUnique[ch.digest] = true
			}
			continue
		}
		finalUnique[en.digest] = true
	}
	uploadedBlobs := len(uploadedSet)
	dedupedBlobs := len(finalUnique) - uploadedBlobs
	if dedupedBlobs < 0 {
		dedupedBlobs = 0
	}

	// Build the manifest and commit. The Go treehash package is byte-identical
	// to the TS canonical hash, so the server accepts the client-computed hash.
	manifestEntries, hashEntries := buildAdoptManifest(scan.entries)
	treeHash := treehash.Compute(hashEntries)
	r.progressf("committing %d entries ...", len(manifestEntries))
	if err := r.renewLeaseIfNeeded(ctx); err != nil {
		return e.fail("adopt", err)
	}
	commit, err := r.api.adoptCommitSummary(ctx, session.sessionID, adoptCommitRequest{
		LeaseID:              r.leaseID,
		FencingToken:         r.fencingToken,
		ExpectedHeadCommitID: session.baseCommitID,
		Manifest: adoptManifest{
			Version:  adoptProtocolVersion,
			TreeHash: treeHash,
			Entries:  manifestEntries,
		},
		MutationCount: int64(len(manifestEntries)),
		ByteCount:     totalBytes,
	})
	if err != nil {
		return e.fail("adopt", err)
	}

	// The authoring session is released BEFORE activation and the follow-up
	// mount: the managed authority must be able to take the exclusive writer
	// lease, and an adopt lease left held would block it until TTL expiry.
	releaseSession()

	// Journal activation: the authored base enters managed journal service
	// (the server converts the manifest head into the immutable PFT2 base
	// and flips the branch to managed_journal). Mounting requires it; the
	// call is idempotent and resumable, so an interrupted adopt re-run picks
	// up where it left off.
	if err := r.activateJournal(ctx, created.Volume.ID); err != nil {
		return e.fail("adopt", fmt.Errorf("journal activation: %w (the content is committed; resume with: portablefs activate %s)", err, created.Volume.ID))
	}

	if o.common.jsonOut {
		result := map[string]any{
			"volumeId":      created.Volume.ID,
			"branch":        o.branch,
			"commitId":      commit.ID,
			"treeHash":      treeHash,
			"files":         scan.files,
			"dirs":          scan.dirs,
			"symlinks":      scan.symlinks,
			"bytes":         totalBytes,
			"skipped":       len(scan.skipped),
			"uploadedBlobs": uploadedBlobs,
			"dedupedBlobs":  dedupedBlobs,
		}
		mountRC := 0
		if o.mountPath != "" {
			mountRC = r.mountAfterAdopt(created.Volume.ID)
			result["mounted"] = mountRC == 0
			result["mountPath"] = o.mountPath
		}
		if rc := e.printJSON(result); rc != 0 {
			return rc
		}
		return mountRC
	}
	fmt.Fprintf(e.stdout, "adopted %s into volume %s\n", dir, created.Volume.ID)
	fmt.Fprintf(e.stdout, "  branch   %s\n", o.branch)
	fmt.Fprintf(e.stdout, "  commit   %s\n", commit.ID)
	fmt.Fprintf(e.stdout, "  entries  %d files, %d dirs, %d symlinks\n", scan.files, scan.dirs, scan.symlinks)
	fmt.Fprintf(e.stdout, "  bytes    %s\n", humanBytes(totalBytes))
	fmt.Fprintf(e.stdout, "  blobs    %d uploaded, %d deduped\n", uploadedBlobs, dedupedBlobs)
	fmt.Fprintf(e.stdout, "\nEverything under %s was imported, including .git and any credential files — use --exclude to skip paths.\n", dir)
	fmt.Fprintf(e.stdout, "\nnext steps:\n")
	fmt.Fprintf(e.stdout, "  portablefs mount %s %s-live\n", created.Volume.ID, dir)
	fmt.Fprintf(e.stdout, "  (cd %s-live && ls -la)\n", dir)
	fmt.Fprintf(e.stdout, "  portablefs fork %s --name agent-1\n", created.Volume.ID)
	if o.mountPath != "" {
		return r.mountAfterAdopt(created.Volume.ID)
	}
	return 0
}

// mountAfterAdopt reuses the normal mount flow. In JSON mode the mount's own
// human output is diverted to stderr so stdout stays one JSON document.
func (r *adoptRun) mountAfterAdopt(volumeID string) int {
	o := r.opts
	margs := []string{volumeID, o.mountPath, "--branch", o.branch}
	margs = append(margs, o.common.passthroughArgs()...)
	me := *r.e
	if o.common.jsonOut {
		me.stdout = r.e.stderr
	}
	if rc := cmdMount(&me, margs); rc != 0 {
		fmt.Fprintf(r.e.stderr, "portablefs adopt: volume %s was adopted, but the mount failed (see above); mount manually with: portablefs mount %s %s\n", volumeID, volumeID, o.mountPath)
		return rc
	}
	return 0
}

// passthroughArgs re-materializes connection overrides for a nested command
// invocation (adopt --mount runs the mount command with the same settings).
func (o *commonOpts) passthroughArgs() []string {
	var a []string
	if o.apiURL != "" {
		a = append(a, "--api-url", o.apiURL)
	}
	if o.apiToken != "" {
		a = append(a, "--api-token", o.apiToken)
	}
	if o.managerURL != "" {
		a = append(a, "--manager-url", o.managerURL)
	}
	if o.managerToken != "" {
		a = append(a, "--manager-token", o.managerToken)
	}
	if o.profile != "" {
		a = append(a, "--profile", o.profile)
	}
	return a
}

// renewLeaseIfNeeded renews the write lease once half its TTL has elapsed,
// called between upload requests so long imports never let the lease lapse.
// activateJournal polls the server-side journal activation until the branch
// serves managed journal ("active"), surfacing progress as it advances. The
// server converges one step per call (begin conversion → conversion cut →
// finalize); the resident history worker materializes the cut in between. A
// terminal failure (state or cutState "failed") stops the poll immediately;
// the 15-minute ceiling is only the final safety net, and its message keeps
// the last seen attempt/error so the user knows where the server stopped.
func (r *adoptRun) activateJournal(ctx context.Context, volumeID string) error {
	const pollEvery = 2 * time.Second
	const activationTimeout = 15 * time.Minute
	deadline := r.now().Add(activationTimeout)
	lastProgress := ""
	for {
		status, err := r.api.activateJournal(ctx, volumeID, r.opts.branch)
		if err != nil {
			return err
		}
		if status.State == "active" {
			r.progressf("journal active (branch mode %s)", status.BranchMode)
			return nil
		}
		if detail, failed := activationFailed(status); failed {
			return fmt.Errorf("activation failed%s", detail)
		}
		progress := activationProgress(status)
		if progress != lastProgress {
			r.progressf("activating journal (%s) ...", progress)
			lastProgress = progress
		}
		if r.now().After(deadline) {
			return fmt.Errorf("activation did not converge within %s (%s); the server keeps working", activationTimeout, progress)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		r.sleep(pollEvery)
	}
}

func (r *adoptRun) renewLeaseIfNeeded(ctx context.Context) error {
	if r.now().Sub(r.lastRenew) < adoptLeaseTTL/2 {
		return nil
	}
	if err := r.api.adoptRenewLease(ctx, r.leaseID, r.fencingToken, adoptLeaseTTL.Milliseconds()); err != nil {
		return fmt.Errorf("renew lease: %w", err)
	}
	r.lastRenew = r.now()
	return nil
}

// probeBlobs asks the server which digests it is missing, in chunks. A 404
// means the server predates the probe route: report everything as missing.
func (r *adoptRun) probeBlobs(ctx context.Context, digests []string) (map[string]bool, bool, error) {
	missing := make(map[string]bool, len(digests))
	for start := 0; start < len(digests); start += adoptProbeChunk {
		end := min(start+adoptProbeChunk, len(digests))
		chunkMissing, supported, err := r.api.adoptProbeBlobs(ctx, digests[start:end])
		if err != nil {
			return nil, false, err
		}
		if !supported {
			for _, d := range digests {
				missing[d] = true
			}
			return missing, false, nil
		}
		for _, d := range chunkMissing {
			missing[d] = true
		}
	}
	return missing, true, nil
}

func (r *adoptRun) uploadBatch(ctx context.Context, batch []adoptBatchBlob) error {
	return r.withRetry(func() error {
		return r.api.adoptUploadBatchBinary(ctx, batch)
	})
}

// uploadLargeBlob streams one large file. If the server rejects the bytes as
// digest-mismatched, the file changed after the scan: re-hash it, update the
// entry to the new digest, and stream again (the server re-verifies, so the
// stored bytes always match the digest the manifest references).
func (r *adoptRun) uploadLargeBlob(ctx context.Context, en *adoptEntry, present, uploadedSet map[string]bool) error {
	for attempt := 0; attempt < adoptRetryAttempts; attempt++ {
		if present[en.digest] || uploadedSet[en.digest] {
			return nil
		}
		err := r.withRetry(func() error {
			return r.api.adoptPutBlob(ctx, en.digest, en.absPath)
		})
		if err == nil {
			uploadedSet[en.digest] = true
			return nil
		}
		if httpCode(err) != "VOLUME_BLOB_DIGEST_MISMATCH" {
			return fmt.Errorf("upload %s: %w", en.relPath, err)
		}
		newDigest, newSize, herr := hashFile(en.absPath)
		if herr != nil {
			return fmt.Errorf("read %s: %w", en.relPath, herr)
		}
		if newDigest == en.digest {
			return fmt.Errorf("upload %s: server rejected the bytes as digest-mismatched but the file re-hashes identically; re-run adopt when the directory is quiescent", en.relPath)
		}
		r.progressf("portablefs adopt: warning: %s changed while adopting; importing the current contents", en.relPath)
		en.digest = newDigest
		en.size = newSize
	}
	return fmt.Errorf("upload %s: file keeps changing while adopting; re-run adopt when the directory is quiescent", en.relPath)
}

// uploadChunkedFile stages every missing chunk of a chunked entry through the
// shared batcher. Each chunk's bytes are verified against the scanned chunk
// digest at read time; a mismatch means the file changed since the scan, so
// the whole file is re-hashed once (updating digest/size/chunks) and its chunk
// plan restarts with the fresh refs.
func (r *adoptRun) uploadChunkedFile(
	en *adoptEntry,
	present, uploadedSet map[string]bool,
	appendBlob func(digest string, data []byte) error,
	progress func(n int),
) error {
	for attempt := 0; attempt < adoptRetryAttempts; attempt++ {
		rehash := false
		staged := 0
		f, err := os.Open(en.absPath)
		if err != nil {
			return fmt.Errorf("read %s: %w", en.relPath, err)
		}
		for _, ch := range en.chunks {
			if present[ch.digest] || uploadedSet[ch.digest] {
				continue
			}
			data := make([]byte, ch.size)
			if _, err := f.ReadAt(data, ch.offset); err != nil {
				_ = f.Close()
				return fmt.Errorf("read %s @%d: %w", en.relPath, ch.offset, err)
			}
			sum := sha256.Sum256(data)
			if got := "sha256:" + hex.EncodeToString(sum[:]); got != ch.digest {
				rehash = true
				break
			}
			if err := appendBlob(ch.digest, data); err != nil {
				_ = f.Close()
				return err
			}
			staged++
		}
		_ = f.Close()
		if !rehash {
			if staged > 0 {
				progress(staged)
			}
			return nil
		}
		r.progressf("portablefs adopt: warning: %s changed while adopting; importing the current contents", en.relPath)
		digest, size, chunks, herr := hashChunkedFile(en.absPath)
		if herr != nil {
			return fmt.Errorf("read %s: %w", en.relPath, herr)
		}
		en.digest = digest
		en.size = size
		en.chunks = chunks
	}
	return fmt.Errorf("upload %s: file keeps changing while adopting; re-run adopt when the directory is quiescent", en.relPath)
}

// withRetry retries transient failures (network errors and 5xx) with
// exponential backoff; 4xx responses and version-handshake refusals are
// permanent and returned immediately.
func (r *adoptRun) withRetry(fn func() error) error {
	delay := 500 * time.Millisecond
	var err error
	for attempt := 0; attempt < adoptRetryAttempts; attempt++ {
		if attempt > 0 {
			r.sleep(delay)
			delay *= 2
		}
		err = fn()
		if err == nil {
			return nil
		}
		var skew *versionSkewError
		if errors.As(err, &skew) {
			return err
		}
		if status := httpStatus(err); status >= 400 && status < 500 {
			return err
		}
	}
	return err
}

// ---- manifest construction ----

type adoptManifestBlob struct {
	Digest      string `json:"digest"`
	Size        int64  `json:"size"`
	Compression string `json:"compression"`
	Packed      bool   `json:"packed"`
}

type adoptManifestChunk struct {
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
	Offset int64  `json:"offset"`
}

type adoptManifestEntry struct {
	Path       string               `json:"path"`
	Kind       string               `json:"kind"`
	Mode       uint32               `json:"mode"`
	Size       int64                `json:"size"`
	MtimeMs    int64                `json:"mtimeMs"`
	Executable bool                 `json:"executable"`
	Blob       *adoptManifestBlob   `json:"blob,omitempty"`
	Chunks     []adoptManifestChunk `json:"chunks,omitempty"`
	LinkTarget string               `json:"linkTarget,omitempty"`
}

type adoptManifest struct {
	Version  string               `json:"version"`
	TreeHash string               `json:"treeHash"`
	Entries  []adoptManifestEntry `json:"entries"`
}

// buildAdoptManifest maps scanned entries to the wire manifest and the
// treehash inputs. uid/gid/ino are deliberately omitted: adopt captures
// portable content, not machine-local ownership.
func buildAdoptManifest(entries []*adoptEntry) ([]adoptManifestEntry, []treehash.Entry) {
	manifest := make([]adoptManifestEntry, 0, len(entries))
	hashEntries := make([]treehash.Entry, 0, len(entries))
	for _, en := range entries {
		me := adoptManifestEntry{
			Path:       en.relPath,
			Kind:       en.kind,
			Mode:       en.mode,
			Size:       en.size,
			MtimeMs:    en.mtimeMs,
			Executable: en.executable,
			LinkTarget: en.linkTarget,
		}
		he := treehash.Entry{
			Path:       en.relPath,
			Kind:       en.kind,
			Mode:       en.mode,
			Size:       en.size,
			Executable: en.executable,
			LinkTarget: en.linkTarget,
		}
		if en.kind == "file" {
			me.Blob = &adoptManifestBlob{Digest: en.digest, Size: en.size, Compression: "none", Packed: false}
			he.Blob = &treehash.Blob{Digest: en.digest, Size: en.size, Compression: "none", Packed: false}
			// Chunk refs participate in the tree hash (TS scanners chunk files
			// at the same threshold), so they must round-trip exactly.
			for _, ch := range en.chunks {
				me.Chunks = append(me.Chunks, adoptManifestChunk{Digest: ch.digest, Size: ch.size, Offset: ch.offset})
				he.Chunks = append(he.Chunks, treehash.Chunk{Digest: ch.digest, Size: ch.size, Offset: ch.offset})
			}
		}
		manifest = append(manifest, me)
		hashEntries = append(hashEntries, he)
	}
	return manifest, hashEntries
}

// ---- volume-api calls used only by adopt ----

func (c *apiClient) adoptCreateVolume(ctx context.Context, name, branch string) (*volumeMutationResponse, error) {
	body := map[string]string{"volumeId": name, "branchName": branch}
	var out volumeMutationResponse
	if err := c.doIdempotent(ctx, "POST", "/v1/volumes", body, &out, 0, mintIdempotencyKey()); err != nil {
		return nil, err
	}
	return &out, nil
}

// volumeBranchIsEmpty reports whether a branch has only its genesis commit —
// the state an interrupted adopt strands a volume in. Exactly one commit with
// no parent means nothing was ever committed; the attach layer still enforces
// write exclusivity and branch mode on the resume path.
func (c *apiClient) volumeBranchIsEmpty(ctx context.Context, volumeID, branch string) (bool, error) {
	commits, err := c.history(ctx, volumeID, branch, 2)
	if err != nil {
		return false, err
	}
	return len(commits) == 1 && commits[0].ParentCommitID == "", nil
}

type adoptSession struct {
	sessionID    string
	baseCommitID string
	leaseID      string
	fencingToken int64
	expiresAt    int64
}

func (c *apiClient) adoptAttachWrite(ctx context.Context, volumeID, branch, holderID string, leaseTtlMs int64) (*adoptSession, error) {
	body := map[string]any{
		"branch":     branch,
		"mode":       "write",
		"holderId":   holderID,
		"leaseTtlMs": leaseTtlMs,
	}
	var out struct {
		Session struct {
			ID           string `json:"id"`
			BaseCommitID string `json:"baseCommitId"`
			Lease        struct {
				ID           string `json:"id"`
				FencingToken int64  `json:"fencingToken"`
				ExpiresAt    int64  `json:"expiresAt"`
			} `json:"lease"`
		} `json:"session"`
	}
	path := fmt.Sprintf("/v1/volumes/%s/attach", url.PathEscape(volumeID))
	if err := c.do(ctx, "POST", path, body, &out, 0); err != nil {
		return nil, fmt.Errorf("attach write session: %w", err)
	}
	if out.Session.Lease.ID == "" {
		return nil, fmt.Errorf("attach write session: server returned no lease")
	}
	return &adoptSession{
		sessionID:    out.Session.ID,
		baseCommitID: out.Session.BaseCommitID,
		leaseID:      out.Session.Lease.ID,
		fencingToken: out.Session.Lease.FencingToken,
		expiresAt:    out.Session.Lease.ExpiresAt,
	}, nil
}

// adoptProbeBlobs returns the digests the server is missing. supported=false
// means the server has no probe route (HTTP 404); callers upload everything.
func (c *apiClient) adoptProbeBlobs(ctx context.Context, digests []string) (missing []string, supported bool, err error) {
	if len(digests) == 0 {
		return nil, true, nil
	}
	var out struct {
		Missing []string `json:"missing"`
	}
	if err := c.do(ctx, "POST", "/v1/blobs/probe", map[string]any{"digests": digests}, &out, 0); err != nil {
		if httpStatus(err) == 404 {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("probe blobs: %w", err)
	}
	return out.Missing, true, nil
}

type adoptBatchBlob struct {
	digest string
	bytes  []byte
}

// encodeBlobBatchBinary produces the compact batch framing the server parses
// in parseBlobBatchBinary: ascii "OSVB", u16BE version=1, u16BE count, then
// per entry u16BE digest length, u32BE size, digest utf-8, raw bytes.
func encodeBlobBatchBinary(entries []adoptBatchBlob) []byte {
	var buf bytes.Buffer
	buf.WriteString("OSVB")
	var u16 [2]byte
	var u32 [4]byte
	binary.BigEndian.PutUint16(u16[:], 1)
	buf.Write(u16[:])
	binary.BigEndian.PutUint16(u16[:], uint16(len(entries)))
	buf.Write(u16[:])
	for _, en := range entries {
		binary.BigEndian.PutUint16(u16[:], uint16(len(en.digest)))
		buf.Write(u16[:])
		binary.BigEndian.PutUint32(u32[:], uint32(len(en.bytes)))
		buf.Write(u32[:])
		buf.WriteString(en.digest)
		buf.Write(en.bytes)
	}
	return buf.Bytes()
}

// uploadRequestTimeout bounds ONE upload attempt: the shared 60-second
// request floor, scaled up with payload size at a conservative 128 KiB/s, so
// big blobs on slow links get the time they physically need while a wedged
// connection still fails in bounded time instead of hanging the import.
func uploadRequestTimeout(payloadBytes int64) time.Duration {
	scaled := time.Duration(payloadBytes/(128<<10)) * time.Second
	if scaled < defaultRequestTimeout {
		return defaultRequestTimeout
	}
	return scaled
}

// adoptUploadBatchBinary posts one binary batch with ?response=ack so huge
// batches do not echo every blob ref back.
func (c *apiClient) adoptUploadBatchBinary(ctx context.Context, entries []adoptBatchBlob) error {
	payload := encodeBlobBatchBinary(entries)
	ctx, cancel := context.WithTimeout(ctx, uploadRequestTimeout(int64(len(payload))))
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/v1/blobs/batch-binary?response=ack", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/vnd.portablefs.blob-batch.v1")
	if c.token != "" {
		req.Header.Set("authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("upload blob batch: %w", err)
	}
	defer resp.Body.Close()
	if verr := c.checkMinCLIVersion(resp.Header); verr != nil {
		return verr
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("upload blob batch: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return parseErrorBody(resp.StatusCode, data)
	}
	return nil
}

// adoptPutBlob streams one large blob with PUT /v1/blobs/:digest. Each attempt
// re-opens and re-stats the file so retries always send the full current body.
func (c *apiClient) adoptPutBlob(ctx context.Context, digest, absPath string) error {
	f, err := os.Open(absPath)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	size := info.Size()
	ctx, cancel := context.WithTimeout(ctx, uploadRequestTimeout(size))
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "PUT", c.baseURL+"/v1/blobs/"+url.PathEscape(digest), f)
	if err != nil {
		return err
	}
	req.ContentLength = size
	req.Header.Set("content-type", "application/octet-stream")
	if c.token != "" {
		req.Header.Set("authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if verr := c.checkMinCLIVersion(resp.Header); verr != nil {
		return verr
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return parseErrorBody(resp.StatusCode, data)
	}
	return nil
}

// adoptRenewLease sends the renewLeaseRequestSchema body {fencingToken, leaseTtlMs}.
func (c *apiClient) adoptRenewLease(ctx context.Context, leaseID string, fencingToken, leaseTtlMs int64) error {
	body := map[string]any{"fencingToken": fencingToken, "leaseTtlMs": leaseTtlMs}
	path := fmt.Sprintf("/v1/leases/%s/renew", url.PathEscape(leaseID))
	return c.do(ctx, "POST", path, body, nil, 0)
}

type adoptCommitRequest struct {
	LeaseID              string        `json:"leaseId"`
	FencingToken         int64         `json:"fencingToken"`
	ExpectedHeadCommitID string        `json:"expectedHeadCommitId"`
	Manifest             adoptManifest `json:"manifest"`
	MutationCount        int64         `json:"mutationCount"`
	ByteCount            int64         `json:"byteCount"`
}

// adoptCommitSummary commits via commit-summary, which returns the commit
// without echoing the (possibly huge) manifest back.
func (c *apiClient) adoptCommitSummary(ctx context.Context, sessionID string, body adoptCommitRequest) (*commitInfo, error) {
	var out struct {
		Commit commitInfo `json:"commit"`
	}
	path := fmt.Sprintf("/v1/attach-sessions/%s/commit-summary", url.PathEscape(sessionID))
	if err := c.do(ctx, "POST", path, body, &out, 5*time.Minute); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return &out.Commit, nil
}

func (c *apiClient) adoptDetach(ctx context.Context, sessionID string) error {
	path := fmt.Sprintf("/v1/attach-sessions/%s/detach", url.PathEscape(sessionID))
	return c.do(ctx, "POST", path, map[string]any{"releaseLease": true}, nil, 0)
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
