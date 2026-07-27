package cli

import (
	"context"
	"fmt"
	"time"
)

func cmdSnapshot(e *cmdEnv, args []string) int {
	fs := newFlagSet("snapshot")
	var o commonOpts
	addCommonFlags(fs, &o)
	name := fs.String("name", "", "snapshot name (server assigns an id either way)")
	branch := fs.String("branch", "main", "branch to snapshot")
	positionals, err := parseArgs(fs, args)
	if err != nil {
		return e.handleParseError("snapshot", err)
	}
	if len(positionals) != 1 {
		return e.usageError("snapshot", fmt.Errorf("expected exactly one volume id"))
	}
	s, err := e.resolveSettings(&o)
	if err != nil {
		return e.fail("snapshot", err)
	}
	if err := s.requireAPI(); err != nil {
		return e.fail("snapshot", err)
	}
	snap, err := e.apiClient(s.apiURL, s.apiToken).snapshot(context.Background(), positionals[0], *branch, *name)
	if err != nil {
		return e.fail("snapshot", explainSnapshotModeConflict(err, positionals[0]))
	}
	if o.jsonOut {
		return e.printJSON(map[string]any{"snapshot": snap})
	}
	label := snap.Name
	if label == "" {
		label = "(unnamed)"
	}
	if snap.isMaterializing() {
		// Live-branch snapshots capture asynchronously; the record exists
		// now, the content lands in the background.
		fmt.Fprintf(e.stdout, "snapshot %s  %s  being written from the live branch (watch it: portablefs snapshots %s)\n", snap.ID, label, positionals[0])
		return 0
	}
	fmt.Fprintf(e.stdout, "snapshot %s  %s  commit %s\n", snap.ID, label, snap.CommitID)
	return 0
}

func cmdSnapshots(e *cmdEnv, args []string) int {
	fs := newFlagSet("snapshots")
	var o commonOpts
	addCommonFlags(fs, &o)
	branch := fs.String("branch", "", "filter to one branch (default: all branches)")
	positionals, err := parseArgs(fs, args)
	if err != nil {
		return e.handleParseError("snapshots", err)
	}
	if len(positionals) != 1 {
		return e.usageError("snapshots", fmt.Errorf("expected exactly one volume id"))
	}
	s, err := e.resolveSettings(&o)
	if err != nil {
		return e.fail("snapshots", err)
	}
	if err := s.requireAPI(); err != nil {
		return e.fail("snapshots", err)
	}
	snaps, err := e.apiClient(s.apiURL, s.apiToken).snapshots(context.Background(), positionals[0], *branch)
	if err != nil {
		return e.fail("snapshots", err)
	}
	if o.jsonOut {
		return e.printJSON(map[string]any{"snapshots": snaps})
	}
	if len(snaps) == 0 {
		fmt.Fprintln(e.stdout, "no snapshots (create one: portablefs snapshot <volumeId> --name <name>)")
		return 0
	}
	for _, sn := range snaps {
		name := sn.Name
		if name == "" {
			name = "(unnamed)"
		}
		// State is additive (journal-era cut records); ready commit-pinned
		// records keep the previous line exactly.
		state := ""
		if !sn.isReady() {
			state = "  " + sn.State
		}
		fmt.Fprintf(e.stdout, "%s  %s  commit %s  %s%s\n", sn.ID, name, sn.CommitID, formatMs(sn.CreatedAt), state)
	}
	return 0
}

// snapshotReadyTimeout bounds how long fork/branch wait for a snapshot cut of
// a live branch to materialize (matches the journal-activation budget).
const snapshotReadyTimeout = 15 * time.Minute

// explainSnapshotModeConflict rewrites the typed refusal snapshot creation
// gets on a journal-owned branch that has never been served (a
// created-but-never-mounted volume has no live journal state to capture).
// The raw envelope talks about manifest commits mutating branch heads, which
// means nothing at the CLI surface.
func explainSnapshotModeConflict(err error, volumeID string) error {
	if httpCode(err) != "VOLUME_BRANCH_MODE_CONFLICT" {
		return err
	}
	return fmt.Errorf("this branch is live-managed but has never been served, so there is no live state to snapshot yet; mount the volume once (portablefs mount %s <path>) to start it and retry", volumeID)
}

// resolveSnapshotRef finds a snapshot record by name (newest match wins) or
// raw id. branch narrows the listing to one branch's records; empty searches
// the whole volume.
func resolveSnapshotRef(ctx context.Context, api *apiClient, volumeID, branch, ref string) (*snapshotInfo, error) {
	snaps, err := api.snapshots(ctx, volumeID, branch)
	if err != nil {
		return nil, err
	}
	var match *snapshotInfo
	for i := range snaps {
		sn := &snaps[i]
		if sn.Name == ref && (match == nil || sn.CreatedAt > match.CreatedAt) {
			match = sn
		}
	}
	if match == nil {
		for i := range snaps {
			if snaps[i].ID == ref {
				match = &snaps[i]
				break
			}
		}
	}
	if match == nil {
		return nil, fmt.Errorf("snapshot %q not found on volume %s (list them: portablefs snapshots %s)", ref, volumeID, volumeID)
	}
	return match, nil
}

// awaitSnapshotReady waits until a snapshot record can be branched or forked.
// Commit-pinned records are born ready and return immediately. A snapshot of
// a journal-served branch is an asynchronous history cut that materializes in
// the background, so this polls the listing — with progress on stderr — until
// the cut is ready, definitively failed, or the timeout elapses.
func (e *cmdEnv) awaitSnapshotReady(api *apiClient, volumeID string, snap *snapshotInfo) (*snapshotInfo, error) {
	if snap.isDead() {
		return nil, fmt.Errorf("snapshot %s failed while being written (state %s) and can never be used; create a fresh one (portablefs snapshot %s)", snap.ID, snap.State, volumeID)
	}
	if snap.isReady() {
		return snap, nil
	}
	sleep := e.sleepFn
	if sleep == nil {
		sleep = time.Sleep
	}
	fmt.Fprintf(e.stderr, "snapshot %s is being written from the live branch state ...\n", snap.ID)
	lastState := snap.State
	deadline := time.Now().Add(snapshotReadyTimeout)
	for {
		sleep(2 * time.Second)
		snaps, err := api.snapshots(context.Background(), volumeID, "")
		if err != nil {
			return nil, fmt.Errorf("waiting for snapshot %s: %w", snap.ID, err)
		}
		var cur *snapshotInfo
		for i := range snaps {
			if snaps[i].ID == snap.ID {
				cur = &snaps[i]
				break
			}
		}
		if cur == nil {
			return nil, fmt.Errorf("snapshot %s disappeared while being written (list them: portablefs snapshots %s)", snap.ID, volumeID)
		}
		if cur.isDead() {
			return nil, fmt.Errorf("snapshot %s failed while being written (state %s); create a fresh one (portablefs snapshot %s)", cur.ID, cur.State, volumeID)
		}
		if cur.isReady() {
			fmt.Fprintf(e.stderr, "snapshot %s ready\n", cur.ID)
			return cur, nil
		}
		if cur.State != lastState {
			fmt.Fprintf(e.stderr, "snapshot %s %s ...\n", cur.ID, cur.State)
			lastState = cur.State
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("snapshot %s did not become ready within %s (state %s); it keeps materializing server-side — retry once `portablefs snapshots %s` shows it ready", snap.ID, snapshotReadyTimeout, cur.State, volumeID)
		}
	}
}

func cmdBranch(e *cmdEnv, args []string) int {
	fs := newFlagSet("branch")
	var o commonOpts
	addCommonFlags(fs, &o)
	fromBranch := fs.String("from-branch", "main", "source branch")
	fromSnapshot := fs.String("from-snapshot", "", "source snapshot name or id (default: source branch's current state)")
	positionals, err := parseArgs(fs, args)
	if err != nil {
		return e.handleParseError("branch", err)
	}
	if len(positionals) != 2 {
		return e.usageError("branch", fmt.Errorf("expected <volumeId> <branchName>"))
	}
	volumeID, branchName := positionals[0], positionals[1]
	s, err := e.resolveSettings(&o)
	if err != nil {
		return e.fail("branch", err)
	}
	if err := s.requireAPI(); err != nil {
		return e.fail("branch", err)
	}
	api := e.apiClient(s.apiURL, s.apiToken)
	ctx := context.Background()

	var resp *createBranchResponse
	if *fromSnapshot != "" {
		// Resolve the reference client-side (scoped to the source branch,
		// matching the server's own name resolution) so cut-backed records —
		// which have ids but no names on the wire — work exactly like
		// commit-pinned ones, including the wait for a cut still being
		// written.
		snap, err := resolveSnapshotRef(ctx, api, volumeID, *fromBranch, *fromSnapshot)
		if err != nil {
			return e.fail("branch", err)
		}
		snap, err = e.awaitSnapshotReady(api, volumeID, snap)
		if err != nil {
			return e.fail("branch", err)
		}
		resp, err = api.createBranch(ctx, volumeID, branchName, *fromBranch, "", snap.ID)
		if err != nil {
			return e.fail("branch", err)
		}
	} else {
		resp, err = api.createBranch(ctx, volumeID, branchName, *fromBranch, "", "")
		if httpCode(err) == "LIVE_AUTHORITY_ROUTE_REQUIRED" {
			// The source branch is served live: its manifest head is not the
			// branchable truth. Record a snapshot cut of the live state, wait
			// for it to land, and open the branch from the cut — the exact
			// flow the server supports for live branches.
			fmt.Fprintf(e.stderr, "branch %s@%s is live; snapshotting its current state for the new branch ...\n", volumeID, *fromBranch)
			snap, serr := api.snapshot(ctx, volumeID, *fromBranch, fmt.Sprintf("branch-%d", time.Now().UnixMilli()))
			if serr != nil {
				return e.fail("branch", explainSnapshotModeConflict(serr, volumeID))
			}
			snap, serr = e.awaitSnapshotReady(api, volumeID, snap)
			if serr != nil {
				return e.fail("branch", serr)
			}
			resp, err = api.createBranch(ctx, volumeID, branchName, *fromBranch, "", snap.ID)
		}
		if err != nil {
			return e.fail("branch", err)
		}
	}
	if o.jsonOut {
		return e.printJSON(map[string]any{
			"branch":       resp.Branch.Name,
			"headCommitId": resp.Head.ID,
			"treeHash":     resp.Head.TreeHash,
		})
	}
	fmt.Fprintf(e.stdout, "created branch %s @ %s\n", resp.Branch.Name, resp.Head.ID)
	return 0
}

func cmdBranches(e *cmdEnv, args []string) int {
	fs := newFlagSet("branches")
	var o commonOpts
	addCommonFlags(fs, &o)
	positionals, err := parseArgs(fs, args)
	if err != nil {
		return e.handleParseError("branches", err)
	}
	if len(positionals) != 1 {
		return e.usageError("branches", fmt.Errorf("expected exactly one volume id"))
	}
	s, err := e.resolveSettings(&o)
	if err != nil {
		return e.fail("branches", err)
	}
	if err := s.requireAPI(); err != nil {
		return e.fail("branches", err)
	}
	branches, err := e.apiClient(s.apiURL, s.apiToken).branches(context.Background(), positionals[0])
	if err != nil {
		return e.fail("branches", err)
	}
	if o.jsonOut {
		return e.printJSON(map[string]any{"branches": branches})
	}
	for _, b := range branches {
		fmt.Fprintf(e.stdout, "%s @ %s\n", b.Name, b.HeadCommitID)
	}
	return 0
}

func cmdFork(e *cmdEnv, args []string) int {
	fs := newFlagSet("fork")
	var o commonOpts
	addCommonFlags(fs, &o)
	snapshotName := fs.String("snapshot", "", "snapshot name or id to fork from (default: snapshot the branch state now)")
	newName := fs.String("name", "", "volume id for the fork (default: server-generated)")
	branch := fs.String("branch", "main", "branch to snapshot when --snapshot is omitted")
	positionals, err := parseArgs(fs, args)
	if err != nil {
		return e.handleParseError("fork", err)
	}
	if len(positionals) != 1 {
		return e.usageError("fork", fmt.Errorf("expected exactly one source volume id"))
	}
	if *newName != "" && !validVolumeName(*newName) {
		return e.usageError("fork", fmt.Errorf("invalid volume name %q: must match [A-Za-z0-9_-]{1,220}", *newName))
	}
	volumeID := positionals[0]
	s, err := e.resolveSettings(&o)
	if err != nil {
		return e.fail("fork", err)
	}
	if err := s.requireAPI(); err != nil {
		return e.fail("fork", err)
	}
	api := e.apiClient(s.apiURL, s.apiToken)
	ctx := context.Background()

	// The source volume's tenant id rides in the fork body (older volume-api
	// builds require it). Resolved through mode-agnostic metadata — the
	// manifest head route refuses journal-served branches typed, and those
	// are exactly the branches cloud volumes have.
	tenantID := api.resolveVolumeTenant(ctx, volumeID, *branch)

	var snap *snapshotInfo
	if *snapshotName == "" {
		snap, err = api.snapshot(ctx, volumeID, *branch, fmt.Sprintf("fork-%d", time.Now().UnixMilli()))
		if err != nil {
			if httpCode(err) == "VOLUME_BRANCH_MODE_CONFLICT" {
				return e.fail("fork", explainSnapshotModeConflict(err, volumeID))
			}
			return e.fail("fork", fmt.Errorf("snapshot branch state before fork: %w", err))
		}
	} else {
		snap, err = resolveSnapshotRef(ctx, api, volumeID, "", *snapshotName)
		if err != nil {
			return e.fail("fork", err)
		}
	}
	// A snapshot of a live (journal-served) branch is an asynchronous cut;
	// wait for it to land before forking, with progress while it writes.
	snap, err = e.awaitSnapshotReady(api, volumeID, snap)
	if err != nil {
		return e.fail("fork", err)
	}

	resp, err := api.forkSnapshot(ctx, snap.ID, tenantID, *newName)
	if err != nil {
		if httpCode(err) == "HISTORY_FORK_UNSUPPORTED" {
			// This server's schema lineage only opens live-branch snapshots
			// within their own volume. The snapshot is ready and usable —
			// hand the user the exact command that works.
			return e.fail("fork", fmt.Errorf("this server cannot fork a live branch's snapshot into a new volume; the snapshot is ready — open it as a branch of %s instead:\n  portablefs branch %s <newBranchName> --from-snapshot %s", volumeID, volumeID, snap.ID))
		}
		return e.fail("fork", err)
	}
	if o.jsonOut {
		return e.printJSON(map[string]any{
			"volumeId":     resp.Volume.ID,
			"branch":       resp.Branch.Name,
			"headCommitId": resp.Head.ID,
			"snapshotId":   snap.ID,
		})
	}
	fmt.Fprintf(e.stdout, "forked %s (snapshot %s) into new volume %s\n", volumeID, snap.ID, resp.Volume.ID)
	fmt.Fprintf(e.stdout, "  branch  %s @ %s\n", resp.Branch.Name, resp.Head.ID)
	fmt.Fprintf(e.stdout, "\nmount it:  portablefs mount %s <path>\n", resp.Volume.ID)
	return 0
}
