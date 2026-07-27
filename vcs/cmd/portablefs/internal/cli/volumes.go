package cli

import (
	"context"
	"fmt"
	"strings"
	"time"
)

func formatMs(ms int64) string {
	if ms == 0 {
		return "-"
	}
	return time.UnixMilli(ms).Local().Format(time.RFC3339)
}

func cmdCreate(e *cmdEnv, args []string) int {
	fs := newFlagSet("create")
	var o commonOpts
	addCommonFlags(fs, &o)
	tenant := fs.String("tenant", "", "tenant id to create the volume under (admin credentials only)")
	positionals, err := parseArgs(fs, args)
	if err != nil {
		return e.handleParseError("create", err)
	}
	if len(positionals) > 1 {
		return e.usageError("create", fmt.Errorf("expected at most one volume name, got %d arguments", len(positionals)))
	}
	name := ""
	if len(positionals) == 1 {
		name = positionals[0]
		if !validVolumeName(name) {
			return e.usageError("create", fmt.Errorf("invalid volume name %q: must match [A-Za-z0-9_-]{1,220}", name))
		}
	}
	s, err := e.resolveSettings(&o)
	if err != nil {
		return e.fail("create", err)
	}
	if err := s.requireAPI(); err != nil {
		return e.fail("create", err)
	}
	resp, err := e.apiClient(s.apiURL, s.apiToken).createVolume(context.Background(), name, *tenant)
	if err != nil {
		return e.fail("create", err)
	}
	if o.jsonOut {
		return e.printJSON(map[string]any{
			"volumeId":     resp.Volume.ID,
			"tenantId":     resp.Volume.TenantID,
			"branch":       resp.Branch.Name,
			"headCommitId": resp.Head.ID,
			"treeHash":     resp.Head.TreeHash,
		})
	}
	fmt.Fprintf(e.stdout, "created volume %s\n", resp.Volume.ID)
	fmt.Fprintf(e.stdout, "  branch  %s\n", resp.Branch.Name)
	fmt.Fprintf(e.stdout, "  head    %s\n", resp.Head.ID)
	fmt.Fprintf(e.stdout, "\nmount it:  portablefs mount %s <path>\n", resp.Volume.ID)
	return 0
}

func cmdLs(e *cmdEnv, args []string) int {
	fs := newFlagSet("ls")
	var o commonOpts
	addCommonFlags(fs, &o)
	limit := fs.Int("limit", 0, "maximum number of volumes to print (0 = all)")
	if _, err := parseArgs(fs, args); err != nil {
		return e.handleParseError("ls", err)
	}
	s, err := e.resolveSettings(&o)
	if err != nil {
		return e.fail("ls", err)
	}
	if err := s.requireAPI(); err != nil {
		return e.fail("ls", err)
	}
	volumes, err := e.apiClient(s.apiURL, s.apiToken).listVolumes(context.Background(), *limit)
	if err != nil {
		if httpStatus(err) == 404 {
			return e.fail("ls", fmt.Errorf("server does not support volume listing (upgrade volume-api)"))
		}
		return e.fail("ls", err)
	}
	// Older servers ignore the limit query parameter; enforce it client-side too.
	if *limit > 0 && len(volumes) > *limit {
		volumes = volumes[:*limit]
	}
	if o.jsonOut {
		return e.printJSON(map[string]any{"volumes": volumes})
	}
	if len(volumes) == 0 {
		fmt.Fprintln(e.stdout, "no volumes (create one: portablefs create <name>)")
		return 0
	}
	for _, v := range volumes {
		fmt.Fprintf(e.stdout, "%s  created %s\n", v.VolumeID, formatMs(v.CreatedAtMs))
		for _, b := range v.Branches {
			fmt.Fprintf(e.stdout, "  %s @ %s\n", b.Name, b.HeadCommitID)
		}
	}
	return 0
}

// cmdStatus reports a branch's state from mode-agnostic metadata: the branch
// listing (which carries the serving mode and answers in every mode) decides
// the shape. Base-authoring branches keep the manifest head summary; branches
// served by a live journal authority report the live-serving facts honestly
// (mode, latest committed snapshot cut, latest published commit, local
// mounts) instead of dying on the manifest head route.
func cmdStatus(e *cmdEnv, args []string) int {
	fs := newFlagSet("status")
	var o commonOpts
	addCommonFlags(fs, &o)
	branch := fs.String("branch", "main", "branch name")
	positionals, err := parseArgs(fs, args)
	if err != nil {
		return e.handleParseError("status", err)
	}
	if len(positionals) != 1 {
		return e.usageError("status", fmt.Errorf("expected exactly one volume id"))
	}
	volumeID := positionals[0]
	s, err := e.resolveSettings(&o)
	if err != nil {
		return e.fail("status", err)
	}
	if err := s.requireAPI(); err != nil {
		return e.fail("status", err)
	}
	api := e.apiClient(s.apiURL, s.apiToken)
	ctx := context.Background()

	branches, err := api.branches(ctx, volumeID)
	if err != nil {
		if httpStatus(err) == 404 {
			return e.fail("status", fmt.Errorf("volume %q not found (list volumes: portablefs ls)", volumeID))
		}
		return e.fail("status", err)
	}
	var br *branchInfo
	names := make([]string, 0, len(branches))
	for i := range branches {
		names = append(names, branches[i].Name)
		if branches[i].Name == *branch {
			br = &branches[i]
		}
	}
	if br == nil {
		return e.fail("status", fmt.Errorf("branch %q not found on volume %s (branches: %s)", *branch, volumeID, strings.Join(names, ", ")))
	}

	if !br.isJournalServed() {
		// Base-authoring (or pre-journal server): the manifest head summary
		// is live truth. A typed live-authority refusal here means the server
		// knows better than the branch listing (older listings carry no
		// mode); fall through to the live rendering instead of failing.
		head, herr := api.head(ctx, volumeID, *branch)
		if herr == nil {
			return e.printManifestStatus(&o, br, head)
		}
		if httpCode(herr) != "LIVE_AUTHORITY_ROUTE_REQUIRED" {
			return e.fail("status", herr)
		}
	}
	return e.printLiveStatus(&o, api, volumeID, br)
}

// printManifestStatus renders the classic head summary for a branch whose
// manifest head is live truth.
func (e *cmdEnv) printManifestStatus(o *commonOpts, br *branchInfo, head *headResponse) int {
	mode := br.BranchMode
	if mode == "" {
		mode = "legacy_manifest"
	}
	if o.jsonOut {
		return e.printJSON(map[string]any{
			"volumeId":          head.Volume.ID,
			"branch":            head.Branch.Name,
			"branchMode":        mode,
			"headCommitId":      head.Head.ID,
			"treeHash":          head.Head.TreeHash,
			"activeLeases":      head.ActiveLeases,
			"activeDelegations": head.ActiveDelegations,
		})
	}
	fmt.Fprintf(e.stdout, "volume       %s\n", head.Volume.ID)
	fmt.Fprintf(e.stdout, "branch       %s\n", head.Branch.Name)
	fmt.Fprintf(e.stdout, "mode         authoring (import in progress — finish with: portablefs activate %s)\n", head.Volume.ID)
	fmt.Fprintf(e.stdout, "head         %s\n", head.Head.ID)
	fmt.Fprintf(e.stdout, "tree         %s\n", head.Head.TreeHash)
	fmt.Fprintf(e.stdout, "leases       %d active\n", head.ActiveLeases)
	fmt.Fprintf(e.stdout, "delegations  %d active\n", head.ActiveDelegations)
	return 0
}

// printLiveStatus renders a journal-served (or retiring) branch from
// mode-agnostic reads: latest published commit, snapshot-cut lifecycle, and
// this machine's mounts of the branch.
func (e *cmdEnv) printLiveStatus(o *commonOpts, api *apiClient, volumeID string, br *branchInfo) int {
	ctx := context.Background()
	var latest *historyCommit
	if commits, err := api.history(ctx, volumeID, br.Name, 1); err == nil && len(commits) > 0 {
		latest = &commits[0]
	}
	var latestReady *snapshotInfo
	pendingCuts := 0
	if snaps, err := api.snapshots(ctx, volumeID, br.Name); err == nil {
		for i := range snaps {
			sn := &snaps[i]
			if sn.isMaterializing() {
				pendingCuts++
			}
			if sn.CutID != "" && sn.isReady() && (latestReady == nil || sn.CreatedAt > latestReady.CreatedAt) {
				latestReady = sn
			}
		}
	}
	localMounts := e.localMountsOf(volumeID, br.Name)

	retiring := br.BranchMode == "retiring" || br.BranchMode == "retired"
	modeLine := "live (served by a managed journal authority; mount to read or write)"
	if retiring {
		modeLine = fmt.Sprintf("%s (leaving live service; committed history stays readable through snapshots)", br.BranchMode)
	}

	if o.jsonOut {
		out := map[string]any{
			"volumeId":   volumeID,
			"branch":     br.Name,
			"branchMode": br.BranchMode,
			"live":       !retiring,
			// The branch row's committed base head; the live tip is served
			// through mounts, not manifest routes.
			"baseCommitId": br.HeadCommitID,
			"pendingCuts":  pendingCuts,
			"localMounts":  localMounts,
		}
		if latest != nil {
			out["latestCommit"] = latest
		}
		if latestReady != nil {
			out["latestReadySnapshot"] = latestReady
		}
		return e.printJSON(out)
	}
	fmt.Fprintf(e.stdout, "volume       %s\n", volumeID)
	fmt.Fprintf(e.stdout, "branch       %s\n", br.Name)
	fmt.Fprintf(e.stdout, "mode         %s\n", modeLine)
	if latest != nil {
		kind := "manifest"
		if latest.CommitKind != "" {
			kind = latest.CommitKind
		}
		fmt.Fprintf(e.stdout, "committed    %s (%s, %s)\n", latest.ID, kind, formatMs(latest.CreatedAtMs))
	}
	if latestReady != nil {
		fmt.Fprintf(e.stdout, "latest cut   %s ready %s\n", latestReady.ID, formatMs(latestReady.CreatedAt))
	} else {
		fmt.Fprintf(e.stdout, "latest cut   none ready yet (snapshot the branch to record one: portablefs snapshot %s)\n", volumeID)
	}
	if pendingCuts > 0 {
		fmt.Fprintf(e.stdout, "cuts         %d still being written\n", pendingCuts)
	}
	if len(localMounts) == 0 {
		fmt.Fprintf(e.stdout, "mounts       none on this machine (attach one: portablefs mount %s <path>)\n", volumeID)
	} else {
		for _, m := range localMounts {
			fmt.Fprintf(e.stdout, "mounts       %s (%s)\n", m.MountPath, m.Health)
		}
	}
	return 0
}

// localMountRow is one of this machine's mounts of a volume+branch, as
// reported by status: the recorded mount plus its liveness/credential health.
type localMountRow struct {
	MountPath string `json:"mountPath"`
	PID       int    `json:"pid"`
	Health    string `json:"health"`
}

// localMountsOf lists this machine's recorded mounts of volume+branch — the
// cheap local slice of "who is serving this live branch right now".
func (e *cmdEnv) localMountsOf(volumeID, branch string) []localMountRow {
	dir, err := e.mountStateDir()
	if err != nil {
		return nil
	}
	states, err := listMountStates(dir)
	if err != nil {
		return nil
	}
	rows := make([]localMountRow, 0, 2)
	for _, st := range states {
		if st.VolumeID != volumeID || st.Branch != branch {
			continue
		}
		rows = append(rows, localMountRow{MountPath: st.MountPath, PID: st.PID, Health: mountHealth(&st)})
	}
	return rows
}

func cmdHistory(e *cmdEnv, args []string) int {
	fs := newFlagSet("history")
	var o commonOpts
	addCommonFlags(fs, &o)
	branch := fs.String("branch", "main", "branch name")
	limit := fs.Int("limit", 50, "maximum number of commits")
	positionals, err := parseArgs(fs, args)
	if err != nil {
		return e.handleParseError("history", err)
	}
	if len(positionals) != 1 {
		return e.usageError("history", fmt.Errorf("expected exactly one volume id"))
	}
	volumeID := positionals[0]
	s, err := e.resolveSettings(&o)
	if err != nil {
		return e.fail("history", err)
	}
	if err := s.requireAPI(); err != nil {
		return e.fail("history", err)
	}
	api := e.apiClient(s.apiURL, s.apiToken)
	commits, err := api.history(context.Background(), volumeID, *branch, *limit)
	if err == nil {
		if o.jsonOut {
			return e.printJSON(map[string]any{"commits": commits})
		}
		if len(commits) == 0 {
			fmt.Fprintln(e.stdout, "no commits")
			return 0
		}
		for _, c := range commits {
			fmt.Fprintf(e.stdout, "%s  %s  +%d mutations  %d bytes\n", c.ID, formatMs(c.CreatedAtMs), c.MutationCount, c.ByteCount)
		}
		return 0
	}
	if httpStatus(err) != 404 {
		return e.fail("history", err)
	}

	// Older volume-api without /commits: fall back to the head summary plus the
	// snapshot list, which is the closest available view of branch history.
	head, herr := api.head(context.Background(), volumeID, *branch)
	if herr != nil {
		return e.fail("history", herr)
	}
	snaps, serr := api.snapshots(context.Background(), volumeID, *branch)
	if serr != nil {
		return e.fail("history", serr)
	}
	const note = "server does not support commit history (upgrade volume-api); showing head and snapshots instead"
	if o.jsonOut {
		return e.printJSON(map[string]any{
			"note":         note,
			"headCommitId": head.Head.ID,
			"treeHash":     head.Head.TreeHash,
			"snapshots":    snaps,
		})
	}
	fmt.Fprintf(e.stderr, "note: %s\n", note)
	fmt.Fprintf(e.stdout, "head  %s  tree %s\n", head.Head.ID, head.Head.TreeHash)
	for _, sn := range snaps {
		name := sn.Name
		if name == "" {
			name = "(unnamed)"
		}
		fmt.Fprintf(e.stdout, "snapshot %s  %s  commit %s  %s\n", sn.ID, name, sn.CommitID, formatMs(sn.CreatedAt))
	}
	return 0
}
