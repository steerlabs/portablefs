package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/steerlabs/portablefs/vcs/internal/localdirs"
	"github.com/steerlabs/portablefs/vcs/internal/localroutes"
	"github.com/steerlabs/portablefs/vcs/internal/portablefsd"
	"github.com/steerlabs/portablefs/vcs/internal/privatepath"
)

// This file holds the two operator-facing commands for machine-local routes:
// `portablefs route <path>`, which answers "is this path local or shared, and
// why", and `portablefs prune-local`, which reclaims backing no route can
// reach any more. Both read the same durable facts a mount publishes — the
// per-mount state record and the per-volume active-route record — so they
// answer identically whether or not a mount is currently running.

// localBackingDir is <stateBase>/local, the parent of every volume's backing
// tree and of the sidecar records beside them.
func localBackingDir(mountsDir string) string {
	return filepath.Join(filepath.Dir(mountsDir), "local")
}

// portablefsdStateDir is the daemon's independent durable state root. FSKit
// grafts do not live in localBackingDir: the daemon keys them by
// (volume, branch) beneath this tree.
func portablefsdStateDir(mountsDir string) string {
	return filepath.Join(filepath.Dir(mountsDir), "portablefsd")
}

func fskitBackingRoot(mountsDir, volumeID, branch string) string {
	return portablefsd.LocalBackingRoot(portablefsdStateDir(mountsDir), volumeID, branch)
}

func mountBackingRoot(mountsDir string, st *mountState) string {
	if st.Strategy == "fskit" {
		return fskitBackingRoot(mountsDir, st.VolumeID, st.Branch)
	}
	if st.LocalBackingRoot != "" {
		return st.LocalBackingRoot
	}
	return localDirsBackingRoot(mountsDir, st.VolumeID)
}

// routeAnswer is one resolved path, in the shape `portablefs route` prints.
type routeAnswer struct {
	Path        string `json:"path"`
	MountPath   string `json:"mountPath"`
	VolumeID    string `json:"volumeId"`
	Branch      string `json:"branch"`
	VolumePath  string `json:"volumePath"`
	Storage     string `json:"storage"` // "machine-local" | "shared"
	Rule        string `json:"rule,omitempty"`
	RouteRoot   string `json:"routeRoot,omitempty"`
	BackingPath string `json:"backingPath,omitempty"`
	BackingLive bool   `json:"backingExists,omitempty"`
	Bytes       int64  `json:"backingBytes,omitempty"`
	// Revision is the VOLUME declaration's revision — what the authority
	// pins the attach to. PerMachine reports the legacy case where this
	// machine's --local-dir flags supplied the rules instead, which is
	// possible only on a volume that declares nothing.
	Revision   string   `json:"revision"`
	PerMachine bool     `json:"perMachineRoutes,omitempty"`
	Patterns   []string `json:"patterns,omitempty"`
}

// cmdRoute explains one path: which mount serves it, whether it is served
// from machine-local disk or from the shared volume, and exactly which rule
// decided that.
func cmdRoute(e *cmdEnv, args []string) int {
	fs := newFlagSet("route")
	var o commonOpts
	addCommonFlags(fs, &o)
	positionals, err := parseArgs(fs, args)
	if err != nil {
		return e.handleParseError("route", err)
	}
	if len(positionals) != 1 {
		return e.usageError("route", fmt.Errorf("expected exactly one path"))
	}
	target, err := filepath.Abs(positionals[0])
	if err != nil {
		return e.fail("route", err)
	}
	target = filepath.Clean(target)
	dir, err := e.mountStateDir()
	if err != nil {
		return e.fail("route", err)
	}
	states, err := listMountStates(dir)
	if err != nil {
		return e.fail("route", err)
	}
	st, rel, ok := mountContaining(states, target)
	if !ok {
		return e.fail("route", fmt.Errorf("no PortableFS mount on this machine contains %s (list mounts: portablefs mounts)", target))
	}
	rules, err := mountRuleSet(&st)
	if err != nil {
		return e.fail("route", fmt.Errorf("mount %s recorded an unparsable route set: %w", st.MountPath, err))
	}
	ans := routeAnswer{
		Path:       target,
		MountPath:  st.MountPath,
		VolumeID:   st.VolumeID,
		Branch:     st.Branch,
		VolumePath: rel,
		Storage:    "shared",
		Revision:   st.LocalRouteRevision,
		PerMachine: st.LocalRoutesPerMachine || (len(st.LocalRoutes) == 0 && len(st.LocalDirs) > 0 && !st.LocalDirsDeclared),
		Patterns:   rules.Patterns(),
	}
	if root, rule, matched := rules.MatchRule(rel); matched {
		ans.Storage = "machine-local"
		ans.Rule = rule
		ans.RouteRoot = root
		backingRoot := mountBackingRoot(dir, &st)
		ans.BackingPath = filepath.Join(backingRoot, filepath.FromSlash(root))
		if fi, err := os.Stat(ans.BackingPath); err == nil && fi.IsDir() {
			ans.BackingLive = true
			if bytes, _, err := localdirs.BackingUsage(backingRoot, root); err == nil {
				ans.Bytes = bytes
			}
		}
	}
	if o.jsonOut {
		return e.printJSON(ans)
	}
	fmt.Fprintf(e.stdout, "path         %s\n", ans.Path)
	fmt.Fprintf(e.stdout, "mount        %s (volume %s, branch %s)\n", ans.MountPath, ans.VolumeID, ans.Branch)
	fmt.Fprintf(e.stdout, "volume path  %s\n", displayVolumePath(ans.VolumePath))
	fmt.Fprintf(e.stdout, "storage      %s\n", ans.Storage)
	if ans.Storage == "shared" {
		fmt.Fprintf(e.stdout, "rule         none matches (served by the authority volume)\n")
	} else {
		fmt.Fprintf(e.stdout, "rule         %s\n", ans.Rule)
		fmt.Fprintf(e.stdout, "route root   %s\n", ans.RouteRoot)
		if ans.BackingLive {
			fmt.Fprintf(e.stdout, "backing      %s (%s)\n", ans.BackingPath, humanBytes(ans.Bytes))
		} else {
			fmt.Fprintf(e.stdout, "backing      %s (not created yet — the route owns the name, nothing more)\n", ans.BackingPath)
		}
	}
	fmt.Fprintf(e.stdout, "revision     %s (%s)\n", revisionPrefix(ans.Revision), localdirs.VolumeConfigPath)
	if len(ans.Patterns) == 0 {
		fmt.Fprintf(e.stdout, "patterns     none (declare them in %s)\n", localdirs.VolumeConfigPath)
	} else {
		fmt.Fprintf(e.stdout, "patterns     %s\n", strings.Join(ans.Patterns, " "))
	}
	if ans.PerMachine {
		fmt.Fprintf(e.stdout, "warning      these rules come from this machine's --local-dir flags, not from the volume:\n")
		fmt.Fprintf(e.stdout, "             peers still treat these paths as shared. Declare them in %s instead.\n", localdirs.VolumeConfigPath)
	}
	return 0
}

func displayVolumePath(rel string) string {
	if rel == "" {
		return "(volume root)"
	}
	return rel
}

// revisionPrefix renders a route revision the way logs and status do: a hex
// prefix long enough to correlate, never a bare truncation of nothing.
func revisionPrefix(rev string) string {
	if rev == "" {
		return "(none)"
	}
	if len(rev) > 12 {
		return rev[:12] + "…"
	}
	return rev
}

// mountRuleSet is the rule set one recorded mount serves. A FUSE mount
// records its activated rules directly. An FSKit mount is served by
// portablefsd from LITERAL graft roots, which are exactly anchored rules, so
// they are rendered as such — the diagnostic must never answer "shared" for a
// path the macOS daemon is serving from local disk just because that client
// does not speak the pattern language yet. Its revision stays whatever the
// record carries (empty for such a mount), because a revision it never
// reported to the authority is not one to invent here.
func mountRuleSet(st *mountState) (localroutes.RuleSet, error) {
	if len(st.LocalRoutes) > 0 {
		return localroutes.Parse([]byte(strings.Join(st.LocalRoutes, "\n")))
	}
	var text strings.Builder
	for _, dir := range st.LocalDirs {
		pattern, err := localroutes.LiteralPattern(dir)
		if err != nil {
			return localroutes.RuleSet{}, err
		}
		text.WriteString(pattern + "\n")
	}
	return localroutes.Parse([]byte(text.String()))
}

// mountContaining finds the mount that serves target and target's
// volume-relative path within it. The longest mount path wins, so a mount
// nested inside another mount's directory answers for its own subtree.
func mountContaining(states []mountState, target string) (mountState, string, bool) {
	best := -1
	var rel string
	for i, st := range states {
		if target != st.MountPath && !strings.HasPrefix(target, st.MountPath+string(filepath.Separator)) {
			continue
		}
		if best >= 0 && len(st.MountPath) <= len(states[best].MountPath) {
			continue
		}
		best = i
		rel = filepath.ToSlash(strings.TrimPrefix(strings.TrimPrefix(target, st.MountPath), string(filepath.Separator)))
	}
	if best < 0 {
		return mountState{}, "", false
	}
	return states[best], rel, true
}

// pruneRow is one reclaimable backing subtree.
type pruneRow struct {
	VolumeID string `json:"volumeId,omitempty"`
	Storage  string `json:"storageId"`
	Path     string `json:"path"`
	Bytes    int64  `json:"bytes"`
	Files    int    `json:"files"`
	Reason   string `json:"reason"`
	Removed  bool   `json:"removed"`
}

// cmdPruneLocal reclaims machine-local backing that no route can reach.
// Dry-run is the default and deletion needs --delete: this command is the one
// place in PortableFS that deletes user data outright, and it will not do
// that because someone typed a command whose name sounded harmless.
func cmdPruneLocal(e *cmdEnv, args []string) int {
	fs := newFlagSet("prune-local")
	var o commonOpts
	addCommonFlags(fs, &o)
	volume := fs.String("volume", "", "only consider this volume's machine-local backing")
	dryRun := fs.Bool("dry-run", true, "list what would be reclaimed without removing anything (default)")
	del := fs.Bool("delete", false, "actually remove the orphaned backing trees")
	positionals, err := parseArgs(fs, args)
	if err != nil {
		return e.handleParseError("prune-local", err)
	}
	if len(positionals) != 0 {
		return e.usageError("prune-local", fmt.Errorf("expected no positional arguments"))
	}
	// Deletion is opt-in and unambiguous: --delete is the only way to remove
	// anything, and asking for both --dry-run and --delete is a contradiction
	// worth refusing rather than resolving.
	explicitDryRun := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "dry-run" {
			explicitDryRun = true
		}
	})
	if *del && explicitDryRun && *dryRun {
		return e.usageError("prune-local", fmt.Errorf("--delete and --dry-run are mutually exclusive"))
	}
	remove := *del
	dir, err := e.mountStateDir()
	if err != nil {
		return e.fail("prune-local", err)
	}
	rows, err := collectPruneRows(dir, *volume, remove)
	if err != nil {
		return e.fail("prune-local", err)
	}
	if o.jsonOut {
		return e.printJSON(map[string]any{"removed": remove, "orphans": rows})
	}
	if len(rows) == 0 {
		fmt.Fprintf(e.stdout, "no orphaned machine-local backing on this machine\n")
		return 0
	}
	var total int64
	for _, r := range rows {
		verb := "would remove"
		if r.Removed {
			verb = "removed"
		}
		volume := r.VolumeID
		if volume == "" {
			volume = "volume unknown (" + r.Storage + ")"
		}
		fmt.Fprintf(e.stdout, "%-12s %s  %s  %s  [%s]\n", verb, volume, r.Path, humanBytes(r.Bytes), r.Reason)
		total += r.Bytes
	}
	fmt.Fprintf(e.stdout, "%d orphaned tree(s), %s\n", len(rows), humanBytes(total))
	if !remove {
		fmt.Fprintf(e.stdout, "reclaim them with: portablefs prune-local --dry-run=false --delete\n")
	}
	return 0
}

// collectPruneRows is the reclamation decision, kept separate from printing
// so it is testable without a terminal. A backing subtree is orphaned when no
// current mount state and no recorded active route set for its volume routes
// it — those two sources together are "reachable on this machine".
func collectPruneRows(mountsDir, onlyVolume string, remove bool) ([]pruneRow, error) {
	base := localBackingDir(mountsDir)
	entries, err := privatepath.ReadDir(base)
	if os.IsNotExist(err) {
		entries = nil
	}
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	states, err := listMountStates(mountsDir)
	if err != nil {
		return nil, err
	}
	// FSKit owns a separate (volume, branch)-keyed backing area. Its effective
	// routes can change through the daemon control API without rewriting the
	// CLI mount record, so this command never prunes inside a daemon-owned tree.
	// Inventory it before touching FUSE backing: an unidentified hash may be a
	// detached or legacy FSKit tree, and deletion must fail before any partial
	// reclamation rather than guess which volume it belongs to.
	if err := verifyFSKitPruneInventory(mountsDir, states); err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, nil
	}
	// Storage id -> the volume it belongs to and every rule set that can
	// still reach it (live mounts first, then the recorded active set).
	type known struct {
		volumeID string
		patterns []string
	}
	reachable := map[string]*known{}
	note := func(volumeID string, patterns []string) {
		if volumeID == "" || (onlyVolume != "" && volumeID != onlyVolume) {
			return
		}
		id := localdirs.StorageID(volumeID)
		k := reachable[id]
		if k == nil {
			k = &known{volumeID: volumeID}
			reachable[id] = k
		}
		k.patterns = append(k.patterns, patterns...)
	}
	for _, st := range states {
		if st.Strategy == "fuse" && recordedMountVerified(&st) {
			note(st.VolumeID, st.LocalRoutes)
		}
	}
	var rows []pruneRow
	for _, ent := range entries {
		name := ent.Name()
		if !ent.IsDir() {
			continue
		}
		if len(name) != 32 || strings.Trim(name, "0123456789abcdef") != "" {
			continue // not a storage id; leave foreign directories alone
		}
		rec, err := readLocalRoutesRecordByStorage(mountsDir, name)
		if err != nil {
			return nil, err
		}
		if rec != nil {
			note(rec.VolumeID, rec.Patterns)
		}
		k := reachable[name]
		if onlyVolume != "" && (k == nil || k.volumeID != onlyVolume) {
			continue
		}
		var patterns []string
		volumeID := ""
		if k != nil {
			patterns, volumeID = k.patterns, k.volumeID
		}
		rules, err := localroutes.Parse([]byte(strings.Join(patterns, "\n")))
		if err != nil {
			return nil, fmt.Errorf("machine-local routes for volume %s: %w", volumeID, err)
		}
		reason := "no rule routes it any more"
		if rules.Empty() {
			reason = "no mount and no active route set on this machine"
		}
		tree := filepath.Join(base, name)
		orphans, err := localdirs.PruneBacking(tree, rules, remove)
		if err != nil {
			return nil, err
		}
		if remove && rules.Empty() {
			// Nothing on this machine can reach the volume at all, so the now
			// empty tree goes too. The sidecars beside it stay: a persisted
			// --local-dir list is the user's configuration, and reclaiming
			// storage is not a reason to forget it.
			if err := os.Remove(tree); err != nil && !os.IsNotExist(err) {
				return nil, fmt.Errorf("remove emptied backing tree %s: %w", tree, err)
			}
		}
		for _, o := range orphans {
			rows = append(rows, pruneRow{
				VolumeID: volumeID,
				Storage:  name,
				Path:     o.Path,
				Bytes:    o.Bytes,
				Files:    o.Files,
				Reason:   reason,
				Removed:  remove,
			})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Storage != rows[j].Storage {
			return rows[i].Storage < rows[j].Storage
		}
		return rows[i].Path < rows[j].Path
	})
	return rows, nil
}

type fskitBackingIdentity struct {
	volumeID string
	branch   string
}

// verifyFSKitPruneInventory proves that every daemon-owned storage hash is
// attributable to a mount or durable daemon attach. Attributable trees remain
// wholly protected: mount-state LocalDirs can lag a runtime control update,
// so they are not sufficient authority for subtree deletion. An unattributed
// hash makes every prune fail closed: even a volume-scoped command cannot
// prove that the unidentified tree does not belong to the selected volume.
func verifyFSKitPruneInventory(mountsDir string, states []mountState) error {
	base := filepath.Join(portablefsdStateDir(mountsDir), "local")
	entries, err := privatepath.ReadDir(base)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inventory FSKit backing %s: %w", base, err)
	}
	known := map[string]fskitBackingIdentity{}
	note := func(volumeID, branch string) error {
		if volumeID == "" || branch == "" {
			return nil
		}
		identity := fskitBackingIdentity{volumeID: volumeID, branch: branch}
		id := filepath.Base(fskitBackingRoot(mountsDir, volumeID, branch))
		if prior, ok := known[id]; ok && prior != identity {
			return fmt.Errorf("FSKit backing identity collision for %s: %s@%s and %s@%s", id,
				prior.volumeID, prior.branch, volumeID, branch)
		}
		known[id] = identity
		return nil
	}
	for i := range states {
		if states[i].Strategy == "fskit" {
			if err := note(states[i].VolumeID, states[i].Branch); err != nil {
				return err
			}
		}
	}
	attaches, err := portablefsd.ReadPersistedAttachInventory(portablefsdStateDir(mountsDir))
	if err != nil {
		return fmt.Errorf("prove FSKit backing ownership from durable attach inventory: %w", err)
	}
	for _, attach := range attaches {
		if err := note(attach.VolumeID, attach.Branch); err != nil {
			return err
		}
	}
	for _, ent := range entries {
		name := ent.Name()
		if !ent.IsDir() || len(name) != 32 || strings.Trim(name, "0123456789abcdef") != "" {
			continue
		}
		if _, ok := known[name]; ok {
			continue // possibly live; preserve the entire daemon-owned tree
		}
		return fmt.Errorf(
			"refusing to prune: FSKit backing %s has no mount or durable daemon attach that proves its volume and branch; it was left untouched",
			filepath.Join(base, name),
		)
	}
	return nil
}

// readLocalRoutesRecordByStorage reads the active route record that sits
// beside one backing tree, keyed by its storage id.
func readLocalRoutesRecordByStorage(mountsDir, storageID string) (*localRoutesRecord, error) {
	p := filepath.Join(localBackingDir(mountsDir), storageID+".routes.json")
	data, err := privatepath.ReadFile(p)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read local-routes record %s: %w", p, err)
	}
	rec, err := decodeLocalRoutesRecord(data, p)
	if err != nil {
		return nil, err
	}
	if localdirs.StorageID(rec.VolumeID) != storageID {
		return nil, fmt.Errorf("local-routes record %s names volume %q, which is not its storage key", p, rec.VolumeID)
	}
	return rec, nil
}

// localRouteStatusRow is one volume's machine-local routing, as
// `portablefs status` prints it.
type localRouteStatusRow struct {
	// Revision is the volume declaration's revision, the value every mount of
	// the volume must agree on.
	Revision   string           `json:"revision"`
	Patterns   []string         `json:"patterns"`
	PerMachine bool             `json:"perMachineRoutes,omitempty"`
	Backing    string           `json:"backingRoot,omitempty"`
	Roots      []localRouteRoot `json:"roots,omitempty"`
}

type localRouteRoot struct {
	Path    string `json:"path"`
	Backing string `json:"backingPath"`
	Bytes   int64  `json:"bytes"`
	Files   int    `json:"files"`
}

// localRoutesOf reports this machine's active routing for a volume: the
// revision and patterns a live mount activated (or the recorded active set
// when nothing is mounted), plus every route root that actually holds bytes.
func (e *cmdEnv) localRoutesOf(volumeID, branch string) *localRouteStatusRow {
	dir, err := e.mountStateDir()
	if err != nil {
		return nil
	}
	patterns, revision, perMachine := []string(nil), "", false
	backing := ""
	fskitDirs := []string(nil)
	mountAnswered := false
	if states, err := listMountStates(dir); err == nil {
		for i := range states {
			st := &states[i]
			if st.VolumeID != volumeID || st.Branch != branch {
				continue
			}
			if rules, err := mountRuleSet(st); err == nil {
				mountAnswered = true
				if rules.Empty() {
					break
				}
				patterns, revision = rules.Patterns(), st.LocalRouteRevision
				perMachine = st.LocalRoutesPerMachine || (len(st.LocalRoutes) == 0 && len(st.LocalDirs) > 0 && !st.LocalDirsDeclared)
				backing = mountBackingRoot(dir, st)
				if st.Strategy == "fskit" {
					fskitDirs = append([]string(nil), st.LocalDirs...)
				}
				break
			}
		}
	}
	if mountAnswered && len(patterns) == 0 {
		// A current branch mount serving no routes outranks a stale
		// last-activated FUSE sidecar for the same volume.
		return nil
	}
	if len(patterns) == 0 {
		rec, err := readLocalRoutesRecord(dir, volumeID)
		if err != nil || rec == nil {
			return nil
		}
		patterns, revision, perMachine = rec.Patterns, rec.Revision, rec.PerMachine
		backing = localDirsBackingRoot(dir, volumeID)
	}
	if len(patterns) == 0 {
		return nil
	}
	rules, err := localroutes.Parse([]byte(strings.Join(patterns, "\n")))
	if err != nil {
		return nil
	}
	row := &localRouteStatusRow{Revision: revision, Patterns: rules.Patterns(), PerMachine: perMachine, Backing: backing}
	if fskitDirs != nil {
		for _, root := range fskitDirs {
			p := filepath.Join(backing, filepath.FromSlash(root))
			fi, err := os.Lstat(p)
			if err != nil || !fi.IsDir() {
				continue
			}
			bytes, files, err := localdirs.BackingUsage(backing, root)
			if err != nil {
				continue
			}
			row.Roots = append(row.Roots, localRouteRoot{Path: root, Backing: p, Bytes: bytes, Files: files})
		}
		return row
	}
	g, err := localdirs.New(localdirs.Config{BackingRoot: backing, Rules: rules})
	if err != nil || g == nil {
		return row
	}
	defer func() { _ = g.Close() }()
	roots, eno := g.ActiveRootsUnder("")
	if eno != 0 {
		return row
	}
	for _, root := range roots {
		bytes, files, err := localdirs.BackingUsage(backing, root)
		if err != nil {
			continue
		}
		row.Roots = append(row.Roots, localRouteRoot{
			Path:    root,
			Backing: filepath.Join(backing, filepath.FromSlash(root)),
			Bytes:   bytes,
			Files:   files,
		})
	}
	return row
}

// printLocalRoutes renders the machine-local routing lines of
// `portablefs status`.
func (e *cmdEnv) printLocalRoutes(row *localRouteStatusRow) {
	if row == nil {
		return
	}
	fmt.Fprintf(e.stdout, "local routes %s declared in %s: %s\n",
		revisionPrefix(row.Revision), localdirs.VolumeConfigPath, strings.Join(row.Patterns, " "))
	if row.PerMachine {
		fmt.Fprintf(e.stdout, "             (these rules are this machine's --local-dir flags, not the volume's: peers treat these paths as shared)\n")
	}
	if len(row.Roots) == 0 {
		fmt.Fprintf(e.stdout, "             no route root has machine-local content yet (backing %s)\n", row.Backing)
		return
	}
	for _, r := range row.Roots {
		fmt.Fprintf(e.stdout, "             %s  %s  %s\n", r.Path, humanBytes(r.Bytes), r.Backing)
	}
}

// humanBytes renders a byte count for the human-readable route/prune reports.
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
