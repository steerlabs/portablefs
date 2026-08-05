package localdirs

import (
	"errors"
	"fmt"
	"io/fs"
	"sort"

	"github.com/steerlabs/portablefs/vcs/internal/confinedfs"
	"github.com/steerlabs/portablefs/vcs/internal/localroutes"
)

// Orphan is one backing subtree that no current rule routes: storage that can
// never be reached through any mount of the volume again.
type Orphan struct {
	// Path is volume-relative, the same name a route root would have.
	Path  string
	Bytes int64
	Files int
	// Dir is false for a stray non-directory left in the scaffold, which is
	// never part of any route.
	Dir bool
}

// BackingUsage measures one backing subtree. It resolves every step through
// the backing capability rather than joining host paths, so a symlink planted
// in the backing can neither redirect the walk nor inflate the answer.
func BackingUsage(backingRoot, rel string) (bytes int64, files int, err error) {
	root, err := openExistingBacking(backingRoot)
	if err != nil || root == nil {
		return 0, 0, err
	}
	defer func() { _ = root.Close() }()
	return usage(root, rel, 0)
}

// PruneBacking finds — and, when remove is set, deletes — every backing
// subtree under one volume's backing tree that rules no longer route. It is
// the reclamation half of the (volume, route root) identity: a route removed
// from the declaration leaves its bytes behind on purpose (removing a rule
// must never delete data as a side effect), and this is the explicit,
// auditable step that frees them.
//
// An empty rule set makes every top-level subtree an orphan, which is exactly
// the right answer for a volume that has no route record at all.
func PruneBacking(backingRoot string, rules localroutes.RuleSet, remove bool) ([]Orphan, error) {
	root, err := openExistingBacking(backingRoot)
	if err != nil || root == nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	_, orphans, err := scanOrphans(root, rules, "", 0)
	if err != nil {
		return nil, err
	}
	sort.Slice(orphans, func(i, j int) bool { return orphans[i].Path < orphans[j].Path })
	if !remove {
		return orphans, nil
	}
	for _, o := range orphans {
		if err := removeAll(root, o.Path); err != nil {
			return orphans, fmt.Errorf("remove orphaned backing %q: %w", o.Path, err)
		}
	}
	return orphans, nil
}

// openExistingBacking opens the backing capability without creating it: an
// inspection must never bring into existence the thing it is inspecting.
func openExistingBacking(backingRoot string) (*confinedfs.Root, error) {
	if backingRoot == "" {
		return nil, errors.New("localdirs: backing root is required")
	}
	root, err := confinedfs.OpenExisting(backingRoot)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return root, err
}

// scanOrphans reports whether rel holds any live route root, plus the topmost
// orphaned subtrees beneath it. Reporting the topmost one is deliberate: an
// operator wants "agent-app/node_modules, 412 MiB", not every file in it.
func scanOrphans(root *confinedfs.Root, rules localroutes.RuleSet, rel string, depth int) (live bool, orphans []Orphan, err error) {
	if depth > maxScaffoldDepth {
		return true, nil, nil // refuse to reclaim what we did not fully walk
	}
	if rel != "" {
		if _, ok := rules.Match(rel); ok {
			// A live route root, or something inside one: keep it, and never
			// walk into a dependency tree to decide that.
			return true, nil, nil
		}
	}
	entries, err := root.ReadDir(rel)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil, nil
		}
		return false, nil, err
	}
	for _, e := range entries {
		child := e.Name()
		if rel != "" {
			child = rel + "/" + child
		}
		if !e.IsDir() {
			bytes, files, err := usage(root, child, depth+1)
			if err != nil {
				return false, nil, err
			}
			orphans = append(orphans, Orphan{Path: child, Bytes: bytes, Files: files})
			continue
		}
		childLive, childOrphans, err := scanOrphans(root, rules, child, depth+1)
		if err != nil {
			return false, nil, err
		}
		if childLive {
			live = true
			orphans = append(orphans, childOrphans...)
			continue
		}
		bytes, files, err := usage(root, child, depth+1)
		if err != nil {
			return false, nil, err
		}
		orphans = append(orphans, Orphan{Path: child, Bytes: bytes, Files: files, Dir: true})
	}
	if !live && rel != "" {
		// Nothing live below: the caller reports this whole subtree instead
		// of the pieces we just collected.
		return false, nil, nil
	}
	return live || rel == "", orphans, nil
}

// usage sums the apparent size of a backing subtree.
func usage(root *confinedfs.Root, rel string, depth int) (bytes int64, files int, err error) {
	if depth > 128 {
		return 0, 0, nil
	}
	fi, err := root.Lstat(rel)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, 0, nil
		}
		return 0, 0, err
	}
	if !fi.IsDir() {
		return fi.Size(), 1, nil
	}
	entries, err := root.ReadDir(rel)
	if err != nil {
		return 0, 0, err
	}
	for _, e := range entries {
		child := e.Name()
		if rel != "" {
			child = rel + "/" + child
		}
		b, f, err := usage(root, child, depth+1)
		if err != nil {
			return 0, 0, err
		}
		bytes += b
		files += f
	}
	return bytes, files, nil
}

// removeAll deletes a backing subtree through the capability, depth first.
// Every step is capability-relative, so a symlink inside the tree is unlinked
// as a symlink and can never redirect the deletion out of the backing root.
func removeAll(root *confinedfs.Root, rel string) error {
	fi, err := root.Lstat(rel)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	if fi.IsDir() {
		entries, err := root.ReadDir(rel)
		if err != nil {
			return err
		}
		for _, e := range entries {
			child := e.Name()
			if rel != "" {
				child = rel + "/" + child
			}
			if err := removeAll(root, child); err != nil {
				return err
			}
		}
	}
	return root.Remove(rel)
}
