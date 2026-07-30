package portablefsd

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/steerlabs/portablefs/vcs/internal/mountid"
	"github.com/steerlabs/portablefs/vcs/internal/privatepath"
)

const attachRegistryVersion = 2

func attachRegistryPath(stateDir string) string {
	return filepath.Join(stateDir, "attaches.json")
}

type persistedAttachRegistry struct {
	Version  int                    `json:"version"`
	Attaches []persistedAttachEntry `json:"attaches"`
}

type persistedAttachEntry struct {
	Ref                 string                `json:"ref"`
	VolumeID            string                `json:"volumeId"`
	Branch              string                `json:"branch"`
	MountPath           string                `json:"mountPath"`
	AuthorityURL        string                `json:"authorityUrl"`
	DataPlaneTransport  string                `json:"dataPlaneTransport"`
	DataPlaneServerName string                `json:"dataPlaneServerName,omitempty"`
	TLSCAPEM            string                `json:"tlsCaPem,omitempty"`
	TLSCASHA256         string                `json:"tlsCaSha256,omitempty"`
	Options             AttachOptions         `json:"options"`
	IdentityEpoch       uint64                `json:"identityEpoch,omitempty"`
	DetachPrepared      bool                  `json:"detachPrepared,omitempty"`
	DetachForce         bool                  `json:"detachForce,omitempty"`
	DetachJobID         string                `json:"detachJobId,omitempty"`
	Items               []persistedItemRecord `json:"items,omitempty"`
}

type persistedItemRecord struct {
	Path            string `json:"path"`
	ItemID          uint64 `json:"itemId"`
	ItemGeneration  uint64 `json:"itemGeneration"`
	AuthorityIno    bool   `json:"authorityIno,omitempty"`
	AuthorityItemID uint64 `json:"authorityItemId,omitempty"`
	Kind            string `json:"kind,omitempty"`
	Graft           bool   `json:"graft,omitempty"`
	// Detached records preserve an FSKit Item↔authority identity after its
	// last locally known name is removed. FSKit stays mounted across a daemon
	// restart, so only explicit Reclaim—not process lifetime—retires it.
	Detached bool `json:"detached,omitempty"`
}

type PersistedAttachIdentity struct {
	AttachRef string
	VolumeID  string
	Branch    string
	MountPath string
}

// ReadPersistedAttachInventory is the strict read-only inventory boundary
// used by installers and account mutation even when no daemon/socket exists.
func ReadPersistedAttachInventory(stateDir string) ([]PersistedAttachIdentity, error) {
	entries, err := loadPersistedAttaches(stateDir)
	if err != nil {
		return nil, err
	}
	out := make([]PersistedAttachIdentity, 0, len(entries))
	for _, entry := range entries {
		out = append(out, PersistedAttachIdentity{
			AttachRef: entry.Ref,
			VolumeID:  entry.VolumeID,
			Branch:    entry.Branch,
			MountPath: entry.MountPath,
		})
	}
	return out, nil
}

func (i persistedItemRecord) authorityItemID() uint64 {
	if i.AuthorityItemID != 0 {
		return i.AuthorityItemID
	}
	if i.AuthorityIno {
		return i.ItemID
	}
	return 0
}

func loadPersistedAttaches(stateDir string) ([]persistedAttachEntry, error) {
	p := attachRegistryPath(stateDir)
	data, err := privatepath.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read attach registry %s: %w", p, err)
	}
	var raw persistedAttachRegistry
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return nil, fmt.Errorf("parse attach registry %s: %w", p, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil || err != io.EOF {
		return nil, fmt.Errorf("parse attach registry %s: trailing JSON", p)
	}
	if raw.Version != attachRegistryVersion {
		return nil, fmt.Errorf("attach registry %s has unsupported version %d", p, raw.Version)
	}
	seenRef := map[string]struct{}{}
	seenKey := map[string]struct{}{}
	seenStorage := map[string]struct{}{}
	for i := range raw.Attaches {
		e := &raw.Attaches[i]
		if err := validatePersistedAttach(e); err != nil {
			return nil, fmt.Errorf("invalid attach registry entry %d in %s: %w", i, p, err)
		}
		if _, duplicate := seenRef[e.Ref]; duplicate {
			return nil, fmt.Errorf("duplicate attach ref %s in %s", e.Ref, p)
		}
		key := attachKey(e.VolumeID, e.Branch, e.MountPath)
		if _, duplicate := seenKey[key]; duplicate {
			return nil, fmt.Errorf("duplicate attach key for %s in %s", e.MountPath, p)
		}
		storage := storageKey(e.VolumeID, e.Branch)
		if _, duplicate := seenStorage[storage]; duplicate {
			return nil, fmt.Errorf("multiple persisted attaches own %s@%s in %s", e.VolumeID, e.Branch, p)
		}
		if err := validatePersistedItems(*e); err != nil {
			return nil, fmt.Errorf("attach registry entry %d in %s: %w", i, p, err)
		}
		seenRef[e.Ref], seenKey[key], seenStorage[storage] = struct{}{}, struct{}{}, struct{}{}
	}
	return raw.Attaches, nil
}

func validatePersistedAttach(e *persistedAttachEntry) error {
	if !mountid.ValidAttachRef(e.Ref) {
		return fmt.Errorf("invalid ref %q", e.Ref)
	}
	if strings.TrimSpace(e.VolumeID) == "" || strings.TrimSpace(e.VolumeID) != e.VolumeID {
		return fmt.Errorf("volumeId is empty or has surrounding whitespace")
	}
	if strings.TrimSpace(e.Branch) == "" || strings.TrimSpace(e.Branch) != e.Branch {
		return fmt.Errorf("branch is empty or has surrounding whitespace")
	}
	if !filepath.IsAbs(e.MountPath) || filepath.Clean(e.MountPath) != e.MountPath {
		return fmt.Errorf("mountPath %q is not canonical and absolute", e.MountPath)
	}
	if strings.TrimSpace(e.AuthorityURL) == "" || strings.TrimSpace(e.AuthorityURL) != e.AuthorityURL {
		return fmt.Errorf("authorityUrl is empty or has surrounding whitespace")
	}
	if e.Options.DiskCacheMB < 0 {
		return fmt.Errorf("negative diskCacheMb")
	}
	normalizedLocalDirs, err := normalizeLocalDirs(e.Options.LocalDirs)
	if err != nil {
		return fmt.Errorf("invalid persisted localDirs: %w", err)
	}
	if len(normalizedLocalDirs) != len(e.Options.LocalDirs) {
		return fmt.Errorf("persisted localDirs are not canonical")
	}
	for i := range normalizedLocalDirs {
		if normalizedLocalDirs[i] != e.Options.LocalDirs[i] {
			return fmt.Errorf("persisted localDirs are not canonical")
		}
	}
	if err := (dataPlaneTransport{
		mode:       e.DataPlaneTransport,
		serverName: e.DataPlaneServerName,
		caPEM:      e.TLSCAPEM,
		caSHA256:   e.TLSCASHA256,
	}).validate(); err != nil {
		return fmt.Errorf("invalid data-plane transport: %w", err)
	}
	if e.IdentityEpoch == 0 {
		return fmt.Errorf("missing identityEpoch")
	}
	if e.DetachJobID != "" && !e.DetachForce {
		return fmt.Errorf("detachJobId requires durable force authorization")
	}
	if e.DetachJobID != "" {
		if len(e.DetachJobID) != 35 || !strings.HasPrefix(e.DetachJobID, "job") ||
			e.DetachJobID != strings.ToLower(e.DetachJobID) {
			return fmt.Errorf("detachJobId has invalid recovery-job identity")
		}
		if _, err := hex.DecodeString(e.DetachJobID[3:]); err != nil {
			return fmt.Errorf("detachJobId has invalid recovery-job identity")
		}
	}
	return nil
}

func validatePersistedItems(e persistedAttachEntry) error {
	seenIDAuth := map[uint64]uint64{}
	seenPath := map[string]struct{}{}
	seenDetachedID := map[uint64]struct{}{}
	for i, item := range e.Items {
		if _, ok := fskitItemID(item.ItemID); !ok {
			return fmt.Errorf("item %d has unrepresentable itemId %d", i, item.ItemID)
		}
		if item.ItemGeneration == 0 {
			return fmt.Errorf("item %d has no itemGeneration", i)
		}
		if item.ItemGeneration != e.IdentityEpoch {
			return fmt.Errorf("item %d generation %d does not equal identityEpoch %d", i, item.ItemGeneration, e.IdentityEpoch)
		}
		cleanPath := strings.Trim(path.Clean("/"+item.Path), "/")
		if cleanPath == "." {
			cleanPath = ""
		}
		if cleanPath != item.Path {
			return fmt.Errorf("item %d path %q is not canonical", i, item.Path)
		}
		if item.Detached {
			if item.Path == "" {
				return fmt.Errorf("item %d detaches the root item", i)
			}
			if _, dup := seenDetachedID[item.ItemID]; dup {
				return fmt.Errorf("item %d duplicates detached item id %d", i, item.ItemID)
			}
			seenDetachedID[item.ItemID] = struct{}{}
		} else {
			if _, dup := seenPath[cleanPath]; dup {
				return fmt.Errorf("item %d duplicates path %q", i, cleanPath)
			}
			seenPath[cleanPath] = struct{}{}
		}
		switch item.Kind {
		case "", "file", "directory", "symlink":
		default:
			return fmt.Errorf("item %d has invalid kind %q", i, item.Kind)
		}
		authorityItemID := item.authorityItemID()
		if authorityItemID != 0 {
			if _, ok := fskitItemID(authorityItemID); !ok {
				return fmt.Errorf("item %d has unrepresentable authority item id %d", i, authorityItemID)
			}
		}
		if auth, dup := seenIDAuth[item.ItemID]; dup && auth != authorityItemID {
			return fmt.Errorf("item %d id %d conflicts with authority identity", i, item.ItemID)
		}
		expectedAuthorityIno := authorityItemID != 0
		expectedAuthorityItemID := authorityItemID
		if authorityItemID == item.ItemID {
			expectedAuthorityItemID = 0
		}
		if item.AuthorityIno != expectedAuthorityIno || item.AuthorityItemID != expectedAuthorityItemID {
			return fmt.Errorf("item %d authority identity fields are not canonical", i)
		}
		seenIDAuth[item.ItemID] = authorityItemID
	}
	return nil
}

func (r *registry) persist() error {
	r.persistMu.Lock()
	defer r.persistMu.Unlock()
	// Hold the journal closed across snapshot+write+truncate: an append racing
	// the snapshot could otherwise be truncated away while its binding change
	// missed the snapshot — a lost delta. Appenders never hold attach locks
	// while appending, so blocking them here cannot deadlock.
	if r.journal != nil {
		r.journal.mu.Lock()
		defer r.journal.mu.Unlock()
	}
	entries := r.persistedEntries()
	if err := writePersistedAttaches(r.stateDir, entries); err != nil {
		return err
	}
	if r.journal != nil {
		r.journal.truncateLocked()
	}
	return nil
}

func (r *registry) persistedEntries() []persistedAttachEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entries := make([]persistedAttachEntry, 0, len(r.byRef))
	for _, a := range r.byRef {
		entries = append(entries, a.persistedEntry())
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Ref < entries[j].Ref })
	return entries
}

func writePersistedAttaches(stateDir string, entries []persistedAttachEntry) error {
	seenRef, seenKey, seenStorage := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i := range entries {
		if err := validatePersistedAttach(&entries[i]); err != nil {
			return fmt.Errorf("refuse invalid persisted attach %d: %w", i, err)
		}
		if err := validatePersistedItems(entries[i]); err != nil {
			return fmt.Errorf("refuse invalid persisted attach items %d: %w", i, err)
		}
		key, storage := attachKey(entries[i].VolumeID, entries[i].Branch, entries[i].MountPath), storageKey(entries[i].VolumeID, entries[i].Branch)
		if seenRef[entries[i].Ref] || seenKey[key] || seenStorage[storage] {
			return fmt.Errorf("refuse duplicate persisted attach identity at entry %d", i)
		}
		seenRef[entries[i].Ref], seenKey[key], seenStorage[storage] = true, true, true
	}
	reg := persistedAttachRegistry{Version: attachRegistryVersion, Attaches: entries}
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return privatepath.WriteFileAtomic(attachRegistryPath(stateDir), data)
}
