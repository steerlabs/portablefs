package portablefsd

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

const attachRegistryVersion = 1

func attachRegistryPath(stateDir string) string {
	return filepath.Join(stateDir, "attaches.json")
}

type persistedAttachRegistry struct {
	Version  int                    `json:"version"`
	Attaches []persistedAttachEntry `json:"attaches"`
}

type persistedAttachEntry struct {
	Ref           string                `json:"ref"`
	VolumeID      string                `json:"volumeId"`
	Branch        string                `json:"branch"`
	MountPath     string                `json:"mountPath"`
	AuthorityURL  string                `json:"authorityUrl"`
	TLSCAPEM      string                `json:"tlsCaPem,omitempty"`
	Options       AttachOptions         `json:"options"`
	IdentityEpoch uint64                `json:"identityEpoch,omitempty"`
	Items         []persistedItemRecord `json:"items,omitempty"`
}

type persistedItemRecord struct {
	Path           string `json:"path"`
	ItemID         uint64 `json:"itemId"`
	ItemGeneration uint64 `json:"itemGeneration"`
	AuthorityIno   bool   `json:"authorityIno,omitempty"`
}

func loadPersistedAttaches(stateDir string) []persistedAttachEntry {
	p := attachRegistryPath(stateDir)
	data, err := os.ReadFile(p)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("portablefsd: read attach registry %s: %v", p, err)
		}
		return nil
	}
	var raw struct {
		Version  int               `json:"version"`
		Attaches []json.RawMessage `json:"attaches"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		log.Printf("portablefsd: ignoring corrupt attach registry %s: %v", p, err)
		return nil
	}
	if raw.Version != attachRegistryVersion {
		log.Printf("portablefsd: ignoring attach registry %s with unsupported version %d", p, raw.Version)
		return nil
	}
	out := make([]persistedAttachEntry, 0, len(raw.Attaches))
	for i, msg := range raw.Attaches {
		var e persistedAttachEntry
		if err := json.Unmarshal(msg, &e); err != nil {
			log.Printf("portablefsd: skipping corrupt attach registry entry %d in %s: %v", i, p, err)
			continue
		}
		if err := validatePersistedAttach(e); err != nil {
			log.Printf("portablefsd: skipping corrupt attach registry entry %d in %s: %v", i, p, err)
			continue
		}
		if e.IdentityEpoch == 0 {
			e.IdentityEpoch = 1
		}
		e.Items = sanitizePersistedItems(e, i, p)
		out = append(out, e)
	}
	return out
}

func validatePersistedAttach(e persistedAttachEntry) error {
	if strings.TrimSpace(e.Ref) == "" || strings.ContainsAny(e.Ref, `/\`) {
		return fmt.Errorf("invalid ref %q", e.Ref)
	}
	if strings.TrimSpace(e.VolumeID) == "" {
		return fmt.Errorf("missing volumeId")
	}
	if strings.TrimSpace(e.Branch) == "" {
		return fmt.Errorf("missing branch")
	}
	if strings.TrimSpace(e.MountPath) == "" {
		return fmt.Errorf("missing mountPath")
	}
	if strings.TrimSpace(e.AuthorityURL) == "" {
		return fmt.Errorf("missing authorityUrl")
	}
	if e.Options.DiskCacheMB < 0 {
		return fmt.Errorf("negative diskCacheMb")
	}
	if _, err := tlsConfigFromPEM(e.TLSCAPEM); err != nil {
		return err
	}
	return nil
}

func sanitizePersistedItems(e persistedAttachEntry, attachIndex int, registryPath string) []persistedItemRecord {
	out := make([]persistedItemRecord, 0, len(e.Items))
	seenIDAuth := map[uint64]bool{}
	seenPath := map[string]struct{}{}
	for i, item := range e.Items {
		if item.ItemID == 0 {
			log.Printf("portablefsd: skipping corrupt item entry %d for attach entry %d in %s: missing itemId", i, attachIndex, registryPath)
			continue
		}
		if item.ItemGeneration == 0 {
			log.Printf("portablefsd: skipping corrupt item entry %d for attach entry %d in %s: missing itemGeneration", i, attachIndex, registryPath)
			continue
		}
		if item.ItemGeneration != e.IdentityEpoch {
			log.Printf("portablefsd: skipping stale item entry %d for attach entry %d in %s: generation %d != identityEpoch %d", i, attachIndex, registryPath, item.ItemGeneration, e.IdentityEpoch)
			continue
		}
		cleanPath := strings.Trim(path.Clean("/"+item.Path), "/")
		if cleanPath == "." {
			cleanPath = ""
		}
		if _, dup := seenPath[cleanPath]; dup {
			log.Printf("portablefsd: skipping duplicate item path %q for attach entry %d in %s", cleanPath, attachIndex, registryPath)
			continue
		}
		if auth, dup := seenIDAuth[item.ItemID]; dup && auth != item.AuthorityIno {
			log.Printf("portablefsd: skipping item id %d with conflicting authority identity for attach entry %d in %s", item.ItemID, attachIndex, registryPath)
			continue
		}
		item.Path = cleanPath
		seenIDAuth[item.ItemID] = item.AuthorityIno
		seenPath[cleanPath] = struct{}{}
		out = append(out, item)
	}
	return out
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
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	reg := persistedAttachRegistry{Version: attachRegistryVersion, Attaches: entries}
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(stateDir, ".attaches.json.*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, attachRegistryPath(stateDir)); err != nil {
		return err
	}
	cleanup = false
	return nil
}
