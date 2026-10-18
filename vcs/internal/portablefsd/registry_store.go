package portablefsd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/steerlabs/portablefs/vcs/internal/mountid"
	"github.com/steerlabs/portablefs/vcs/internal/privatepath"
)

const attachRegistryVersion = 3

func attachRegistryPath(stateDir string) string {
	return filepath.Join(stateDir, "attaches.json")
}

type persistedAttachRegistry struct {
	Version  int                    `json:"version"`
	Attaches []persistedAttachEntry `json:"attaches"`
}

type loadedAttachRegistry struct {
	attaches []persistedAttachEntry
}

type persistedAttachEntry struct {
	Ref      string `json:"ref"`
	VolumeID string `json:"volumeId"`

	MountPath           string `json:"mountPath"`
	AuthorityURL        string `json:"authorityUrl"`
	DataPlaneTransport  string `json:"dataPlaneTransport"`
	DataPlaneServerName string `json:"dataPlaneServerName,omitempty"`
	TLSCAPEM            string `json:"tlsCaPem,omitempty"`
	TLSCASHA256         string `json:"tlsCaSha256,omitempty"`

	IdentityEpoch uint64 `json:"identityEpoch,omitempty"`

	// V3 marks an authority-v3 attach. It carries only the credential-free
	// declared contract (see v3attach.go): the strict session dies with the
	// daemon process, so a revived v3 entry supports exactly one operation —
	// the exact unmount — and is never reactivated from disk.
	V3 *persistedV3Attach `json:"v3,omitempty"`
}

type PersistedAttachIdentity struct {
	AttachRef string
	VolumeID  string

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
			MountPath: entry.MountPath,
		})
	}
	return out, nil
}

func loadPersistedAttaches(stateDir string) ([]persistedAttachEntry, error) {
	loaded, err := loadAttachRegistry(stateDir)
	if err != nil {
		return nil, err
	}
	return loaded.attaches, nil
}

func loadAttachRegistry(stateDir string) (loadedAttachRegistry, error) {
	p := attachRegistryPath(stateDir)
	data, err := privatepath.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return loadedAttachRegistry{}, nil
		}
		return loadedAttachRegistry{}, fmt.Errorf("read attach registry %s: %w", p, err)
	}
	if err := rejectDuplicateRegistryFields(data); err != nil {
		return loadedAttachRegistry{}, fmt.Errorf("parse attach registry %s: %w", p, err)
	}
	var raw persistedAttachRegistry
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return loadedAttachRegistry{}, fmt.Errorf("parse attach registry %s: %w", p, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil || err != io.EOF {
		return loadedAttachRegistry{}, fmt.Errorf("parse attach registry %s: trailing JSON", p)
	}
	if raw.Version != attachRegistryVersion || raw.Attaches == nil {
		return loadedAttachRegistry{}, fmt.Errorf("attach registry %s has invalid version or inventory", p)
	}
	seenRef := map[string]struct{}{}
	seenKey := map[string]struct{}{}
	seenStorage := map[string]struct{}{}
	for i := range raw.Attaches {
		e := &raw.Attaches[i]
		if err := validatePersistedAttach(e); err != nil {
			return loadedAttachRegistry{}, fmt.Errorf("invalid attach registry entry %d in %s: %w", i, p, err)
		}
		if _, duplicate := seenRef[e.Ref]; duplicate {
			return loadedAttachRegistry{}, fmt.Errorf("duplicate attach ref %s in %s", e.Ref, p)
		}
		key := attachKey(e.VolumeID, e.MountPath)
		if _, duplicate := seenKey[key]; duplicate {
			return loadedAttachRegistry{}, fmt.Errorf("duplicate attach key for %s in %s", e.MountPath, p)
		}
		storage := e.VolumeID
		if _, duplicate := seenStorage[storage]; duplicate {
			return loadedAttachRegistry{}, fmt.Errorf("multiple persisted attaches own %s@%s in %s", e.VolumeID, "", p)
		}
		seenRef[e.Ref], seenKey[key], seenStorage[storage] = struct{}{}, struct{}{}, struct{}{}
	}
	return loadedAttachRegistry{attaches: raw.Attaches}, nil
}

func rejectDuplicateRegistryFields(data []byte) error {
	if !utf8.Valid(data) {
		return errors.New("registry is not UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('{') {
		return fmt.Errorf("top-level value must be an object")
	}
	return rejectDuplicateObjectFields(decoder, "$")
}

func rejectDuplicateObjectFields(decoder *json.Decoder, objectPath string) error {
	seen := map[string]struct{}{}
	for decoder.More() {
		nameToken, err := decoder.Token()
		if err != nil {
			return err
		}
		name, ok := nameToken.(string)
		if !ok {
			return fmt.Errorf("object member name is not a string")
		}
		if !registryFieldAllowed(objectPath, name) {
			return fmt.Errorf("unknown registry field %q in %s", name, objectPath)
		}
		if _, duplicate := seen[name]; duplicate {
			return fmt.Errorf("duplicate field %q in %s", name, objectPath)
		}
		seen[name] = struct{}{}
		if err := rejectDuplicateValueFields(decoder, objectPath+"."+name); err != nil {
			return err
		}
	}
	closeToken, err := decoder.Token()
	if err != nil || closeToken != json.Delim('}') {
		return fmt.Errorf("invalid object close: %v", err)
	}
	return nil
}

func rejectDuplicateValueFields(decoder *json.Decoder, valuePath string) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return fmt.Errorf("null registry field at %s", valuePath)
	}
	delim, isContainer := token.(json.Delim)
	if !isContainer {
		return nil
	}
	switch delim {
	case '{':
		return rejectDuplicateObjectFields(decoder, valuePath)
	case '[':
		index := 0
		for decoder.More() {
			if err := rejectDuplicateValueFields(decoder, fmt.Sprintf("%s[%d]", valuePath, index)); err != nil {
				return err
			}
			index++
		}
		closeToken, err := decoder.Token()
		if err != nil || closeToken != json.Delim(']') {
			return fmt.Errorf("invalid array close in %s: %v", valuePath, err)
		}
		return nil
	default:
		return fmt.Errorf("unexpected container delimiter %q in %s", delim, valuePath)
	}
}

func validatePersistedAttach(e *persistedAttachEntry) error {
	if !mountid.ValidAttachRef(e.Ref) {
		return fmt.Errorf("invalid ref %q", e.Ref)
	}
	if strings.TrimSpace(e.VolumeID) == "" || strings.TrimSpace(e.VolumeID) != e.VolumeID {
		return fmt.Errorf("volumeId is empty or has surrounding whitespace")
	}
	if e.V3 == nil {
		return errors.New("missing v3 attach contract")
	}
	if err := validPersistedV3Attach(e.V3); err != nil {
		return err
	}
	if e.DataPlaneTransport != "tls-private-ca" && e.DataPlaneTransport != "tls-system-pki" {
		return errors.New("attach requires mutually authenticated TLS")
	}
	if !filepath.IsAbs(e.MountPath) || filepath.Clean(e.MountPath) != e.MountPath {
		return fmt.Errorf("mountPath %q is not canonical and absolute", e.MountPath)
	}
	if strings.TrimSpace(e.AuthorityURL) == "" || strings.TrimSpace(e.AuthorityURL) != e.AuthorityURL {
		return fmt.Errorf("authorityUrl is empty or has surrounding whitespace")
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
	return nil
}

func (r *registry) persist() error {
	r.persistMu.Lock()
	defer r.persistMu.Unlock()
	entries := r.persistedEntries()
	if err := writePersistedAttaches(r.stateDir, entries); err != nil {
		return err
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
		key, storage := attachKey(entries[i].VolumeID, entries[i].MountPath), entries[i].VolumeID
		if seenRef[entries[i].Ref] || seenKey[key] || seenStorage[storage] {
			return fmt.Errorf("refuse duplicate persisted attach identity at entry %d", i)
		}
		seenRef[entries[i].Ref], seenKey[key], seenStorage[storage] = true, true, true
	}
	if entries == nil {
		entries = []persistedAttachEntry{}
	}
	reg := persistedAttachRegistry{Version: attachRegistryVersion, Attaches: entries}
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return privatepath.WriteFileAtomic(attachRegistryPath(stateDir), data)
}

func registryFieldAllowed(path, name string) bool {
	if path == "$" {
		return name == "version" || name == "attaches"
	}
	if strings.HasSuffix(path, ".v3") {
		return name == "routesRevision"
	}
	switch name {
	case "ref", "volumeId", "mountPath", "authorityUrl", "dataPlaneTransport", "dataPlaneServerName", "tlsCaPem", "tlsCaSha256", "identityEpoch", "v3":
		return true
	}
	return false
}
