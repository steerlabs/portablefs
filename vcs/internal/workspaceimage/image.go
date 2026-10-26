// Package workspaceimage verifies the sealed protocol-8 guest without booting it.
package workspaceimage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"

	"github.com/steerlabs/portablefs/vcs/internal/hostctl"
)

type Record struct {
	SHA256 string `json:"sha256"`
	Size   uint64 `json:"size"`
}
type Release struct {
	Version string `json:"app_version"`
	Commit  string `json:"commit"`
	Digest  string `json:"image_digest"`
	Major   uint32 `json:"authority_major"`
}
type Manifest struct {
	Format  int               `json:"format"`
	Release Release           `json:"release"`
	Files   map[string]Record `json:"files"`
}

var required = []string{"kernel", "initramfs", "system.ext4", "kernel.config", "packages.json", "packages.tsv", "source-manifest.json", "licenses.tar.gz", "initramfs.inventory", "image-inputs.json", "release.json", "bin/portablefs", "bin/portablefsd", "bin/portablefs-workspaced"}
var sha = regexp.MustCompile(`^[a-f0-9]{64}$`)
var commitPattern = regexp.MustCompile(`^[a-f0-9]{40}$`)

// Verify returns the conservative expanded byte count. The caller authenticates
// the enclosing code signature before trusting the plist's manifest pin.
func Verify(directory, manifestSHA, commit, version string) (uint64, error) {
	fail := func(err error) (uint64, error) { return 0, fmt.Errorf("Workspace image failed verification: %w", err) }
	if !sha.MatchString(manifestSHA) || !commitPattern.MatchString(commit) {
		return fail(fmt.Errorf("invalid sealed identity"))
	}
	raw, err := os.ReadFile(filepath.Join(directory, "manifest.json"))
	if err != nil {
		return fail(err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != manifestSHA {
		return fail(fmt.Errorf("manifest digest mismatch"))
	}
	manifest, err := hostctl.DecodeExact[Manifest](raw)
	if err != nil {
		return fail(err)
	}
	if manifest.Format != 8 || manifest.Release.Major != 8 || manifest.Release.Commit != commit || manifest.Release.Version != version || !sha.MatchString(manifest.Release.Digest) || len(manifest.Files) != len(required) {
		return fail(fmt.Errorf("release identity mismatch"))
	}
	total := uint64(len(raw))
	for _, name := range required {
		r, ok := manifest.Files[name]
		if !ok || !sha.MatchString(r.SHA256) {
			return fail(fmt.Errorf("missing artifact %s", name))
		}
		path := filepath.Join(directory, filepath.FromSlash(name))
		info, err := os.Lstat(path)
		if err != nil {
			return fail(err)
		}
		if !info.Mode().IsRegular() || info.Size() < 0 || uint64(info.Size()) != r.Size {
			return fail(fmt.Errorf("invalid artifact %s", name))
		}
		file, err := os.Open(path)
		if err != nil {
			return fail(err)
		}
		h := sha256.New()
		_, err = io.Copy(h, file)
		closeErr := file.Close()
		if err != nil {
			return fail(err)
		}
		if closeErr != nil {
			return fail(closeErr)
		}
		if hex.EncodeToString(h.Sum(nil)) != r.SHA256 {
			return fail(fmt.Errorf("artifact digest mismatch: %s", name))
		}
		if ^uint64(0)-total < r.Size {
			return fail(fmt.Errorf("image size overflow"))
		}
		total += r.Size
	}
	err = filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == directory {
			return nil
		}
		name, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		if entry.IsDir() && name == "bin" {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("unexpected image entry %s", name)
		}
		if name != "manifest.json" {
			if _, ok := manifest.Files[filepath.ToSlash(name)]; !ok {
				return fmt.Errorf("unexpected image file %s", name)
			}
		}
		return nil
	})
	if err != nil {
		return fail(err)
	}
	embeddedRaw, err := os.ReadFile(filepath.Join(directory, "release.json"))
	if err != nil {
		return fail(err)
	}
	embedded, err := hostctl.DecodeExact[Release](embeddedRaw)
	if err != nil || !reflect.DeepEqual(embedded, manifest.Release) {
		return fail(fmt.Errorf("embedded release mismatch"))
	}
	if manifest.Files["image-inputs.json"].SHA256 != manifest.Release.Digest {
		return fail(fmt.Errorf("image input digest mismatch"))
	}
	sourceRaw, err := os.ReadFile(filepath.Join(directory, "source-manifest.json"))
	if err != nil {
		return fail(err)
	}
	var source struct {
		Format  int    `json:"format"`
		Commit  string `json:"commit"`
		Archive Record `json:"archive"`
	}
	if err = json.Unmarshal(sourceRaw, &source); err != nil || source.Format != 8 || source.Commit != commit || !sha.MatchString(source.Archive.SHA256) || source.Archive.Size == 0 {
		return fail(fmt.Errorf("source archive identity mismatch"))
	}
	return total, nil
}
