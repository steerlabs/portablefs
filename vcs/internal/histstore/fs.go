package histstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// FSStore is the confined local-filesystem failure domain. All traversal
// happens through one os.Root handle (openat-style), so a symlink — even
// one racily created after validation — can never redirect an operation
// outside the configured root. Writes are exclusive temp file → incremental
// hash proof → fsync → atomic rename → parent directory fsync: no byte is
// visible at the final exact key before it is durable and proven.
type FSStore struct {
	domain  string
	prefix  string
	rootDir string
	root    *os.Root
}

// FSConfig configures one filesystem failure domain.
type FSConfig struct {
	// Domain is the operator-declared failure-domain id (required).
	Domain string
	// RootDir is the absolute confinement root (required; must exist).
	RootDir string
	// Prefix is an optional validated key prefix inside the root.
	Prefix string
}

// NewFSStore opens the confinement root.
func NewFSStore(cfg FSConfig) (*FSStore, error) {
	if strings.TrimSpace(cfg.Domain) == "" {
		return nil, errors.New("histstore: filesystem store requires a failure domain id")
	}
	if !path.IsAbs(cfg.RootDir) {
		return nil, fmt.Errorf("histstore: filesystem root %q must be absolute", cfg.RootDir)
	}
	if cfg.Prefix != "" {
		if err := ValidateKey(cfg.Prefix); err != nil {
			return nil, fmt.Errorf("histstore: filesystem prefix: %w", err)
		}
	}
	root, err := os.OpenRoot(cfg.RootDir)
	if err != nil {
		return nil, fmt.Errorf("histstore: open filesystem root: %w", err)
	}
	return &FSStore{
		domain: strings.TrimSpace(cfg.Domain), prefix: cfg.Prefix,
		rootDir: filepath.Clean(cfg.RootDir), root: root,
	}, nil
}

// Close releases the root handle.
func (s *FSStore) Close() error { return s.root.Close() }

// SweepTemps removes crash-orphaned temporary uploads older than minAge.
// WalkDir does not follow symlinks and every removal is repeated through
// the confined root handle. A generous minimum age prevents one worker
// from disturbing another worker's active upload to the same shared store.
func (s *FSStore) SweepTemps(ctx context.Context, minAge time.Duration) (int, error) {
	if minAge < time.Hour {
		return 0, fmt.Errorf("histstore: temp sweep age %v is below 1h", minAge)
	}
	cutoff := time.Now().Add(-minAge)
	removed := 0
	err := fs.WalkDir(os.DirFS(s.rootDir), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() || entry.Type()&fs.ModeSymlink != 0 || !isTempName(entry.Name()) {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || !info.ModTime().Before(cutoff) {
			return nil
		}
		key := filepath.ToSlash(name)
		if err := s.root.Remove(key); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("histstore: remove stale temp %s/%s: %w", s.domain, key, err)
		}
		removed++
		return nil
	})
	return removed, err
}

func isTempName(name string) bool {
	marker := strings.LastIndex(name, ".tmp-")
	if marker < 0 || len(name)-(marker+len(".tmp-")) != 16 {
		return false
	}
	for _, c := range name[marker+len(".tmp-"):] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Domain implements Store.
func (s *FSStore) Domain() string { return s.domain }

// ExactKey implements Store.
func (s *FSStore) ExactKey(id ObjectID) (string, error) {
	key, err := id.Key()
	if err != nil {
		return "", err
	}
	return JoinPrefix(s.prefix, key)
}

// open opens a validated key through the confinement root and proves the
// result is a regular file (a directory, device, or dangling symlink at an
// exact key is corruption, not content).
func (s *FSStore) open(key string) (*os.File, os.FileInfo, error) {
	if err := ValidateKey(key); err != nil {
		return nil, nil, err
	}
	f, err := s.root.Open(key)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, fmt.Errorf("%w: %s/%s", ErrNotFound, s.domain, key)
		}
		return nil, nil, fmt.Errorf("histstore: open %s/%s: %w", s.domain, key, err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("histstore: stat %s/%s: %w", s.domain, key, err)
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, nil, fmt.Errorf("histstore: %s/%s is not a regular file (mode %v)",
			s.domain, key, info.Mode())
	}
	return f, info, nil
}

// Put implements Store.
func (s *FSStore) Put(ctx context.Context, key string, size int64, digestHex string, body io.Reader) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	if size < 0 || !isLowerHex64(digestHex) {
		return fmt.Errorf("%w: put requires a size and a lowercase sha256 digest", ErrInvalidKey)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// Fast path: accept an existing object only after proving BOTH size and
	// digest. A same-size corrupt copy must fall through to atomic replacement
	// so scrub/repair and lost-response retries can actually heal it.
	if existing, err := s.Head(ctx, key); err == nil && existing == size {
		if err := VerifyStream(ctx, s, key, size, digestHex); err == nil {
			// The prior caller may have lost the outcome after rename but
			// before parent fsync. Re-syncing makes replay a durability repair,
			// not merely a content-presence check.
			return s.syncDir(path.Dir(key))
		}
	}

	dir := path.Dir(key)
	if dir != "." {
		if err := s.root.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("histstore: mkdir %s/%s: %w", s.domain, dir, err)
		}
	}

	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return fmt.Errorf("histstore: temp suffix: %w", err)
	}
	tempKey := key + ".tmp-" + hex.EncodeToString(suffix[:])
	temp, err := s.root.OpenFile(tempKey, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("histstore: create temp for %s/%s: %w", s.domain, key, err)
	}
	cleanup := func() {
		temp.Close()
		_ = s.root.Remove(tempKey)
	}

	hasher := sha256.New()
	written := int64(0)
	chunk := make([]byte, 256<<10)
	for {
		if err := ctx.Err(); err != nil {
			cleanup()
			return err
		}
		n, readErr := body.Read(chunk)
		if n > 0 {
			written += int64(n)
			if written > size {
				cleanup()
				return fmt.Errorf("histstore: put %s/%s: body exceeds the declared %d bytes",
					s.domain, key, size)
			}
			hasher.Write(chunk[:n])
			if _, err := temp.Write(chunk[:n]); err != nil {
				cleanup()
				return fmt.Errorf("histstore: write %s/%s: %w", s.domain, key, err)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			cleanup()
			return fmt.Errorf("histstore: put %s/%s: body read: %w", s.domain, key, readErr)
		}
	}
	if written != size {
		cleanup()
		return fmt.Errorf("histstore: put %s/%s: body is %d bytes, declared %d",
			s.domain, key, written, size)
	}
	if got := hex.EncodeToString(hasher.Sum(nil)); got != digestHex {
		cleanup()
		return fmt.Errorf("histstore: put %s/%s: body hash %s does not match declared %s",
			s.domain, key, got, digestHex)
	}
	if err := temp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("histstore: fsync %s/%s: %w", s.domain, key, err)
	}
	if err := temp.Close(); err != nil {
		_ = s.root.Remove(tempKey)
		return fmt.Errorf("histstore: close temp %s/%s: %w", s.domain, key, err)
	}
	if err := s.root.Rename(tempKey, key); err != nil {
		_ = s.root.Remove(tempKey)
		return fmt.Errorf("histstore: publish %s/%s: %w", s.domain, key, err)
	}
	if err := s.syncDir(dir); err != nil {
		return err
	}
	return nil
}

// syncDir makes the rename durable by fsyncing the parent directory.
func (s *FSStore) syncDir(dir string) error {
	if dir == "" {
		dir = "."
	}
	d, err := s.root.Open(dir)
	if err != nil {
		return fmt.Errorf("histstore: open parent %s/%s: %w", s.domain, dir, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("histstore: fsync parent %s/%s: %w", s.domain, dir, err)
	}
	return nil
}

// Get implements Store.
func (s *FSStore) Get(ctx context.Context, key string) (io.ReadCloser, int64, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	f, info, err := s.open(key)
	if err != nil {
		return nil, 0, err
	}
	return f, info.Size(), nil
}

// Head implements Store.
func (s *FSStore) Head(ctx context.Context, key string) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	f, info, err := s.open(key)
	if err != nil {
		return 0, err
	}
	f.Close()
	return info.Size(), nil
}

// Delete implements Store.
func (s *FSStore) Delete(ctx context.Context, key string) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	err := s.root.Remove(key)
	if err == nil {
		return s.syncDir(path.Dir(key))
	}
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return fmt.Errorf("histstore: delete %s/%s: %w", s.domain, key, err)
}
