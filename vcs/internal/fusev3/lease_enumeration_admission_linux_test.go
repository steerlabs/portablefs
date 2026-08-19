//go:build linux

package fusev3

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const (
	treeInstallPackages    = 24
	treeInstallFilesPerPkg = 8
)

func treeInstallPackageName(index int) string { return fmt.Sprintf("pkg-%03d", index) }

func treeInstallFileBytes(pkg, file int) []byte {
	return bytes.Repeat([]byte{byte('a' + pkg%26)}, 64+file)
}

// treeInstallTolerable reports whether an error a concurrent reader saw is one
// the enumeration contract allows a racing reader to see.
//
// ESTALE is the documented answer to resuming an enumeration a peer mutation
// invalidated (docs/portable-coherence.md §5.4; see
// TestPagedReaddirRefusesToPageAcrossARemoteMutation), and ENOENT is the
// ordinary answer to a name that the installer's rename had not published yet
// or that was read between two of its steps. Everything else -- and ENOTCONN
// above all, which is what a revoked mount returns for every subsequent
// syscall -- is a genuine failure.
func treeInstallTolerable(err error) bool {
	return errors.Is(err, syscall.ESTALE) || errors.Is(err, syscall.ENOENT)
}

// TestDependencyTreeInstallRacingEnumeratingReadersKeepsBothMountsServing is
// the enumeration counterpart of
// TestRepeatedOpenForReadRacingAPeerWriteKeepsBothMountsServing, and it exists
// because the two lanes did not answer a declined grant the same way.
//
// A package-manager install publishes each package by building it under a
// staging name and rename(2)-ing that name into the tree. Every one of those
// renames touches the same parent directory, so every one of them recalls
// E(node_modules) from any mount enumerating it. A reader enumerating that
// directory throughout the install therefore has READDIR replies in flight
// across those recalls continuously.
//
// A reply whose enumeration grant the frontend cannot install -- because a
// newer recall already raised the grant floor, because that coordinate's recall
// has begun and not finished, or because the family is at its cache budget --
// is not an authority protocol violation. The authority is explicitly permitted
// to answer a read without cache authority (docs/portable-coherence.md §2.2:
// grants MAY be attached, and a coordinate under recall "serves its bytes and
// mints nothing"), and §5.4 says an enumeration without E-R simply refetches.
// Treating the ungranted reply as a violation revoked the mount instead, and
// every descriptor on it then returned ENOTCONN -- which is exactly what live
// staging qualification hit, in seconds, three runs out of three.
//
// The bound below is on the whole race for the reason the read-lane test gives:
// one slow round is ordinary, the defect is systemic, and the healthy run is
// two orders of magnitude under it.
func TestDependencyTreeInstallRacingEnumeratingReadersKeepsBothMountsServing(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
	installRoot := f.join(0, "tree")
	readRoot := f.join(1, "tree")
	mustMkdir(t, installRoot)
	modulesInstall := filepath.Join(installRoot, "node_modules")
	modulesRead := filepath.Join(readRoot, "node_modules")
	mustMkdir(t, modulesInstall)

	var failure atomic.Pointer[error]
	record := func(err error) { failure.CompareAndSwap(nil, &err) }
	var enumerations, entriesSeen atomic.Int64

	stop := make(chan struct{})
	var readers sync.WaitGroup
	// Four readers, the staging shape's count. They enumerate the directory the
	// installer is publishing into and then descend into whatever they found,
	// so both the mutating directory and its freshly renamed children are being
	// enumerated while the next rename recalls them.
	for reader := range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				packages, err := os.ReadDir(modulesRead)
				if err != nil {
					if !treeInstallTolerable(err) {
						record(fmt.Errorf("reader %d: enumerate %s: %w", reader, modulesRead, err))
						return
					}
					continue
				}
				enumerations.Add(1)
				for _, pkg := range packages {
					files, err := os.ReadDir(filepath.Join(modulesRead, pkg.Name()))
					if err != nil {
						if !treeInstallTolerable(err) {
							record(fmt.Errorf("reader %d: enumerate %s: %w", reader, pkg.Name(), err))
							return
						}
						continue
					}
					entriesSeen.Add(int64(len(files)))
					// A published package is immutable: the installer never
					// touches a name after the rename that created it. Any byte
					// a reader gets from one is therefore exactly assertable,
					// which is what turns "the mount stayed up" into "the mount
					// stayed up and stayed right".
					for _, file := range files {
						var pkgIndex, fileIndex int
						if _, scanErr := fmt.Sscanf(pkg.Name(), "pkg-%03d", &pkgIndex); scanErr != nil {
							record(fmt.Errorf("reader %d: unexpected package name %q", reader, pkg.Name()))
							return
						}
						if _, scanErr := fmt.Sscanf(file.Name(), "file-%d.txt", &fileIndex); scanErr != nil {
							record(fmt.Errorf("reader %d: unexpected file name %q in %s", reader, file.Name(), pkg.Name()))
							return
						}
						got, err := os.ReadFile(filepath.Join(modulesRead, pkg.Name(), file.Name()))
						if err != nil {
							if !treeInstallTolerable(err) {
								record(fmt.Errorf("reader %d: read %s/%s: %w", reader, pkg.Name(), file.Name(), err))
								return
							}
							continue
						}
						if want := treeInstallFileBytes(pkgIndex, fileIndex); !bytes.Equal(got, want) {
							record(fmt.Errorf("reader %d: %s/%s holds %d bytes the installer never wrote (want %d of %q)",
								reader, pkg.Name(), file.Name(), len(got), len(want), string(want[0])))
							return
						}
					}
				}
			}
		}()
	}

	const raceBound = 90 * time.Second
	raceStart := time.Now()
	staging := filepath.Join(installRoot, ".tree-staging")
	for pkg := range treeInstallPackages {
		if err := os.Mkdir(staging, 0o700); err != nil {
			close(stop)
			readers.Wait()
			t.Fatalf("package %d: stage: %v (%s)", pkg, err, f.sessionDiagnostics())
		}
		for file := range treeInstallFilesPerPkg {
			path := filepath.Join(staging, fmt.Sprintf("file-%d.txt", file))
			if err := os.WriteFile(path, treeInstallFileBytes(pkg, file), 0o600); err != nil {
				close(stop)
				readers.Wait()
				t.Fatalf("package %d: write %s: %v (%s)", pkg, path, err, f.sessionDiagnostics())
			}
		}
		if err := os.Rename(staging, filepath.Join(modulesInstall, treeInstallPackageName(pkg))); err != nil {
			close(stop)
			readers.Wait()
			t.Fatalf("package %d: publish by rename: %v (%s)", pkg, err, f.sessionDiagnostics())
		}
		if recorded := failure.Load(); recorded != nil {
			close(stop)
			readers.Wait()
			t.Fatalf("package %d: %v (%s)", pkg, *recorded, f.sessionDiagnostics())
		}
	}
	close(stop)
	readers.Wait()
	if recorded := failure.Load(); recorded != nil {
		t.Fatalf("after the install: %v (%s)", *recorded, f.sessionDiagnostics())
	}
	if raced := time.Since(raceStart); raced > raceBound {
		t.Fatalf("%d renamed packages raced by 4 enumerating readers took %s, past the %s bound (%s)",
			treeInstallPackages, raced, raceBound, f.sessionDiagnostics())
	}

	// A revoked mount is the defect this test exists for, and it is asserted
	// separately from the readers' own errors: a mount can be revoked in a
	// window where every in-flight syscall happened to have already returned.
	for index := range 2 {
		if cause := f.mounts[index].fatalError(); cause != nil {
			t.Fatalf("mount %d was revoked during the tree install: %v", index, cause)
		}
	}
	if seen := enumerations.Load(); seen < treeInstallPackages {
		t.Fatalf("readers completed only %d enumerations across %d published packages; the window this test exists for was not entered",
			seen, treeInstallPackages)
	}
	if seen := entriesSeen.Load(); seen == 0 {
		t.Fatal("no reader ever enumerated a published package, so nothing raced the renames")
	}

	// Quiescent, the tree is exact from the mount that never wrote it.
	packages, err := os.ReadDir(modulesRead)
	if err != nil {
		t.Fatalf("enumerate the finished tree: %v", err)
	}
	if len(packages) != treeInstallPackages {
		t.Fatalf("finished tree holds %d packages, want %d", len(packages), treeInstallPackages)
	}
	for pkg := range treeInstallPackages {
		directory := filepath.Join(modulesRead, treeInstallPackageName(pkg))
		files, err := os.ReadDir(directory)
		if err != nil {
			t.Fatalf("enumerate %s: %v", directory, err)
		}
		if len(files) != treeInstallFilesPerPkg {
			t.Fatalf("%s holds %d files, want %d", directory, len(files), treeInstallFilesPerPkg)
		}
		for file := range treeInstallFilesPerPkg {
			path := filepath.Join(directory, fmt.Sprintf("file-%d.txt", file))
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			if want := treeInstallFileBytes(pkg, file); !bytes.Equal(got, want) {
				t.Fatalf("%s holds %d bytes, want %d of %q", path, len(got), len(want), string(want[0]))
			}
		}
	}
}
