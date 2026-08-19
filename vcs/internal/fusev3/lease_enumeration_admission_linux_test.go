//go:build linux

package fusev3

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const (
	treeInstallPackages    = 24
	treeInstallFilesPerPkg = 48
	// Each entry name is padded so one package's listing cannot be answered by a
	// single kernel READDIR callback. That is not cosmetic: a stream that fits in
	// one callback is never resumed, and the whole class of defect here lives in
	// the resume. Go's ReadDir asks for 8 KiB at a time, so 48 entries of about
	// 216 bytes each guarantee at least two callbacks per pass, on every kernel,
	// without depending on a buffer size this test does not control.
	treeInstallNamePadding = 180
)

func treeInstallPackageName(index int) string { return fmt.Sprintf("pkg-%03d", index) }

func treeInstallFileName(index int) string {
	return fmt.Sprintf("file-%03d-%s.txt", index, strings.Repeat("p", treeInstallNamePadding))
}

// treeInstallFileIndex is the inverse of treeInstallFileName, and it is strict:
// a name this cannot parse is a name the installer never created.
func treeInstallFileIndex(name string) (int, bool) {
	var index int
	if _, err := fmt.Sscanf(name, "file-%03d-", &index); err != nil {
		return 0, false
	}
	if index < 0 || index >= treeInstallFilesPerPkg || treeInstallFileName(index) != name {
		return 0, false
	}
	return index, true
}

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

// firstDuplicateName reports a name one readdir pass returned more than once.
//
// This is the exactness a single pass owes its caller unconditionally. POSIX's
// allowance is only about *membership* -- an entry created or removed while the
// pass is running may appear or not -- and it never licenses returning one name
// twice or dropping a name that was present for the whole pass. A duplicate is
// therefore never a race; it is a stream that repositioned underneath the
// kernel and re-delivered what it had already handed over.
func firstDuplicateName(entries []os.DirEntry) (string, bool) {
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if _, duplicate := seen[entry.Name()]; duplicate {
			return entry.Name(), true
		}
		seen[entry.Name()] = struct{}{}
	}
	return "", false
}

// summarizeEnumeration describes a bad pass in one line. The names here are
// deliberately long, so printing them all buries the one fact that diagnoses
// this: which prefix of the stream came back more than once. A re-delivered
// prefix followed by a clean tail is a stream that repositioned to the start
// after its first kernel callback; a uniform multiplier is one that repositioned
// on every callback.
func summarizeEnumeration(entries []os.DirEntry) string {
	counts := make(map[string]int, len(entries))
	order := make([]string, 0, len(entries))
	for _, entry := range entries {
		if counts[entry.Name()] == 0 {
			order = append(order, entry.Name())
		}
		counts[entry.Name()]++
	}
	repeated := 0
	maxSeen := 0
	for _, name := range order {
		if counts[name] > 1 {
			repeated++
		}
		maxSeen = max(maxSeen, counts[name])
	}
	short := func(name string) string {
		if index := strings.IndexByte(name, '-'); index >= 0 {
			if second := strings.IndexByte(name[index+1:], '-'); second >= 0 {
				return name[:index+1+second]
			}
		}
		return name
	}
	summary := fmt.Sprintf("%d entries, %d distinct, %d returned more than once (up to %d times)",
		len(entries), len(order), repeated, maxSeen)
	if repeated != 0 {
		summary += fmt.Sprintf("; first %q, last repeated %q, first clean %q",
			short(order[0]), short(order[repeated-1]), func() string {
				if repeated < len(order) {
					return short(order[repeated])
				}
				return "(none)"
			}())
	}
	return summary
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
	// Per reader, not just in total. The permitted answer to an enumeration
	// racing a mutation is ESTALE, and a fix built on ESTALE can satisfy every
	// exactness assertion above while never letting a pass finish at all. A
	// reader that completed zero passes under this churn is a livelocked reader,
	// and it has to fail here rather than read as success.
	var completed [4]atomic.Int64

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
				// node_modules is being mutated under this pass, so its
				// membership is not fixed: POSIX lets an entry created or
				// removed mid-pass appear or not. What it never permits is one
				// name twice. A duplicate here is a repositioned stream, not a
				// race.
				if duplicate, ok := firstDuplicateName(packages); ok {
					record(fmt.Errorf("reader %d: one enumeration pass of %s returned %q more than once (%d entries for at most %d distinct names)",
						reader, modulesRead, duplicate, len(packages), treeInstallPackages))
					return
				}
				enumerations.Add(1)
				completed[reader].Add(1)
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
					// touches a name after the rename that created it. So this
					// directory is stable across the whole pass, and the weaker
					// POSIX allowance does not apply to it at all -- every one
					// of its names must appear exactly once, and the count is
					// exactly what was renamed into place. This is the assertion
					// that catches a stream which restarted from the beginning
					// and appended a second copy of what the kernel already had:
					// live staging saw exactly that, as "pkg-001 with 18
					// entries, not the 9 that were renamed into place".
					if len(files) != treeInstallFilesPerPkg {
						record(fmt.Errorf("reader %d: one enumeration pass of %s returned %d entries, not the %d that were renamed into place (%v)",
							reader, pkg.Name(), len(files), treeInstallFilesPerPkg, summarizeEnumeration(files)))
						return
					}
					if duplicate, ok := firstDuplicateName(files); ok {
						record(fmt.Errorf("reader %d: one enumeration pass of %s returned %q more than once (%v)",
							reader, pkg.Name(), duplicate, summarizeEnumeration(files)))
						return
					}
					var pkgIndex int
					if _, scanErr := fmt.Sscanf(pkg.Name(), "pkg-%03d", &pkgIndex); scanErr != nil {
						record(fmt.Errorf("reader %d: unexpected package name %q", reader, pkg.Name()))
						return
					}
					// Every name must be one the installer created -- an
					// enumeration that invented or corrupted a name fails here
					// rather than at the byte check below.
					for _, file := range files {
						if _, ok := treeInstallFileIndex(file.Name()); !ok {
							record(fmt.Errorf("reader %d: %s holds a name the installer never created: %q", reader, pkg.Name(), file.Name()))
							return
						}
					}
					// A published package is immutable, so any byte a reader
					// gets from one is exactly assertable too. One file per pass
					// is sampled rather than all of them: the enumeration
					// assertions above are what this test is for, and reading
					// every file of every package on every pass would spend the
					// whole race budget in read(2) instead of in readdir.
					sampled := int(enumerations.Load()) % treeInstallFilesPerPkg
					{
						file := treeInstallFileName(sampled)
						got, err := os.ReadFile(filepath.Join(modulesRead, pkg.Name(), file))
						if err != nil {
							if !treeInstallTolerable(err) {
								record(fmt.Errorf("reader %d: read %s/%s: %w", reader, pkg.Name(), file, err))
								return
							}
						} else if want := treeInstallFileBytes(pkgIndex, sampled); !bytes.Equal(got, want) {
							record(fmt.Errorf("reader %d: %s/%s holds %d bytes the installer never wrote (want %d of %q)",
								reader, pkg.Name(), file, len(got), len(want), string(want[0])))
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
			path := filepath.Join(staging, treeInstallFileName(file))
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
	for reader := range completed {
		if passes := completed[reader].Load(); passes == 0 {
			t.Fatalf("reader %d completed no enumeration pass in the whole install: enumeration cannot finish under this churn rate (%s)",
				reader, f.sessionDiagnostics())
		}
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
			path := filepath.Join(directory, treeInstallFileName(file))
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
