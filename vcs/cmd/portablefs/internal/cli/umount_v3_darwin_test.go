//go:build darwin

package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fskitidentity"
)

// These tests pin the two live-battery failures against the daemon-v3 umount
// flow: a terminal FSKit mount whose daemon attach is already gone could only
// be removed with the system umount, and a mount path with a symlinked
// ancestor could not even be named once the volume stopped answering lstat.

func v3FSKitMountState(t *testing.T, mountPath string) mountState {
	t.Helper()
	st := staleFSKitMountState(t, mountPath)
	st.Engine = mountEngineDaemonV3
	return st
}

// stubV3KernelMount publishes the recorded mount's exact kernel identity in
// the stubbed mount table, gated on a flag so the test's platform unmount can
// make it absent. Returns the presence flag.
func stubV3KernelMount(t *testing.T, st mountState) *atomic.Bool {
	t.Helper()
	var present atomic.Bool
	present.Store(true)
	stubMountIdentification(t, nil, func(path string) ([]kernelMountIdentity, error) {
		if present.Load() && path == st.MountPath {
			return []kernelMountIdentity{{
				fsType: fskitidentity.FSType,
				path:   st.MountPath,
				source: fskitidentity.ResourcePrefix + st.AttachRef,
			}}, nil
		}
		return nil, nil
	})
	return &present
}

// stubPlatformUnmount replaces the exec surface of the direct kernel detach
// and flips the stubbed kernel mount to absent when it runs, exactly like a
// successful /sbin/umount. Returns the invocation counter.
func stubPlatformUnmount(t *testing.T, present *atomic.Bool) *atomic.Int32 {
	t.Helper()
	var detaches atomic.Int32
	prior := platformUnmountOpsSource
	platformUnmountOpsSource = func(time.Duration) unmountOps {
		return unmountOps{
			goos: "darwin",
			combinedOut: func(name string, args ...string) ([]byte, error) {
				if name != "/sbin/umount" {
					t.Errorf("direct kernel detach ran %q, want /sbin/umount", name)
				}
				detaches.Add(1)
				present.Store(false)
				return nil, nil
			},
		}
	}
	t.Cleanup(func() { platformUnmountOpsSource = prior })
	return &detaches
}

func TestUmountV3DetachesTerminalMountWhoseDaemonAttachIsGone(t *testing.T) {
	for _, force := range []bool{true, false} {
		t.Run(map[bool]string{true: "force", false: "normal"}[force], func(t *testing.T) {
			e, _, stderr, stateDir := umountTestEnv(t)
			mountPath, err := canonicalMountPath(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			st := v3FSKitMountState(t, mountPath)
			if err := writeMountState(stateDir, st); err != nil {
				t.Fatal(err)
			}
			present := stubV3KernelMount(t, st)
			detaches := stubPlatformUnmount(t, present)
			ctl, calls := serveFSKitReconcileControl(t, st, false, false, http.StatusOK)
			e.ensurePortablefsdFn = func(fskitConfig, string, string) (*fsdControl, error) { return ctl, nil }

			args := []string{"umount", mountPath}
			if force {
				args = []string{"umount", "--force", mountPath}
			}
			if rc := e.run(args); rc != 0 {
				t.Fatalf("rc=%d stderr=%q", rc, stderr.String())
			}
			if detaches.Load() != 1 {
				t.Fatalf("direct kernel detaches=%d, want exactly 1", detaches.Load())
			}
			if calls.unmount.Load() != 0 {
				t.Fatalf("daemon unmount endpoint was called %d times for an absent attach", calls.unmount.Load())
			}
			if current, err := readMountState(stateDir, mountPath); err != nil || current != nil {
				t.Fatalf("state after detach=%+v err=%v", current, err)
			}

		})
	}
}

func TestUmountV3ForceDetachesWhenTheDaemonIsUnreachable(t *testing.T) {
	e, _, stderr, stateDir := umountTestEnv(t)
	mountPath, err := canonicalMountPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st := v3FSKitMountState(t, mountPath)
	if err := writeMountState(stateDir, st); err != nil {
		t.Fatal(err)
	}
	present := stubV3KernelMount(t, st)
	detaches := stubPlatformUnmount(t, present)
	e.ensurePortablefsdFn = func(fskitConfig, string, string) (*fsdControl, error) {
		return nil, errors.New("daemon did not start")
	}

	if rc := e.run([]string{"umount", "--force", mountPath}); rc == 0 {
		t.Fatalf("rc=%d stderr=%q", rc, stderr.String())
	}
	if detaches.Load() != 1 {
		t.Fatalf("direct kernel detaches=%d, want exactly 1", detaches.Load())
	}
	if current, err := readMountState(stateDir, mountPath); err != nil || current == nil {
		t.Fatalf("unconfirmed detach lost state=%+v err=%v", current, err)
	}
	if !strings.Contains(stderr.String(), "kernel mount is absent; daemon unmount completion is unconfirmed") || !strings.Contains(stderr.String(), "state and intent were preserved") {
		t.Fatal(stderr.String())
	}
	_, intentPath := mountOperationPaths(stateDir, mountPath)
	if _, err := os.Stat(intentPath); err != nil {
		t.Fatal("unconfirmed force lost intent", err)
	}
}

func TestUmountV3NormalRequiresTheDaemonWhenItsAttachMayBeLive(t *testing.T) {
	e, _, stderr, stateDir := umountTestEnv(t)
	mountPath, err := canonicalMountPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st := v3FSKitMountState(t, mountPath)
	if err := writeMountState(stateDir, st); err != nil {
		t.Fatal(err)
	}
	present := stubV3KernelMount(t, st)
	detaches := stubPlatformUnmount(t, present)
	e.ensurePortablefsdFn = func(fskitConfig, string, string) (*fsdControl, error) {
		return nil, errors.New("daemon did not start")
	}

	if rc := e.run([]string{"umount", mountPath}); rc == 0 {
		t.Fatal("a normal unmount succeeded without either the daemon transaction or --force")
	}
	if detaches.Load() != 0 {
		t.Fatalf("a refused normal unmount performed %d kernel detaches", detaches.Load())
	}
	if !strings.Contains(stderr.String(), "kernel mount remains present; daemon-owned FSKit unmount failed or is incomplete") {
		t.Fatalf("refusal lost outcome: stderr=%q", stderr.String())
	}
	if current, err := readMountState(stateDir, mountPath); err != nil || current == nil {
		t.Fatalf("refusal lost state: state=%+v err=%v", current, err)
	}
}

func TestUmountV3NeverOverridesAnAttachIdentityMismatch(t *testing.T) {
	e, _, stderr, stateDir := umountTestEnv(t)
	mountPath, err := canonicalMountPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st := v3FSKitMountState(t, mountPath)
	if err := writeMountState(stateDir, st); err != nil {
		t.Fatal(err)
	}
	present := stubV3KernelMount(t, st)
	detaches := stubPlatformUnmount(t, present)
	ctl, _ := serveFSKitReconcileControl(t, st, true, true, http.StatusOK)
	e.ensurePortablefsdFn = func(fskitConfig, string, string) (*fsdControl, error) { return ctl, nil }

	if rc := e.run([]string{"umount", "--force", mountPath}); rc == 0 {
		t.Fatal("--force overrode an attach identity mismatch")
	}
	if detaches.Load() != 0 {
		t.Fatalf("an identity mismatch still performed %d kernel detaches", detaches.Load())
	}
	if !strings.Contains(stderr.String(), "identity mismatch") {
		t.Fatalf("refusal does not state the mismatch: stderr=%q", stderr.String())
	}
	if current, err := readMountState(stateDir, mountPath); err != nil || current == nil {
		t.Fatalf("mismatch refusal lost state: state=%+v err=%v", current, err)
	}
}

func TestCanonicalMountPathResolvesSymlinkedAncestorOfADeadMount(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	resolvedReal, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	typed := filepath.Join(link, "mnt")             // the path the user types
	canonical := filepath.Join(resolvedReal, "mnt") // the path the kernel records

	stubMountIdentification(t,
		func(path string) (fs.FileInfo, error) {
			if path == typed || path == canonical {
				return nil, &os.PathError{Op: "lstat", Path: path, Err: syscall.EIO}
			}
			return os.Lstat(path)
		},
		func(path string) ([]kernelMountIdentity, error) {
			if path == canonical {
				return []kernelMountIdentity{{fsType: fskitidentity.FSType, path: canonical, source: fskitidentity.ResourcePrefix + "att_AAAAAAAAAAAAAAAAAAAAAA"}}, nil
			}
			return nil, nil
		})

	got, err := canonicalMountPath(typed)
	if err != nil {
		t.Fatalf("a dead mount under a symlinked ancestor could not be named: %v", err)
	}
	if got != canonical {
		t.Fatalf("canonical path = %q, want the kernel's recorded %q", got, canonical)
	}
}

func TestFSKitUnmountErrorReportsIndependentKernelAbsence(t *testing.T) {
	for _, present := range []bool{false, true} {
		t.Run(fmt.Sprint(present), func(t *testing.T) {
			e, _, _, _ := umountTestEnv(t)
			st := validFSKitMountState(t, filepath.Join(t.TempDir(), "mount"))
			ctl, _ := serveFSKitReconcileControl(t, st, true, false, http.StatusConflict)
			e.ensurePortablefsdFn = func(fskitConfig, string, string) (*fsdControl, error) { return ctl, nil }
			stubMountIdentification(t, nil, func(path string) ([]kernelMountIdentity, error) {
				if !present {
					return nil, nil
				}
				return []kernelMountIdentity{{path: path, fsType: defaultFskitType, source: fskitidentity.ResourcePrefix + st.AttachRef}}, nil
			})
			detached, err := e.v3FSKitDaemonDetach(&st, false)
			if err == nil || detached == present {
				t.Fatalf("detach=%v error=%v", detached, err)
			}
			want := "kernel mount is absent"
			if present {
				want = "kernel mount remains present"
			}
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("wrong outcome: %v", err)
			}
		})
	}
}

func TestFSKitSupervisorShutdownReportsKernelOutcome(t *testing.T) {
	for _, outcome := range []string{"absent", "present", "unverified", "success still present"} {
		t.Run(outcome, func(t *testing.T) {
			st := validFSKitMountState(t, filepath.Join(t.TempDir(), "mount"))
			afterDetach := false
			classificationErr := errors.New("kernel inventory unavailable")
			stubMountIdentification(t, nil, func(path string) ([]kernelMountIdentity, error) {
				if afterDetach && outcome == "unverified" {
					return nil, classificationErr
				}
				if afterDetach && outcome == "absent" {
					return nil, nil
				}
				return []kernelMountIdentity{{path: path, fsType: defaultFskitType, source: fskitidentity.ResourcePrefix + st.AttachRef}}, nil
			})
			detachErr := errors.New("daemon transaction incomplete")
			absent, err := unmountFSKitWithKernelOutcome(&st, func() error {
				afterDetach = true
				if outcome == "success still present" {
					return nil
				}
				return detachErr
			})
			if err == nil || absent != (outcome == "absent") {
				t.Fatalf("absent=%t error=%v", absent, err)
			}
			if outcome != "success still present" && !errors.Is(err, detachErr) {
				t.Fatalf("lost daemon error: %v", err)
			}
			switch outcome {
			case "absent":
				if !strings.Contains(err.Error(), "kernel mount is absent") || strings.Contains(err.Error(), "remains") {
					t.Fatal(err)
				}
			case "present", "success still present":
				if !strings.Contains(err.Error(), "kernel mount remains") {
					t.Fatal(err)
				}
			case "unverified":
				if !strings.Contains(err.Error(), "kernel mount presence is unverified") || !errors.Is(err, classificationErr) {
					t.Fatal(err)
				}
			}
		})
	}
}

type detachRoundTrip struct {
	lifecycleRoundTrip
	closes int
}

func (r *detachRoundTrip) CloseIdleConnections() { r.closes++ }

func TestFSKitDetachPreservesUnconfirmedTransactionAnchors(t *testing.T) {
	for _, initiallyMounted := range []bool{true, false} {
		for _, force := range []bool{false, true} {
			for _, outcome := range []string{
				"lost reply absent", "lost reply present", "lost reply unverified",
				"malformed 204 absent", "204 present", "204 absent", "204 replacement", "204 unverified",
				"inventory mismatch absent", "inventory failure absent",
			} {
				t.Run(fmt.Sprintf("initiallyMounted=%t/force=%t/%s", initiallyMounted, force, outcome), func(t *testing.T) {
					e, stdout, stderr, stateDir := umountTestEnv(t)
					mountPath, err := canonicalMountPath(t.TempDir())
					if err != nil {
						t.Fatal(err)
					}
					st := v3FSKitMountState(t, mountPath)
					if mountProcessMatches(&st) {
						t.Fatal("fixture supervisor must be absent")
					}
					if err := writeMountState(stateDir, st); err != nil {
						t.Fatal(err)
					}
					mounted, after, finalSnapshots := initiallyMounted, false, 0
					stubMountIdentification(t, nil, func(path string) ([]kernelMountIdentity, error) {
						if after {
							finalSnapshots++
							if strings.HasSuffix(outcome, "unverified") {
								return nil, errors.New("kernel query failed")
							}
							if strings.HasSuffix(outcome, "replacement") {
								return []kernelMountIdentity{{path: path, fsType: "apfs", source: "/dev/replacement"}}, nil
							}
						}
						if !mounted {
							return nil, nil
						}
						return []kernelMountIdentity{{path: path, fsType: defaultFskitType, source: fskitidentity.ResourcePrefix + st.AttachRef}}, nil
					})
					forceCalls := 0
					original := platformUnmountOpsSource
					platformUnmountOpsSource = func(time.Duration) unmountOps {
						return unmountOps{goos: "darwin", combinedOut: func(name string, args ...string) ([]byte, error) {
							forceCalls++
							if !force || name != "/sbin/umount" || len(args) != 2 || args[0] != "-f" || args[1] != mountPath {
								t.Fatalf("unauthorized or inexact kernel force: %s %v", name, args)
							}
							mounted = false
							return nil, nil
						}}
					}
					t.Cleanup(func() { platformUnmountOpsSource = original })
					unmountCalls := 0
					transport := &detachRoundTrip{lifecycleRoundTrip: lifecycleRoundTrip(func(r *http.Request) (*http.Response, error) {
						status, body := http.StatusOK, fmt.Sprintf(`{"attaches":[{"attachRef":%q,"mountPath":%q,"volumeId":%q}]}`, st.AttachRef, mountPath, st.VolumeID)
						if strings.HasPrefix(outcome, "inventory") {
							after, mounted = true, false
							if outcome == "inventory failure absent" {
								return nil, io.EOF
							}
							body = fmt.Sprintf(`{"attaches":[{"attachRef":%q,"mountPath":%q,"volumeId":%q}]}`, st.AttachRef, mountPath+"-other", st.VolumeID)
						}
						if strings.Contains(r.URL.Path, "/unmount") {
							unmountCalls++
							if (r.URL.Query().Get("force") == "1") != force {
								t.Fatal("wrong daemon force request")
							}
							after, mounted = true, !strings.HasSuffix(outcome, "absent")
							if strings.HasPrefix(outcome, "lost reply") {
								return nil, io.EOF
							}
							status, body = http.StatusNoContent, ""
							if strings.HasPrefix(outcome, "malformed") {
								body = "unexpected"
							}
						}
						return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
					})}
					ctl := &fsdControl{httpClient: &http.Client{Transport: transport}}
					ctl.pairOnce.Do(func() {})
					e.ensurePortablefsdFn = func(fskitConfig, string, string) (*fsdControl, error) { return ctl, nil }
					args := []string{"umount", mountPath}
					if force {
						args = append(args, "--force")
					}
					rc := e.run(args)
					success := outcome == "204 absent"
					if (rc == 0) != success {
						t.Fatalf("rc=%d stdout=%q stderr=%q", rc, stdout.String(), stderr.String())
					}
					if finalSnapshots == 0 || transport.closes != 1 {
						t.Fatalf("final kernel snapshots=%d, control pool closes=%d", finalSnapshots, transport.closes)
					}
					wantUnmounts := 1
					if strings.HasPrefix(outcome, "inventory") {
						wantUnmounts = 0
					}
					if unmountCalls != wantUnmounts {
						t.Fatalf("daemon unmount calls=%d, want %d", unmountCalls, wantUnmounts)
					}
					current, err := readMountState(stateDir, mountPath)
					if err != nil || (current == nil) != success {
						t.Fatalf("state=%+v err=%v success=%t", current, err, success)
					}
					_, intentPath := mountOperationPaths(stateDir, mountPath)
					intent, intentErr := readMountIntent(intentPath, mountPath)
					if success {
						if intentErr != nil || intent != nil {
							t.Fatalf("completed transaction retained intent: %+v %v", intent, intentErr)
						}
					} else if intentErr != nil || intent == nil || intent.Phase != "unmounting" {
						t.Fatalf("unconfirmed transaction lost reconciliation intent: %+v %v", intent, intentErr)
					}
					if forceCalls != 0 && (!force || strings.Contains(outcome, "replacement") || strings.HasPrefix(outcome, "inventory mismatch")) {
						t.Fatal("normal request, replacement mount, or mismatched attach forced")
					}
					if !success {
						want := "kernel mount is absent; daemon unmount completion is unconfirmed"
						if strings.HasSuffix(outcome, "unverified") || strings.HasSuffix(outcome, "replacement") {
							want = "kernel mount presence is unverified"
						} else if outcome == "204 present" {
							want = "daemon-owned FSKit unmount acknowledged completion but the exact kernel mount remains"
						} else if mounted {
							want = "kernel mount remains present; daemon-owned FSKit unmount failed or is incomplete"
						}
						if !strings.Contains(stderr.String(), want) || !strings.Contains(stderr.String(), "state and intent were preserved") {
							t.Fatal(stderr.String())
						}
						if strings.Contains(stdout.String(), "unmounted ") || strings.Contains(stderr.String(), "attach cleanup failed") || strings.Contains(stderr.String(), "retry cleanup or use") {
							t.Fatalf("unconfirmed completion misstated: stdout=%q stderr=%q", stdout.String(), stderr.String())
						}
					}
				})
			}
		}
	}
}
