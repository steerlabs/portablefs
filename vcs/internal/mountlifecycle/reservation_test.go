package mountlifecycle

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/privatepath"
)

func reservation(frontend, owner string) Reservation {
	return Reservation{Authority: strings.Repeat("ab", 32), Volume: "vol-1", Frontend: frontend, Owner: owner}
}
func TestReservationRefusesBothOrdersAndRetainsCrashIntent(t *testing.T) {
	for _, first := range []string{"fskit", "workspace"} {
		t.Run(first, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "state")
			one, err := BeginTransition(dir)
			if err != nil {
				t.Fatal(err)
			}
			old := reservation(first, "pending-owner")
			if err = one.Reserve(old); err != nil {
				t.Fatal(err)
			}
			one.Close()
			// No live process is required to retain ownership. Reopening is not GC.
			next, err := BeginTransition(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer next.Close()
			other := "fskit"
			message := LinuxVolumeConflict
			if first == "fskit" {
				other = "workspace"
				message = MacVolumeConflict
			}
			if err = next.Reserve(reservation(other, "second-owner")); err == nil || err.Error() != message {
				t.Fatalf("second attach = %v", err)
			}
			if err = next.Release(reservation(first, "wrong-owner")); err == nil {
				t.Fatal("foreign cleanup released pending owner")
			}
			if err = next.Reserve(old); err != nil {
				t.Fatal("idempotent owner", err)
			}
			if err = next.Release(old); err != nil {
				t.Fatal(err)
			}
			if err = next.Reserve(reservation(other, "second-owner")); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestReservationConcurrentOpposingAttachesHaveOneWinner(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	ready := make(chan struct{})
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, frontend := range []string{"fskit", "workspace"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-ready
			owner, err := BeginTransition(dir)
			if err == nil {
				defer owner.Close()
				err = owner.Reserve(reservation(frontend, frontend))
			}
			results <- err
		}()
	}
	close(ready)
	wg.Wait()
	close(results)
	wins := 0
	for err := range results {
		if err == nil {
			wins++
		} else if !errors.Is(err, ErrBusy) && err.Error() != MacVolumeConflict && err.Error() != LinuxVolumeConflict {
			t.Fatal(err)
		}
	}
	if wins != 1 {
		t.Fatalf("%d winners", wins)
	}
}
func TestReservationSamePathCollisionAndWorkspaceDisabled(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	owner, err := BeginTransition(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	// Reading/reserving FSKit does not create a workspace directory or start it.
	fskit := reservation("fskit", "mac")
	if err = owner.Reserve(fskit); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(filepath.Join(dir, "workspace")); !os.IsNotExist(err) {
		t.Fatal("FSKit initialized workspace")
	}
	linux := reservation("workspace", "linux")
	linux.Volume = "different"
	if err = owner.Reserve(linux); err != nil {
		t.Fatal(err)
	}
	alias := linux
	alias.Authority = strings.Repeat("cd", 32)
	alias.Owner = "alias"
	if owner.Reserve(alias) == nil {
		t.Fatal("same Linux pathname collision accepted")
	}
}
func TestReservationMalformedStateAndReplacedLockRefuse(t *testing.T) {
	for _, raw := range []string{`{"version":2,"reservations":[]}`, `{"version":1,"reservations":null}`, `{"version":1,"version":1,"reservations":[]}`, `{"version":1,"reservations":[],"extra":true}`} {
		t.Run(raw, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "state")
			if err := privatepath.EnsureDir(dir); err != nil {
				t.Fatal(err)
			}
			if err := privatepath.WriteFileAtomic(filepath.Join(dir, ReservationFile), []byte(raw)); err != nil {
				t.Fatal(err)
			}
			if owner, err := BeginTransition(dir); err == nil {
				owner.Close()
				t.Fatal("corrupt reservation accepted")
			}
		})
	}
}
func TestAuthorityIdentityCanonicalNameNotEndpoint(t *testing.T) {
	a, err := AuthorityIdentity("AUTHORITY.example.")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := AuthorityIdentity("authority.example")
	if a != b {
		t.Fatal("TLS spelling split authority")
	}
	for _, name := range []string{"", "bad/name", "bad name", "bad\x00name"} {
		if _, err := AuthorityIdentity(name); err == nil {
			t.Fatal("invalid name accepted")
		}
	}
}

func TestWorkspacePathReservationCannotSplitAcrossAuthorityAliases(t *testing.T) {
	for _, first := range []string{"fskit", "workspace"} {
		t.Run(first, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "state")
			transition, err := BeginTransition(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer transition.Close()
			if err = transition.Reserve(reservation(first, "first")); err != nil {
				t.Fatal(err)
			}
			second := reservation("workspace", "second")
			if first == "workspace" {
				second.Frontend = "fskit"
			}
			second.Authority = strings.Repeat("cd", 32)
			if transition.Reserve(second) == nil {
				t.Fatal("same workspace path escaped through another authority name")
			}
		})
	}
}
