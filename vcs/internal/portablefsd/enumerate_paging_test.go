package portablefsd

import (
	"fmt"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// adapterDaemonPageSize mirrors PfsEnumerationCookies.daemonPageSize in the
// FSKit adapter: every kernel enumerateDirectory call drains daemon pages of
// this size until the kernel's directory-entry packer stops accepting entries.
const adapterDaemonPageSize = 256

// enumerationWalk models one kernel enumerateDirectory call the way the FSKit
// adapter performs it: fetch daemon pages of adapterDaemonPageSize and pack
// entries until the packer refuses after packerCapacity entries. It returns the
// packed names and the cookie the kernel will resume from, which is the cookie
// carried by the last packed entry.
func enumerationWalk(
	t *testing.T,
	c *pfsTestClient,
	dir pfslocal.Item,
	cookie uint64,
	packerCapacity int,
	names *[]string,
	seen map[string]bool,
) uint64 {
	t.Helper()
	packed := 0
	for {
		page := c.call(&pfslocal.EnumerateRequest{
			Dir: dir, Cookie: cookie, MaxEntries: adapterDaemonPageSize, WantAttrs: false,
		}).(*pfslocal.EnumerateReply)
		for _, e := range page.Entries {
			name := string(e.Name)
			if seen[name] {
				t.Fatalf("duplicate enumerate entry %q", name)
			}
			seen[name] = true
			*names = append(*names, name)
			packed++
			if packed == packerCapacity {
				// The packer is full. FSKit keeps this entry's cookie and
				// resumes there on the next enumerateDirectory call.
				return e.Cookie
			}
		}
		if page.NextCookie == 0 {
			return 0
		}
		cookie = page.NextCookie
	}
}

// TestDaemonEnumerateResumesAfterAdapterDrainedFinalPage reproduces the live
// macOS failures. The FSKit adapter drains daemon pages inside a single kernel
// enumerateDirectory call, so by the time the kernel's entry packer fills up
// the daemon has usually already served the directory's final page. The cookie
// the kernel keeps points into that finished page, and the walk must continue
// from exactly there.
//
// The three cases are the three shapes observed on a real macOS 26 host:
// `ls` stopping at 303 of 500 entries with fts_read: Invalid argument, Go
// os.ReadDir returning 457 of 500 with no error at all, and a 120-entry
// directory coming back as 49 entries with no error.
func TestDaemonEnumerateResumesAfterAdapterDrainedFinalPage(t *testing.T) {
	for _, tc := range []struct {
		name     string
		entries  int
		capacity int
	}{
		{"ls_303_of_500", 500, 303},
		{"readdir_457_of_500", 500, 457},
		{"readdir_49_of_120", 120, 49},
	} {
		t.Run(tc.name, func(t *testing.T) {
			authority := serveAuthority(t)
			want := seedAuthorityFiles(t, authority, tc.entries)

			cfg, _, ref, cancel := startDaemon(t, authority)
			defer cancel()
			c := dialPFS(t, cfg.FrontendSocket)
			defer c.close()
			c.call(&pfslocal.Hello{ProtocolMajor: 1})
			res := c.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply)

			var names []string
			seen := map[string]bool{}
			cookie := enumerationWalk(t, c, res.Root, 0, tc.capacity, &names, seen)
			if len(names) != tc.capacity {
				t.Fatalf("first enumerateDirectory packed %d entries, want %d", len(names), tc.capacity)
			}
			if cookie == 0 {
				t.Fatalf("first enumerateDirectory ended the directory after %d of %d entries", tc.capacity, tc.entries)
			}
			if cookie&enumerateCookieMarker == 0 {
				t.Fatalf("resume cookie %#x is not in the daemon cookie namespace", cookie)
			}
			for cookie != 0 {
				cookie = enumerationWalk(t, c, res.Root, cookie, tc.capacity, &names, seen)
			}
			assertExactNames(t, names, want)
		})
	}
}

// TestDaemonEnumerateCompletesAcrossRenameInBetweenPages walks a directory the
// way the kernel does while a writer keeps renaming files in and removing
// others between pages. Entries that exist for the whole walk must be returned
// exactly once, and no page may fail: a resumption point stays meaningful
// across concurrent mutation.
func TestDaemonEnumerateCompletesAcrossRenameInBetweenPages(t *testing.T) {
	authority := serveAuthority(t)
	stable := seedAuthorityFiles(t, authority, 400)

	cfg, _, ref, cancel := startDaemon(t, authority)
	defer cancel()
	c := dialPFS(t, cfg.FrontendSocket)
	defer c.close()
	c.call(&pfslocal.Hello{ProtocolMajor: 1})
	res := c.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply)

	mutator := dialPFS(t, cfg.FrontendSocket)
	defer mutator.close()
	mutator.call(&pfslocal.Hello{ProtocolMajor: 1})
	mres := mutator.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply)
	renameIn := func(round int) {
		tmp := fmt.Sprintf(".tmp-%03d", round)
		create := mutator.call(&pfslocal.CreateRequest{
			Dir: mres.Root, Name: []byte(tmp), Mode: 0o644, Exclusive: true,
		}).(*pfslocal.CreateReply)
		mutator.call(&pfslocal.CloseRequest{Handle: create.Handle})
		mutator.call(&pfslocal.RenameRequest{
			FromDir: mres.Root, FromName: []byte(tmp),
			ToDir: mres.Root, ToName: []byte(fmt.Sprintf("renamed-%03d", round)),
		})
	}

	var names []string
	seen := map[string]bool{}
	var cookie uint64
	for round := 0; ; round++ {
		renameIn(round)
		cookie = enumerationWalk(t, c, res.Root, cookie, 64, &names, seen)
		if cookie == 0 {
			break
		}
		if round > 200 {
			t.Fatalf("enumeration did not terminate after %d pages (%d entries)", round, len(names))
		}
	}
	for _, name := range stable {
		if !seen[name] {
			t.Fatalf("enumeration under concurrent rename-in lost stable entry %q (%d of %d returned)",
				name, len(names), len(stable))
		}
	}
}

// TestDaemonEnumerateManyLiveWalksAllResume keeps far more directory walks open
// at once than the daemon ever kept snapshot records for. Every walk must still
// resume: a resumption cookie is not a scarce server-side resource.
func TestDaemonEnumerateManyLiveWalksAllResume(t *testing.T) {
	authority := serveAuthority(t)
	want := seedAuthorityFiles(t, authority, 40)

	cfg, _, ref, cancel := startDaemon(t, authority)
	defer cancel()

	const walks = 80 // > the 64 snapshot records the pre-fix daemon could hold
	clients := make([]*pfsTestClient, walks)
	roots := make([]pfslocal.Item, walks)
	cookies := make([]uint64, walks)
	collected := make([][]string, walks)
	seen := make([]map[string]bool, walks)
	for i := 0; i < walks; i++ {
		c := dialPFS(t, cfg.FrontendSocket)
		defer c.close()
		c.call(&pfslocal.Hello{ProtocolMajor: 1})
		res := c.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply)
		clients[i] = c
		roots[i] = res.Root
		seen[i] = map[string]bool{}
		cookies[i] = appendEnumeratePageMode(t, c, res.Root, 0, 1, false, &collected[i], seen[i])
		if cookies[i] == 0 {
			t.Fatalf("walk %d finished on its first entry", i)
		}
	}
	// Every walk is now live and holding a cookie issued long before the last
	// one started. Finish them all.
	for i := 0; i < walks; i++ {
		for cookies[i] != 0 {
			cookies[i] = appendEnumeratePageMode(t, clients[i], roots[i], cookies[i], 7, false, &collected[i], seen[i])
		}
		assertExactNames(t, collected[i], want)
	}
}
