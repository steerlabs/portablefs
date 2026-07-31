package portablefsd

import (
	"fmt"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

func dirEntriesNamed(names []string) []clientcore.DirEntry {
	out := make([]clientcore.DirEntry, 0, len(names))
	for _, name := range names {
		out = append(out, clientcore.DirEntry{Name: name, Attr: fsproto.Attr{Kind: "file"}})
	}
	return out
}

// TestDaemonEnumerateCursorCookiesAreStableAndSelfDescribing pins the cookie
// contract itself: cursors are a pure function of the entry name, cookies are
// tagged so a foreign or pre-fix token cannot be misread as a cursor, and the
// enumeration order they induce is strictly increasing.
func TestDaemonEnumerateCursorCookiesAreStableAndSelfDescribing(t *testing.T) {
	if enumerationCursor("file-000000.dat") != enumerationCursor("file-000000.dat") {
		t.Fatal("cursor is not a pure function of the name")
	}
	if enumerationCursor("a") == enumerationCursor("b") {
		t.Fatal("distinct names collided in the cursor space")
	}
	for _, name := range []string{"", ".", "..", "a", "file-000499.dat"} {
		cursor := enumerationCursor(name)
		if cursor == 0 || cursor > enumerateCursorSpace {
			t.Fatalf("cursor(%q)=%d out of range", name, cursor)
		}
		cookie, ok := encodeEnumerationCookie(cursor)
		if !ok {
			t.Fatalf("encodeEnumerationCookie(%d) failed", cursor)
		}
		if cookie&enumerateCookieMarker == 0 {
			t.Fatalf("cookie %#x is not high-bit-set", cookie)
		}
		if cookie&enumerateCookieTagMask != enumerateCookieTagCursor {
			t.Fatalf("cookie %#x is not tagged as a cursor cookie", cookie)
		}
		if cookie == ^uint64(0) {
			t.Fatalf("cookie %#x collides with the adapter's terminal sentinel", cookie)
		}
		got, ok := decodeEnumerationCookie(cookie)
		if !ok || got != cursor {
			t.Fatalf("decodeEnumerationCookie(%#x)=(%d,%v), want (%d,true)", cookie, got, ok, cursor)
		}
		for _, bad := range []uint64{cookie &^ enumerateCookieMarker, cookie ^ 0x1, cookie | 0x2, cookie &^ enumerateCookieTagMask} {
			if got, ok := decodeEnumerationCookie(bad); ok {
				t.Fatalf("decodeEnumerationCookie(%#x)=(%d,true), want fail-safe", bad, got)
			}
		}
	}
	for _, bad := range []uint64{0, 1, 2, 3, ^uint64(0), enumerateCookieMarker} {
		if cursor, ok := decodeEnumerationCookie(bad); ok {
			t.Fatalf("decodeEnumerationCookie(%#x)=(%d,true), want fail-safe", bad, cursor)
		}
	}
	if _, ok := encodeEnumerationCookie(0); ok {
		t.Fatal("encodeEnumerationCookie(0) succeeded")
	}
	if _, ok := encodeEnumerationCookie(enumerateCursorMax + 1); ok {
		t.Fatal("encodeEnumerationCookie(overflow) succeeded")
	}
}

// TestDaemonEnumerateOrderIsATotalOrderOverNames proves the ordering the
// cookies index is deterministic, strictly increasing, and independent of the
// order the merged listing arrived in — the property that lets a cursor resume
// a listing that was recomputed from scratch.
func TestDaemonEnumerateOrderIsATotalOrderOverNames(t *testing.T) {
	names := make([]string, 0, 500)
	for i := 0; i < 500; i++ {
		names = append(names, fmt.Sprintf("file-%06d.dat", i))
	}
	forward := orderEnumeration(dirEntriesNamed(names))
	reversed := make([]string, len(names))
	for i, name := range names {
		reversed[len(names)-1-i] = name
	}
	backward := orderEnumeration(dirEntriesNamed(reversed))
	if len(forward) != len(names) || len(backward) != len(names) {
		t.Fatalf("orderEnumeration dropped entries: %d/%d", len(forward), len(backward))
	}
	for i := range forward {
		if forward[i].entry.Name != backward[i].entry.Name || forward[i].cursor != backward[i].cursor {
			t.Fatalf("order depends on input order at %d: %q/%d vs %q/%d",
				i, forward[i].entry.Name, forward[i].cursor, backward[i].entry.Name, backward[i].cursor)
		}
		if i > 0 && forward[i].cursor <= forward[i-1].cursor {
			t.Fatalf("cursor not strictly increasing at %d: %d after %d", i, forward[i].cursor, forward[i-1].cursor)
		}
	}
	// Removing an entry must not move any other entry's resumption key.
	withoutOne := orderEnumeration(dirEntriesNamed(append(append([]string(nil), names[:100]...), names[101:]...)))
	keys := map[string]uint64{}
	for _, e := range forward {
		keys[e.entry.Name] = e.cursor
	}
	for _, e := range withoutOne {
		if keys[e.entry.Name] != e.cursor {
			t.Fatalf("removing an entry moved %q: %d -> %d", e.entry.Name, keys[e.entry.Name], e.cursor)
		}
	}
}
