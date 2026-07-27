package portablefsd

import (
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// TestConsumeExpectedTruncate pins the marked-truncate note protocol that
// keeps the daemon's kernel-size refreshes invisible to the authority: only
// a pure size-set matching the noted size consumes the note; mode/ownership
// changes never match; a size mismatch retires the note (the kernel is doing
// a REAL truncate that must reach the authority); expired notes never match;
// and every note is single-use.
func TestConsumeExpectedTruncate(t *testing.T) {
	size := func(v uint64) *uint64 { return &v }
	mode := uint32(0o600)

	a := &attach{}
	note := func(p string, itemID uint64, sz int64, ttl time.Duration) {
		a.mu.Lock()
		if a.expectedTruncates == nil {
			a.expectedTruncates = map[string]expectedTruncate{}
		}
		a.expectedTruncates[p] = expectedTruncate{
			itemID: itemID, size: sz, deadline: time.Now().Add(ttl),
		}
		a.mu.Unlock()
	}
	request := func(itemID uint64, sz uint64) *pfslocal.SetAttrRequest {
		return &pfslocal.SetAttrRequest{
			Item: pfslocal.Item{ItemID: itemID},
			Size: size(sz),
		}
	}

	// No note: never consumed.
	if a.consumeExpectedTruncate("f", request(7, 22)) {
		t.Fatal("consumed without a note")
	}
	// Matching size-only request consumes exactly once.
	note("f", 7, 22, time.Minute)
	if !a.consumeExpectedTruncate("f", request(7, 22)) {
		t.Fatal("matching refresh truncate not consumed")
	}
	if a.consumeExpectedTruncate("f", request(7, 22)) {
		t.Fatal("note consumed twice")
	}
	// A mode-bearing setattr is a real application request even if size matches.
	note("f", 7, 22, time.Minute)
	withMode := request(7, 22)
	withMode.Mode = &mode
	if a.consumeExpectedTruncate("f", withMode) {
		t.Fatal("application setattr with mode was suppressed")
	}
	// Size mismatch: a REAL truncate races the note; it must pass through AND
	// retire the note so it cannot suppress anything later.
	if a.consumeExpectedTruncate("f", request(7, 7)) {
		t.Fatal("mismatched truncate was suppressed")
	}
	if a.consumeExpectedTruncate("f", request(7, 22)) {
		t.Fatal("note survived a mismatched truncate")
	}
	// Expired notes never match.
	note("f", 7, 22, -time.Second)
	if a.consumeExpectedTruncate("f", request(7, 22)) {
		t.Fatal("expired note consumed")
	}
	// A rename between secure open and ftruncate changes the current path but
	// not the descriptor's FSItem identity. The moved marker must still be
	// consumed so the refresh cannot mutate the item's new authority path.
	note("old-name", 7, 22, time.Minute)
	if !a.consumeExpectedTruncate("new-name", request(7, 22)) {
		t.Fatal("renamed FSItem refresh note not consumed")
	}
}
