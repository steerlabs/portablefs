package secure

import (
	"bytes"
	"crypto/rand"
	"strings"
	"sync"
	"testing"
)

// AES-256-GCM framing constants (nonce || ciphertext || tag). The plaintext and
// ciphertext are equal length under GCM (it's a stream cipher with a separate
// tag), so a sealed blob of an n-byte payload is exactly nonceSize+n+tagSize.
const (
	nonceSize = 12
	tagSize   = 16
	overhead  = nonceSize + tagSize // 28: the size of a sealed empty payload
)

func newAtRest(t *testing.T, hexKey string) *AtRest {
	t.Helper()
	a, err := NewAtRestFromKey(hexKey)
	if err != nil {
		t.Fatalf("NewAtRestFromKey: %v", err)
	}
	if a == nil {
		t.Fatal("expected an enabled AtRest, got nil")
	}
	return a
}

// ----- Round-trip across payload sizes (zero / small / boundary / large) -----

func TestSealOpenRoundTripSizes(t *testing.T) {
	a := newAtRest(t, keyA)

	// Sizes chosen around the GCM block size (16) and a few powers of two, plus a
	// large multi-MB payload. Includes the empty payload (0).
	sizes := []int{0, 1, 2, 15, 16, 17, 31, 32, 33, 63, 64, 127, 128, 255, 256, 1023, 1024, 4096, 65535, 1 << 20}
	for _, n := range sizes {
		pt := make([]byte, n)
		if _, err := rand.Read(pt); err != nil {
			t.Fatalf("rand: %v", err)
		}
		ct, err := a.Seal(pt)
		if err != nil {
			t.Fatalf("Seal(%d): %v", n, err)
		}
		// Framing: sealed length is exactly nonce + n + tag.
		if len(ct) != overhead+n {
			t.Fatalf("size %d: sealed len = %d, want %d", n, len(ct), overhead+n)
		}
		got, err := a.Open(ct)
		if err != nil {
			t.Fatalf("Open(%d): %v", n, err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("size %d: round-trip mismatch", n)
		}
	}
}

// TestSealEmptyPayload: an empty plaintext seals to exactly the overhead (nonce +
// tag) and opens back to an empty, non-nil-or-nil slice equal to the input.
func TestSealEmptyPayload(t *testing.T) {
	a := newAtRest(t, keyA)
	ct, err := a.Seal([]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) != overhead {
		t.Fatalf("sealed empty len = %d, want %d", len(ct), overhead)
	}
	got, err := a.Open(ct)
	if err != nil {
		t.Fatalf("Open empty: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("opened empty payload len = %d, want 0", len(got))
	}
}

// TestSealNilPayload: a nil plaintext (distinct from empty slice) seals and opens.
func TestSealNilPayload(t *testing.T) {
	a := newAtRest(t, keyA)
	ct, err := a.Seal(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) != overhead {
		t.Fatalf("sealed nil len = %d, want %d", len(ct), overhead)
	}
	got, err := a.Open(ct)
	if err != nil || len(got) != 0 {
		t.Fatalf("Open(seal(nil)) = %v (err %v), want empty", got, err)
	}
}

// ----- Ciphertext independence / no plaintext leakage -----

// TestSealOutputIndependentOfPlaintextSlice: the doc says the returned slice is
// independent of plaintext (safe to retain). Mutating the plaintext after Seal
// must not change the ciphertext, and Open must still recover the original bytes.
func TestSealOutputIndependentOfPlaintextSlice(t *testing.T) {
	a := newAtRest(t, keyA)
	pt := []byte("mutable-plaintext-buffer")
	orig := append([]byte(nil), pt...)
	ct, err := a.Seal(pt)
	if err != nil {
		t.Fatal(err)
	}
	ctCopy := append([]byte(nil), ct...)
	// Scribble over the plaintext buffer.
	for i := range pt {
		pt[i] = 0
	}
	if !bytes.Equal(ct, ctCopy) {
		t.Fatal("ciphertext changed when the plaintext buffer was mutated (not independent)")
	}
	got, err := a.Open(ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, orig) {
		t.Fatal("Open did not recover the original plaintext after the buffer was scribbled")
	}
}

func TestSealDoesNotContainPlaintext(t *testing.T) {
	a := newAtRest(t, keyA)
	pt := bytes.Repeat([]byte("SECRET-"), 64) // a recognizable repeated marker
	ct, err := a.Seal(pt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, []byte("SECRET-")) {
		t.Fatal("ciphertext leaks a plaintext marker")
	}
}

// ----- Wrong key -----

func TestWrongKeyFailsToOpen(t *testing.T) {
	a := newAtRest(t, keyA)
	b := newAtRest(t, keyB)
	for _, n := range []int{0, 1, 16, 100, 4096} {
		pt := make([]byte, n)
		_, _ = rand.Read(pt)
		ct, err := a.Seal(pt)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := b.Open(ct); err == nil {
			t.Fatalf("size %d: wrong key must fail to Open", n)
		}
	}
}

// TestSwappedKeysSymmetric: A cannot open B's blob either (both directions fail).
func TestSwappedKeysSymmetric(t *testing.T) {
	a := newAtRest(t, keyA)
	b := newAtRest(t, keyB)
	ctB, _ := b.Seal([]byte("from B"))
	if _, err := a.Open(ctB); err == nil {
		t.Fatal("A must not open B's ciphertext")
	}
}

// ----- Single-byte tampering at every position -----

// TestTamperEveryBytePosition flips every single byte of a sealed blob (nonce,
// ciphertext, and tag regions all covered) and asserts Open fails authentication
// for each. This is the core at-rest integrity guarantee: no single-byte
// corruption is ever returned as valid plaintext.
func TestTamperEveryBytePosition(t *testing.T) {
	a := newAtRest(t, keyA)
	pt := []byte("integrity-protected payload, longer than one block")
	ct, err := a.Seal(pt)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) <= overhead {
		t.Fatalf("expected a non-empty ciphertext region, len=%d", len(ct))
	}
	for i := 0; i < len(ct); i++ {
		tampered := append([]byte(nil), ct...)
		tampered[i] ^= 0x01 // flip one bit of one byte
		if _, err := a.Open(tampered); err == nil {
			region := classifyByte(i, len(ct))
			t.Fatalf("flipping byte %d (%s) did not fail authentication", i, region)
		}
	}
}

// classifyByte names which framing region an index falls in (for diagnostics).
func classifyByte(i, total int) string {
	switch {
	case i < nonceSize:
		return "nonce"
	case i >= total-tagSize:
		return "tag"
	default:
		return "ciphertext"
	}
}

// TestTamperTruncation: dropping the last byte (a too-short tag) must fail.
func TestTamperTruncation(t *testing.T) {
	a := newAtRest(t, keyA)
	ct, _ := a.Seal([]byte("abc"))
	if _, err := a.Open(ct[:len(ct)-1]); err == nil {
		t.Fatal("a truncated ciphertext must fail to Open")
	}
}

// TestTamperExtraByte: appending a stray byte must fail authentication.
func TestTamperExtraByte(t *testing.T) {
	a := newAtRest(t, keyA)
	ct, _ := a.Seal([]byte("abc"))
	ct = append(ct, 0x00)
	if _, err := a.Open(ct); err == nil {
		t.Fatal("an over-long ciphertext must fail to Open")
	}
}

// ----- Framing edges around the nonce/tag boundaries -----

// TestOpenShortInputs sweeps every length from 0 up to one below the minimum valid
// sealed blob (overhead-1) plus exactly the nonce size, asserting Open fails on all
// of them (either the explicit length guard for < nonceSize, or GCM auth for an
// absent/short tag from nonceSize .. overhead-1). None may panic.
func TestOpenShortInputs(t *testing.T) {
	a := newAtRest(t, keyA)
	for n := 0; n < overhead; n++ {
		data := make([]byte, n)
		_, _ = rand.Read(data)
		got, err := a.Open(data)
		if err == nil {
			t.Fatalf("Open of a %d-byte blob (< minimum %d) must fail, got %d bytes", n, overhead, len(got))
		}
	}
}

// TestOpenExactlyNonceLenFails: a blob exactly nonceSize bytes passes the explicit
// length check but has an empty ciphertext+tag, so GCM authentication must fail.
func TestOpenExactlyNonceLenFails(t *testing.T) {
	a := newAtRest(t, keyA)
	data := make([]byte, nonceSize)
	_, _ = rand.Read(data)
	if _, err := a.Open(data); err == nil {
		t.Fatal("a blob with a nonce but no ciphertext/tag must fail authentication")
	}
}

// TestOpenShortInputErrorMessage: the explicit guard for data shorter than the
// nonce reports a clear error (locks in the user-facing message contract).
func TestOpenShortInputErrorMessage(t *testing.T) {
	a := newAtRest(t, keyA)
	_, err := a.Open([]byte{1, 2, 3})
	if err == nil {
		t.Fatal("short input must error")
	}
	if !strings.Contains(err.Error(), "shorter than the nonce") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

// TestOpenEmptyInputFails: zero-length data is shorter than the nonce -> error.
func TestOpenEmptyInputFails(t *testing.T) {
	a := newAtRest(t, keyA)
	if _, err := a.Open(nil); err == nil {
		t.Fatal("Open(nil) must fail")
	}
	if _, err := a.Open([]byte{}); err == nil {
		t.Fatal("Open(empty) must fail")
	}
}

// TestOpenAllZeroMinimalBlob: a 28-byte all-zero blob (valid framing length) must
// fail authentication — a zeroed nonce+ciphertext+tag is not a valid GCM tag.
func TestOpenAllZeroMinimalBlob(t *testing.T) {
	a := newAtRest(t, keyA)
	data := make([]byte, overhead) // all zeros
	if _, err := a.Open(data); err == nil {
		t.Fatal("an all-zero minimal blob must fail authentication")
	}
}

// ----- Nonce uniqueness -----

// TestNonceUniquePerSeal: many seals of the same plaintext must all differ
// (fresh random nonce each call) and all still open to the same plaintext.
func TestNonceUniquePerSeal(t *testing.T) {
	a := newAtRest(t, keyA)
	pt := []byte("repeated plaintext")
	const n = 256
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		ct, err := a.Seal(pt)
		if err != nil {
			t.Fatal(err)
		}
		nonce := string(ct[:nonceSize])
		if _, dup := seen[nonce]; dup {
			t.Fatalf("nonce collision at seal %d", i)
		}
		seen[nonce] = struct{}{}
		got, err := a.Open(ct)
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("seal %d did not round-trip", i)
		}
	}
}

// ----- nil receiver pass-through edges -----

func TestNilReceiverPassThroughSizes(t *testing.T) {
	var a *AtRest // disabled
	if a.Enabled() {
		t.Fatal("nil AtRest must be disabled")
	}
	for _, n := range []int{0, 1, 1024} {
		pt := make([]byte, n)
		_, _ = rand.Read(pt)
		ct, err := a.Seal(pt)
		if err != nil {
			t.Fatalf("nil Seal err: %v", err)
		}
		if !bytes.Equal(ct, pt) {
			t.Fatalf("nil Seal must pass through unchanged (size %d)", n)
		}
		got, err := a.Open(ct)
		if err != nil {
			t.Fatalf("nil Open err: %v", err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("nil Open must pass through unchanged (size %d)", n)
		}
	}
}

// TestNilReceiverOpenDoesNotEnforceFraming: with encryption disabled, Open is a
// pass-through and does NOT apply the nonce-length guard (a 3-byte blob comes back
// verbatim). This documents the opt-in semantics.
func TestNilReceiverOpenShortPassThrough(t *testing.T) {
	var a *AtRest
	in := []byte{1, 2, 3}
	got, err := a.Open(in)
	if err != nil {
		t.Fatalf("nil Open err: %v", err)
	}
	if !bytes.Equal(got, in) {
		t.Fatal("nil Open must return short input unchanged (no framing enforced when disabled)")
	}
}

// ----- Cross-instance with the same key (interoperability) -----

// TestSameKeyDifferentInstanceInterop: two AtRest built from the same key bytes
// must interoperate — one seals, the other opens. (No per-instance state beyond
// the key affects the ciphertext.)
func TestSameKeyDifferentInstanceInterop(t *testing.T) {
	a := newAtRest(t, keyA)
	b := newAtRest(t, keyA)
	pt := []byte("portable across instances")
	ct, err := a.Seal(pt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := b.Open(ct)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("same-key instance B could not open A's blob: %v err=%v", got, err)
	}
}

// ----- Key validation edges -----

func TestKeyValidationEdges(t *testing.T) {
	// Empty -> disabled (nil, nil).
	if a, err := NewAtRestFromKey(""); a != nil || err != nil {
		t.Fatalf("empty key: a=%v err=%v, want nil,nil", a, err)
	}
	// 31 bytes (62 hex) -> too short.
	if _, err := NewAtRestFromKey(strings.Repeat("ab", 31)); err == nil {
		t.Fatal("a 31-byte key must error")
	}
	// 33 bytes (66 hex) -> too long.
	if _, err := NewAtRestFromKey(strings.Repeat("ab", 33)); err == nil {
		t.Fatal("a 33-byte key must error")
	}
	// Exactly 32 bytes (64 hex) -> valid.
	if a, err := NewAtRestFromKey(strings.Repeat("ab", 32)); err != nil || a == nil {
		t.Fatalf("a 64-hex key must be valid: a=%v err=%v", a, err)
	}
	// Odd hex length -> decode error.
	if _, err := NewAtRestFromKey(strings.Repeat("a", 63)); err == nil {
		t.Fatal("an odd-length hex key must error")
	}
	// Non-hex characters -> decode error.
	if _, err := NewAtRestFromKey("zz" + keyA[2:]); err == nil {
		t.Fatal("a non-hex key must error")
	}
	// Uppercase hex is accepted by encoding/hex; the key still builds.
	if a, err := NewAtRestFromKey(strings.ToUpper(keyA)); err != nil || a == nil {
		t.Fatalf("uppercase hex key must build: a=%v err=%v", a, err)
	}
}

// TestUppercaseHexSameKey: uppercase and lowercase forms of the same hex key
// decode to the same bytes, so a blob sealed by one opens with the other.
func TestUppercaseHexSameKey(t *testing.T) {
	lower := newAtRest(t, keyA)
	upper := newAtRest(t, strings.ToUpper(keyA))
	ct, _ := lower.Seal([]byte("case-insensitive key"))
	got, err := upper.Open(ct)
	if err != nil || !bytes.Equal(got, []byte("case-insensitive key")) {
		t.Fatalf("uppercase-key instance could not open: %v err=%v", got, err)
	}
}

// ----- Concurrency (-race) -----

// TestConcurrentSealOpen: a single shared AtRest is used by many goroutines doing
// Seal+Open concurrently. AES-GCM's Seal/Open are safe for concurrent use; this
// guards against any accidental shared mutable state and runs under -race.
func TestConcurrentSealOpen(t *testing.T) {
	a := newAtRest(t, keyA)
	const goroutines, perG = 32, 500
	var wg sync.WaitGroup
	errCh := make(chan error, goroutines)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			pt := make([]byte, 64+g)
			for i := range pt {
				pt[i] = byte(g + i)
			}
			for i := 0; i < perG; i++ {
				ct, err := a.Seal(pt)
				if err != nil {
					errCh <- err
					return
				}
				got, err := a.Open(ct)
				if err != nil {
					errCh <- err
					return
				}
				if !bytes.Equal(got, pt) {
					errCh <- errMismatch
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent seal/open: %v", err)
	}
}

// TestConcurrentCrossOpen: goroutines seal into a shared channel; other goroutines
// open them. Exercises hand-off of ciphertext between goroutines under -race.
func TestConcurrentCrossOpen(t *testing.T) {
	a := newAtRest(t, keyA)
	const n = 2000
	pt := []byte("shared-payload")
	ch := make(chan []byte, 64)

	var producers sync.WaitGroup
	for p := 0; p < 4; p++ {
		producers.Add(1)
		go func() {
			defer producers.Done()
			for i := 0; i < n/4; i++ {
				ct, err := a.Seal(pt)
				if err != nil {
					panic(err)
				}
				ch <- ct
			}
		}()
	}
	go func() { producers.Wait(); close(ch) }()

	var consumers sync.WaitGroup
	errCh := make(chan error, 8)
	for c := 0; c < 8; c++ {
		consumers.Add(1)
		go func() {
			defer consumers.Done()
			for ct := range ch {
				got, err := a.Open(ct)
				if err != nil {
					errCh <- err
					return
				}
				if !bytes.Equal(got, pt) {
					errCh <- errMismatch
					return
				}
			}
		}()
	}
	consumers.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("cross-goroutine open: %v", err)
	}
}

var errMismatch = errString("round-trip mismatch")

type errString string

func (e errString) Error() string { return string(e) }
