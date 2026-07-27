package secure

import (
	"bytes"
	"testing"
)

const (
	keyA = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	keyB = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"
)

func TestAtRestSealOpenRoundTrip(t *testing.T) {
	a, err := NewAtRestFromKey(keyA)
	if err != nil || a == nil {
		t.Fatalf("build: %v", err)
	}
	pt := []byte("secret payload bytes")
	ct, err := a.Seal(pt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, pt) {
		t.Fatal("ciphertext contains the plaintext")
	}
	got, err := a.Open(ct)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("open = %q (err %v), want %q", got, err, pt)
	}
}

func TestAtRestNilIsPassThrough(t *testing.T) {
	var a *AtRest // disabled
	pt := []byte("plain")
	ct, _ := a.Seal(pt)
	if !bytes.Equal(ct, pt) {
		t.Fatal("nil Seal must pass through unchanged")
	}
	got, _ := a.Open(ct)
	if !bytes.Equal(got, pt) {
		t.Fatal("nil Open must pass through unchanged")
	}
	if a.Enabled() {
		t.Fatal("nil AtRest must report disabled")
	}
}

func TestAtRestWrongKeyFails(t *testing.T) {
	a, _ := NewAtRestFromKey(keyA)
	b, _ := NewAtRestFromKey(keyB)
	ct, _ := a.Seal([]byte("data"))
	if _, err := b.Open(ct); err == nil {
		t.Fatal("opening with the wrong key must fail authentication")
	}
}

func TestAtRestNonceIsRandomPerCall(t *testing.T) {
	a, _ := NewAtRestFromKey(keyA)
	ct1, _ := a.Seal([]byte("same"))
	ct2, _ := a.Seal([]byte("same"))
	if bytes.Equal(ct1, ct2) {
		t.Fatal("the same plaintext must seal to different ciphertext (fresh random nonce)")
	}
}

func TestAtRestKeyValidation(t *testing.T) {
	if a, err := NewAtRestFromKey(""); err != nil || a != nil {
		t.Fatalf("empty key must mean disabled, got a=%v err=%v", a, err)
	}
	if _, err := NewAtRestFromKey("tooshort"); err == nil {
		t.Fatal("a too-short key must error")
	}
	if _, err := NewAtRestFromKey("zz" + keyA[2:]); err == nil {
		t.Fatal("a non-hex key must error")
	}
}

func TestAtRestOpenShortInputFails(t *testing.T) {
	a, _ := NewAtRestFromKey(keyA)
	if _, err := a.Open([]byte{1, 2, 3}); err == nil {
		t.Fatal("ciphertext shorter than the nonce must fail")
	}
}
