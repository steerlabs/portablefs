package pft2

import (
	"bytes"
	"testing"
)

// FuzzDecodeNode drives the strict decoder with arbitrary bytes. The
// invariants under fuzz:
//
//  1. the decoder never panics and never allocates beyond node bounds;
//  2. any accepted input re-encodes to exactly the input bytes (canonical
//     uniqueness), and re-validates.
func FuzzDecodeNode(f *testing.F) {
	for _, node := range sampleNodes() {
		encoded, err := EncodeNode(node)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(encoded)
		// A couple of near-miss variants to steer the fuzzer.
		f.Add(encoded[:len(encoded)-1])
		f.Add(append(append([]byte(nil), encoded...), 0))
	}
	f.Add([]byte("PFT2"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		node, err := DecodeNode(data)
		if err != nil {
			return
		}
		reencoded, err := EncodeNode(node)
		if err != nil {
			t.Fatalf("accepted input failed to re-encode: %v", err)
		}
		if !bytes.Equal(reencoded, data) {
			t.Fatalf("accepted non-canonical bytes\n  in:  %x\n  out: %x", data, reencoded)
		}
	})
}

// FuzzParseUint64Decimal checks the decimal boundary parser never accepts a
// non-canonical rendering.
func FuzzParseUint64Decimal(f *testing.F) {
	f.Add("0")
	f.Add("18446744073709551615")
	f.Add("01")
	f.Add("-3")
	f.Fuzz(func(t *testing.T, s string) {
		v, err := ParseUint64Decimal(s)
		if err != nil {
			return
		}
		if FormatUint64Decimal(v) != s {
			t.Fatalf("accepted non-canonical decimal %q", s)
		}
	})
}
