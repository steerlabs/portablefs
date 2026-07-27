package pfc2

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

// FuzzDecode: any accepted record payload must be canonical (re-encode gives
// the identical bytes) and structurally valid.
func FuzzDecode(f *testing.F) {
	for _, g := range goldenRecords() {
		raw, err := hex.DecodeString(g.hex)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	f.Add([]byte("PFC2"))
	f.Fuzz(func(t *testing.T, payload []byte) {
		rec, err := Decode(payload)
		if err != nil {
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("decode rejection is not typed ErrMalformed: %v", err)
			}
			return
		}
		re, err := Encode(&rec)
		if err != nil {
			t.Fatalf("accepted payload does not re-encode: %v", err)
		}
		if !bytes.Equal(re, payload) {
			t.Fatalf("accepted payload is not canonical:\n in %x\nout %x", payload, re)
		}
	})
}

// FuzzDecodeEntry: same canonicality property for control-map entries.
func FuzzDecodeEntry(f *testing.F) {
	for _, g := range goldenEntries() {
		raw, err := hex.DecodeString(g.value)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, payload []byte) {
		entry, err := DecodeEntry(payload)
		if err != nil {
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("entry rejection is not typed ErrMalformed: %v", err)
			}
			return
		}
		re, err := EncodeEntry(&entry)
		if err != nil {
			t.Fatalf("accepted entry does not re-encode: %v", err)
		}
		if !bytes.Equal(re, payload) {
			t.Fatalf("accepted entry is not canonical:\n in %x\nout %x", payload, re)
		}
	})
}

// FuzzApply: arbitrary decoded records driven at a live reducer either apply
// or fail with exactly one typed error, and a failed apply leaves the state
// digest untouched.
func FuzzApply(f *testing.F) {
	for _, g := range goldenRecords() {
		raw, err := hex.DecodeString(g.hex)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, payload []byte) {
		rec, err := Decode(payload)
		if err != nil {
			return
		}
		st := NewState()
		if _, err := st.Apply(openAt("pfs-fuzz", 1, t0)); err != nil {
			t.Fatal(err)
		}
		if _, err := st.Apply(pinRec("pfs-fuzz", 1, 42, false)); err != nil {
			t.Fatal(err)
		}
		before, err := st.Project().Digest()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.Apply(&rec); err != nil {
			n := 0
			for _, root := range []error{ErrMalformed, ErrCapacity, ErrIntegrity, ErrFence} {
				if errors.Is(err, root) {
					n++
				}
			}
			if n != 1 {
				t.Fatalf("apply error matches %d typed roots: %v", n, err)
			}
			after, derr := st.Project().Digest()
			if derr != nil {
				t.Fatal(derr)
			}
			if after != before {
				t.Fatal("failed apply mutated state")
			}
			return
		}
		// A successful apply must survive projection round trip.
		p := st.Project()
		rebuilt, err := Rebuild(p)
		if err != nil {
			t.Fatalf("projection after fuzz apply does not rebuild: %v", err)
		}
		d1, err := p.Digest()
		if err != nil {
			t.Fatal(err)
		}
		d2, err := rebuilt.Project().Digest()
		if err != nil {
			t.Fatal(err)
		}
		if d1 != d2 {
			t.Fatal("projection round trip diverged after fuzz apply")
		}
	})
}

// FuzzEpoch: the decimal successor function agrees with the validation
// domain: Next of a valid epoch is valid and strictly greater.
func FuzzEpoch(f *testing.F) {
	f.Add("1")
	f.Add("9")
	f.Add("9223372036854775806")
	f.Add(EpochBound)
	f.Add("00")
	f.Fuzz(func(t *testing.T, s string) {
		e := Epoch(s)
		if err := e.Validate(); err != nil {
			return
		}
		next, err := e.Next()
		if err != nil {
			if !errors.Is(err, ErrCapacity) {
				t.Fatalf("epoch exhaustion is not typed: %v", err)
			}
			if string(e) != EpochBound {
				t.Fatalf("premature exhaustion at %s", e)
			}
			return
		}
		if err := next.Validate(); err != nil {
			t.Fatalf("Next(%s)=%s is invalid: %v", e, next, err)
		}
		if e.Compare(next) != -1 || next.Compare(e) != 1 {
			t.Fatalf("Next(%s)=%s does not compare greater", e, next)
		}
	})
}
