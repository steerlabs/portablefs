package hydrator

import (
	"errors"
	"testing"
)

func TestBindingsRoundTrip(t *testing.T) {
	bindings := []Binding{
		{EntryIndex: 0, Identity: [16]byte{0, 0, 0, 129, 1, 2, 3}},
		{EntryIndex: 1, Identity: [16]byte{0, 0, 0, 129, 4, 5, 6}},
		{EntryIndex: 2, Identity: [16]byte{0, 0, 0, 129, 7, 8, 9}},
	}
	payload, err := EncodeBindings(bindings)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodeBindings(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(decoded) != len(bindings) {
		t.Fatalf("decoded %d of %d bindings", len(decoded), len(bindings))
	}
	for index, binding := range decoded {
		if binding != bindings[index] {
			t.Fatalf("binding %d does not round-trip", index)
		}
	}
}

func TestBindingsRefuseDamageAndDisorder(t *testing.T) {
	payload, err := EncodeBindings([]Binding{{EntryIndex: 0}, {EntryIndex: 1, Identity: [16]byte{9}}})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	damaged := append([]byte(nil), payload...)
	damaged[bindingsHeader+8] ^= 0xff
	if _, err := DecodeBindings(damaged); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a damaged table passed its seal: %v", err)
	}
	truncated := payload[:len(payload)-1]
	if _, err := DecodeBindings(truncated); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a truncated table was accepted: %v", err)
	}
	foreign := append([]byte(nil), payload...)
	foreign[0] = 'X'
	if _, err := DecodeBindings(foreign); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a table with no magic was accepted: %v", err)
	}
	if _, err := EncodeBindings(nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an empty table was encoded: %v", err)
	}
	if _, err := EncodeBindings([]Binding{{EntryIndex: 4}, {EntryIndex: 2}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bindings out of entry order were encoded: %v", err)
	}
}
