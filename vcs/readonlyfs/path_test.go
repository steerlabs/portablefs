package readonlyfs

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestPathKeyRoundTripPreservesRawNames(t *testing.T) {
	components := [][]byte{[]byte("src"), {0xff, 0xfe, 'x'}, []byte("name with spaces")}
	key, err := EncodePath(components)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodePath(key)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != len(components) {
		t.Fatalf("decoded %d components, want %d", len(decoded), len(components))
	}
	for index := range components {
		if !bytes.Equal(decoded[index], components[index]) {
			t.Fatalf("component %d changed: got %x want %x", index, decoded[index], components[index])
		}
	}
}

func TestRootPathKeyIsEmpty(t *testing.T) {
	key, err := EncodePath(nil)
	if err != nil || key != "" {
		t.Fatalf("EncodePath(nil) = %q, %v", key, err)
	}
	components, err := DecodePath("")
	if err != nil || len(components) != 0 {
		t.Fatalf("DecodePath(root) = %#v, %v", components, err)
	}
}

func TestAppendPathBuildsOneCanonicalKey(t *testing.T) {
	parent, err := EncodePath([][]byte{[]byte("parent")})
	if err != nil {
		t.Fatal(err)
	}
	child, err := AppendPath(parent, []byte("child"))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodePath(child)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || string(decoded[0]) != "parent" || string(decoded[1]) != "child" {
		t.Fatalf("unexpected child components: %#v", decoded)
	}
}

func TestPathKeyRejectsUnsafeOrOversizedComponents(t *testing.T) {
	cases := [][][]byte{
		{nil},
		{[]byte(".")},
		{[]byte("..")},
		{[]byte("a/b")},
		{[]byte{'a', 0, 'b'}},
		{bytes.Repeat([]byte{'a'}, maxNameBytes+1)},
	}
	for _, components := range cases {
		if _, err := EncodePath(components); err == nil {
			t.Fatalf("EncodePath(%q) unexpectedly succeeded", components)
		}
	}
	tooLong := make([][]byte, 17)
	for index := range tooLong {
		tooLong[index] = bytes.Repeat([]byte{'x'}, maxNameBytes)
	}
	if _, err := EncodePath(tooLong); err == nil {
		t.Fatal("oversized path unexpectedly succeeded")
	}
}

func TestDecodePathRejectsNonCanonicalAndMalformedKeys(t *testing.T) {
	for _, key := range []string{
		base64.URLEncoding.EncodeToString([]byte("name")),
		"not+base64url",
		base64.RawURLEncoding.EncodeToString([]byte("../escape")),
		base64.RawURLEncoding.EncodeToString([]byte("one\x00\x00two")),
		strings.Repeat("A", base64.RawURLEncoding.EncodedLen(maxPathBytes)+1),
	} {
		if _, err := DecodePath(key); err == nil {
			t.Fatalf("DecodePath(%q) unexpectedly succeeded", key)
		}
	}
}
