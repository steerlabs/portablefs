package fsproto

import (
	"bytes"
	"context"
	"encoding/gob"
	"testing"
)

// legacyResponse is a byte-for-byte stand-in for a PRE-change client's view of
// Response: every field the old build knew, and none of the new ones. Decoding a
// new server's reply into it is the wire-compatibility argument, run rather than
// asserted.
type legacyResponse struct {
	Status         int32
	Attr           *Attr
	Entries        []Dirent
	Data           []byte
	Target         string
	Count          int32
	Version        uint64
	Gen            uint64
	ParentVersion  uint64
	AppliedThrough uint64
	OrphanIno      uint64
	ProtoVersion   uint32
	Features       uint64
	Ino            uint64
	Duplicate      bool
}

// TestPostAttrsAreAdditiveOnTheWire proves both directions of the additive
// change: a pre-change client decoding a new authority's mutation reply gets
// every field it knew, unchanged, and silently drops PostAttrs; and a new client
// decoding a pre-change authority's reply sees no PostAttrs, which is precisely
// the state in which it keeps evicting instead of installing.
func TestPostAttrsAreAdditiveOnTheWire(t *testing.T) {
	newReply := Response{
		Status: OK, Gen: 7, Version: 42, Ino: 99, Count: 4096,
		Attr: &Attr{Kind: "file", Size: 4096, Ino: 99},
		PostAttrs: []PathAttr{
			{Path: "d/f", Exists: true, Attr: Attr{Kind: "file", Size: 4096, Ino: 99}},
			{Path: "d", Exists: true, Attr: Attr{Kind: "directory", Ino: 3}},
			{Path: "d/gone"},
		},
	}

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(&newReply); err != nil {
		t.Fatalf("encode new reply: %v", err)
	}
	var old legacyResponse
	if err := gob.NewDecoder(bytes.NewReader(buf.Bytes())).Decode(&old); err != nil {
		t.Fatalf("pre-change client could not decode a new authority's reply: %v", err)
	}
	if old.Status != OK || old.Gen != 7 || old.Version != 42 || old.Ino != 99 || old.Count != 4096 {
		t.Fatalf("pre-change client saw a changed reply: %+v", old)
	}
	if old.Attr == nil || old.Attr.Size != 4096 || old.Attr.Ino != 99 {
		t.Fatalf("pre-change client lost the convenience attr: %+v", old.Attr)
	}

	// The other direction: an authority that predates the field.
	buf.Reset()
	if err := gob.NewEncoder(&buf).Encode(&legacyResponse{Status: OK, Gen: 7, Version: 42, Ino: 99}); err != nil {
		t.Fatalf("encode legacy reply: %v", err)
	}
	var fresh Response
	if err := gob.NewDecoder(bytes.NewReader(buf.Bytes())).Decode(&fresh); err != nil {
		t.Fatalf("new client could not decode a pre-change authority's reply: %v", err)
	}
	if len(fresh.PostAttrs) != 0 {
		t.Fatalf("a pre-change reply produced %d post attrs", len(fresh.PostAttrs))
	}
}

// TestPostAttrCollectionIsGatedOnTheNegotiatedCapability pins that the install
// lane is selected from the probe bit and never from the reply's shape, and that
// a DUPLICATE exact replay — whose stored outcome carries no fresh ordered-apply
// observation — never contributes one.
func TestPostAttrCollectionIsGatedOnTheNegotiatedCapability(t *testing.T) {
	reply := &Response{
		Status: OK, Gen: 7, Version: 42,
		PostAttrs: []PathAttr{{Path: "d/f", Exists: true, Attr: Attr{Kind: "file"}}},
	}

	// No negotiated session at all: Features() is zero, so nothing is collected
	// even though the reply carries attributes.
	c := &Client{}
	var sink PostAttrSink
	ctx := WithPostAttrs(context.Background(), &sink)
	c.collectPostAttrs(ctx, reply)
	if got := len(sink.Observations()); got != 0 {
		t.Fatalf("collected %d observations without the negotiated capability", got)
	}

	c.exactMu.Lock()
	c.exact = &exactSession{features: FeatureMutationAttrs}
	c.exactMu.Unlock()
	c.collectPostAttrs(ctx, reply)
	obs := sink.Observations()
	if len(obs) != 1 || obs[0].Gen != 7 || obs[0].Version != 42 || len(obs[0].Attrs) != 1 {
		t.Fatalf("negotiated collection produced %+v", obs)
	}

	dup := *reply
	dup.Duplicate = true
	c.collectPostAttrs(ctx, &dup)
	if got := len(sink.Observations()); got != 1 {
		t.Fatalf("a duplicate replay contributed an observation (%d total)", got)
	}
}
