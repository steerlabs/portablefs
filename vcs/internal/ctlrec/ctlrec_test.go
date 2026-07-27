package ctlrec

import (
	"crypto/sha256"
	"strings"
	"testing"
)

func TestV2SnapshotRoundTripPreservesCompleteSlotAndOrphan(t *testing.T) {
	reqHash := sha256.Sum256([]byte("request"))
	payload := Payload{Kind: KindSnapshot, Snapshot: &Snapshot{
		AsOfLSN: 7,
		Sessions: []SessionState{{
			SessionID: "s", Generation: 2, Slots: 4,
			SlotStates: []SlotState{{Slot: 1, SlotSeq: 9, ReqHash: reqHash[:], Status: 3, Count: 4, Version: 5, Offset: 6, Ino: 7, OrphanIno: 8}},
		}},
		Orphans: []OrphanState{{
			Ino: 8, Name: "gone", Kind: "file", Mode: 0o600, Size: 3, Born: true,
			Blocks: []DirtyBlock{{Index: 0, Data: []byte("abc")}},
		}},
	}}
	encoded, err := Encode(payload)
	if err != nil {
		t.Fatal(err)
	}
	if encoded[0] != Version {
		t.Fatalf("wire version=%d want=%d", encoded[0], Version)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	slot := decoded.Snapshot.Sessions[0].SlotStates[0]
	if slot.OrphanIno != 8 || slot.Ino != 7 || slot.Version != 5 {
		t.Fatalf("slot outcome did not round-trip: %+v", slot)
	}
	orphan := decoded.Snapshot.Orphans[0]
	if orphan.Ino != 8 || len(orphan.Blocks) != 1 || string(orphan.Blocks[0].Data) != "abc" {
		t.Fatalf("orphan sidecar did not round-trip: %+v", orphan)
	}
}

func TestSessionRenewRoundTripAndTaggedUnionValidation(t *testing.T) {
	tokenHash := sha256.Sum256([]byte("token"))
	payload := Payload{Kind: KindSessionRenew, SessionRenew: &SessionRenew{
		SessionID: "s", Generation: 3, TokenHash: tokenHash[:], ExpiresMs: 12345,
	}}
	encoded, err := Encode(payload)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.SessionRenew == nil || decoded.SessionRenew.Generation != 3 || decoded.SessionRenew.ExpiresMs != 12345 {
		t.Fatalf("renewal round trip = %+v", decoded.SessionRenew)
	}
	if _, err := Encode(Payload{Kind: KindSessionRenew, SessionRenew: payload.SessionRenew, Session: &Session{SessionID: "s", Slots: 1}}); err == nil {
		t.Fatal("multiple tagged-union values must fail")
	}
	if _, err := Encode(Payload{Kind: KindSessionRenew, SessionRenew: &SessionRenew{SessionID: "s", TokenHash: []byte("short"), ExpiresMs: 1}}); err == nil {
		t.Fatal("short renewal token hash must fail")
	}

	withTrailing := append(append([]byte(nil), encoded...), 0xff)
	if _, err := Decode(withTrailing); err == nil {
		t.Fatal("trailing payload bytes must fail closed")
	}
}

func TestDecodeAcceptsLegacyV1AndRejectsUnknownVersion(t *testing.T) {
	encoded, err := Encode(Payload{Kind: KindSession, Session: &Session{SessionID: "s", Generation: 1, Slots: 1}})
	if err != nil {
		t.Fatal(err)
	}
	encoded[0] = legacyVersion
	if _, err := Decode(encoded); err != nil {
		t.Fatalf("legacy v1 record: %v", err)
	}
	encoded[0] = Version + 1
	if _, err := Decode(encoded); err == nil {
		t.Fatal("unknown control version must fail closed")
	}
}

func TestSnapshotValidationFailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		orphan OrphanState
		want   string
	}{
		{name: "zero inode", orphan: OrphanState{Kind: "file"}, want: "zero inode"},
		{name: "unknown kind", orphan: OrphanState{Ino: 1, Kind: "socket"}, want: "invalid kind"},
		{name: "non-file content", orphan: OrphanState{Ino: 1, Kind: "directory", Born: true}, want: "non-file"},
		{name: "duplicate block", orphan: OrphanState{Ino: 1, Kind: "file", Blocks: []DirtyBlock{{Index: 0}, {Index: 0}}}, want: "unsorted/duplicate"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Encode(Payload{Kind: KindSnapshot, Snapshot: &Snapshot{Orphans: []OrphanState{tc.orphan}}})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v want substring %q", err, tc.want)
			}
		})
	}
}

func TestSnapshotSessionAndWatermarkBoundsFailClosed(t *testing.T) {
	hash := sha256.Sum256([]byte("request"))
	token := sha256.Sum256([]byte("token"))
	valid := SessionState{
		SessionID: "s", Generation: 1, Owner: "owner", TokenHash: token[:], Slots: 1,
		SlotStates: []SlotState{{Slot: 0, SlotSeq: 1, ReqHash: hash[:]}},
	}
	for name, snapshot := range map[string]*Snapshot{
		"duplicate session":   {Sessions: []SessionState{valid, valid}},
		"duplicate watermark": {Watermarks: []FlushWatermark{{SessionID: "s"}, {SessionID: "s"}}},
		"duplicate slot": {Sessions: []SessionState{{
			SessionID: "s", TokenHash: token[:], Slots: 2,
			SlotStates: []SlotState{{Slot: 0, SlotSeq: 1, ReqHash: hash[:]}, {Slot: 0, SlotSeq: 2, ReqHash: hash[:]}},
		}}},
		"bad request hash": {Sessions: []SessionState{{
			SessionID: "s", TokenHash: token[:], Slots: 1,
			SlotStates: []SlotState{{Slot: 0, SlotSeq: 1, ReqHash: []byte("short")}},
		}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Encode(Payload{Kind: KindSnapshot, Snapshot: snapshot}); err == nil {
				t.Fatal("malformed snapshot accepted")
			}
		})
	}

	tooMany := &Snapshot{Sessions: make([]SessionState, MaxSessions+1)}
	if _, err := Encode(Payload{Kind: KindSnapshot, Snapshot: tooMany}); err == nil {
		t.Fatal("session capacity snapshot accepted")
	}
}

func TestEncodeRejectsOversizedControlPayload(t *testing.T) {
	// Shape bounds alone do not account for every encoded string byte. Never
	// hand an oversized control frame to WAL or replication.
	_, err := Encode(Payload{Kind: KindSnapshot, Snapshot: &Snapshot{Orphans: []OrphanState{{
		Ino: 1, Kind: "symlink", Name: strings.Repeat("x", MaxEncodedControlBytes),
	}}}})
	if err == nil {
		t.Fatal("oversized encoded control payload accepted")
	}
}
