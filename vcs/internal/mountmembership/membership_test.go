package mountmembership

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

func TestSharedConsumerVectors(t *testing.T) {
	for _, test := range []struct {
		name    string
		volume  string
		records []Record
		want    string
	}{
		{"empty", "volume", nil, "PFS-MEMBERSHIP-1\n766f6c756d65\n"},
		{"profiles", "v", []Record{
			{SessionID: [16]byte{3}, Profile: ProfileCacheless},
			{SessionID: [16]byte{1}, Profile: ProfileLinux},
			{SessionID: [16]byte{2}, Profile: ProfileFSKitExclusive},
		}, "PFS-MEMBERSHIP-1\n76\n" +
			"01000000000000000000000000000000\tlinux\n" +
			"02000000000000000000000000000000\tfskit-exclusive\n" +
			"03000000000000000000000000000000\tcacheless\n"},
		{"exact volume bytes", "v\n\x00\xff", []Record{{SessionID: [16]byte{0xff}, Profile: ProfileLinux}},
			"PFS-MEMBERSHIP-1\n760a00ff\nff000000000000000000000000000000\tlinux\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			original := append([]Record(nil), test.records...)
			encoded, err := Encode(test.volume, test.records)
			if err != nil || string(encoded) != test.want || !reflect.DeepEqual(test.records, original) {
				t.Fatalf("encode = %q, %v; input=%v", encoded, err, test.records)
			}
			// The authority needs the complete profile-bearing set to restore
			// admission/exclusion ownership; cellhost needs its validated size.
			t.Run("authority restore", func(t *testing.T) {
				records, err := Decode(encoded, test.volume)
				if err != nil || len(records) != len(test.records) {
					t.Fatalf("decode = %v, %v", records, err)
				}
				reencoded, err := Encode(test.volume, records)
				if err != nil || !bytes.Equal(encoded, reencoded) {
					t.Fatalf("restored profiles changed: %q, %v", reencoded, err)
				}
				for _, want := range test.records {
					found := false
					for _, got := range records {
						found = found || got == want
					}
					if !found {
						t.Fatalf("lost membership %+v", want)
					}
				}
			})
			t.Run("host absence count", func(t *testing.T) {
				records, err := Decode(encoded, test.volume)
				if err != nil {
					t.Fatal(err)
				}
				if got, want := len(records), len(test.records); got != want {
					t.Fatalf("validated membership count = %d, want %d", got, want)
				}
			})
		})
	}
}

func TestDecodeRejectsWholeMalformedFile(t *testing.T) {
	const prefix = "PFS-MEMBERSHIP-1\n76\n"
	const first = "01000000000000000000000000000000\tlinux\n"
	const second = "02000000000000000000000000000000\tcacheless\n"
	for _, test := range []struct{ name, data string }{
		{"missing", ""},
		{"header", "UNKNOWN\n76\n"},
		{"wrong volume", "PFS-MEMBERSHIP-1\n77\n"},
		{"uppercase volume", "PFS-MEMBERSHIP-1\n7A\n"},
		{"unencoded volume", "PFS-MEMBERSHIP-1\nv\n"},
		{"unterminated volume", "PFS-MEMBERSHIP-1\n76"},
		{"crlf", "PFS-MEMBERSHIP-1\r\n76\r\n"},
		{"zero session", prefix + strings.Repeat("0", 32) + "\tlinux\n"},
		{"duplicate", prefix + first + first},
		{"conflicting duplicate", prefix + first + strings.Replace(first, "linux", "cacheless", 1)},
		{"unsorted", prefix + second + first},
		{"short session", prefix + "01\tlinux\n"},
		{"long session", prefix + "0100000000000000000000000000000000\tlinux\n"},
		{"uppercase session", prefix + "AB000000000000000000000000000000\tlinux\n"},
		{"nonhex session", prefix + "gg000000000000000000000000000000\tlinux\n"},
		{"missing profile", prefix + strings.TrimSuffix(first, "\tlinux\n") + "\n"},
		{"unknown profile", prefix + strings.Replace(first, "linux", "unknown", 1)},
		{"empty profile", prefix + strings.Replace(first, "linux", "", 1)},
		{"extra tab", prefix + strings.Replace(first, "linux", "linux\textra", 1)},
		{"space", prefix + strings.Replace(first, "\t", " ", 1)},
		{"unterminated record", prefix + strings.TrimSuffix(first, "\n")},
		{"trailing blank", prefix + first + "\n"},
		{"trailing junk", prefix + first + "junk"},
		{"nul", prefix + first + "\x00\n"},
		{"invalid utf8", prefix + first + "\xff\n"},
		{"late malformed", prefix + first + second + "bad\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if records, err := Decode([]byte(test.data), "v"); err == nil || records != nil {
				t.Fatalf("trusted malformed membership: %v, %v", records, err)
			}
		})
	}
	for _, volume := range []string{"", strings.Repeat("x", MaxBytes)} {
		if records, err := Decode([]byte(prefix), volume); err == nil || records != nil {
			t.Fatalf("accepted invalid expected volume: %v, %v", records, err)
		}
	}
	// A hex letter in the actual binding must also be lowercase.
	if records, err := Decode([]byte("PFS-MEMBERSHIP-1\n7A\n"), "z"); err == nil || records != nil {
		t.Fatalf("accepted uppercase binding: %v, %v", records, err)
	}
}

func TestEncodeRejectsInvalidRecords(t *testing.T) {
	for _, records := range [][]Record{
		{{Profile: ProfileLinux}},
		{{SessionID: [16]byte{1}}},
		{{SessionID: [16]byte{1}, Profile: "unknown"}},
		{{SessionID: [16]byte{1}, Profile: ProfileLinux}, {SessionID: [16]byte{1}, Profile: ProfileCacheless}},
	} {
		if encoded, err := Encode("v", records); err == nil || encoded != nil {
			t.Fatalf("accepted invalid records: %q, %v", encoded, err)
		}
	}
	for _, volume := range []string{"", strings.Repeat("x", MaxBytes)} {
		if encoded, err := Encode(volume, nil); err == nil || encoded != nil {
			t.Fatalf("accepted invalid volume: %q, %v", encoded, err)
		}
	}
}

func TestFileSizeBound(t *testing.T) {
	// Fill each profile to the last complete record within the bound.
	// Every added record must be refused by both consumers.
	for _, profile := range []Profile{ProfileLinux, ProfileFSKitExclusive, ProfileCacheless} {
		t.Run(string(profile), func(t *testing.T) {
			volume := "v"
			prefix, err := Encode(volume, nil)
			if err != nil {
				t.Fatal(err)
			}
			count := (MaxBytes - len(prefix)) / (34 + len(profile))
			records := make([]Record, count+1)
			for i := range records {
				binary.BigEndian.PutUint64(records[i].SessionID[8:], uint64(i+1))
				records[i].Profile = profile
			}
			encoded, err := Encode(volume, records[:count])
			if err != nil || len(encoded) > MaxBytes {
				t.Fatalf("bounded encode: %d, %v", len(encoded), err)
			}
			if decoded, err := Decode(encoded, volume); err != nil || len(decoded) != count {
				t.Fatalf("bounded decode: %d, %v", len(decoded), err)
			}
			if encoded, err := Encode(volume, records); err == nil || encoded != nil {
				t.Fatal("encoded file over bound")
			}
			oversize := append([]byte(nil), prefix...)
			for _, record := range records {
				oversize = hex.AppendEncode(oversize, record.SessionID[:])
				oversize = append(oversize, '\t')
				oversize = append(oversize, record.Profile...)
				oversize = append(oversize, '\n')
			}
			if decoded, err := Decode(oversize, volume); err == nil || decoded != nil {
				t.Fatal("decoded file over bound")
			}
		})
	}
	// The maximum itself is inclusive, including header and volume lines.
	volume := strings.Repeat("v", (MaxBytes-len(Header)-2-78)/2)
	records := []Record{{SessionID: [16]byte{1}, Profile: ProfileLinux}, {SessionID: [16]byte{2}, Profile: ProfileLinux}}
	encoded, err := Encode(volume, records)
	if err != nil || len(encoded) != MaxBytes {
		t.Fatalf("exact bound: %d, %v", len(encoded), err)
	}
	if decoded, err := Decode(encoded, volume); err != nil || !reflect.DeepEqual(decoded, records) {
		t.Fatalf("exact bound decode: %v, %v", decoded, err)
	}
	if decoded, err := Decode(append(encoded, 'x'), volume); err == nil || decoded != nil {
		t.Fatal("decoded one byte over bound")
	}
}
