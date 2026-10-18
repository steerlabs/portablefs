package portablefsd

import (
	"bytes"
	"encoding/hex"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// Both paired artifacts accept the current vector. Substitute the daemon's
// actual attach values into that shape and compare its complete wire output,
// including root identity, numeric limits and the checked root file ID.
func TestP4ResolveMatchesCurrentPairedCodecs(t *testing.T) {
	d := testV3DataPlane(t, newFakeV3DataClient())
	root := pfslocal.Item{ItemID: 1, ItemGeneration: 9, StableIdentity: [16]byte{0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20}}
	for _, path := range []string{"pfslocal/testdata/resolve_contract.hex", "swift/PortableFSKit/Tests/PortableFSKitTests/Goldens/resolve_contract.hex"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "..", path))
		if err != nil {
			t.Fatal(err)
		}
		frame, err := hex.DecodeString(string(bytes.TrimSpace(raw)))
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := pfslocal.ReadFrame(bytes.NewReader(frame))
		if err != nil {
			t.Fatal(err)
		}
		expected, ok := envelope.Body.(*pfslocal.ResolveReply)
		if !ok {
			t.Fatalf("paired Resolve vector contained %T", envelope.Body)
		}
		expected.Root = root
		expected.RootAttr = pfslocal.Attr{Item: root, Kind: pfslocal.ItemKindDirectory, Mode: 0755, Nlink: 1, UID: 501, GID: 20, FileID: 1}
		expected.VolumeID = "volume"
		expected.VolumeName = "Volume"
		expected.Capabilities = pfslocal.Capabilities{MaxNameBytes: 255, MaxFileSize: math.MaxInt64, PreferredIOSize: 4096}
		want, err := pfslocal.EncodeFrame(envelope)
		if err != nil {
			t.Fatal(err)
		}
		got, err := pfslocal.EncodeFrame(&pfslocal.Envelope{RequestID: envelope.RequestID, Body: d.resolveReply()})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("daemon Resolve differs from paired %s:\n got %x\nwant %x", path, got, want)
		}
	}
}
