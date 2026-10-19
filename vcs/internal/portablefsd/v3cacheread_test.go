package portablefsd

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// Swift owns optional access acquisition. This seam checks every authority OPEN
// it sends: canonical capability, access only, one trip per attempt, and no
// handle on denial. In particular a denied combined OPEN cannot truncate before
// the original write-only request reaches storage.
func TestV3CacheReadAcquisitionAuthorityAccessAndTrips(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		modes                 []pfslocal.OpenMode
		readErrno, writeErrno int32
		wantErrnos            []int32
	}{
		{"combined", []pfslocal.OpenMode{pfslocal.OpenModeReadWrite}, 0, 0, []int32{0}},
		{"read-denied", []pfslocal.OpenMode{pfslocal.OpenModeReadWrite, pfslocal.OpenModeWrite}, 13, 0, []int32{13, 0}},
		{"write-denied", []pfslocal.OpenMode{pfslocal.OpenModeReadWrite, pfslocal.OpenModeWrite}, 13, 30, []int32{13, 30}},
		{"retained-write-upgrade", []pfslocal.OpenMode{pfslocal.OpenModeWrite, pfslocal.OpenModeRead}, 0, 0, []int32{0, 0}},
		{"retained-write-read-denied", []pfslocal.OpenMode{pfslocal.OpenModeWrite, pfslocal.OpenModeRead}, 13, 0, []int32{0, 13}},
		{"resource-failure", []pfslocal.OpenMode{pfslocal.OpenModeReadWrite}, 12, 0, []int32{12}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCachedV3Fixture(t, v3FileObjects())
			f.ns.bind(0x20, "file", 0x70)
			file := f.lookup(f.root, "file")
			f.d.mu.Lock()
			canonical := cloneBytesV3(f.d.itemsByID[file.Item.ItemID].token)
			f.d.mu.Unlock()
			var flags []*authoritypb.OpenFlags
			f.client.mu.Lock()
			original := f.client.mutation
			f.client.mutation = func(ctx context.Context, id authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
				open := request.GetOpen()
				if open == nil {
					return original(ctx, id, request)
				}
				if !bytes.Equal(open.GetItem(), canonical) {
					t.Errorf("OPEN changed canonical capability: %x, want %x", open.GetItem(), canonical)
				}
				flags = append(flags, open.GetFlags())
				response := exactTestMutationReply(id)
				if open.GetFlags().GetRead() && tc.readErrno != 0 {
					response.Errno = tc.readErrno
					return response, nil
				}
				if open.GetFlags().GetWrite() && tc.writeErrno != 0 {
					response.Errno = tc.writeErrno
					return response, nil
				}
				return original(ctx, id, request)
			}
			f.client.mu.Unlock()
			var handles []uint64
			for index, mode := range tc.modes {
				f.requireOperations([]string{"open"}, func() {
					reply, errno := f.dispatch(&pfslocal.OpenRequest{Item: file.Item, Mode: mode})
					if errno != tc.wantErrnos[index] {
						t.Fatalf("OPEN %d errno=%d, want %d", index, errno, tc.wantErrnos[index])
					}
					if errno == 0 {
						handles = append(handles, reply.(*pfslocal.OpenReply).Handle)
					}
				})
				want := &authoritypb.OpenFlags{Read: mode != pfslocal.OpenModeWrite, Write: mode != pfslocal.OpenModeRead}
				if !reflect.DeepEqual(flags[index], want) {
					t.Fatalf("OPEN %d flags=%v, want access-only %v", index, flags[index], want)
				}
			}
			if len(flags) != len(tc.modes) {
				t.Fatalf("OPEN trips=%d, want %d", len(flags), len(tc.modes))
			}
			// An added-read refusal leaves the original write ownership usable.
			if tc.modes[0] == pfslocal.OpenModeWrite {
				f.requireOperations([]string{"write"}, func() {
					if _, errno := f.dispatch(&pfslocal.WriteRequest{Handle: handles[0], Data: []byte("W")}); errno != 0 {
						t.Fatal(errno)
					}
				})
			}
			for _, handle := range handles {
				if _, errno := f.dispatch(&pfslocal.CloseRequest{Handle: handle}); errno != 0 {
					t.Fatal(errno)
				}
			}
			f.d.mu.Lock()
			remaining := len(f.d.handles)
			f.d.mu.Unlock()
			if remaining != 0 {
				t.Fatalf("owned handles after close=%d", remaining)
			}
		})
	}
}
