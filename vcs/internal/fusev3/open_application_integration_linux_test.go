//go:build linux

package fusev3

import (
	"context"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"google.golang.org/protobuf/proto"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

// A truncating allocating mutation must return an application cut for the
// grant it reports. Otherwise the authority cannot separate application from
// the peer withdrawal that may itself require this holder's CONTROL receipt.
func TestTruncatingOpenCarriesItsGrantApplicationCut(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 1})
	path := f.join(0, "application-cut")
	mustWrite(t, path, []byte("before"), 0600)
	f.waitForDelegationReleases(t)
	holder := mustOpenFile(t, path, os.O_WRONLY, 0)
	defer holder.Close()
	cuts := make(chan uint64, 1)
	f.transports[0].setAfterMutation(func(req *authoritypb.Request, response *authoritypb.Response, err error) {
		if req.GetOpen().GetFlags().GetTruncate() && err == nil && response.GetErrno() == 0 {
			cuts <- response.GetAppliedSequence()
		}
	})
	defer f.transports[0].setAfterMutation(nil)
	truncated, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0600)
	if truncated != nil {
		defer truncated.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	select {
	case cut := <-cuts:
		if cut == 0 {
			t.Fatal("truncating OPEN omitted its grant's application receipt")
		}
	default:
		t.Fatal("truncating OPEN completed without its authority outcome")
	}
}

// Linux may translate O_CREAT on a positive dentry into OPEN. Invoke the real
// RawFS CREATE callback to require its existing-name path on the real XFS/TLS
// fixture. These request IDs cannot collide with the kernel's request stream.
func allocatingFrontendCreate(t *testing.T, f *integrationFixture, name string) (func(), error) {
	raw := f.mounts[0].raw
	unique := uint64(1)<<63 | nextTestRequestUnique()
	out := &fuse.CreateOut{}
	status := raw.Create(nil, &fuse.CreateIn{InHeader: fuse.InHeader{Unique: unique, NodeId: 1}, Flags: syscall.O_CREAT | syscall.O_WRONLY | syscall.O_TRUNC, Mode: 0600}, name, out)
	completeTestReply(t, raw, unique, fuse.OK)
	if !status.Ok() {
		return nil, fmt.Errorf("CREATE: %v", status)
	}
	return func() {
		unique := uint64(1)<<63 | nextTestRequestUnique()
		raw.Release(nil, &fuse.ReleaseIn{InHeader: fuse.InHeader{Unique: unique, NodeId: out.NodeId}, Fh: out.Fh})
		completeTestReply(t, raw, unique, fuse.OK)
		raw.Forget(out.NodeId, 1)
	}, nil
}

func TestTruncatingCreateCarriesItsGrantApplicationCut(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 1})
	const name = "create-application-cut"
	mustWrite(t, f.join(0, name), []byte("before"), 0600)
	f.waitForDelegationReleases(t)
	holder := mustOpenFile(t, f.join(0, name), os.O_WRONLY, 0)
	defer holder.Close()
	cuts := make(chan *authoritypb.Response, 1)
	f.transports[0].setAfterMutation(func(req *authoritypb.Request, response *authoritypb.Response, err error) {
		if req.GetCreate().GetFlags().GetTruncate() && err == nil && response.GetErrno() == 0 {
			cuts <- proto.Clone(response).(*authoritypb.Response)
		}
	})
	defer f.transports[0].setAfterMutation(nil)
	closeHandle, err := allocatingFrontendCreate(t, f, name)
	if err != nil {
		t.Fatal(err)
	}
	defer closeHandle()
	select {
	case response := <-cuts:
		if response.GetAppliedSequence() == 0 {
			t.Fatal("truncating CREATE omitted its grant's application receipt")
		}
		if response.GetCreate().GetDelegation() == nil || response.GetCreate().GetItem().GetAttr().GetSize() != 0 {
			t.Fatalf("invalid truncating CREATE receipt: %v", response)
		}
	default:
		t.Fatal("truncating CREATE completed without its authority outcome")
	}
	info, err := holder.Stat()
	if err != nil || info.Size() != 0 {
		t.Fatalf("existing descriptor after CREATE: %v %v", info, err)
	}
}

func TestAllocatingGrantApplicationAndControlOnXFS(t *testing.T) {
	for _, public := range []bool{false, true} {
		for _, create := range []bool{false, true} {
			name := "private/OPEN"
			if public {
				name = "public/OPEN"
			}
			if create {
				name = name[:len(name)-4] + "CREATE"
			}
			t.Run(name, func(t *testing.T) {
				f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
				const name = "allocating"
				mustWrite(t, f.join(0, name), []byte("before"), 0600)
				f.waitForDelegationReleases(t)
				peerOpened := make(chan []byte, 1)
				f.transports[1].setAfterMutation(func(req *authoritypb.Request, response *authoritypb.Response, err error) {
					if req.GetOpen() != nil && err == nil && response.GetErrno() == 0 {
						peerOpened <- cloneBytes(response.GetOpen().GetHandle())
					}
				})
				peer := mustOpenFile(t, f.join(1, name), os.O_RDONLY, 0)
				defer peer.Close()
				peerHandle := <-peerOpened
				f.transports[1].setAfterMutation(nil)
				if got := string(readExactlyAt(t, peer, 0, 6, "prime peer footprint")); got != "before" {
					t.Fatal(got)
				}
				if public {
					holder := mustOpenFile(t, f.join(0, name), os.O_WRONLY, 0)
					defer holder.Close()
				}
				releaseData, releaseWithdrawal := make(chan struct{}), make(chan struct{})
				var dataOnce, withdrawOnce sync.Once
				deliver := func() { dataOnce.Do(func() { close(releaseData) }) }
				withdraw := func() { withdrawOnce.Do(func() { close(releaseWithdrawal) }) }
				defer deliver()
				defer withdraw()
				receipt := make(chan *authoritypb.Response, 1)
				overtook := make(chan *authoritypb.ControlEvent, 1)
				acked := make(chan *authoritypb.DelegationBreakAck, 1)
				withdrawing := make(chan struct{}, 1)
				visibility := make(chan struct{}, 1)
				f.transports[0].setAfterMutation(func(req *authoritypb.Request, response *authoritypb.Response, err error) {
					if (req.GetOpen().GetFlags().GetTruncate() || req.GetCreate().GetFlags().GetTruncate()) && err == nil && response.GetErrno() == 0 {
						receipt <- proto.Clone(response).(*authoritypb.Response)
						if !public {
							<-releaseData
						}
					}
				})
				defer f.transports[0].setAfterMutation(nil)
				f.transports[0].hookMu.Lock()
				f.transports[0].afterControlEvent = func(ctx context.Context, event *authoritypb.ControlEvent) error {
					if event.GetDelegationBreak() != nil {
						overtook <- proto.Clone(event).(*authoritypb.ControlEvent)
					}
					return nil
				}
				f.transports[0].hookMu.Unlock()
				f.transports[1].hookMu.Lock()
				f.transports[1].afterControlEvent = func(ctx context.Context, event *authoritypb.ControlEvent) error {
					if public && event.GetChangeBatch() != nil {
						select {
						case withdrawing <- struct{}{}:
						default:
						}
						select {
						case <-releaseWithdrawal:
						case <-ctx.Done():
							return ctx.Err()
						}
					}
					return nil
				}
				f.transports[1].hookMu.Unlock()
				f.counter.setBeforeHandle(func(req *authoritypb.Request) {
					if ack := req.GetDelegationBreakAck(); ack != nil {
						acked <- proto.Clone(ack).(*authoritypb.DelegationBreakAck)
					}
					if req.GetWaitVisibility() != nil {
						select {
						case visibility <- struct{}{}:
						default:
						}
					}
				})
				defer f.counter.setBeforeHandle(nil)
				result := make(chan error, 1)
				go func() {
					if create {
						closeHandle, err := allocatingFrontendCreate(t, f, name)
						if closeHandle != nil {
							defer closeHandle()
						}
						result <- err
					} else {
						file, err := os.OpenFile(f.join(0, name), os.O_WRONLY|os.O_TRUNC, 0600)
						if file != nil {
							defer file.Close()
						}
						result <- err
					}
				}()
				var applied *authoritypb.Response
				select {
				case applied = <-receipt:
				case <-time.After(2 * time.Second):
					t.Fatal("no allocating application receipt before withdrawal")
				}
				grant := applied.GetOpen().GetDelegation()
				if create {
					grant = applied.GetCreate().GetDelegation()
				}
				if grant == nil || applied.GetAppliedSequence() == 0 {
					t.Fatalf("missing grant/application: %v", applied)
				}
				if public {
					awaitAllocatingControl(t, withdrawing, "targeted peer withdrawal")
					awaitAllocatingControl(t, visibility, "frontend visibility wait")
				}
				read := make(chan error, 1)
				go func() {
					response, err := f.clients[1].CallRead(t.Context(), &authoritypb.Request{Body: &authoritypb.Request_Read{Read: &authoritypb.ReadRequest{Handle: peerHandle, Length: 6}}})
					if err == nil && (response.GetErrno() != 0 || len(response.GetRead().GetData()) != 0) {
						err = fmt.Errorf("post-truncate READ: %v", response)
					}
					read <- err
				}()
				var event *authoritypb.ControlEvent
				select {
				case event = <-overtook:
				case <-time.After(2 * time.Second):
					t.Fatal("peer READ did not issue holder CONTROL")
				}
				if !public {
					// Authority returned this receipt only after final activation. DATA is
					// still held at the transport consumption boundary when CONTROL arrives.
					select {
					case ack := <-acked:
						t.Fatalf("unregistered DATA was acknowledged: %v", ack)
					default:
					}
					deliver()
				}
				var ack *authoritypb.DelegationBreakAck
				select {
				case ack = <-acked:
				case <-time.After(2 * time.Second):
					t.Fatal("holder failed to acknowledge exact application")
				}
				if ack.GetAppliedSequence() != applied.GetAppliedSequence() || ack.GetEventSequence() != event.GetSequence() || ack.GetIncarnation() != event.GetIncarnation() || !sameDelegation(ack.GetDelegation(), event.GetDelegationBreak().GetDelegation()) || !sameDelegation(ack.GetDelegation(), &authoritypb.DelegationRef{Id: grant.Id, Generation: grant.Generation}) {
					t.Fatalf("ack=%v event=%v application=%v", ack, event, applied)
				}
				select {
				case err := <-read:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("peer READ could not finish through application cut")
				}
				if public {
					select {
					case err := <-result:
						t.Fatalf("frontend completed before peer withdrawal: %v", err)
					default:
					}
					withdraw()
				}
				select {
				case err := <-result:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("frontend failed to complete after withdrawal")
				}
				for _, mount := range f.mounts {
					if mount.delegations.LossSequence() != 0 || mount.fatalError() != nil {
						t.Fatalf("healthy schedule lost ownership: %v", mount.fatalError())
					}
				}
			})
		}
	}
}
