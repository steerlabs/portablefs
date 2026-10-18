package portablefsd

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
)

func TestP4RealClientCancelDrainFailureIsTerminal(t *testing.T) {
	pki := newV3TestPKI(t)
	h := newV3TestAuthority()
	address := startV3TestAuthority(t, h, pki.serverTLS)
	req := v3TestEnsureRequest(address, pki, "/Volumes/CancelDrain")
	cfg, err := v3ConfigForEnsure(req)
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig, err := (dataPlaneTransport{
		mode: req.DataPlaneTransport, serverName: req.DataPlaneServerName,
		caPEM: req.TLSCAPEM, caSHA256: req.TLSCASHA256,
	}).tlsConfig()
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig.GetClientCertificate = cfg.clientCertificate
	client, err := authorityrpc.DialClient(context.Background(), authorityrpc.ClientConfig{
		Address: address, TLS: tlsConfig, VolumeID: req.VolumeID,
		AccessToken: []byte(req.AuthToken), ReplaySlots: v3AttachReplaySlots,
		MaxFrame: v3AttachMaxFrame, DialTimeout: time.Second,
		CancelDrainTimeout: 30 * time.Millisecond, MaxInFlight: v3AttachMaxInFlight,
		Purpose:         authoritypb.SessionPurpose_SESSION_PURPOSE_MOUNT,
		FrontendProfile: authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE,
		RoutesRevision:  cfg.routesRevision, ObservePreKernelMountAbsence: req.observePreKernelMountAbsence,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	started, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	h.mu.Lock()
	h.keepAliveHook = func(context.Context, *authoritypb.Request) { close(started); <-release }
	h.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err = client.KeepAlive(ctx)
	<-started
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, authorityrpc.ErrTransportUncertain) {
		t.Fatalf("cancel-drain result=%v", err)
	}
	if client.LocalAdmissionOpen() || client.SessionError() == nil {
		t.Fatalf("CONTROL cancel-drain failure remained usable: err=%v admission=%t session=%v",
			err, client.LocalAdmissionOpen(), client.SessionError())
	}
}
