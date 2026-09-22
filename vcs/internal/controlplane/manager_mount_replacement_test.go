package controlplane

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

func TestMountReplacementRequiresFreshEnrollmentAfterExpiredAttachGrant(t *testing.T) {
	h := newManagerHarness(t)
	cell, volume := readyVolumeForMount(t, h)
	public, csr := testCSR(t)
	spki, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	peer := sha256.Sum256(spki)
	issue := func(nonce string) MountAuthorization {
		t.Helper()
		grant, err := h.manager.IssueMount(nonce, IssueMountRequest{
			VolumeID: volume.ID, ProductAuthorization: signedProductAuthorization(t, h, volume.Volume, peer, nonce, []string{"write"}),
			ClientCSRPEM: csr, Access: []string{"write"}, AutomaticReauthorization: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		return grant
	}
	old := issue("old-epoch-attach")
	oldSession := base64.RawURLEncoding.EncodeToString([]byte("old-session-0001"))
	newSession := base64.RawURLEncoding.EncodeToString([]byte("new-session-0002"))
	if _, err := h.manager.RefreshMountEnrollment("old-renewal", old.EnrollmentID, RefreshMountEnrollmentRequest{ClientCSRPEM: csr, SessionID: oldSession, Sequence: 1}); err != nil {
		t.Fatal(err)
	}
	*h.now = time.Unix(old.ExpiresUnix, 0).Add(time.Second)
	if err := h.manager.HeartbeatCell(CellHeartbeat{CellID: cell.ID, PlanGeneration: cell.PlanGeneration, ManagerReleaseID: h.manager.ReleaseIdentity(), AgentReleaseID: "agent-test", HelperReleaseID: "helper-test", ObservedUnix: h.now.Unix()}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.manager.RefreshMountEnrollment("stale-owner-new-session", old.EnrollmentID, RefreshMountEnrollmentRequest{ClientCSRPEM: csr, SessionID: newSession, Sequence: 1}); !errors.Is(err, ErrConflict) {
		t.Fatalf("old enrollment authorized a replacement session: %v", err)
	}
	if _, err := h.manager.CloseMountEnrollment("old-withdrawn", old.EnrollmentID, TerminateMountEnrollmentRequest{Reason: "exact mount withdrawn after authority epoch change"}); err != nil {
		t.Fatal(err)
	}
	replacement := issue("fresh-host-authorization")
	if replacement.EnrollmentID == old.EnrollmentID || replacement.ExpiresUnix <= old.ExpiresUnix {
		t.Fatal("replacement reused expired mount authorization")
	}
	renewed, err := h.manager.RefreshMountEnrollment("replacement-renewal", replacement.EnrollmentID, RefreshMountEnrollmentRequest{ClientCSRPEM: csr, SessionID: newSession, Sequence: 1})
	if err != nil || renewed.SessionID != newSession || renewed.Sequence != 1 {
		t.Fatalf("replacement renewal = %+v, %v", renewed, err)
	}
	if _, err := h.manager.RefreshMountEnrollment("replacement-wrong-session", replacement.EnrollmentID, RefreshMountEnrollmentRequest{ClientCSRPEM: csr, SessionID: oldSession, Sequence: 2}); !errors.Is(err, ErrConflict) {
		t.Fatalf("replacement enrollment accepted old session: %v", err)
	}
}
