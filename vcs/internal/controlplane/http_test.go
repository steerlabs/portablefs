package controlplane

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestHTTPProductCannotOperateOnAnotherIssuerVolume(t *testing.T) {
	harness := newManagerHarness(t)
	_, err := harness.manager.RegisterCell("cell", RegisterCellRequest{
		ID: "11111111-1111-4111-8111-111111111111", AvailabilityZone: "zone-a",
		AuthorityHost: "cell.test", AuthorityDNSZone: "cell.test", CapacityBytes: 2 << 30, CapacityInodes: 200_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	volume, err := harness.manager.CreateVolume("volume", CreateVolumeRequest{
		AuthorizationDomain: "org", Owner: "owner", ProductIssuer: "opensteer", QuotaBytes: 1 << 30, QuotaInodes: 100_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := testHTTPHandler(harness.manager)

	response := serveControlRequest(t, handler, http.MethodGet, "/v1/volumes/"+volume.ID, nil, RoleProduct, "other-product", "")
	if response.Code != http.StatusNotFound {
		t.Fatalf("cross-product GET status = %d, body=%s", response.Code, response.Body.String())
	}
	restart := RestartVolumeRequest{VolumeID: volume.ID, Reason: "malicious restart"}
	response = serveControlRequest(t, handler, http.MethodPost, "/v1/volumes/"+volume.ID+"/restart", restart, RoleProduct, "other-product", "restart-key")
	if response.Code != http.StatusNotFound {
		t.Fatalf("cross-product restart status = %d, body=%s", response.Code, response.Body.String())
	}
	response = serveControlRequest(t, handler, http.MethodGet, "/v1/volumes/"+volume.ID, nil, RoleProduct, "opensteer", "")
	if response.Code != http.StatusOK {
		t.Fatalf("owner GET status = %d, body=%s", response.Code, response.Body.String())
	}
}

func TestHTTPProductIdentityMustMatchCreatedIssuer(t *testing.T) {
	harness := newManagerHarness(t)
	_, err := harness.manager.RegisterCell("cell", RegisterCellRequest{
		ID: "11111111-1111-4111-8111-111111111111", AvailabilityZone: "zone-a",
		AuthorityHost: "cell.test", AuthorityDNSZone: "cell.test", CapacityBytes: 2 << 30, CapacityInodes: 200_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := CreateVolumeRequest{
		AuthorizationDomain: "org", Owner: "owner", ProductIssuer: "opensteer", QuotaBytes: 1 << 30, QuotaInodes: 100_000,
	}
	response := serveControlRequest(t, testHTTPHandler(harness.manager), http.MethodPost, "/v1/volumes", request, RoleProduct, "other-product", "create-key")
	if response.Code != http.StatusNotFound {
		t.Fatalf("issuer impersonation status = %d, body=%s", response.Code, response.Body.String())
	}
}

func TestHTTPCellObservationRequiresIdempotencyKey(t *testing.T) {
	harness := newManagerHarness(t)
	cell, err := harness.manager.RegisterCell("cell", RegisterCellRequest{
		ID: "11111111-1111-4111-8111-111111111111", AvailabilityZone: "zone-a",
		AuthorityHost: "cell.test", AuthorityDNSZone: "cell.test", CapacityBytes: 2 << 30, CapacityInodes: 200_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	observation := CellObservation{
		CellID: cell.ID, PlanGeneration: cell.PlanGeneration, ManagerReleaseID: harness.manager.ReleaseIdentity(),
		AgentReleaseID: "agent", HelperReleaseID: "helper", ObservedUnix: harness.now.Unix(),
	}
	response := serveControlRequest(t, testHTTPHandler(harness.manager), http.MethodPost, "/v1/cells/"+cell.ID+"/observations", observation, RoleCell, cell.ID, "")
	if response.Code != http.StatusBadRequest {
		t.Fatalf("missing idempotency status = %d, body=%s", response.Code, response.Body.String())
	}
}

func TestHTTPConvergentVolumeScopedRevocation(t *testing.T) {
	h := newManagerHarness(t)
	_, volume := readyVolumeForMount(t, h)
	clientPublic, clientCSR := testCSR(t)
	peerSPKI, err := x509.MarshalPKIXPublicKey(clientPublic)
	if err != nil {
		t.Fatal(err)
	}
	peer := sha256.Sum256(peerSPKI)
	issue := func(requestID string) MountAuthorization {
		t.Helper()
		authorization, err := h.manager.IssueMount(requestID, IssueMountRequest{
			VolumeID: volume.ID, ProductAuthorization: signedProductAuthorization(t, h, volume.Volume, peer, requestID, []string{"write"}),
			ClientCSRPEM: clientCSR, Access: []string{"write"}, AutomaticReauthorization: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		return authorization
	}
	active := issue("http-revoke-active")
	closed := issue("http-revoke-closed")
	revoked := issue("http-revoke-revoked")
	untouched := issue("http-revoke-untouched")
	if _, err := h.manager.CloseMountEnrollment("http-close-first", closed.EnrollmentID, TerminateMountEnrollmentRequest{Reason: "closed-first"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.manager.RevokeVolumeMountEnrollment("opensteer", volume.ID, revoked.EnrollmentID, TerminateMountEnrollmentRequest{Reason: "revoked-first"}); err != nil {
		t.Fatal(err)
	}
	otherVolume, err := h.manager.CreateVolume("http-other-volume", CreateVolumeRequest{
		AuthorizationDomain: "org", Owner: "owner", ProductIssuer: "opensteer", QuotaBytes: 1 << 30, QuotaInodes: 100_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := testHTTPHandler(h.manager)
	path := func(volumeID, enrollmentID string) string {
		return "/v1/volumes/" + volumeID + "/mount-enrollments/" + enrollmentID + "/revocation"
	}
	serve := func(volumeID, enrollmentID, reason, principal string) *httptest.ResponseRecorder {
		t.Helper()
		return serveControlRequest(t, handler, http.MethodPut, path(volumeID, enrollmentID), TerminateMountEnrollmentRequest{Reason: reason}, RoleProduct, principal, "")
	}
	assertOutcome := func(response *httptest.ResponseRecorder, enrollmentID string, outcome MountEnrollmentRevocationOutcome) {
		t.Helper()
		if response.Code != http.StatusOK {
			t.Fatalf("revocation status = %d, body=%s", response.Code, response.Body.String())
		}
		var result MountEnrollmentRevocation
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.VolumeID != volume.ID || result.EnrollmentID != enrollmentID || result.Outcome != outcome {
			t.Fatalf("revocation result = %+v", result)
		}
	}

	response := serveControlRequest(t, handler, http.MethodPut, path(volume.ID, active.EnrollmentID),
		TerminateMountEnrollmentRequest{Reason: "header-must-not-be-accepted"}, RoleProduct, "opensteer", "legacy-key")
	if response.Code != http.StatusBadRequest {
		t.Fatalf("revocation with idempotency header status = %d, body=%s", response.Code, response.Body.String())
	}
	assertOutcome(serve(volume.ID, active.EnrollmentID, "requested-revoke", "opensteer"), active.EnrollmentID, MountEnrollmentRevocationRevoked)
	assertOutcome(serve(volume.ID, active.EnrollmentID, "ignored-repeat", "opensteer"), active.EnrollmentID, MountEnrollmentRevocationRevoked)
	assertOutcome(serve(volume.ID, closed.EnrollmentID, "ignored-after-close", "opensteer"), closed.EnrollmentID, MountEnrollmentRevocationClosed)
	assertOutcome(serve(volume.ID, revoked.EnrollmentID, "ignored-after-revoke", "opensteer"), revoked.EnrollmentID, MountEnrollmentRevocationRevoked)
	absentID := "99999999-9999-4999-8999-999999999999"
	assertOutcome(serve(volume.ID, absentID, "absent-cleanup", "opensteer"), absentID, MountEnrollmentRevocationAbsent)

	response = serve(otherVolume.ID, untouched.EnrollmentID, "wrong-volume", "opensteer")
	if response.Code != http.StatusNotFound {
		t.Fatalf("wrong-volume status = %d, body=%s", response.Code, response.Body.String())
	}
	response = serve(volume.ID, untouched.EnrollmentID, "wrong-product", "other-product")
	if response.Code != http.StatusNotFound {
		t.Fatalf("wrong-product status = %d, body=%s", response.Code, response.Body.String())
	}
	response = serve(volume.ID, untouched.EnrollmentID, "malformed\nreason", "opensteer")
	if response.Code != http.StatusBadRequest {
		t.Fatalf("malformed-reason status = %d, body=%s", response.Code, response.Body.String())
	}
	response = serveControlRequest(t, handler, http.MethodPost, "/v1/mount-enrollments/"+untouched.EnrollmentID+"/revoke",
		TerminateMountEnrollmentRequest{Reason: "legacy-route"}, RoleProduct, "opensteer", "legacy-route")
	if response.Code != http.StatusNotFound {
		t.Fatalf("legacy revocation route status = %d, body=%s", response.Code, response.Body.String())
	}
	if err := h.store.View(func(state State) error {
		for id, reason := range map[string]string{
			active.EnrollmentID:  "requested-revoke",
			closed.EnrollmentID:  "closed-first",
			revoked.EnrollmentID: "revoked-first",
		} {
			if enrollment := state.MountEnrollments[id]; enrollment.TerminationReason != reason {
				t.Fatalf("enrollment %s termination = %q, want %q", id, enrollment.TerminationReason, reason)
			}
		}
		if enrollment := state.MountEnrollments[untouched.EnrollmentID]; enrollment.State != MountEnrollmentActive {
			t.Fatalf("unrelated enrollment = %+v", enrollment)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPRenewalFenceAdvanceAndFencedIssuance(t *testing.T) {
	h := newManagerHarness(t)
	_, volume := readyVolumeForMount(t, h)
	clientPublic, clientCSR := testCSR(t)
	peerSPKI, err := x509.MarshalPKIXPublicKey(clientPublic)
	if err != nil {
		t.Fatal(err)
	}
	peer := sha256.Sum256(peerSPKI)
	scope := "cloud-private-state:computer-1"
	if _, err := h.manager.IssueMount("http-fence-epoch-2", IssueMountRequest{
		VolumeID: volume.ID, ProductAuthorization: signedProductAuthorizationWithRenewal(
			t, h, volume.Volume, peer, "http-fence-epoch-2", []string{"write"}, scope, 2,
		),
		ClientCSRPEM: clientCSR, Access: []string{"write"}, AutomaticReauthorization: true,
	}); err != nil {
		t.Fatal(err)
	}
	handler := testHTTPHandler(h.manager)
	staleRequest := IssueMountRequest{
		VolumeID: volume.ID, ProductAuthorization: signedProductAuthorizationWithRenewal(
			t, h, volume.Volume, peer, "http-fence-stale", []string{"write"}, scope, 1,
		),
		ClientCSRPEM: clientCSR, Access: []string{"write"}, AutomaticReauthorization: true,
	}
	response := serveControlRequest(t, handler, http.MethodPost, "/v1/mount-authorizations", staleRequest, RoleProduct, "opensteer", "http-fence-stale")
	if response.Code != http.StatusConflict {
		t.Fatalf("fenced issuance status = %d, body=%s", response.Code, response.Body.String())
	}
	var failure map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &failure); err != nil || failure["error"] != "renewal_scope_fenced" {
		t.Fatalf("fenced issuance error = %v, %v", failure, err)
	}

	scope = "cloud-private-state:computer-1/attachment"
	fencePath := "/v1/renewal-fences"
	request := AdvanceRenewalFencesRequest{
		Reason: "stopped", Fences: []RenewalFence{{Scope: scope, Epoch: 3}, {Scope: scope, Epoch: 1}},
	}
	response = serveControlRequest(t, handler, http.MethodPut, fencePath, request, RoleProduct, "opensteer", "legacy-key")
	if response.Code != http.StatusBadRequest {
		t.Fatalf("fence with idempotency header status = %d, body=%s", response.Code, response.Body.String())
	}
	response = serveControlRequest(t, handler, http.MethodPut, fencePath, request, RoleProduct, "opensteer", "")
	if response.Code != http.StatusOK {
		t.Fatalf("advance fence status = %d, body=%s", response.Code, response.Body.String())
	}
	var fences AdvanceRenewalFencesResponse
	if err := json.Unmarshal(response.Body.Bytes(), &fences); err != nil || len(fences.Fences) != 2 ||
		fences.Fences[0] != (RenewalFence{Scope: scope, Epoch: 3}) || fences.Fences[1] != (RenewalFence{Scope: scope, Epoch: 3}) {
		t.Fatalf("advance fence response = %+v, %v", fences, err)
	}
	response = serveControlRequest(t, handler, http.MethodPut, fencePath, AdvanceRenewalFencesRequest{
		Reason: "invalid-batch", Fences: []RenewalFence{{Scope: "valid-scope", Epoch: 4}, {Scope: "invalid-scope", Epoch: 0}},
	}, RoleProduct, "opensteer", "")
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid fence batch status = %d, body=%s", response.Code, response.Body.String())
	}
	response = serveControlRequest(t, handler, http.MethodPut, fencePath, AdvanceRenewalFencesRequest{
		Reason: "lower-retry", Fences: []RenewalFence{{Scope: scope, Epoch: 1}},
	}, RoleProduct, "opensteer", "")
	if response.Code != http.StatusOK {
		t.Fatalf("lower fence status = %d, body=%s", response.Code, response.Body.String())
	}
	if err := json.Unmarshal(response.Body.Bytes(), &fences); err != nil || len(fences.Fences) != 1 || fences.Fences[0].Epoch != 3 {
		t.Fatalf("lower fence response = %+v, %v", fences, err)
	}
	response = serveControlRequest(t, handler, http.MethodPut, fencePath+"/legacy-scope", request, RoleProduct, "opensteer", "")
	if response.Code != http.StatusNotFound {
		t.Fatalf("single-scope fence route status = %d, body=%s", response.Code, response.Body.String())
	}
}

func TestDecodeJSONRejectsBytesBeyondTheHardLimit(t *testing.T) {
	payload := append([]byte(`{}`), bytes.Repeat([]byte{' '}, 1<<20)...)
	request := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(payload))
	var target struct{}
	if err := decodeJSON(request, &target); err == nil {
		t.Fatal("decoder accepted a valid JSON prefix followed by bytes beyond its limit")
	}
}

func TestAuthenticateMTLSRequiresOneExactRoleIdentity(t *testing.T) {
	valid, _ := url.Parse("spiffe://portablefs/control/cell/11111111-1111-4111-8111-111111111111")
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{URIs: []*url.URL{valid}}},
		VerifiedChains:   [][]*x509.Certificate{{{}}},
	}
	principal, err := AuthenticateMTLS(request)
	if err != nil || principal.Role != RoleCell || principal.ID != "11111111-1111-4111-8111-111111111111" {
		t.Fatalf("valid identity = %+v, %v", principal, err)
	}
	withQuery, _ := url.Parse(valid.String() + "?ignored=true")
	request.TLS.PeerCertificates[0].URIs = []*url.URL{withQuery}
	if _, err := AuthenticateMTLS(request); err == nil {
		t.Fatal("identity URI with ignored query data was accepted")
	}
	badCell, _ := url.Parse("spiffe://portablefs/control/cell/not-a-cell-id")
	request.TLS.PeerCertificates[0].URIs = []*url.URL{badCell}
	if _, err := AuthenticateMTLS(request); err == nil {
		t.Fatal("non-UUID cell control identity was accepted")
	}
	mountID := "22222222-2222-4222-8222-222222222222"
	mountIdentity, _ := url.Parse("spiffe://portablefs/mount-enrollment/" + mountID)
	request.TLS.PeerCertificates[0].URIs = []*url.URL{mountIdentity}
	principal, err = AuthenticateMTLS(request)
	if err != nil || principal.Role != RoleMount || principal.ID != mountID {
		t.Fatalf("valid mount enrollment identity = %+v, %v", principal, err)
	}
	shortLivedMount, _ := url.Parse("spiffe://portablefs/client/" + mountID)
	request.TLS.PeerCertificates[0].URIs = []*url.URL{shortLivedMount}
	if _, err := AuthenticateMTLS(request); err == nil {
		t.Fatal("authority-facing short-lived client identity authenticated to the Manager")
	}
}

func TestRoleBoundMTLSAuthenticatorRequiresTheMatchingCARoot(t *testing.T) {
	controlCA := testCA(t, "control-ca")
	enrollmentCA := testCA(t, "enrollment-ca")
	authenticate, err := NewRoleBoundMTLSAuthenticator(
		[]byte(controlCA.CertificatePEM), []byte(enrollmentCA.CertificatePEM),
	)
	if err != nil {
		t.Fatal(err)
	}
	controlURI, _ := url.Parse("spiffe://portablefs/control/operator/operator-a")
	mountURI, _ := url.Parse("spiffe://portablefs/mount-enrollment/22222222-2222-4222-8222-222222222222")
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{URIs: []*url.URL{controlURI}}}}
	request.TLS.VerifiedChains = [][]*x509.Certificate{{request.TLS.PeerCertificates[0], controlCA.Certificate}}
	if principal, err := authenticate(request); err != nil || principal.Role != RoleOperator {
		t.Fatalf("control identity under control CA = %+v, %v", principal, err)
	}
	request.TLS.VerifiedChains = [][]*x509.Certificate{{request.TLS.PeerCertificates[0], enrollmentCA.Certificate}}
	if _, err := authenticate(request); err == nil {
		t.Fatal("control identity issued by the enrollment CA was accepted")
	}
	request.TLS.PeerCertificates[0].URIs = []*url.URL{mountURI}
	request.TLS.VerifiedChains = [][]*x509.Certificate{{request.TLS.PeerCertificates[0], enrollmentCA.Certificate}}
	if principal, err := authenticate(request); err != nil || principal.Role != RoleMount {
		t.Fatalf("mount identity under enrollment CA = %+v, %v", principal, err)
	}
	request.TLS.VerifiedChains = [][]*x509.Certificate{{request.TLS.PeerCertificates[0], controlCA.Certificate}}
	if _, err := authenticate(request); err == nil {
		t.Fatal("mount identity issued by the control CA was accepted")
	}
}

func testHTTPHandler(manager *Manager) *HTTPHandler {
	return &HTTPHandler{Manager: manager, Authenticate: func(request *http.Request) (Principal, error) {
		return Principal{Role: Role(request.Header.Get("X-Test-Role")), ID: request.Header.Get("X-Test-ID")}, nil
	}}
}

func serveControlRequest(t *testing.T, handler http.Handler, method, path string, body any, role Role, id, idempotency string) *httptest.ResponseRecorder {
	t.Helper()
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(payload))
	request.Header.Set("X-Test-Role", string(role))
	request.Header.Set("X-Test-ID", id)
	if idempotency != "" {
		request.Header.Set("Idempotency-Key", idempotency)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}
