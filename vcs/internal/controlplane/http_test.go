package controlplane

import (
	"bytes"
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
