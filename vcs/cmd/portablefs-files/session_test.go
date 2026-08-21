package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/readonlyfs"
)

const testVolume = "0f3f2c1a-6b2e-4d51-9c34-5a8e7d0b1f22"

// fakeAuthority is the dialed authority session the fence tests install. The
// production seam is readonlyfs.Dial; nothing here needs a real authority
// because the fence decision is made entirely inside the gateway.
type fakeAuthority struct {
	closed     chan struct{}
	closeOnce  sync.Once
	sessionErr error
}

func newFakeAuthority() *fakeAuthority { return &fakeAuthority{closed: make(chan struct{})} }

func (f *fakeAuthority) Close() error {
	f.closeOnce.Do(func() { close(f.closed) })
	return nil
}

func (f *fakeAuthority) Err() error { return f.sessionErr }

func (f *fakeAuthority) List(context.Context, string, int, *readonlyfs.Cursor) (readonlyfs.Page, error) {
	return readonlyfs.Page{}, syscall.EIO
}

func (f *fakeAuthority) OpenFile(context.Context, string) (*readonlyfs.File, error) {
	return nil, syscall.EIO
}

type fakeDialer struct {
	mu       sync.Mutex
	dialed   int
	sessions []*fakeAuthority
}

func (d *fakeDialer) dial(context.Context, readonlyfs.Config) (authoritySession, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	session := newFakeAuthority()
	d.dialed++
	d.sessions = append(d.sessions, session)
	return session, nil
}

func (d *fakeDialer) last() *fakeAuthority {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.sessions) == 0 {
		return nil
	}
	return d.sessions[len(d.sessions)-1]
}

func (d *fakeDialer) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dialed
}

func newTestServer(t *testing.T, public ed25519.PublicKey, dial dialer) *server {
	t.Helper()
	return &server{
		requestKey: public, issuer: "opensteer-host", identity: identity{keyID: "test", privatePEM: []byte("private")},
		maxSessions: 8, dial: dial,
		downloads: make(chan struct{}, maximumDownloads), operations: make(chan struct{}, maximumOperations),
		sessions: make(map[string]*volumeSession), cursors: make(map[string]cursorRecord), fences: make(map[string]fenceRecord),
	}
}

func testKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

func signedRequest(t *testing.T, private ed25519.PrivateKey, method, target string, claims tokenClaims, body []byte) *http.Request {
	t.Helper()
	claims.Audience = "portablefs-files"
	claims.Issuer = "opensteer-host"
	claims.Issued = time.Now().Unix()
	claims.Expires = time.Now().Unix() + 30
	var request *http.Request
	if body == nil {
		request = httptest.NewRequest(method, target, nil)
	} else {
		request = httptest.NewRequest(method, target, bytes.NewReader(body))
	}
	request.Header.Set("Authorization", "Bearer "+testToken(t, private, claims))
	return request
}

func installGrantBody(t *testing.T, volumeID string) []byte {
	t.Helper()
	expires := time.Now().Add(10 * time.Minute).Format(time.RFC3339Nano)
	grant := readGrant{
		Access: []string{"read"}, AuthorityAddress: "authority.invalid:9000", AuthorityCACertificatePEM: "ca",
		AuthorityGeneration: 7, AuthorityServerName: "authority", Capability: "capability",
		CertificateExpiresAt: expires, ClientCertificatePEM: "certificate", ExpiresAt: expires,
		ManagerReleaseID: "release-1", VolumeID: volumeID,
	}
	body, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func installSession(t *testing.T, service *server, private ed25519.PrivateKey, volumeID string, fence uint64) *httptest.ResponseRecorder {
	t.Helper()
	body := installGrantBody(t, volumeID)
	digest := sha256.Sum256(body)
	request := signedRequest(t, private, http.MethodPut, "/v1/volumes/"+volumeID+"/session", tokenClaims{
		Operation: "session.install", VolumeID: volumeID, Fence: fence,
		BodySHA256: base64.RawURLEncoding.EncodeToString(digest[:]),
	}, body)
	recorder := httptest.NewRecorder()
	service.routes().ServeHTTP(recorder, request)
	return recorder
}

func deleteSession(t *testing.T, service *server, private ed25519.PrivateKey, volumeID string, fence uint64) map[string]any {
	t.Helper()
	request := signedRequest(t, private, http.MethodDelete, "/v1/volumes/"+volumeID+"/session", tokenClaims{
		Operation: "session.delete", VolumeID: volumeID, Fence: fence,
	}, nil)
	recorder := httptest.NewRecorder()
	service.routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("DELETE session = %d, want 200 (%s)", recorder.Code, recorder.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestSessionDeleteEvictsAndRecordsTheFenceFloor(t *testing.T) {
	public, private := testKeys(t)
	dialer := &fakeDialer{}
	service := newTestServer(t, public, dialer.dial)
	if recorder := installSession(t, service, private, testVolume, 0); recorder.Code != http.StatusCreated {
		t.Fatalf("PUT session = %d, want 201 (%s)", recorder.Code, recorder.Body.String())
	}
	installed := dialer.last()

	payload := deleteSession(t, service, private, testVolume, 5)
	if payload["evicted"] != true || payload["fence"] != float64(5) {
		t.Fatalf("first delete = %v, want evicted with fence 5", payload)
	}
	select {
	case <-installed.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the evicted authority session was never closed")
	}
	service.mu.Lock()
	live := len(service.sessions)
	service.mu.Unlock()
	if live != 0 {
		t.Fatalf("registry holds %d sessions after the delete", live)
	}

	// The delete is retried by the product, so it is idempotent, and the floor
	// only ever rises.
	repeat := deleteSession(t, service, private, testVolume, 3)
	if repeat["evicted"] != false || repeat["fence"] != float64(5) {
		t.Fatalf("second delete = %v, want no eviction with the floor still at 5", repeat)
	}
}

func TestSessionInstallBelowTheFenceFloorIsRefusedAfterDialing(t *testing.T) {
	public, private := testKeys(t)
	dialer := &fakeDialer{}
	service := newTestServer(t, public, dialer.dial)
	deleteSession(t, service, private, testVolume, 9)

	// A grant issued before quiesce carries no fence, so it installs at 0.
	recorder := installSession(t, service, private, testVolume, 0)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("fenced PUT session = %d, want 409 (%s)", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "session_fenced") {
		t.Fatalf("fenced PUT body = %s", recorder.Body.String())
	}
	if dialer.count() != 1 {
		t.Fatalf("dialed %d times, want the fence re-check to happen after one dial", dialer.count())
	}
	select {
	case <-dialer.last().closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the refused install left its dialed authority session open")
	}
	service.mu.Lock()
	live := len(service.sessions)
	service.mu.Unlock()
	if live != 0 {
		t.Fatalf("a fenced install left %d sessions in the registry", live)
	}

	// A grant issued at or above the floor still installs.
	if recorder := installSession(t, service, private, testVolume, 9); recorder.Code != http.StatusCreated {
		t.Fatalf("PUT session at the floor = %d, want 201 (%s)", recorder.Code, recorder.Body.String())
	}
}

func TestFenceClaimIsBoundToTheRouteThatUsesIt(t *testing.T) {
	public, private := testKeys(t)
	service := newTestServer(t, public, (&fakeDialer{}).dial)

	// A delete without a fence is not a delete this gateway will honour.
	request := signedRequest(t, private, http.MethodDelete, "/v1/volumes/"+testVolume+"/session", tokenClaims{
		Operation: "session.delete", VolumeID: testVolume,
	}, nil)
	recorder := httptest.NewRecorder()
	service.routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("DELETE without a fence = %d, want 401", recorder.Code)
	}

	// A fence on a route that does not use one is a claim nothing would check.
	request = signedRequest(t, private, http.MethodGet, "/v1/volumes/"+testVolume+"/session", tokenClaims{
		Operation: "session.status", VolumeID: testVolume, Fence: 4,
	}, nil)
	recorder = httptest.NewRecorder()
	service.routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("GET session with a fence = %d, want 401", recorder.Code)
	}
}
