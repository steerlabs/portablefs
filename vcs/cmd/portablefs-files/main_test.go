package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/readonlyfs"
)

func TestVerifyTokenBindsEveryRequestDimension(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	expected := expectedClaims{
		Operation: "list", VolumeID: "volume-a", PathKey: "cGFyZW50", Cursor: "cursor-a", Limit: 200,
		BodySHA256: "body-digest", KnownRevision: "directory_revision", RetainedCursor: "retained_cursor_token_1",
	}
	token := testToken(t, private, tokenClaims{
		Audience: "portablefs-files", Expires: time.Now().Unix() + 30, Issued: time.Now().Unix(),
		Issuer: "opensteer-host", Operation: expected.Operation, VolumeID: expected.VolumeID,
		PathKey: expected.PathKey, Cursor: expected.Cursor, Limit: expected.Limit, BodySHA256: expected.BodySHA256,
		KnownRevision: expected.KnownRevision, RetainedCursor: expected.RetainedCursor,
	})
	if !verifyToken(public, "opensteer-host", token, expected) {
		t.Fatal("valid request-bound token was rejected")
	}
	changed := expected
	changed.PathKey = "b3RoZXI"
	if verifyToken(public, "opensteer-host", token, changed) {
		t.Fatal("token authorized a different path")
	}
	changed = expected
	changed.Limit++
	if verifyToken(public, "opensteer-host", token, changed) {
		t.Fatal("token authorized a different page limit")
	}
	changed = expected
	changed.BodySHA256 = "other-body"
	if verifyToken(public, "opensteer-host", token, changed) {
		t.Fatal("token authorized a different request body")
	}
	changed = expected
	changed.RetainedCursor = "other-retained-cursor"
	if verifyToken(public, "opensteer-host", token, changed) {
		t.Fatal("token authorized a different retained cursor")
	}
	parts := splitToken(t, token)
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"aud":"portablefs-files"}`))
	if verifyToken(public, "opensteer-host", parts[0]+"."+parts[1]+"."+parts[2], expected) {
		t.Fatal("tampered token was accepted")
	}
}

func TestVerifyTokenRejectsExpiredOrOverlongLifetimes(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	for _, claims := range []tokenClaims{
		{Audience: "portablefs-files", Expires: now, Issued: now, Issuer: "opensteer-host", Operation: "identity", VolumeID: "volume-a"},
		{Audience: "portablefs-files", Expires: now + 61, Issued: now, Issuer: "opensteer-host", Operation: "identity", VolumeID: "volume-a"},
		{Audience: "portablefs-files", Expires: now + 30, Issued: now - 61, Issuer: "opensteer-host", Operation: "identity", VolumeID: "volume-a"},
	} {
		if verifyToken(public, "opensteer-host", testToken(t, private, claims), expectedClaims{Operation: "identity", VolumeID: "volume-a"}) {
			t.Fatalf("invalid lifetime was accepted: %+v", claims)
		}
	}
}

func TestIdentityPersistsOnePrivateServiceKey(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(base, "identity")
	first, err := loadOrCreateIdentity(directory)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrCreateIdentity(directory)
	if err != nil {
		t.Fatal(err)
	}
	if first.keyID != second.keyID || string(first.privatePEM) != string(second.privatePEM) {
		t.Fatal("Files identity changed across loads")
	}
	info, err := os.Stat(filepath.Join(directory, "files-private.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode = %04o, want 0600", info.Mode().Perm())
	}
}

func TestFileETagIncludesAuthorityChangeTime(t *testing.T) {
	base := readonlyfs.Attr{
		ChangedAt:  time.Unix(10, 0),
		Inode:      7,
		Kind:       readonlyfs.KindFile,
		Mode:       0o644,
		ModifiedAt: time.Unix(9, 0),
		Size:       5,
	}
	changed := base
	changed.ChangedAt = time.Unix(11, 0)
	if fileETag(base) == fileETag(changed) {
		t.Fatal("file ETag ignored the authority change time")
	}
}

func TestDisplayNameNeutralizesControlAndBidirectionalFormatting(t *testing.T) {
	if got := displayName([]byte("safe\u202Etxt\n")); got != "safe�txt�" {
		t.Fatalf("displayName = %q", got)
	}
}

func testToken(t *testing.T, private ed25519.PrivateKey, claims tokenClaims) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"JWT","v":1}`))
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	input := header + "." + payload
	signature := ed25519.Sign(private, []byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func splitToken(t *testing.T, token string) [3]string {
	t.Helper()
	var result [3]string
	start := 0
	for index := 0; index < 2; index++ {
		next := start
		for next < len(token) && token[next] != '.' {
			next++
		}
		if next == len(token) {
			t.Fatal("test token is malformed")
		}
		result[index] = token[start:next]
		start = next + 1
	}
	result[2] = token[start:]
	return result
}
