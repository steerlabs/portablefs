package cellplan

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func validPlan(now time.Time) Plan {
	return Plan{
		Version: Version, CellID: "11111111-1111-4111-8111-111111111111", Generation: 3,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), ReleaseID: "v3-test",
		Volumes: []VolumePlan{{
			VolumeID: "22222222-2222-4222-8222-222222222222", Phase: PhaseServe,
			AuthorizationDomain: "org", Owner: "owner", ProductIssuer: "product", ProductPublicKeyPEM: "product-key",
			AuthorityID: "authority", AuthorityGeneration: 4, ProjectID: 10001,
			ServiceUID: 200001, ServiceGID: 200001, ListenPort: 20001, QuotaBytes: 1 << 30, QuotaInodes: 1000,
			AuthorityServerName: "volume.example", AuthorityCertificate: "cert", AuthorityCAPEM: "authority-ca",
			ClientCAPEM: "client-ca", CapabilityPublicKey: "cap-key",
		}},
	}
}

func TestSignedPlanBindsCellAndExactPayload(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	now := time.Unix(1_700_000_000, 0)
	plan := validPlan(now)
	envelope, err := Sign(privateKey, plan)
	if err != nil {
		t.Fatal(err)
	}
	got, digest, err := Verify(publicKey, envelope, plan.CellID, now, time.Second, 5*time.Minute)
	if err != nil || got.Generation != plan.Generation || digest == ([32]byte{}) {
		t.Fatalf("Verify = %+v, %x, %v", got, digest, err)
	}
	if _, _, err := Verify(publicKey, envelope, "33333333-3333-4333-8333-333333333333", now, time.Second, 5*time.Minute); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong cell = %v", err)
	}
	tampered := envelope
	parts := strings.Split(tampered.Token, ".")
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	signature[0] ^= 1
	parts[2] = base64.RawURLEncoding.EncodeToString(signature)
	tampered.Token = strings.Join(parts, ".")
	if _, _, err := Verify(publicKey, tampered, plan.CellID, now, time.Second, 5*time.Minute); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tampered = %v", err)
	}
}

func TestPlanRejectsDuplicateIsolationIdentifiers(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	plan := validPlan(now)
	second := plan.Volumes[0]
	second.VolumeID = "33333333-3333-4333-8333-333333333333"
	plan.Volumes = append(plan.Volumes, second)
	if err := Validate(plan); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate isolation IDs = %v, want ErrInvalid", err)
	}
}

func TestPlanRejectsQuotaNotRepresentableInXFSKiB(t *testing.T) {
	plan := validPlan(time.Unix(1_700_000_000, 0))
	plan.Volumes[0].QuotaBytes++
	if err := Validate(plan); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unaligned XFS quota = %v, want ErrInvalid", err)
	}
}

func TestSignRejectsPlanBeyondTransportBound(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(nil)
	plan := validPlan(time.Unix(1_700_000_000, 0))
	plan.Volumes[0].ProductPublicKeyPEM = strings.Repeat("x", MaxPayloadBytes)
	if _, err := Sign(privateKey, plan); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized plan = %v, want ErrInvalid", err)
	}
}
