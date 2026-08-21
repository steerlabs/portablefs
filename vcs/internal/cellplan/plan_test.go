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
		AuthorityCAPEM: "authority-ca", ClientCAPEM: "client-ca", CapabilityPublicKey: "cap-key",
		Volumes: []VolumePlan{{
			VolumeID: "22222222-2222-4222-8222-222222222222", Phase: PhaseServe,
			AuthorizationDomain: "org", Owner: "owner", ProductIssuer: "product", ProductPublicKeyPEM: "product-key",
			AuthorityID: "authority", AuthorityGeneration: 4, ProjectID: 10001,
			ServiceUID: 200001, ServiceGID: 200001, ListenPort: 20001, QuotaBytes: 1 << 30, QuotaInodes: 1000,
			AuthorityServerName: "volume.example", AuthorityCertificate: "cert", PlacementSequence: 1,
		}},
	}
}

func validV1Plan(now time.Time) Plan {
	plan := validPlan(now)
	plan.Version = VersionV1
	plan.AuthorityCAPEM = ""
	plan.ClientCAPEM = ""
	plan.CapabilityPublicKey = ""
	plan.Volumes[0].PlacementSequence = 0
	plan.Volumes[0].AuthorityCAPEM = "authority-ca"
	plan.Volumes[0].ClientCAPEM = "client-ca"
	plan.Volumes[0].CapabilityPublicKey = "cap-key"
	return plan
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

func TestV1AndV2RoundTripAndDomainsAreDisjoint(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	now := time.Unix(1_700_000_000, 0)
	for _, plan := range []Plan{validV1Plan(now), validPlan(now)} {
		envelope, err := Sign(privateKey, plan)
		if err != nil {
			t.Fatal(err)
		}
		got, _, err := Verify(publicKey, envelope, plan.CellID, now, time.Second, 5*time.Minute)
		if err != nil || got.Version != plan.Version {
			t.Fatalf("version %d round trip = %d, %v", plan.Version, got.Version, err)
		}
		parts := strings.Split(envelope.Token, ".")
		if plan.Version == VersionV1 {
			parts[0] = "v2"
		} else {
			parts[0] = "v1"
		}
		if _, _, err := Verify(publicKey, Envelope{Token: strings.Join(parts, ".")}, plan.CellID, now, time.Second, 5*time.Minute); !errors.Is(err, ErrInvalid) {
			t.Fatalf("cross-version envelope for %d = %v", plan.Version, err)
		}
	}
}

func TestPhaseSpecificFieldsAreExact(t *testing.T) {
	base := validPlan(time.Unix(1_700_000_000, 0))
	for _, test := range []struct {
		name  string
		phase VolumePhase
		apply func(*VolumePlan)
		valid bool
	}{
		{name: "archive", phase: PhaseArchive, valid: true, apply: func(v *VolumePlan) {
			v.ArchiveTo = &ArchiveTarget{Attempt: "33333333-3333-4333-8333-333333333333", KeyVersion: "k1"}
		}},
		{name: "archive missing", phase: PhaseArchive},
		{name: "restore", phase: PhaseRestore, valid: true, apply: func(v *VolumePlan) {
			v.RestoreFrom = &RestoreSource{SealedEpoch: 2, Attempt: "33333333-3333-4333-8333-333333333333", ManifestDigestSHA256: strings.Repeat("a", 64), ManifestSizeBytes: 1, PackCount: 1, SealedAllocatedBytes: 1, SealedInodes: 1}
		}},
		{name: "release", phase: PhaseRelease, valid: true, apply: func(v *VolumePlan) {
			v.ReleaseProof = &ReleaseProof{PlacementSequence: 1, AuthorityEpoch: 2, DestroyProofSHA256: strings.Repeat("b", 64)}
		}},
		{name: "serve with archive", phase: PhaseServe, apply: func(v *VolumePlan) {
			v.ArchiveTo = &ArchiveTarget{Attempt: "33333333-3333-4333-8333-333333333333", KeyVersion: "k1"}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			plan := base
			plan.Volumes = append([]VolumePlan(nil), base.Volumes...)
			plan.Volumes[0].Phase = test.phase
			if test.apply != nil {
				test.apply(&plan.Volumes[0])
			}
			err := Validate(plan)
			if test.valid && err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if !test.valid && !errors.Is(err, ErrInvalid) {
				t.Fatalf("Validate = %v, want ErrInvalid", err)
			}
		})
	}
	v1 := validV1Plan(time.Unix(1_700_000_000, 0))
	v1.Volumes[0].Phase = PhaseArchive
	v1.Volumes[0].ArchiveTo = &ArchiveTarget{Attempt: "33333333-3333-4333-8333-333333333333", KeyVersion: "k1"}
	if err := Validate(v1); !errors.Is(err, ErrInvalid) {
		t.Fatalf("v1 archive = %v", err)
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
