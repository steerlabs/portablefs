package portablefsd

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/privatepath"
)

func daemonTestCAPEM(t *testing.T) string {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "PortableFS daemon test CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func daemonPrivateTransport(t *testing.T) dataPlaneTransport {
	t.Helper()
	ca := daemonTestCAPEM(t)
	sum := sha256.Sum256([]byte(ca))
	return dataPlaneTransport{
		mode:       "tls-private-ca",
		serverName: "router.example",
		caPEM:      ca,
		caSHA256:   hex.EncodeToString(sum[:]),
	}
}

func TestDaemonDataPlaneTransportModes(t *testing.T) {
	private := daemonPrivateTransport(t)
	cfg, err := private.tlsConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS13 || cfg.RootCAs == nil || cfg.ServerName != "router.example" {
		t.Fatalf("private config = %+v", cfg)
	}
	cfg, err = (dataPlaneTransport{mode: "tls-system-pki", serverName: "router.example"}).tlsConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS13 || cfg.RootCAs != nil || cfg.ServerName != "router.example" {
		t.Fatalf("system config = %+v", cfg)
	}
	cfg, err = (dataPlaneTransport{mode: "plaintext"}).tlsConfig()
	if err != nil || cfg != nil {
		t.Fatalf("plaintext config = %+v, %v", cfg, err)
	}
}

func TestDaemonDataPlaneTransportRejectsMismatchAndAmbiguity(t *testing.T) {
	private := daemonPrivateTransport(t)
	private.caSHA256 = strings.Repeat("0", 64)
	for _, transport := range []dataPlaneTransport{
		{},
		{mode: "future"},
		{mode: "plaintext", serverName: "router.example"},
		{mode: "tls-system-pki"},
		{mode: "tls-system-pki", serverName: "router.example", caPEM: "unexpected"},
		{mode: "tls-private-ca", serverName: "router.example"},
		private,
	} {
		if err := transport.validate(); err == nil {
			t.Errorf("transport %+v unexpectedly validated", transport)
		}
	}
}

func TestPersistedAttachRestartRejectsTransportFingerprintMismatch(t *testing.T) {
	stateDir := privateTestDir(t)
	transport := daemonPrivateTransport(t)
	entry := persistedAttachEntry{
		Ref:                 "att_TTTTTTTTTTTTTTTTTTTTTT",
		VolumeID:            "vol-transport",
		Branch:              "main",
		MountPath:           "/Volumes/Transport",
		AuthorityURL:        "router.example:2050",
		DataPlaneTransport:  transport.mode,
		DataPlaneServerName: transport.serverName,
		TLSCAPEM:            transport.caPEM,
		TLSCASHA256:         transport.caSHA256,
		Options:             AttachOptions{DiskCacheMB: 1},
		IdentityEpoch:       1,
	}
	if err := writePersistedAttaches(stateDir, []persistedAttachEntry{entry}); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadPersistedAttaches(stateDir)
	if err != nil {
		t.Fatalf("valid persisted transport: %v", err)
	}
	if len(loaded) != 1 || loaded[0].DataPlaneTransport != transport.mode ||
		loaded[0].DataPlaneServerName != transport.serverName ||
		loaded[0].TLSCASHA256 != transport.caSHA256 ||
		loaded[0].TLSCAPEM != transport.caPEM {
		t.Fatalf("persisted transport changed: %+v", loaded)
	}
	path := attachRegistryPath(stateDir)
	data, err := privatepath.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(
		string(data),
		entry.TLSCASHA256,
		strings.Repeat("0", 64),
		1,
	))
	if err := privatepath.WriteFileAtomic(path, data); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPersistedAttaches(stateDir); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("fingerprint mismatch did not fail restart inventory: %v", err)
	}
}
