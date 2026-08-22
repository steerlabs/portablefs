package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/portablefsd"
)

// testClientIdentityFiles writes one self-signed mutual-TLS client identity
// to disk the way a manager-issued one arrives: a readable certificate and a
// 0600 private key.
func testClientIdentityFiles(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "portablefs test client"},
		NotBefore:    now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "client.pem")
	keyPath = filepath.Join(dir, "client.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// v3MountOpts is one complete, valid direct v3 credential shape.
func v3MountOpts(t *testing.T) *mountOpts {
	t.Helper()
	certPath, keyPath := testClientIdentityFiles(t)
	return &mountOpts{
		addr:                "127.0.0.1:2050",
		mountToken:          "capability",
		dataPlaneTransport:  dataPlaneTransportTLSSystemPKI,
		dataPlaneServerName: "authority.example",
		clientCertPath:      certPath,
		clientKeyPath:       keyPath,
		coherence:           "strict",
	}
}

func noEnv(string) string { return "" }

// TestValidateDirectV3MountOptsAcceptsTheDocumentedShape pins the one
// credential shape every mount takes now.
func TestValidateDirectV3MountOptsAcceptsTheDocumentedShape(t *testing.T) {
	o := v3MountOpts(t)
	transport, err := validateDirectV3MountOpts(o, noEnv)
	if err != nil {
		t.Fatalf("complete v3 shape refused: %v", err)
	}
	if transport.Mode != dataPlaneTransportTLSSystemPKI || transport.ServerName != "authority.example" {
		t.Fatalf("validated transport = %+v", transport)
	}
	if _, err := loadClientTLSIdentity(o.clientCertPath, o.clientKeyPath); err != nil {
		t.Fatalf("valid client identity refused: %v", err)
	}
}

func TestMountOptionsParseAutomaticEnrollmentWithoutLeaseExpiryFlag(t *testing.T) {
	fs := newFlagSet("mount")
	parsed := &mountOpts{}
	addMountFlags(fs, parsed)
	positionals, err := parseArgs(fs, []string{
		"volume", "/mnt/volume", "--manager-url", "https://manager.example",
		"--manager-server-name", "manager.example", "--manager-ca", "/manager-ca.pem",
		"--mount-enrollment-id", "22222222-2222-4222-8222-222222222222",
		"--mount-enrollment-cert", "/enrollment.pem", "--authority-generation", "7",
		"--auth-expires-at-ms", "2000000000000",
	})
	if err != nil || len(positionals) != 2 || parsed.enrollmentID == "" || parsed.authorityGeneration != 7 {
		t.Fatalf("automatic enrollment options = %+v, positionals=%v, err=%v", parsed, positionals, err)
	}

	removed := newFlagSet("mount")
	addMountFlags(removed, &mountOpts{})
	removedExpiryFlag := "--mount-enrollment-" + "expires-at-ms"
	if _, err := parseArgs(removed, []string{"volume", "/mnt/volume", removedExpiryFlag, "2000000000000"}); err == nil {
		t.Fatalf("removed %s flag was accepted", removedExpiryFlag)
	}
}

func TestValidateDirectV3MountOptsRefusesPartialOrExpiredAutomaticEnrollment(t *testing.T) {
	o := v3MountOpts(t)
	o.managerURL = "https://manager.example"
	if _, err := validateDirectV3MountOpts(o, noEnv); err == nil || !strings.Contains(err.Error(), "requires --manager-url") {
		t.Fatalf("partial automatic enrollment = %v", err)
	}

	now := time.Now()
	o.managerServerName = "manager.example"
	o.managerCAPath = "/manager-ca.pem"
	o.enrollmentID = "22222222-2222-4222-8222-222222222222"
	o.enrollmentCertPath = "/enrollment.pem"
	o.authorityGeneration = 7
	o.authExpiresAtMs = now.Add(-time.Second).UnixMilli()
	if _, err := validateDirectV3MountOpts(o, noEnv); err == nil || !strings.Contains(err.Error(), "must be unexpired") {
		t.Fatalf("expired initial authorization = %v", err)
	}
}

func TestAutomaticEnrollmentClosesOnlyBeforeOwnershipOrAfterExactCleanup(t *testing.T) {
	for _, test := range []struct {
		name             string
		ownerEstablished bool
		cleanupComplete  bool
		want             bool
	}{
		{name: "not handed to mount owner", want: true},
		{name: "live owner and unproven cleanup", ownerEstablished: true, want: false},
		{name: "owner proven terminal", ownerEstablished: true, cleanupComplete: true, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := automaticEnrollmentCanCloseAfterStartupFailure(test.ownerEstablished, test.cleanupComplete); got != test.want {
				t.Fatalf("close policy = %t, want %t", got, test.want)
			}
		})
	}
}

// TestValidateDirectV3MountOptsNamesEveryMissingPiece pins that each refusal
// names the exact flag the caller must add — the errors are the migration
// path off the manager/lease flow, so their content is the contract.
func TestValidateDirectV3MountOptsNamesEveryMissingPiece(t *testing.T) {
	mutate := map[string]struct {
		change func(*mountOpts)
		want   string
	}{
		"no addr":          {func(o *mountOpts) { o.addr = "" }, "--addr"},
		"no transport":     {func(o *mountOpts) { o.dataPlaneTransport = "" }, "--data-plane-transport"},
		"plaintext":        {func(o *mountOpts) { o.dataPlaneTransport = dataPlaneTransportPlaintext }, "mutually authenticated TLS"},
		"no token":         {func(o *mountOpts) { o.mountToken = "" }, "--mount-token"},
		"no client cert":   {func(o *mountOpts) { o.clientCertPath = "" }, "--client-cert"},
		"no client key":    {func(o *mountOpts) { o.clientKeyPath = "" }, "--client-key"},
		"bad coherence":    {func(o *mountOpts) { o.coherence = "eventual" }, "--coherence"},
		"retired uncached": {func(o *mountOpts) { o.coherence = "uncached" }, "--coherence must be strict"},
		"local-dir":        {func(o *mountOpts) { o.localDirs = stringListFlag{"node_modules"} }, "declared volume-wide"},
		"lease-only shape": {func(o *mountOpts) { o.addr = ""; o.dataPlaneTransport = ""; o.mountToken = "" }, "cannot mint v3 credentials"},
	}
	for name, tc := range mutate {
		o := v3MountOpts(t)
		tc.change(o)
		_, err := validateDirectV3MountOpts(o, noEnv)
		if err == nil {
			t.Fatalf("%s: incomplete v3 shape accepted", name)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: refusal %q does not name %q", name, err, tc.want)
		}
	}
}

// TestMountCommandRefusesLegacyManagerLeaseInvocation pins the CLI edge: the
// plain v2-era invocation fails with the direct-credential guidance and never
// falls back to the clientcore engine.
func TestMountCommandRefusesLegacyManagerLeaseInvocation(t *testing.T) {
	e, _, stderr := testEnv(t)
	if rc := e.run([]string{"mount", "vol_1", filepath.Join(t.TempDir(), "m")}); rc == 0 {
		t.Fatal("manager/lease-only mount invocation succeeded")
	}
	out := stderr.String()
	for _, want := range []string{"--addr", "--mount-token", "--client-cert", "cannot mint v3 credentials"} {
		if !strings.Contains(out, want) {
			t.Fatalf("refusal %q does not name %q", out, want)
		}
	}
}

func TestMountCommandRefusesRetiredBranchFlag(t *testing.T) {
	e, _, stderr := testEnv(t)
	if rc := e.run([]string{"mount", "vol_1", filepath.Join(t.TempDir(), "m"), "--branch=dev"}); rc == 0 {
		t.Fatal("retired --branch flag accepted")
	}
	if !strings.Contains(stderr.String(), "branchless") {
		t.Fatalf("refusal %q does not explain that v3 volumes are branchless", stderr.String())
	}
}

func TestMountCommandRefusesPlaintextTransport(t *testing.T) {
	e, _, stderr := testEnv(t)
	o := v3MountOpts(t)
	args := []string{
		"mount", "vol_1", filepath.Join(t.TempDir(), "m"),
		"--addr", o.addr, "--mount-token", o.mountToken,
		"--data-plane-transport", "plaintext",
		"--client-cert", o.clientCertPath, "--client-key", o.clientKeyPath,
	}
	if rc := e.run(args); rc == 0 {
		t.Fatal("plaintext v3 mount accepted")
	}
	if !strings.Contains(stderr.String(), "mutually authenticated TLS") {
		t.Fatalf("refusal %q does not explain the TLS requirement", stderr.String())
	}
}

// TestLoadClientTLSIdentityRefusesAWorldReadableKey: a mount identity that
// any local user can read is a misconfiguration to stop on.
func TestLoadClientTLSIdentityRefusesAWorldReadableKey(t *testing.T) {
	certPath, keyPath := testClientIdentityFiles(t)
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadClientTLSIdentity(certPath, keyPath); err == nil {
		t.Fatal("world-readable client key accepted")
	} else if !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("refusal %q does not name the repair", err)
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadClientTLSIdentity(certPath, keyPath); err != nil {
		t.Fatalf("private key refused after repair: %v", err)
	}
}

// TestMountStateEngineValidation pins the (strategy, engine) record contract:
// v3 records are branchless, engines pair with their platform transport, and
// an unknown engine is invalid rather than silently legacy.
func TestMountStateEngineValidation(t *testing.T) {
	valid := func() mountState {
		st := validFuseMountState(t, "/tmp/v3")
		st.Engine = mountEngineFuseV3
		st.Branch = ""
		st.DataPlaneTransport = dataPlaneTransportTLSSystemPKI
		st.DataPlaneServerName = "authority.example"
		return st
	}
	if err := validateMountStateRecord("test", &mountState{}); err == nil {
		t.Fatal("empty record accepted")
	}
	st := valid()
	if err := validateMountStateRecord("test", &st); err != nil {
		t.Fatalf("valid v3 FUSE record refused: %v", err)
	}
	st = valid()
	st.Branch = "main"
	if err := validateMountStateRecord("test", &st); err == nil {
		t.Fatal("branch on a branchless v3 record accepted")
	}
	st = valid()
	st.Engine = mountEngineDaemonV3
	if err := validateMountStateRecord("test", &st); err == nil {
		t.Fatal("daemon-v3 engine on a FUSE record accepted")
	}
	st = valid()
	st.Engine = "v4"
	if err := validateMountStateRecord("test", &st); err == nil {
		t.Fatal("unknown engine accepted")
	}
	fskit := validFSKitMountState(t, "/tmp/v3-fskit")
	fskit.Engine = mountEngineDaemonV3
	fskit.Branch = ""
	if err := validateMountStateRecord("test", &fskit); err != nil {
		t.Fatalf("valid daemon-v3 FSKit record refused: %v", err)
	}
	fskit.Engine = mountEngineFuseV3
	if err := validateMountStateRecord("test", &fskit); err == nil {
		t.Fatal("fusev3 engine on an FSKit record accepted")
	}
}

// TestMountIntentEngineValidation pins the same pairing on the durable
// operation intent, which must describe the identical transaction.
func TestMountIntentEngineValidation(t *testing.T) {
	base := func() mountIntent {
		return mountIntent{
			SchemaVersion: 2, Phase: "starting", MountPath: "/tmp/v3",
			OperationOwnerPID: os.Getpid(), OperationOwnerStartIdentity: "id",
			UpdatedAtMs: 1,
		}
	}
	intent := base()
	intent.Engine = mountEngineFuseV3
	if err := validateMountIntent("test", &intent); err != nil {
		t.Fatalf("fusev3 starting intent refused: %v", err)
	}
	intent = base()
	intent.Engine = mountEngineFuseV3
	intent.Strategy = "fskit"
	if err := validateMountIntent("test", &intent); err == nil {
		t.Fatal("fusev3 engine on an fskit intent accepted")
	}
	intent = base()
	intent.Engine = "clientcore2"
	if err := validateMountIntent("test", &intent); err == nil {
		t.Fatal("unknown intent engine accepted")
	}
}

// TestFskitEnsureRequestCarriesTheDaemonV3Contract pins the exact wire shape
// portablefsd's v3AttachRequest decodes: the mutual-TLS identity, the two
// barrier numbers, the declared macOS 26 cache policy, an empty branch, and
// a well-formed 64-hex routes revision.
func TestFskitEnsureRequestCarriesTheDaemonV3Contract(t *testing.T) {
	req := fskitEnsureAttachRequest{
		AttachRef:           "att_AAAAAAAAAAAAAAAAAAAAAA",
		VolumeID:            "vol_1",
		Branch:              "",
		AuthorityURL:        "127.0.0.1:2050",
		AuthToken:           "capability",
		DataPlaneTransport:  dataPlaneTransportTLSSystemPKI,
		DataPlaneServerName: "authority.example",
		MountPath:           "/tmp/v3",
		Options:             fskitAttachOptions{},
		V3: &fskitV3AttachRequest{
			ClientCertPEM:      "CERT",
			ClientKeyPEM:       "KEY",
			CachedNameCapacity: 1 << 16,
			RepairBudgetMillis: 15_000,
			CachePolicy:        portablefsd.V3CachePolicyMacOS26,
			RoutesRevision:     emptyRoutesRevision(),
		},
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["branch"] != "" {
		t.Fatalf("a v3 ensure request must be branchless, got branch %v", decoded["branch"])
	}
	v3, ok := decoded["v3"].(map[string]any)
	if !ok {
		t.Fatalf("ensure request carries no v3 block: %s", data)
	}
	for key, want := range map[string]any{
		"clientCertPem":      "CERT",
		"clientKeyPem":       "KEY",
		"cachedNameCapacity": float64(1 << 16),
		"repairBudgetMillis": float64(15_000),
		"cachePolicy":        "macos26-synchronous-vfs-repair-v2",
	} {
		if v3[key] != want {
			t.Fatalf("v3 block key %q = %v, want %v", key, v3[key], want)
		}
	}
	revision, _ := v3["routesRevision"].(string)
	if !regexp.MustCompile("^[0-9a-f]{64}$").MatchString(revision) {
		t.Fatalf("routesRevision %q is not 64 lowercase hex digits", revision)
	}
}

// TestUmountReconcilesStaleV3FuseRecordWithoutForce pins the engine-aware
// teardown: a v3 FUSE mount holds no write-back tail, so a record whose
// kernel mount and owner are both gone reconciles on a plain umount — the v2
// path demanded --force here to park a journal that v3 does not have.
func TestUmountReconcilesStaleV3FuseRecordWithoutForce(t *testing.T) {
	e, stdout, stderr, stateDir := umountTestEnv(t)
	mountPath, err := canonicalMountPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st := validFuseMountState(t, mountPath)
	st.Engine = mountEngineFuseV3
	st.Branch = ""
	st.DataPlaneTransport = dataPlaneTransportTLSSystemPKI
	st.DataPlaneServerName = "authority.example"
	st.PID = 4194000
	st.ProcessStartIdentity = "dead-process"
	if err := writeMountState(stateDir, st); err != nil {
		t.Fatal(err)
	}
	if rc := e.run([]string{"umount", mountPath}); rc != 0 {
		t.Fatalf("plain umount of a stale v3 record failed: %s", stderr.String())
	}
	if !strings.Contains(stdout.String()+stderr.String(), "reconciled stale mount state") {
		t.Fatalf("reconciliation was not reported: %q %q", stdout.String(), stderr.String())
	}
	remaining, err := readMountState(stateDir, mountPath)
	if err != nil || remaining != nil {
		t.Fatalf("stale v3 record was not removed: %+v %v", remaining, err)
	}
}

// TestUmountStaleV2FuseRecordStillFailsClosed pins that the engine gate did
// not weaken the legacy contract: a clientcore record with a possible
// write-back tail still refuses the same plain unmount.
func TestUmountStaleV2FuseRecordStillFailsClosed(t *testing.T) {
	e, _, stderr, stateDir := umountTestEnv(t)
	mountPath, err := canonicalMountPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st := validFuseMountState(t, mountPath)
	st.PID = 4194000
	st.ProcessStartIdentity = "dead-process"
	if err := writeMountState(stateDir, st); err != nil {
		t.Fatal(err)
	}
	if rc := e.run([]string{"umount", mountPath}); rc == 0 {
		t.Fatal("plain umount of a stale v2 record succeeded")
	}
	if !strings.Contains(stderr.String(), "cannot prove a clean drain") {
		t.Fatalf("v2 fail-closed detail missing: %q", stderr.String())
	}
}
