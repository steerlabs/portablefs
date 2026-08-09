//go:build linux

package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestReauthorizeCommandDeliversCredentialToExactLiveFuseSupervisor(t *testing.T) {
	e, stdout, stderr := testEnv(t)
	mountPath, err := canonicalMountPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	stateDir, err := e.mountStateDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	type observedRequest struct {
		token       string
		sequence    uint64
		certificate string
	}
	observed := make(chan observedRequest, 1)
	deadline := time.Now().Add(10 * time.Minute).Truncate(time.Millisecond)
	control, err := startFuseReauthorizationControl(
		stateDir,
		mountPath,
		func(_ context.Context, token string, sequence uint64, certificate []byte) (time.Time, error) {
			observed <- observedRequest{token: token, sequence: sequence, certificate: string(certificate)}
			return deadline, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()

	state := validFuseMountState(t, mountPath)
	state.Branch = ""
	state.Engine = mountEngineFuseV3
	state.DataPlaneTransport = dataPlaneTransportTLSSystemPKI
	state.DataPlaneServerName = "authority.example"
	state.AuthorizationSessionID = "AAAAAAAAAAAAAAAAAAAAAA"
	state.ReauthorizationControlSocket = control.SocketPath()
	writeRawMountState(t, stateDir, state)
	e.mountHealthFn = func(*mountState) string { return "live" }
	e.getenv = func(key string) string {
		if key == mountTokenEnv {
			return "v1.hosted-capability.signature"
		}
		return ""
	}
	certificatePath := filepath.Join(t.TempDir(), "renewed.pem")
	const certificate = "-----BEGIN CERTIFICATE-----\nrenewed\n-----END CERTIFICATE-----\n"
	if err := os.WriteFile(certificatePath, []byte(certificate), 0o600); err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().Add(9 * time.Minute).UnixMilli()
	if code := e.run([]string{
		"reauthorize", mountPath,
		"--client-cert", certificatePath,
		"--auth-expires-at-ms", formatInt64(expiresAt),
		"--auth-sequence", "3",
		"--json",
	}); code != 0 {
		t.Fatalf("reauthorize code=%d stderr=%s", code, stderr.String())
	}
	request := <-observed
	if request.token != "v1.hosted-capability.signature" || request.sequence != 3 || request.certificate != certificate {
		t.Fatalf("supervisor request = %+v", request)
	}
	var result reauthorizationResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.OK || result.MountPath != mountPath || result.Sequence != 3 || result.AuthorizationDeadlineUnixMs != deadline.UnixMilli() {
		t.Fatalf("reauthorization result = %+v", result)
	}
}

func TestReauthorizeCommandRefusesAnAutomaticallyOwnedMountBeforeDelivery(t *testing.T) {
	e, _, stderr := testEnv(t)
	mountPath, err := canonicalMountPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	stateDir, err := e.mountStateDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	state := validFuseMountState(t, mountPath)
	state.Branch = ""
	state.Engine = mountEngineFuseV3
	state.DataPlaneTransport = dataPlaneTransportTLSSystemPKI
	state.DataPlaneServerName = "authority.example"
	state.AuthorizationSessionID = "AAAAAAAAAAAAAAAAAAAAAA"
	state.MountEnrollmentID = "22222222-2222-4222-8222-222222222222"
	state.EnrollmentExpiresAtMs = time.Now().Add(time.Hour).UnixMilli()
	state.AuthorizationDeadlineAtMs = time.Now().Add(10 * time.Minute).UnixMilli()
	writeRawMountState(t, stateDir, state)
	e.mountHealthFn = func(*mountState) string { return "live" }
	e.getenv = func(key string) string {
		if key == mountTokenEnv {
			return "v1.hosted-capability.signature"
		}
		return ""
	}
	code := e.run([]string{
		"reauthorize", mountPath,
		"--client-cert", "/this/path/must/not/be/read",
		"--auth-expires-at-ms", formatInt64(time.Now().Add(9 * time.Minute).UnixMilli()),
		"--auth-sequence", "2",
	})
	if code == 0 || !strings.Contains(stderr.String(), "owned by its automatic Manager enrollment") {
		t.Fatalf("automatic owner refusal code=%d stderr=%s", code, stderr.String())
	}
}

func formatInt64(value int64) string {
	return strconv.FormatInt(value, 10)
}
