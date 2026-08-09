package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"time"
)

type reauthorizeOpts struct {
	common       commonOpts
	clientCert   string
	expiresAtMs  int64
	authSequence uint64
}

type reauthorizationResult struct {
	AuthorizationDeadlineUnixMs int64  `json:"authorizationDeadlineUnixMs"`
	MountPath                   string `json:"mountPath"`
	OK                          bool   `json:"ok"`
	Sequence                    uint64 `json:"sequence"`
}

func cmdReauthorize(e *cmdEnv, args []string) int {
	fs := newFlagSet("reauthorize")
	var o reauthorizeOpts
	addCommonFlags(fs, &o.common)
	fs.StringVar(&o.clientCert, "client-cert", "", "renewed mutual-TLS client certificate PEM file")
	fs.Int64Var(&o.expiresAtMs, "auth-expires-at-ms", 0, "manager authorization expiry as unix milliseconds")
	fs.Uint64Var(&o.authSequence, "auth-sequence", 0, "exact positive manager reauthorization sequence")
	positionals, err := parseArgs(fs, args)
	if err != nil {
		return e.handleParseError("reauthorize", err)
	}
	if len(positionals) != 1 || o.clientCert == "" || o.expiresAtMs <= 0 || o.authSequence == 0 {
		return e.usageError("reauthorize", fmt.Errorf("requires <mountPath>, --client-cert, --auth-expires-at-ms, and --auth-sequence"))
	}
	token := e.getenv(mountTokenEnv)
	if token == "" {
		return e.usageError("reauthorize", fmt.Errorf("set %s to the manager-issued reauthorization capability", mountTokenEnv))
	}
	if len(token) > 32<<10 {
		return e.usageError("reauthorize", fmt.Errorf("%s exceeds the credential bound", mountTokenEnv))
	}
	if o.expiresAtMs <= time.Now().UnixMilli() {
		return e.usageError("reauthorize", fmt.Errorf("--auth-expires-at-ms is already expired"))
	}
	mountPath, err := canonicalMountPath(positionals[0])
	if err != nil {
		return e.fail("reauthorize", err)
	}
	stateDir, err := e.mountStateDir()
	if err != nil {
		return e.fail("reauthorize", err)
	}
	state, err := readMountState(stateDir, mountPath)
	if err != nil {
		return e.fail("reauthorize", err)
	}
	if state == nil || e.classifyMount(state) != "live" {
		return e.fail("reauthorize", fmt.Errorf("no exact live PortableFS mount is recorded at %s", mountPath))
	}
	if state.Engine != mountEngineFuseV3 && state.Engine != mountEngineDaemonV3 {
		return e.fail("reauthorize", fmt.Errorf("mount does not support hosted v3 reauthorization"))
	}
	if state.AuthorizationSessionID == "" {
		return e.fail("reauthorize", fmt.Errorf("mount predates hosted reauthorization support and must be remounted once"))
	}
	if state.MountEnrollmentID != "" {
		return e.fail("reauthorize", fmt.Errorf("mount authorization is owned by its automatic Manager enrollment; manual reauthorization is refused"))
	}
	certificatePEM, err := readBoundedRegularFile(o.clientCert, false)
	if err != nil {
		return e.fail("reauthorize", fmt.Errorf("read --client-cert: %w", err))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var deadline time.Time
	switch state.Strategy {
	case "fuse":
		deadline, err = reauthorizeFuseMount(ctx, state, token, o.authSequence, certificatePEM)
	case "fskit":
		cfg, configErr := fskitConfigFromEnv(e.getenv)
		if configErr != nil {
			err = configErr
			break
		}
		ctl, ensureErr := e.ensureFskitDaemon(cfg, filepath.Dir(stateDir))
		if ensureErr != nil {
			err = ensureErr
			break
		}
		deadline, err = ctl.reauthorizeCredential(state.AttachRef, token, o.expiresAtMs, o.authSequence, string(certificatePEM))
	default:
		err = fmt.Errorf("unsupported mount strategy %q", state.Strategy)
	}
	if err != nil {
		return e.fail("reauthorize", err)
	}
	result := reauthorizationResult{
		AuthorizationDeadlineUnixMs: deadline.UnixMilli(),
		MountPath:                   mountPath,
		OK:                          true,
		Sequence:                    o.authSequence,
	}
	if o.common.jsonOut {
		return e.printJSON(result)
	}
	fmt.Fprintf(e.stdout, "reauthorized %s through sequence %s\n", mountPath, strconv.FormatUint(o.authSequence, 10))
	return 0
}
