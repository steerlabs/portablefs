package cli

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// hostedAPIURL is the hosted control plane a bare `portablefs login` targets.
const hostedAPIURL = "https://portablefs.com"

func normalizeServerURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	return strings.TrimRight(raw, "/")
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// warnInsecureTransport flags a plaintext http:// target on a non-loopback
// host: the static bearer token and all file data would cross the network in
// cleartext, so the login is only safe behind an encrypted tunnel.
func warnInsecureTransport(e *cmdEnv, label, raw string) {
	if raw == "" {
		return
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" {
		return
	}
	host := u.Hostname()
	if host == "" || isLoopbackHost(host) {
		return
	}
	fmt.Fprintf(e.stderr,
		"portablefs login: warning: %s uses plaintext http:// to %s; your bearer token and file data cross the network in cleartext. Use https, or keep this on a trusted tunnel (e.g. Tailscale/WireGuard) only.\n",
		label, host)
}

func cmdLogin(e *cmdEnv, args []string) int {
	fs := newFlagSet("login")
	var (
		urlFlag      = fs.String("url", "", "PortableFS server URL")
		token        = fs.String("token", "", "API token to store (skips device login)")
		managerURL   = fs.String("manager-url", "", "authority manager URL (defaults to the server URL)")
		managerToken = fs.String("manager-token", "", "authority manager token (defaults to the API token)")
		profileFlag  = fs.String("profile", "default", "config profile to write")
		noBrowser    = fs.Bool("no-browser", false, "print the approval link instead of opening a browser")
		jsonOut      = fs.Bool("json", false, "print machine-readable JSON")
	)
	positionals, err := parseArgs(fs, args)
	if err != nil {
		return e.handleParseError("login", err)
	}
	serverURL := *urlFlag
	if len(positionals) > 1 {
		return e.usageError("login", fmt.Errorf("expected at most one URL argument, got %d", len(positionals)))
	}
	if len(positionals) == 1 {
		if serverURL != "" && serverURL != positionals[0] {
			return e.usageError("login", fmt.Errorf("server URL given twice (positional %q and --url %q)", positionals[0], serverURL))
		}
		serverURL = positionals[0]
	}

	cfg, cfgPath, err := e.loadConfig()
	if err != nil {
		return e.fail("login", err)
	}
	profileName := *profileFlag
	if serverURL == "" {
		serverURL = e.getenv("PORTABLEFS_API_URL")
	}
	if serverURL == "" {
		serverURL = cfg.Profiles[profileName].APIUrl
	}
	serverURL = normalizeServerURL(serverURL)
	if serverURL == "" {
		// Hosted-first default: a bare `portablefs login` lands on the hosted
		// control plane. Self-hosts pass a URL, --url, PORTABLEFS_API_URL, or
		// have one saved in the profile already.
		serverURL = hostedAPIURL
	}
	warnInsecureTransport(e, "server URL", serverURL)

	prof := Profile{
		APIUrl:       serverURL,
		ManagerUrl:   normalizeServerURL(*managerURL),
		ManagerToken: *managerToken,
	}
	warnInsecureTransport(e, "manager URL", prof.ManagerUrl)

	if *token != "" {
		prof.APIToken = *token
	} else {
		apiKey, serverManagerURL, err := deviceLogin(e, serverURL, *noBrowser)
		if err != nil {
			return e.fail("login", err)
		}
		prof.APIToken = apiKey
		if prof.ManagerUrl == "" && serverManagerURL != "" {
			prof.ManagerUrl = normalizeServerURL(serverManagerURL)
		}
	}

	// Capture the deployment's data-plane router CA so mounts trust its TLS
	// endpoint with zero local setup. Best-effort: deployments without a
	// published CA (plaintext dev routers, or trust distributed out of band
	// via PORTABLEFS_TLS_CA) simply store nothing.
	prof.DataPlaneCAPEM = fetchRouterCA(serverURL, prof.ManagerUrl)

	cfg.Profiles[profileName] = prof
	cfg.CurrentProfile = profileName
	if err := saveConfig(cfgPath, cfg); err != nil {
		return e.fail("login", err)
	}

	if err := verifyCredential(e, serverURL, prof.APIToken); err != nil {
		var skew *versionSkewError
		if errors.As(err, &skew) {
			// A too-old binary is not a credential problem; the saved
			// credentials are fine once the CLI is upgraded.
			return e.fail("login", skew)
		}
		return e.fail("login", fmt.Errorf("%w\ncredentials were saved to %s but were rejected; re-run `portablefs login %s --token <valid token>`", err, cfgPath, serverURL))
	}
	if *jsonOut {
		return e.printJSON(map[string]any{"apiUrl": serverURL, "profile": profileName, "verified": true})
	}
	fmt.Fprintf(e.stdout, "logged in to %s (profile %q, config %s)\n", serverURL, profileName, cfgPath)
	return 0
}

// fetchRouterCA retrieves the data-plane router CA bundle a deployment
// publishes at GET /router-ca.pem (the hosted control plane serves it from
// the API origin; a split self-host may serve it from the manager origin).
// The response must parse as PEM certificate material; anything else — 404,
// HTML error pages, an empty body — yields "" and mounts fall back to env
// trust (PORTABLEFS_TLS_CA) or plaintext for local routers.
func fetchRouterCA(origins ...string) string {
	client := &http.Client{Timeout: 10 * time.Second}
	seen := map[string]bool{}
	for _, origin := range origins {
		if origin == "" || seen[origin] {
			continue
		}
		seen[origin] = true
		resp, err := client.Get(origin + "/router-ca.pem")
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
		_ = resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			continue
		}
		if block, _ := pem.Decode(body); block == nil || block.Type != "CERTIFICATE" {
			continue
		}
		return string(body)
	}
	return ""
}

// verifyCredential checks the token against GET /v1/volumes. The server
// authenticates before routing, so ANY HTTP response other than 401/403 proves
// the token was accepted — including 404 from older builds without the listing
// route and 400 from admin tokens that need a tenantId query parameter.
func verifyCredential(e *cmdEnv, serverURL, token string) error {
	c := e.jsonClient(serverURL, token)
	err := c.do(context.Background(), "GET", "/v1/volumes", nil, nil, 0)
	if err == nil {
		return nil
	}
	var skew *versionSkewError
	if errors.As(err, &skew) {
		return skew
	}
	switch httpStatus(err) {
	case 401, 403:
		return fmt.Errorf("the server rejected the token (HTTP %d): check the token value and its tenant", httpStatus(err))
	case 0:
		return fmt.Errorf("verify credential: %w", err)
	default:
		return nil
	}
}

type deviceCodeResponse struct {
	DeviceCode       string `json:"deviceCode"`
	UserCode         string `json:"userCode"`
	VerificationURI  string `json:"verificationUri"`
	ExpiresInSeconds int    `json:"expiresInSeconds"`
	IntervalSeconds  int    `json:"intervalSeconds"`
}

// deviceLogin runs the OAuth-style device flow: request a user code, hand the
// human a one-click approval link (opening it in the local browser unless
// told not to), and poll for the minted API key. The key only ever travels
// over this authenticated poll channel — never through the browser redirect —
// so the browser hop needs no extra token plumbing.
func deviceLogin(e *cmdEnv, serverURL string, noBrowser bool) (apiKey, managerURL string, err error) {
	c := e.jsonClient(serverURL, "")
	var code deviceCodeResponse
	if err := c.do(context.Background(), "POST", "/v1/auth/device/code", map[string]string{}, &code, 0); err != nil {
		switch httpStatus(err) {
		case 404:
			return "", "", fmt.Errorf("this server does not support device login; pass --token")
		case 401, 403:
			return "", "", fmt.Errorf("this server requires a pre-issued token for login; pass --token")
		}
		return "", "", fmt.Errorf("start device login: %w", err)
	}
	if code.DeviceCode == "" || code.VerificationURI == "" {
		return "", "", fmt.Errorf("this server returned an incomplete device-login response; pass --token")
	}
	approve := approvalURL(code.VerificationURI, code.UserCode)
	opened := false
	if !noBrowser {
		// Best-effort: a headless box or SSH session falls through to the
		// printed link without failing the login.
		opened = e.openURL(approve) == nil
	}
	if opened {
		fmt.Fprintf(e.stdout, "Opened %s\n", approve)
		fmt.Fprintf(e.stdout, "Approve the request in your browser (code %s), then return here.\n", code.UserCode)
	} else {
		fmt.Fprintf(e.stdout, "Visit %s\n", approve)
		fmt.Fprintf(e.stdout, "or enter code %s at %s\n", code.UserCode, code.VerificationURI)
	}

	interval := time.Duration(code.IntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	expires := time.Duration(code.ExpiresInSeconds) * time.Second
	if expires <= 0 {
		expires = 15 * time.Minute
	}
	deadline := time.Now().Add(expires)
	sleep := e.sleeper()
	for {
		if time.Now().After(deadline) {
			return "", "", fmt.Errorf("device login expired before the code was entered; run `portablefs login` again")
		}
		status, body, err := c.doRaw(context.Background(), "POST", "/v1/auth/device/token", map[string]string{"deviceCode": code.DeviceCode})
		if err != nil {
			return "", "", fmt.Errorf("poll device login: %w", err)
		}
		switch {
		case status == 200:
			var tok struct {
				APIKey     string `json:"apiKey"`
				ManagerURL string `json:"managerUrl"`
				Status     string `json:"status"`
			}
			if err := json.Unmarshal(body, &tok); err != nil {
				return "", "", fmt.Errorf("poll device login: parse response: %w", err)
			}
			if tok.APIKey != "" {
				return tok.APIKey, tok.ManagerURL, nil
			}
			if tok.Status != "pending" {
				return "", "", fmt.Errorf("device login returned no apiKey; run `portablefs login` again or pass --token")
			}
		case status == 202:
			// pending
		case status == 400 || status == 410:
			he := parseErrorBody(status, body)
			return "", "", fmt.Errorf("device login was denied or expired: %v", he)
		default:
			return "", "", fmt.Errorf("poll device login: %v", parseErrorBody(status, body))
		}
		sleep(interval)
	}
}

func cmdLogout(e *cmdEnv, args []string) int {
	fs := newFlagSet("logout")
	var (
		profileFlag = fs.String("profile", "", "config profile to clear (default: currentProfile)")
		jsonOut     = fs.Bool("json", false, "print machine-readable JSON")
	)
	if _, err := parseArgs(fs, args); err != nil {
		return e.handleParseError("logout", err)
	}
	cfg, cfgPath, err := e.loadConfig()
	if err != nil {
		return e.fail("logout", err)
	}
	name := *profileFlag
	if name == "" {
		name = cfg.CurrentProfile
	}
	if _, ok := cfg.Profiles[name]; !ok {
		return e.fail("logout", fmt.Errorf("profile %q has no saved credentials in %s", name, cfgPath))
	}
	delete(cfg.Profiles, name)
	if err := saveConfig(cfgPath, cfg); err != nil {
		return e.fail("logout", err)
	}
	if *jsonOut {
		return e.printJSON(map[string]any{"profile": name, "removed": true})
	}
	fmt.Fprintf(e.stdout, "removed credentials for profile %q from %s\n", name, cfgPath)
	return 0
}

// sleeper returns the poll-delay function; tests override sleepFn.
func (e *cmdEnv) sleeper() func(time.Duration) {
	if e.sleepFn != nil {
		return e.sleepFn
	}
	return time.Sleep
}
