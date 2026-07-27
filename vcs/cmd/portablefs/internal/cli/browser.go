package cli

import (
	"fmt"
	"net/url"
	"os/exec"
	"runtime"
)

// openURL launches the platform browser for an http(s) URL. Best-effort by
// design: login never fails because a browser could not start — the printed
// link is always the fallback (SSH sessions, containers, headless boxes).
func (e *cmdEnv) openURL(raw string) error {
	if e.openURLFn != nil {
		return e.openURLFn(raw)
	}
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("refusing to open non-http(s) URL %q", raw)
	}
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", raw).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", raw).Start()
	default:
		return exec.Command("xdg-open", raw).Start()
	}
}

// approvalURL is the verification URI with the user code prefilled, so the
// browser lands on a one-click approve screen (typing the code stays as the
// cross-machine fallback). The code rides a query parameter the console
// prefills; approval still requires an authenticated, explicit click.
func approvalURL(verificationURI, userCode string) string {
	parsed, err := url.Parse(verificationURI)
	if err != nil {
		return verificationURI
	}
	query := parsed.Query()
	query.Set("code", userCode)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}
