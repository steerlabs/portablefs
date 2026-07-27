package fsproto

import "testing"

// TestSetAuthTokenPreservesInstalledSource pins m3: a CredentialSource must win over — and survive — a
// later SetAuthToken (RenewCredential). The old SetAuthToken nil'd the source, pinning a
// source-configured client to a static token forever.
func TestSetAuthTokenPreservesInstalledSource(t *testing.T) {
	c := &Client{}
	c.SetAuthTokenSource(func() string { return "from-source" })
	c.SetAuthToken("static")

	if got := c.tokenForHandshake(); got != "from-source" {
		t.Fatalf("installed source must win over a later SetAuthToken: got %q, want from-source", got)
	}
}

// TestSetAuthTokenUsedWhenNoSource: with no source installed, SetAuthToken is authoritative.
func TestSetAuthTokenUsedWhenNoSource(t *testing.T) {
	c := &Client{}
	c.SetAuthToken("static-token")
	if got := c.tokenForHandshake(); got != "static-token" {
		t.Fatalf("static token should be used when no source: got %q", got)
	}
}
