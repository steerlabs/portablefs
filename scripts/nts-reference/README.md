# Read-only NTS reference

This test-only module supplies RFC 8915 observations to
`scripts/qualify-linux-workspace-clock.py`. It is outside the production module
graph. It never sets or slews a clock, persists keys/cookies, or uses a local
wall-clock estimate as reference UTC.

```bash
go -C scripts/nts-reference test -race ./...
go -C scripts/nts-reference build -o /absolute/path/nts-reference .
python3 scripts/qualify-linux-workspace-clock.py IMAGE SSH_CONFIG EVIDENCE \
  --seconds 1800 --dry-run --utc-reference-command /absolute/path/nts-reference
```

The adapter queries Cloudflare, Netnod and PTB concurrently. At least two
different operators must succeed. `-servers` can select a subset of this
operator-diverse allowlist. TLS 1.3 certificate/hostname verification, NTS-KE
ALPN, fresh request identifiers, authenticated NTPv4 extension verification and
NTP validity checks must all succeed before an observation is emitted. Failures
go to stderr; insufficient coverage exits nonzero without JSON.

`unix_ns` is the authenticated server transmit timestamp inside the command's
invocation. `uncertainty_ns` charges root dispersion, upward-rounded half of
nonnegative root delay, and at least one nanosecond of server precision. The
harness separately charges the complete reference-command and guest-sampling
transit windows; RTT is not added twice. This requires the normal trusted-server
and trusted-host assumptions. NTS authenticates a server's assertion; it does
not independently prove that server's UTC accuracy. Missing evidence remains
inconclusive.
