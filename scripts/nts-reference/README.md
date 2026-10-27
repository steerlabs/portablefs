# Read-only NTS reference

This test-only module uses [beevik/nts](https://github.com/beevik/nts) for
[RFC 8915](https://www.rfc-editor.org/rfc/rfc8915.html) observations to
`scripts/qualify-linux-workspace-clock.py`. It is outside the production module
graph. It never sets or slews a clock, persists keys/cookies, or uses a local
wall-clock estimate as reference UTC.

```bash
go -C scripts/nts-reference test -race ./...
go -C scripts/nts-reference build -o /absolute/path/nts-reference .
python3 scripts/qualify-linux-workspace-clock.py IMAGE SSH_CONFIG EVIDENCE \
  --seconds 1800 --dry-run --utc-reference-command /absolute/path/nts-reference
```

At least two approved operator groups must succeed. `-servers` can select
a subset of the pinned hostname allowlist, still requiring two groups. TLS 1.3 certificate/hostname verification, NTS-KE
ALPN, fresh request identifiers, authenticated NTPv4 extension verification and
NTP validity checks must all succeed before an observation is emitted. Failures
go to stderr and remain in the JSON exchange inventory.

`unix_ns` is the authenticated server transmit timestamp inside the command's
invocation. `uncertainty_ns` charges root dispersion, upward-rounded half of
nonnegative root delay, and at least one nanosecond of server precision. The
harness separately charges the complete NTP query and guest-sampling transit;
RTT is not added twice. Optional `query_began_ns`/`query_ended_ns` bracket the
NTP exchange in the named host kernel monotonic clock: `darwin.CLOCK_UPTIME_RAW`
(Python's `mach_absolute_time`) or `linux.CLOCK_MONOTONIC`. The parent verifies
both endpoints lie inside its full command interval and rejects a different
clock domain. Every NTP sampling/transit delay is charged; already-completed
NTS-KE precedes the fresh timestamp. Without this metadata the harness retains
the conservative full-invocation contract.
This requires the normal trusted-server
and trusted-host assumptions. NTS authenticates a server's assertion; it does
not independently prove that server's UTC accuracy. Missing evidence remains
inconclusive.

The G3 reference policy is pinned in `policy.json`: Cloudflare, Netnod, PTB,
SIDN/TimeNL and NIC.br/NTP.br. All approved aliases of one operator count once.
Each operator runs concurrently, trying IPv4 and IPv6 NTS-KE and the available
families of the authenticated negotiated UDP endpoint. TLS still validates the
approved DNS hostname. A failed operator gets at most one retry, optionally on
its next approved hostname. Both attempts share a nine-second aggregate deadline.
Each exchange carries host monotonic brackets and its failure, if any.

Partial collections retain successful authenticated responses and exchange
failures in JSON, including collections with fewer than two operators. The
qualifier decides whether they are usable. Every successful response is kept;
authenticated disagreement cannot be repaired by choosing a favorable pair.
There is no plain-NTP fallback or persisted cookie/key cache.
