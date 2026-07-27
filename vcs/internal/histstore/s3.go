package histstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// S3Store is one S3-compatible failure domain: exact-key PUT/GET/HEAD/DELETE
// over a configured endpoint/region/bucket/prefix with SigV4 signing,
// streaming bodies in both directions (no whole-object buffering), per-call
// deadlines, context abort, and bounded backoff over transient throttling
// (see RetryPolicy).
type S3Store struct {
	cfg    S3Config
	base   *url.URL
	client *http.Client
	now    func() time.Time
	retry  RetryPolicy

	retries          atomic.Int64
	retriesExhausted atomic.Int64
}

// S3Config configures one S3-compatible failure domain. Secrets are held in
// memory only; nothing in this package logs them.
type S3Config struct {
	// Domain is the operator-declared failure-domain id (required).
	Domain string
	// Endpoint is the https(s) base URL of the S3-compatible service.
	Endpoint string
	// Region participates in SigV4 scope ("auto" for many R2-likes).
	Region string
	// Bucket is the bucket name (required).
	Bucket string
	// Prefix is an optional validated key prefix inside the bucket.
	Prefix string
	// PathStyle selects path-style addressing (endpoint/bucket/key) instead
	// of virtual-host style (bucket.endpoint/key).
	PathStyle bool
	// AccessKeyID / SecretAccessKey are the SigV4 credentials (required).
	AccessKeyID     string
	SecretAccessKey string
	// OperationTimeout bounds each single HTTP ATTEMPT including the body
	// transfer (default 2 minutes).
	OperationTimeout time.Duration
	// Retry bounds the backoff over transient failures (503 SlowDown, 429,
	// reset connections). The zero value takes the package defaults; set
	// MaxAttempts to 1 to disable retrying.
	Retry RetryPolicy
	// OnRetry, when set, observes every absorbed transient failure. The
	// store also counts them (RetryStats) so callers without a hook still
	// see throttling. It must not block.
	OnRetry func(RetryEvent)
	// Transport overrides the HTTP transport (tests). Nil uses a dedicated
	// production transport with sane connection bounds.
	Transport http.RoundTripper
	// Now overrides the signing clock (tests).
	Now func() time.Time
}

// NewS3Store validates the configuration; it performs no network I/O.
func NewS3Store(cfg S3Config) (*S3Store, error) {
	if strings.TrimSpace(cfg.Domain) == "" {
		return nil, errors.New("histstore: s3 store requires a failure domain id")
	}
	base, err := url.Parse(cfg.Endpoint)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return nil, fmt.Errorf("histstore: s3 endpoint %q must be an http(s) URL", cfg.Endpoint)
	}
	if base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("histstore: s3 endpoint must not carry query or fragment")
	}
	if cfg.Bucket == "" || strings.ContainsAny(cfg.Bucket, "/ ") {
		return nil, fmt.Errorf("histstore: s3 bucket %q is invalid", cfg.Bucket)
	}
	if cfg.Region == "" {
		return nil, errors.New("histstore: s3 region is required")
	}
	if cfg.AccessKeyID == "" || cfg.SecretAccessKey == "" {
		return nil, errors.New("histstore: s3 credentials are required")
	}
	if cfg.Prefix != "" {
		if err := ValidateKey(cfg.Prefix); err != nil {
			return nil, fmt.Errorf("histstore: s3 prefix: %w", err)
		}
	}
	if cfg.OperationTimeout <= 0 {
		cfg.OperationTimeout = 2 * time.Minute
	}
	transport := cfg.Transport
	if transport == nil {
		transport = &http.Transport{
			MaxIdleConns:        16,
			MaxIdleConnsPerHost: 8,
			IdleConnTimeout:     90 * time.Second,
		}
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &S3Store{
		cfg:    cfg,
		base:   base,
		client: &http.Client{Transport: transport},
		now:    now,
		retry:  cfg.Retry.withDefaults(),
	}, nil
}

// RetryStats implements RetryReporter: how much transient backend throttling
// this store has absorbed since the process started.
func (s *S3Store) RetryStats() RetryStats {
	return RetryStats{
		Retries:   s.retries.Load(),
		Exhausted: s.retriesExhausted.Load(),
	}
}

// Domain implements Store.
func (s *S3Store) Domain() string { return strings.TrimSpace(s.cfg.Domain) }

// ExactKey implements Store.
func (s *S3Store) ExactKey(id ObjectID) (string, error) {
	key, err := id.Key()
	if err != nil {
		return "", err
	}
	return JoinPrefix(s.cfg.Prefix, key)
}

// objectURL builds the request URL for one validated key. The key is
// assigned in DECODED form; net/url escapes it exactly once on the wire and
// the signer covers that same escaped path (canonicalURI == EscapedPath).
func (s *S3Store) objectURL(key string) *url.URL {
	u := *s.base
	if s.cfg.PathStyle {
		u.Path = joinURLPath(s.base.Path, s.cfg.Bucket, key)
	} else {
		u.Host = s.cfg.Bucket + "." + s.base.Host
		u.Path = joinURLPath(s.base.Path, key)
	}
	return &u
}

// bodyFactory opens the request body for ONE attempt. replayable reports
// whether open may be called again for a retry — only a rewindable source
// can be re-sent byte for byte, and a body that cannot be rewound must never
// be re-issued after the transport may already have consumed it.
type bodyFactory struct {
	open       func() (io.Reader, error)
	replayable bool
}

// newBodyFactory adapts one caller-supplied body to the retry loop. The
// worker always uploads from an in-memory bytes.Reader, so PUTs are
// rewindable and therefore retriable; a piped or streamed body (the rehome
// copy path) stays single-shot and behaves exactly as it did before.
func newBodyFactory(body io.Reader, size int64) *bodyFactory {
	if seeker, ok := body.(io.Seeker); ok {
		if start, err := seeker.Seek(0, io.SeekCurrent); err == nil {
			return &bodyFactory{
				replayable: true,
				open: func() (io.Reader, error) {
					if _, err := seeker.Seek(start, io.SeekStart); err != nil {
						return nil, err
					}
					return io.LimitReader(body, size), nil
				},
			}
		}
	}
	limited := io.LimitReader(body, size)
	return &bodyFactory{open: func() (io.Reader, error) { return limited, nil }}
}

// attempt issues ONE signed request under its own operation deadline.
// retriable reports whether a transport failure is the kind a later attempt
// could still succeed at.
func (s *S3Store) attempt(ctx context.Context, method, key, payloadHash string, size int64, body *bodyFactory) (
	resp *http.Response, cancel context.CancelFunc, retriable bool, err error) {
	var reader io.Reader
	if body != nil {
		reader, err = body.open()
		if err != nil {
			return nil, nil, false, fmt.Errorf("histstore: rewind %s %s/%s: %w", method, s.Domain(), key, err)
		}
	}
	opCtx, opCancel := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	req, err := http.NewRequestWithContext(opCtx, method, s.objectURL(key).String(), reader)
	if err != nil {
		opCancel()
		return nil, nil, false, fmt.Errorf("histstore: build %s %s/%s: %w", method, s.Domain(), key, err)
	}
	if reader != nil {
		// The exact declared length streams the body with no buffering and
		// no chunked encoding (widest S3-compatible support).
		req.ContentLength = size
	}
	signV4(req, s.cfg.Region, s.cfg.AccessKeyID, s.cfg.SecretAccessKey, payloadHash, s.now())
	resp, err = s.client.Do(req)
	if err != nil {
		opCancel()
		return nil, nil, retriableTransportError(err),
			fmt.Errorf("histstore: %s %s/%s: %w", method, s.Domain(), key, err)
	}
	return resp, opCancel, false, nil
}

// do issues one exact-key operation, absorbing bounded transient failure:
// throttling responses (503 SlowDown, 429) and transient server/transport
// failures are retried with exponential backoff and full jitter, everything
// else is returned on the first attempt. Retries never change the bytes
// written or the key they are written to, so the fold stays deterministic.
//
// Exhausting the budget surfaces the failure EXACTLY as it did before this
// existed — the last response is returned for the caller to classify, or the
// last transport error is returned wrapped — so the cut-level retry remains
// the outer loop and nothing here can loop unboundedly.
func (s *S3Store) do(ctx context.Context, method, key, payloadHash string, size int64, body *bodyFactory) (*http.Response, context.CancelFunc, error) {
	if err := ValidateKey(key); err != nil {
		return nil, nil, err
	}
	maxAttempts := s.retry.MaxAttempts
	if body != nil && !body.replayable {
		maxAttempts = 1
	}
	for attempt := 1; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, nil, fmt.Errorf("histstore: %s %s/%s: %w", method, s.Domain(), key, err)
		}
		resp, cancel, retriable, err := s.attempt(ctx, method, key, payloadHash, size, body)
		status := 0
		if err == nil {
			status = resp.StatusCode
			retriable = retriableStatus(status)
			if !retriable {
				return resp, cancel, nil
			}
		} else if !retriable {
			return nil, nil, err
		}
		if attempt >= maxAttempts {
			if maxAttempts > 1 {
				s.retriesExhausted.Add(1)
			}
			if err != nil {
				return nil, nil, err
			}
			// The caller classifies this response itself (httpError), so a
			// throttled-out PUT reads identically to a pre-retry one.
			return resp, cancel, nil
		}
		if resp != nil {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
			resp.Body.Close()
			cancel()
		}
		delay := s.retry.delay(attempt)
		if waitErr := sleepBackoff(ctx, delay); waitErr != nil {
			// Fenced or shut down mid-backoff: abort now, do not sleep out
			// the remaining delay and do not re-issue the operation.
			return nil, nil, fmt.Errorf("histstore: %s %s/%s: %w", method, s.Domain(), key, waitErr)
		}
		s.retries.Add(1)
		if s.cfg.OnRetry != nil {
			s.cfg.OnRetry(RetryEvent{
				Domain: s.Domain(), Op: method, Key: key,
				Attempt: attempt, Status: status, Delay: delay, Err: err,
			})
		}
	}
}

// httpError drains and classifies a non-2xx response without retaining more
// than a bounded diagnostic prefix.
func (s *S3Store) httpError(op, key string, resp *http.Response) error {
	const maxDiag = 512
	diag, _ := io.ReadAll(io.LimitReader(resp.Body, maxDiag))
	resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%w: %s/%s", ErrNotFound, s.Domain(), key)
	}
	return fmt.Errorf("histstore: %s %s/%s: HTTP %d: %s",
		op, s.Domain(), key, resp.StatusCode, strings.TrimSpace(string(diag)))
}

// Put implements Store. The payload hash for signing is the object digest —
// content addressing lets the body stream without buffering or double
// hashing (the store still relies on the caller's read-after-write proof).
func (s *S3Store) Put(ctx context.Context, key string, size int64, digestHex string, body io.Reader) error {
	if size < 0 || !isLowerHex64(digestHex) {
		return fmt.Errorf("%w: put requires a size and a lowercase sha256 digest", ErrInvalidKey)
	}
	resp, cancel, err := s.do(ctx, http.MethodPut, key, digestHex, size, newBodyFactory(body, size))
	if err != nil {
		return err
	}
	defer cancel()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return s.httpError("put", key, resp)
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	resp.Body.Close()
	return nil
}

// timedBody couples the response body with the per-operation deadline so
// callers streaming a GET stay bounded by the operation timeout.
type timedBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *timedBody) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}

// Get implements Store.
func (s *S3Store) Get(ctx context.Context, key string) (io.ReadCloser, int64, error) {
	resp, cancel, err := s.do(ctx, http.MethodGet, key, emptyPayloadSHA256, 0, nil)
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode != http.StatusOK {
		cancel()
		return nil, 0, s.httpError("get", key, resp)
	}
	size := int64(-1)
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		if parsed, err := strconv.ParseInt(cl, 10, 64); err == nil {
			size = parsed
		}
	}
	return &timedBody{ReadCloser: resp.Body, cancel: cancel}, size, nil
}

// Head implements Store.
func (s *S3Store) Head(ctx context.Context, key string) (int64, error) {
	resp, cancel, err := s.do(ctx, http.MethodHead, key, emptyPayloadSHA256, 0, nil)
	if err != nil {
		return 0, err
	}
	defer cancel()
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return 0, fmt.Errorf("%w: %s/%s", ErrNotFound, s.Domain(), key)
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("histstore: head %s/%s: HTTP %d", s.Domain(), key, resp.StatusCode)
	}
	size, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
	if err != nil || size < 0 {
		return 0, fmt.Errorf("histstore: head %s/%s returned no usable Content-Length", s.Domain(), key)
	}
	return size, nil
}

// Delete implements Store (idempotent: 404 and 204 are both success).
func (s *S3Store) Delete(ctx context.Context, key string) error {
	resp, cancel, err := s.do(ctx, http.MethodDelete, key, emptyPayloadSHA256, 0, nil)
	if err != nil {
		return err
	}
	defer cancel()
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK ||
		resp.StatusCode == http.StatusNotFound {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		resp.Body.Close()
		return nil
	}
	return s.httpError("delete", key, resp)
}

// GetHeader exposes one response header of an exact-key GET alongside the
// body (the legacy blob path needs x-amz-meta-compression). pft2 objects
// never use this.
func (s *S3Store) GetWithMeta(ctx context.Context, key string) (io.ReadCloser, int64, http.Header, error) {
	resp, cancel, err := s.do(ctx, http.MethodGet, key, emptyPayloadSHA256, 0, nil)
	if err != nil {
		return nil, 0, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		cancel()
		return nil, 0, nil, s.httpError("get", key, resp)
	}
	size := int64(-1)
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		if parsed, err := strconv.ParseInt(cl, 10, 64); err == nil {
			size = parsed
		}
	}
	return &timedBody{ReadCloser: resp.Body, cancel: cancel}, size, resp.Header, nil
}

func joinURLPath(parts ...string) string {
	var segments []string
	for _, part := range parts {
		for _, seg := range strings.Split(part, "/") {
			if seg != "" {
				segments = append(segments, seg)
			}
		}
	}
	return "/" + strings.Join(segments, "/")
}
