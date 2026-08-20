// Package archivestore is the minimal S3-compatible client the tiered-storage
// archiver, hydrator, files gateway, and manager use to reach one sealed
// archive store.
//
// It deliberately depends on nothing outside the standard library and
// golang.org/x/sys: SigV4 signing and the eight operations the archive contract
// needs (pack-format.md "S3 mechanics") are a small, frozen surface, and this
// repository treats every external dependency as a reviewed decision rather
// than a convenience.
//
// Three rules run through the whole package:
//
//   - Fail closed. Configuration, keys, checksums, and responses are validated
//     against closed grammars; anything not exactly understood is an error, not
//     something to interpret generously.
//   - Bound everything. Every response body has a byte limit and is drained and
//     closed exactly once. The one streaming body — a ranged GET — is length
//     enforced and belongs to the caller.
//   - Sign the payload. UNSIGNED-PAYLOAD is never used. Single-shot bodies are
//     hashed in memory; streamed parts carry a precomputed digest supplied by
//     the caller, so the signature always covers the bytes.
package archivestore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// maxErrorBodyBytes bounds an S3 XML error document.
	maxErrorBodyBytes = 64 << 10
	// maxXMLBodyBytes bounds a successful XML response (the largest is a
	// CompleteMultipartUpload result, a few hundred bytes).
	maxXMLBodyBytes = 1 << 20
	// maxDrainBytes bounds how much of an unwanted body is read back to make a
	// connection reusable; beyond it the connection is simply dropped.
	maxDrainBytes = 1 << 20
)

// Client is a bounded, signing S3 client for exactly one bucket and prefix. It
// is safe for concurrent use.
type Client struct {
	config      Config
	credentials credentials
	endpoint    *url.URL
	httpClient  *http.Client

	// Injection points. Production values are wall-clock time, a real sleep,
	// and a real jitter source; the test suite pins all three.
	now    func() time.Time
	sleep  func(context.Context, time.Duration) error
	jitter func() float64
}

// Option adjusts a Client at construction.
type Option func(*Client)

// WithHTTPClient supplies the HTTP client. The caller then owns every transport
// bound; Config.Timeouts.Request still bounds buffered operations.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *Client) {
		if httpClient != nil {
			c.httpClient = httpClient
		}
	}
}

// New validates the configuration completely and returns a ready client.
func New(config Config, options ...Option) (*Client, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	config = config.withDefaults()
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("%w: endpoint is not a URL", ErrInvalid)
	}
	endpoint.Path = ""
	endpoint.RawPath = ""
	client := &Client{
		config: config,
		credentials: credentials{
			accessKeyID:     config.AccessKeyID,
			secretAccessKey: config.SecretAccessKey,
			sessionToken:    config.SessionToken,
		},
		endpoint: endpoint,
		httpClient: &http.Client{
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				DialContext:           (&net.Dialer{Timeout: config.Timeouts.Dial, KeepAlive: 30 * time.Second}).DialContext,
				TLSHandshakeTimeout:   config.Timeouts.TLSHandshake,
				ResponseHeaderTimeout: config.Timeouts.ResponseHeader,
				IdleConnTimeout:       config.Timeouts.IdleConnection,
				MaxIdleConnsPerHost:   16,
				ForceAttemptHTTP2:     true,
			},
			// Redirects are refused: a redirect would move archive bytes to a
			// host the root-pinned configuration never named, and the signature
			// scope would no longer describe the destination.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("archivestore: redirects are refused")
			},
		},
		now:    time.Now,
		sleep:  sleepContext,
		jitter: rand.Float64,
	}
	for _, option := range options {
		option(client)
	}
	return client, nil
}

// Config returns the normalized configuration. Credentials are redacted so a
// caller cannot log them by accident.
func (c *Client) Config() Config {
	redacted := c.config
	redacted.AccessKeyID = "[redacted]"
	redacted.SecretAccessKey = "[redacted]"
	if redacted.SessionToken != "" {
		redacted.SessionToken = "[redacted]"
	}
	return redacted
}

// ChecksumsEnabled reports whether the store was declared able to carry
// full-object CRC64NVME checksums.
func (c *Client) ChecksumsEnabled() bool {
	return c.config.ChecksumCapability == ChecksumCRC64NVMEFullObject
}

// PartBody is a replayable request payload with a known length and a
// precomputed SHA-256, so a streamed upload is signed over its actual bytes
// without ever buffering them here.
//
// Retries call open again. A body that cannot be reopened (PartBodyFromReader)
// refuses the second call, which fails the operation loudly rather than
// sending a truncated part.
type PartBody struct {
	length    int64
	sha256Hex string
	open      func() (io.ReadCloser, error)
}

// Len returns the exact payload length in bytes.
func (b PartBody) Len() int64 { return b.length }

// SHA256Hex returns the payload digest that will be signed.
func (b PartBody) SHA256Hex() string { return b.sha256Hex }

// PartBodyFromBytes builds a fully buffered, freely replayable body.
func PartBodyFromBytes(payload []byte) PartBody {
	digest := sha256.Sum256(payload)
	buffered := payload
	return PartBody{
		length:    int64(len(payload)),
		sha256Hex: hex.EncodeToString(digest[:]),
		open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(buffered)), nil
		},
	}
}

// PartBodyFromOpener builds a replayable streamed body. open must return a
// reader positioned at the payload start yielding exactly length bytes whose
// SHA-256 is sha256Hex; it may be called once per attempt.
func PartBodyFromOpener(length int64, sha256Hex string, open func() (io.ReadCloser, error)) (PartBody, error) {
	if length < 0 || !validLowerHex(sha256Hex, sha256.Size) || open == nil {
		return PartBody{}, fmt.Errorf("%w: streamed body needs a non-negative length, a 64-character lowercase hex digest, and an opener", ErrInvalid)
	}
	return PartBody{length: length, sha256Hex: sha256Hex, open: open}, nil
}

// PartBodyFromReader adapts a one-shot reader. The resulting body cannot be
// replayed, so an operation using it never retries; prefer PartBodyFromOpener
// when the source can be reopened or seeked.
func PartBodyFromReader(reader io.Reader, length int64, sha256Hex string) (PartBody, error) {
	if reader == nil {
		return PartBody{}, fmt.Errorf("%w: streamed body needs a reader", ErrInvalid)
	}
	used := false
	return PartBodyFromOpener(length, sha256Hex, func() (io.ReadCloser, error) {
		if used {
			return nil, fmt.Errorf("%w: one-shot body cannot be replayed for a retry", ErrInvalid)
		}
		used = true
		return io.NopCloser(io.LimitReader(reader, length)), nil
	})
}

func emptyBody() PartBody {
	return PartBody{length: 0, sha256Hex: EmptyPayloadSHA256, open: func() (io.ReadCloser, error) {
		return http.NoBody, nil
	}}
}

type storeRequest struct {
	op     string
	method string
	key    string
	query  []queryParameter
	header http.Header
	body   PartBody
	// stream marks an operation whose response body is handed to the caller.
	// No overall request timeout applies; the caller's context governs.
	stream bool
}

// roundTrip performs one operation with bounded retries.
//
// Ownership rule: for a 2xx response the success function owns resp.Body
// entirely (it must drain and close, or hand it out). For every other outcome
// this function has already closed the body. Success may itself return a
// retryable *Error — that is how the 200-with-<Error> S3 quirk re-enters the
// retry loop.
func (c *Client) roundTrip(ctx context.Context, request storeRequest, success func(*http.Response) error) error {
	if ctx == nil {
		return fmt.Errorf("%w: %s requires a context", ErrInvalid, request.op)
	}
	var lastErr error
	for attempt := 1; ; attempt++ {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return lastErr
			}
			return &Error{Op: request.op, Key: request.key, Kind: KindNetwork, Attempts: attempt - 1, cause: err}
		}
		err := c.attempt(ctx, request, success)
		if err == nil {
			return nil
		}
		var storeError *Error
		if errors.As(err, &storeError) {
			storeError.Attempts = attempt
		}
		lastErr = err
		if attempt >= c.config.MaxAttempts || !retryable(err) {
			return lastErr
		}
		delay := c.backoffDelay(attempt, retryAfterOf(err))
		if err := c.sleep(ctx, delay); err != nil {
			return lastErr
		}
	}
}

func (c *Client) attempt(ctx context.Context, request storeRequest, success func(*http.Response) error) error {
	attemptContext := ctx
	if !request.stream && c.config.Timeouts.Request > 0 {
		var cancel context.CancelFunc
		attemptContext, cancel = context.WithTimeout(ctx, c.config.Timeouts.Request)
		defer cancel()
	}
	httpRequest, err := c.newHTTPRequest(attemptContext, request)
	if err != nil {
		return err
	}
	response, err := c.httpClient.Do(httpRequest)
	if err != nil {
		return &Error{
			Op:        request.op,
			Key:       request.key,
			Kind:      KindNetwork,
			retryable: ctx.Err() == nil,
			cause:     err,
		}
	}
	if response.StatusCode/100 != 2 {
		return c.responseError(request, response)
	}
	return success(response)
}

func (c *Client) newHTTPRequest(ctx context.Context, request storeRequest) (*http.Request, error) {
	if err := validateKey(request.key); err != nil {
		return nil, err
	}
	body := request.body
	if body.open == nil {
		body = emptyBody()
	}
	reader, err := body.open()
	if err != nil {
		return nil, fmt.Errorf("%w: %s could not open its request body: %w", ErrInvalid, request.op, err)
	}
	target := *c.endpoint
	encodedPath := "/" + uriEncode(request.key, false)
	decodedPath := "/" + request.key
	if c.config.PathStyle {
		encodedPath = "/" + uriEncode(c.config.Bucket, true) + encodedPath
		decodedPath = "/" + c.config.Bucket + decodedPath
	} else {
		target.Host = c.config.Bucket + "." + c.endpoint.Host
	}
	target.Path = decodedPath
	target.RawPath = encodedPath
	target.RawQuery = encodeQuery(request.query)

	httpRequest, err := http.NewRequestWithContext(ctx, request.method, target.String(), reader)
	if err != nil {
		_ = reader.Close()
		return nil, fmt.Errorf("%w: %s could not build a request: %w", ErrInvalid, request.op, err)
	}
	// http.NewRequestWithContext cannot infer a length from an opaque reader,
	// and a chunked request body is not signable as a single payload hash.
	httpRequest.ContentLength = body.length
	if body.length == 0 {
		httpRequest.Body = http.NoBody
	}
	httpRequest.Host = target.Host
	for name, values := range request.header {
		for _, value := range values {
			httpRequest.Header.Add(name, value)
		}
	}
	if err := signRequest(httpRequest, c.credentials, c.config.Region, c.now(), body.sha256Hex); err != nil {
		_ = reader.Close()
		return nil, err
	}
	return httpRequest, nil
}

type xmlError struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	RequestID string   `xml:"RequestId"`
}

// responseError converts a non-2xx response into a typed error, consuming and
// closing the body.
func (c *Client) responseError(request storeRequest, response *http.Response) *Error {
	payload, _ := readBounded(response.Body, maxErrorBodyBytes)
	closeAndDrain(response.Body)
	storeError := &Error{
		Op:         request.op,
		Key:        request.key,
		StatusCode: response.StatusCode,
		RequestID:  response.Header.Get("x-amz-request-id"),
	}
	if document, err := decodeXMLError(payload); err == nil {
		storeError.Code = document.Code
		storeError.Message = document.Message
		if document.RequestID != "" {
			storeError.RequestID = document.RequestID
		}
	}
	storeError.Kind, storeError.retryable = classifyStatus(response.StatusCode, storeError.Code)
	if storeError.retryable {
		storeError.retryAfter = parseRetryAfter(response.Header.Get("Retry-After"))
	}
	return storeError
}

func decodeXMLError(payload []byte) (xmlError, error) {
	if len(bytes.TrimSpace(payload)) == 0 {
		return xmlError{}, fmt.Errorf("%w: empty error body", ErrResponse)
	}
	var document xmlError
	if err := xml.Unmarshal(payload, &document); err != nil {
		return xmlError{}, fmt.Errorf("%w: error body is not XML", ErrResponse)
	}
	if document.XMLName.Local != "Error" {
		return xmlError{}, fmt.Errorf("%w: error body root is %q", ErrResponse, document.XMLName.Local)
	}
	document.Code = sanitizeText(document.Code, 128)
	document.Message = sanitizeText(document.Message, 512)
	document.RequestID = sanitizeText(document.RequestID, 128)
	return document, nil
}

// errorBodyIn detects the S3 quirk where a 200 response carries an <Error>
// document. Treating such a response as success would report a completed
// multipart upload that never happened.
func (c *Client) errorBodyIn(request storeRequest, payload []byte) *Error {
	document, err := decodeXMLError(payload)
	if err != nil {
		return nil
	}
	storeError := &Error{
		Op:         request.op,
		Key:        request.key,
		StatusCode: http.StatusOK,
		Code:       document.Code,
		Message:    document.Message,
		RequestID:  document.RequestID,
	}
	// The status line claimed success, so status-based classification would say
	// "other"; classify from the code alone and default to a retryable server
	// fault, which is what a 200-with-<Error> actually is.
	storeError.Kind, storeError.retryable = classifyStatus(0, document.Code)
	if storeError.Kind == KindOther {
		storeError.Kind, storeError.retryable = KindServer, true
	}
	return storeError
}

func sanitizeText(value string, maximum int) string {
	value = strings.TrimSpace(value)
	if len(value) > maximum {
		value = value[:maximum]
	}
	var builder strings.Builder
	builder.Grow(len(value))
	for i := 0; i < len(value); i++ {
		if c := value[i]; c >= 0x20 && c != 0x7f {
			builder.WriteByte(c)
		}
	}
	return builder.String()
}

func readBounded(body io.Reader, limit int64) ([]byte, error) {
	payload, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return payload, err
	}
	if int64(len(payload)) > limit {
		return nil, fmt.Errorf("%w: response body exceeds %d bytes", ErrResponse, limit)
	}
	return payload, nil
}

// closeAndDrain consumes a bounded remainder so the connection can be pooled,
// then closes exactly once.
func closeAndDrain(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(body, maxDrainBytes))
	_ = body.Close()
}

func (c *Client) backoffDelay(attempt int, retryAfter time.Duration) time.Duration {
	if retryAfter > 0 {
		if retryAfter > maxRetryAfterDelay {
			retryAfter = maxRetryAfterDelay
		}
		return retryAfter
	}
	delay := c.config.RetryBaseDelay
	for i := 1; i < attempt && delay < c.config.RetryMaxDelay; i++ {
		delay *= 2
	}
	if delay > c.config.RetryMaxDelay {
		delay = c.config.RetryMaxDelay
	}
	// Full jitter: a fleet of archivers retrying a shared store must not
	// synchronize on the same backoff schedule.
	jittered := time.Duration(c.jitter() * float64(delay))
	if jittered < time.Millisecond {
		jittered = time.Millisecond
	}
	return jittered
}

func retryAfterOf(err error) time.Duration {
	var storeError *Error
	if errors.As(err, &storeError) {
		return storeError.retryAfter
	}
	return 0
}

func parseRetryAfter(value string) time.Duration {
	if value == "" {
		return 0
	}
	if seconds, err := strconv.ParseInt(value, 10, 32); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	return 0
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
