package archivestore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// newTestClient wires a client to the fake store and replaces the three
// injection points so the retry paths are deterministic and instant.
func newTestClient(t *testing.T, server *httptest.Server, mutate func(*Config)) (*Client, *[]time.Duration) {
	t.Helper()
	config := Config{
		Endpoint:           server.URL,
		Region:             fakeRegion,
		Bucket:             fakeBucket,
		KeyPrefix:          "cells/cell-a",
		AccessKeyID:        fakeAccessKeyID,
		SecretAccessKey:    fakeSecretAccessKey,
		ChecksumCapability: ChecksumCRC64NVMEFullObject,
		PathStyle:          true,
	}
	if mutate != nil {
		mutate(&config)
	}
	client, err := New(config, WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var delays []time.Duration
	client.sleep = func(ctx context.Context, delay time.Duration) error {
		delays = append(delays, delay)
		return ctx.Err()
	}
	client.jitter = func() float64 { return 1 }
	return client, &delays
}

func testKey(t *testing.T, client *Client, object string) string {
	t.Helper()
	key, err := client.KeyFor(testVolumeID, 7, testAttempt, object)
	if err != nil {
		t.Fatalf("KeyFor: %v", err)
	}
	return key
}

func TestPutGetHeadDeleteRoundTrip(t *testing.T) {
	store, server := newFakeStore(t)
	client, _ := newTestClient(t, server, nil)
	ctx := context.Background()
	key := testKey(t, client, "manifest")
	payload := bytes.Repeat([]byte("manifest bytes\n"), 512)
	checksum := CRC64Hex(ChecksumCRC64NVME(payload))

	result, err := client.PutObject(ctx, key, payload, PutOptions{IfNoneMatch: true, ChecksumCRC64NVMEHex: checksum})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	if result.ChecksumCRC64NVMEHex != checksum {
		t.Fatalf("echoed checksum = %q, want %q", result.ChecksumCRC64NVMEHex, checksum)
	}
	if result.ETag == "" || strings.Contains(result.ETag, "\"") {
		t.Fatalf("ETag was not normalized: %q", result.ETag)
	}

	info, err := client.HeadObject(ctx, key)
	if err != nil {
		t.Fatalf("HeadObject: %v", err)
	}
	if info.Size != int64(len(payload)) {
		t.Fatalf("size = %d, want %d", info.Size, len(payload))
	}
	if info.CRC64NVMEHex != checksum {
		t.Fatalf("head checksum = %q, want %q", info.CRC64NVMEHex, checksum)
	}

	fetched, err := client.GetObject(ctx, key, 1<<20)
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	if !bytes.Equal(fetched, payload) {
		t.Fatal("GetObject returned different bytes")
	}

	if err := client.DeleteObject(ctx, key); err != nil {
		t.Fatalf("DeleteObject: %v", err)
	}
	if _, ok := store.object(key); ok {
		t.Fatal("object survived deletion")
	}
	// Deletion is idempotent: a second delete and a delete of an unknown key
	// both succeed.
	if err := client.DeleteObject(ctx, key); err != nil {
		t.Fatalf("second DeleteObject: %v", err)
	}
	if _, err := client.HeadObject(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("HeadObject after delete = %v, want ErrNotFound", err)
	}
	if _, err := client.GetObject(ctx, key, 1<<20); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetObject after delete = %v, want ErrNotFound", err)
	}
}

func TestConditionalCreateLosesTheRace(t *testing.T) {
	_, server := newFakeStore(t)
	client, _ := newTestClient(t, server, nil)
	ctx := context.Background()
	key := testKey(t, client, "manifest")

	if _, err := client.PutObject(ctx, key, []byte("first"), PutOptions{IfNoneMatch: true}); err != nil {
		t.Fatalf("first PutObject: %v", err)
	}
	_, err := client.PutObject(ctx, key, []byte("second"), PutOptions{IfNoneMatch: true})
	if !errors.Is(err, ErrPreconditionFailed) {
		t.Fatalf("conditional create = %v, want ErrPreconditionFailed", err)
	}
	var storeError *Error
	if !errors.As(err, &storeError) {
		t.Fatalf("error is not an *Error: %v", err)
	}
	if storeError.Retryable() {
		t.Fatal("a lost conditional create must never be retried")
	}
	if storeError.StatusCode != http.StatusPreconditionFailed || storeError.Code != "PreconditionFailed" {
		t.Fatalf("unexpected error detail: %+v", storeError)
	}
	if storeError.RequestID != "fake-request" {
		t.Fatalf("request ID was not carried: %q", storeError.RequestID)
	}
	// Without the condition, the same write simply overwrites.
	if _, err := client.PutObject(ctx, key, []byte("second"), PutOptions{}); err != nil {
		t.Fatalf("unconditional PutObject: %v", err)
	}
}

func TestMultipartLifecycle(t *testing.T) {
	store, server := newFakeStore(t)
	client, _ := newTestClient(t, server, nil)
	ctx := context.Background()
	key := testKey(t, client, "pack-000001")

	uploadID, err := client.CreateMultipartUpload(ctx, key, CreateMultipartOptions{FullObjectChecksum: true})
	if err != nil {
		t.Fatalf("CreateMultipartUpload: %v", err)
	}
	if !strings.Contains(uploadID, "+") || !strings.Contains(uploadID, "/") {
		t.Fatalf("the fake store should hand out an upload ID needing encoding, got %q", uploadID)
	}

	partPayloads := [][]byte{
		bytes.Repeat([]byte("A"), 5<<20),
		bytes.Repeat([]byte("B"), 3<<20),
		[]byte("tail"),
	}
	var parts []UploadedPart
	var assembled []byte
	for index, payload := range partPayloads {
		assembled = append(assembled, payload...)
		checksum := CRC64Hex(ChecksumCRC64NVME(payload))
		var body PartBody
		if index == 1 {
			// Exercise the streamed path: length plus a precomputed digest,
			// with the bytes handed over by an opener rather than buffered.
			digest := sha256.Sum256(payload)
			body, err = PartBodyFromOpener(int64(len(payload)), hex.EncodeToString(digest[:]), func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(payload)), nil
			})
			if err != nil {
				t.Fatalf("PartBodyFromOpener: %v", err)
			}
		} else {
			body = PartBodyFromBytes(payload)
		}
		part, err := client.UploadPart(ctx, key, uploadID, index+1, body, checksum)
		if err != nil {
			t.Fatalf("UploadPart %d: %v", index+1, err)
		}
		if part.Number != index+1 || part.ETag == "" {
			t.Fatalf("unexpected part %+v", part)
		}
		if part.ChecksumCRC64NVMEHex != checksum {
			t.Fatalf("part checksum = %q, want %q", part.ChecksumCRC64NVMEHex, checksum)
		}
		parts = append(parts, part)
	}

	result, err := client.CompleteMultipartUpload(ctx, key, uploadID, parts)
	if err != nil {
		t.Fatalf("CompleteMultipartUpload: %v", err)
	}
	wantChecksum := CRC64Hex(ChecksumCRC64NVME(assembled))
	if result.ChecksumCRC64NVMEHex != wantChecksum {
		t.Fatalf("full-object checksum = %q, want %q", result.ChecksumCRC64NVMEHex, wantChecksum)
	}
	stored, ok := store.object(key)
	if !ok || !bytes.Equal(stored, assembled) {
		t.Fatal("the sealed object does not match the concatenated parts")
	}

	info, err := client.HeadObject(ctx, key)
	if err != nil {
		t.Fatalf("HeadObject: %v", err)
	}
	if info.Size != int64(len(assembled)) || info.CRC64NVMEHex != wantChecksum {
		t.Fatalf("HeadObject = %+v, want size %d and checksum %s", info, len(assembled), wantChecksum)
	}
}

func TestMultipartAbort(t *testing.T) {
	_, server := newFakeStore(t)
	client, _ := newTestClient(t, server, nil)
	ctx := context.Background()
	key := testKey(t, client, "pack-000001")

	uploadID, err := client.CreateMultipartUpload(ctx, key, CreateMultipartOptions{FullObjectChecksum: true})
	if err != nil {
		t.Fatalf("CreateMultipartUpload: %v", err)
	}
	if _, err := client.UploadPart(ctx, key, uploadID, 1, PartBodyFromBytes([]byte("partial")), ""); err != nil {
		t.Fatalf("UploadPart: %v", err)
	}
	if err := client.AbortMultipartUpload(ctx, key, uploadID); err != nil {
		t.Fatalf("AbortMultipartUpload: %v", err)
	}
	// Abort is idempotent: aborting an upload the store has forgotten succeeds.
	if err := client.AbortMultipartUpload(ctx, key, uploadID); err != nil {
		t.Fatalf("second AbortMultipartUpload: %v", err)
	}
	if _, err := client.UploadPart(ctx, key, uploadID, 2, PartBodyFromBytes([]byte("late")), ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("upload after abort = %v, want ErrNotFound", err)
	}
}

func TestCompleteMultipartUploadRejectsA200ErrorBody(t *testing.T) {
	store, server := newFakeStore(t)
	client, _ := newTestClient(t, server, nil)
	ctx := context.Background()
	key := testKey(t, client, "pack-000001")

	uploadID, err := client.CreateMultipartUpload(ctx, key, CreateMultipartOptions{FullObjectChecksum: true})
	if err != nil {
		t.Fatalf("CreateMultipartUpload: %v", err)
	}
	part, err := client.UploadPart(ctx, key, uploadID, 1, PartBodyFromBytes([]byte("payload")), "")
	if err != nil {
		t.Fatalf("UploadPart: %v", err)
	}

	// S3 may stream a 200 status line and only then discover the failure. The
	// body, not the status, decides.
	store.mu.Lock()
	store.hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
		if r.Method != http.MethodPost || !r.URL.Query().Has("uploadId") {
			return false
		}
		writeFakeXML(w, http.StatusOK, "<Error><Code>InternalError</Code><Message>we encountered an internal error</Message><RequestId>quirk</RequestId></Error>")
		return true
	}
	store.mu.Unlock()

	_, err = client.CompleteMultipartUpload(ctx, key, uploadID, []UploadedPart{part})
	if err == nil {
		t.Fatal("a 200 response carrying an <Error> body was accepted as a seal")
	}
	var storeError *Error
	if !errors.As(err, &storeError) {
		t.Fatalf("error is not an *Error: %v", err)
	}
	if storeError.StatusCode != http.StatusOK || storeError.Code != "InternalError" {
		t.Fatalf("unexpected error detail: %+v", storeError)
	}
	if !storeError.Retryable() || storeError.Attempts != DefaultMaxAttempts {
		t.Fatalf("a 200-with-<Error> InternalError should have been retried to exhaustion: %+v", storeError)
	}
	if _, ok := store.object(key); ok {
		t.Fatal("the object must not be recorded as sealed")
	}
}

func TestPutObjectRejectsA200ErrorBody(t *testing.T) {
	store, server := newFakeStore(t)
	client, _ := newTestClient(t, server, func(config *Config) { config.MaxAttempts = 1 })
	key := testKey(t, client, "manifest")
	store.mu.Lock()
	store.hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
		if r.Method != http.MethodPut {
			return false
		}
		writeFakeXML(w, http.StatusOK, "<Error><Code>InternalError</Code><Message>not written</Message></Error>")
		return true
	}
	store.mu.Unlock()
	_, err := client.PutObject(context.Background(), key, []byte("payload"), PutOptions{})
	if err == nil {
		t.Fatal("a 200 PUT carrying an <Error> body was accepted as a write")
	}
	var storeError *Error
	if !errors.As(err, &storeError) || storeError.StatusCode != http.StatusOK || storeError.Code != "InternalError" {
		t.Fatalf("unexpected error: %+v", storeError)
	}
}

func TestCompleteMultipartUploadRetriesWithAnIdenticalPartsList(t *testing.T) {
	store, server := newFakeStore(t)
	client, delays := newTestClient(t, server, nil)
	ctx := context.Background()
	key := testKey(t, client, "pack-000001")

	uploadID, err := client.CreateMultipartUpload(ctx, key, CreateMultipartOptions{FullObjectChecksum: true})
	if err != nil {
		t.Fatalf("CreateMultipartUpload: %v", err)
	}
	payload := []byte("one part is enough")
	part, err := client.UploadPart(ctx, key, uploadID, 1, PartBodyFromBytes(payload), CRC64Hex(ChecksumCRC64NVME(payload)))
	if err != nil {
		t.Fatalf("UploadPart: %v", err)
	}

	var mu sync.Mutex
	var bodies [][]byte
	failures := 2
	store.mu.Lock()
	store.hook = func(w http.ResponseWriter, r *http.Request, body []byte) bool {
		if r.Method != http.MethodPost || !r.URL.Query().Has("uploadId") {
			return false
		}
		mu.Lock()
		bodies = append(bodies, append([]byte(nil), body...))
		remaining := failures
		failures--
		mu.Unlock()
		if remaining > 0 {
			w.Header().Set("Retry-After", "1")
			writeFakeError(w, http.StatusServiceUnavailable, "InternalError", "try again")
			return true
		}
		return false
	}
	store.mu.Unlock()

	result, err := client.CompleteMultipartUpload(ctx, key, uploadID, []UploadedPart{part})
	if err != nil {
		t.Fatalf("CompleteMultipartUpload: %v", err)
	}
	if result.ChecksumCRC64NVMEHex != CRC64Hex(ChecksumCRC64NVME(payload)) {
		t.Fatalf("unexpected sealed checksum %q", result.ChecksumCRC64NVMEHex)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 3 {
		t.Fatalf("completion was attempted %d times, want 3", len(bodies))
	}
	for i := 1; i < len(bodies); i++ {
		if !bytes.Equal(bodies[0], bodies[i]) {
			t.Fatalf("retry %d sent a different parts list:\n%s\n%s", i, bodies[0], bodies[i])
		}
	}
	if len(*delays) != 2 {
		t.Fatalf("recorded %d backoff delays, want 2", len(*delays))
	}
	for _, delay := range *delays {
		if delay != time.Second {
			t.Fatalf("Retry-After was not honoured: %v", delay)
		}
	}
}

func TestRetryOn503CountsAttemptsAndBacksOff(t *testing.T) {
	store, server := newFakeStore(t)
	client, delays := newTestClient(t, server, func(config *Config) {
		config.MaxAttempts = 4
		config.RetryBaseDelay = 10 * time.Millisecond
		config.RetryMaxDelay = 40 * time.Millisecond
	})
	ctx := context.Background()
	key := testKey(t, client, "manifest")

	var mu sync.Mutex
	failures := 2
	store.mu.Lock()
	store.hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
		if r.Method != http.MethodPut {
			return false
		}
		mu.Lock()
		remaining := failures
		failures--
		mu.Unlock()
		if remaining > 0 {
			writeFakeError(w, http.StatusServiceUnavailable, "ServiceUnavailable", "please retry")
			return true
		}
		return false
	}
	store.mu.Unlock()

	if _, err := client.PutObject(ctx, key, []byte("payload"), PutOptions{}); err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	if got := store.callCount(http.MethodPut); got != 3 {
		t.Fatalf("the store saw %d PUTs, want 3", got)
	}
	// Full jitter is pinned to 1.0 in tests, so the delays are the exact
	// doubling sequence capped at RetryMaxDelay.
	want := []time.Duration{10 * time.Millisecond, 20 * time.Millisecond}
	if len(*delays) != len(want) {
		t.Fatalf("delays = %v, want %v", *delays, want)
	}
	for i, delay := range *delays {
		if delay != want[i] {
			t.Fatalf("delays = %v, want %v", *delays, want)
		}
	}
}

func TestRetryBudgetIsExhaustedAndReported(t *testing.T) {
	store, server := newFakeStore(t)
	client, delays := newTestClient(t, server, func(config *Config) { config.MaxAttempts = 3 })
	store.mu.Lock()
	store.hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
		writeFakeError(w, http.StatusServiceUnavailable, "ServiceUnavailable", "still down")
		return true
	}
	store.mu.Unlock()

	key := testKey(t, client, "manifest")
	_, err := client.GetObject(context.Background(), key, 1<<20)
	if !errors.Is(err, ErrRetryable) {
		t.Fatalf("error = %v, want ErrRetryable", err)
	}
	var storeError *Error
	if !errors.As(err, &storeError) || storeError.Attempts != 3 || storeError.Kind != KindServer {
		t.Fatalf("unexpected error: %+v", storeError)
	}
	if got := store.callCount(http.MethodGet); got != 3 {
		t.Fatalf("the store saw %d GETs, want 3", got)
	}
	if len(*delays) != 2 {
		t.Fatalf("recorded %d delays, want 2", len(*delays))
	}
	if !strings.Contains(err.Error(), "after 3 attempts") {
		t.Fatalf("the error does not report its attempt count: %v", err)
	}
}

func TestNonRetryableFailuresAreNotRetried(t *testing.T) {
	store, server := newFakeStore(t)
	client, delays := newTestClient(t, server, nil)
	store.mu.Lock()
	store.hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
		writeFakeError(w, http.StatusForbidden, "AccessDenied", "no")
		return true
	}
	store.mu.Unlock()
	key := testKey(t, client, "manifest")
	_, err := client.GetObject(context.Background(), key, 1<<20)
	if !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("error = %v, want ErrAccessDenied", err)
	}
	if errors.Is(err, ErrRetryable) {
		t.Fatal("access denied must not be classified retryable")
	}
	if got := store.callCount(http.MethodGet); got != 1 {
		t.Fatalf("the store saw %d GETs, want 1", got)
	}
	if len(*delays) != 0 {
		t.Fatalf("a non-retryable failure slept: %v", *delays)
	}
}

func TestThrottlingIsRetryable(t *testing.T) {
	store, server := newFakeStore(t)
	client, _ := newTestClient(t, server, func(config *Config) { config.MaxAttempts = 2 })
	store.mu.Lock()
	store.hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
		writeFakeError(w, http.StatusTooManyRequests, "SlowDown", "slow down")
		return true
	}
	store.mu.Unlock()
	key := testKey(t, client, "manifest")
	_, err := client.HeadObject(context.Background(), key)
	if !errors.Is(err, ErrThrottled) || !errors.Is(err, ErrRetryable) {
		t.Fatalf("error = %v, want a throttled and retryable error", err)
	}
	if got := store.callCount(http.MethodHead); got != 2 {
		t.Fatalf("the store saw %d HEADs, want 2", got)
	}
}

func TestGetObjectRange(t *testing.T) {
	store, server := newFakeStore(t)
	client, _ := newTestClient(t, server, nil)
	ctx := context.Background()
	key := testKey(t, client, "pack-000001")
	payload := make([]byte, 64<<10)
	for i := range payload {
		payload[i] = byte(i)
	}
	store.putObject(key, payload)

	for _, span := range []struct{ offset, length int64 }{
		{0, 1},
		{0, 4096},
		{1234, 5678},
		{int64(len(payload)) - 1, 1},
	} {
		stream, err := client.GetObjectRange(ctx, key, span.offset, span.length)
		if err != nil {
			t.Fatalf("GetObjectRange(%d, %d): %v", span.offset, span.length, err)
		}
		got, err := io.ReadAll(stream)
		if err != nil {
			t.Fatalf("read range: %v", err)
		}
		if err := stream.Close(); err != nil {
			t.Fatalf("close range: %v", err)
		}
		if !bytes.Equal(got, payload[span.offset:span.offset+span.length]) {
			t.Fatalf("range (%d, %d) returned the wrong bytes", span.offset, span.length)
		}
	}

	if _, err := client.GetObjectRange(ctx, key, -1, 10); !errors.Is(err, ErrInvalid) {
		t.Fatalf("negative offset = %v, want ErrInvalid", err)
	}
	if _, err := client.GetObjectRange(ctx, key, 0, 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero length = %v, want ErrInvalid", err)
	}
	if _, err := client.GetObjectRange(ctx, testKey(t, client, "absent"), 0, 10); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing object = %v, want ErrNotFound", err)
	}
}

func TestGetObjectRangeRefusesAWholeObjectResponse(t *testing.T) {
	store, server := newFakeStore(t)
	client, _ := newTestClient(t, server, nil)
	key := testKey(t, client, "pack-000001")
	payload := bytes.Repeat([]byte("z"), 4096)
	store.putObject(key, payload)
	store.mu.Lock()
	store.hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
		if r.Method != http.MethodGet {
			return false
		}
		// A store that ignores Range and streams the whole object.
		w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
		return true
	}
	store.mu.Unlock()
	if _, err := client.GetObjectRange(context.Background(), key, 10, 20); !errors.Is(err, ErrResponse) {
		t.Fatalf("error = %v, want ErrResponse", err)
	}
}

func TestGetObjectRangeEnforcesTheExactLength(t *testing.T) {
	store, server := newFakeStore(t)
	client, _ := newTestClient(t, server, nil)
	key := testKey(t, client, "pack-000001")

	t.Run("declared length mismatch", func(t *testing.T) {
		// The cheap check first: a Content-Length that disagrees with the
		// requested span is refused before a byte is read.
		store.mu.Lock()
		store.hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method != http.MethodGet {
				return false
			}
			w.Header().Set("Content-Range", "bytes 0-99/1000")
			w.Header().Set("Content-Length", "40")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(bytes.Repeat([]byte("a"), 40))
			return true
		}
		store.mu.Unlock()
		if _, err := client.GetObjectRange(context.Background(), key, 0, 100); !errors.Is(err, ErrResponse) {
			t.Fatalf("mismatched Content-Length = %v, want ErrResponse", err)
		}
	})

	t.Run("short stream", func(t *testing.T) {
		// A chunked response declares no length, so only the reader's own
		// enforcement stands between a truncated range and "verified" content.
		store.mu.Lock()
		store.hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method != http.MethodGet {
				return false
			}
			w.Header().Set("Content-Range", "bytes 0-99/1000")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(bytes.Repeat([]byte("a"), 40))
			w.(http.Flusher).Flush()
			return true
		}
		store.mu.Unlock()
		stream, err := client.GetObjectRange(context.Background(), key, 0, 100)
		if err != nil {
			t.Fatalf("GetObjectRange: %v", err)
		}
		defer stream.Close()
		if _, err := io.ReadAll(stream); !errors.Is(err, ErrResponse) {
			t.Fatalf("short range read = %v, want ErrResponse", err)
		}
	})

	t.Run("long stream", func(t *testing.T) {
		store.mu.Lock()
		store.hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method != http.MethodGet {
				return false
			}
			w.Header().Set("Content-Range", "bytes 0-99/1000")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(bytes.Repeat([]byte("a"), 180))
			w.(http.Flusher).Flush()
			return true
		}
		store.mu.Unlock()
		stream, err := client.GetObjectRange(context.Background(), key, 0, 100)
		if err != nil {
			t.Fatalf("GetObjectRange: %v", err)
		}
		defer stream.Close()
		payload, err := io.ReadAll(stream)
		if len(payload) != 100 {
			t.Fatalf("read %d bytes, want the range's 100", len(payload))
		}
		if err != nil && !errors.Is(err, ErrResponse) {
			t.Fatalf("unexpected error %v", err)
		}
		// A caller that keeps reading past the promised length must be told.
		if _, err := stream.Read(make([]byte, 1)); !errors.Is(err, ErrResponse) {
			t.Fatalf("over-long range read = %v, want ErrResponse", err)
		}
	})

	t.Run("mismatched content range", func(t *testing.T) {
		store.mu.Lock()
		store.hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method != http.MethodGet {
				return false
			}
			w.Header().Set("Content-Range", "bytes 500-599/1000")
			w.Header().Set("Content-Length", "100")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(bytes.Repeat([]byte("a"), 100))
			return true
		}
		store.mu.Unlock()
		if _, err := client.GetObjectRange(context.Background(), key, 0, 100); !errors.Is(err, ErrResponse) {
			t.Fatalf("mismatched Content-Range = %v, want ErrResponse", err)
		}
	})
}

func TestGetObjectEnforcesItsBound(t *testing.T) {
	store, server := newFakeStore(t)
	client, _ := newTestClient(t, server, nil)
	key := testKey(t, client, "manifest")
	store.putObject(key, bytes.Repeat([]byte("m"), 4096))

	if _, err := client.GetObject(context.Background(), key, 4095); !errors.Is(err, ErrResponse) {
		t.Fatalf("over-bound object = %v, want ErrResponse", err)
	}
	if _, err := client.GetObject(context.Background(), key, 4096); err != nil {
		t.Fatalf("exactly-at-bound object: %v", err)
	}
	if _, err := client.GetObject(context.Background(), key, 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero bound = %v, want ErrInvalid", err)
	}

	// A lying Content-Length must not defeat the bound either.
	store.mu.Lock()
	store.hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
		if r.Method != http.MethodGet {
			return false
		}
		w.Header().Set("Content-Length", "8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bytes.Repeat([]byte("x"), 8))
		return true
	}
	store.mu.Unlock()
	if _, err := client.GetObject(context.Background(), key, 4); !errors.Is(err, ErrResponse) {
		t.Fatalf("lying Content-Length = %v, want ErrResponse", err)
	}
}

func TestChecksumCapabilityIsEnforced(t *testing.T) {
	store, server := newFakeStore(t)
	ctx := context.Background()

	t.Run("declared none refuses checksums", func(t *testing.T) {
		client, _ := newTestClient(t, server, func(config *Config) { config.ChecksumCapability = ChecksumNone })
		key := testKey(t, client, "manifest")
		if client.ChecksumsEnabled() {
			t.Fatal("checksums should be disabled")
		}
		if _, err := client.PutObject(ctx, key, []byte("x"), PutOptions{ChecksumCRC64NVMEHex: CRC64Hex(1)}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("PutObject = %v, want ErrInvalid", err)
		}
		if _, err := client.CreateMultipartUpload(ctx, key, CreateMultipartOptions{FullObjectChecksum: true}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("CreateMultipartUpload = %v, want ErrInvalid", err)
		}
		if _, err := client.CompleteMultipartUpload(ctx, key, "upload", []UploadedPart{{Number: 1, ETag: "abc", ChecksumCRC64NVMEHex: CRC64Hex(1)}}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("CompleteMultipartUpload = %v, want ErrInvalid", err)
		}
	})

	t.Run("malformed checksum is refused locally", func(t *testing.T) {
		client, _ := newTestClient(t, server, nil)
		key := testKey(t, client, "manifest")
		if _, err := client.PutObject(ctx, key, []byte("x"), PutOptions{ChecksumCRC64NVMEHex: "not-hex"}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("PutObject = %v, want ErrInvalid", err)
		}
		if got := store.callCount(http.MethodPut); got != 0 {
			t.Fatalf("a malformed checksum reached the store (%d PUTs)", got)
		}
	})

	t.Run("composite checksums are refused", func(t *testing.T) {
		client, _ := newTestClient(t, server, nil)
		key := testKey(t, client, "pack-000001")
		store.putObject(key, []byte("payload"))
		store.mu.Lock()
		store.hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method != http.MethodHead {
				return false
			}
			w.Header().Set(headerChecksumCRC64, CRC64Base64(ChecksumCRC64NVME([]byte("payload")))+"-5")
			w.Header().Set("Content-Length", "7")
			w.WriteHeader(http.StatusOK)
			return true
		}
		store.mu.Unlock()
		_, err := client.HeadObject(ctx, key)
		if !errors.Is(err, ErrResponse) || !errors.Is(err, errCompositeChecksum) {
			t.Fatalf("HeadObject = %v, want a composite-checksum response error", err)
		}
		store.mu.Lock()
		store.hook = nil
		store.mu.Unlock()
	})

	t.Run("a store carrying no checksum reports an empty digest", func(t *testing.T) {
		noChecksumStore, noChecksumServer := newFakeStore(t)
		noChecksumStore.checksums = false
		client, _ := newTestClient(t, noChecksumServer, func(config *Config) { config.ChecksumCapability = ChecksumNone })
		key := testKey(t, client, "manifest")
		if _, err := client.PutObject(ctx, key, []byte("payload"), PutOptions{}); err != nil {
			t.Fatalf("PutObject: %v", err)
		}
		info, err := client.HeadObject(ctx, key)
		if err != nil {
			t.Fatalf("HeadObject: %v", err)
		}
		if info.CRC64NVMEHex != "" || info.Size != 7 {
			t.Fatalf("HeadObject = %+v, want an empty checksum and size 7", info)
		}
	})
}

func TestCreateMultipartUploadRejectsAMalformedResult(t *testing.T) {
	store, server := newFakeStore(t)
	client, _ := newTestClient(t, server, nil)
	key := testKey(t, client, "pack-000001")

	cases := map[string]string{
		"wrong root":     "<SomethingElse><UploadId>abc</UploadId></SomethingElse>",
		"empty upload":   "<InitiateMultipartUploadResult><UploadId></UploadId></InitiateMultipartUploadResult>",
		"not xml":        "this is not xml at all",
		"truncated body": "<InitiateMultipartUploadResult><UploadId>abc",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			store.mu.Lock()
			store.hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
				if r.Method != http.MethodPost {
					return false
				}
				writeFakeXML(w, http.StatusOK, body)
				return true
			}
			store.mu.Unlock()
			if _, err := client.CreateMultipartUpload(context.Background(), key, CreateMultipartOptions{}); !errors.Is(err, ErrResponse) {
				t.Fatalf("error = %v, want ErrResponse", err)
			}
		})
	}
}

func TestOperationArgumentValidation(t *testing.T) {
	_, server := newFakeStore(t)
	client, _ := newTestClient(t, server, nil)
	ctx := context.Background()
	key := testKey(t, client, "manifest")

	cases := map[string]func() error{
		"empty key": func() error {
			_, err := client.PutObject(ctx, "", nil, PutOptions{})
			return err
		},
		"traversal key": func() error {
			_, err := client.PutObject(ctx, "a/../b", nil, PutOptions{})
			return err
		},
		"empty upload ID": func() error {
			_, err := client.UploadPart(ctx, key, "", 1, PartBodyFromBytes([]byte("x")), "")
			return err
		},
		"part number zero": func() error {
			_, err := client.UploadPart(ctx, key, "upload", 0, PartBodyFromBytes([]byte("x")), "")
			return err
		},
		"part number too large": func() error {
			_, err := client.UploadPart(ctx, key, "upload", MaxPartNumber+1, PartBodyFromBytes([]byte("x")), "")
			return err
		},
		"empty part body": func() error {
			_, err := client.UploadPart(ctx, key, "upload", 1, PartBodyFromBytes(nil), "")
			return err
		},
		"no parts to complete": func() error {
			_, err := client.CompleteMultipartUpload(ctx, key, "upload", nil)
			return err
		},
		"descending part numbers": func() error {
			_, err := client.CompleteMultipartUpload(ctx, key, "upload", []UploadedPart{{Number: 2, ETag: "a"}, {Number: 1, ETag: "b"}})
			return err
		},
		"duplicate part numbers": func() error {
			_, err := client.CompleteMultipartUpload(ctx, key, "upload", []UploadedPart{{Number: 1, ETag: "a"}, {Number: 1, ETag: "b"}})
			return err
		},
		"empty part etag": func() error {
			_, err := client.CompleteMultipartUpload(ctx, key, "upload", []UploadedPart{{Number: 1}})
			return err
		},
		"abort without an upload ID": func() error {
			return client.AbortMultipartUpload(ctx, key, "")
		},
		"nil context": func() error {
			//nolint:staticcheck // deliberately passing a nil context
			_, err := client.PutObject(nil, key, nil, PutOptions{})
			return err
		},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			err := run()
			if !errors.Is(err, ErrInvalid) && !errors.Is(err, ErrResponse) {
				t.Fatalf("error = %v, want a local validation failure", err)
			}
		})
	}
}

func TestPartBodyReplayRules(t *testing.T) {
	payload := []byte("part payload")
	digest := sha256.Sum256(payload)
	digestHex := hex.EncodeToString(digest[:])

	buffered := PartBodyFromBytes(payload)
	if buffered.Len() != int64(len(payload)) || buffered.SHA256Hex() != digestHex {
		t.Fatalf("buffered body = %d bytes / %s", buffered.Len(), buffered.SHA256Hex())
	}
	for i := 0; i < 3; i++ {
		reader, err := buffered.open()
		if err != nil {
			t.Fatalf("buffered body refused replay %d: %v", i, err)
		}
		got, err := io.ReadAll(reader)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("replay %d returned %q, %v", i, got, err)
		}
	}

	oneShot, err := PartBodyFromReader(bytes.NewReader(payload), int64(len(payload)), digestHex)
	if err != nil {
		t.Fatalf("PartBodyFromReader: %v", err)
	}
	if _, err := oneShot.open(); err != nil {
		t.Fatalf("first open: %v", err)
	}
	if _, err := oneShot.open(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("second open = %v, want ErrInvalid", err)
	}

	if _, err := PartBodyFromOpener(1, "short", func() (io.ReadCloser, error) { return nil, nil }); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a malformed digest was accepted")
	}
	if _, err := PartBodyFromOpener(-1, digestHex, func() (io.ReadCloser, error) { return nil, nil }); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a negative length was accepted")
	}
	if _, err := PartBodyFromOpener(1, digestHex, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a nil opener was accepted")
	}
	if _, err := PartBodyFromReader(nil, 1, digestHex); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a nil reader was accepted")
	}
}

func TestOneShotPartBodyIsNotRetried(t *testing.T) {
	store, server := newFakeStore(t)
	client, _ := newTestClient(t, server, nil)
	key := testKey(t, client, "pack-000001")
	uploadID, err := client.CreateMultipartUpload(context.Background(), key, CreateMultipartOptions{})
	if err != nil {
		t.Fatalf("CreateMultipartUpload: %v", err)
	}
	store.mu.Lock()
	store.hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
		if r.Method != http.MethodPut {
			return false
		}
		writeFakeError(w, http.StatusServiceUnavailable, "ServiceUnavailable", "down")
		return true
	}
	store.mu.Unlock()

	payload := []byte("streamed part")
	digest := sha256.Sum256(payload)
	body, err := PartBodyFromReader(bytes.NewReader(payload), int64(len(payload)), hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatalf("PartBodyFromReader: %v", err)
	}
	_, err = client.UploadPart(context.Background(), key, uploadID, 1, body, "")
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("error = %v, want the unreplayable-body refusal", err)
	}
	if got := store.callCount("UploadPart"); got != 1 {
		t.Fatalf("the store saw %d part uploads, want 1", got)
	}
}

func TestNetworkFailureIsRetryable(t *testing.T) {
	_, server := newFakeStore(t)
	client, delays := newTestClient(t, server, func(config *Config) { config.MaxAttempts = 3 })
	key := testKey(t, client, "manifest")
	server.Close()

	_, err := client.GetObject(context.Background(), key, 1<<20)
	if !errors.Is(err, ErrRetryable) {
		t.Fatalf("error = %v, want ErrRetryable", err)
	}
	var storeError *Error
	if !errors.As(err, &storeError) || storeError.Kind != KindNetwork || storeError.StatusCode != 0 {
		t.Fatalf("unexpected error: %+v", storeError)
	}
	if len(*delays) != 2 {
		t.Fatalf("recorded %d delays, want 2", len(*delays))
	}
}

func TestCancelledContextStopsRetrying(t *testing.T) {
	store, server := newFakeStore(t)
	client, _ := newTestClient(t, server, func(config *Config) { config.MaxAttempts = 5 })
	ctx, cancel := context.WithCancel(context.Background())
	store.mu.Lock()
	store.hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
		cancel()
		writeFakeError(w, http.StatusServiceUnavailable, "ServiceUnavailable", "down")
		return true
	}
	store.mu.Unlock()
	// The recorded sleep returns the context error, which ends the loop.
	if _, err := client.GetObject(ctx, testKey(t, client, "manifest"), 1<<20); err == nil {
		t.Fatal("expected an error")
	}
	if got := store.callCount(http.MethodGet); got != 1 {
		t.Fatalf("the store saw %d GETs after cancellation, want 1", got)
	}
}

func TestVirtualHostAddressing(t *testing.T) {
	// The fake store is reached over loopback, so virtual-host addressing is
	// exercised by checking the request line and Host header a signed request
	// would carry rather than by dialling a bucket subdomain.
	client, err := New(Config{
		Endpoint:           "https://objects.example.internal",
		Region:             fakeRegion,
		Bucket:             fakeBucket,
		KeyPrefix:          "cells/cell-a",
		AccessKeyID:        fakeAccessKeyID,
		SecretAccessKey:    fakeSecretAccessKey,
		ChecksumCapability: ChecksumNone,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	key := testKey(t, client, "manifest")
	request, err := client.newHTTPRequest(context.Background(), storeRequest{
		op: "GetObject", method: http.MethodGet, key: key,
	})
	if err != nil {
		t.Fatalf("newHTTPRequest: %v", err)
	}
	if request.URL.Host != fakeBucket+".objects.example.internal" {
		t.Fatalf("host = %q", request.URL.Host)
	}
	if request.URL.EscapedPath() != "/"+key {
		t.Fatalf("path = %q, want %q", request.URL.EscapedPath(), "/"+key)
	}
	if !strings.Contains(request.Header.Get("Authorization"), "SignedHeaders=host;x-amz-content-sha256;x-amz-date,") {
		t.Fatalf("unexpected signed headers: %s", request.Header.Get("Authorization"))
	}
}

func TestPathStyleRequestShape(t *testing.T) {
	_, server := newFakeStore(t)
	client, _ := newTestClient(t, server, nil)
	key := testKey(t, client, "pack-000001")
	request, err := client.newHTTPRequest(context.Background(), storeRequest{
		op: "UploadPart", method: http.MethodPut, key: key,
		query: []queryParameter{{name: "partNumber", value: "3"}, {name: "uploadId", value: "a+b/c=="}},
		body:  PartBodyFromBytes([]byte("payload")),
	})
	if err != nil {
		t.Fatalf("newHTTPRequest: %v", err)
	}
	if request.URL.EscapedPath() != "/"+fakeBucket+"/"+key {
		t.Fatalf("path = %q", request.URL.EscapedPath())
	}
	if request.URL.RawQuery != "partNumber=3&uploadId=a%2Bb%2Fc%3D%3D" {
		t.Fatalf("query = %q", request.URL.RawQuery)
	}
	if request.ContentLength != 7 {
		t.Fatalf("content length = %d, want 7", request.ContentLength)
	}
	digest := sha256.Sum256([]byte("payload"))
	if request.Header.Get("X-Amz-Content-Sha256") != hex.EncodeToString(digest[:]) {
		t.Fatal("the part payload hash was not signed")
	}
}

func TestSignatureRejectionSurfacesAsAccessDenied(t *testing.T) {
	_, server := newFakeStore(t)
	client, _ := newTestClient(t, server, func(config *Config) {
		config.SecretAccessKey = "the-wrong-secret-entirely"
	})
	_, err := client.GetObject(context.Background(), testKey(t, client, "manifest"), 1<<20)
	if !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("error = %v, want ErrAccessDenied", err)
	}
	if errors.Is(err, ErrRetryable) {
		t.Fatal("a bad signature must not be retried")
	}
}

func TestSessionTokenIsAcceptedEndToEnd(t *testing.T) {
	store, server := newFakeStore(t)
	// The fake store now demands the token on every request, so a signature
	// that omitted or mis-signed it would fail the whole suite below.
	store.sessions = "AQoDYXdzEJr/session+token=="
	client, _ := newTestClient(t, server, func(config *Config) {
		config.SessionToken = "AQoDYXdzEJr/session+token=="
	})
	ctx := context.Background()
	key := testKey(t, client, "manifest")
	if _, err := client.PutObject(ctx, key, []byte("payload"), PutOptions{IfNoneMatch: true}); err != nil {
		t.Fatalf("PutObject with a session token: %v", err)
	}
	if _, err := client.HeadObject(ctx, key); err != nil {
		t.Fatalf("HeadObject with a session token: %v", err)
	}

	// A client without the token is rejected by the same store.
	tokenless, _ := newTestClient(t, server, nil)
	if _, err := tokenless.HeadObject(ctx, key); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("tokenless request = %v, want ErrAccessDenied", err)
	}
}

func TestRedirectsAreRefused(t *testing.T) {
	store, server := newFakeStore(t)
	client, _ := newTestClient(t, server, nil)
	store.mu.Lock()
	store.hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
		w.Header().Set("Location", "https://elsewhere.example/steal")
		w.WriteHeader(http.StatusTemporaryRedirect)
		return true
	}
	store.mu.Unlock()
	if _, err := client.GetObject(context.Background(), testKey(t, client, "manifest"), 1<<20); err == nil {
		t.Fatal("a redirect was followed")
	}
}

func TestErrorKindStrings(t *testing.T) {
	kinds := []Kind{KindOther, KindNotFound, KindPreconditionFailed, KindAccessDenied, KindThrottled, KindServer, KindNetwork, KindResponse}
	seen := map[string]struct{}{}
	for _, kind := range kinds {
		name := kind.String()
		if name == "" || name == "unknown" {
			t.Fatalf("kind %d has no name", kind)
		}
		if _, duplicate := seen[name]; duplicate {
			t.Fatalf("duplicate kind name %q", name)
		}
		seen[name] = struct{}{}
	}
	if Kind(200).String() != "unknown" {
		t.Fatal("an out-of-range kind should render as unknown")
	}
	storeError := &Error{Op: "GetObject", Key: "k", StatusCode: 404, Code: "NoSuchKey", Message: "gone", Kind: KindNotFound, Attempts: 1}
	if !strings.Contains(storeError.Error(), "GetObject") || !strings.Contains(storeError.Error(), "NoSuchKey") {
		t.Fatalf("error text is missing detail: %s", storeError.Error())
	}
	wrapped := &Error{Op: "PutObject", Kind: KindNetwork, cause: io.ErrUnexpectedEOF}
	if !errors.Is(wrapped, io.ErrUnexpectedEOF) {
		t.Fatal("the transport cause is not unwrappable")
	}
}
