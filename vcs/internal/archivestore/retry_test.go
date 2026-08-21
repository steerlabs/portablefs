package archivestore

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestClassifyStatus(t *testing.T) {
	cases := []struct {
		status        int
		code          string
		wantKind      Kind
		wantRetryable bool
	}{
		{404, "NoSuchKey", KindNotFound, false},
		{404, "", KindNotFound, false},
		{404, "NoSuchUpload", KindNotFound, false},
		{412, "PreconditionFailed", KindPreconditionFailed, false},
		{409, "ConditionalRequestConflict", KindPreconditionFailed, false},
		{409, "", KindPreconditionFailed, false},
		{403, "AccessDenied", KindAccessDenied, false},
		{403, "SignatureDoesNotMatch", KindAccessDenied, false},
		{401, "", KindAccessDenied, false},
		{400, "ExpiredToken", KindAccessDenied, false},
		{429, "", KindThrottled, true},
		{503, "SlowDown", KindThrottled, true},
		{500, "InternalError", KindServer, true},
		{503, "", KindServer, true},
		{502, "", KindServer, true},
		{400, "RequestTimeout", KindServer, true},
		{400, "MalformedXML", KindOther, false},
		{418, "", KindOther, false},
		// A 200 carrying an <Error> classifies on the code alone.
		{0, "InternalError", KindServer, true},
		{0, "NoSuchKey", KindNotFound, false},
	}
	for _, testCase := range cases {
		kind, isRetryable := classifyStatus(testCase.status, testCase.code)
		if kind != testCase.wantKind || isRetryable != testCase.wantRetryable {
			t.Fatalf("classifyStatus(%d, %q) = %v/%v, want %v/%v",
				testCase.status, testCase.code, kind, isRetryable, testCase.wantKind, testCase.wantRetryable)
		}
	}
}

func TestErrorSentinelMapping(t *testing.T) {
	cases := map[Kind]error{
		KindNotFound:           ErrNotFound,
		KindPreconditionFailed: ErrPreconditionFailed,
		KindAccessDenied:       ErrAccessDenied,
		KindThrottled:          ErrThrottled,
		KindResponse:           ErrResponse,
	}
	for kind, sentinel := range cases {
		storeError := &Error{Kind: kind}
		if !errors.Is(storeError, sentinel) {
			t.Fatalf("kind %v does not match its sentinel", kind)
		}
		for otherKind, otherSentinel := range cases {
			if otherKind != kind && errors.Is(storeError, otherSentinel) {
				t.Fatalf("kind %v also matched %v's sentinel", kind, otherKind)
			}
		}
	}
	if errors.Is(&Error{Kind: KindServer}, ErrNotFound) {
		t.Fatal("a server error matched ErrNotFound")
	}
	if !errors.Is(&Error{Kind: KindServer, retryable: true}, ErrRetryable) {
		t.Fatal("a retryable error did not match ErrRetryable")
	}
	if errors.Is(&Error{Kind: KindNotFound}, ErrRetryable) {
		t.Fatal("a non-retryable error matched ErrRetryable")
	}
	if errors.Is(&Error{Kind: KindOther}, ErrInvalid) {
		t.Fatal("a store error must never masquerade as a local validation failure")
	}
}

func TestBackoffDelay(t *testing.T) {
	client := &Client{jitter: func() float64 { return 1 }}
	client.config.RetryBaseDelay = 100 * time.Millisecond
	client.config.RetryMaxDelay = 500 * time.Millisecond

	want := []time.Duration{100, 200, 400, 500, 500}
	for attempt := 1; attempt <= len(want); attempt++ {
		got := client.backoffDelay(attempt, 0)
		if got != want[attempt-1]*time.Millisecond {
			t.Fatalf("backoffDelay(%d) = %v, want %v", attempt, got, want[attempt-1]*time.Millisecond)
		}
	}

	// Jitter only ever shortens a delay, and never below one millisecond.
	client.jitter = func() float64 { return 0 }
	if got := client.backoffDelay(3, 0); got != time.Millisecond {
		t.Fatalf("fully jittered delay = %v, want the 1ms floor", got)
	}
	client.jitter = func() float64 { return 0.5 }
	if got := client.backoffDelay(2, 0); got != 100*time.Millisecond {
		t.Fatalf("half-jittered delay = %v, want 100ms", got)
	}

	// A Retry-After hint wins, but is clamped.
	if got := client.backoffDelay(1, 2*time.Second); got != 2*time.Second {
		t.Fatalf("Retry-After delay = %v, want 2s", got)
	}
	if got := client.backoffDelay(1, time.Hour); got != maxRetryAfterDelay {
		t.Fatalf("an unbounded Retry-After was honoured: %v", got)
	}
}

func TestParseRetryAfter(t *testing.T) {
	cases := map[string]time.Duration{
		"":                              0,
		"1":                             time.Second,
		"30":                            30 * time.Second,
		"0":                             0,
		"-5":                            0,
		"not-a-number":                  0,
		"Wed, 21 Oct 2015 07:28:00 GMT": 0, // the date form is ignored, not guessed at
	}
	for value, want := range cases {
		if got := parseRetryAfter(value); got != want {
			t.Fatalf("parseRetryAfter(%q) = %v, want %v", value, got, want)
		}
	}
}

func TestSleepContext(t *testing.T) {
	start := time.Now()
	if err := sleepContext(context.Background(), 5*time.Millisecond); err != nil {
		t.Fatalf("sleepContext: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 4*time.Millisecond {
		t.Fatalf("sleepContext returned after only %v", elapsed)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleepContext(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("sleepContext on a cancelled context = %v, want context.Canceled", err)
	}
}

func TestDecodeXMLErrorIsBoundedAndStrict(t *testing.T) {
	document, err := decodeXMLError([]byte(`<?xml version="1.0"?><Error><Code>NoSuchKey</Code><Message> gone
</Message><RequestId>abc</RequestId></Error>`))
	if err != nil {
		t.Fatalf("decodeXMLError: %v", err)
	}
	if document.Code != "NoSuchKey" || document.Message != "gone" || document.RequestID != "abc" {
		t.Fatalf("decoded %+v", document)
	}
	for _, payload := range []string{"", "   ", "not xml", "<Other><Code>x</Code></Other>"} {
		if _, err := decodeXMLError([]byte(payload)); !errors.Is(err, ErrResponse) {
			t.Fatalf("decodeXMLError(%q) = %v, want ErrResponse", payload, err)
		}
	}
}

func TestSanitizeText(t *testing.T) {
	if got := sanitizeText("  hello\x00\x07 world\n", 64); got != "hello world" {
		t.Fatalf("sanitizeText = %q", got)
	}
	if got := sanitizeText("abcdef", 3); got != "abc" {
		t.Fatalf("sanitizeText did not truncate: %q", got)
	}
}

func TestResponseErrorCarriesRetryAfter(t *testing.T) {
	client := &Client{}
	response := &http.Response{
		StatusCode: http.StatusServiceUnavailable,
		Header:     http.Header{"Retry-After": []string{"3"}, "X-Amz-Request-Id": []string{"req-1"}},
		Body:       http.NoBody,
	}
	storeError := client.responseError(storeRequest{op: "GetObject", key: "k"}, response)
	if !storeError.Retryable() || storeError.retryAfter != 3*time.Second {
		t.Fatalf("unexpected error: %+v (retryAfter %v)", storeError, storeError.retryAfter)
	}
	if storeError.RequestID != "req-1" {
		t.Fatalf("request ID = %q", storeError.RequestID)
	}
	if got := retryAfterOf(storeError); got != 3*time.Second {
		t.Fatalf("retryAfterOf = %v", got)
	}
	if got := retryAfterOf(errors.New("plain")); got != 0 {
		t.Fatalf("retryAfterOf on a plain error = %v", got)
	}
}
