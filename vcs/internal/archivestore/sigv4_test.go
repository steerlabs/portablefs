package archivestore

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The vectors below follow the shape of the official AWS SigV4 test suite: each
// pins the canonical request — the human-checkable intermediate where every
// canonicalization rule is visible — and the expected signature is then derived
// inside the test with a second, step-by-step HMAC chain written against the
// specification. No signature constant is copied from anywhere, so a vector
// cannot silently encode a bug in the code under test.

const (
	vectorAccessKeyID = "AKIAIOSFODNN7EXAMPLE"
	vectorSecret      = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	vectorRegion      = "us-east-1"
	vectorHost        = "examplebucket.s3.amazonaws.com"
	vectorAmzDate     = "20130524T000000Z"
	vectorDateStamp   = "20130524"
)

var vectorTime = time.Date(2013, time.May, 24, 0, 0, 0, 0, time.UTC)

type sigv4Vector struct {
	name string
	// build returns a request with its headers already set, exactly as the
	// client would hand it to the signer.
	build func(t *testing.T) (*http.Request, string)
	// wantCanonicalRequest is hand-derived from the SigV4 specification.
	wantCanonicalRequest string
	wantSignedHeaders    string
}

func sigv4Vectors() []sigv4Vector {
	return []sigv4Vector{
		{
			name: "simple GET",
			build: func(t *testing.T) (*http.Request, string) {
				return newVectorRequest(t, http.MethodGet, "/test.txt", "", nil, nil), EmptyPayloadSHA256
			},
			wantCanonicalRequest: strings.Join([]string{
				"GET",
				"/test.txt",
				"",
				"host:examplebucket.s3.amazonaws.com",
				"x-amz-content-sha256:" + EmptyPayloadSHA256,
				"x-amz-date:" + vectorAmzDate,
				"",
				"host;x-amz-content-sha256;x-amz-date",
				EmptyPayloadSHA256,
			}, "\n"),
			wantSignedHeaders: "host;x-amz-content-sha256;x-amz-date",
		},
		{
			name: "GET with query parameters needing encoding",
			build: func(t *testing.T) (*http.Request, string) {
				query := encodeQuery([]queryParameter{
					{name: "uploadId", value: "abc+def/xyz=="},
					{name: "partNumber", value: "2"},
				})
				if query != "partNumber=2&uploadId=abc%2Bdef%2Fxyz%3D%3D" {
					t.Fatalf("query encoder produced %q", query)
				}
				return newVectorRequest(t, http.MethodGet, "/pack-000001", query, nil, nil), EmptyPayloadSHA256
			},
			wantCanonicalRequest: strings.Join([]string{
				"GET",
				"/pack-000001",
				"partNumber=2&uploadId=abc%2Bdef%2Fxyz%3D%3D",
				"host:examplebucket.s3.amazonaws.com",
				"x-amz-content-sha256:" + EmptyPayloadSHA256,
				"x-amz-date:" + vectorAmzDate,
				"",
				"host;x-amz-content-sha256;x-amz-date",
				EmptyPayloadSHA256,
			}, "\n"),
			wantSignedHeaders: "host;x-amz-content-sha256;x-amz-date",
		},
		{
			name: "PUT with a signed payload and conditional create",
			build: func(t *testing.T) (*http.Request, string) {
				payload := []byte("Welcome to Amazon S3.")
				digest := sha256.Sum256(payload)
				header := http.Header{}
				header.Set("Content-Type", "application/octet-stream")
				header.Set("If-None-Match", "*")
				header.Set(headerChecksumCRC64, CRC64Base64(ChecksumCRC64NVME(payload)))
				return newVectorRequest(t, http.MethodPut, "/test%24file.text", "", header, payload),
					hex.EncodeToString(digest[:])
			},
			wantCanonicalRequest: strings.Join([]string{
				"PUT",
				// '$' is not unreserved, so the key encodes to %24 and the
				// canonical URI carries the encoded form verbatim (S3 encodes
				// the path exactly once).
				"/test%24file.text",
				"",
				"content-type:application/octet-stream",
				"host:examplebucket.s3.amazonaws.com",
				"if-none-match:*",
				"x-amz-checksum-crc64nvme:" + CRC64Base64(ChecksumCRC64NVME([]byte("Welcome to Amazon S3."))),
				"x-amz-content-sha256:" + sha256Hex([]byte("Welcome to Amazon S3.")),
				"x-amz-date:" + vectorAmzDate,
				"",
				"content-type;host;if-none-match;x-amz-checksum-crc64nvme;x-amz-content-sha256;x-amz-date",
				sha256Hex([]byte("Welcome to Amazon S3.")),
			}, "\n"),
			wantSignedHeaders: "content-type;host;if-none-match;x-amz-checksum-crc64nvme;x-amz-content-sha256;x-amz-date",
		},
		{
			name: "header canonicalization with duplicate and padded values",
			build: func(t *testing.T) (*http.Request, string) {
				header := http.Header{}
				// Leading, trailing, and internal whitespace all collapse; the
				// two values for one name join with a comma in order.
				header.Add("My-Header1", "  a  b  c  ")
				header.Add("My-Header1", "def")
				header.Set("Range", "bytes=0-8388607")
				return newVectorRequest(t, http.MethodGet, "/pack-000001", "", header, nil), EmptyPayloadSHA256
			},
			wantCanonicalRequest: strings.Join([]string{
				"GET",
				"/pack-000001",
				"",
				"host:examplebucket.s3.amazonaws.com",
				"my-header1:a b c,def",
				"range:bytes=0-8388607",
				"x-amz-content-sha256:" + EmptyPayloadSHA256,
				"x-amz-date:" + vectorAmzDate,
				"",
				"host;my-header1;range;x-amz-content-sha256;x-amz-date",
				EmptyPayloadSHA256,
			}, "\n"),
			wantSignedHeaders: "host;my-header1;range;x-amz-content-sha256;x-amz-date",
		},
	}
}

func TestSigV4Vectors(t *testing.T) {
	for _, vector := range sigv4Vectors() {
		t.Run(vector.name, func(t *testing.T) {
			request, payloadHash := vector.build(t)
			credential := credentials{accessKeyID: vectorAccessKeyID, secretAccessKey: vectorSecret}
			if err := signRequest(request, credential, vectorRegion, vectorTime, payloadHash); err != nil {
				t.Fatalf("signRequest: %v", err)
			}

			// Step 1: the canonical request the signer actually built.
			gotCanonical, gotSignedHeaders, err := canonicalRequestFor(request, vectorHost, payloadHash)
			if err != nil {
				t.Fatalf("canonicalRequestFor: %v", err)
			}
			if gotCanonical != vector.wantCanonicalRequest {
				t.Fatalf("canonical request mismatch\n got:\n%s\nwant:\n%s", gotCanonical, vector.wantCanonicalRequest)
			}
			if gotSignedHeaders != vector.wantSignedHeaders {
				t.Fatalf("signed headers = %q, want %q", gotSignedHeaders, vector.wantSignedHeaders)
			}

			// Step 2: derive the string to sign from the pinned canonical
			// request, independently of the code under test.
			scope := vectorDateStamp + "/" + vectorRegion + "/s3/aws4_request"
			canonicalDigest := sha256.Sum256([]byte(vector.wantCanonicalRequest))
			stringToSign := strings.Join([]string{
				"AWS4-HMAC-SHA256",
				vectorAmzDate,
				scope,
				hex.EncodeToString(canonicalDigest[:]),
			}, "\n")
			if lines := strings.Split(stringToSign, "\n"); len(lines) != 4 || lines[0] != "AWS4-HMAC-SHA256" {
				t.Fatalf("string to sign has an unexpected shape: %q", stringToSign)
			}

			// Step 3: derive the signing key one HMAC at a time.
			dateKey := vectorMAC([]byte("AWS4"+vectorSecret), vectorDateStamp)
			regionKey := vectorMAC(dateKey, vectorRegion)
			serviceKey := vectorMAC(regionKey, "s3")
			signingKey := vectorMAC(serviceKey, "aws4_request")
			if len(dateKey) != 32 || len(signingKey) != 32 {
				t.Fatalf("signing key derivation produced the wrong width")
			}

			// Step 4: the signature, and the whole Authorization header.
			wantSignature := hex.EncodeToString(vectorMAC(signingKey, stringToSign))
			wantAuthorization := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
				vectorAccessKeyID, scope, vector.wantSignedHeaders, wantSignature)
			if got := request.Header.Get("Authorization"); got != wantAuthorization {
				t.Fatalf("authorization mismatch\n got: %s\nwant: %s", got, wantAuthorization)
			}
			if got := request.Header.Get("X-Amz-Date"); got != vectorAmzDate {
				t.Fatalf("x-amz-date = %q, want %q", got, vectorAmzDate)
			}
			if got := request.Header.Get("X-Amz-Content-Sha256"); got != payloadHash {
				t.Fatalf("x-amz-content-sha256 = %q, want %q", got, payloadHash)
			}
		})
	}
}

func TestSignRequestSessionTokenIsSigned(t *testing.T) {
	request := newVectorRequest(t, http.MethodGet, "/manifest", "", nil, nil)
	credential := credentials{accessKeyID: vectorAccessKeyID, secretAccessKey: vectorSecret, sessionToken: "session/token+value=="}
	if err := signRequest(request, credential, vectorRegion, vectorTime, EmptyPayloadSHA256); err != nil {
		t.Fatalf("signRequest: %v", err)
	}
	if got := request.Header.Get("X-Amz-Security-Token"); got != "session/token+value==" {
		t.Fatalf("session token header = %q", got)
	}
	authorization := request.Header.Get("Authorization")
	if !strings.Contains(authorization, "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token,") {
		t.Fatalf("session token is not covered by the signature: %s", authorization)
	}
}

func TestSignRequestRefusesBadInput(t *testing.T) {
	credential := credentials{accessKeyID: vectorAccessKeyID, secretAccessKey: vectorSecret}
	cases := map[string]func() error{
		"no request": func() error {
			return signRequest(nil, credential, vectorRegion, vectorTime, EmptyPayloadSHA256)
		},
		"no region": func() error {
			return signRequest(newVectorRequest(t, http.MethodGet, "/k", "", nil, nil), credential, "", vectorTime, EmptyPayloadSHA256)
		},
		"no credentials": func() error {
			return signRequest(newVectorRequest(t, http.MethodGet, "/k", "", nil, nil), credentials{}, vectorRegion, vectorTime, EmptyPayloadSHA256)
		},
		"uppercase payload hash": func() error {
			return signRequest(newVectorRequest(t, http.MethodGet, "/k", "", nil, nil), credential, vectorRegion, vectorTime, strings.ToUpper(EmptyPayloadSHA256))
		},
		"short payload hash": func() error {
			return signRequest(newVectorRequest(t, http.MethodGet, "/k", "", nil, nil), credential, vectorRegion, vectorTime, "abcd")
		},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			if err := run(); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestSignRequestOverwritesAStaleAuthorization(t *testing.T) {
	// A retry re-signs the same request object shape; a stale Authorization
	// header must never be signed into the next attempt's canonical headers.
	request := newVectorRequest(t, http.MethodGet, "/manifest", "", nil, nil)
	request.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=stale")
	credential := credentials{accessKeyID: vectorAccessKeyID, secretAccessKey: vectorSecret}
	if err := signRequest(request, credential, vectorRegion, vectorTime, EmptyPayloadSHA256); err != nil {
		t.Fatalf("signRequest: %v", err)
	}
	if strings.Contains(request.Header.Get("Authorization"), "stale") {
		t.Fatal("stale authorization survived signing")
	}
	if strings.Contains(request.Header.Get("Authorization"), "SignedHeaders=authorization") {
		t.Fatal("authorization must never appear in signed headers")
	}
}

func TestURIEncode(t *testing.T) {
	cases := []struct {
		value       string
		encodeSlash bool
		want        string
	}{
		{"simple-key.txt", true, "simple-key.txt"},
		{"a/b/c", false, "a/b/c"},
		{"a/b/c", true, "a%2Fb%2Fc"},
		{"a b", true, "a%20b"},
		{"a+b", true, "a%2Bb"},
		{"~-_.", true, "~-_."},
		{"\x00\xff", true, "%00%FF"},
		{"=&?", true, "%3D%26%3F"},
	}
	for _, testCase := range cases {
		if got := uriEncode(testCase.value, testCase.encodeSlash); got != testCase.want {
			t.Fatalf("uriEncode(%q, %v) = %q, want %q", testCase.value, testCase.encodeSlash, got, testCase.want)
		}
	}
}

func TestCanonicalQueryStringIsIdempotent(t *testing.T) {
	encoded := encodeQuery([]queryParameter{
		{name: "uploadId", value: "a+b/c=="},
		{name: "partNumber", value: "10"},
		{name: "uploads"},
	})
	first, err := canonicalQueryString(encoded)
	if err != nil {
		t.Fatalf("canonicalQueryString: %v", err)
	}
	if first != encoded {
		t.Fatalf("canonicalization changed an already-canonical query: %q -> %q", encoded, first)
	}
	second, err := canonicalQueryString(first)
	if err != nil {
		t.Fatalf("canonicalQueryString: %v", err)
	}
	if second != first {
		t.Fatalf("canonicalization is not idempotent: %q -> %q", first, second)
	}
	if !strings.HasPrefix(encoded, "partNumber=10&uploadId=") || !strings.HasSuffix(encoded, "&uploads=") {
		t.Fatalf("unexpected canonical query %q", encoded)
	}
}

func TestCollapseHeaderValue(t *testing.T) {
	cases := map[string]string{
		"  a  b  c  ":  "a b c",
		"a\tb":         "a b",
		"single":       "single",
		"   ":          "",
		"a   b\t\t  c": "a b c",
	}
	for input, want := range cases {
		if got := collapseHeaderValue(input); got != want {
			t.Fatalf("collapseHeaderValue(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestPercentDecodeLeavesPlusAlone(t *testing.T) {
	// url.QueryUnescape would turn this into a space and silently corrupt an
	// upload ID; the canonicalizer must not.
	got, err := percentDecode("a+b%2Fc")
	if err != nil {
		t.Fatalf("percentDecode: %v", err)
	}
	if got != "a+b/c" {
		t.Fatalf("percentDecode = %q, want %q", got, "a+b/c")
	}
	if _, err := percentDecode("%zz"); err == nil {
		t.Fatal("expected an error for a malformed escape")
	}
	if _, err := percentDecode("abc%2"); err == nil {
		t.Fatal("expected an error for a truncated escape")
	}
}

func newVectorRequest(t *testing.T, method, encodedPath, rawQuery string, header http.Header, payload []byte) *http.Request {
	t.Helper()
	decodedPath, err := percentDecode(encodedPath)
	if err != nil {
		t.Fatalf("percentDecode(%q): %v", encodedPath, err)
	}
	target := url.URL{Scheme: "https", Host: vectorHost, Path: decodedPath, RawPath: encodedPath, RawQuery: rawQuery}
	request, err := http.NewRequest(method, target.String(), nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	request.URL = &target
	request.Host = vectorHost
	request.ContentLength = int64(len(payload))
	for name, values := range header {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	if got := request.URL.EscapedPath(); got != encodedPath {
		t.Fatalf("EscapedPath() = %q, want the wire form %q", got, encodedPath)
	}
	return request
}

func vectorMAC(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

func sha256Hex(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}
