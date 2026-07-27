package histstore

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// signV4 signs one S3 request in place with AWS Signature Version 4
// (service "s3"). payloadHashHex is the hex sha256 of the exact body bytes;
// content addressing means the worker always knows it WITHOUT buffering the
// body (an object's payload hash is its digest; empty-body operations use
// the empty hash). This mirrors the TypeScript S3BlobStore
// (@portablefs/storage-s3) signer byte for byte so both sides accept the
// same endpoints.
func signV4(req *http.Request, region, accessKeyID, secretAccessKey, payloadHashHex string, now time.Time) {
	amzDate := now.UTC().Format("20060102T150405Z")
	shortDate := amzDate[:8]

	req.Header.Set("host", req.URL.Host)
	req.Header.Set("x-amz-content-sha256", payloadHashHex)
	req.Header.Set("x-amz-date", amzDate)

	type headerKV struct{ name, value string }
	var canonical []headerKV
	for name, values := range req.Header {
		lower := strings.ToLower(name)
		canonical = append(canonical, headerKV{lower, normalizeHeaderValue(strings.Join(values, ","))})
	}
	sort.Slice(canonical, func(i, j int) bool { return canonical[i].name < canonical[j].name })

	var signedNames, canonicalHeaders strings.Builder
	for i, kv := range canonical {
		if i > 0 {
			signedNames.WriteByte(';')
		}
		signedNames.WriteString(kv.name)
		canonicalHeaders.WriteString(kv.name)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(kv.value)
		canonicalHeaders.WriteByte('\n')
	}

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI(req.URL),
		canonicalQuery(req.URL),
		canonicalHeaders.String(),
		signedNames.String(),
		payloadHashHex,
	}, "\n")

	scope := shortDate + "/" + region + "/s3/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		hexSHA256([]byte(canonicalRequest)),
	}, "\n")

	key := hmacSHA256([]byte("AWS4"+secretAccessKey), shortDate)
	key = hmacSHA256(key, region)
	key = hmacSHA256(key, "s3")
	key = hmacSHA256(key, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(key, stringToSign))

	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKeyID, scope, signedNames.String(), signature))
}

// canonicalURI returns the RFC 3986 segment-encoded path. Keys built by
// this package are already limited to safe bytes plus '%', so the encoded
// path equals EscapedPath; using the URL's escaped form keeps the wire path
// and the signed path identical.
func canonicalURI(u *url.URL) string {
	p := u.EscapedPath()
	if p == "" {
		return "/"
	}
	return p
}

func canonicalQuery(u *url.URL) string {
	if u.RawQuery == "" {
		return ""
	}
	values, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return u.RawQuery
	}
	return values.Encode() // sorted by key, URL-escaped
}

func normalizeHeaderValue(v string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(v)), " ")
}

func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, value string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(value))
	return m.Sum(nil)
}

// emptyPayloadSHA256 is sha256("") — the payload hash of bodyless requests.
const emptyPayloadSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
