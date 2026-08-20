package archivestore

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

const (
	signingAlgorithm   = "AWS4-HMAC-SHA256"
	signingService     = "s3"
	signingTerminator  = "aws4_request"
	amzDateFormat      = "20060102T150405Z"
	amzDateStampFormat = "20060102"
	// EmptyPayloadSHA256 is SHA-256 of the empty string, the payload hash every
	// bodyless request signs. UNSIGNED-PAYLOAD is deliberately never used: the
	// archive path always knows its payload digest, and signing it makes the
	// signature cover the bytes rather than only their envelope.
	EmptyPayloadSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

type credentials struct {
	accessKeyID     string
	secretAccessKey string
	sessionToken    string
}

// signRequest signs req in place with SigV4 for the s3 service.
//
// Two invariants make signer and wire agree byte for byte:
//   - req.URL.RawPath holds this package's own percent-encoding of the key, so
//     EscapedPath returns exactly what net/http writes on the wire;
//   - req.URL.RawQuery was produced by encodeQuery, so re-canonicalizing it
//     here is idempotent and never sees a bare '+' (which would otherwise be
//     ambiguous between a literal plus and an encoded space).
//
// Every header present on req at call time is signed, plus host. Nothing may be
// added to req.Header after signing; net/http's own late additions
// (User-Agent, Accept-Encoding) are outside SignedHeaders and therefore safe.
func signRequest(req *http.Request, cred credentials, region string, signTime time.Time, payloadSHA256 string) error {
	if req == nil || req.URL == nil {
		return fmt.Errorf("%w: signing requires a request with a URL", ErrInvalid)
	}
	if cred.accessKeyID == "" || cred.secretAccessKey == "" || region == "" {
		return fmt.Errorf("%w: signing requires credentials and a region", ErrInvalid)
	}
	if !validLowerHex(payloadSHA256, sha256.Size) {
		return fmt.Errorf("%w: payload hash must be 64 lowercase hex characters", ErrInvalid)
	}
	signTime = signTime.UTC()
	amzDate := signTime.Format(amzDateFormat)
	dateStamp := signTime.Format(amzDateStampFormat)

	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadSHA256)
	if cred.sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", cred.sessionToken)
	}
	req.Header.Del("Authorization")

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	if host == "" {
		return fmt.Errorf("%w: signing requires a host", ErrInvalid)
	}

	canonicalRequest, signedHeaders, err := canonicalRequestFor(req, host, payloadSHA256)
	if err != nil {
		return err
	}

	scope := strings.Join([]string{dateStamp, region, signingService, signingTerminator}, "/")
	hashedRequest := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := strings.Join([]string{
		signingAlgorithm,
		amzDate,
		scope,
		hex.EncodeToString(hashedRequest[:]),
	}, "\n")

	signature := hex.EncodeToString(hmacSHA256(signingKey(cred.secretAccessKey, dateStamp, region), []byte(stringToSign)))
	req.Header.Set("Authorization", fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		signingAlgorithm, cred.accessKeyID, scope, signedHeaders, signature))
	return nil
}

// canonicalRequestFor builds the canonical request and the signed-header list.
// It is separate from signRequest so the vector tests can assert the exact
// intermediate string rather than only the final signature.
func canonicalRequestFor(req *http.Request, host, payloadSHA256 string) (string, string, error) {
	canonicalHeaders, signedHeaders := canonicalizeHeaders(req.Header, host)
	canonicalQuery, err := canonicalQueryString(req.URL.RawQuery)
	if err != nil {
		return "", "", err
	}
	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	return strings.Join([]string{
		req.Method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders,
		signedHeaders,
		payloadSHA256,
	}, "\n"), signedHeaders, nil
}

func signingKey(secretAccessKey, dateStamp, region string) []byte {
	key := hmacSHA256([]byte("AWS4"+secretAccessKey), []byte(dateStamp))
	key = hmacSHA256(key, []byte(region))
	key = hmacSHA256(key, []byte(signingService))
	return hmacSHA256(key, []byte(signingTerminator))
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// canonicalizeHeaders returns the canonical headers block and the signed-header
// list. Header values are trimmed and their internal whitespace runs collapsed
// to a single space, per the SigV4 rules; duplicate values for one name are
// joined with "," in the order net/http stored them.
func canonicalizeHeaders(header http.Header, host string) (string, string) {
	values := make(map[string][]string, len(header)+1)
	values["host"] = []string{host}
	for name, list := range header {
		lower := strings.ToLower(name)
		if lower == "authorization" || lower == "host" {
			continue
		}
		collapsed := make([]string, 0, len(list))
		for _, value := range list {
			collapsed = append(collapsed, collapseHeaderValue(value))
		}
		values[lower] = collapsed
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	var canonical strings.Builder
	for _, name := range names {
		canonical.WriteString(name)
		canonical.WriteByte(':')
		canonical.WriteString(strings.Join(values[name], ","))
		canonical.WriteByte('\n')
	}
	return canonical.String(), strings.Join(names, ";")
}

func collapseHeaderValue(value string) string {
	value = strings.Trim(value, " \t")
	var builder strings.Builder
	builder.Grow(len(value))
	space := false
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == ' ' || c == '\t' {
			space = true
			continue
		}
		if space && builder.Len() > 0 {
			builder.WriteByte(' ')
		}
		space = false
		builder.WriteByte(c)
	}
	return builder.String()
}

type queryParameter struct {
	name  string
	value string
}

// encodeQuery renders parameters in canonical SigV4 order. The result is used
// verbatim both as URL.RawQuery and, after an idempotent re-canonicalization,
// as the canonical query string.
func encodeQuery(parameters []queryParameter) string {
	encoded := make([]string, 0, len(parameters))
	for _, parameter := range parameters {
		encoded = append(encoded, uriEncode(parameter.name, true)+"="+uriEncode(parameter.value, true))
	}
	sort.Strings(encoded)
	return strings.Join(encoded, "&")
}

func canonicalQueryString(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	pairs := strings.Split(raw, "&")
	encoded := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		if pair == "" {
			return "", fmt.Errorf("%w: empty query parameter", ErrInvalid)
		}
		name, value, _ := strings.Cut(pair, "=")
		decodedName, err := percentDecode(name)
		if err != nil {
			return "", err
		}
		decodedValue, err := percentDecode(value)
		if err != nil {
			return "", err
		}
		encoded = append(encoded, uriEncode(decodedName, true)+"="+uriEncode(decodedValue, true))
	}
	sort.Strings(encoded)
	return strings.Join(encoded, "&"), nil
}

// percentDecode decodes %XX escapes only. Unlike url.QueryUnescape it leaves
// '+' alone: this package never emits a bare '+', and treating one as a space
// would silently corrupt a multipart upload ID.
func percentDecode(value string) (string, error) {
	if !strings.Contains(value, "%") {
		return value, nil
	}
	var builder strings.Builder
	builder.Grow(len(value))
	for i := 0; i < len(value); i++ {
		if value[i] != '%' {
			builder.WriteByte(value[i])
			continue
		}
		if i+2 >= len(value) {
			return "", fmt.Errorf("%w: truncated percent escape", ErrInvalid)
		}
		decoded, err := hex.DecodeString(value[i+1 : i+3])
		if err != nil {
			return "", fmt.Errorf("%w: malformed percent escape", ErrInvalid)
		}
		builder.WriteByte(decoded[0])
		i += 2
	}
	return builder.String(), nil
}

// uriEncode implements the S3 flavour of RFC 3986 encoding: unreserved
// characters pass through, everything else becomes uppercase %XX, and '/' is
// preserved in path position. S3 canonical URIs are encoded exactly once (the
// double-encoding rule of other AWS services does not apply).
func uriEncode(value string, encodeSlash bool) string {
	var builder strings.Builder
	builder.Grow(len(value))
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			builder.WriteByte(c)
		case c == '/' && !encodeSlash:
			builder.WriteByte('/')
		default:
			builder.WriteByte('%')
			builder.WriteByte(upperHexDigits[c>>4])
			builder.WriteByte(upperHexDigits[c&0x0f])
		}
	}
	return builder.String()
}

const upperHexDigits = "0123456789ABCDEF"

func validLowerHex(value string, size int) bool {
	if len(value) != 2*size {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
