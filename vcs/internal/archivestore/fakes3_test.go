package archivestore

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// The fake store verifies every request signature with a SigV4 implementation
// written independently of sigv4.go: it canonicalizes from the raw request
// target the server received rather than from a net/url round trip, and it has
// its own percent codec, header collapser, and HMAC chain. A signer bug that
// happened to be self-consistent would still fail here.

const (
	fakeAccessKeyID     = "AKIAIOSFODNN7EXAMPLE"
	fakeSecretAccessKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	fakeRegion          = "us-west-2"
	fakeBucket          = "portablefs-archive"
)

type fakeObject struct {
	payload []byte
	etag    string
}

type fakePart struct {
	payload  []byte
	etag     string
	checksum string // base64 CRC64NVME, empty when not supplied
}

type fakeUpload struct {
	key          string
	fullObject   bool
	parts        map[int]fakePart
	completeBody [][]byte
}

// fakeStore is an in-memory S3-compatible store. It is intentionally strict:
// anything the client sends that S3 would reject, it rejects.
type fakeStore struct {
	t *testing.T

	mu         sync.Mutex
	objects    map[string]fakeObject
	uploads    map[string]*fakeUpload
	nextUpload int
	calls      map[string]int
	sessions   string

	// checksums controls whether the store echoes x-amz-checksum-crc64nvme.
	checksums bool
	// hook may short-circuit a request. It runs after signature verification
	// so scripted failures still prove the signature was correct.
	hook func(w http.ResponseWriter, r *http.Request, body []byte) bool
}

func newFakeStore(t *testing.T) (*fakeStore, *httptest.Server) {
	t.Helper()
	store := &fakeStore{
		t:         t,
		objects:   map[string]fakeObject{},
		uploads:   map[string]*fakeUpload{},
		calls:     map[string]int{},
		checksums: true,
	}
	server := httptest.NewServer(store)
	t.Cleanup(server.Close)
	return store, server
}

func (s *fakeStore) callCount(operation string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[operation]
}

func (s *fakeStore) putObject(key string, payload []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects[key] = fakeObject{payload: payload, etag: fakeETag(payload)}
}

func (s *fakeStore) object(key string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	object, ok := s.objects[key]
	return object.payload, ok
}

func fakeETag(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:16])
}

func (s *fakeStore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<26))
	if err != nil {
		writeFakeError(w, http.StatusBadRequest, "InvalidRequest", "unreadable body")
		return
	}
	if err := verifyFakeSignature(r, body, fakeSecretAccessKey, fakeRegion, s.sessions); err != nil {
		s.t.Logf("fake store rejected a signature: %v", err)
		writeFakeError(w, http.StatusForbidden, "SignatureDoesNotMatch", err.Error())
		return
	}
	operation := s.classify(r)
	s.mu.Lock()
	s.calls[operation]++
	hook := s.hook
	s.mu.Unlock()
	if hook != nil && hook(w, r, body) {
		return
	}
	prefix := "/" + fakeBucket + "/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		writeFakeError(w, http.StatusNotFound, "NoSuchBucket", "unknown bucket")
		return
	}
	key := strings.TrimPrefix(r.URL.Path, prefix)
	query := r.URL.Query()
	switch {
	case r.Method == http.MethodPost && query.Has("uploads"):
		s.createMultipart(w, r, key)
	case r.Method == http.MethodPut && query.Has("uploadId"):
		s.uploadPart(w, r, key, query.Get("uploadId"), query.Get("partNumber"), body)
	case r.Method == http.MethodPost && query.Has("uploadId"):
		s.completeMultipart(w, r, key, query.Get("uploadId"), body)
	case r.Method == http.MethodDelete && query.Has("uploadId"):
		s.abortMultipart(w, key, query.Get("uploadId"))
	case r.Method == http.MethodPut:
		s.put(w, r, key, body)
	case r.Method == http.MethodGet:
		s.get(w, r, key)
	case r.Method == http.MethodHead:
		s.head(w, key)
	case r.Method == http.MethodDelete:
		s.delete(w, key)
	default:
		writeFakeError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", r.Method)
	}
}

func (s *fakeStore) classify(r *http.Request) string {
	query := r.URL.Query()
	switch {
	case r.Method == http.MethodPost && query.Has("uploads"):
		return "CreateMultipartUpload"
	case r.Method == http.MethodPut && query.Has("uploadId"):
		return "UploadPart"
	case r.Method == http.MethodPost && query.Has("uploadId"):
		return "CompleteMultipartUpload"
	case r.Method == http.MethodDelete && query.Has("uploadId"):
		return "AbortMultipartUpload"
	default:
		return r.Method
	}
}

func (s *fakeStore) put(w http.ResponseWriter, r *http.Request, key string, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Header.Get("If-None-Match") == "*" {
		if _, exists := s.objects[key]; exists {
			writeFakeError(w, http.StatusPreconditionFailed, "PreconditionFailed", "object already exists")
			return
		}
	}
	if supplied := r.Header.Get(headerChecksumCRC64); supplied != "" {
		if want := CRC64Base64(ChecksumCRC64NVME(body)); supplied != want {
			writeFakeError(w, http.StatusBadRequest, "BadDigest", "crc64nvme mismatch")
			return
		}
	}
	object := fakeObject{payload: body, etag: fakeETag(body)}
	s.objects[key] = object
	w.Header().Set("ETag", "\""+object.etag+"\"")
	if s.checksums {
		w.Header().Set(headerChecksumCRC64, CRC64Base64(ChecksumCRC64NVME(body)))
		w.Header().Set(headerChecksumType, checksumTypeFullObject)
	}
	w.WriteHeader(http.StatusOK)
}

func (s *fakeStore) createMultipart(w http.ResponseWriter, r *http.Request, key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fullObject := false
	if algorithm := r.Header.Get(headerChecksumAlgo); algorithm != "" {
		if algorithm != checksumAlgoCRC64NVME || r.Header.Get(headerChecksumType) != checksumTypeFullObject {
			writeFakeError(w, http.StatusBadRequest, "InvalidRequest", "unsupported checksum declaration")
			return
		}
		fullObject = true
	}
	s.nextUpload++
	// A deliberately awkward upload ID: it needs percent-encoding in the query
	// string, which is exactly where a signer and a wire encoder can disagree.
	uploadID := fmt.Sprintf("upload+%d/id==", s.nextUpload)
	s.uploads[uploadID] = &fakeUpload{key: key, fullObject: fullObject, parts: map[int]fakePart{}}
	writeFakeXML(w, http.StatusOK, fmt.Sprintf(
		"<InitiateMultipartUploadResult><Bucket>%s</Bucket><Key>%s</Key><UploadId>%s</UploadId></InitiateMultipartUploadResult>",
		fakeBucket, xmlEscape(key), xmlEscape(uploadID)))
}

func (s *fakeStore) uploadPart(w http.ResponseWriter, r *http.Request, key, uploadID, partNumber string, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	upload, ok := s.uploads[uploadID]
	if !ok || upload.key != key {
		writeFakeError(w, http.StatusNotFound, "NoSuchUpload", "unknown upload")
		return
	}
	number, err := strconv.Atoi(partNumber)
	if err != nil || number < MinPartNumber || number > MaxPartNumber {
		writeFakeError(w, http.StatusBadRequest, "InvalidPart", "bad part number")
		return
	}
	checksum := r.Header.Get(headerChecksumCRC64)
	if checksum != "" {
		if want := CRC64Base64(ChecksumCRC64NVME(body)); checksum != want {
			writeFakeError(w, http.StatusBadRequest, "BadDigest", "part crc64nvme mismatch")
			return
		}
	}
	part := fakePart{payload: body, etag: fakeETag(body), checksum: checksum}
	upload.parts[number] = part
	w.Header().Set("ETag", "\""+part.etag+"\"")
	if s.checksums && checksum != "" {
		w.Header().Set(headerChecksumCRC64, checksum)
	}
	w.WriteHeader(http.StatusOK)
}

type fakeCompleteRequest struct {
	XMLName xml.Name `xml:"CompleteMultipartUpload"`
	Parts   []struct {
		PartNumber        int    `xml:"PartNumber"`
		ETag              string `xml:"ETag"`
		ChecksumCRC64NVME string `xml:"ChecksumCRC64NVME"`
	} `xml:"Part"`
}

func (s *fakeStore) completeMultipart(w http.ResponseWriter, r *http.Request, key, uploadID string, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	upload, ok := s.uploads[uploadID]
	if !ok || upload.key != key {
		writeFakeError(w, http.StatusNotFound, "NoSuchUpload", "unknown upload")
		return
	}
	upload.completeBody = append(upload.completeBody, append([]byte(nil), body...))
	var document fakeCompleteRequest
	if err := xml.Unmarshal(body, &document); err != nil || len(document.Parts) == 0 {
		writeFakeError(w, http.StatusBadRequest, "MalformedXML", "bad completion body")
		return
	}
	var assembled []byte
	previous := 0
	for _, part := range document.Parts {
		stored, ok := upload.parts[part.PartNumber]
		if !ok || part.PartNumber <= previous {
			writeFakeError(w, http.StatusBadRequest, "InvalidPart", "unknown or misordered part")
			return
		}
		if strings.Trim(part.ETag, "\"") != stored.etag {
			writeFakeError(w, http.StatusBadRequest, "InvalidPart", "etag mismatch")
			return
		}
		if part.ChecksumCRC64NVME != "" && part.ChecksumCRC64NVME != stored.checksum {
			writeFakeError(w, http.StatusBadRequest, "InvalidPart", "part checksum mismatch")
			return
		}
		previous = part.PartNumber
		assembled = append(assembled, stored.payload...)
	}
	object := fakeObject{payload: assembled, etag: fakeETag(assembled) + "-" + strconv.Itoa(len(document.Parts))}
	s.objects[key] = object
	delete(s.uploads, uploadID)
	checksumElement := ""
	if s.checksums && upload.fullObject {
		checksumElement = fmt.Sprintf("<ChecksumCRC64NVME>%s</ChecksumCRC64NVME><ChecksumType>%s</ChecksumType>",
			CRC64Base64(ChecksumCRC64NVME(assembled)), checksumTypeFullObject)
	}
	writeFakeXML(w, http.StatusOK, fmt.Sprintf(
		"<CompleteMultipartUploadResult><Bucket>%s</Bucket><Key>%s</Key><ETag>&quot;%s&quot;</ETag>%s</CompleteMultipartUploadResult>",
		fakeBucket, xmlEscape(key), object.etag, checksumElement))
}

func (s *fakeStore) abortMultipart(w http.ResponseWriter, key, uploadID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	upload, ok := s.uploads[uploadID]
	if !ok || upload.key != key {
		writeFakeError(w, http.StatusNotFound, "NoSuchUpload", "unknown upload")
		return
	}
	delete(s.uploads, uploadID)
	w.WriteHeader(http.StatusNoContent)
}

func (s *fakeStore) get(w http.ResponseWriter, r *http.Request, key string) {
	s.mu.Lock()
	object, ok := s.objects[key]
	checksums := s.checksums
	s.mu.Unlock()
	if !ok {
		writeFakeError(w, http.StatusNotFound, "NoSuchKey", "unknown key")
		return
	}
	if checksums {
		w.Header().Set(headerChecksumCRC64, CRC64Base64(ChecksumCRC64NVME(object.payload)))
		w.Header().Set(headerChecksumType, checksumTypeFullObject)
	}
	w.Header().Set("ETag", "\""+object.etag+"\"")
	rangeHeader := r.Header.Get("Range")
	if rangeHeader == "" {
		w.Header().Set("Content-Length", strconv.Itoa(len(object.payload)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(object.payload)
		return
	}
	first, last, err := parseFakeRange(rangeHeader, int64(len(object.payload)))
	if err != nil {
		writeFakeError(w, http.StatusRequestedRangeNotSatisfiable, "InvalidRange", err.Error())
		return
	}
	slice := object.payload[first : last+1]
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", first, last, len(object.payload)))
	w.Header().Set("Content-Length", strconv.Itoa(len(slice)))
	w.WriteHeader(http.StatusPartialContent)
	_, _ = w.Write(slice)
}

func parseFakeRange(value string, size int64) (int64, int64, error) {
	span, ok := strings.CutPrefix(value, "bytes=")
	if !ok || strings.Contains(span, ",") {
		return 0, 0, fmt.Errorf("unsupported range %q", value)
	}
	firstText, lastText, ok := strings.Cut(span, "-")
	if !ok {
		return 0, 0, fmt.Errorf("unsupported range %q", value)
	}
	first, err := strconv.ParseInt(firstText, 10, 64)
	if err != nil {
		return 0, 0, err
	}
	last, err := strconv.ParseInt(lastText, 10, 64)
	if err != nil {
		return 0, 0, err
	}
	if first < 0 || first > last || first >= size {
		return 0, 0, fmt.Errorf("range %q outside object", value)
	}
	if last >= size {
		last = size - 1
	}
	return first, last, nil
}

func (s *fakeStore) head(w http.ResponseWriter, key string) {
	s.mu.Lock()
	object, ok := s.objects[key]
	checksums := s.checksums
	s.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if checksums {
		w.Header().Set(headerChecksumCRC64, CRC64Base64(ChecksumCRC64NVME(object.payload)))
		w.Header().Set(headerChecksumType, checksumTypeFullObject)
	}
	w.Header().Set("ETag", "\""+object.etag+"\"")
	w.Header().Set("Content-Length", strconv.Itoa(len(object.payload)))
	w.WriteHeader(http.StatusOK)
}

func (s *fakeStore) delete(w http.ResponseWriter, key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.objects[key]; !ok {
		writeFakeError(w, http.StatusNotFound, "NoSuchKey", "unknown key")
		return
	}
	delete(s.objects, key)
	w.WriteHeader(http.StatusNoContent)
}

func writeFakeError(w http.ResponseWriter, status int, code, message string) {
	body := fmt.Sprintf("<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>%s</Code><Message>%s</Message><RequestId>fake-request</RequestId></Error>",
		xmlEscape(code), xmlEscape(message))
	w.Header().Set("Content-Type", contentTypeXML)
	w.Header().Set("x-amz-request-id", "fake-request")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func writeFakeXML(w http.ResponseWriter, status int, body string) {
	document := "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + body
	w.Header().Set("Content-Type", contentTypeXML)
	w.Header().Set("Content-Length", strconv.Itoa(len(document)))
	w.WriteHeader(status)
	_, _ = io.WriteString(w, document)
}

func xmlEscape(value string) string {
	var buffer bytes.Buffer
	_ = xml.EscapeText(&buffer, []byte(value))
	return buffer.String()
}

// ---------------------------------------------------------------------------
// Independent server-side SigV4 verification.
// ---------------------------------------------------------------------------

func verifyFakeSignature(r *http.Request, body []byte, secret, region, sessionToken string) error {
	authorization := r.Header.Get("Authorization")
	algorithm, rest, ok := strings.Cut(authorization, " ")
	if !ok || algorithm != "AWS4-HMAC-SHA256" {
		return fmt.Errorf("missing or unknown authorization algorithm %q", algorithm)
	}
	fields := map[string]string{}
	for _, field := range strings.Split(rest, ",") {
		name, value, ok := strings.Cut(strings.TrimSpace(field), "=")
		if !ok {
			return fmt.Errorf("malformed authorization field %q", field)
		}
		fields[name] = value
	}
	credential, signedHeaders, signature := fields["Credential"], fields["SignedHeaders"], fields["Signature"]
	if credential == "" || signedHeaders == "" || signature == "" {
		return fmt.Errorf("incomplete authorization header %q", authorization)
	}
	credentialParts := strings.Split(credential, "/")
	if len(credentialParts) != 5 {
		return fmt.Errorf("malformed credential %q", credential)
	}
	keyID, dateStamp, credentialRegion, service, terminator := credentialParts[0], credentialParts[1],
		credentialParts[2], credentialParts[3], credentialParts[4]
	if keyID != fakeAccessKeyID || credentialRegion != region || service != "s3" || terminator != "aws4_request" {
		return fmt.Errorf("unexpected credential scope %q", credential)
	}
	if sessionToken != "" && r.Header.Get("X-Amz-Security-Token") != sessionToken {
		return fmt.Errorf("missing or wrong session token")
	}

	payloadHash := r.Header.Get("X-Amz-Content-Sha256")
	actual := sha256.Sum256(body)
	if payloadHash != hex.EncodeToString(actual[:]) {
		return fmt.Errorf("x-amz-content-sha256 %q does not describe the %d-byte body", payloadHash, len(body))
	}

	// Canonicalize from the raw request target the server actually received,
	// not from a net/url round trip.
	rawTarget := r.RequestURI
	rawPath, rawQuery, _ := strings.Cut(rawTarget, "?")
	canonicalQuery, err := fakeCanonicalQuery(rawQuery)
	if err != nil {
		return err
	}

	names := strings.Split(signedHeaders, ";")
	for i := 1; i < len(names); i++ {
		if names[i-1] >= names[i] {
			return fmt.Errorf("signed headers are not sorted: %q", signedHeaders)
		}
	}
	var canonicalHeaders strings.Builder
	for _, name := range names {
		var values []string
		if name == "host" {
			values = []string{r.Host}
		} else {
			values = r.Header.Values(http.CanonicalHeaderKey(name))
			if len(values) == 0 {
				return fmt.Errorf("signed header %q is absent from the request", name)
			}
		}
		collapsed := make([]string, 0, len(values))
		for _, value := range values {
			collapsed = append(collapsed, fakeCollapse(value))
		}
		canonicalHeaders.WriteString(name + ":" + strings.Join(collapsed, ",") + "\n")
	}

	canonicalRequest := strings.Join([]string{
		r.Method, rawPath, canonicalQuery, canonicalHeaders.String(), signedHeaders, payloadHash,
	}, "\n")
	hashedRequest := sha256.Sum256([]byte(canonicalRequest))
	scope := strings.Join([]string{dateStamp, region, "s3", "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", r.Header.Get("X-Amz-Date"), scope, hex.EncodeToString(hashedRequest[:]),
	}, "\n")

	key := fakeMAC([]byte("AWS4"+secret), dateStamp)
	key = fakeMAC(key, region)
	key = fakeMAC(key, "s3")
	key = fakeMAC(key, "aws4_request")
	expected := hex.EncodeToString(fakeMAC(key, stringToSign))
	if !hmac.Equal([]byte(expected), []byte(signature)) {
		return fmt.Errorf("signature mismatch\ncanonical request:\n%s\nstring to sign:\n%s", canonicalRequest, stringToSign)
	}
	return nil
}

func fakeMAC(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

func fakeCanonicalQuery(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	pairs := strings.Split(raw, "&")
	encoded := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		name, value, _ := strings.Cut(pair, "=")
		decodedName, err := fakePercentDecode(name)
		if err != nil {
			return "", err
		}
		decodedValue, err := fakePercentDecode(value)
		if err != nil {
			return "", err
		}
		encoded = append(encoded, fakeURIEncode(decodedName)+"="+fakeURIEncode(decodedValue))
	}
	sort.Strings(encoded)
	return strings.Join(encoded, "&"), nil
}

func fakePercentDecode(value string) (string, error) {
	out := make([]byte, 0, len(value))
	for i := 0; i < len(value); i++ {
		if value[i] != '%' {
			out = append(out, value[i])
			continue
		}
		if i+2 >= len(value) {
			return "", fmt.Errorf("truncated escape in %q", value)
		}
		decoded, err := strconv.ParseUint(value[i+1:i+3], 16, 8)
		if err != nil {
			return "", fmt.Errorf("bad escape in %q", value)
		}
		out = append(out, byte(decoded))
		i += 2
	}
	return string(out), nil
}

func fakeURIEncode(value string) string {
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
	out := make([]byte, 0, len(value))
	for i := 0; i < len(value); i++ {
		if strings.IndexByte(unreserved, value[i]) >= 0 {
			out = append(out, value[i])
			continue
		}
		out = append(out, []byte(fmt.Sprintf("%%%02X", value[i]))...)
	}
	return string(out)
}

func fakeCollapse(value string) string {
	fields := strings.FieldsFunc(strings.TrimSpace(value), func(r rune) bool { return r == ' ' || r == '\t' })
	return strings.Join(fields, " ")
}

// base64Padded is a tiny guard that the fake and the package agree on the
// checksum wire form; it exists so a change to either encoder is caught here.
func base64Padded(value uint64) string {
	var digest [8]byte
	for i := 7; i >= 0; i-- {
		digest[i] = byte(value)
		value >>= 8
	}
	return base64.StdEncoding.EncodeToString(digest[:])
}
