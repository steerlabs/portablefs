package archivestore

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

const (
	// MinPartNumber and MaxPartNumber are the S3 multipart part-number bounds.
	MinPartNumber = 1
	MaxPartNumber = 10000
	// MaxSingleObjectBytes is the S3 single-PUT ceiling (5 GiB). Archive
	// manifests are bounded at 2 GiB by pack-format.md, well inside it.
	MaxSingleObjectBytes = 5 << 30
	// MaxPartBytes is the S3 part ceiling (5 GiB); packs use 8..64 MiB parts.
	MaxPartBytes = 5 << 30

	contentTypeOctetStream = "application/octet-stream"
	contentTypeXML         = "application/xml"
	headerChecksumCRC64    = "x-amz-checksum-crc64nvme"
	headerChecksumAlgo     = "x-amz-checksum-algorithm"
	headerChecksumType     = "x-amz-checksum-type"
	checksumAlgoCRC64NVME  = "CRC64NVME"
	checksumTypeFullObject = "FULL_OBJECT"
)

// PutOptions controls a single-shot PutObject.
type PutOptions struct {
	// IfNoneMatch sends If-None-Match: "*", turning the write into a
	// conditional create. A lost race returns ErrPreconditionFailed. The
	// attempt discipline (attempt UUIDs are never reused) is the primary
	// defense against a stale writer; this is the second line.
	IfNoneMatch bool
	// ChecksumCRC64NVMEHex is the object's full-object CRC-64/NVME in the
	// 16-character lowercase hex form. Sent only when the store declared the
	// crc64nvme-full-object capability; supplying it against a "none" store is
	// an error rather than a silent drop.
	ChecksumCRC64NVMEHex string
	// ContentType overrides application/octet-stream.
	ContentType string
}

// PutResult reports what the store recorded for a completed single-shot write.
type PutResult struct {
	ETag string
	// ChecksumCRC64NVMEHex is the store's echoed checksum, empty when the
	// store returned none.
	ChecksumCRC64NVMEHex string
}

// PutObject writes one complete object.
func (c *Client) PutObject(ctx context.Context, key string, body []byte, options PutOptions) (PutResult, error) {
	if int64(len(body)) > MaxSingleObjectBytes {
		return PutResult{}, fmt.Errorf("%w: single-shot object exceeds %d bytes", ErrInvalid, int64(MaxSingleObjectBytes))
	}
	header := http.Header{}
	contentType := options.ContentType
	if contentType == "" {
		contentType = contentTypeOctetStream
	}
	header.Set("Content-Type", contentType)
	if options.IfNoneMatch {
		header.Set("If-None-Match", "*")
	}
	if err := c.setChecksumHeader(header, options.ChecksumCRC64NVMEHex); err != nil {
		return PutResult{}, err
	}
	result := PutResult{}
	request := storeRequest{op: "PutObject", method: http.MethodPut, key: key, header: header, body: PartBodyFromBytes(body)}
	err := c.roundTrip(ctx, request, func(response *http.Response) error {
		defer closeAndDrain(response.Body)
		payload, err := readBounded(response.Body, maxErrorBodyBytes)
		if err != nil {
			return err
		}
		// A successful PUT has an empty body. Anything that parses as an
		// <Error> is the 200-with-error quirk and is a failure, not a write.
		if quirk := c.errorBodyIn(request, payload); quirk != nil {
			return quirk
		}
		result.ETag = normalizeETag(response.Header.Get("ETag"))
		checksum, err := checksumHeaderHex(response.Header)
		if err != nil {
			return &Error{Op: request.op, Key: key, StatusCode: response.StatusCode, Kind: KindResponse, cause: err}
		}
		result.ChecksumCRC64NVMEHex = checksum
		return nil
	})
	if err != nil {
		return PutResult{}, err
	}
	return result, nil
}

// CreateMultipartOptions controls CreateMultipartUpload.
type CreateMultipartOptions struct {
	// FullObjectChecksum declares CRC64NVME in FULL_OBJECT mode, so the sealed
	// object's HeadObject returns a checksum comparable with the archiver's own
	// (identity-lifecycle §2). Ignored when the store's capability is "none".
	FullObjectChecksum bool
	ContentType        string
}

type initiateMultipartUploadResult struct {
	XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	UploadID string   `xml:"UploadId"`
}

// CreateMultipartUpload starts a multipart upload and returns its upload ID.
func (c *Client) CreateMultipartUpload(ctx context.Context, key string, options CreateMultipartOptions) (string, error) {
	header := http.Header{}
	contentType := options.ContentType
	if contentType == "" {
		contentType = contentTypeOctetStream
	}
	header.Set("Content-Type", contentType)
	if options.FullObjectChecksum {
		if !c.ChecksumsEnabled() {
			return "", fmt.Errorf("%w: full-object checksums requested against a store declared %q", ErrInvalid, ChecksumNone)
		}
		header.Set(headerChecksumAlgo, checksumAlgoCRC64NVME)
		header.Set(headerChecksumType, checksumTypeFullObject)
	}
	uploadID := ""
	request := storeRequest{
		op:     "CreateMultipartUpload",
		method: http.MethodPost,
		key:    key,
		query:  []queryParameter{{name: "uploads"}},
		header: header,
	}
	err := c.roundTrip(ctx, request, func(response *http.Response) error {
		payload, err := c.readSuccessBody(response)
		if err != nil {
			return err
		}
		if quirk := c.errorBodyIn(request, payload); quirk != nil {
			return quirk
		}
		var document initiateMultipartUploadResult
		if err := unmarshalRoot(payload, "InitiateMultipartUploadResult", &document); err != nil {
			return &Error{Op: request.op, Key: key, StatusCode: response.StatusCode, Kind: KindResponse, cause: err}
		}
		if err := validUploadID(document.UploadID); err != nil {
			return &Error{Op: request.op, Key: key, StatusCode: response.StatusCode, Kind: KindResponse, cause: err}
		}
		uploadID = document.UploadID
		return nil
	})
	if err != nil {
		return "", err
	}
	return uploadID, nil
}

// UploadedPart is one completed part, in the exact shape
// CompleteMultipartUpload requires.
type UploadedPart struct {
	Number int
	ETag   string
	// ChecksumCRC64NVMEHex is empty when the store carries no checksums.
	ChecksumCRC64NVMEHex string
}

// UploadPart uploads one part. body carries its own length and precomputed
// SHA-256, so a caller streaming a compressed-byte range from disk never
// buffers it here; checksumHex, when supplied, is the part's CRC-64/NVME in hex.
func (c *Client) UploadPart(ctx context.Context, key, uploadID string, partNumber int, body PartBody, checksumHex string) (UploadedPart, error) {
	if err := validUploadID(uploadID); err != nil {
		return UploadedPart{}, err
	}
	if partNumber < MinPartNumber || partNumber > MaxPartNumber {
		return UploadedPart{}, fmt.Errorf("%w: part number must be within %d..%d", ErrInvalid, MinPartNumber, MaxPartNumber)
	}
	if body.open == nil || body.length <= 0 || body.length > MaxPartBytes {
		return UploadedPart{}, fmt.Errorf("%w: part body must be 1..%d bytes with an opener", ErrInvalid, int64(MaxPartBytes))
	}
	header := http.Header{}
	if err := c.setChecksumHeader(header, checksumHex); err != nil {
		return UploadedPart{}, err
	}
	part := UploadedPart{Number: partNumber}
	request := storeRequest{
		op:     "UploadPart",
		method: http.MethodPut,
		key:    key,
		query:  []queryParameter{{name: "partNumber", value: strconv.Itoa(partNumber)}, {name: "uploadId", value: uploadID}},
		header: header,
		body:   body,
	}
	err := c.roundTrip(ctx, request, func(response *http.Response) error {
		defer closeAndDrain(response.Body)
		payload, err := readBounded(response.Body, maxErrorBodyBytes)
		if err != nil {
			return err
		}
		if quirk := c.errorBodyIn(request, payload); quirk != nil {
			return quirk
		}
		etag := normalizeETag(response.Header.Get("ETag"))
		if err := validETag(etag); err != nil {
			return &Error{Op: request.op, Key: key, StatusCode: response.StatusCode, Kind: KindResponse, cause: err}
		}
		checksum, err := checksumHeaderHex(response.Header)
		if err != nil {
			return &Error{Op: request.op, Key: key, StatusCode: response.StatusCode, Kind: KindResponse, cause: err}
		}
		part.ETag = etag
		part.ChecksumCRC64NVMEHex = checksum
		return nil
	})
	if err != nil {
		return UploadedPart{}, err
	}
	return part, nil
}

type completeMultipartUploadRequest struct {
	XMLName xml.Name        `xml:"CompleteMultipartUpload"`
	XMLNS   string          `xml:"xmlns,attr"`
	Parts   []completedPart `xml:"Part"`
}

type completedPart struct {
	XMLName           xml.Name `xml:"Part"`
	PartNumber        int      `xml:"PartNumber"`
	ETag              string   `xml:"ETag"`
	ChecksumCRC64NVME string   `xml:"ChecksumCRC64NVME,omitempty"`
}

type completeMultipartUploadResult struct {
	XMLName           xml.Name `xml:"CompleteMultipartUploadResult"`
	Bucket            string   `xml:"Bucket"`
	Key               string   `xml:"Key"`
	ETag              string   `xml:"ETag"`
	ChecksumCRC64NVME string   `xml:"ChecksumCRC64NVME"`
	ChecksumType      string   `xml:"ChecksumType"`
}

// CompleteResult reports the sealed object's identity.
type CompleteResult struct {
	ETag string
	// ChecksumCRC64NVMEHex is the full-object checksum the store computed,
	// empty when the store returned none.
	ChecksumCRC64NVMEHex string
}

// CompleteMultipartUpload seals a multipart upload.
//
// Retrying it is safe and is therefore allowed: S3 defines completion with an
// identical parts list as idempotent. The parts list is rebuilt byte-identically
// on every attempt, so a retry can never seal a different object than the
// attempt it repeats. This is the only non-GET operation with a body that is
// retried, and it is retried for exactly that reason.
//
// A 200 response carrying an <Error> document is treated as a failure. S3 may
// stream a success status before it knows the outcome, and accepting it would
// report a seal that never happened.
func (c *Client) CompleteMultipartUpload(ctx context.Context, key, uploadID string, parts []UploadedPart) (CompleteResult, error) {
	if err := validUploadID(uploadID); err != nil {
		return CompleteResult{}, err
	}
	if len(parts) == 0 || len(parts) > MaxPartNumber {
		return CompleteResult{}, fmt.Errorf("%w: completion needs 1..%d parts", ErrInvalid, MaxPartNumber)
	}
	document := completeMultipartUploadRequest{XMLNS: "http://s3.amazonaws.com/doc/2006-03-01/"}
	previous := 0
	for _, part := range parts {
		if part.Number < MinPartNumber || part.Number > MaxPartNumber || part.Number <= previous {
			return CompleteResult{}, fmt.Errorf("%w: part numbers must be strictly ascending within %d..%d", ErrInvalid, MinPartNumber, MaxPartNumber)
		}
		previous = part.Number
		etag := normalizeETag(part.ETag)
		if err := validETag(etag); err != nil {
			return CompleteResult{}, err
		}
		encoded := completedPart{PartNumber: part.Number, ETag: "\"" + etag + "\""}
		if part.ChecksumCRC64NVMEHex != "" {
			if !c.ChecksumsEnabled() {
				return CompleteResult{}, fmt.Errorf("%w: part checksum supplied against a store declared %q", ErrInvalid, ChecksumNone)
			}
			base64Checksum, err := CRC64HexToBase64(part.ChecksumCRC64NVMEHex)
			if err != nil {
				return CompleteResult{}, err
			}
			encoded.ChecksumCRC64NVME = base64Checksum
		}
		document.Parts = append(document.Parts, encoded)
	}
	payload, err := xml.Marshal(document)
	if err != nil {
		return CompleteResult{}, fmt.Errorf("%w: completion body could not be encoded: %w", ErrInvalid, err)
	}
	header := http.Header{}
	header.Set("Content-Type", contentTypeXML)

	result := CompleteResult{}
	request := storeRequest{
		op:     "CompleteMultipartUpload",
		method: http.MethodPost,
		key:    key,
		query:  []queryParameter{{name: "uploadId", value: uploadID}},
		header: header,
		body:   PartBodyFromBytes(payload),
	}
	err = c.roundTrip(ctx, request, func(response *http.Response) error {
		body, err := c.readSuccessBody(response)
		if err != nil {
			return err
		}
		if quirk := c.errorBodyIn(request, body); quirk != nil {
			return quirk
		}
		var document completeMultipartUploadResult
		if err := unmarshalRoot(body, "CompleteMultipartUploadResult", &document); err != nil {
			return &Error{Op: request.op, Key: key, StatusCode: response.StatusCode, Kind: KindResponse, cause: err}
		}
		etag := normalizeETag(document.ETag)
		if err := validETag(etag); err != nil {
			return &Error{Op: request.op, Key: key, StatusCode: response.StatusCode, Kind: KindResponse, cause: err}
		}
		result.ETag = etag
		if document.ChecksumCRC64NVME != "" {
			if document.ChecksumType != "" && document.ChecksumType != checksumTypeFullObject {
				return &Error{Op: request.op, Key: key, StatusCode: response.StatusCode, Kind: KindResponse, cause: errCompositeChecksum}
			}
			checksum, err := CRC64Base64ToHex(document.ChecksumCRC64NVME)
			if err != nil {
				return &Error{Op: request.op, Key: key, StatusCode: response.StatusCode, Kind: KindResponse, cause: err}
			}
			result.ChecksumCRC64NVMEHex = checksum
		}
		return nil
	})
	if err != nil {
		return CompleteResult{}, err
	}
	return result, nil
}

// AbortMultipartUpload discards an in-flight multipart upload. A missing upload
// is success: abort exists to leave no partial upload behind, and an upload the
// store has already forgotten satisfies that.
func (c *Client) AbortMultipartUpload(ctx context.Context, key, uploadID string) error {
	if err := validUploadID(uploadID); err != nil {
		return err
	}
	request := storeRequest{
		op:     "AbortMultipartUpload",
		method: http.MethodDelete,
		key:    key,
		query:  []queryParameter{{name: "uploadId", value: uploadID}},
	}
	err := c.roundTrip(ctx, request, func(response *http.Response) error {
		closeAndDrain(response.Body)
		return nil
	})
	if isNotFound(err) {
		return nil
	}
	return err
}

// ObjectInfo is what HeadObject proves about a sealed object without
// downloading it.
type ObjectInfo struct {
	Size int64
	// CRC64NVMEHex is the store's full-object checksum in hex, empty when the
	// store carries none. A composite (multipart, "-N" suffixed) checksum is
	// refused rather than returned.
	CRC64NVMEHex string
	ETag         string
}

// HeadObject returns an object's size, checksum, and ETag.
func (c *Client) HeadObject(ctx context.Context, key string) (ObjectInfo, error) {
	info := ObjectInfo{}
	request := storeRequest{op: "HeadObject", method: http.MethodHead, key: key}
	err := c.roundTrip(ctx, request, func(response *http.Response) error {
		closeAndDrain(response.Body)
		if response.ContentLength < 0 {
			return &Error{Op: request.op, Key: key, StatusCode: response.StatusCode, Kind: KindResponse,
				cause: fmt.Errorf("%w: HeadObject returned no Content-Length", ErrResponse)}
		}
		checksum, err := checksumHeaderHex(response.Header)
		if err != nil {
			return &Error{Op: request.op, Key: key, StatusCode: response.StatusCode, Kind: KindResponse, cause: err}
		}
		info = ObjectInfo{Size: response.ContentLength, CRC64NVMEHex: checksum, ETag: normalizeETag(response.Header.Get("ETag"))}
		return nil
	})
	if err != nil {
		return ObjectInfo{}, err
	}
	return info, nil
}

// GetObject fetches a whole object into memory, refusing anything larger than
// maxBytes. Content-Length is checked before a byte is read and the reader is
// bounded regardless, so a lying header cannot exhaust memory. It is for
// manifests and other bounded control objects; pack content uses
// GetObjectRange.
func (c *Client) GetObject(ctx context.Context, key string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("%w: maxBytes must be positive", ErrInvalid)
	}
	var payload []byte
	request := storeRequest{op: "GetObject", method: http.MethodGet, key: key}
	err := c.roundTrip(ctx, request, func(response *http.Response) error {
		defer closeAndDrain(response.Body)
		if response.StatusCode != http.StatusOK {
			return &Error{Op: request.op, Key: key, StatusCode: response.StatusCode, Kind: KindResponse,
				cause: fmt.Errorf("%w: expected 200 for a whole-object GET", ErrResponse)}
		}
		if response.ContentLength > maxBytes {
			return &Error{Op: request.op, Key: key, StatusCode: response.StatusCode, Kind: KindResponse,
				cause: fmt.Errorf("%w: object is %d bytes, limit is %d", ErrResponse, response.ContentLength, maxBytes)}
		}
		body, err := readBounded(response.Body, maxBytes)
		if err != nil {
			return &Error{Op: request.op, Key: key, StatusCode: response.StatusCode, Kind: KindResponse, cause: err}
		}
		if response.ContentLength >= 0 && int64(len(body)) != response.ContentLength {
			return &Error{Op: request.op, Key: key, StatusCode: response.StatusCode, Kind: KindResponse,
				cause: fmt.Errorf("%w: body is %d bytes, Content-Length said %d", ErrResponse, len(body), response.ContentLength)}
		}
		payload = body
		return nil
	})
	if err != nil {
		return nil, err
	}
	return payload, nil
}

// GetObjectRange fetches exactly one byte range and hands the caller a stream.
//
// Exactly one range per request, never a multi-range GET (pack-format.md "S3
// mechanics"): a multipart/byteranges response would be a different, unbounded
// parse. The returned reader yields exactly length bytes and errors if the
// store sends fewer or more, so a truncated pack range can never be mistaken
// for verified content. The caller must Close it; no client-side request
// timeout applies to the streaming phase, so the caller's context governs the
// stream's lifetime.
func (c *Client) GetObjectRange(ctx context.Context, key string, offset, length int64) (io.ReadCloser, error) {
	if offset < 0 || length <= 0 || offset > offset+length-1 {
		return nil, fmt.Errorf("%w: range offset must be non-negative and length positive without overflow", ErrInvalid)
	}
	header := http.Header{}
	header.Set("Range", fmt.Sprintf("bytes=%d-%d", offset, offset+length-1))
	var stream io.ReadCloser
	request := storeRequest{op: "GetObjectRange", method: http.MethodGet, key: key, header: header, stream: true}
	err := c.roundTrip(ctx, request, func(response *http.Response) error {
		fail := func(err error) error {
			closeAndDrain(response.Body)
			return &Error{Op: request.op, Key: key, StatusCode: response.StatusCode, Kind: KindResponse, cause: err}
		}
		if response.StatusCode != http.StatusPartialContent {
			// A 200 means the store ignored the Range header and is streaming
			// the whole object. Fail closed rather than silently re-slicing.
			return fail(fmt.Errorf("%w: expected 206 Partial Content, got %d", ErrResponse, response.StatusCode))
		}
		if response.ContentLength >= 0 && response.ContentLength != length {
			return fail(fmt.Errorf("%w: Content-Length is %d, requested %d", ErrResponse, response.ContentLength, length))
		}
		if contentRange := response.Header.Get("Content-Range"); contentRange != "" {
			if err := checkContentRange(contentRange, offset, length); err != nil {
				return fail(err)
			}
		}
		stream = &exactReader{body: response.Body, remaining: length}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return stream, nil
}

// DeleteObject removes an object. A missing object is success: deletion is
// idempotent and the manager's GC re-runs from a durable cursor.
func (c *Client) DeleteObject(ctx context.Context, key string) error {
	request := storeRequest{op: "DeleteObject", method: http.MethodDelete, key: key}
	err := c.roundTrip(ctx, request, func(response *http.Response) error {
		closeAndDrain(response.Body)
		return nil
	})
	if isNotFound(err) {
		return nil
	}
	return err
}

func isNotFound(err error) bool {
	var storeError *Error
	return err != nil && errors.As(err, &storeError) && storeError.Kind == KindNotFound
}

// exactReader enforces the promised length in both directions: a short stream
// fails at EOF, a long one fails on the extra byte.
type exactReader struct {
	body      io.ReadCloser
	remaining int64
	failed    bool
}

func (r *exactReader) Read(buffer []byte) (int, error) {
	if r.failed {
		return 0, fmt.Errorf("%w: ranged read already failed", ErrResponse)
	}
	if r.remaining == 0 {
		// Confirm the store is not sending more than the range promised.
		var probe [1]byte
		n, err := r.body.Read(probe[:])
		if n > 0 {
			r.failed = true
			return 0, fmt.Errorf("%w: ranged read returned more bytes than requested", ErrResponse)
		}
		if err == nil || err == io.EOF {
			return 0, io.EOF
		}
		return 0, err
	}
	if int64(len(buffer)) > r.remaining {
		buffer = buffer[:r.remaining]
	}
	n, err := r.body.Read(buffer)
	r.remaining -= int64(n)
	if err == io.EOF && r.remaining > 0 {
		r.failed = true
		return n, fmt.Errorf("%w: ranged read ended %d bytes early", ErrResponse, r.remaining)
	}
	return n, err
}

func (r *exactReader) Close() error {
	closeAndDrain(r.body)
	return nil
}

func checkContentRange(value string, offset, length int64) error {
	unit, rest, found := strings.Cut(strings.TrimSpace(value), " ")
	if !found || unit != "bytes" {
		return fmt.Errorf("%w: Content-Range %q is not a bytes range", ErrResponse, value)
	}
	span, _, _ := strings.Cut(rest, "/")
	first, last, found := strings.Cut(span, "-")
	if !found {
		return fmt.Errorf("%w: Content-Range %q has no range span", ErrResponse, value)
	}
	firstByte, firstErr := strconv.ParseInt(first, 10, 64)
	lastByte, lastErr := strconv.ParseInt(last, 10, 64)
	if firstErr != nil || lastErr != nil || firstByte != offset || lastByte != offset+length-1 {
		return fmt.Errorf("%w: Content-Range %q does not match the requested bytes=%d-%d", ErrResponse, value, offset, offset+length-1)
	}
	return nil
}

// readSuccessBody reads a bounded XML success body and closes the response.
func (c *Client) readSuccessBody(response *http.Response) ([]byte, error) {
	defer closeAndDrain(response.Body)
	return readBounded(response.Body, maxXMLBodyBytes)
}

// unmarshalRoot decodes payload, requiring the document's root element to be
// exactly name. Matching by local name only keeps the parse namespace tolerant
// (S3 and MinIO differ), while still refusing a document of another shape.
func unmarshalRoot(payload []byte, name string, target any) error {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 {
		return fmt.Errorf("%w: empty response body", ErrResponse)
	}
	decoder := xml.NewDecoder(bytes.NewReader(trimmed))
	for {
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("%w: response body is not XML", ErrResponse)
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		if start.Name.Local != name {
			return fmt.Errorf("%w: response root is %q, expected %q", ErrResponse, start.Name.Local, name)
		}
		if err := decoder.DecodeElement(target, &start); err != nil {
			return fmt.Errorf("%w: response body does not match %s", ErrResponse, name)
		}
		return nil
	}
}

func (c *Client) setChecksumHeader(header http.Header, checksumHex string) error {
	if checksumHex == "" {
		return nil
	}
	if !c.ChecksumsEnabled() {
		return fmt.Errorf("%w: a checksum was supplied against a store declared %q", ErrInvalid, ChecksumNone)
	}
	value, err := CRC64HexToBase64(checksumHex)
	if err != nil {
		return err
	}
	header.Set(headerChecksumCRC64, value)
	return nil
}

// checksumHeaderHex reads x-amz-checksum-crc64nvme. A composite multipart
// checksum ("<base64>-<count>") is refused: the archive contract compares
// full-object checksums, and a composite value is not comparable with one.
func checksumHeaderHex(header http.Header) (string, error) {
	value := strings.TrimSpace(header.Get(headerChecksumCRC64))
	if value == "" {
		return "", nil
	}
	if index := strings.LastIndexByte(value, '-'); index >= 0 {
		if _, err := strconv.Atoi(value[index+1:]); err == nil {
			return "", errCompositeChecksum
		}
	}
	if checksumType := header.Get(headerChecksumType); checksumType != "" && checksumType != checksumTypeFullObject {
		return "", errCompositeChecksum
	}
	return CRC64Base64ToHex(value)
}

func normalizeETag(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "W/")
	return strings.Trim(value, "\"")
}

func validETag(value string) error {
	if value == "" || len(value) > 128 {
		return fmt.Errorf("%w: ETag must be 1..128 characters", ErrResponse)
	}
	for i := 0; i < len(value); i++ {
		if c := value[i]; c < 0x21 || c > 0x7e || c == '"' {
			return fmt.Errorf("%w: ETag has a disallowed character", ErrResponse)
		}
	}
	return nil
}

func validUploadID(value string) error {
	if value == "" || len(value) > 1024 {
		return fmt.Errorf("%w: upload ID must be 1..1024 characters", ErrInvalid)
	}
	for i := 0; i < len(value); i++ {
		if c := value[i]; c < 0x21 || c > 0x7e {
			return fmt.Errorf("%w: upload ID has a disallowed character", ErrInvalid)
		}
	}
	return nil
}
