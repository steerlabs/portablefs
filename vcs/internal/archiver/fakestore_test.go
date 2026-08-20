package archiver

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/archivestore"
)

// A minimal in-memory S3-compatible store for the suites in this package.
//
// It deliberately does not verify signatures: archivestore has its own fake
// that does, written independently of its signer, and duplicating that here
// would test archivestore rather than the archiver. What this fake does check is
// everything the archiver depends on being true — conditional create,
// multipart part ordering and ETags, full-object checksums, exact ranged reads
// — so a change in how the archiver uploads or reads back fails here.

const (
	testBucket = "portablefs-archive"
	testPrefix = "archives"
)

type fakeUpload struct {
	key        string
	fullObject bool
	parts      map[int][]byte
	checksums  map[int]string
}

type fakeStore struct {
	mutex      sync.Mutex
	objects    map[string][]byte
	uploads    map[string]*fakeUpload
	nextUpload int
	calls      map[string]int
	// partSizes records the byte length of every part of a completed upload,
	// in order, so a test can prove part boundaries land on frame boundaries.
	partSizes map[string][]uint64

	// corrupt, when set, flips a byte of every body this store returns for the
	// given key. It models storage that lost integrity after the write, which
	// is exactly what read-back verification exists to catch.
	corrupt map[string]bool
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		objects:   map[string][]byte{},
		uploads:   map[string]*fakeUpload{},
		calls:     map[string]int{},
		partSizes: map[string][]uint64{},
		corrupt:   map[string]bool{},
	}
}

func (s *fakeStore) object(key string) ([]byte, bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	payload, ok := s.objects[key]
	return payload, ok
}

func (s *fakeStore) put(key string, payload []byte) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.objects[key] = payload
}

func (s *fakeStore) corruptKey(key string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.corrupt[key] = true
}

// flip damages one byte of a stored object in place: storage that accepted the
// write and lost integrity afterwards, which is the failure both the read-back
// pass and the serve path exist to catch.
func (s *fakeStore) flip(key string, offset uint64) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	payload, ok := s.objects[key]
	if !ok || offset >= uint64(len(payload)) {
		return false
	}
	damaged := append([]byte(nil), payload...)
	damaged[offset] ^= 0xff
	s.objects[key] = damaged
	return true
}

// forget removes an object without a trace: a store that is reachable but
// cannot answer, which is the blocked class rather than the corrupt one.
func (s *fakeStore) forget(key string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.objects, key)
}

func (s *fakeStore) callCount(operation string) int {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.calls[operation]
}

func (s *fakeStore) record(operation string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.calls[operation]++
}

func (s *fakeStore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<26))
	if err != nil {
		writeStoreError(w, http.StatusBadRequest, "InvalidRequest", "unreadable body")
		return
	}
	prefix := "/" + testBucket + "/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		writeStoreError(w, http.StatusNotFound, "NoSuchBucket", "unknown bucket")
		return
	}
	key := strings.TrimPrefix(r.URL.Path, prefix)
	query := r.URL.Query()
	switch {
	case r.Method == http.MethodPost && query.Has("uploads"):
		s.record("CreateMultipartUpload")
		s.createMultipart(w, r, key)
	case r.Method == http.MethodPut && query.Has("uploadId"):
		s.record("UploadPart")
		s.uploadPart(w, key, query.Get("uploadId"), query.Get("partNumber"), r.Header.Get("x-amz-checksum-crc64nvme"), body)
	case r.Method == http.MethodPost && query.Has("uploadId"):
		s.record("CompleteMultipartUpload")
		s.completeMultipart(w, key, query.Get("uploadId"), body)
	case r.Method == http.MethodDelete && query.Has("uploadId"):
		s.record("AbortMultipartUpload")
		s.abortMultipart(w, query.Get("uploadId"))
	case r.Method == http.MethodPut:
		s.record("PutObject")
		s.putObject(w, r, key, body)
	case r.Method == http.MethodGet:
		s.record("GetObject")
		s.getObject(w, r, key)
	case r.Method == http.MethodHead:
		s.record("HeadObject")
		s.headObject(w, key)
	case r.Method == http.MethodDelete:
		s.record("DeleteObject")
		s.deleteObject(w, key)
	default:
		writeStoreError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", r.Method)
	}
}

func (s *fakeStore) putObject(w http.ResponseWriter, r *http.Request, key string, body []byte) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if r.Header.Get("If-None-Match") == "*" {
		if _, exists := s.objects[key]; exists {
			writeStoreError(w, http.StatusPreconditionFailed, "PreconditionFailed", "object already exists")
			return
		}
	}
	if supplied := r.Header.Get("x-amz-checksum-crc64nvme"); supplied != "" {
		if want := archivestore.CRC64Base64(archivestore.ChecksumCRC64NVME(body)); supplied != want {
			writeStoreError(w, http.StatusBadRequest, "BadDigest", "crc64nvme mismatch")
			return
		}
	}
	s.objects[key] = body
	w.Header().Set("ETag", "\""+storeETag(body)+"\"")
	w.Header().Set("x-amz-checksum-crc64nvme", archivestore.CRC64Base64(archivestore.ChecksumCRC64NVME(body)))
	w.Header().Set("x-amz-checksum-type", "FULL_OBJECT")
	w.WriteHeader(http.StatusOK)
}

func (s *fakeStore) createMultipart(w http.ResponseWriter, r *http.Request, key string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	fullObject := false
	if algorithm := r.Header.Get("x-amz-checksum-algorithm"); algorithm != "" {
		if algorithm != "CRC64NVME" || r.Header.Get("x-amz-checksum-type") != "FULL_OBJECT" {
			writeStoreError(w, http.StatusBadRequest, "InvalidRequest", "unsupported checksum declaration")
			return
		}
		fullObject = true
	}
	s.nextUpload++
	uploadID := fmt.Sprintf("upload-%d", s.nextUpload)
	s.uploads[uploadID] = &fakeUpload{key: key, fullObject: fullObject, parts: map[int][]byte{}, checksums: map[int]string{}}
	writeStoreXML(w, fmt.Sprintf(
		"<InitiateMultipartUploadResult><Bucket>%s</Bucket><Key>%s</Key><UploadId>%s</UploadId></InitiateMultipartUploadResult>",
		testBucket, key, uploadID))
}

func (s *fakeStore) uploadPart(w http.ResponseWriter, key, uploadID, partNumber, checksum string, body []byte) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	upload, ok := s.uploads[uploadID]
	if !ok || upload.key != key {
		writeStoreError(w, http.StatusNotFound, "NoSuchUpload", "unknown upload")
		return
	}
	number, err := strconv.Atoi(partNumber)
	if err != nil || number < 1 || number > 10000 {
		writeStoreError(w, http.StatusBadRequest, "InvalidPart", "bad part number")
		return
	}
	if checksum != "" {
		if want := archivestore.CRC64Base64(archivestore.ChecksumCRC64NVME(body)); checksum != want {
			writeStoreError(w, http.StatusBadRequest, "BadDigest", "part crc64nvme mismatch")
			return
		}
	}
	upload.parts[number] = body
	upload.checksums[number] = checksum
	w.Header().Set("ETag", "\""+storeETag(body)+"\"")
	if checksum != "" {
		w.Header().Set("x-amz-checksum-crc64nvme", checksum)
	}
	w.WriteHeader(http.StatusOK)
}

type completionDocument struct {
	XMLName xml.Name `xml:"CompleteMultipartUpload"`
	Parts   []struct {
		PartNumber        int    `xml:"PartNumber"`
		ETag              string `xml:"ETag"`
		ChecksumCRC64NVME string `xml:"ChecksumCRC64NVME"`
	} `xml:"Part"`
}

func (s *fakeStore) completeMultipart(w http.ResponseWriter, key, uploadID string, body []byte) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	upload, ok := s.uploads[uploadID]
	if !ok || upload.key != key {
		writeStoreError(w, http.StatusNotFound, "NoSuchUpload", "unknown upload")
		return
	}
	var document completionDocument
	if err := xml.Unmarshal(body, &document); err != nil || len(document.Parts) == 0 {
		writeStoreError(w, http.StatusBadRequest, "MalformedXML", "bad completion body")
		return
	}
	var assembled []byte
	previous := 0
	for _, part := range document.Parts {
		stored, ok := upload.parts[part.PartNumber]
		if !ok || part.PartNumber <= previous {
			writeStoreError(w, http.StatusBadRequest, "InvalidPart", "unknown or misordered part")
			return
		}
		if strings.Trim(part.ETag, "\"") != storeETag(stored) {
			writeStoreError(w, http.StatusBadRequest, "InvalidPart", "etag mismatch")
			return
		}
		if part.ChecksumCRC64NVME != "" && part.ChecksumCRC64NVME != upload.checksums[part.PartNumber] {
			writeStoreError(w, http.StatusBadRequest, "InvalidPart", "part checksum mismatch")
			return
		}
		previous = part.PartNumber
		assembled = append(assembled, stored...)
	}
	s.objects[key] = assembled
	sizes := make([]uint64, 0, len(document.Parts))
	for _, part := range document.Parts {
		sizes = append(sizes, uint64(len(upload.parts[part.PartNumber])))
	}
	s.partSizes[key] = sizes
	delete(s.uploads, uploadID)
	checksum := ""
	if upload.fullObject {
		checksum = fmt.Sprintf("<ChecksumCRC64NVME>%s</ChecksumCRC64NVME><ChecksumType>FULL_OBJECT</ChecksumType>",
			archivestore.CRC64Base64(archivestore.ChecksumCRC64NVME(assembled)))
	}
	writeStoreXML(w, fmt.Sprintf(
		"<CompleteMultipartUploadResult><Bucket>%s</Bucket><Key>%s</Key><ETag>&quot;%s-%d&quot;</ETag>%s</CompleteMultipartUploadResult>",
		testBucket, key, storeETag(assembled), len(document.Parts), checksum))
}

func (s *fakeStore) parts(key string) []uint64 {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return append([]uint64(nil), s.partSizes[key]...)
}

func (s *fakeStore) abortMultipart(w http.ResponseWriter, uploadID string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.uploads, uploadID)
	w.WriteHeader(http.StatusNoContent)
}

func (s *fakeStore) getObject(w http.ResponseWriter, r *http.Request, key string) {
	s.mutex.Lock()
	payload, ok := s.objects[key]
	corrupt := s.corrupt[key]
	s.mutex.Unlock()
	if !ok {
		writeStoreError(w, http.StatusNotFound, "NoSuchKey", "unknown key")
		return
	}
	if corrupt {
		payload = append([]byte(nil), payload...)
		payload[len(payload)/2] ^= 0xff
	}
	w.Header().Set("ETag", "\""+storeETag(payload)+"\"")
	rangeHeader := r.Header.Get("Range")
	if rangeHeader == "" {
		w.Header().Set("x-amz-checksum-crc64nvme", archivestore.CRC64Base64(archivestore.ChecksumCRC64NVME(payload)))
		w.Header().Set("x-amz-checksum-type", "FULL_OBJECT")
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
		return
	}
	first, last, err := parseStoreRange(rangeHeader, int64(len(payload)))
	if err != nil {
		writeStoreError(w, http.StatusRequestedRangeNotSatisfiable, "InvalidRange", err.Error())
		return
	}
	slice := payload[first : last+1]
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", first, last, len(payload)))
	w.Header().Set("Content-Length", strconv.Itoa(len(slice)))
	w.WriteHeader(http.StatusPartialContent)
	_, _ = w.Write(slice)
}

func (s *fakeStore) headObject(w http.ResponseWriter, key string) {
	s.mutex.Lock()
	payload, ok := s.objects[key]
	s.mutex.Unlock()
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("ETag", "\""+storeETag(payload)+"\"")
	w.Header().Set("x-amz-checksum-crc64nvme", archivestore.CRC64Base64(archivestore.ChecksumCRC64NVME(payload)))
	w.Header().Set("x-amz-checksum-type", "FULL_OBJECT")
	w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
	w.WriteHeader(http.StatusOK)
}

func (s *fakeStore) deleteObject(w http.ResponseWriter, key string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if _, ok := s.objects[key]; !ok {
		writeStoreError(w, http.StatusNotFound, "NoSuchKey", "unknown key")
		return
	}
	delete(s.objects, key)
	w.WriteHeader(http.StatusNoContent)
}

func parseStoreRange(value string, size int64) (int64, int64, error) {
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

func storeETag(payload []byte) string {
	return archivestore.CRC64Hex(archivestore.ChecksumCRC64NVME(payload))
}

func writeStoreError(w http.ResponseWriter, status int, code, message string) {
	body := fmt.Sprintf("<?xml version=\"1.0\"?><Error><Code>%s</Code><Message>%s</Message><RequestId>fake</RequestId></Error>", code, message)
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func writeStoreXML(w http.ResponseWriter, body string) {
	document := "<?xml version=\"1.0\"?>" + body
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("Content-Length", strconv.Itoa(len(document)))
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, document)
}

// newTestStore starts the fake and returns a client addressed at it.
func newTestStore(t *testing.T) (*archivestore.Client, *fakeStore) {
	t.Helper()
	store := newFakeStore()
	server := httptest.NewServer(store)
	t.Cleanup(server.Close)
	client, err := archivestore.New(archivestore.Config{
		Endpoint:           server.URL,
		Region:             "us-east-1",
		Bucket:             testBucket,
		KeyPrefix:          testPrefix,
		AccessKeyID:        "AKIAEXAMPLE",
		SecretAccessKey:    "secret-example",
		ChecksumCapability: archivestore.ChecksumCRC64NVMEFullObject,
		PathStyle:          true,
		MaxAttempts:        1,
	})
	if err != nil {
		t.Fatalf("build store client: %v", err)
	}
	return client, store
}
