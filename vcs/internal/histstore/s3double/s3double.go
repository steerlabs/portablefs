// Package s3double is an in-memory S3-compatible test double: exact-key
// PUT/GET/HEAD/DELETE over both path-style and virtual-host addressing,
// full AWS SigV4 verification against configured credentials, and typed
// fault injection (unavailability, truncated bodies, corrupted bytes,
// response delays, dropped writes). It serves requests through an
// in-process http.RoundTripper — no sockets — so store and worker tests
// exercise the REAL HTTP/signing code path hermetically.
package s3double

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Object is one stored object with its metadata headers.
type Object struct {
	Data []byte
	Meta map[string]string // lowercase x-amz-meta-* suffixes -> values
}

// Fault selects one injected behaviour for matching requests.
type Fault struct {
	// Method and KeySuffix select requests ("" matches all).
	Method    string
	KeySuffix string
	// Remaining bounds how many times the fault fires (<0 = forever).
	Remaining int
	// Status, when nonzero, short-circuits with that HTTP status.
	Status int
	// TruncateBody serves only the first half of a GET body while
	// advertising the full Content-Length (a short read).
	TruncateBody bool
	// CorruptBody flips one byte of a GET body.
	CorruptBody bool
	// Delay blocks before answering, honouring request-context cancel
	// (deadline tests).
	Delay time.Duration
	// DropPut accepts a PUT (200) without storing the bytes (lost write).
	DropPut bool
}

// Double is the in-process S3-compatible endpoint.
type Double struct {
	Bucket          string
	Region          string
	AccessKeyID     string
	SecretAccessKey string

	mu      sync.Mutex
	objects map[string]Object
	faults  []*Fault
	// Requests records "METHOD key" in arrival order.
	Requests []string
	// UnsignedRejects counts requests refused for bad signatures.
	UnsignedRejects int
}

// New creates the double.
func New(bucket, region, accessKeyID, secretAccessKey string) *Double {
	return &Double{
		Bucket:          bucket,
		Region:          region,
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		objects:         map[string]Object{},
	}
}

// Close exists for symmetry with server-backed doubles.
func (d *Double) Close() {}

// URL is the endpoint base URL clients should be configured with. Nothing
// resolves or dials it; the Transport routes in-process.
func (d *Double) URL() string { return "http://s3.double.test" }

// Transport returns the in-process RoundTripper serving this double.
func (d *Double) Transport() http.RoundTripper { return roundTripper{d} }

type roundTripper struct{ d *Double }

func (rt roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return rt.d.roundTrip(req)
}

// InjectFault registers one fault.
func (d *Double) InjectFault(f Fault) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.faults = append(d.faults, &f)
}

// PutObject seeds one object directly (bypasses HTTP).
func (d *Double) PutObject(key string, data []byte, meta map[string]string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	copied := append([]byte(nil), data...)
	m := map[string]string{}
	for k, v := range meta {
		m[strings.ToLower(k)] = v
	}
	d.objects[key] = Object{Data: copied, Meta: m}
}

// GetObject reads one object directly.
func (d *Double) GetObject(key string) ([]byte, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	obj, ok := d.objects[key]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), obj.Data...), true
}

// DeleteObject removes one object directly.
func (d *Double) DeleteObject(key string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.objects, key)
}

// CorruptObject flips one byte of a stored object (scrub tests).
func (d *Double) CorruptObject(key string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	obj, ok := d.objects[key]
	if !ok || len(obj.Data) == 0 {
		return false
	}
	obj.Data = append([]byte(nil), obj.Data...)
	obj.Data[len(obj.Data)/2] ^= 0x5A
	d.objects[key] = obj
	return true
}

// Keys lists stored keys sorted.
func (d *Double) Keys() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]string, 0, len(d.objects))
	for k := range d.objects {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// RequestLog returns a copy of the request log.
func (d *Double) RequestLog() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.Requests...)
}

// resolveKey strips path-style ("/bucket/key") or virtual-host
// ("bucket.host" + "/key") addressing down to the object key.
func (d *Double) resolveKey(req *http.Request) (string, bool) {
	path := strings.TrimPrefix(req.URL.EscapedPath(), "/")
	host := req.URL.Host
	if req.Host != "" {
		host = req.Host
	}
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	if strings.HasPrefix(host, d.Bucket+".") {
		key, err := url.PathUnescape(path)
		return key, err == nil && key != ""
	}
	if strings.HasPrefix(path, d.Bucket+"/") {
		key, err := url.PathUnescape(strings.TrimPrefix(path, d.Bucket+"/"))
		return key, err == nil && key != ""
	}
	return "", false
}

func (d *Double) matchFault(method, key string) *Fault {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, f := range d.faults {
		if f.Remaining == 0 {
			continue
		}
		if f.Method != "" && f.Method != method {
			continue
		}
		if f.KeySuffix != "" && !strings.HasSuffix(key, f.KeySuffix) {
			continue
		}
		if f.Remaining > 0 {
			f.Remaining--
		}
		return f
	}
	return nil
}

func respond(req *http.Request, status int, header http.Header, body []byte) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	if body == nil {
		body = []byte{}
	}
	if header.Get("Content-Length") == "" {
		header.Set("Content-Length", strconv.Itoa(len(body)))
	}
	length, _ := strconv.ParseInt(header.Get("Content-Length"), 10, 64)
	return &http.Response{
		StatusCode:    status,
		Status:        http.StatusText(status),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: length,
		Request:       req,
	}
}

func (d *Double) roundTrip(req *http.Request) (*http.Response, error) {
	key, ok := d.resolveKey(req)
	if !ok {
		return respond(req, http.StatusBadRequest, nil, []byte("unresolvable bucket/key")), nil
	}
	var body []byte
	if req.Body != nil {
		read, err := readBodyWithContext(req.Context(), req.Body)
		req.Body.Close()
		if err != nil {
			return nil, err
		}
		body = read
	}
	if !d.verifySignature(req, body) {
		d.mu.Lock()
		d.UnsignedRejects++
		d.mu.Unlock()
		return respond(req, http.StatusForbidden, nil, []byte("SignatureDoesNotMatch")), nil
	}
	d.mu.Lock()
	d.Requests = append(d.Requests, req.Method+" "+key)
	d.mu.Unlock()

	if f := d.matchFault(req.Method, key); f != nil {
		if f.Delay > 0 {
			select {
			case <-time.After(f.Delay):
			case <-req.Context().Done():
				return nil, req.Context().Err()
			}
		}
		if f.Status != 0 {
			return respond(req, f.Status, nil, []byte("injected fault")), nil
		}
		if f.DropPut && req.Method == http.MethodPut {
			return respond(req, http.StatusOK, nil, nil), nil
		}
		if (f.TruncateBody || f.CorruptBody) && req.Method == http.MethodGet {
			d.mu.Lock()
			obj, exists := d.objects[key]
			d.mu.Unlock()
			if !exists {
				return respond(req, http.StatusNotFound, nil, []byte("NoSuchKey")), nil
			}
			data := append([]byte(nil), obj.Data...)
			if f.CorruptBody && len(data) > 0 {
				data[len(data)/2] ^= 0xFF
			}
			serveLen := len(data)
			if f.TruncateBody {
				serveLen = len(data) / 2
			}
			header := http.Header{}
			// Advertise the FULL length, then end the stream early.
			header.Set("Content-Length", strconv.Itoa(len(data)))
			resp := respond(req, http.StatusOK, header, nil)
			resp.Body = io.NopCloser(bytes.NewReader(data[:serveLen]))
			return resp, nil
		}
	}

	switch req.Method {
	case http.MethodPut:
		meta := map[string]string{}
		for name, values := range req.Header {
			lower := strings.ToLower(name)
			if strings.HasPrefix(lower, "x-amz-meta-") && len(values) > 0 {
				meta[strings.TrimPrefix(lower, "x-amz-meta-")] = values[0]
			}
		}
		d.mu.Lock()
		d.objects[key] = Object{Data: body, Meta: meta}
		d.mu.Unlock()
		return respond(req, http.StatusOK, nil, nil), nil
	case http.MethodGet, http.MethodHead:
		d.mu.Lock()
		obj, exists := d.objects[key]
		d.mu.Unlock()
		if !exists {
			return respond(req, http.StatusNotFound, nil, []byte("NoSuchKey")), nil
		}
		header := http.Header{}
		for suffix, value := range obj.Meta {
			header.Set("x-amz-meta-"+suffix, value)
		}
		if req.Method == http.MethodHead {
			header.Set("Content-Length", strconv.Itoa(len(obj.Data)))
			resp := respond(req, http.StatusOK, header, nil)
			resp.ContentLength = int64(len(obj.Data))
			resp.Header.Set("Content-Length", strconv.Itoa(len(obj.Data)))
			return resp, nil
		}
		return respond(req, http.StatusOK, header, obj.Data), nil
	case http.MethodDelete:
		d.mu.Lock()
		delete(d.objects, key)
		d.mu.Unlock()
		return respond(req, http.StatusNoContent, nil, nil), nil
	default:
		return respond(req, http.StatusMethodNotAllowed, nil, nil), nil
	}
}

func readBodyWithContext(ctx context.Context, body io.Reader) ([]byte, error) {
	type result struct {
		data []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		data, err := io.ReadAll(body)
		done <- result{data, err}
	}()
	select {
	case r := <-done:
		return r.data, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// verifySignature recomputes the SigV4 signature over the received request
// and compares it with the presented Authorization header.
func (d *Double) verifySignature(req *http.Request, body []byte) bool {
	auth := req.Header.Get("Authorization")
	const prefix = "AWS4-HMAC-SHA256 "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	fields := map[string]string{}
	for _, part := range strings.Split(strings.TrimPrefix(auth, prefix), ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 {
			fields[kv[0]] = kv[1]
		}
	}
	credential := fields["Credential"]
	signedHeaders := fields["SignedHeaders"]
	signature := fields["Signature"]
	if credential == "" || signedHeaders == "" || signature == "" {
		return false
	}
	credParts := strings.Split(credential, "/")
	if len(credParts) != 5 || credParts[0] != d.AccessKeyID ||
		credParts[2] != d.Region || credParts[3] != "s3" || credParts[4] != "aws4_request" {
		return false
	}
	shortDate := credParts[1]

	payloadHash := req.Header.Get("x-amz-content-sha256")
	actualHash := sha256.Sum256(body)
	if payloadHash != hex.EncodeToString(actualHash[:]) {
		return false
	}

	var canonicalHeaders strings.Builder
	for _, name := range strings.Split(signedHeaders, ";") {
		value := req.Header.Get(name)
		if name == "host" {
			value = req.Host
			if value == "" {
				value = req.URL.Host
			}
		}
		canonicalHeaders.WriteString(name)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(strings.Join(strings.Fields(strings.TrimSpace(value)), " "))
		canonicalHeaders.WriteByte('\n')
	}
	uri := req.URL.EscapedPath()
	if uri == "" {
		uri = "/"
	}
	query := ""
	if req.URL.RawQuery != "" {
		if values, err := url.ParseQuery(req.URL.RawQuery); err == nil {
			query = values.Encode()
		} else {
			query = req.URL.RawQuery
		}
	}
	canonicalRequest := strings.Join([]string{
		req.Method, uri, query, canonicalHeaders.String(), signedHeaders, payloadHash,
	}, "\n")
	crHash := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		req.Header.Get("x-amz-date"),
		shortDate + "/" + d.Region + "/s3/aws4_request",
		hex.EncodeToString(crHash[:]),
	}, "\n")
	key := hmacSHA256([]byte("AWS4"+d.SecretAccessKey), shortDate)
	key = hmacSHA256(key, d.Region)
	key = hmacSHA256(key, "s3")
	key = hmacSHA256(key, "aws4_request")
	expected := hex.EncodeToString(hmacSHA256(key, stringToSign))
	return hmac.Equal([]byte(expected), []byte(signature))
}

func hmacSHA256(key []byte, value string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(value))
	return m.Sum(nil)
}
