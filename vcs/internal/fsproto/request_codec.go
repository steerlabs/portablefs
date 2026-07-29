package fsproto

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// PFRQ1 is the allocation-safe client-to-authority request wire format.
//
// Each request is a uint32 big-endian body length followed by this fixed
// schema. The outer length is rejected before reading or allocating the body;
// every variable field and collection is then checked against both its
// field-specific ceiling and the bytes remaining in the frame before make.
// Responses deliberately remain a gob stream in the opposite direction.
var requestWireMagic = [4]byte{'P', 'F', 'R', 'Q'}

const (
	requestWireVersion = 1

	// The largest legitimate request is one MaxWriteBytes write plus bounded
	// metadata. Keep the existing 64 MiB write allowance while bounding the
	// aggregate frame independently of any one field.
	maxRequestBytes = MaxWriteBytes + (8 << 20)

	// Text fields are semantically much smaller (paths are PATH_MAX-shaped),
	// but the decoder leaves enough room for the server to return its typed
	// validation error for modestly malformed requests.
	maxRequestTextBytes = 1 << 20
	maxRequestAuxBytes  = 1 << 20

	// Every request collection is finite before allocation. Flush records
	// already use this public semantic bound; the same generous cap covers
	// inode-renewal and write-back recovery lists.
	maxRequestCollectionItems = MaxBatchRecords

	requestFlagOrphanTarget uint32 = 1 << iota
	requestFlagAppend
	requestFlagSetMode
	requestFlagSetTime
	requestFlagSetUID
	requestFlagSetGID
	requestFlagLockWrite
	requestFlagLockUnlock
	requestFlagOpenState
	requestFlagRegisterOpen
	requestFlagExcl
	requestFlagEnvelope
)

const requestKnownFlags = requestFlagOrphanTarget |
	requestFlagAppend |
	requestFlagSetMode |
	requestFlagSetTime |
	requestFlagSetUID |
	requestFlagSetGID |
	requestFlagLockWrite |
	requestFlagLockUnlock |
	requestFlagOpenState |
	requestFlagRegisterOpen |
	requestFlagExcl |
	requestFlagEnvelope

var (
	errRequestTooLarge  = errors.New("fsproto: request exceeds the aggregate byte bound")
	errMalformedRequest = errors.New("fsproto: malformed request frame")
)

type requestEncoder struct {
	w *bufio.Writer
}

func newRequestEncoder(w io.Writer) *requestEncoder {
	return &requestEncoder{w: bufio.NewWriterSize(w, 32<<10)}
}

type preparedRequest struct {
	bodyBytes uint32
	records   [][]byte
}

func prepareRequest(req *Request) (preparedRequest, error) {
	if req == nil {
		return preparedRequest{}, fmt.Errorf("%w: nil request", errMalformedRequest)
	}
	var n uint64
	add := func(v uint64) error {
		n += v
		if n > maxRequestBytes {
			return errRequestTooLarge
		}
		return nil
	}
	// Magic, version, op, flags, then the fixed-width scalar fields.
	if err := add(4 + 1 + 1 + 4 +
		8 + 8 + 4 + 8 + 4 + 4 + 8 +
		8 + 8 + 8 + 1 +
		8 + 8 + 8 +
		8 + 4 + 1 + 8 + 8); err != nil {
		return preparedRequest{}, err
	}
	addText := func(name, value string) error {
		if len(value) > maxRequestTextBytes {
			return fmt.Errorf("%w: %s is %d bytes (max %d)", errMalformedRequest, name, len(value), maxRequestTextBytes)
		}
		return add(4 + uint64(len(value)))
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"path", req.Path},
		{"new path", req.NewPath},
		{"target", req.Target},
		{"owner", req.Owner},
		{"session id", req.SessionID},
		{"session token", req.SessionToken},
		{"checkout path", req.CheckoutPath},
		{"checkout epoch", req.CheckoutEpoch},
		{"xattr name", req.XattrName},
	} {
		if err := addText(field.name, field.value); err != nil {
			return preparedRequest{}, err
		}
	}
	addBytes := func(name string, value []byte, max int) error {
		if len(value) > max {
			return fmt.Errorf("%w: %s is %d bytes (max %d)", errMalformedRequest, name, len(value), max)
		}
		return add(4 + uint64(len(value)))
	}
	if err := addBytes("data", req.Data, MaxWriteBytes); err != nil {
		return preparedRequest{}, err
	}
	if err := addBytes("previous digest", req.WBPrevDigest, maxRequestAuxBytes); err != nil {
		return preparedRequest{}, err
	}
	if err := addBytes("end digest", req.WBEndDigest, maxRequestAuxBytes); err != nil {
		return preparedRequest{}, err
	}
	if req.Env != nil {
		if err := addText("envelope session id", req.Env.SessionID); err != nil {
			return preparedRequest{}, err
		}
		if err := add(8 + 4 + 8); err != nil {
			return preparedRequest{}, err
		}
		if err := addBytes("envelope request hash", req.Env.ReqHash, maxRequestAuxBytes); err != nil {
			return preparedRequest{}, err
		}
	}
	addUint64s := func(name string, values []uint64) error {
		if len(values) > maxRequestCollectionItems {
			return fmt.Errorf("%w: %s has %d items (max %d)", errMalformedRequest, name, len(values), maxRequestCollectionItems)
		}
		return add(4 + 8*uint64(len(values)))
	}
	if err := addUint64s("orphan inode list", req.OrphanInos); err != nil {
		return preparedRequest{}, err
	}
	if err := addUint64s("open inode list", req.OpenInos); err != nil {
		return preparedRequest{}, err
	}
	if len(req.Records) > MaxBatchRecords {
		return preparedRequest{}, fmt.Errorf("%w: record list has %d items (max %d)", errMalformedRequest, len(req.Records), MaxBatchRecords)
	}
	if err := add(4); err != nil {
		return preparedRequest{}, err
	}
	prepared := preparedRequest{records: make([][]byte, 0, len(req.Records))}
	for i := range req.Records {
		payload, err := wal.EncodePFR1(&req.Records[i])
		if err != nil {
			return preparedRequest{}, fmt.Errorf("%w: record %d: %v", errMalformedRequest, i, err)
		}
		if err := add(4 + uint64(len(payload))); err != nil {
			return preparedRequest{}, err
		}
		prepared.records = append(prepared.records, payload)
	}
	if len(req.WBScopes) > maxRequestCollectionItems {
		return preparedRequest{}, fmt.Errorf("%w: write-back scope list has %d items (max %d)", errMalformedRequest, len(req.WBScopes), maxRequestCollectionItems)
	}
	if err := add(4); err != nil {
		return preparedRequest{}, err
	}
	for i := range req.WBScopes {
		if err := addText("write-back scope path", req.WBScopes[i].Path); err != nil {
			return preparedRequest{}, err
		}
		if err := addText("write-back scope epoch", req.WBScopes[i].Epoch); err != nil {
			return preparedRequest{}, err
		}
		if err := add(8); err != nil {
			return preparedRequest{}, err
		}
	}
	prepared.bodyBytes = uint32(n)
	return prepared, nil
}

func requestFlags(req *Request) uint32 {
	var flags uint32
	if req.OrphanTarget {
		flags |= requestFlagOrphanTarget
	}
	if req.Append {
		flags |= requestFlagAppend
	}
	if req.SetMode {
		flags |= requestFlagSetMode
	}
	if req.SetTime {
		flags |= requestFlagSetTime
	}
	if req.SetUID {
		flags |= requestFlagSetUID
	}
	if req.SetGID {
		flags |= requestFlagSetGID
	}
	if req.LkWrite {
		flags |= requestFlagLockWrite
	}
	if req.LkUnlock {
		flags |= requestFlagLockUnlock
	}
	if req.OpenState {
		flags |= requestFlagOpenState
	}
	if req.RegisterOpen {
		flags |= requestFlagRegisterOpen
	}
	if req.Excl {
		flags |= requestFlagExcl
	}
	if req.Env != nil {
		flags |= requestFlagEnvelope
	}
	return flags
}

type requestWireWriter struct {
	w   io.Writer
	err error
	buf [8]byte
}

func (w *requestWireWriter) bytes(value []byte) {
	if w.err != nil {
		return
	}
	w.u32(uint32(len(value)))
	if w.err == nil && len(value) != 0 {
		_, w.err = w.w.Write(value)
	}
}

func (w *requestWireWriter) text(value string) { w.bytes([]byte(value)) }

func (w *requestWireWriter) u8(value uint8) {
	if w.err == nil {
		w.buf[0] = value
		_, w.err = w.w.Write(w.buf[:1])
	}
}

func (w *requestWireWriter) u32(value uint32) {
	if w.err == nil {
		binary.BigEndian.PutUint32(w.buf[:4], value)
		_, w.err = w.w.Write(w.buf[:4])
	}
}

func (w *requestWireWriter) u64(value uint64) {
	if w.err == nil {
		binary.BigEndian.PutUint64(w.buf[:8], value)
		_, w.err = w.w.Write(w.buf[:8])
	}
}

func (e *requestEncoder) Encode(req *Request) error {
	prepared, err := prepareRequest(req)
	if err != nil {
		return err
	}
	w := requestWireWriter{w: e.w}
	w.u32(prepared.bodyBytes)
	if w.err == nil {
		_, w.err = e.w.Write(requestWireMagic[:])
	}
	w.u8(requestWireVersion)
	w.u8(uint8(req.Op))
	w.u32(requestFlags(req))
	w.u64(uint64(req.Offset))
	w.u64(uint64(req.Size))
	w.u32(req.Mode)
	w.u64(uint64(req.MtimeMs))
	w.u32(req.UID)
	w.u32(req.GID)
	w.u64(req.Epoch)
	w.u64(req.LkID)
	w.u64(req.LkStart)
	w.u64(req.LkEnd)
	w.u8(req.LkMode)
	w.u64(req.OrphanIno)
	w.u64(req.HandleIno)
	w.u64(req.OpenIno)
	w.u64(req.SessionGen)
	w.u32(req.SessionSlots)
	w.u8(req.XattrFlags)
	w.u64(req.WBThrough)
	w.u64(req.AckPos)

	for _, value := range []string{
		req.Path,
		req.NewPath,
		req.Target,
		req.Owner,
		req.SessionID,
		req.SessionToken,
		req.CheckoutPath,
		req.CheckoutEpoch,
		req.XattrName,
	} {
		w.text(value)
	}
	w.bytes(req.Data)
	w.bytes(req.WBPrevDigest)
	w.bytes(req.WBEndDigest)
	if req.Env != nil {
		w.text(req.Env.SessionID)
		w.u64(req.Env.Generation)
		w.u32(req.Env.Slot)
		w.u64(req.Env.SlotSeq)
		w.bytes(req.Env.ReqHash)
	}
	w.u32(uint32(len(req.OrphanInos)))
	for _, ino := range req.OrphanInos {
		w.u64(ino)
	}
	w.u32(uint32(len(req.OpenInos)))
	for _, ino := range req.OpenInos {
		w.u64(ino)
	}
	w.u32(uint32(len(prepared.records)))
	for _, payload := range prepared.records {
		w.bytes(payload)
	}
	w.u32(uint32(len(req.WBScopes)))
	for _, scope := range req.WBScopes {
		w.text(scope.Path)
		w.text(scope.Epoch)
		w.u64(scope.Through)
	}
	if w.err != nil {
		return w.err
	}
	return e.w.Flush()
}

type requestDecoder struct {
	r *bufio.Reader
}

func newRequestDecoder(r io.Reader) *requestDecoder {
	return &requestDecoder{r: bufio.NewReaderSize(r, 32<<10)}
}

type requestWireReader struct {
	r   *io.LimitedReader
	err error
	buf [8]byte
}

func (r *requestWireReader) read(dst []byte) {
	if r.err == nil {
		_, r.err = io.ReadFull(r.r, dst)
	}
}

func (r *requestWireReader) u8() uint8 {
	r.read(r.buf[:1])
	return r.buf[0]
}

func (r *requestWireReader) u32() uint32 {
	r.read(r.buf[:4])
	return binary.BigEndian.Uint32(r.buf[:4])
}

func (r *requestWireReader) u64() uint64 {
	r.read(r.buf[:8])
	return binary.BigEndian.Uint64(r.buf[:8])
}

func (r *requestWireReader) bytes(name string, max uint32) []byte {
	n := r.u32()
	if r.err != nil {
		return nil
	}
	if n > max {
		r.err = fmt.Errorf("%w: %s announces %d bytes (max %d)", errMalformedRequest, name, n, max)
		return nil
	}
	if int64(n) > r.r.N {
		r.err = fmt.Errorf("%w: %s announces %d bytes with only %d left", errMalformedRequest, name, n, r.r.N)
		return nil
	}
	if n == 0 {
		return nil
	}
	value := make([]byte, int(n))
	r.read(value)
	return value
}

func (r *requestWireReader) text(name string) string {
	return string(r.bytes(name, maxRequestTextBytes))
}

func (r *requestWireReader) count(name string, max uint32, minItemBytes int64) uint32 {
	n := r.u32()
	if r.err != nil {
		return 0
	}
	if n > max {
		r.err = fmt.Errorf("%w: %s announces %d items (max %d)", errMalformedRequest, name, n, max)
		return 0
	}
	if minItemBytes > 0 && int64(n) > r.r.N/minItemBytes {
		r.err = fmt.Errorf("%w: %s count %d cannot fit in the %d remaining bytes", errMalformedRequest, name, n, r.r.N)
		return 0
	}
	return n
}

func (d *requestDecoder) Decode(dst *Request) error {
	if dst == nil {
		return fmt.Errorf("%w: nil destination", errMalformedRequest)
	}
	var header [4]byte
	if _, err := io.ReadFull(d.r, header[:]); err != nil {
		return err
	}
	bodyBytes := binary.BigEndian.Uint32(header[:])
	if bodyBytes > maxRequestBytes {
		return fmt.Errorf("%w: announced %d bytes (max %d)", errRequestTooLarge, bodyBytes, maxRequestBytes)
	}
	lr := &io.LimitedReader{R: d.r, N: int64(bodyBytes)}
	r := requestWireReader{r: lr}
	var magic [4]byte
	r.read(magic[:])
	if r.err == nil && magic != requestWireMagic {
		r.err = fmt.Errorf("%w: bad request magic", errMalformedRequest)
	}
	if version := r.u8(); r.err == nil && version != requestWireVersion {
		r.err = fmt.Errorf("%w: unsupported request codec version %d", errMalformedRequest, version)
	}
	var req Request
	req.Op = Op(r.u8())
	flags := r.u32()
	if r.err == nil && flags&^requestKnownFlags != 0 {
		r.err = fmt.Errorf("%w: unknown request flags %#x", errMalformedRequest, flags&^requestKnownFlags)
	}
	req.Offset = int64(r.u64())
	req.Size = int64(r.u64())
	req.Mode = r.u32()
	req.MtimeMs = int64(r.u64())
	req.UID = r.u32()
	req.GID = r.u32()
	req.Epoch = r.u64()
	req.LkID = r.u64()
	req.LkStart = r.u64()
	req.LkEnd = r.u64()
	req.LkMode = r.u8()
	req.OrphanIno = r.u64()
	req.HandleIno = r.u64()
	req.OpenIno = r.u64()
	req.SessionGen = r.u64()
	req.SessionSlots = r.u32()
	req.XattrFlags = r.u8()
	req.WBThrough = r.u64()
	req.AckPos = r.u64()

	req.OrphanTarget = flags&requestFlagOrphanTarget != 0
	req.Append = flags&requestFlagAppend != 0
	req.SetMode = flags&requestFlagSetMode != 0
	req.SetTime = flags&requestFlagSetTime != 0
	req.SetUID = flags&requestFlagSetUID != 0
	req.SetGID = flags&requestFlagSetGID != 0
	req.LkWrite = flags&requestFlagLockWrite != 0
	req.LkUnlock = flags&requestFlagLockUnlock != 0
	req.OpenState = flags&requestFlagOpenState != 0
	req.RegisterOpen = flags&requestFlagRegisterOpen != 0
	req.Excl = flags&requestFlagExcl != 0

	req.Path = r.text("path")
	req.NewPath = r.text("new path")
	req.Target = r.text("target")
	req.Owner = r.text("owner")
	req.SessionID = r.text("session id")
	req.SessionToken = r.text("session token")
	req.CheckoutPath = r.text("checkout path")
	req.CheckoutEpoch = r.text("checkout epoch")
	req.XattrName = r.text("xattr name")
	req.Data = r.bytes("data", MaxWriteBytes)
	req.WBPrevDigest = r.bytes("previous digest", maxRequestAuxBytes)
	req.WBEndDigest = r.bytes("end digest", maxRequestAuxBytes)
	if flags&requestFlagEnvelope != 0 {
		req.Env = &wal.Envelope{
			SessionID:  r.text("envelope session id"),
			Generation: r.u64(),
			Slot:       r.u32(),
			SlotSeq:    r.u64(),
			ReqHash:    r.bytes("envelope request hash", maxRequestAuxBytes),
		}
	}
	orphanCount := r.count("orphan inode list", maxRequestCollectionItems, 8)
	if r.err == nil && orphanCount != 0 {
		req.OrphanInos = make([]uint64, int(orphanCount))
		for i := range req.OrphanInos {
			req.OrphanInos[i] = r.u64()
		}
	}
	openCount := r.count("open inode list", maxRequestCollectionItems, 8)
	if r.err == nil && openCount != 0 {
		req.OpenInos = make([]uint64, int(openCount))
		for i := range req.OpenInos {
			req.OpenInos[i] = r.u64()
		}
	}
	recordCount := r.count("record list", MaxBatchRecords, 4)
	if r.err == nil && recordCount != 0 {
		req.Records = make([]wal.Record, int(recordCount))
		for i := range req.Records {
			payload := r.bytes("record", wal.MaxPFR1RecordBytes)
			if r.err != nil {
				break
			}
			record, err := wal.DecodePFR1(payload)
			if err != nil {
				r.err = fmt.Errorf("%w: record %d: %v", errMalformedRequest, i, err)
				break
			}
			req.Records[i] = record
		}
	}
	scopeCount := r.count("write-back scope list", maxRequestCollectionItems, 16)
	if r.err == nil && scopeCount != 0 {
		req.WBScopes = make([]WBScope, int(scopeCount))
		for i := range req.WBScopes {
			req.WBScopes[i] = WBScope{
				Path:    r.text("write-back scope path"),
				Epoch:   r.text("write-back scope epoch"),
				Through: r.u64(),
			}
		}
	}
	if r.err != nil {
		return r.err
	}
	if lr.N != 0 {
		return fmt.Errorf("%w: %d trailing request bytes", errMalformedRequest, lr.N)
	}
	*dst = req
	return nil
}
