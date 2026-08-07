package directstoreharness

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
)

var recordMagic = [4]byte{'P', 'F', 'R', '1'}

type diskFile struct {
	working []byte
	synced  []byte
}

type virtualDisk struct {
	files map[string]*diskFile
}

func newVirtualDisk() virtualDisk {
	return virtualDisk{files: make(map[string]*diskFile, 8)}
}

func encodeRecord(payload []byte) []byte {
	digest := sha256.Sum256(payload)
	record := make([]byte, 0, len(recordMagic)+4+len(digest)+len(payload))
	record = append(record, recordMagic[:]...)
	record = binary.LittleEndian.AppendUint32(record, uint32(len(payload)))
	record = append(record, digest[:]...)
	record = append(record, payload...)
	return record
}

func decodeRecord(record []byte) ([]byte, error) {
	const header = 4 + 4 + sha256.Size
	if len(record) < header || string(record[:4]) != string(recordMagic[:]) {
		return nil, ErrChecksum
	}
	length := binary.LittleEndian.Uint32(record[4:8])
	if uint64(length) != uint64(len(record)-header) {
		return nil, ErrChecksum
	}
	want := Digest{}
	copy(want[:], record[8:8+sha256.Size])
	payload := record[header:]
	if got := digestBytes(payload); got != want {
		return nil, ErrChecksum
	}
	return payload, nil
}

func (d *virtualDisk) truncate(path string) {
	file := d.files[path]
	if file == nil {
		file = &diskFile{}
		d.files[path] = file
	}
	file.working = file.working[:0]

}

func (d *virtualDisk) writeAt(path string, offset int, data []byte) error {
	file := d.files[path]
	if file == nil {
		file = &diskFile{}
		d.files[path] = file
	}
	if offset < 0 || offset > len(file.working) {
		return fmt.Errorf("write %q at invalid offset %d with length %d", path, offset, len(file.working))
	}
	end := offset + len(data)
	if end > len(file.working) {
		file.working = append(file.working, make([]byte, end-len(file.working))...)
	}
	copy(file.working[offset:end], data)
	return nil
}

func (d *virtualDisk) sync(path string) error {
	file := d.files[path]
	if file == nil {
		return fmt.Errorf("sync %q: file does not exist", path)
	}
	file.synced = append(file.synced[:0], file.working...)
	return nil
}

func (d *virtualDisk) read(path string) ([]byte, error) {
	file := d.files[path]
	if file == nil {
		return nil, nil
	}
	return decodeRecord(file.working)
}

func (d *virtualDisk) corrupt(path string) error {
	file := d.files[path]
	if file == nil || len(file.synced) == 0 {
		return fmt.Errorf("corrupt %q: no synced bytes", path)
	}
	file.synced[len(file.synced)-1] ^= 0x80
	file.working = append(file.working[:0], file.synced...)
	return nil
}

func (d *virtualDisk) crash() {
	for _, file := range d.files {
		file.working = append(file.working[:0], file.synced...)
	}
}

func (d *virtualDisk) syncedDigest() Digest {
	paths := make([]string, 0, len(d.files))
	for path := range d.files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	h := sha256.New()
	var length [8]byte
	for _, path := range paths {
		file := d.files[path]
		binary.LittleEndian.PutUint64(length[:], uint64(len(path)))
		_, _ = h.Write(length[:])
		_, _ = h.Write([]byte(path))
		binary.LittleEndian.PutUint64(length[:], uint64(len(file.synced)))
		_, _ = h.Write(length[:])
		_, _ = h.Write(file.synced)
	}
	var out Digest
	copy(out[:], h.Sum(nil))
	return out
}

type Environment struct {
	recorder  *Recorder
	operation uint64
	disks     [ReplicaCount]virtualDisk
	alive     [ReplicaCount]bool
	links     [ReplicaCount + 1][ReplicaCount + 1]bool
	fault     Fault
	faultSet  bool
	fired     bool
}

func NewEnvironment(recorder *Recorder) *Environment {
	env := &Environment{recorder: recorder}
	for node := range ReplicaCount {
		env.disks[node] = newVirtualDisk()
		env.alive[node] = true
	}
	return env
}

func (e *Environment) SetOperation(operation uint64) { e.operation = operation }

func (e *Environment) Arm(fault Fault) {
	e.ClearFault()
	e.fault = fault
	e.faultSet = fault.Kind != NoFault
	e.fired = false
	if fault.Kind == PartitionLink {
		if fault.Links == 0 {
			fault.Links = directedLinkBit(fault.From, fault.To)
			e.fault.Links = fault.Links
		}
		for bit, link := range directedReplicaLinks {
			if fault.Links&(1<<bit) != 0 {
				e.links[link[0]][link[1]] = true
			}
		}
		e.fired = true
	}
	detail := fault.Kind.String()
	if fault.Kind == PartitionLink {
		detail = fmt.Sprintf("%s mask=%06b", detail, fault.Links)
	}
	e.emit(TraceEvent{Kind: EventFaultArmed, Node: fault.Node, Peer: fault.To, Point: fault.Point, Detail: detail})
}

func (e *Environment) ClearFault() {
	if e.faultSet && e.fault.Kind == PartitionLink {
		for bit, link := range directedReplicaLinks {
			if e.fault.Links&(1<<bit) != 0 {
				e.links[link[0]][link[1]] = false
			}
		}
	}
	e.fault = Fault{}
	e.faultSet = false
	e.fired = false
}

var directedReplicaLinks = [ReplicaCount * (ReplicaCount - 1)][2]NodeID{
	{0, 1}, {0, 2}, {1, 0}, {1, 2}, {2, 0}, {2, 1},
}

func directedLinkBit(from, to NodeID) uint8 {
	for bit, link := range directedReplicaLinks {
		if link[0] == from && link[1] == to {
			return 1 << bit
		}
	}
	return 0
}

func (e *Environment) FaultFired() bool { return e.fired }

func (e *Environment) Alive(node NodeID) bool {
	return node < ReplicaCount && e.alive[node]
}

func (e *Environment) Crash(node NodeID, point string) {
	if node >= ReplicaCount || !e.alive[node] {
		return
	}
	e.alive[node] = false
	e.disks[node].crash()
	e.emit(TraceEvent{Kind: EventCrash, Node: node, Point: point, Digest: e.disks[node].syncedDigest()})
}

func (e *Environment) Restart(node NodeID) {
	if node >= ReplicaCount || e.alive[node] {
		return
	}
	e.disks[node].crash()
	e.alive[node] = true
	e.emit(TraceEvent{Kind: EventRestart, Node: node, Digest: e.disks[node].syncedDigest()})
}

func (e *Environment) Persist(node NodeID, point, path string, payload []byte) error {
	if !e.Alive(node) {
		return ErrProcessKilled
	}
	record := encodeRecord(payload)
	e.disks[node].truncate(path)
	for offset := 0; offset < len(record); {
		written, err := e.Write(node, point, path, offset, record[offset:])
		offset += written
		if err != nil {
			return err
		}
		if written == 0 {
			return fmt.Errorf("write %q made no progress", path)
		}
	}
	return e.Sync(node, point, path)
}

// Write is the syscall-level storage seam. A target that owns its persistence
// loop can call Write and Sync directly; Persist is the correct reference
// implementation used by Fixture.
func (e *Environment) Write(node NodeID, point, path string, offset int, data []byte) (int, error) {
	if !e.Alive(node) {
		return 0, ErrProcessKilled
	}
	written := len(data)
	var result error
	if e.matches(ShortWrite, point, node, AnyNode, AnyNode) && written > 1 {
		e.fired = true
		written /= 2
	} else if e.matches(NoSpace, point, node, AnyNode, AnyNode) {
		e.fired = true
		written /= 2
		if written == 0 && len(data) > 0 {
			written = 1
		}
		result = ErrNoSpace
	}
	if err := e.disks[node].writeAt(path, offset, data[:written]); err != nil {
		return 0, err
	}
	e.emit(TraceEvent{Kind: EventDiskWrite, Node: node, Point: point, Detail: fmt.Sprintf("path=%s offset=%d bytes=%d", path, offset, written)})
	return written, result
}

// Sync is the named persistence boundary. KillBefore observes a complete
// volatile record and then discards it; KillAfter observes the synced record.
func (e *Environment) Sync(node NodeID, point, path string) error {
	if !e.Alive(node) {
		return ErrProcessKilled
	}
	e.emit(TraceEvent{Kind: EventCutBefore, Node: node, Point: point})
	if e.matches(KillBefore, point, node, AnyNode, AnyNode) {
		e.fired = true
		e.Crash(node, point+":before")
		return ErrProcessKilled
	}
	if err := e.disks[node].sync(path); err != nil {
		return err
	}
	e.emit(TraceEvent{Kind: EventDiskSync, Node: node, Point: point, Detail: path, Digest: e.disks[node].syncedDigest()})
	if e.matches(ChecksumFailure, point, node, AnyNode, AnyNode) {
		e.fired = true
		if err := e.disks[node].corrupt(path); err != nil {
			return err
		}
		e.emit(TraceEvent{Kind: EventDiskSync, Node: node, Point: point, Detail: path + ":corrupt", Digest: e.disks[node].syncedDigest()})
		return ErrChecksum
	}
	e.emit(TraceEvent{Kind: EventCutAfter, Node: node, Point: point})
	if e.matches(KillAfter, point, node, AnyNode, AnyNode) {
		e.fired = true
		e.Crash(node, point+":after")
		return ErrProcessKilled
	}
	return nil
}

func (e *Environment) Read(node NodeID, path string) ([]byte, error) {
	if !e.Alive(node) {
		return nil, ErrProcessKilled
	}
	return e.disks[node].read(path)
}

// Send returns the number of copies delivered. A duplicated reply therefore
// remains visible to the target while carrying the same exact outcome.
func (e *Environment) Send(from, to NodeID, point string, index uint64, payload []byte) (int, error) {
	if from < ReplicaCount && !e.Alive(from) {
		return 0, ErrProcessKilled
	}
	if to < ReplicaCount && !e.Alive(to) {
		return 0, ErrProcessKilled
	}
	e.emit(TraceEvent{Kind: EventCutBefore, Node: from, Peer: to, Index: index, Point: point})
	if kill, ok := e.messageKill(KillBefore, point, from, to); ok {
		e.fired = true
		e.Crash(kill, point+":before")
		return 0, ErrProcessKilled
	}
	digest := digestBytes(payload)
	if e.links[from][to] || e.matches(DropMessage, point, AnyNode, from, to) {
		if e.matches(DropMessage, point, AnyNode, from, to) {
			e.fired = true
		}
		e.emit(TraceEvent{Kind: EventMessageDrop, Node: from, Peer: to, Index: index, Point: point, Digest: digest})
		return 0, ErrPartitioned
	}
	copies := 1
	kind := EventMessageDeliver
	if e.matches(DuplicateMessage, point, AnyNode, from, to) {
		e.fired = true
		copies = 2
		kind = EventMessageDuplicate
	}
	e.emit(TraceEvent{Kind: kind, Node: from, Peer: to, Index: index, Point: point, Digest: digest})
	e.emit(TraceEvent{Kind: EventCutAfter, Node: from, Peer: to, Index: index, Point: point})
	if kill, ok := e.messageKill(KillAfter, point, from, to); ok {
		e.fired = true
		e.Crash(kill, point+":after")
		return copies, ErrProcessKilled
	}
	return copies, nil
}

func (e *Environment) Partitioned(from, to NodeID) bool { return e.links[from][to] }

func (e *Environment) emit(event TraceEvent) {
	event.Operation = e.operation
	e.recorder.Emit(event)
}

func (e *Environment) matches(kind FaultKind, point string, node, from, to NodeID) bool {
	if !e.faultSet || e.fired || e.fault.Kind != kind || e.fault.Point != point {
		return false
	}
	if e.fault.Node != AnyNode && node != AnyNode && e.fault.Node != node {
		return false
	}
	if e.fault.From != AnyNode && from != AnyNode && e.fault.From != from {
		return false
	}
	if e.fault.To != AnyNode && to != AnyNode && e.fault.To != to {
		return false
	}
	return true
}

func (e *Environment) messageKill(kind FaultKind, point string, from, to NodeID) (NodeID, bool) {
	if !e.faultSet || e.fired || e.fault.Kind != kind || e.fault.Point != point {
		return 0, false
	}
	if e.fault.From != AnyNode && e.fault.From != from || e.fault.To != AnyNode && e.fault.To != to {
		return 0, false
	}
	if e.fault.Node == AnyNode {
		return from, true
	}
	if e.fault.Node != from && e.fault.Node != to {
		return 0, false
	}
	return e.fault.Node, true
}
