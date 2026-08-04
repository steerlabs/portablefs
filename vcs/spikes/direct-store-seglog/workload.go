package main

// The logical filesystem model, key encoding, mutation sequence, and cell
// contents are copied verbatim from vcs/spikes/direct-store-writeamp so that
// the two spikes measure the same logical work. Only the storage engine
// differs.

import (
	"encoding/binary"
	"fmt"
	"math/rand/v2"

	"github.com/steerlabs/portablefs/vcs/internal/pft2"
)

const (
	sparseFileBytes = uint64(1 << 30)
	createBytes     = 128
)

var workloads = []string{"random-4k", "sequential-append", "small-creates", "rename", "chmod", "mkdir", "mixed"}

type mutationState struct {
	fileCount int
	rng       *rand.Rand
	appendAt  uint64
	nextIno   uint64
	created   int
	mkdirs    int
	renameIno uint64
	rename    string
	renameAlt string
}

func newMutationState(fileCount int, seed uint64) *mutationState {
	return &mutationState{
		fileCount: fileCount,
		rng:       rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)),
		nextIno:   uint64(fileCount + 2),
		renameIno: 3,
		rename:    baseName(1),
		renameAlt: "renamed-anchor",
	}
}

func (s *mutationState) allocateIno() uint64 {
	ino := s.nextIno
	s.nextIno++
	return ino
}

func workloadSeed(workload string) uint64 {
	var out uint64
	for _, b := range []byte(workload) {
		out = out*131 + uint64(b)
	}
	return out
}

func measuredOperations(workload string, configured int) int {
	if workload == "mixed" {
		return 100
	}
	return configured
}

func operationKind(workload string, op int) string {
	if workload != "mixed" {
		return workload
	}
	switch index := op % 100; {
	case index < 50:
		return "random-4k"
	case index < 70:
		return "sequential-append"
	case index < 80:
		return "small-creates"
	case index < 90:
		return "rename"
	case index < 95:
		return "chmod"
	default:
		return "mkdir"
	}
}

func baseName(index int) string {
	return fmt.Sprintf("f%09d", index)
}

func dataCell(op int, salt uint64) []byte {
	cell := make([]byte, pft2.CellBytes)
	state := uint64(op+1)*0x9e3779b97f4a7c15 ^ salt
	for i := 0; i < len(cell); i += 8 {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		binary.LittleEndian.PutUint64(cell[i:], state|1)
	}
	return cell
}

func createCell(op int, salt uint64) []byte {
	cell := dataCell(op, salt)
	clear(cell[createBytes:])
	return cell
}

func inodeKey(ino uint64) string {
	key := make([]byte, 9)
	key[0] = 'i'
	binary.BigEndian.PutUint64(key[1:], ino)
	return string(key)
}

func dirKey(parent uint64, name string) string {
	key := make([]byte, 9+len(name))
	key[0] = 'd'
	binary.BigEndian.PutUint64(key[1:], parent)
	copy(key[9:], name)
	return string(key)
}

func cellKey(ino, offset uint64) string {
	key := make([]byte, 17)
	key[0] = 'c'
	binary.BigEndian.PutUint64(key[1:], ino)
	binary.BigEndian.PutUint64(key[9:], offset)
	return string(key)
}

type inodeValue struct {
	Kind  byte
	Mode  uint32
	Size  uint64
	Mtime int64
	Ctime int64
}

func encodeInodeValue(value inodeValue) []byte {
	out := make([]byte, 32)
	out[0] = value.Kind
	binary.LittleEndian.PutUint32(out[4:], value.Mode)
	binary.LittleEndian.PutUint64(out[8:], value.Size)
	binary.LittleEndian.PutUint64(out[16:], uint64(value.Mtime))
	binary.LittleEndian.PutUint64(out[24:], uint64(value.Ctime))
	return out
}

func decodeInodeValue(data []byte) (inodeValue, error) {
	if len(data) != 32 {
		return inodeValue{}, fmt.Errorf("inode value is %d bytes", len(data))
	}
	return inodeValue{
		Kind: data[0], Mode: binary.LittleEndian.Uint32(data[4:]), Size: binary.LittleEndian.Uint64(data[8:]),
		Mtime: int64(binary.LittleEndian.Uint64(data[16:])), Ctime: int64(binary.LittleEndian.Uint64(data[24:])),
	}, nil
}

func encodeDirValue(ino uint64, kind byte) []byte {
	out := make([]byte, 9)
	binary.LittleEndian.PutUint64(out, ino)
	out[8] = kind
	return out
}
