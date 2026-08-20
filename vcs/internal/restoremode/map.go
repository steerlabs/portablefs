package restoremode

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const (
	mapMagic       = "PFS-RESTORE-MAP\x00"
	mapVersion     = uint32(1)
	mapHeaderBytes = 16 + 4 + 4 + 32
	mapRecordBytes = 16
	mapRecordChunk = byte(1)
	mapRecordUser  = byte(2)
)

type hydrationMap struct {
	mu         sync.Mutex
	file       *os.File
	path       string
	chunkSize  uint32
	digest     [32]byte
	maxRecords uint64
	records    uint64
	hydrated   map[chunkKey]bool
	durable    map[chunkKey]bool
	modified   map[uint32]bool
	hook       func(uint32, uint32, bool)
}

func openHydrationMap(path string, chunkSize uint32, digest [32]byte, maxRecords uint64, hook func(uint32, uint32, bool)) (*hydrationMap, error) {
	if chunkSize == 0 || maxRecords == 0 {
		return nil, errors.New("restoremode: invalid hydration map bounds")
	}
	m := &hydrationMap{path: path, chunkSize: chunkSize, digest: digest, maxRecords: maxRecords,
		hydrated: make(map[chunkKey]bool), durable: make(map[chunkKey]bool), modified: make(map[uint32]bool), hook: hook}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open hydration map: %w", err)
	}
	m.file = file
	info, err := file.Stat()
	if err != nil {
		m.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		m.Close()
		return nil, errors.New("restoremode: hydration map must be a private regular file")
	}
	if info.Size() == 0 {
		if err := m.writeHeader(); err != nil {
			m.Close()
			return nil, err
		}
	} else if err := m.replay(info.Size()); err != nil {
		m.Close()
		return nil, err
	}
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		m.Close()
		return nil, err
	}
	return m, nil
}

func (m *hydrationMap) writeHeader() error {
	header := make([]byte, mapHeaderBytes)
	copy(header[:16], []byte(mapMagic))
	binary.LittleEndian.PutUint32(header[16:20], mapVersion)
	binary.LittleEndian.PutUint32(header[20:24], m.chunkSize)
	copy(header[24:], m.digest[:])
	if _, err := m.file.WriteAt(header, 0); err != nil {
		return err
	}
	if err := m.file.Sync(); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(m.path))
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

func (m *hydrationMap) replay(size int64) error {
	if size < mapHeaderBytes {
		return errors.New("restoremode: truncated hydration map header")
	}
	header := make([]byte, mapHeaderBytes)
	if _, err := m.file.ReadAt(header, 0); err != nil {
		return err
	}
	if string(header[:16]) != mapMagic || binary.LittleEndian.Uint32(header[16:20]) != mapVersion ||
		binary.LittleEndian.Uint32(header[20:24]) != m.chunkSize || !equalBytes(header[24:], m.digest[:]) {
		return errors.New("restoremode: hydration map belongs to different restore state")
	}
	tail := size - mapHeaderBytes
	complete := tail / mapRecordBytes
	if uint64(complete) > m.maxRecords {
		return errors.New("restoremode: hydration map exceeds configured record bound")
	}
	if tail%mapRecordBytes != 0 {
		if err := m.file.Truncate(mapHeaderBytes + complete*mapRecordBytes); err != nil {
			return fmt.Errorf("truncate torn hydration map tail: %w", err)
		}
	}
	record := make([]byte, mapRecordBytes)
	for i := int64(0); i < complete; i++ {
		if _, err := m.file.ReadAt(record, mapHeaderBytes+i*mapRecordBytes); err != nil {
			return err
		}
		if binary.LittleEndian.Uint32(record[12:]) != crc32.ChecksumIEEE(record[:12]) || record[1] != 0 || record[2] != 0 || record[3] != 0 {
			return fmt.Errorf("restoremode: corrupt hydration map record %d", i)
		}
		entry := binary.LittleEndian.Uint32(record[4:8])
		chunk := binary.LittleEndian.Uint32(record[8:12])
		switch record[0] {
		case mapRecordChunk:
			key := chunkKey{entry: entry, chunk: chunk}
			m.hydrated[key], m.durable[key] = true, true
		case mapRecordUser:
			if chunk != 0 {
				return fmt.Errorf("restoremode: invalid user-modified record %d", i)
			}
			m.modified[entry] = true
		default:
			return fmt.Errorf("restoremode: unknown hydration map record %d", i)
		}
	}
	m.records = uint64(complete)
	return nil
}

func (m *hydrationMap) isHydrated(key chunkKey) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.hydrated[key]
}

func (m *hydrationMap) isDurable(key chunkKey) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.durable[key]
}

func (m *hydrationMap) isModified(entry uint32) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.modified[entry]
}

func (m *hydrationMap) markLazy(key chunkKey) {
	m.mu.Lock()
	m.hydrated[key] = true
	m.mu.Unlock()
}

func (m *hydrationMap) markDurable(keys []chunkKey, userEntry *uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var records [][]byte
	for _, key := range keys {
		if !m.durable[key] {
			records = append(records, encodeMapRecord(mapRecordChunk, key.entry, key.chunk))
		}
	}
	if userEntry != nil && !m.modified[*userEntry] {
		records = append(records, encodeMapRecord(mapRecordUser, *userEntry, 0))
	}
	if len(records) == 0 {
		return nil
	}
	if m.records+uint64(len(records)) > m.maxRecords {
		return errors.New("restoremode: hydration map record bound reached")
	}
	for _, record := range records {
		if _, err := m.file.Write(record); err != nil {
			return fmt.Errorf("append hydration map: %w", err)
		}
	}
	if err := m.file.Sync(); err != nil {
		return fmt.Errorf("sync hydration map: %w", err)
	}
	for _, key := range keys {
		m.hydrated[key], m.durable[key] = true, true
		if m.hook != nil {
			m.hook(key.entry, key.chunk, false)
		}
	}
	if userEntry != nil {
		m.modified[*userEntry] = true
		if m.hook != nil {
			m.hook(*userEntry, 0, true)
		}
	}
	m.records += uint64(len(records))
	return nil
}

func encodeMapRecord(kind byte, entry, chunk uint32) []byte {
	record := make([]byte, mapRecordBytes)
	record[0] = kind
	binary.LittleEndian.PutUint32(record[4:8], entry)
	binary.LittleEndian.PutUint32(record[8:12], chunk)
	binary.LittleEndian.PutUint32(record[12:], crc32.ChecksumIEEE(record[:12]))
	return record
}

func (m *hydrationMap) Close() error {
	if m == nil || m.file == nil {
		return nil
	}
	err := m.file.Close()
	m.file = nil
	return err
}
