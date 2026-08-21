package archive

import "hash/crc64"

// crc64NVMEReversed is the CRC-64/NVME polynomial 0xAD93D23594C93659 in the
// bit-reversed form hash/crc64 takes. CRC-64/NVME is the reflected algorithm
// with an all-ones initial value and an all-ones final xor, which is exactly
// what hash/crc64 computes starting from a zero seed, so the standard library
// table and update produce the value S3 returns for a full-object checksum.
const crc64NVMEReversed uint64 = 0x9A6C9329AC4BC9B5

// crc64NVMETable is built once; hash/crc64 tables are immutable and safe to
// share across goroutines.
var crc64NVMETable = crc64.MakeTable(crc64NVMEReversed)

// crc64NVME is the running full-object checksum of one pack, updated as the
// pack is written so no pack is ever read back to compute it.
type crc64NVME struct{ value uint64 }

func (c *crc64NVME) Write(p []byte) (int, error) {
	c.value = crc64.Update(c.value, crc64NVMETable, p)
	return len(p), nil
}

func (c *crc64NVME) Sum64() uint64 { return c.value }

// CRC64NVMESum is the CRC-64/NVME checksum of one buffer: the value to declare
// at CreateMultipartUpload and to compare against HeadObject without
// downloading the object.
func CRC64NVMESum(data []byte) uint64 { return crc64.Checksum(data, crc64NVMETable) }
