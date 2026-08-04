//go:build darwin && cgo

package main

/*
#include <libproc.h>
#include <stdint.h>
#include <sys/resource.h>
#include <unistd.h>

static int portablefs_process_disk_bytes_written(uint64_t *out) {
	struct rusage_info_v4 usage = {0};
	int result = proc_pid_rusage(getpid(), RUSAGE_INFO_V4, (rusage_info_t *)&usage);
	if (result != 0) {
		return result;
	}
	*out = usage.ri_diskio_byteswritten;
	return 0;
}
*/
import "C"

import "fmt"

func diskBytesWritten() (uint64, error) {
	var written C.uint64_t
	if result := C.portablefs_process_disk_bytes_written(&written); result != 0 {
		return 0, fmt.Errorf("proc_pid_rusage: result %d", int(result))
	}
	return uint64(written), nil
}
