// Copyright 2016 the Go-FUSE Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fuse

import "fmt"

const useSingleReader = false

// UnmountLazy removes the mount from its namespace without waiting for open
// references or the serving loops to exit. Unlike a direct MNT_DETACH syscall,
// the fusermount path is authorized for the unprivileged user that created the
// mount. A caller that owns connection teardown can therefore make the path
// unreachable first, then keep using /dev/fuse to withdraw retained state.
func (ms *Server) UnmountLazy() error {
	ms.mountMu.Lock()
	defer ms.mountMu.Unlock()
	if ms.mountPoint == "" {
		return nil
	}
	if parseFuseFd(ms.mountPoint) >= 0 {
		return fmt.Errorf("cannot lazy-unmount magic mountpoint %q; use fusermount -u -z on the real mountpoint", ms.mountPoint)
	}
	if err := unmountLazy(ms.mountPoint, ms.opts); err != nil {
		return err
	}
	ms.mountPoint = ""
	return nil
}

func (ms *Server) write(req *request) Status {
	if req.outPayloadSize() == 0 {
		err := handleEINTR(func() error {
			_, err := writev(ms.mountFd, [][]byte{req.outHeaderBuf, req.outDataBuf})
			return err
		})
		return ToStatus(err)
	}
	if req.readResult != nil {
		defer req.readResult.Done()
		if ms.canSplice {
			err := ms.trySplice(req, req.readResult)
			if err == nil {
				return OK
			}
			if err != errRecoverSplice {
				ms.opts.Logger.Println("trySplice:", err)
			}
		}

		req.outPayload, req.status = req.readResult.Bytes(req.outPayload)
		req.serializeHeader(len(req.outPayload))
	}

	_, err := writev(ms.mountFd, [][]byte{req.outHeaderBuf, req.outDataBuf, req.outPayload})
	return ToStatus(err)
}
