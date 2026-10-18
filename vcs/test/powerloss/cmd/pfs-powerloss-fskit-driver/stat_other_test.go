//go:build !linux && !darwin

package main

import "os"

// rawLinksAndAtime reports nothing here, so the local-volume tests fail on
// their first comparison rather than passing without link counts or atimes.
func rawLinksAndAtime(os.FileInfo) (uint32, int64, bool) { return 0, 0, false }
