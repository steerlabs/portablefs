//go:build linux

package cli

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/steerlabs/portablefs/vcs/internal/mountid"
)

func verifyFSKitMountIdentity(_, _, _ string) error {
	return fmt.Errorf("FSKit mount identity is unavailable on Linux")
}

func verifyRecordedMountIdentity(st *mountState) error {
	entries, err := linuxMountEntriesAt(st.MountPath)
	if err != nil {
		return err
	}
	return verifyLinuxRecordedMountEntries(st, entries)
}

func verifyLinuxRecordedMountEntries(st *mountState, entries []linuxMountInfoEntry) error {
	if len(entries) == 0 {
		return fmt.Errorf("%w at %s", errRecordedMountAbsent, st.MountPath)
	}
	if len(entries) != 1 {
		return fmt.Errorf("kernel mount identity at %s is ambiguous: %d stacked entries share the path", st.MountPath, len(entries))
	}
	if st.Strategy != "fuse" || !mountid.ValidMountInstance(st.MountInstanceID) || !validKernelMountID(st.KernelMountID) {
		return fmt.Errorf("recorded Linux mount identity is incomplete: strategy=%q mountInstanceId=%q kernelMountId=%q", st.Strategy, st.MountInstanceID, st.KernelMountID)
	}
	entry := entries[0]
	expectedSource := "portablefs:" + st.MountInstanceID
	if entry.id != st.KernelMountID || entry.fsType != "fuse.portablefs" || entry.source != expectedSource {
		return fmt.Errorf(
			"kernel mount at %s is id %s, %s from %s; want exact id %s, fuse.portablefs from %s",
			st.MountPath, entry.id, entry.fsType, entry.source, st.KernelMountID, expectedSource,
		)
	}
	return nil
}

func captureFUSEKernelMountID(mountPath, mountInstanceID string) (string, error) {
	if !mountid.ValidMountInstance(mountInstanceID) {
		return "", fmt.Errorf("invalid mount instance identity %q", mountInstanceID)
	}
	entries, err := linuxMountEntriesAt(mountPath)
	if err != nil {
		return "", err
	}
	id, present, err := recoverFUSEMountingIdentityFromEntries(mountPath, mountInstanceID, entries)
	if err != nil {
		return "", err
	}
	if !present {
		return "", fmt.Errorf("capture kernel mount identity at %s: exact mount is absent", mountPath)
	}
	return id, nil
}

func recoverFUSEMountingIdentity(mountPath, mountInstanceID string) (string, bool, error) {
	entries, err := linuxMountEntriesAt(mountPath)
	if err != nil {
		return "", false, err
	}
	return recoverFUSEMountingIdentityFromEntries(mountPath, mountInstanceID, entries)
}

func recoverFUSEMountingIdentityFromEntries(mountPath, mountInstanceID string, entries []linuxMountInfoEntry) (string, bool, error) {
	if !mountid.ValidMountInstance(mountInstanceID) {
		return "", false, fmt.Errorf("invalid mount instance identity %q", mountInstanceID)
	}
	if len(entries) == 0 {
		return "", false, nil
	}
	if len(entries) != 1 {
		return "", false, fmt.Errorf("capture kernel mount identity at %s: found %d same-path entries; refusing stacked mount", mountPath, len(entries))
	}
	entry := entries[0]
	expectedSource := "portablefs:" + mountInstanceID
	if !validKernelMountID(entry.id) || entry.fsType != "fuse.portablefs" || entry.source != expectedSource {
		return "", false, fmt.Errorf(
			"capture kernel mount identity at %s: got id %s, %s from %s; want fuse.portablefs from %s",
			mountPath, entry.id, entry.fsType, entry.source, expectedSource,
		)
	}
	return entry.id, true, nil
}

type linuxMountInfoEntry struct {
	id         string
	mountPoint string
	fsType     string
	source     string
}

func linuxMountEntriesAt(mountPath string) ([]linuxMountInfoEntry, error) {
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, fmt.Errorf("read kernel mount table: %w", err)
	}
	defer file.Close()
	var entries []linuxMountInfoEntry
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		entry, ok := parseLinuxMountInfoEntry(scanner.Text())
		if ok && entry.mountPoint == mountPath {
			entries = append(entries, entry)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan kernel mount table: %w", err)
	}
	return entries, nil
}

func parseLinuxMountInfoLine(line string) (mountPoint, fsType, source string, ok bool) {
	entry, ok := parseLinuxMountInfoEntry(line)
	return entry.mountPoint, entry.fsType, entry.source, ok
}

func parseLinuxMountInfoEntry(line string) (linuxMountInfoEntry, bool) {
	before, after, found := strings.Cut(line, " - ")
	if !found {
		return linuxMountInfoEntry{}, false
	}
	left, right := strings.Fields(before), strings.Fields(after)
	if len(left) < 5 || len(right) < 2 {
		return linuxMountInfoEntry{}, false
	}
	if !validKernelMountID(left[0]) {
		return linuxMountInfoEntry{}, false
	}
	return linuxMountInfoEntry{
		id:         left[0],
		mountPoint: unescapeMountInfo(left[4]),
		fsType:     right[0],
		source:     unescapeMountInfo(right[1]),
	}, true
}

func unescapeMountInfo(value string) string {
	var out strings.Builder
	for i := 0; i < len(value); {
		if value[i] == '\\' && i+3 < len(value) {
			if n, err := strconv.ParseUint(value[i+1:i+4], 8, 8); err == nil {
				out.WriteByte(byte(n))
				i += 4
				continue
			}
		}
		out.WriteByte(value[i])
		i++
	}
	return out.String()
}
