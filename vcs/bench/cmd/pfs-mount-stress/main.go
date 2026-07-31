package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type doneRecord struct {
	Host       string `json:"host"`
	Files      int    `json:"files"`
	Appends    int    `json:"appends"`
	BigMiB     int    `json:"bigMiB"`
	LockIters  int    `json:"lockIters"`
	BigSHA256  string `json:"bigSha256"`
	Successful bool   `json:"successful"`
	Error      string `json:"error,omitempty"`
}

type result struct {
	Host                   string  `json:"host"`
	Peer                   string  `json:"peer"`
	ElapsedSeconds         float64 `json:"elapsedSeconds"`
	FilesPerHost           int     `json:"filesPerHost"`
	AppendRecords          int     `json:"appendRecords"`
	BigBytesPerHost        int64   `json:"bigBytesPerHost"`
	LockCounter            int     `json:"lockCounter"`
	PeerFilesObservedLive  int64   `json:"peerFilesObservedLive"`
	RenameOverOpenVerified bool    `json:"renameOverOpenVerified"`
}

func main() {
	root := flag.String("root", "", "mounted filesystem root")
	host := flag.String("host", "", "this host's stable test id")
	peer := flag.String("peer", "", "peer host's stable test id")
	run := flag.String("run", "", "unique run id")
	files := flag.Int("files", 500, "atomic files created per host")
	appends := flag.Int("appends", 1500, "shared append records per host")
	bigMiB := flag.Int("big-mib", 64, "sequential file size per host in MiB")
	lockIters := flag.Int("lock-iters", 200, "cross-host locked counter increments per host")
	timeout := flag.Duration("timeout", 4*time.Minute, "coordination timeout")
	flag.Parse()

	if *root == "" || *host == "" || *peer == "" || *run == "" || *host == *peer {
		fatalf("-root, -host, -peer, and -run are required; host and peer must differ")
	}
	if *files <= 0 || *appends <= 0 || *bigMiB <= 0 || *lockIters <= 0 || *timeout <= 0 {
		fatalf("all workload sizes and timeout must be positive")
	}

	started := time.Now()
	runRoot := filepath.Join(*root, "portablefs-stress", *run)
	hostRoot := filepath.Join(runRoot, "hosts", *host)
	peerRoot := filepath.Join(runRoot, "hosts", *peer)
	readyDir := filepath.Join(runRoot, "ready")
	doneDir := filepath.Join(runRoot, "done")
	for _, dir := range []string{
		filepath.Join(hostRoot, "files"),
		filepath.Join(hostRoot, "tmp"),
		filepath.Join(hostRoot, "churn"),
		readyDir,
		doneDir,
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			fatalf("mkdir %s: %v", dir, err)
		}
	}

	if err := writeAtomic(filepath.Join(readyDir, *host+".json"), []byte(`{"ready":true}`+"\n"), 0o600); err != nil {
		fatalf("publish ready marker: %v", err)
	}
	if err := waitFor(filepath.Join(readyDir, *peer+".json"), *timeout); err != nil {
		fatalf("wait for peer ready marker: %v", err)
	}

	var peerObserved atomic.Int64
	scanStop := make(chan struct{})
	scanDone := make(chan error, 1)
	go func() {
		scanDone <- scanPeerFiles(filepath.Join(peerRoot, "files"), *peer, *files, scanStop, &peerObserved)
	}()

	type opResult struct {
		name string
		data string
		err  error
	}
	ops := make(chan opResult, 5)
	go func() {
		ops <- opResult{name: "files", err: writeFileSet(hostRoot, *host, *files)}
	}()
	go func() {
		sum, err := writeBigFile(hostRoot, *host, *bigMiB)
		ops <- opResult{name: "big", data: sum, err: err}
	}()
	go func() {
		ops <- opResult{name: "append", err: appendRecords(filepath.Join(runRoot, "shared-append.log"), *host, *appends)}
	}()
	go func() {
		ops <- opResult{name: "churn", err: churnNames(filepath.Join(hostRoot, "churn"), *host, *files)}
	}()
	go func() {
		ops <- opResult{name: "lock", err: incrementLockedCounter(filepath.Join(runRoot, "locked-counter"), *lockIters)}
	}()

	var opErr error
	var ownBigSum string
	for range 5 {
		op := <-ops
		if op.name == "big" {
			ownBigSum = op.data
		}
		if op.err != nil {
			opErr = errors.Join(opErr, fmt.Errorf("%s: %w", op.name, op.err))
		}
	}

	record := doneRecord{
		Host:       *host,
		Files:      *files,
		Appends:    *appends,
		BigMiB:     *bigMiB,
		LockIters:  *lockIters,
		BigSHA256:  ownBigSum,
		Successful: opErr == nil,
	}
	if opErr != nil {
		record.Error = opErr.Error()
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		fatalf("encode done marker: %v", err)
	}
	if err := writeAtomic(filepath.Join(doneDir, *host+".json"), append(encoded, '\n'), 0o600); err != nil {
		fatalf("publish done marker: %v", err)
	}
	if err := waitFor(filepath.Join(doneDir, *peer+".json"), *timeout); err != nil {
		fatalf("wait for peer done marker: %v", err)
	}
	close(scanStop)
	if err := <-scanDone; err != nil {
		opErr = errors.Join(opErr, fmt.Errorf("live peer scan: %w", err))
	}

	peerRecord, err := readDoneRecord(filepath.Join(doneDir, *peer+".json"))
	if err != nil {
		opErr = errors.Join(opErr, fmt.Errorf("read peer done marker: %w", err))
	} else if !peerRecord.Successful {
		opErr = errors.Join(opErr, fmt.Errorf("peer workload failed: %s", peerRecord.Error))
	} else if peerRecord.Files != *files || peerRecord.Appends != *appends ||
		peerRecord.BigMiB != *bigMiB || peerRecord.LockIters != *lockIters {
		opErr = errors.Join(opErr, fmt.Errorf("peer workload shape mismatch: %+v", peerRecord))
	}

	if err := verifyFileSet(filepath.Join(hostRoot, "files"), *host, *files); err != nil {
		opErr = errors.Join(opErr, fmt.Errorf("verify own files: %w", err))
	}
	if err := verifyFileSet(filepath.Join(peerRoot, "files"), *peer, *files); err != nil {
		opErr = errors.Join(opErr, fmt.Errorf("verify peer files: %w", err))
	}
	if err := verifyBigFile(filepath.Join(hostRoot, "big.bin"), *host, *bigMiB, ownBigSum); err != nil {
		opErr = errors.Join(opErr, fmt.Errorf("verify own big file: %w", err))
	}
	if peerRecord.BigSHA256 != "" {
		if err := verifyBigFile(filepath.Join(peerRoot, "big.bin"), *peer, *bigMiB, peerRecord.BigSHA256); err != nil {
			opErr = errors.Join(opErr, fmt.Errorf("verify peer big file: %w", err))
		}
	}
	appendCount, err := verifyAppends(filepath.Join(runRoot, "shared-append.log"), []string{*host, *peer}, *appends)
	if err != nil {
		opErr = errors.Join(opErr, fmt.Errorf("verify shared appends: %w", err))
	}
	counter, err := readCounter(filepath.Join(runRoot, "locked-counter"))
	if err != nil {
		opErr = errors.Join(opErr, fmt.Errorf("read locked counter: %w", err))
	} else if counter != 2**lockIters {
		opErr = errors.Join(opErr, fmt.Errorf("locked counter=%d, want %d", counter, 2**lockIters))
	}
	if err := verifyChurnEmpty(filepath.Join(hostRoot, "churn")); err != nil {
		opErr = errors.Join(opErr, fmt.Errorf("verify own churn: %w", err))
	}
	if err := verifyChurnEmpty(filepath.Join(peerRoot, "churn")); err != nil {
		opErr = errors.Join(opErr, fmt.Errorf("verify peer churn: %w", err))
	}
	if err := renameOverOpen(filepath.Join(hostRoot, "rename-over-open")); err != nil {
		opErr = errors.Join(opErr, fmt.Errorf("rename-over-open: %w", err))
	}
	if opErr != nil {
		fatalf("%v", opErr)
	}

	out := result{
		Host:                   *host,
		Peer:                   *peer,
		ElapsedSeconds:         time.Since(started).Seconds(),
		FilesPerHost:           *files,
		AppendRecords:          appendCount,
		BigBytesPerHost:        int64(*bigMiB) * 1024 * 1024,
		LockCounter:            counter,
		PeerFilesObservedLive:  peerObserved.Load(),
		RenameOverOpenVerified: true,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fatalf("encode result: %v", err)
	}
}

func writeFileSet(hostRoot, host string, count int) error {
	filesDir := filepath.Join(hostRoot, "files")
	tmpDir := filepath.Join(hostRoot, "tmp")
	jobs := make(chan int)
	errs := make(chan error, 8)
	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for index := range jobs {
				name := fmt.Sprintf("file-%06d.dat", index)
				tmp := filepath.Join(tmpDir, fmt.Sprintf("%s.%d.tmp", name, worker))
				final := filepath.Join(filesDir, name)
				content := fileContent(host, index)
				if err := writeExclusiveSynced(tmp, content, 0o600); err != nil {
					errs <- fmt.Errorf("write %s: %w", tmp, err)
					return
				}
				if err := os.Rename(tmp, final); err != nil {
					errs <- fmt.Errorf("rename %s to %s: %w", tmp, final, err)
					return
				}
				if err := os.Chmod(final, 0o640); err != nil {
					errs <- fmt.Errorf("chmod %s: %w", final, err)
					return
				}
				info, err := os.Stat(final)
				if err != nil || info.Mode().Perm() != 0o640 || info.Size() != int64(len(content)) {
					errs <- fmt.Errorf("stat %s: info=%v err=%v", final, info, err)
					return
				}
			}
		}(worker)
	}
	for index := range count {
		jobs <- index
	}
	close(jobs)
	wg.Wait()
	close(errs)
	var result error
	for err := range errs {
		result = errors.Join(result, err)
	}
	if result != nil {
		return result
	}
	return syncDir(filesDir)
}

func fileContent(host string, index int) []byte {
	seed := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", host, index)))
	content := make([]byte, 4096)
	header := fmt.Sprintf("host=%s index=%06d sha=%s\n", host, index, hex.EncodeToString(seed[:]))
	copy(content, header)
	for i := len(header); i < len(content); i++ {
		content[i] = seed[(i-len(header))%len(seed)]
	}
	return content
}

func writeBigFile(hostRoot, host string, mib int) (string, error) {
	tmp := filepath.Join(hostRoot, "big.bin.tmp")
	final := filepath.Join(hostRoot, "big.bin")
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	hasher := sha256.New()
	buf := make([]byte, 1024*1024)
	for block := range mib {
		fillBigChunk(buf, host, block)
		if _, err := file.Write(buf); err != nil {
			_ = file.Close()
			return "", err
		}
		_, _ = hasher.Write(buf)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, final); err != nil {
		return "", err
	}
	if err := syncDir(hostRoot); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func fillBigChunk(buf []byte, host string, block int) {
	seed := sha256.Sum256([]byte(fmt.Sprintf("big:%s:%d", host, block)))
	for i := range buf {
		buf[i] = seed[i%len(seed)] ^ byte(i>>10)
	}
}

func appendRecords(path, host string, count int) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	for index := range count {
		payload := appendPayload(host, index)
		line := fmt.Sprintf("%s|%06d|%s\n", host, index, payload)
		written, err := file.Write([]byte(line))
		if err != nil {
			return err
		}
		if written != len(line) {
			return io.ErrShortWrite
		}
		if index%25 == 24 {
			if err := file.Sync(); err != nil {
				return err
			}
		}
	}
	return file.Sync()
}

func appendPayload(host string, index int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("append:%s:%d", host, index)))
	return hex.EncodeToString(sum[:])
}

func churnNames(dir, host string, count int) error {
	for index := range count {
		first := filepath.Join(dir, fmt.Sprintf("%s-%06d.a", host, index))
		second := filepath.Join(dir, fmt.Sprintf("%s-%06d.b", host, index))
		if err := writeExclusiveSynced(first, []byte(strconv.Itoa(index)), 0o600); err != nil {
			return err
		}
		if err := os.Rename(first, second); err != nil {
			return err
		}
		if _, err := os.Stat(second); err != nil {
			return err
		}
		if err := os.Remove(second); err != nil {
			return err
		}
	}
	return syncDir(dir)
}

func incrementLockedCounter(path string, iterations int) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	for range iterations {
		lock := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: io.SeekStart, Start: 0, Len: 0}
		if err := syscall.FcntlFlock(file.Fd(), syscall.F_SETLKW, &lock); err != nil {
			return err
		}
		data, readErr := io.ReadAll(io.NewSectionReader(file, 0, 64))
		value := 0
		if readErr == nil && len(bytes.TrimSpace(data)) != 0 {
			value, readErr = strconv.Atoi(string(bytes.TrimSpace(data)))
		}
		if readErr == nil {
			value++
			payload := []byte(strconv.Itoa(value) + "\n")
			if err := file.Truncate(0); err != nil {
				readErr = err
			} else if _, err := file.WriteAt(payload, 0); err != nil {
				readErr = err
			} else if err := file.Sync(); err != nil {
				readErr = err
			}
		}
		unlock := syscall.Flock_t{Type: syscall.F_UNLCK, Whence: io.SeekStart, Start: 0, Len: 0}
		unlockErr := syscall.FcntlFlock(file.Fd(), syscall.F_SETLK, &unlock)
		if readErr != nil {
			return readErr
		}
		if unlockErr != nil {
			return unlockErr
		}
	}
	return nil
}

func scanPeerFiles(dir, host string, count int, stop <-chan struct{}, observed *atomic.Int64) error {
	seen := make(map[string]struct{}, count)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return nil
		case <-ticker.C:
			entries, err := os.ReadDir(dir)
			if err != nil {
				if os.IsNotExist(err) {
					continue
				}
				return err
			}
			for _, entry := range entries {
				if entry.IsDir() || !strings.HasPrefix(entry.Name(), "file-") {
					continue
				}
				if _, ok := seen[entry.Name()]; ok {
					continue
				}
				index, err := fileIndex(entry.Name())
				if err != nil {
					return err
				}
				data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
				if err != nil {
					if os.IsNotExist(err) {
						continue
					}
					return err
				}
				if !bytes.Equal(data, fileContent(host, index)) {
					return fmt.Errorf("content mismatch for %s", entry.Name())
				}
				seen[entry.Name()] = struct{}{}
				observed.Add(1)
			}
		}
	}
}

func verifyFileSet(dir, host string, count int) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) != count {
		return fmt.Errorf("%s has %d entries, want %d", dir, len(entries), count)
	}
	for index := range count {
		path := filepath.Join(dir, fmt.Sprintf("file-%06d.dat", index))
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.Equal(data, fileContent(host, index)) {
			return fmt.Errorf("content mismatch for %s", path)
		}
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		if info.Mode().Perm() != 0o640 {
			return fmt.Errorf("%s mode=%#o, want 0640", path, info.Mode().Perm())
		}
	}
	return nil
}

func fileIndex(name string) (int, error) {
	if !strings.HasPrefix(name, "file-") || !strings.HasSuffix(name, ".dat") {
		return 0, fmt.Errorf("invalid file name %q", name)
	}
	return strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(name, "file-"), ".dat"))
}

func verifyBigFile(path, host string, mib int, claimed string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	hasher := sha256.New()
	buf := make([]byte, 1024*1024)
	for block := range mib {
		if _, err := io.ReadFull(file, buf); err != nil {
			return err
		}
		expected := make([]byte, len(buf))
		fillBigChunk(expected, host, block)
		if !bytes.Equal(buf, expected) {
			return fmt.Errorf("content mismatch at MiB block %d", block)
		}
		_, _ = hasher.Write(buf)
	}
	extra := make([]byte, 1)
	if n, err := file.Read(extra); n != 0 || err != io.EOF {
		return fmt.Errorf("unexpected trailing bytes: n=%d err=%v", n, err)
	}
	actual := hex.EncodeToString(hasher.Sum(nil))
	if actual != claimed {
		return fmt.Errorf("sha256=%s, peer claimed %s", actual, claimed)
	}
	return nil
}

func verifyAppends(path string, hosts []string, count int) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	validHosts := make(map[string]bool, len(hosts))
	for _, host := range hosts {
		validHosts[host] = true
	}
	seen := make(map[string]bool, len(hosts)*count)
	scanner := bufio.NewScanner(file)
	total := 0
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), "|")
		if len(parts) != 3 || !validHosts[parts[0]] {
			return total, fmt.Errorf("torn or invalid record %q", scanner.Text())
		}
		index, err := strconv.Atoi(parts[1])
		if err != nil || index < 0 || index >= count || parts[2] != appendPayload(parts[0], index) {
			return total, fmt.Errorf("invalid record %q", scanner.Text())
		}
		key := fmt.Sprintf("%s:%d", parts[0], index)
		if seen[key] {
			return total, fmt.Errorf("duplicate record %s", key)
		}
		seen[key] = true
		total++
	}
	if err := scanner.Err(); err != nil {
		return total, err
	}
	if total != len(hosts)*count {
		return total, fmt.Errorf("record count=%d, want %d", total, len(hosts)*count)
	}
	return total, nil
}

func readCounter(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(string(bytes.TrimSpace(data)))
}

func verifyChurnEmpty(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("%s has %d residual entries", dir, len(entries))
	}
	return nil
}

func renameOverOpen(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	target := filepath.Join(dir, "target")
	replacement := filepath.Join(dir, "replacement")
	if err := writeExclusiveSynced(target, []byte("old"), 0o600); err != nil {
		return err
	}
	old, err := os.Open(target)
	if err != nil {
		return err
	}
	defer old.Close()
	if err := writeExclusiveSynced(replacement, []byte("new"), 0o600); err != nil {
		return err
	}
	if err := os.Rename(replacement, target); err != nil {
		return err
	}
	oldData := make([]byte, 3)
	if _, err := old.ReadAt(oldData, 0); err != nil {
		return err
	}
	newData, err := os.ReadFile(target)
	if err != nil {
		return err
	}
	if string(oldData) != "old" || string(newData) != "new" {
		return fmt.Errorf("old fd=%q new path=%q", oldData, newData)
	}
	return syncDir(dir)
}

func writeExclusiveSynced(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := fmt.Sprintf("%s.%d.tmp", path, os.Getpid())
	if err := writeExclusiveSynced(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func waitFor(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		} else if !os.IsNotExist(err) {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s waiting for %s", timeout, path)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func readDoneRecord(path string) (doneRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return doneRecord{}, err
	}
	var record doneRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return doneRecord{}, err
	}
	return record, nil
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "pfs-mount-stress: "+format+"\n", args...)
	os.Exit(1)
}
