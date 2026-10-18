//go:build darwin

package portablefsd

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Swift takes the exact app/daemon canonical flock before publishing anything
// in the file. Empty or stale bytes cannot authorize inode replacement.
func TestP4SingletonRefusesSwiftOwnerBeforePublicationAndAfterCrash(t *testing.T) {
	dir := privateTestDir(t)
	script := filepath.Join(dir, "hold.swift")
	source := `import Foundation
import Darwin
let fd = open(CommandLine.arguments[1], O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
guard fd >= 0, flock(fd, LOCK_EX | LOCK_NB) == 0 else { exit(1) }
FileHandle.standardOutput.write(Data("locked\n".utf8))
_ = FileHandle.standardInput.readDataToEndOfFile()
close(fd)
`
	if err := os.WriteFile(script, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, ".portablefsd-state.lock")
	for _, payload := range [][]byte{nil, []byte("arbitrary stale owner bytes\n")} {
		if err := os.WriteFile(path, payload, 0600); err != nil {
			t.Fatal(err)
		}
		before, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		command := exec.Command("/usr/bin/swift", script, path)
		stdout, err := command.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		stdin, err := command.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		var stderr bytes.Buffer
		command.Stderr = &stderr
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		scanner := bufio.NewScanner(stdout)
		if !scanner.Scan() || scanner.Text() != "locked" {
			_ = command.Process.Kill()
			_ = command.Wait()
			t.Fatalf("Swift lock holder: %s", stderr.String())
		}
		for range 20 {
			lock, err := acquireStateSingleton(dir)
			if lock != nil {
				releaseSingleton(lock)
			}
			if !errors.Is(err, errSingletonHeld) {
				_ = command.Process.Kill()
				_ = command.Wait()
				t.Fatalf("acquisition displaced Swift owner: %v", err)
			}
		}
		data, err := os.ReadFile(path)
		after, statErr := os.Stat(path)
		if err != nil || statErr != nil || !bytes.Equal(data, payload) || !os.SameFile(before, after) {
			_ = command.Process.Kill()
			_ = command.Wait()
			t.Fatal("held canonical lock contents or inode changed")
		}
		// Exercise both cooperative unregister completion and ordinary process death.
		if len(payload) == 0 {
			_ = stdin.Close()
			if err := command.Wait(); err != nil {
				t.Fatal(err)
			}
		} else {
			_ = command.Process.Kill()
			_ = command.Wait()
			_ = stdin.Close()
		}
		next, err := acquireStateSingleton(dir)
		if err != nil {
			t.Fatal(err)
		}
		opened, err := next.file.Stat()
		if err != nil || !os.SameFile(before, opened) {
			releaseSingleton(next)
			t.Fatal("restart acquired a different lock inode")
		}
		releaseSingleton(next)
	}
}
