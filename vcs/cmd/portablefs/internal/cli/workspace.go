package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/workspacehost"
)

func cmdWorkspace(e *cmdEnv, args []string) int {
	if len(args) == 0 {
		return e.usageError("workspace", fmt.Errorf("expected start, status, mount, umount, or stop"))
	}
	operation := args[0]
	switch operation {
	case "start", "status", "mount", "umount", "stop":
	default:
		return e.usageError("workspace", fmt.Errorf("unknown workspace verb %q", operation))
	}
	fs := newFlagSet("workspace " + operation)
	var jsonOut, force bool
	if operation != "start" {
		fs.BoolVar(&jsonOut, "json", false, "print machine-readable state")
	}
	if operation == "umount" || operation == "stop" {
		fs.BoolVar(&force, "force", false, "explicitly discard open operations and potentially unflushed changes")
	}
	positional, err := parseArgs(fs, args[1:])
	if err != nil {
		return e.handleParseError("workspace", err)
	}
	request := workspacehost.Request{Version: 1, Operation: operation, Force: force}
	if operation == "mount" {
		if len(positional) != 1 || filepath.Ext(positional[0]) != ".pfsworkspace" {
			return e.usageError("workspace", fmt.Errorf("mount requires one .pfsworkspace connection file"))
		}
		file, err := os.Open(positional[0])
		if err != nil {
			return e.fail("workspace", err)
		}
		raw, err := io.ReadAll(io.LimitReader(file, workspacehost.MaxDocument+1))
		file.Close()
		if err != nil {
			return e.fail("workspace", err)
		}
		document, err := workspacehost.DecodeDocument(raw)
		if err != nil {
			return e.fail("workspace", err)
		}
		request.Document = &document
	} else if operation == "umount" {
		if len(positional) != 1 {
			return e.usageError("workspace", fmt.Errorf("umount requires one volume ID"))
		}
		request.VolumeID = positional[0]
	} else if len(positional) != 0 {
		return e.usageError("workspace", fmt.Errorf("%s expects no arguments", operation))
	}
	if err := request.Validate(); err != nil {
		return e.usageError("workspace", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var reply workspacehost.Reply
	if e.workspaceRequestFn != nil {
		reply, err = e.workspaceRequestFn(ctx, request)
	} else {
		reply, err = e.requestWorkspace(ctx, request)
	}
	if err != nil {
		return e.fail("workspace", err)
	}
	if jsonOut {
		if code := e.printJSON(reply); code != 0 {
			return code
		}
	} else {
		fmt.Fprintln(e.stdout, reply.Message)
		if reply.SomeChangesWereNotSaved {
			fmt.Fprintln(e.stdout, "Some changes were not saved")
		}
		if reply.PreviousWriteOutcomeUnknown {
			fmt.Fprintln(e.stdout, "Previous write outcome unknown")
		}
		for _, volume := range reply.Volumes {
			fmt.Fprintf(e.stdout, "%s: %s\n", volume.Path, volume.State)
			if volume.Message != "" {
				fmt.Fprintln(e.stdout, volume.Message)
			}
			if volume.AuthorizationRequest != "" && volume.State == "authorization-required" {
				fmt.Fprintf(e.stdout, "Save Authorization Request… %s\n", volume.AuthorizationRequest)
			}
		}
	}
	if reply.State == "refused" || reply.State == "busy" || reply.State == "cleanup-required" {
		return 1
	}
	return 0
}
