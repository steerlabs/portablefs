package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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
	var dismiss string
	if operation == "status" {
		fs.StringVar(&dismiss, "dismiss", "", "acknowledge one exact retained outcome ID")
	}
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
	fs.Visit(func(option *flag.Flag) {
		if option.Name == "dismiss" {
			request.Operation = "dismiss"
			request.OutcomeID = dismiss
		}
	})
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
		if reply.SomeChangesWereNotSaved && len(reply.Outcomes) == 0 {
			fmt.Fprintln(e.stdout, "Some changes were not saved")
		}
		if reply.PreviousWriteOutcomeUnknown && len(reply.Outcomes) == 0 {
			fmt.Fprintln(e.stdout, "Previous write outcome unknown")
		}
		for _, outcome := range reply.Outcomes {
			fmt.Fprintf(e.stdout, "%s\nOutcome: %s\nDismiss: portablefs workspace status --dismiss %s\n", outcomeMessage(outcome), outcome.ID, outcome.ID)
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

func outcomeMessage(outcome workspacehost.Outcome) string {
	var messages []string
	if outcome.SomeChangesWereNotSaved {
		messages = append(messages, "Some changes were not saved")
	}
	if outcome.PreviousWriteOutcomeUnknown {
		messages = append(messages, "Previous write outcome unknown")
	}
	return strings.Join(messages, "; ")
}
