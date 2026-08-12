package portablefsd

import (
	"fmt"
	"net"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// preflightFrontend proves that this daemon's exact Data Vault frontend socket
// can negotiate the shipped protocol and resolve the just-created attach. The
// shell CLI invokes this through the external control socket because it is
// intentionally unentitled and must never dial the app-group itself.
func (s *Server) preflightFrontend(attachRef string) error {
	return preflightFrontendAt(
		s.cfg.FrontendSocket,
		attachRef,
		s.cfg.Version,
	)
}

func preflightFrontendAt(frontendSocket, attachRef, expectedVersion string) error {
	conn, err := net.DialTimeout("unix", frontendSocket, 5*time.Second)
	if err != nil {
		return fmt.Errorf("frontend socket is not answering: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	call := func(id uint64, body any) (any, error) {
		if err := pfslocal.WriteFrame(conn, &pfslocal.Envelope{RequestID: id, Body: body}); err != nil {
			return nil, err
		}
		for {
			envelope, err := pfslocal.ReadFrame(conn)
			if err != nil {
				return nil, err
			}
			if envelope.RequestID != id {
				continue
			}
			if reply, ok := envelope.Body.(*pfslocal.ErrorReply); ok {
				return nil, fmt.Errorf("errno %d: %s", reply.Errno, reply.Message)
			}
			return envelope.Body, nil
		}
	}
	helloBody, err := call(1, &pfslocal.Hello{
		ProtocolMajor: pfslocal.ProtocolMajor,
		ProtocolMinor: pfslocal.ProtocolMinor,
		ClientName:    "portablefsd-control-preflight",
		ClientVersion: expectedVersion,
	})
	if err != nil {
		return fmt.Errorf("frontend handshake: %w", err)
	}
	hello, ok := helloBody.(*pfslocal.HelloReply)
	if !ok || hello.ProtocolMajor != pfslocal.ProtocolMajor || hello.DaemonVersion != expectedVersion {
		gotMajor := uint32(0)
		gotVersion := ""
		if ok {
			gotMajor = hello.ProtocolMajor
			gotVersion = hello.DaemonVersion
		}
		return fmt.Errorf(
			"frontend handshake returned incompatible %T (protocol %d, daemon %q; want major %d, daemon %q)",
			helloBody,
			gotMajor,
			gotVersion,
			pfslocal.ProtocolMajor,
			expectedVersion,
		)
	}
	if _, err := call(2, &pfslocal.ResolveRequest{AttachRef: attachRef}); err != nil {
		return fmt.Errorf("attach %s is not resolvable on this daemon's frontend: %w", attachRef, err)
	}
	return nil
}
