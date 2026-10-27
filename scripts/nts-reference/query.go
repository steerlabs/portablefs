package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/beevik/ntp"
	"github.com/beevik/nts"
)

// KE keeps the approved DNS name for SNI/certificate verification even when a
// particular IP family is selected. UDP uses only the authenticated negotiated
// endpoint and NTS extensions; there is no unauthenticated fallback.
func query(ctx context.Context, server, family string) (refs []reference, exchanges []exchange) {
	record := func(stage, family string, began int64, err error) {
		ended, clockErr := monotonicNow()
		item := exchange{Server: server, Family: family, Stage: stage, BeganNS: began, EndedNS: ended}
		if err != nil {
			item.Error = err.Error()
		} else if clockErr != nil {
			item.Error = clockErr.Error()
		}
		exchanges = append(exchanges, item)
	}
	began, err := monotonicNow()
	if err != nil {
		return nil, nil
	}
	keCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	deadline, _ := keCtx.Deadline()
	session, err := nts.NewSessionWithOptions(server, &nts.SessionOptions{
		Timeout: time.Until(deadline), TLSConfig: &tls.Config{ServerName: server, MinVersion: tls.VersionTLS13},
		Dialer: func(_, address string, config *tls.Config) (*tls.Conn, error) {
			raw, err := (&net.Dialer{}).DialContext(keCtx, "tcp"+family, address)
			if err != nil {
				return nil, err
			}
			conn := tls.Client(raw, config)
			if err := conn.SetDeadline(deadline); err != nil {
				conn.Close()
				return nil, err
			}
			if err := conn.HandshakeContext(keCtx); err != nil {
				conn.Close()
				return nil, err
			}
			return conn, nil
		},
	})
	record("NTS-KE", family, began, err)
	if err != nil {
		return nil, exchanges
	}
	// A negotiated literal address has one available family. A negotiated DNS
	// endpoint is tried over both. Sessions are used serially (the library mutates
	// cookies and request IDs), so authentication cannot race between exchanges.
	host, _, err := net.SplitHostPort(session.Address())
	if err != nil {
		return nil, exchanges
	}
	families := []string{family, map[string]string{"4": "6", "6": "4"}[family]}
	for _, udpFamily := range families {
		if ip := net.ParseIP(host); ip != nil && ((ip.To4() != nil) != (udpFamily == "4")) {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		began, err := monotonicNow()
		if err != nil {
			break
		}
		udpCtx, done := context.WithTimeout(ctx, 1100*time.Millisecond)
		deadline, _ := udpCtx.Deadline()
		response, err := session.QueryWithOptions(&ntp.QueryOptions{Version: 4, Timeout: time.Until(deadline),
			Dialer: func(_, remote string) (net.Conn, error) {
				conn, err := (&net.Dialer{}).DialContext(udpCtx, "udp"+udpFamily, remote)
				if err != nil {
					return nil, err
				}
				if err := conn.SetDeadline(deadline); err != nil {
					conn.Close()
					return nil, err
				}
				return deadlineConn{Conn: conn, deadline: deadline}, nil
			},
		})
		ended, clockErr := monotonicNow()
		if err == nil {
			err = clockErr
		}
		if err == nil {
			var ref reference
			ref, err = authenticatedReference(server, response)
			if err == nil {
				ref.QueryBeganNS = began
				ref.QueryEndedNS = ended
				refs = append(refs, ref)
			}
		}
		record("NTS-NTP", udpFamily, began, err)
		done()
	}
	if len(refs) == 0 && ctx.Err() != nil {
		record("deadline", family, began, fmt.Errorf("aggregate/attempt deadline: %w", ctx.Err()))
	}
	return refs, exchanges
}

// ntp sets its deadline after dialing. Preserve the absolute aggregate deadline
// across DNS and dial time instead of restarting a duration at that point.
type deadlineConn struct {
	net.Conn
	deadline time.Time
}

func (c deadlineConn) SetDeadline(t time.Time) error {
	if t.After(c.deadline) {
		t = c.deadline
	}
	return c.Conn.SetDeadline(t)
}
