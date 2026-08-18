package authorityrpc

import (
	"bufio"
	"crypto/tls"
	"errors"
	"net"
	"sync"
)

// tlsSocketWriteBuffer batches the TLS records for one maximal data frame into
// a few socket writes. TLS still owns record boundaries and authentication;
// this buffer exists below it solely to stop each 16 KiB record becoming its
// own write(2).
const tlsSocketWriteBuffer = 256 << 10

type frameSocket struct {
	net.Conn

	mu       sync.Mutex
	buffer   *bufio.Writer
	buffered bool
}

func newFrameSocket(conn net.Conn) *frameSocket {
	return &frameSocket{Conn: conn, buffer: bufio.NewWriterSize(conn, tlsSocketWriteBuffer)}
}

func (c *frameSocket) Write(payload []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.buffered {
		return c.buffer.Write(payload)
	}
	return c.Conn.Write(payload)
}

func (c *frameSocket) beginFrameWrite() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.buffered || c.buffer.Buffered() != 0 {
		return errors.New("authorityrpc: overlapping buffered frame write")
	}
	c.buffered = true
	return nil
}

func (c *frameSocket) endFrameWrite() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.buffered {
		return errors.New("authorityrpc: buffered frame write was not active")
	}
	err := c.buffer.Flush()
	c.buffered = false
	return err
}

// authorityTLSConn keeps handshake and alert traffic unbuffered while giving
// authority frames an explicit begin/flush boundary. Embedding tls.Conn keeps
// the ordinary net.Conn deadline and address behavior exact.
type authorityTLSConn struct {
	*tls.Conn
	socket *frameSocket
}

func newAuthorityTLSClient(raw net.Conn, config *tls.Config) *authorityTLSConn {
	socket := newFrameSocket(raw)
	return &authorityTLSConn{Conn: tls.Client(socket, config), socket: socket}
}

func newAuthorityTLSServer(raw net.Conn, config *tls.Config) *authorityTLSConn {
	socket := newFrameSocket(raw)
	return &authorityTLSConn{Conn: tls.Server(socket, config), socket: socket}
}

func (c *authorityTLSConn) beginFrameWrite() error { return c.socket.beginFrameWrite() }
func (c *authorityTLSConn) endFrameWrite() error   { return c.socket.endFrameWrite() }
