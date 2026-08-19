package authorityrpc

import (
	"bufio"
	"crypto/tls"
	"errors"
	"net"
	"sync"
)

// tlsSocketBuffer batches the TLS records for one maximal data frame into a
// few socket operations. TLS still owns record boundaries and authentication;
// these buffers exist below it solely to stop each 16 KiB record becoming its
// own read(2) or write(2).
const tlsSocketBuffer = 256 << 10

type frameSocket struct {
	net.Conn

	mu       sync.Mutex
	reader   *bufio.Reader
	writer   *bufio.Writer
	buffered bool
}

func newFrameSocket(conn net.Conn) *frameSocket {
	return &frameSocket{
		Conn: conn, reader: bufio.NewReaderSize(conn, tlsSocketBuffer),
		writer: bufio.NewWriterSize(conn, tlsSocketBuffer),
	}
}

func (c *frameSocket) Read(payload []byte) (int, error) { return c.reader.Read(payload) }

func (c *frameSocket) Write(payload []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.buffered {
		return c.writer.Write(payload)
	}
	return c.Conn.Write(payload)
}

func (c *frameSocket) beginFrameWrite() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.buffered || c.writer.Buffered() != 0 {
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
	err := c.writer.Flush()
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
