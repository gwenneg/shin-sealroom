package egress

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
)

// Go's HTTP parser is lenient: it accepts bare LF line endings and folded
// headers, merges a repeated Content-Length, drops one sent with chunked
// framing, ignores chunk extensions and reads trailers, all before the proxy
// sees the request. wireConn sits between the TLS connection and that parser
// and hands it only bytes that already have the one strict form RFC 9112
// defines, so nothing is normalized before the checks.

// wireHeadLimit bounds a request's head, its line and headers together.
const wireHeadLimit = maxHeaderBytes

// wireRefused is the head handed to Go's parser in place of a refused one:
// the proxy answers it with the refusal, in order with any request before it,
// and the connection closes after.
const wireRefused = "GET / HTTP/1.1\r\nHost: refused.invalid\r\nConnection: close\r\n\r\n"

type wireState int

const (
	wireHead      wireState = iota // reading a request head
	wireBody                       // a body of known length
	wireChunkSize                  // a chunk-size line
	wireChunkData                  // a chunk's data
	wireChunkEnd                   // the CRLF after a chunk's data
	wireLastChunk                  // the CRLF ending a chunked body: no trailers
	wireClosed                     // refused: nothing more is read
)

type wireConn struct {
	net.Conn // the TLS connection: writes, deadlines and closing go to it
	tls      *tls.Conn

	mu        sync.Mutex
	decisions []*refusal // one per head handed on, nil when it passed
	// bodyRefused is why a body was cut, which Go's body reader may report
	// as an error of its own.
	bodyRefused *refusal

	buf       []byte // read, not yet validated
	out       []byte // validated, not yet read by Go's parser
	state     wireState
	remaining int64 // bytes left in a body or a chunk
	failed    error // once set, returned when out is drained
	raw       []byte
}

func newWireConn(c *tls.Conn) *wireConn {
	return &wireConn{Conn: c, tls: c, raw: make([]byte, 32<<10)}
}

// CloseWrite lets Go's server close the connection gracefully.
func (c *wireConn) CloseWrite() error { return c.tls.CloseWrite() }

func (c *wireConn) Read(p []byte) (int, error) {
	for len(c.out) == 0 {
		if c.failed != nil {
			return 0, c.failed
		}
		n, err := c.Conn.Read(c.raw)
		if n > 0 {
			c.buf = append(c.buf, c.raw[:n]...)
			c.process()
		}
		if err != nil && len(c.out) == 0 {
			// A deadline is not the end: Go's server sets one to stop a
			// background read, then reads on.
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return 0, err
			}
			if c.failed == nil {
				c.failed = err
			}
		}
	}
	n := copy(p, c.out)
	c.out = c.out[n:]
	return n, nil
}

// next returns the decision on the next request Go's server hands the proxy.
func (c *wireConn) next() *refusal {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.decisions) == 0 {
		return nil
	}
	d := c.decisions[0]
	c.decisions = c.decisions[1:]
	return d
}

// refusedBody returns why the body being read was cut, if it was.
func (c *wireConn) refusedBody() *refusal {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bodyRefused
}

func (c *wireConn) decide(d *refusal) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.decisions = append(c.decisions, d)
}

// refuseHead replaces a refused head, and everything after it, by the
// stand-in head the proxy answers with the refusal.
func (c *wireConn) refuseHead(ref *refusal) {
	c.decide(ref)
	c.out = append(c.out, wireRefused...)
	c.buf = nil
	c.state = wireClosed
}

// failBody stops a body in the middle: its end never reaches Go's parser,
// so no complete request is ever read from it.
func (c *wireConn) failBody(ref *refusal) {
	c.mu.Lock()
	c.bodyRefused = ref
	c.mu.Unlock()
	c.failed = ref
	c.buf = nil
	c.state = wireClosed
}

func (c *wireConn) process() {
	for {
		switch c.state {
		case wireClosed:
			c.buf = nil
			return
		case wireHead:
			if len(c.buf) == 0 {
				return
			}
			end := bytes.Index(c.buf, []byte("\r\n\r\n"))
			scan := c.buf
			if end >= 0 {
				scan = c.buf[:end+4]
			}
			if ref := lineEndings(scan); ref != nil {
				c.refuseHead(ref)
				return
			}
			if end < 0 {
				if len(c.buf) > wireHeadLimit {
					c.refuseHead(refuse(reasonTooLarge, "a request head over %d bytes", wireHeadLimit))
				}
				return
			}
			if end+4 > wireHeadLimit {
				c.refuseHead(refuse(reasonTooLarge, "a request head over %d bytes", wireHeadLimit))
				return
			}
			head := c.buf[:end+4]
			chunked, length, ref := parseHead(string(head[:end]))
			if ref != nil {
				c.refuseHead(ref)
				return
			}
			c.decide(nil)
			c.out = append(c.out, head...)
			c.buf = c.buf[end+4:]
			switch {
			case chunked:
				c.state = wireChunkSize
			case length > 0:
				c.state, c.remaining = wireBody, length
			}
		case wireBody, wireChunkData:
			n := int64(len(c.buf))
			if n == 0 {
				return
			}
			if n > c.remaining {
				n = c.remaining
			}
			c.out = append(c.out, c.buf[:n]...)
			c.buf = c.buf[n:]
			c.remaining -= n
			if c.remaining == 0 {
				if c.state == wireBody {
					c.state = wireHead
				} else {
					c.state = wireChunkEnd
				}
			}
		case wireChunkSize:
			end := bytes.Index(c.buf, []byte("\r\n"))
			line := c.buf
			if end >= 0 {
				line = c.buf[:end]
			}
			// The size alone, in hex: no extension, no space, no sign.
			if len(line) > 8 || bytes.IndexFunc(line, func(r rune) bool { return !isHex(byte(r)) || r > 0x7f }) >= 0 {
				c.failBody(refuse(reasonBody, "a malformed chunk size"))
				return
			}
			if end < 0 {
				return
			}
			if len(line) == 0 {
				c.failBody(refuse(reasonBody, "an empty chunk size"))
				return
			}
			size, _ := strconv.ParseInt(string(line), 16, 64)
			if size > MaxBodyBytes {
				c.failBody(refuse(reasonTooLarge, "a chunk over %d bytes", MaxBodyBytes))
				return
			}
			c.out = append(c.out, c.buf[:end+2]...)
			c.buf = c.buf[end+2:]
			if size == 0 {
				c.state = wireLastChunk
			} else {
				c.state, c.remaining = wireChunkData, size
			}
		case wireChunkEnd, wireLastChunk:
			if len(c.buf) < 2 {
				if len(c.buf) == 1 && c.buf[0] != '\r' {
					c.failBody(refuse(reasonBody, "chunk data not followed by CRLF, or a trailer"))
				}
				return
			}
			if c.buf[0] != '\r' || c.buf[1] != '\n' {
				c.failBody(refuse(reasonBody, "chunk data not followed by CRLF, or a trailer"))
				return
			}
			c.out = append(c.out, "\r\n"...)
			c.buf = c.buf[2:]
			if c.state == wireChunkEnd {
				c.state = wireChunkSize
			} else {
				c.state = wireHead
			}
		}
	}
}

// lineEndings refuses a head with a bare LF or a bare CR, as soon as one is
// seen: every line ends with CRLF, and nothing else breaks a line.
func lineEndings(b []byte) *refusal {
	for i, x := range b {
		switch {
		case x == '\n' && (i == 0 || b[i-1] != '\r'):
			return refuse(reasonForm, "a line ending that is not CRLF")
		case x == '\r' && i+1 < len(b) && b[i+1] != '\n':
			return refuse(reasonForm, "a CR alone")
		}
	}
	return nil
}

// parseHead checks a request head, without its final CRLF CRLF, and returns
// its framing.
func parseHead(head string) (chunked bool, length int64, ref *refusal) {
	lines := strings.Split(head, "\r\n")
	parts := strings.Split(lines[0], " ")
	if len(parts) != 3 || parts[2] != "HTTP/1.1" {
		return false, 0, refuse(reasonForm, "not METHOD SP TARGET SP HTTP/1.1")
	}
	if m := parts[0]; m == "" || len(m) > 16 || strings.IndexFunc(m, func(r rune) bool { return r < 'A' || r > 'Z' }) >= 0 {
		return false, 0, refuse(reasonForm, "a method that is not upper-case letters")
	}
	// The target's bytes are checkRequest's: Go's parser keeps it as sent.
	if parts[1] == "" {
		return false, 0, refuse(reasonForm, "an empty request target")
	}
	if len(lines)-1 > 128 {
		return false, 0, refuse(reasonHeader, "more than 128 header lines")
	}
	var hosts, lengths, encodings int
	for _, line := range lines[1:] {
		if line == "" || line[0] == ' ' || line[0] == '\t' {
			return false, 0, refuse(reasonHeader, "a folded or empty header line")
		}
		// The same bytes checkHeaders allows, checked here so that Go's server
		// never refuses a header itself, unlogged.
		name, value, ok := strings.Cut(line, ":")
		if !ok || name == "" || strings.IndexFunc(name, func(r rune) bool {
			return !(r == '-' || 'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9')
		}) >= 0 {
			return false, 0, refuse(reasonHeader, "a malformed header name")
		}
		value = strings.Trim(value, " \t")
		if strings.IndexFunc(value, func(r rune) bool { return r != '\t' && (r < 0x20 || r > 0x7e) }) >= 0 {
			return false, 0, refuse(reasonHeader, "a byte outside the printable range in %s", name)
		}
		switch strings.ToLower(name) {
		case "host":
			hosts++
		case "content-length":
			lengths++
			if value == "" || len(value) > 18 || value != "0" && value[0] == '0' || strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
				return false, 0, refuse(reasonBody, "a malformed Content-Length")
			}
			length, _ = strconv.ParseInt(value, 10, 64)
		case "transfer-encoding":
			encodings++
			if value != "chunked" {
				return false, 0, refuse(reasonBody, "a transfer encoding other than chunked")
			}
			chunked = true
		}
	}
	switch {
	case hosts != 1:
		return false, 0, refuse(reasonHost, "%d Host headers", hosts)
	case lengths > 1 || encodings > 1:
		return false, 0, refuse(reasonBody, "framing headers repeated")
	case lengths == 1 && encodings == 1:
		return false, 0, refuse(reasonBody, "both Content-Length and Transfer-Encoding")
	}
	return chunked, length, nil
}

// wireListener hands Go's server validated connections.
type wireListener struct {
	net.Listener // a TLS listener
}

func (l wireListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	tc, ok := c.(*tls.Conn)
	if !ok {
		c.Close()
		return nil, errors.New("not a TLS connection")
	}
	return newWireConn(tc), nil
}

type wireKey struct{}

// wireContext makes a request's connection known to the proxy, for its TLS
// state and the decision on its head.
func wireContext(ctx context.Context, c net.Conn) context.Context {
	if wc, ok := c.(*wireConn); ok {
		return context.WithValue(ctx, wireKey{}, wc)
	}
	return ctx
}
